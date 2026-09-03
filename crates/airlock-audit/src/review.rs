//! 이 모듈은 사람이 감사 로그를 점검했다는 사실을 append-only 체인으로 남깁니다.
//!
//! # Features
//! 감사 체인은 "무슨 일이 있었는가" 를 남기고 앵커 체인은 "그 체인이 그대로인가" 를
//! 남깁니다. 둘 다 사람이 실제로 들여다보았는지는 말해 주지 않습니다. 대한민국
//! 전자금융감독규정 시행세칙 별표 7 의 16번은 기록만이 아니라 **매일 이상여부 점검과
//! 책임자 확인**을 요구하며, 이 모듈이 그 후자의 자리입니다.
//!
//! 확인 줄은 앵커 줄과 같은 방식으로 잠깁니다. 길이 접두 정규 인코딩, SHA-256, prev
//! 링크, in-band 버전 필드가 같고, 파일 권한 0600 과 디렉토리 0700 과 append 마다
//! `fsync` 도 같습니다. 다만 도메인 상수는 반드시 다릅니다. 한쪽 바이트열을 다른 쪽
//! 검증자에게 먹이는 교차 프로토콜 공격을 막기 위함입니다.
//!
//! # 범위와 다이제스트의 결합
//! 확인 도장은 **범위와 리포트 본문에 함께 묶입니다.** 기록되는 다이제스트가
//! `H(도메인 || 범위 || 본문)` 이므로, 다른 범위에서 계산한 리포트에 같은 도장을 찍을 수
//! 없습니다. 호출자가 다이제스트를 직접 넘기는 경로를 두지 않은 것도 같은 이유입니다.
//! 사람이 보지 않은 범위에 확인 도장이 찍히면 그 기록은 책임 근거가 아니라 알리바이가
//! 됩니다.
//!
//! # 탐지하지 못하는 것
//! `anchor` 모듈과 같습니다. 키도 서명도 없는 해시체인이므로, 이 파일에 쓸 수 있는
//! 주체는 체인 전체를 같은 비용으로 다시 계산합니다. 실질 탐지력은 저장 위치의 분리에서만
//! 나옵니다. `reviewer_uid` 는 확인 명령을 실제로 돌린 계정이지 그 계정 뒤에 앉은 사람이
//! 아니며, `reviewer_tty` 가 `None` 인 것은 사람이 확인하지 않았다는 뜻이 아니라 터미널을
//! 관측하지 못했다는 뜻입니다. 둘을 같은 것으로 읽으면 없는 보증을 믿게 됩니다.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use airlock_canonical::Encoder;
use airlock_i18n::tr;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::log::{FILE_MODE, create_dir_all_private, process_uids};
use crate::time::{format_rfc3339_nanos, now_unix_nanos};
use crate::types::{Hash, SessionId};

pub const REVIEW_FILE: &str = "reviews.jsonl";
pub const REVIEW_DOMAIN: &[u8] = b"airlock.review.v1\x00";
pub const REVIEW_VERSION: u32 = 1;

/// 확인 대상 리포트의 다이제스트를 계산할 때 쓰는 도메인.
///
/// 확인 줄 자체의 도메인과 다릅니다. 리포트 다이제스트는 체인 밖에서 계산되어 체인 안에
/// 들어가는 값이라, 같은 도메인을 쓰면 한쪽 값을 다른 쪽 자리에 밀어 넣을 수 있습니다
pub const REPORT_DOMAIN: &[u8] = b"airlock.report.v1\x00";

/// 점검 결과 판정.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// 이상 없음
    #[serde(rename = "clean")]
    Clean,
    /// 이상 있음. 확인자가 이상을 본 채로 도장을 찍었다는 사실이 남습니다
    #[serde(rename = "anomalous")]
    Anomalous,
}

impl Verdict {
    pub fn tag(self) -> u8 {
        match self {
            Self::Clean => 1,
            Self::Anomalous => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Anomalous => "anomalous",
        }
    }

    /// 사람이 읽는 한국어 표기.
    pub fn label(self) -> &'static str {
        match self {
            Self::Clean => tr!("정상", "clean"),
            Self::Anomalous => tr!("이상", "anomalous"),
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 확인이 덮는 범위.
///
/// 날짜 두 개만으로는 부족합니다. 같은 날짜 범위라도 그 사이에 세션이 늘어나면 다른 것을
/// 본 것이므로, 실제로 읽은 세션 목록을 함께 묶습니다
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReviewScope {
    pub since: Option<String>,
    pub until: Option<String>,
    pub sessions: Vec<SessionId>,
}

impl ReviewScope {
    pub fn new(
        since: Option<String>,
        until: Option<String>,
        sessions: impl IntoIterator<Item = SessionId>,
    ) -> Self {
        Self {
            since,
            until,
            sessions: sessions.into_iter().collect(),
        }
    }

    fn encode(&self, enc: &mut Encoder) {
        enc.opt_str(self.since.as_deref())
            .opt_str(self.until.as_deref())
            .u64(self.sessions.len() as u64);
        for s in &self.sessions {
            enc.bytes(s.as_bytes());
        }
    }
}

/// 리포트 본문 다이제스트를 범위와 묶은 최종 다이제스트를 만듭니다.
///
/// # Arguments
/// `scope` - 확인이 덮는 범위
/// `body` - 리포트 본문(사실들)의 다이제스트
pub fn report_digest(scope: &ReviewScope, body: &Hash) -> Hash {
    let mut enc = Encoder::with_domain(REPORT_DOMAIN);
    scope.encode(&mut enc);
    enc.bytes(body.as_bytes());
    finish(enc)
}

/// 확인 도장이 가리키는 대상.
///
/// 필드가 비공개인 것은 의도된 것입니다. 다이제스트를 밖에서 넣을 수 있으면 범위와
/// 어긋난 값을 기록할 수 있고, 그것이 정확히 이 체인이 막으려는 것입니다
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewSubject {
    scope: ReviewScope,
    body: Hash,
    digest: Hash,
}

impl ReviewSubject {
    /// 범위와 본문에서 확인 대상을 봉인합니다.
    ///
    /// # Arguments
    /// `scope` - 확인이 덮는 범위
    /// `body` - 리포트 본문의 다이제스트
    pub fn seal(scope: ReviewScope, body: Hash) -> Self {
        let digest = report_digest(&scope, &body);
        Self {
            scope,
            body,
            digest,
        }
    }

    pub fn scope(&self) -> &ReviewScope {
        &self.scope
    }

    pub fn body(&self) -> Hash {
        self.body
    }

    pub fn digest(&self) -> Hash {
        self.digest
    }
}

/// 확인 줄 하나.
///
/// `v` 에 기본값이 없는 것은 앵커 줄과 같은 이유입니다. v1 이전의 확인 포맷은 존재한 적이
/// 없으므로 `v` 없는 줄은 옛 포맷이 아니라 손상입니다
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewEntry {
    pub v: u32,
    pub seq: u64,
    pub ts: u64,
    pub ts_rfc3339: String,
    /// 감사 층이 `getuid(2)` 로 직접 읽은 값. 호출자가 넘길 수 없습니다
    pub reviewer_uid: u32,
    /// 감사 층이 `geteuid(2)` 로 직접 읽은 값
    pub reviewer_euid: u32,
    /// 확인 명령이 실제로 붙어 있던 터미널 장치 경로. 관측하지 못하면 `None`
    pub reviewer_tty: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub sessions: Vec<SessionId>,
    pub report_digest: Hash,
    pub verdict: Verdict,
    pub note: Option<String>,
    pub prev: Hash,
    pub hash: Hash,
}

impl ReviewEntry {
    pub fn scope(&self) -> ReviewScope {
        ReviewScope {
            since: self.since.clone(),
            until: self.until.clone(),
            sessions: self.sessions.clone(),
        }
    }

    pub fn recompute_hash(&self) -> Hash {
        compute_review_hash(self)
    }

    pub fn hash_is_valid(&self) -> bool {
        self.recompute_hash() == self.hash
    }

    /// 사람이 신원과 함께 확인했다고 말할 수 있는지 봅니다.
    ///
    /// 터미널을 관측하지 못한 확인은 계정만 남고 자리는 남지 않습니다. 그 둘을 같은 것으로
    /// 보고하면 무인 스크립트가 찍은 도장이 사람 확인처럼 읽힙니다
    pub fn has_observed_terminal(&self) -> bool {
        self.reviewer_tty.is_some()
    }
}

fn finish(enc: Encoder) -> Hash {
    crate::types::sha256(enc.as_slice())
}

fn compute_review_hash(e: &ReviewEntry) -> Hash {
    let mut enc = Encoder::with_domain(REVIEW_DOMAIN);
    enc.u32(e.v)
        .u64(e.seq)
        .bytes(e.prev.as_bytes())
        .u64(e.ts)
        .u32(e.reviewer_uid)
        .u32(e.reviewer_euid)
        .opt_str(e.reviewer_tty.as_deref());
    e.scope().encode(&mut enc);
    enc.bytes(e.report_digest.as_bytes())
        .tag(e.verdict.tag())
        .opt_str(e.note.as_deref());
    finish(enc)
}

/// 확인 명령이 붙어 있는 터미널 장치 경로.
///
/// `/dev/tty` 는 제어 터미널의 별칭이라 그대로 기록하면 어느 터미널이었는지가 남지
/// 않습니다. 열어서 실제 이름을 읽고, 읽지 못하면 `None` 입니다. 모르는 것을 아는 것처럼
/// 적지 않습니다
///
/// # Safety
/// `ttyname_r` 은 방금 연 유효한 fd 와 버퍼 길이를 받아 그 길이 안에서만 씁니다. 정적
/// 버퍼를 쓰는 `ttyname` 대신 재진입 가능한 쪽을 씁니다
fn observed_tty() -> Option<String> {
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let mut buf = [0 as libc::c_char; 128];
    let rc = unsafe { libc::ttyname_r(tty.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    name.to_str().ok().map(str::to_string)
}

/// 확인 체인의 append 핸들.
///
/// 열 때 기존 체인을 먼저 검증하고, 깨져 있으면 이어 붙이기를 거부합니다. 깨진 체인 뒤에
/// 정상 줄을 쌓으면 그 뒤쪽이 정당해 보이고 어디까지가 신뢰 가능한지가 사라집니다
#[derive(Debug)]
pub struct ReviewLog {
    path: PathBuf,
    file: File,
    seq_next: u64,
    last_hash: Hash,
}

impl ReviewLog {
    /// 확인 체인을 열고 이어 쓸 준비를 합니다.
    ///
    /// # Errors
    /// 디렉토리를 0700 으로 만들지 못하거나, 파일을 열지 못하거나, 이미 있는 확인 체인이
    /// 검증을 통과하지 못하면 실패합니다.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, Error> {
        let dir = dir.as_ref();
        create_dir_all_private(dir)?;
        let path = dir.join(REVIEW_FILE);

        let (seq_next, last_hash) = match verify_reviews(dir) {
            Ok(report) => (
                report.head_seq.checked_add(1).ok_or(Error::SeqOverflow)?,
                report.head_hash,
            ),
            Err(ReviewFailure::FileAbsent) => (0, Hash::ZERO),
            Err(ReviewFailure::Io(e)) => return Err(e),
            Err(broken) => {
                return Err(Error::ReviewChainBroken {
                    path,
                    detail: broken.to_string(),
                });
            }
        };

        let existed = path.exists();
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| Error::io(&path, e))?;
        if !existed {
            // 파일을 새로 만들었으면 디렉토리 엔트리도 내구화해야 합니다. 여기서 크래시하면
            // 확인 줄은 있는데 파일이 없는 상태가 됩니다
            let d = File::open(dir).map_err(|e| Error::io(dir, e))?;
            d.sync_all().map_err(|e| Error::io(dir, e))?;
        }

        Ok(Self {
            path,
            file,
            seq_next,
            last_hash,
        })
    }

    /// 확인 도장 하나를 체인에 잇습니다.
    ///
    /// 확인자 신원은 인자로 받지 않습니다. `getuid(2)`·`geteuid(2)` 와 실제 터미널 이름을
    /// 여기서 직접 읽습니다. 호출자가 넘길 수 있으면 남의 계정으로 확인한 것처럼 기록할 수
    /// 있습니다.
    ///
    /// # Arguments
    /// `subject` - 확인 대상. 범위와 다이제스트가 이미 묶여 있습니다
    /// `verdict` - 점검 판정
    /// `note` - 확인자가 남기는 메모
    ///
    /// # Errors
    /// 쓰기나 `fsync` 가 실패하면 실패합니다. 실패를 삼키면 확인 없는 범위가 확인된 것처럼
    /// 보입니다.
    pub fn append(
        &mut self,
        subject: &ReviewSubject,
        verdict: Verdict,
        note: Option<&str>,
    ) -> Result<ReviewEntry, Error> {
        let (uid, euid) = process_uids();
        let ts = now_unix_nanos();
        let scope = subject.scope();
        let mut entry = ReviewEntry {
            v: REVIEW_VERSION,
            seq: self.seq_next,
            ts,
            ts_rfc3339: format_rfc3339_nanos(ts),
            reviewer_uid: uid,
            reviewer_euid: euid,
            reviewer_tty: observed_tty(),
            since: scope.since.clone(),
            until: scope.until.clone(),
            sessions: scope.sessions.clone(),
            report_digest: subject.digest(),
            verdict,
            note: note.map(str::to_string),
            prev: self.last_hash,
            hash: Hash::ZERO,
        };
        entry.hash = compute_review_hash(&entry);

        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');

        self.file
            .write_all(&line)
            .map_err(|e| Error::io(&self.path, e))?;
        // 확인은 점검마다 한 줄뿐이므로 fsync 를 옵션으로 두지 않습니다
        self.file.sync_all().map_err(|e| Error::io(&self.path, e))?;

        self.last_hash = entry.hash;
        self.seq_next = entry.seq.checked_add(1).ok_or(Error::SeqOverflow)?;
        Ok(entry)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn head_seq(&self) -> Option<u64> {
        self.seq_next.checked_sub(1)
    }

    pub fn head_hash(&self) -> Hash {
        self.last_hash
    }
}

#[derive(Debug)]
pub enum ReviewFailure {
    FileAbsent,
    ChainEmpty,
    MalformedLine { line: u64, detail: String },
    TruncatedFinalLine { line: u64 },
    BlankLine { line: u64 },
    FormatVersionUnsupported { seq: u64, got: u32 },
    GenesisPrevNotZero { got: Hash },
    SeqGap { expected: u64, got: u64 },
    PrevMismatch { seq: u64, expected: Hash, got: Hash },
    HashMismatch { seq: u64, expected: Hash, got: Hash },
    ScopeMismatch { seq: u64 },
    DigestMismatch { seq: u64, expected: Hash, got: Hash },
    Io(Error),
}

impl fmt::Display for ReviewFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileAbsent => write!(
                f,
                "{}",
                tr!(
                    format!("{REVIEW_FILE} 없음. 매일 이상여부 점검과 책임자 확인 기록이 없음"),
                    format!(
                        "{REVIEW_FILE} missing; there is no record of daily anomaly checks and responsible-person sign-off"
                    )
                )
            ),
            Self::ChainEmpty => {
                f.write_str(tr!("확인 체인이 비어 있음", "the review chain is empty"))
            }
            Self::MalformedLine { line, detail } => write!(
                f,
                "{}",
                tr!(
                    format!("확인 {line}번째 줄 파싱 실패: {detail}"),
                    format!("failed to parse review line {line}: {detail}")
                )
            ),
            Self::TruncatedFinalLine { line } => write!(
                f,
                "{}",
                tr!(
                    format!("확인 {line}번째 줄이 개행 없이 잘림. 쓰기 중 중단 의심"),
                    format!(
                        "review line {line} is truncated without a newline; suspected interruption mid-write"
                    )
                )
            ),
            Self::BlankLine { line } => write!(
                f,
                "{}",
                tr!(
                    format!("확인 {line}번째 줄이 비어 있음. 확인 줄이 아닌 줄이 끼어들었음"),
                    format!("review line {line} is blank; a non-review line crept in")
                )
            ),
            Self::FormatVersionUnsupported { seq, got } => write!(
                f,
                "{}",
                tr!(
                    format!("확인 seq {seq}의 포맷이 v{got}. 이 검증자는 v{REVIEW_VERSION}만 안다"),
                    format!(
                        "review seq {seq} has format v{got}; this verifier only knows v{REVIEW_VERSION}"
                    )
                )
            ),
            Self::GenesisPrevNotZero { got } => write!(
                f,
                "{}",
                tr!(
                    format!("첫 확인 줄의 prev가 0이 아님: {got}"),
                    format!("the first review line's prev is not zero: {got}")
                )
            ),
            Self::SeqGap { expected, got } => write!(
                f,
                "{}",
                tr!(
                    format!("확인 seq 빈틈. {expected} 기대, {got} 발견. 확인 줄 삭제 의심"),
                    format!(
                        "review seq gap; expected {expected}, found {got}. Suspected review line deletion"
                    )
                )
            ),
            Self::PrevMismatch { seq, expected, got } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "확인 seq {seq}의 prev 불일치. {expected} 기대, {got} 발견. 삭제·삽입·재배치 의심"
                    ),
                    format!(
                        "review seq {seq} prev mismatch; expected {expected}, found {got}. Suspected deletion, insertion, or reordering"
                    )
                )
            ),
            Self::HashMismatch { seq, expected, got } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "확인 seq {seq}의 hash 불일치. 재계산 {expected}, 기록 {got}. 내용 변조 의심"
                    ),
                    format!(
                        "review seq {seq} hash mismatch; recomputed {expected}, recorded {got}. Suspected content tampering"
                    )
                )
            ),
            Self::ScopeMismatch { seq } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "확인 seq {seq}의 범위가 지금 계산한 리포트의 범위와 다름. \
                 보지 않은 범위에 찍힌 도장임"
                    ),
                    format!(
                        "the scope of review seq {seq} differs from the scope of the report \
                 computed now; it is a stamp on a range never looked at"
                    )
                )
            ),
            Self::DigestMismatch { seq, expected, got } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "확인 seq {seq}의 리포트 다이제스트 불일치. 재계산 {expected}, 기록 {got}. \
                 확인한 리포트와 지금 리포트가 다름"
                    ),
                    format!(
                        "review seq {seq} report digest mismatch; recomputed {expected}, recorded \
                 {got}. The reviewed report and the current report differ"
                    )
                )
            ),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ReviewFailure {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewWarning {
    ClockWentBackwards {
        seq: u64,
        prev_ts: u64,
        ts: u64,
    },
    /// 계정만 남고 터미널이 남지 않은 확인
    TerminalNotObserved {
        seq: u64,
    },
}

impl fmt::Display for ReviewWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClockWentBackwards { seq, prev_ts, ts } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "확인 seq {seq}에서 벽시계가 역행 ({prev_ts} -> {ts}). 시각 조정 가능성"
                    ),
                    format!(
                        "wall clock went backwards at review seq {seq} ({prev_ts} -> {ts}); possible clock adjustment"
                    )
                )
            ),
            Self::TerminalNotObserved { seq } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "확인 seq {seq}에 터미널이 관측되지 않음. 사람이 앉아 있었다는 근거는 아님"
                    ),
                    format!(
                        "no terminal observed at review seq {seq}; this is not evidence that a person was present"
                    )
                )
            ),
        }
    }
}

#[derive(Debug)]
pub struct ReviewReport {
    pub entries: u64,
    pub head_seq: u64,
    pub head_hash: Hash,
    pub last: Option<ReviewEntry>,
    pub warnings: Vec<ReviewWarning>,
}

impl ReviewReport {
    pub fn is_clean(&self) -> bool {
        self.warnings.is_empty()
    }
}

/// 확인 체인 자체의 무결성을 검증합니다.
///
/// # Errors
/// 확인 파일이 없거나, 줄이 손상되었거나, 연결·해시 규칙을 어기면 실패합니다.
pub fn verify_reviews(dir: &Path) -> Result<ReviewReport, ReviewFailure> {
    let path = dir.join(REVIEW_FILE);
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Err(ReviewFailure::FileAbsent),
        Err(e) => return Err(ReviewFailure::Io(Error::io(&path, e))),
    };
    scan(BufReader::new(file))
}

/// 가장 마지막 확인 줄을 돌려줍니다.
///
/// 조회 전에 체인 전체를 검증합니다. 깨진 체인에서 꺼낸 값으로 "확인했다" 고 보고하면
/// 없는 보증을 만들어 냅니다.
///
/// # Errors
/// 확인 체인 검증이 실패하면 그 사유를 그대로 돌려줍니다.
pub fn latest_review(dir: &Path) -> Result<Option<ReviewEntry>, ReviewFailure> {
    Ok(verify_reviews(dir)?.last)
}

/// 확인 줄이 지금 계산한 리포트를 실제로 가리키는지 봅니다.
///
/// # Arguments
/// `entry` - 검사할 확인 줄
/// `subject` - 지금 계산한 리포트의 범위와 본문
///
/// # Errors
/// 범위가 다르면 [`ReviewFailure::ScopeMismatch`], 본문이 다르면
/// [`ReviewFailure::DigestMismatch`] 입니다.
pub fn check_review(entry: &ReviewEntry, subject: &ReviewSubject) -> Result<(), ReviewFailure> {
    if entry.scope() != *subject.scope() {
        return Err(ReviewFailure::ScopeMismatch { seq: entry.seq });
    }
    if entry.report_digest != subject.digest() {
        return Err(ReviewFailure::DigestMismatch {
            seq: entry.seq,
            expected: subject.digest(),
            got: entry.report_digest,
        });
    }
    Ok(())
}

fn scan<R: BufRead>(mut reader: R) -> Result<ReviewReport, ReviewFailure> {
    let mut line_no: u64 = 0;
    let mut expected_seq: u64 = 0;
    let mut prev_hash = Hash::ZERO;
    let mut last_ts: u64 = 0;
    let mut last_seq: u64 = 0;
    let mut entry_count: u64 = 0;
    let mut warnings: Vec<ReviewWarning> = Vec::new();
    let mut last: Option<ReviewEntry> = None;

    let mut buf = String::new();
    loop {
        buf.clear();
        let read = reader
            .read_line(&mut buf)
            .map_err(|e| ReviewFailure::Io(Error::io(REVIEW_FILE, e)))?;
        if read == 0 {
            break;
        }
        let ended_with_newline = buf.ends_with('\n');
        let trimmed = buf.trim_end_matches(['\n', '\r']);
        line_no = line_no.saturating_add(1);

        if !ended_with_newline {
            return Err(ReviewFailure::TruncatedFinalLine { line: line_no });
        }
        if trimmed.trim().is_empty() {
            return Err(ReviewFailure::BlankLine { line: line_no });
        }

        let entry: ReviewEntry =
            serde_json::from_str(trimmed).map_err(|e| ReviewFailure::MalformedLine {
                line: line_no,
                detail: e.to_string(),
            })?;

        // 감사·앵커 체인과 같은 이유로 해시 검사보다 먼저 봅니다
        if entry.v != REVIEW_VERSION {
            return Err(ReviewFailure::FormatVersionUnsupported {
                seq: entry.seq,
                got: entry.v,
            });
        }
        if entry.seq != expected_seq {
            return Err(ReviewFailure::SeqGap {
                expected: expected_seq,
                got: entry.seq,
            });
        }
        if entry.seq == 0 {
            if !entry.prev.is_zero() {
                return Err(ReviewFailure::GenesisPrevNotZero { got: entry.prev });
            }
        } else if entry.prev != prev_hash {
            return Err(ReviewFailure::PrevMismatch {
                seq: entry.seq,
                expected: prev_hash,
                got: entry.prev,
            });
        }

        let recomputed = entry.recompute_hash();
        if recomputed != entry.hash {
            return Err(ReviewFailure::HashMismatch {
                seq: entry.seq,
                expected: recomputed,
                got: entry.hash,
            });
        }

        if entry.seq > 0 && entry.ts < last_ts {
            warnings.push(ReviewWarning::ClockWentBackwards {
                seq: entry.seq,
                prev_ts: last_ts,
                ts: entry.ts,
            });
        }
        if !entry.has_observed_terminal() {
            warnings.push(ReviewWarning::TerminalNotObserved { seq: entry.seq });
        }

        prev_hash = entry.hash;
        last_ts = entry.ts;
        last_seq = entry.seq;
        expected_seq = entry.seq.saturating_add(1);
        entry_count = entry_count.saturating_add(1);
        last = Some(entry);
    }

    if entry_count == 0 {
        return Err(ReviewFailure::ChainEmpty);
    }

    Ok(ReviewReport {
        entries: entry_count,
        head_seq: last_seq,
        head_hash: prev_hash,
        last,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "airlock-review-unit-{name}-{}-{}",
            std::process::id(),
            now_unix_nanos()
        ));
        p
    }

    fn scope(since: &str) -> ReviewScope {
        ReviewScope::new(
            Some(since.to_string()),
            Some("2026-08-26".to_string()),
            [SessionId::from_bytes([7; 16])],
        )
    }

    fn subject(since: &str) -> ReviewSubject {
        ReviewSubject::seal(scope(since), Hash::from_bytes([0x33; 32]))
    }

    #[test]
    fn the_digest_binds_the_scope() {
        let a = subject("2026-08-01");
        let b = subject("2026-08-02");
        assert_ne!(
            a.digest(),
            b.digest(),
            "범위가 다이제스트에 묶이지 않으면 다른 범위에 도장을 옮겨 찍을 수 있음"
        );
        assert_eq!(a.body(), b.body(), "본문은 같아야 이 시험이 의미가 있음");
    }

    #[test]
    fn the_report_domain_differs_from_the_review_domain() {
        assert_ne!(REPORT_DOMAIN, REVIEW_DOMAIN);
        assert_ne!(REVIEW_DOMAIN, crate::DOMAIN);
        assert_ne!(REVIEW_DOMAIN, crate::ANCHOR_DOMAIN);
    }

    #[test]
    fn a_review_line_is_not_an_anchor_line() {
        // 같은 값들을 앵커 도메인으로 계산하면 다른 바이트가 나와야 합니다
        let s = subject("2026-08-01");
        let mut enc = Encoder::with_domain(crate::ANCHOR_DOMAIN);
        s.scope().encode(&mut enc);
        enc.bytes(s.body().as_bytes());
        assert_ne!(finish(enc), s.digest());
    }

    #[test]
    fn check_rejects_a_stamp_from_another_range() {
        let dir = scratch("scope");
        let mut log = ReviewLog::open(&dir).unwrap();
        let entry = log
            .append(&subject("2026-08-01"), Verdict::Clean, None)
            .unwrap();

        assert!(check_review(&entry, &subject("2026-08-01")).is_ok());
        let err = check_review(&entry, &subject("2026-08-02")).unwrap_err();
        assert!(matches!(err, ReviewFailure::ScopeMismatch { .. }), "{err}");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn check_rejects_a_stamp_over_a_different_report_body() {
        let dir = scratch("body");
        let mut log = ReviewLog::open(&dir).unwrap();
        let entry = log
            .append(&subject("2026-08-01"), Verdict::Clean, None)
            .unwrap();

        let other = ReviewSubject::seal(scope("2026-08-01"), Hash::from_bytes([0x44; 32]));
        let err = check_review(&entry, &other).unwrap_err();
        assert!(matches!(err, ReviewFailure::DigestMismatch { .. }), "{err}");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_reviewer_identity_comes_from_the_kernel() {
        let dir = scratch("identity");
        let mut log = ReviewLog::open(&dir).unwrap();
        let entry = log
            .append(&subject("2026-08-01"), Verdict::Clean, None)
            .unwrap();

        let (uid, euid) = process_uids();
        assert_eq!(entry.reviewer_uid, uid);
        assert_eq!(entry.reviewer_euid, euid);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn every_hashed_field_changes_the_hash() {
        let dir = scratch("fields");
        let mut log = ReviewLog::open(&dir).unwrap();
        let base = log
            .append(&subject("2026-08-01"), Verdict::Clean, Some("확인함"))
            .unwrap();
        assert!(base.hash_is_valid());

        let mut v = base.clone();
        v.v = 2;
        assert_ne!(v.recompute_hash(), base.hash);

        let mut seq = base.clone();
        seq.seq = 1;
        assert_ne!(seq.recompute_hash(), base.hash);

        let mut ts = base.clone();
        ts.ts = base.ts.saturating_add(1);
        assert_ne!(ts.recompute_hash(), base.hash);

        let mut uid = base.clone();
        uid.reviewer_uid = base.reviewer_uid.wrapping_add(1);
        assert_ne!(uid.recompute_hash(), base.hash);

        let mut euid = base.clone();
        euid.reviewer_euid = base.reviewer_euid.wrapping_add(1);
        assert_ne!(euid.recompute_hash(), base.hash);

        let mut tty = base.clone();
        tty.reviewer_tty = Some("/dev/ttys099".into());
        assert_ne!(tty.recompute_hash(), base.hash);

        let mut since = base.clone();
        since.since = Some("1999-01-01".into());
        assert_ne!(since.recompute_hash(), base.hash);

        let mut until = base.clone();
        until.until = None;
        assert_ne!(until.recompute_hash(), base.hash);

        let mut sessions = base.clone();
        sessions.sessions = vec![SessionId::from_bytes([8; 16])];
        assert_ne!(sessions.recompute_hash(), base.hash);

        let mut digest = base.clone();
        digest.report_digest = Hash::from_bytes([0xAB; 32]);
        assert_ne!(digest.recompute_hash(), base.hash);

        let mut verdict = base.clone();
        verdict.verdict = Verdict::Anomalous;
        assert_ne!(verdict.recompute_hash(), base.hash);

        let mut note = base.clone();
        note.note = None;
        assert_ne!(note.recompute_hash(), base.hash);

        let mut prev = base.clone();
        prev.prev = Hash::from_bytes([9; 32]);
        assert_ne!(prev.recompute_hash(), base.hash);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rfc3339_is_not_hashed() {
        let dir = scratch("rfc");
        let mut log = ReviewLog::open(&dir).unwrap();
        let mut e = log
            .append(&subject("2026-08-01"), Verdict::Clean, None)
            .unwrap();
        e.ts_rfc3339 = "1999-01-01T00:00:00.000000000Z".into();
        assert!(e.hash_is_valid());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_line_without_v_is_malformed_not_legacy() {
        let dir = scratch("nov");
        let mut log = ReviewLog::open(&dir).unwrap();
        let e = log
            .append(&subject("2026-08-01"), Verdict::Clean, None)
            .unwrap();
        let mut value: serde_json::Value = serde_json::to_value(&e).unwrap();
        value.as_object_mut().unwrap().remove("v");
        assert!(serde_json::from_value::<ReviewEntry>(value).is_err());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let dir = scratch("unknown");
        let mut log = ReviewLog::open(&dir).unwrap();
        let e = log
            .append(&subject("2026-08-01"), Verdict::Clean, None)
            .unwrap();
        let mut value: serde_json::Value = serde_json::to_value(&e).unwrap();
        value["injected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ReviewEntry>(value).is_err());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn append_links_and_persists() {
        let dir = scratch("append");
        let mut log = ReviewLog::open(&dir).unwrap();
        assert_eq!(log.head_seq(), None);

        let a = log
            .append(&subject("2026-08-01"), Verdict::Clean, None)
            .unwrap();
        let b = log
            .append(&subject("2026-08-02"), Verdict::Anomalous, Some("이상 1건"))
            .unwrap();

        assert_eq!(a.seq, 0);
        assert!(a.prev.is_zero());
        assert_eq!(b.prev, a.hash);
        assert_eq!(log.head_seq(), Some(1));

        let report = verify_reviews(&dir).unwrap();
        assert_eq!(report.entries, 2);
        assert_eq!(report.last.map(|e| e.seq), Some(1));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reopen_continues_the_chain() {
        let dir = scratch("reopen");
        {
            let mut log = ReviewLog::open(&dir).unwrap();
            log.append(&subject("2026-08-01"), Verdict::Clean, None)
                .unwrap();
        }
        let mut log = ReviewLog::open(&dir).unwrap();
        let b = log
            .append(&subject("2026-08-02"), Verdict::Clean, None)
            .unwrap();
        assert_eq!(b.seq, 1);
        assert!(verify_reviews(&dir).is_ok());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        let mut log = ReviewLog::open(&dir).unwrap();
        log.append(&subject("2026-08-01"), Verdict::Clean, None)
            .unwrap();

        let dmode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, crate::log::DIR_MODE);
        let fmode = fs::metadata(dir.join(REVIEW_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(fmode, FILE_MODE);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_reported_as_no_review() {
        let dir = scratch("absent");
        fs::create_dir_all(&dir).unwrap();
        let err = verify_reviews(&dir).unwrap_err();
        assert!(matches!(err, ReviewFailure::FileAbsent), "{err}");
        assert!(err.to_string().contains("확인 기록이 없음"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_to_extend_a_broken_chain() {
        let dir = scratch("broken");
        {
            let mut log = ReviewLog::open(&dir).unwrap();
            log.append(&subject("2026-08-01"), Verdict::Clean, None)
                .unwrap();
        }
        let path = dir.join(REVIEW_FILE);
        let body = fs::read_to_string(&path)
            .unwrap()
            .replace("clean", "anomalous");
        fs::write(&path, body).unwrap();

        let err = ReviewLog::open(&dir).unwrap_err();
        assert!(matches!(err, Error::ReviewChainBroken { .. }), "{err}");

        fs::remove_dir_all(&dir).ok();
    }
}
