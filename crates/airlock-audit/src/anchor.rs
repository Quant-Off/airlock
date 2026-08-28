//! 이 모듈은 세션 사이를 잇는 상위 앵커 체인을 기록하고 검증합니다.
//!
//! # Features
//! 감사 세션은 서로 독립된 체인이고 제네시스의 `prev` 는 항상 0 입니다. 그래서 세션
//! 디렉토리를 통째로 지우면 남은 파일 어디에도 흔적이 없습니다. 앵커 체인은 세션
//! 디렉토리 **바깥**의 append-only 로그 하나에 세션마다 최종 head 를 남겨 그 구멍을
//! 좁힙니다 (`docs/audit-format.md` 8절). 파일 하나만 반출하면 세션 통째 삭제와 체인
//! 재계산이 탐지 가능해집니다.
//!
//! 앵커 줄은 감사 엔트리와 같은 방식으로 잠깁니다. 길이 접두 정규 인코딩, SHA-256,
//! prev 링크, in-band 버전 필드가 같습니다. 다만 도메인 상수는 반드시 다릅니다.
//! 한쪽 바이트열을 다른 쪽 검증자에게 먹이는 교차 프로토콜 공격을 막기 위함입니다.
//!
//! 파일 권한은 0600, 디렉토리는 0700 이며 append 마다 `fsync` 합니다. 앵커는 세션당
//! 한 줄뿐이므로 `--no-fsync` 와 무관하게 항상 동기화합니다. 최종 구성 요소는
//! `O_NOFOLLOW` 로 열어 미리 놓인 심볼릭 링크가 앵커를 다른 곳으로 돌리지 못하게 합니다.
//!
//! # 탐지하지 못하는 것
//! **앵커 파일이 세션과 같은 디렉토리 트리에 있고 대상이 거기에 쓸 수 있으면 이 모듈은
//! 아무것도 막지 못합니다.** 키도 서명도 없는 해시체인이므로, 세션 체인을 다시 계산할 수
//! 있는 주체는 앵커 체인도 같은 비용으로 다시 계산합니다. 실질 탐지력은 저장 위치의
//! 분리에서만 나옵니다. 다른 볼륨, 다른 계정 소유, 원격 append-only 마운트 중 하나가
//! 아니면 이 파일은 변조 탐지기가 아니라 크래시 탐지기입니다.
//!
//! 앵커 파일 자체의 삭제도 막지 못합니다. 검증자는 "탐지 불가" 라고 말할 수 있을 뿐
//! 원래 무엇이 있었는지 복원하지 못합니다. 앵커되지 않은 세션(SIGKILL 로 죽은 세션)은
//! 크래시와 삭제가 구분되지 않으며, `ts` 는 감사 체인과 같은 벽시계입니다.

use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use airlock_canonical::Encoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::log::{FILE_MODE, create_dir_all_private};
use crate::time::{format_rfc3339_nanos, now_unix_nanos};
use crate::types::{Hash, SessionId};

pub const ANCHOR_FILE: &str = "anchors.jsonl";
pub const ANCHOR_DOMAIN: &[u8] = b"airlock.anchor.v1\x00";
pub const ANCHOR_VERSION: u32 = 1;

/// 세션 하나의 최종 head 를 가리키는 앵커 줄.
///
/// `v` 에 기본값이 없는 것은 의도된 것입니다. v1 이전의 앵커 포맷은 존재한 적이 없으므로
/// `v` 없는 줄은 옛 포맷이 아니라 손상이며, 관대하게 받아들이면 없는 과거를 있는 것처럼
/// 만들어 줄 뿐입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorEntry {
    pub v: u32,
    pub seq: u64,
    pub ts: u64,
    pub ts_rfc3339: String,
    pub session: SessionId,
    pub head_seq: u64,
    pub head_hash: Hash,
    pub prev: Hash,
    pub hash: Hash,
}

impl AnchorEntry {
    pub fn seal(
        seq: u64,
        ts: u64,
        session: SessionId,
        head_seq: u64,
        head_hash: Hash,
        prev: Hash,
    ) -> Self {
        let v = ANCHOR_VERSION;
        let hash = compute_anchor_hash(v, seq, &prev, ts, &session, head_seq, &head_hash);
        Self {
            v,
            seq,
            ts,
            ts_rfc3339: format_rfc3339_nanos(ts),
            session,
            head_seq,
            head_hash,
            prev,
            hash,
        }
    }

    pub fn recompute_hash(&self) -> Hash {
        compute_anchor_hash(
            self.v,
            self.seq,
            &self.prev,
            self.ts,
            &self.session,
            self.head_seq,
            &self.head_hash,
        )
    }

    pub fn hash_is_valid(&self) -> bool {
        self.recompute_hash() == self.hash
    }
}

pub fn compute_anchor_hash(
    v: u32,
    seq: u64,
    prev: &Hash,
    ts: u64,
    session: &SessionId,
    head_seq: u64,
    head_hash: &Hash,
) -> Hash {
    let mut enc = Encoder::with_domain(ANCHOR_DOMAIN);
    enc.u32(v)
        .u64(seq)
        .bytes(prev.as_bytes())
        .u64(ts)
        .bytes(session.as_bytes())
        .u64(head_seq)
        .bytes(head_hash.as_bytes());

    let digest = Sha256::digest(enc.as_slice());
    let mut out = [0u8; Hash::LEN];
    out.copy_from_slice(&digest);
    Hash::from_bytes(out)
}

/// 세션 상위 앵커 체인의 append 핸들.
///
/// 열 때 기존 체인을 먼저 검증하고, 깨져 있으면 이어 붙이기를 거부합니다. 깨진 체인 뒤에
/// 정상 줄을 쌓으면 그 뒤쪽이 정당해 보이고 어디까지가 신뢰 가능한지가 사라집니다.
#[derive(Debug)]
pub struct AnchorLog {
    path: PathBuf,
    file: File,
    seq_next: u64,
    last_hash: Hash,
}

impl AnchorLog {
    /// 앵커 루트를 열고 이어 쓸 준비를 합니다.
    ///
    /// # Errors
    /// 디렉토리를 0700 으로 만들지 못하거나, 파일을 열지 못하거나, 이미 있는 앵커 체인이
    /// 검증을 통과하지 못하면 실패합니다.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, Error> {
        let dir = dir.as_ref();
        create_dir_all_private(dir)?;
        let path = dir.join(ANCHOR_FILE);

        let (seq_next, last_hash) = match verify_anchors(dir) {
            Ok(report) => (
                report.head_seq.checked_add(1).ok_or(Error::SeqOverflow)?,
                report.head_hash,
            ),
            Err(AnchorFailure::FileAbsent) => (0, Hash::ZERO),
            Err(AnchorFailure::Io(e)) => return Err(e),
            Err(broken) => {
                return Err(Error::AnchorChainBroken {
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
            // 앵커 줄은 있는데 파일이 없는 상태가 됩니다
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

    /// 세션 하나의 최종 head 를 앵커에 잇습니다.
    ///
    /// # Errors
    /// 쓰기나 `fsync` 가 실패하면 실패합니다. 실패를 삼키면 앵커 없는 세션이 앵커된 세션처럼
    /// 보입니다.
    pub fn append(
        &mut self,
        session: SessionId,
        head_seq: u64,
        head_hash: Hash,
    ) -> Result<AnchorEntry, Error> {
        let entry = AnchorEntry::seal(
            self.seq_next,
            now_unix_nanos(),
            session,
            head_seq,
            head_hash,
            self.last_hash,
        );

        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');

        self.file
            .write_all(&line)
            .map_err(|e| Error::io(&self.path, e))?;
        // 앵커는 세션당 한 줄이므로 fsync 를 옵션으로 두지 않습니다
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
pub enum AnchorFailure {
    FileAbsent,
    ChainEmpty,
    MalformedLine {
        line: u64,
        detail: String,
    },
    TruncatedFinalLine {
        line: u64,
    },
    BlankLine {
        line: u64,
    },
    FormatVersionUnsupported {
        seq: u64,
        got: u32,
    },
    GenesisPrevNotZero {
        got: Hash,
    },
    SeqGap {
        expected: u64,
        got: u64,
    },
    PrevMismatch {
        seq: u64,
        expected: Hash,
        got: Hash,
    },
    HashMismatch {
        seq: u64,
        expected: Hash,
        got: Hash,
    },
    SessionDuplicated {
        seq: u64,
        session: SessionId,
        first_seq: u64,
    },
    HeadSeqRegressed {
        seq: u64,
        session: SessionId,
        previous: u64,
        got: u64,
    },
    SessionHeadMismatch {
        session: SessionId,
        anchor_seq: u64,
        anchor_head_seq: u64,
        anchor_head_hash: Hash,
        chain_head_seq: u64,
        chain_head_hash: Hash,
    },
    Io(Error),
}

impl fmt::Display for AnchorFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileAbsent => write!(
                f,
                "{ANCHOR_FILE} 없음. 세션 삭제와 체인 재계산을 탐지할 수 없음. 앵커 삭제 의심"
            ),
            Self::ChainEmpty => write!(f, "앵커 체인이 비어 있음"),
            Self::MalformedLine { line, detail } => {
                write!(f, "앵커 {line}번째 줄 파싱 실패: {detail}")
            }
            Self::TruncatedFinalLine { line } => {
                write!(f, "앵커 {line}번째 줄이 개행 없이 잘림. 쓰기 중 중단 의심")
            }
            Self::BlankLine { line } => write!(
                f,
                "앵커 {line}번째 줄이 비어 있음. 앵커가 아닌 줄이 끼어들었음"
            ),
            Self::FormatVersionUnsupported { seq, got } => write!(
                f,
                "앵커 seq {seq}의 포맷이 v{got}. 이 검증자는 v{ANCHOR_VERSION}만 안다. 변조가 아니라 옛 포맷일 수 있으니 그 버전의 airlock으로 검증할 것"
            ),
            Self::GenesisPrevNotZero { got } => {
                write!(f, "첫 앵커의 prev가 0이 아님: {got}")
            }
            Self::SeqGap { expected, got } => {
                write!(
                    f,
                    "앵커 seq 빈틈. {expected} 기대, {got} 발견. 앵커 줄 삭제 의심"
                )
            }
            Self::PrevMismatch { seq, expected, got } => write!(
                f,
                "앵커 seq {seq}의 prev 불일치. {expected} 기대, {got} 발견. 삭제·삽입·재배치 의심"
            ),
            Self::HashMismatch { seq, expected, got } => write!(
                f,
                "앵커 seq {seq}의 hash 불일치. 재계산 {expected}, 기록 {got}. 내용 변조 의심"
            ),
            Self::SessionDuplicated {
                seq,
                session,
                first_seq,
            } => write!(
                f,
                "앵커 seq {seq}가 세션 {session}을 같은 head_seq로 다시 기록함 (처음은 seq {first_seq}). 앵커 줄 복제 의심"
            ),
            Self::HeadSeqRegressed {
                seq,
                session,
                previous,
                got,
            } => write!(
                f,
                "앵커 seq {seq}에서 세션 {session}의 head_seq가 되감김 ({previous} -> {got}). 세션 체인은 자라기만 하므로 잘라내기 의심"
            ),
            Self::SessionHeadMismatch {
                session,
                anchor_seq,
                anchor_head_seq,
                anchor_head_hash,
                chain_head_seq,
                chain_head_hash,
            } => {
                if chain_head_seq > anchor_head_seq {
                    write!(
                        f,
                        "세션 {session}의 체인이 앵커보다 김. 앵커(seq {anchor_seq})는 head {anchor_head_seq}, 체인은 head {chain_head_seq}. 앵커 이후 덧붙이기 의심"
                    )
                } else {
                    write!(
                        f,
                        "세션 {session}의 head가 앵커와 다름. 앵커(seq {anchor_seq})는 {anchor_head_seq}/{anchor_head_hash}, 체인은 {chain_head_seq}/{chain_head_hash}. 체인 재계산 의심"
                    )
                }
            }
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AnchorFailure {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorWarning {
    ClockWentBackwards { seq: u64, prev_ts: u64, ts: u64 },
    SessionReanchored { session: SessionId, count: u64 },
}

impl fmt::Display for AnchorWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClockWentBackwards { seq, prev_ts, ts } => write!(
                f,
                "앵커 seq {seq}에서 벽시계가 역행 ({prev_ts} -> {ts}). 시각 조정 가능성"
            ),
            Self::SessionReanchored { session, count } => write!(
                f,
                "세션 {session}이 {count}번 앵커됨. 중간 체크포인트로 판단"
            ),
        }
    }
}

#[derive(Debug)]
pub struct AnchorReport {
    pub entries: u64,
    pub sessions: u64,
    pub head_seq: u64,
    pub head_hash: Hash,
    pub warnings: Vec<AnchorWarning>,
}

impl AnchorReport {
    pub fn is_clean(&self) -> bool {
        self.warnings.is_empty()
    }
}

/// 세션 체인의 실제 head 를 앵커 기록과 대조한 결과.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorCheck {
    /// 이 세션의 앵커 줄이 없습니다. 통과가 아니라 탐지 불가입니다
    Missing,
    /// 앵커가 가리키는 head 와 세션 체인의 head 가 일치합니다
    Matches { anchor_seq: u64 },
}

/// 앵커 체인 자체의 무결성을 검증합니다.
///
/// # Errors
/// 앵커 파일이 없거나, 줄이 손상되었거나, 연결·해시·세션 규칙을 어기면 실패합니다.
pub fn verify_anchors(dir: &Path) -> Result<AnchorReport, AnchorFailure> {
    let reader = open_anchors(dir)?;
    scan(reader, |_| {})
}

/// 앵커 체인을 검증하고 모든 줄을 등장 순으로 돌려줍니다.
///
/// 세션 디렉토리 목록과 대조해 **앵커에는 있는데 디렉토리가 없는 세션**을 찾을 때 씁니다.
/// 세션 통째 삭제는 남은 세션만 훑어서는 보이지 않고, 이 방향으로 봐야만 드러납니다.
///
/// # Errors
/// 앵커 체인 검증이 실패하면 그 사유를 그대로 돌려줍니다. 깨진 체인에서 꺼낸 목록으로
/// 대조하면 없는 보증을 만들어 냅니다.
pub fn read_anchors(dir: &Path) -> Result<Vec<AnchorEntry>, AnchorFailure> {
    let reader = open_anchors(dir)?;
    let mut out: Vec<AnchorEntry> = Vec::new();
    scan(reader, |e| out.push(e.clone()))?;
    Ok(out)
}

/// 세션 하나의 앵커 기록을 찾습니다. 여러 번 앵커된 세션은 가장 나중 줄을 돌려줍니다.
///
/// 조회 전에 앵커 체인 전체를 검증합니다. 깨진 체인에서 꺼낸 값으로 대조하면 없는 보증을
/// 만들어 내기 때문입니다.
///
/// # Errors
/// 앵커 체인 검증이 실패하면 그 사유를 그대로 돌려줍니다.
pub fn lookup(dir: &Path, session: &SessionId) -> Result<Option<AnchorEntry>, AnchorFailure> {
    let reader = open_anchors(dir)?;
    let mut found: Option<AnchorEntry> = None;
    scan(reader, |e| {
        if e.session == *session {
            found = Some(e.clone());
        }
    })?;
    Ok(found)
}

/// 세션 체인의 실제 head 를 앵커 기록과 대조합니다.
///
/// # Arguments
/// `dir` - 앵커 루트
/// `session` - 대조할 세션 식별자
/// `head_seq` - 세션 체인에서 실제로 관측한 마지막 seq
/// `head_hash` - 세션 체인에서 실제로 관측한 마지막 hash
///
/// # Errors
/// 앵커 체인이 깨졌거나, 앵커가 가리키는 head 와 실제 head 가 다르면 실패합니다. 체인이
/// 앵커보다 긴 경우도 실패입니다. 앵커는 세션 종료 시점에 쓰므로 그 뒤에 자란 체인은 종료
/// 후 덧붙이기를 뜻합니다.
pub fn check_session(
    dir: &Path,
    session: &SessionId,
    head_seq: u64,
    head_hash: &Hash,
) -> Result<AnchorCheck, AnchorFailure> {
    match lookup(dir, session)? {
        None => Ok(AnchorCheck::Missing),
        Some(a) if a.head_seq == head_seq && a.head_hash == *head_hash => {
            Ok(AnchorCheck::Matches { anchor_seq: a.seq })
        }
        Some(a) => Err(AnchorFailure::SessionHeadMismatch {
            session: *session,
            anchor_seq: a.seq,
            anchor_head_seq: a.head_seq,
            anchor_head_hash: a.head_hash,
            chain_head_seq: head_seq,
            chain_head_hash: *head_hash,
        }),
    }
}

fn open_anchors(dir: &Path) -> Result<BufReader<File>, AnchorFailure> {
    let path = dir.join(ANCHOR_FILE);
    match File::open(&path) {
        Ok(f) => Ok(BufReader::new(f)),
        Err(e) if e.kind() == ErrorKind::NotFound => Err(AnchorFailure::FileAbsent),
        Err(e) => Err(AnchorFailure::Io(Error::io(&path, e))),
    }
}

fn scan<R: BufRead>(
    mut reader: R,
    mut on_entry: impl FnMut(&AnchorEntry),
) -> Result<AnchorReport, AnchorFailure> {
    let mut line_no: u64 = 0;
    let mut expected_seq: u64 = 0;
    let mut prev_hash = Hash::ZERO;
    let mut last_ts: u64 = 0;
    let mut last_seq: u64 = 0;
    let mut entry_count: u64 = 0;
    let mut warnings: Vec<AnchorWarning> = Vec::new();

    // 세션 -> (첫 등장 seq, 마지막 head_seq, 등장 횟수)
    let mut seen: HashMap<SessionId, (u64, u64, u64)> = HashMap::new();
    let mut order: Vec<SessionId> = Vec::new();

    let mut buf = String::new();
    loop {
        buf.clear();
        let read = reader
            .read_line(&mut buf)
            .map_err(|e| AnchorFailure::Io(Error::io(ANCHOR_FILE, e)))?;
        if read == 0 {
            break;
        }
        let ended_with_newline = buf.ends_with('\n');
        let trimmed = buf.trim_end_matches(['\n', '\r']);
        line_no = line_no.saturating_add(1);

        if !ended_with_newline {
            return Err(AnchorFailure::TruncatedFinalLine { line: line_no });
        }
        if trimmed.trim().is_empty() {
            return Err(AnchorFailure::BlankLine { line: line_no });
        }

        let entry: AnchorEntry =
            serde_json::from_str(trimmed).map_err(|e| AnchorFailure::MalformedLine {
                line: line_no,
                detail: e.to_string(),
            })?;

        // 감사 체인과 같은 이유로 해시 검사보다 먼저 봅니다
        if entry.v != ANCHOR_VERSION {
            return Err(AnchorFailure::FormatVersionUnsupported {
                seq: entry.seq,
                got: entry.v,
            });
        }

        if entry.seq != expected_seq {
            return Err(AnchorFailure::SeqGap {
                expected: expected_seq,
                got: entry.seq,
            });
        }

        if entry.seq == 0 {
            if !entry.prev.is_zero() {
                return Err(AnchorFailure::GenesisPrevNotZero { got: entry.prev });
            }
        } else if entry.prev != prev_hash {
            return Err(AnchorFailure::PrevMismatch {
                seq: entry.seq,
                expected: prev_hash,
                got: entry.prev,
            });
        }

        let recomputed = entry.recompute_hash();
        if recomputed != entry.hash {
            return Err(AnchorFailure::HashMismatch {
                seq: entry.seq,
                expected: recomputed,
                got: entry.hash,
            });
        }

        match seen.get_mut(&entry.session) {
            None => {
                seen.insert(entry.session, (entry.seq, entry.head_seq, 1));
                order.push(entry.session);
            }
            Some((first_seq, last_head_seq, count)) => {
                if entry.head_seq == *last_head_seq {
                    return Err(AnchorFailure::SessionDuplicated {
                        seq: entry.seq,
                        session: entry.session,
                        first_seq: *first_seq,
                    });
                }
                if entry.head_seq < *last_head_seq {
                    return Err(AnchorFailure::HeadSeqRegressed {
                        seq: entry.seq,
                        session: entry.session,
                        previous: *last_head_seq,
                        got: entry.head_seq,
                    });
                }
                *last_head_seq = entry.head_seq;
                *count = count.saturating_add(1);
            }
        }

        if entry.seq > 0 && entry.ts < last_ts {
            warnings.push(AnchorWarning::ClockWentBackwards {
                seq: entry.seq,
                prev_ts: last_ts,
                ts: entry.ts,
            });
        }

        on_entry(&entry);

        prev_hash = entry.hash;
        last_ts = entry.ts;
        last_seq = entry.seq;
        expected_seq = entry.seq.saturating_add(1);
        entry_count = entry_count.saturating_add(1);
    }

    if entry_count == 0 {
        return Err(AnchorFailure::ChainEmpty);
    }

    // HashMap 순회 순서는 실행마다 달라집니다. 보고가 재현 가능해야 하므로 등장 순으로 냅니다
    for session in &order {
        if let Some((_, _, count)) = seen.get(session)
            && *count > 1
        {
            warnings.push(AnchorWarning::SessionReanchored {
                session: *session,
                count: *count,
            });
        }
    }

    Ok(AnchorReport {
        entries: entry_count,
        sessions: seen.len() as u64,
        head_seq: last_seq,
        head_hash: prev_hash,
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
            "airlock-anchor-unit-{name}-{}-{}",
            std::process::id(),
            now_unix_nanos()
        ));
        p
    }

    fn sample(seq: u64, session: u8, head_seq: u64, prev: Hash) -> AnchorEntry {
        AnchorEntry::seal(
            seq,
            1_700_000_000_000_000_000,
            SessionId::from_bytes([session; 16]),
            head_seq,
            Hash::from_bytes([head_seq as u8; 32]),
            prev,
        )
    }

    #[test]
    fn sealed_anchor_verifies() {
        let a = sample(0, 1, 4, Hash::ZERO);
        assert!(a.hash_is_valid());
        assert_eq!(a.v, ANCHOR_VERSION);
    }

    #[test]
    fn every_hashed_field_changes_the_hash() {
        let base = sample(0, 1, 4, Hash::ZERO);

        let mut v = base.clone();
        v.v = 2;
        assert_ne!(v.recompute_hash(), base.hash);

        let mut seq = base.clone();
        seq.seq = 1;
        assert_ne!(seq.recompute_hash(), base.hash);

        let mut ts = base.clone();
        ts.ts = base.ts + 1;
        assert_ne!(ts.recompute_hash(), base.hash);

        let mut session = base.clone();
        session.session = SessionId::from_bytes([9; 16]);
        assert_ne!(session.recompute_hash(), base.hash);

        let mut head_seq = base.clone();
        head_seq.head_seq = 5;
        assert_ne!(head_seq.recompute_hash(), base.hash);

        let mut head_hash = base.clone();
        head_hash.head_hash = Hash::from_bytes([0xEE; 32]);
        assert_ne!(head_hash.recompute_hash(), base.hash);

        let mut prev = base.clone();
        prev.prev = Hash::from_bytes([7; 32]);
        assert_ne!(prev.recompute_hash(), base.hash);
    }

    #[test]
    fn rfc3339_is_not_hashed() {
        let mut a = sample(0, 1, 4, Hash::ZERO);
        a.ts_rfc3339 = "1999-01-01T00:00:00.000000000Z".into();
        assert!(a.hash_is_valid());
    }

    #[test]
    fn anchor_domain_differs_from_audit_domain() {
        assert_ne!(ANCHOR_DOMAIN, crate::DOMAIN);

        // 같은 값들을 감사 엔트리 도메인으로 계산하면 다른 바이트가 나와야 합니다.
        // 교차 프로토콜로 한쪽 해시를 다른 쪽에 먹일 수 없어야 합니다
        let a = sample(0, 1, 4, Hash::ZERO);
        let mut enc = Encoder::with_domain(crate::DOMAIN);
        enc.u32(a.v)
            .u64(a.seq)
            .bytes(a.prev.as_bytes())
            .u64(a.ts)
            .bytes(a.session.as_bytes())
            .u64(a.head_seq)
            .bytes(a.head_hash.as_bytes());
        let cross = Sha256::digest(enc.as_slice());
        assert_ne!(cross.as_slice(), a.hash.as_bytes().as_slice());
    }

    #[test]
    fn anchor_line_without_v_is_malformed_not_legacy() {
        let a = sample(0, 1, 4, Hash::ZERO);
        let mut value: serde_json::Value = serde_json::to_value(&a).unwrap();
        value.as_object_mut().unwrap().remove("v");
        assert!(
            serde_json::from_value::<AnchorEntry>(value).is_err(),
            "존재한 적 없는 옛 앵커 포맷을 만들어 주면 안 됨"
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let a = sample(0, 1, 4, Hash::ZERO);
        let mut value: serde_json::Value = serde_json::to_value(&a).unwrap();
        value["injected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AnchorEntry>(value).is_err());
    }

    #[test]
    fn append_links_and_persists() {
        let dir = scratch("append");
        let mut log = AnchorLog::open(&dir).unwrap();
        assert_eq!(log.head_seq(), None);

        let a = log
            .append(SessionId::from_bytes([1; 16]), 4, Hash::from_bytes([4; 32]))
            .unwrap();
        let b = log
            .append(SessionId::from_bytes([2; 16]), 9, Hash::from_bytes([9; 32]))
            .unwrap();

        assert_eq!(a.seq, 0);
        assert!(a.prev.is_zero());
        assert_eq!(b.prev, a.hash);
        assert_eq!(log.head_seq(), Some(1));
        assert_eq!(log.head_hash(), b.hash);

        let report = verify_anchors(&dir).unwrap();
        assert_eq!(report.entries, 2);
        assert_eq!(report.sessions, 2);
        assert!(report.is_clean(), "{:?}", report.warnings);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reopen_continues_the_chain() {
        let dir = scratch("reopen");
        {
            let mut log = AnchorLog::open(&dir).unwrap();
            log.append(SessionId::from_bytes([1; 16]), 4, Hash::from_bytes([4; 32]))
                .unwrap();
        }
        let mut log = AnchorLog::open(&dir).unwrap();
        assert_eq!(log.head_seq(), Some(0));
        let b = log
            .append(SessionId::from_bytes([2; 16]), 1, Hash::from_bytes([1; 32]))
            .unwrap();
        assert_eq!(b.seq, 1);
        assert!(verify_anchors(&dir).is_ok());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        let mut log = AnchorLog::open(&dir).unwrap();
        log.append(SessionId::from_bytes([1; 16]), 0, Hash::ZERO)
            .unwrap();

        let dmode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, crate::log::DIR_MODE);
        let fmode = fs::metadata(dir.join(ANCHOR_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(fmode, FILE_MODE);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_reported_as_undetectable() {
        let dir = scratch("absent");
        fs::create_dir_all(&dir).unwrap();
        let err = verify_anchors(&dir).unwrap_err();
        assert!(matches!(err, AnchorFailure::FileAbsent), "{err}");
        assert!(err.to_string().contains("탐지할 수 없음"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_file_is_rejected() {
        let dir = scratch("empty");
        AnchorLog::open(&dir).unwrap();
        let err = verify_anchors(&dir).unwrap_err();
        assert!(matches!(err, AnchorFailure::ChainEmpty), "{err}");

        fs::remove_dir_all(&dir).ok();
    }
}
