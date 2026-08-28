//! 이 모듈은 감사 로그의 매일 이상여부 점검 보고를 만듭니다.
//!
//! # Features
//! 대한민국 전자금융감독규정 시행세칙 별표 7 의 16번이 요구하는 "원격으로 접속하여
//! 수행한 모든 작업 내역을 기록하고 **매일 이상여부 점검** 실시" 의 실물입니다. cron 이나
//! launchd 에 그대로 걸 수 있도록 종료 코드가 판정을 담습니다.
//!
//! 이 모듈은 사실만 모읍니다. 세션마다 무결성과 앵커 대조와 결정 집계와 승인 집계와 거부된
//! exec 과 목적지별 아웃바운드를 모으고, 그 위에서 **이상 목록**을 만듭니다. 렌더링은
//! 사람용과 JSON 두 갈래이며 둘은 같은 사실을 담습니다.
//!
//! # 판단 불가는 통과가 아니다
//! 앵커 없음, 세션을 읽지 못함, 확인 체인 손상은 전부 이상으로 셉니다. 매일 점검의 목적이
//! 탐지인데 탐지 불가를 통과로 보고하면 점검이 거짓 보증을 합니다. 같은 이유로 앵커에는
//! 있는데 디렉토리가 없는 세션도 이상입니다. 남은 세션만 훑으면 세션 통째 삭제가 "이상
//! 없음" 으로 보고됩니다.
//!
//! # 상한
//! 사람용 출력은 목록에 상한을 두지만 상한이 걸린 사실 자체를 반드시 함께 찍습니다. 조용한
//! 절단은 "전부 점검했다" 로 읽힙니다. JSON 과 다이제스트는 절단하지 않습니다.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use airlock_audit::{
    AnchorCheck, AnchorEntry, AnchorFailure, Decision, Entry, Event, Hash, Protocol, ReviewEntry,
    ReviewFailure, ReviewScope, ReviewSubject, SessionId, Verdict, Warning,
};
use airlock_canonical::Encoder;
use airlock_canonical::display::sanitize;

use crate::paths;

/// JSON 출력의 스키마 이름. 스키마가 바뀌면 이 값을 올립니다
pub const SCHEMA: &str = "airlock.audit-report.v1";

/// 리포트 본문 다이제스트의 도메인 분리 상수.
///
/// 확인 체인이 씌우는 `airlock.report.v1` 과 다릅니다. 본문 다이제스트는 범위와 묶이기
/// 전의 중간값이라, 같은 도메인을 쓰면 한쪽을 다른 쪽 자리에 밀어 넣을 수 있습니다
pub const BODY_DOMAIN: &[u8] = b"airlock.report-body.v1\x00";

/// 사람용 출력에서 보여 줄 반출 상위 목적지 수
pub const TOP_DESTINATIONS: usize = 10;

/// 사람용 출력에서 세션마다 보여 줄 목록 항목 수
pub const MAX_LISTED: usize = 20;

/// 종료 코드. 증거 자체를 믿을 수 없는 이상
pub const EXIT_EVIDENCE: i32 = 2;

/// 종료 코드. 증거는 온전하나 운영상 이상
pub const EXIT_OPERATIONAL: i32 = 3;

/// 이상의 등급.
///
/// 둘을 하나로 합치지 않는 이유는 대응이 다르기 때문입니다. 증거 이상은 로그 자체를 믿을 수
/// 없다는 뜻이라 즉시 사람이 붙어야 하고, 운영 이상은 로그는 믿을 수 있는데 그 안에 답하지
/// 않은 승인 같은 것이 있다는 뜻입니다
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// 증거를 믿을 수 없음. 종료 코드 [`EXIT_EVIDENCE`]
    Evidence,
    /// 증거는 온전하나 운영상 이상. 종료 코드 [`EXIT_OPERATIONAL`]
    Operational,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::Operational => "operational",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Evidence => "증거",
            Self::Operational => "운영",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Anomaly {
    pub severity: Severity,
    /// 기계가 분류할 수 있게 두는 고정 문자열
    pub kind: &'static str,
    /// 어느 세션의 이상인지. 세션과 무관하면 `None`
    pub session: Option<String>,
    pub detail: String,
}

/// UTC 날짜 하나가 덮는 나노초 구간.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub from: u64,
    pub to: u64,
}

impl Default for Range {
    fn default() -> Self {
        Self {
            from: 0,
            to: u64::MAX,
        }
    }
}

impl Range {
    pub fn contains(&self, ts: u64) -> bool {
        ts >= self.from && ts <= self.to
    }
}

const NANOS_PER_DAY: u64 = 86_400 * 1_000_000_000;

/// `YYYY-MM-DD` 를 그 날 00:00:00 UTC 의 유닉스 나노초로 바꿉니다.
///
/// # Arguments
/// `s` - 날짜 문자열
///
/// # Errors
/// 형식이 다르거나 실재하지 않는 날짜면 `None` 입니다. 관대하게 받아들이면 사람이 의도한
/// 범위와 실제로 점검한 범위가 달라집니다.
pub fn parse_date(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    if !b.iter().enumerate().all(|(i, c)| {
        if i == 4 || i == 7 {
            true
        } else {
            c.is_ascii_digit()
        }
    }) {
        return None;
    }
    let y: i64 = s.get(0..4)?.parse().ok()?;
    let m: u32 = s.get(5..7)?.parse().ok()?;
    let d: u32 = s.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&m) || d < 1 || d > days_in_month(y, m) {
        return None;
    }
    // 1970 이전은 유닉스 나노초로 표현할 수 없습니다. 음수를 u64 로 접으면 아득히 먼
    // 미래가 되어 범위가 조용히 뒤집힙니다
    let days = days_from_civil(y, m, d);
    if days < 0 {
        return None;
    }
    u64::try_from(days).ok()?.checked_mul(NANOS_PER_DAY)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// 그레고리력 날짜를 유닉스 에폭 기준 일수로 바꿉니다.
///
/// `airlock-audit` 의 `civil_from_days` 와 짝이 되는 방향이며 같은 알고리즘을 씁니다.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let m = i64::from(m);
    let d = i64::from(d);
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// 점검 범위를 만듭니다.
///
/// `since` 는 그 날 00:00:00 UTC 부터, `until` 은 그 날 23:59:59.999999999 UTC 까지
/// 포함합니다. 하루를 통째로 덮지 않으면 자정 근처 세션이 어느 날의 점검에도 들어가지
/// 않습니다.
///
/// # Arguments
/// `since` - 시작 날짜
/// `until` - 끝 날짜
///
/// # Errors
/// 날짜 형식이 잘못되었거나 `since` 가 `until` 보다 뒤면 그 사유를 냅니다.
pub fn range_of(since: Option<&str>, until: Option<&str>) -> Result<Range, String> {
    let from = match since {
        None => 0,
        Some(s) => parse_date(s)
            .ok_or_else(|| format!("--since `{}` 를 YYYY-MM-DD 로 읽을 수 없음", sanitize(s)))?,
    };
    let to = match until {
        None => u64::MAX,
        Some(s) => {
            let start = parse_date(s).ok_or_else(|| {
                format!("--until `{}` 를 YYYY-MM-DD 로 읽을 수 없음", sanitize(s))
            })?;
            start
                .checked_add(NANOS_PER_DAY)
                .and_then(|v| v.checked_sub(1))
                .ok_or_else(|| format!("--until `{}` 가 표현 범위를 넘음", sanitize(s)))?
        }
    };
    if from > to {
        return Err("--since 가 --until 보다 뒤임. 아무 세션도 덮지 않는 범위임".to_string());
    }
    Ok(Range { from, to })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decisions {
    pub allow: u64,
    pub deny: u64,
    pub ask: u64,
    pub forbid: u64,
}

impl Decisions {
    fn count(&mut self, d: Decision) {
        match d {
            Decision::Allow => self.allow = self.allow.saturating_add(1),
            Decision::Deny => self.deny = self.deny.saturating_add(1),
            Decision::Ask => self.ask = self.ask.saturating_add(1),
            Decision::Forbid => self.forbid = self.forbid.saturating_add(1),
        }
    }

    pub fn blocked(&self) -> u64 {
        self.deny.saturating_add(self.forbid)
    }
}

/// 승인 집계.
///
/// `identified` 와 `unidentified` 를 반드시 나눕니다. 신원 없는 응답은 `--yes` 자동 승인이거나
/// 신원을 관측하지 못한 채널이며, 그것을 사람 승인과 같은 칸에 넣으면 감사 로그가 거짓
/// 보증을 합니다.
///
/// `auto_granted` 를 따로 두는 이유는 신원 없는 **거부**가 위험이 아니기 때문입니다. 아무것도
/// 통과하지 않았으므로 그것까지 이상으로 세면 진짜 이상이 소음에 묻힙니다
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Approvals {
    pub identified: u64,
    pub unidentified: u64,
    /// 신원 없이 허용된 건. `--strict-approval` 이 이상으로 세는 것
    pub auto_granted: u64,
    pub approved: u64,
    pub refused: u64,
    pub timed_out: u64,
    pub unanswered: u64,
}

#[derive(Debug, Clone)]
pub struct DeniedExec {
    pub program: String,
    pub argv: Vec<String>,
    pub rule: Option<String>,
    pub count: u64,
}

/// 목적지 하나에 대한 아웃바운드 사실.
#[derive(Debug, Clone)]
pub struct Destination {
    pub host: String,
    pub port: u16,
    pub protocol: &'static str,
    pub attempts: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub asked: u64,
    /// `EgressSummary` 가 남은 연결 수. 시도 수보다 작으면 결과를 모르는 연결이 있다는 뜻
    pub completed: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub duration_ms: u64,
}

impl Destination {
    fn key(&self) -> (String, u16, &'static str) {
        (self.host.clone(), self.port, self.protocol)
    }
}

#[derive(Debug, Clone)]
pub enum Integrity {
    Ok {
        entries: u64,
        head_seq: u64,
        head_hash: Hash,
    },
    Failed {
        detail: String,
    },
}

#[derive(Debug, Clone)]
pub enum AnchorState {
    Matches { anchor_seq: u64 },
    Missing,
    Mismatch { detail: String },
    ChainAbsent,
    ChainBroken,
}

impl AnchorState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Matches { .. } => "matches",
            Self::Missing => "missing",
            Self::Mismatch { .. } => "mismatch",
            Self::ChainAbsent => "chain_absent",
            Self::ChainBroken => "chain_broken",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionReport {
    pub dir: PathBuf,
    pub name: String,
    pub session: Option<SessionId>,
    pub started_ts: u64,
    pub integrity: Integrity,
    pub read_problem: Option<String>,
    pub anchor: AnchorState,
    pub warnings: Vec<String>,
    pub decisions: Decisions,
    pub approvals: Approvals,
    pub denied_exec: Vec<DeniedExec>,
    pub destinations: Vec<Destination>,
    pub anomalies: Vec<Anomaly>,
}

#[derive(Debug, Clone)]
pub enum ChainState {
    Ok {
        entries: u64,
        sessions: u64,
        head_seq: u64,
        warnings: Vec<String>,
    },
    Absent,
    Broken {
        detail: String,
    },
}

impl ChainState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok { .. } => "ok",
            Self::Absent => "absent",
            Self::Broken { .. } => "broken",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReviewState {
    /// `reviews.jsonl` 이 없음. 확인 기록 없음
    None,
    Ok {
        last: Box<ReviewEntry>,
        warnings: Vec<String>,
    },
    Broken {
        detail: String,
    },
}

impl ReviewState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Ok { .. } => "ok",
            Self::Broken { .. } => "broken",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Totals {
    pub sessions: u64,
    pub unreadable: u64,
    pub blocked: u64,
    pub asked: u64,
    pub identified_approvals: u64,
    pub unidentified_approvals: u64,
    pub auto_granted: u64,
    pub unanswered_asks: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub destinations: Vec<Destination>,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub root: PathBuf,
    pub anchor_dir: PathBuf,
    pub since: Option<String>,
    pub until: Option<String>,
    pub strict_approval: bool,
    pub generated_ts: u64,
    pub chain: ChainState,
    pub review: ReviewState,
    /// 마지막 확인 이후에 시작된 세션 수. 매일 점검이 밀렸는지를 보는 값
    pub sessions_after_review: u64,
    pub sessions: Vec<SessionReport>,
    pub totals: Totals,
    pub anomalies: Vec<Anomaly>,
}

impl Report {
    /// 감사 루트를 훑어 점검 보고를 만듭니다.
    ///
    /// # Arguments
    /// `root` - 감사 루트
    /// `anchor_dir` - 앵커와 확인 체인이 있는 디렉토리
    /// `since` - 시작 날짜 문자열. 기록에 그대로 남습니다
    /// `until` - 끝 날짜 문자열
    /// `range` - 위 두 값에서 만든 나노초 구간
    /// `strict_approval` - 자동 승인을 이상으로 셀지 여부
    pub fn build(
        root: &Path,
        anchor_dir: &Path,
        since: Option<String>,
        until: Option<String>,
        range: Range,
        strict_approval: bool,
    ) -> Self {
        let mut anomalies: Vec<Anomaly> = Vec::new();

        let (chain, anchors) = read_chain(anchor_dir, &mut anomalies);
        let chain_usable = matches!(chain, ChainState::Ok { .. });

        let mut sessions: Vec<SessionReport> = Vec::new();
        let mut seen: HashSet<SessionId> = HashSet::new();
        for dir in paths::all_sessions(root) {
            let report = build_session(&dir, anchor_dir, &chain, range, strict_approval);
            let Some(report) = report else { continue };
            if let Some(id) = report.session {
                seen.insert(id);
            }
            sessions.push(report);
        }

        // 앵커에는 있는데 디렉토리가 없는 세션을 찾습니다. 남은 세션만 훑어서는 세션 통째
        // 삭제가 "이상 없음" 으로 보고됩니다
        if chain_usable {
            for a in &anchors {
                if !range.contains(a.ts) || seen.contains(&a.session) {
                    continue;
                }
                anomalies.push(Anomaly {
                    severity: Severity::Evidence,
                    kind: "session_missing",
                    session: Some(a.session.to_hex()),
                    detail: format!(
                        "앵커 seq {}가 가리키는 세션의 디렉토리가 {} 아래에 없음. \
                         세션 통째 삭제이거나 앵커 루트가 다른 감사 루트의 것임",
                        a.seq,
                        root.display()
                    ),
                });
            }
        }

        for s in &sessions {
            anomalies.extend(s.anomalies.iter().cloned());
        }

        let totals = totals_of(&sessions);
        let (review, sessions_after_review) = read_review(anchor_dir, &sessions, &mut anomalies);

        // 보고가 재현 가능해야 하므로 등급, 세션, 종류 순으로 고정합니다
        anomalies.sort_by(|a, b| {
            a.severity
                .cmp(&b.severity)
                .then_with(|| a.session.cmp(&b.session))
                .then_with(|| a.kind.cmp(b.kind))
                .then_with(|| a.detail.cmp(&b.detail))
        });

        Self {
            root: root.to_path_buf(),
            anchor_dir: anchor_dir.to_path_buf(),
            since,
            until,
            strict_approval,
            generated_ts: airlock_audit::now_unix_nanos(),
            chain,
            review,
            sessions_after_review,
            sessions,
            totals,
            anomalies,
        }
    }

    /// 이 리포트가 덮는 범위.
    pub fn scope(&self) -> ReviewScope {
        ReviewScope::new(
            self.since.clone(),
            self.until.clone(),
            self.sessions.iter().filter_map(|s| s.session),
        )
    }

    /// 리포트 본문의 다이제스트.
    ///
    /// 생성 시각은 들어가지 않습니다. 들어가면 같은 사실을 두 번 계산할 때마다 값이 달라져
    /// 확인 도장이 어떤 리포트도 가리키지 못합니다
    pub fn body_digest(&self) -> Hash {
        let mut enc = Encoder::with_domain(BODY_DOMAIN);
        enc.str(&self.root.to_string_lossy())
            .str(&self.anchor_dir.to_string_lossy())
            .opt_str(self.since.as_deref())
            .opt_str(self.until.as_deref())
            .bool(self.strict_approval)
            .str(self.chain.as_str())
            .u64(self.sessions.len() as u64);

        for s in &self.sessions {
            enc.str(&s.name)
                .opt_str(s.session.map(|v| v.to_hex()).as_deref())
                .u64(s.started_ts)
                .str(s.anchor.as_str());
            match &s.integrity {
                Integrity::Ok {
                    entries,
                    head_seq,
                    head_hash,
                } => {
                    enc.tag(1).u64(*entries).u64(*head_seq);
                    enc.bytes(head_hash.as_bytes());
                }
                Integrity::Failed { detail } => {
                    enc.tag(2).str(detail);
                }
            }
            enc.u64(s.decisions.allow)
                .u64(s.decisions.deny)
                .u64(s.decisions.ask)
                .u64(s.decisions.forbid)
                .u64(s.approvals.identified)
                .u64(s.approvals.unidentified)
                .u64(s.approvals.auto_granted)
                .u64(s.approvals.approved)
                .u64(s.approvals.refused)
                .u64(s.approvals.timed_out)
                .u64(s.approvals.unanswered)
                .u64(s.denied_exec.len() as u64);
            for e in &s.denied_exec {
                enc.str(&e.program).list_str(&e.argv).u64(e.count);
            }
            enc.u64(s.destinations.len() as u64);
            for d in &s.destinations {
                enc.str(&d.host)
                    .u32(u32::from(d.port))
                    .str(d.protocol)
                    .u64(d.attempts)
                    .u64(d.allowed)
                    .u64(d.blocked)
                    .u64(d.asked)
                    .u64(d.completed)
                    .u64(d.bytes_out)
                    .u64(d.bytes_in);
            }
        }

        enc.u64(self.anomalies.len() as u64);
        for a in &self.anomalies {
            enc.str(a.severity.as_str())
                .str(a.kind)
                .opt_str(a.session.as_deref())
                .str(&a.detail);
        }

        airlock_audit::sha256(enc.as_slice())
    }

    /// 확인 도장이 가리킬 대상.
    pub fn subject(&self) -> ReviewSubject {
        ReviewSubject::seal(self.scope(), self.body_digest())
    }

    /// 판정. 이상이 하나라도 있으면 [`Verdict::Anomalous`] 입니다
    pub fn verdict(&self) -> Verdict {
        if self.anomalies.is_empty() {
            Verdict::Clean
        } else {
            Verdict::Anomalous
        }
    }

    /// 종료 코드.
    ///
    /// 0 은 이상 없음이고, 증거 이상이 하나라도 있으면 [`EXIT_EVIDENCE`], 증거는 온전한데
    /// 운영 이상만 있으면 [`EXIT_OPERATIONAL`] 입니다
    pub fn exit_code(&self) -> i32 {
        if self
            .anomalies
            .iter()
            .any(|a| a.severity == Severity::Evidence)
        {
            return EXIT_EVIDENCE;
        }
        if self.anomalies.is_empty() {
            0
        } else {
            EXIT_OPERATIONAL
        }
    }
}

fn read_chain(anchor_dir: &Path, anomalies: &mut Vec<Anomaly>) -> (ChainState, Vec<AnchorEntry>) {
    match airlock_audit::verify_anchors(anchor_dir) {
        Ok(report) => {
            let entries = airlock_audit::read_anchors(anchor_dir).unwrap_or_default();
            (
                ChainState::Ok {
                    entries: report.entries,
                    sessions: report.sessions,
                    head_seq: report.head_seq,
                    warnings: report.warnings.iter().map(ToString::to_string).collect(),
                },
                entries,
            )
        }
        // 앵커 파일이 없는 것은 통과가 아니라 탐지 불가입니다. 세션 통째 삭제와 체인
        // 재계산을 알아낼 방법이 없다는 뜻이므로 매일 점검은 이것을 이상으로 셉니다
        Err(AnchorFailure::FileAbsent) => {
            anomalies.push(Anomaly {
                severity: Severity::Evidence,
                kind: "anchor_absent",
                session: None,
                detail: format!(
                    "{} 없음. 세션 통째 삭제와 체인 재계산을 탐지할 수 없음. 통과가 아님",
                    anchor_dir.join(airlock_audit::ANCHOR_FILE).display()
                ),
            });
            (ChainState::Absent, Vec::new())
        }
        Err(failure) => {
            let detail = failure.to_string();
            anomalies.push(Anomaly {
                severity: Severity::Evidence,
                kind: "anchor_chain_broken",
                session: None,
                detail: detail.clone(),
            });
            (ChainState::Broken { detail }, Vec::new())
        }
    }
}

fn read_review(
    anchor_dir: &Path,
    sessions: &[SessionReport],
    anomalies: &mut Vec<Anomaly>,
) -> (ReviewState, u64) {
    match airlock_audit::verify_reviews(anchor_dir) {
        Ok(report) => {
            let warnings: Vec<String> = report.warnings.iter().map(ToString::to_string).collect();
            match report.last {
                None => (ReviewState::None, sessions.len() as u64),
                Some(last) => {
                    let after = sessions
                        .iter()
                        .filter(|s| s.started_ts > last.ts)
                        .count()
                        .try_into()
                        .unwrap_or(u64::MAX);
                    (
                        ReviewState::Ok {
                            last: Box::new(last),
                            warnings,
                        },
                        after,
                    )
                }
            }
        }
        // 확인 기록이 아예 없는 것은 변조가 아닙니다. 아직 아무도 점검하지 않았다는 사실을
        // 그대로 보고하고 종료 코드는 올리지 않습니다
        Err(ReviewFailure::FileAbsent) => (ReviewState::None, sessions.len() as u64),
        Err(failure) => {
            let detail = failure.to_string();
            anomalies.push(Anomaly {
                severity: Severity::Evidence,
                kind: "review_chain_broken",
                session: None,
                detail: detail.clone(),
            });
            (ReviewState::Broken { detail }, sessions.len() as u64)
        }
    }
}

/// 세션 디렉토리 이름 앞의 나노초. 체인을 읽지 못한 세션의 시각 추정에 씁니다
fn ts_from_name(name: &str) -> u64 {
    name.split('-')
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

fn genesis_ts(entries: &[Entry]) -> Option<u64> {
    entries.first().map(|e| e.ts)
}

fn build_session(
    dir: &Path,
    anchor_dir: &Path,
    chain: &ChainState,
    range: Range,
    strict_approval: bool,
) -> Option<SessionReport> {
    let name = dir
        .file_name()
        .map(|n| sanitize(&n.to_string_lossy()))
        .unwrap_or_default();

    let mut anomalies: Vec<Anomaly> = Vec::new();
    let read = airlock_audit::read_entries_lossy(dir);

    let (entries, read_problem) = match read {
        Ok(v) => v,
        Err(e) => {
            // 읽지 못한 세션을 조용히 건너뛰면 못 읽는 것이 가장 값싼 은폐가 됩니다
            let started_ts = ts_from_name(&name);
            if !range.contains(started_ts) {
                return None;
            }
            anomalies.push(Anomaly {
                severity: Severity::Evidence,
                kind: "session_unreadable",
                session: Some(name.clone()),
                detail: format!("세션을 읽지 못함: {e}"),
            });
            return Some(SessionReport {
                dir: dir.to_path_buf(),
                name,
                session: None,
                started_ts,
                integrity: Integrity::Failed {
                    detail: e.to_string(),
                },
                read_problem: Some(e.to_string()),
                anchor: AnchorState::Missing,
                warnings: Vec::new(),
                decisions: Decisions::default(),
                approvals: Approvals::default(),
                denied_exec: Vec::new(),
                destinations: Vec::new(),
                anomalies,
            });
        }
    };

    let started_ts = genesis_ts(&entries).unwrap_or_else(|| ts_from_name(&name));
    if !range.contains(started_ts) {
        return None;
    }

    let session = entries.first().map(|e| e.session);

    if let Some(p) = &read_problem {
        anomalies.push(Anomaly {
            severity: Severity::Evidence,
            kind: "session_unreadable",
            session: Some(name.clone()),
            detail: sanitize(p),
        });
    }

    let mut warnings: Vec<String> = Vec::new();
    let integrity = match airlock_audit::verify_dir(dir) {
        Ok(v) => {
            for w in &v.warnings {
                warnings.push(w.to_string());
                if let Warning::UnansweredAsk { seq } = w {
                    anomalies.push(Anomaly {
                        severity: Severity::Operational,
                        kind: "unanswered_ask",
                        session: Some(name.clone()),
                        detail: format!("seq {seq}의 ask에 답이 없음. 승인 없이 끝난 요청임"),
                    });
                }
            }
            Integrity::Ok {
                entries: v.entries,
                head_seq: v.head_seq,
                head_hash: v.head_hash,
            }
        }
        Err(failure) => {
            let detail = failure.to_string();
            anomalies.push(Anomaly {
                severity: Severity::Evidence,
                kind: "integrity",
                session: Some(name.clone()),
                detail: detail.clone(),
            });
            Integrity::Failed { detail }
        }
    };

    let anchor = match (chain, session, &integrity) {
        (ChainState::Absent, _, _) => AnchorState::ChainAbsent,
        (ChainState::Broken { .. }, _, _) => AnchorState::ChainBroken,
        (
            ChainState::Ok { .. },
            Some(id),
            Integrity::Ok {
                head_seq,
                head_hash,
                ..
            },
        ) => match airlock_audit::check_session(anchor_dir, &id, *head_seq, head_hash) {
            Ok(AnchorCheck::Matches { anchor_seq }) => AnchorState::Matches { anchor_seq },
            Ok(AnchorCheck::Missing) => {
                anomalies.push(Anomaly {
                    severity: Severity::Evidence,
                    kind: "anchor_missing",
                    session: Some(name.clone()),
                    detail:
                        "이 세션의 앵커 줄이 없음. 삭제와 재계산을 탐지할 수 없으며 통과가 아님"
                            .to_string(),
                });
                AnchorState::Missing
            }
            Err(failure) => {
                let detail = failure.to_string();
                anomalies.push(Anomaly {
                    severity: Severity::Evidence,
                    kind: "anchor_mismatch",
                    session: Some(name.clone()),
                    detail: detail.clone(),
                });
                AnchorState::Mismatch { detail }
            }
        },
        // 체인을 읽지 못한 세션은 대조할 head 가 없습니다. 무결성 실패가 이미 이상으로
        // 올라가 있으므로 여기서 다시 세지 않습니다
        (ChainState::Ok { .. }, _, _) => AnchorState::Missing,
    };

    let mut decisions = Decisions::default();
    let mut approvals = Approvals::default();
    let mut denied: BTreeMap<(String, String), DeniedExec> = BTreeMap::new();
    let mut dests: HashMap<(String, u16, &'static str), Destination> = HashMap::new();
    let mut open_asks: HashSet<u64> = HashSet::new();

    for e in &entries {
        decisions.count(e.decision);
        if e.decision == Decision::Ask {
            open_asks.insert(e.seq);
        }
        match &e.event {
            Event::Approval {
                for_seq,
                granted,
                approver_uid,
                approver_tty,
                ..
            } => {
                open_asks.remove(for_seq);
                // 신원이 하나라도 관측된 승인만 사람 승인으로 셉니다. `--yes` 자동 승인은
                // 반드시 둘 다 없으므로 여기서 갈립니다
                let identified = approver_uid.is_some() || approver_tty.is_some();
                if identified {
                    approvals.identified = approvals.identified.saturating_add(1);
                } else {
                    approvals.unidentified = approvals.unidentified.saturating_add(1);
                }
                match granted {
                    airlock_audit::Granted::Approved => {
                        approvals.approved = approvals.approved.saturating_add(1);
                        if !identified {
                            approvals.auto_granted = approvals.auto_granted.saturating_add(1);
                        }
                    }
                    airlock_audit::Granted::Refused => {
                        approvals.refused = approvals.refused.saturating_add(1);
                    }
                    airlock_audit::Granted::TimedOut => {
                        approvals.timed_out = approvals.timed_out.saturating_add(1);
                    }
                }
            }
            Event::Exec { program, argv, .. }
                if matches!(e.decision, Decision::Deny | Decision::Forbid) =>
            {
                let program = sanitize(program);
                let argv: Vec<String> = argv.iter().map(|a| sanitize(a)).collect();
                let key = (program.clone(), argv.join("\u{0}"));
                let slot = denied.entry(key).or_insert_with(|| DeniedExec {
                    program,
                    argv,
                    rule: e.rule.as_deref().map(sanitize),
                    count: 0,
                });
                slot.count = slot.count.saturating_add(1);
            }
            Event::Egress {
                host,
                port,
                protocol,
            } => {
                let slot = destination(&mut dests, host, *port, *protocol);
                slot.attempts = slot.attempts.saturating_add(1);
                match e.decision {
                    Decision::Allow => slot.allowed = slot.allowed.saturating_add(1),
                    Decision::Ask => slot.asked = slot.asked.saturating_add(1),
                    Decision::Deny | Decision::Forbid => {
                        slot.blocked = slot.blocked.saturating_add(1);
                    }
                }
            }
            Event::EgressSummary {
                host,
                port,
                protocol,
                bytes_out,
                bytes_in,
                duration_ms,
            } => {
                let slot = destination(&mut dests, host, *port, *protocol);
                slot.completed = slot.completed.saturating_add(1);
                slot.bytes_out = slot.bytes_out.saturating_add(*bytes_out);
                slot.bytes_in = slot.bytes_in.saturating_add(*bytes_in);
                slot.duration_ms = slot.duration_ms.saturating_add(*duration_ms);
            }
            _ => {}
        }
    }

    approvals.unanswered = open_asks.len().try_into().unwrap_or(u64::MAX);
    if strict_approval && approvals.auto_granted > 0 {
        anomalies.push(Anomaly {
            severity: Severity::Operational,
            kind: "automatic_approval",
            session: Some(name.clone()),
            detail: format!(
                "{}건이 사람 신원 없이 허용됨. --yes 자동 승인이거나 신원을 관측하지 못한 채널임",
                approvals.auto_granted
            ),
        });
    }

    let mut destinations: Vec<Destination> = dests.into_values().collect();
    sort_destinations(&mut destinations);

    Some(SessionReport {
        dir: dir.to_path_buf(),
        name,
        session,
        started_ts,
        integrity,
        read_problem: read_problem.map(|p| sanitize(&p)),
        anchor,
        warnings,
        decisions,
        approvals,
        denied_exec: denied.into_values().collect(),
        destinations,
        anomalies,
    })
}

fn destination<'a>(
    dests: &'a mut HashMap<(String, u16, &'static str), Destination>,
    host: &str,
    port: u16,
    protocol: Protocol,
) -> &'a mut Destination {
    let host = sanitize(host);
    let protocol = protocol.as_str();
    dests
        .entry((host.clone(), port, protocol))
        .or_insert_with(|| Destination {
            host,
            port,
            protocol,
            attempts: 0,
            allowed: 0,
            blocked: 0,
            asked: 0,
            completed: 0,
            bytes_out: 0,
            bytes_in: 0,
            duration_ms: 0,
        })
}

/// 반출량이 많은 쪽을 앞에 둡니다. 같으면 이름으로 고정해 보고를 재현 가능하게 합니다
fn sort_destinations(v: &mut [Destination]) {
    v.sort_by(|a, b| {
        b.bytes_out
            .cmp(&a.bytes_out)
            .then_with(|| b.attempts.cmp(&a.attempts))
            .then_with(|| a.host.cmp(&b.host))
            .then_with(|| a.port.cmp(&b.port))
            .then_with(|| a.protocol.cmp(b.protocol))
    });
}

fn totals_of(sessions: &[SessionReport]) -> Totals {
    let mut totals = Totals {
        sessions: sessions.len().try_into().unwrap_or(u64::MAX),
        ..Totals::default()
    };
    let mut merged: HashMap<(String, u16, &'static str), Destination> = HashMap::new();
    for s in sessions {
        if matches!(s.integrity, Integrity::Failed { .. }) || s.read_problem.is_some() {
            totals.unreadable = totals.unreadable.saturating_add(1);
        }
        totals.blocked = totals.blocked.saturating_add(s.decisions.blocked());
        totals.asked = totals.asked.saturating_add(s.decisions.ask);
        totals.identified_approvals = totals
            .identified_approvals
            .saturating_add(s.approvals.identified);
        totals.unidentified_approvals = totals
            .unidentified_approvals
            .saturating_add(s.approvals.unidentified);
        totals.auto_granted = totals.auto_granted.saturating_add(s.approvals.auto_granted);
        totals.unanswered_asks = totals
            .unanswered_asks
            .saturating_add(s.approvals.unanswered);
        for d in &s.destinations {
            totals.bytes_out = totals.bytes_out.saturating_add(d.bytes_out);
            totals.bytes_in = totals.bytes_in.saturating_add(d.bytes_in);
            let slot = merged.entry(d.key()).or_insert_with(|| Destination {
                host: d.host.clone(),
                port: d.port,
                protocol: d.protocol,
                attempts: 0,
                allowed: 0,
                blocked: 0,
                asked: 0,
                completed: 0,
                bytes_out: 0,
                bytes_in: 0,
                duration_ms: 0,
            });
            slot.attempts = slot.attempts.saturating_add(d.attempts);
            slot.allowed = slot.allowed.saturating_add(d.allowed);
            slot.blocked = slot.blocked.saturating_add(d.blocked);
            slot.asked = slot.asked.saturating_add(d.asked);
            slot.completed = slot.completed.saturating_add(d.completed);
            slot.bytes_out = slot.bytes_out.saturating_add(d.bytes_out);
            slot.bytes_in = slot.bytes_in.saturating_add(d.bytes_in);
            slot.duration_ms = slot.duration_ms.saturating_add(d.duration_ms);
        }
    }
    let mut destinations: Vec<Destination> = merged.into_values().collect();
    sort_destinations(&mut destinations);
    totals.destinations = destinations;
    totals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_map_to_utc_midnight() {
        assert_eq!(parse_date("1970-01-01"), Some(0));
        assert_eq!(
            parse_date("2024-02-29"),
            Some(1_709_164_800 * 1_000_000_000)
        );
        assert_eq!(
            parse_date("2026-08-26"),
            Some(1_787_702_400 * 1_000_000_000)
        );
    }

    #[test]
    fn malformed_dates_are_refused() {
        for bad in [
            "2026-8-26",
            "2026/08/26",
            "20260826",
            "2026-13-01",
            "2026-02-30",
            "2023-02-29",
            "1969-12-31",
            "",
            "2026-08-26T00:00:00Z",
            "abcd-ef-gh",
        ] {
            assert_eq!(parse_date(bad), None, "{bad} 를 받아들이면 안 됨");
        }
    }

    #[test]
    fn until_covers_the_whole_day() {
        let r = range_of(Some("2026-08-26"), Some("2026-08-26")).unwrap();
        let midnight = parse_date("2026-08-26").unwrap();
        assert!(r.contains(midnight));
        assert!(r.contains(midnight + NANOS_PER_DAY - 1));
        assert!(!r.contains(midnight + NANOS_PER_DAY));
        assert!(!r.contains(midnight - 1));
    }

    #[test]
    fn an_inverted_range_is_refused() {
        assert!(range_of(Some("2026-08-27"), Some("2026-08-26")).is_err());
    }

    #[test]
    fn an_open_range_covers_everything() {
        let r = range_of(None, None).unwrap();
        assert!(r.contains(0));
        assert!(r.contains(u64::MAX));
    }

    #[test]
    fn civil_roundtrip_matches_the_audit_formatter() {
        for date in ["1970-01-01", "2000-02-29", "2024-12-31", "2100-03-01"] {
            let nanos = parse_date(date).unwrap();
            let text = airlock_audit::format_rfc3339_nanos(nanos);
            assert!(text.starts_with(date), "{date} -> {text}");
        }
    }

    #[test]
    fn destinations_sort_by_outbound_bytes() {
        let mut v = vec![
            Destination {
                host: "a".into(),
                port: 443,
                protocol: "tls",
                attempts: 1,
                allowed: 1,
                blocked: 0,
                asked: 0,
                completed: 1,
                bytes_out: 10,
                bytes_in: 0,
                duration_ms: 0,
            },
            Destination {
                host: "b".into(),
                port: 443,
                protocol: "tls",
                attempts: 1,
                allowed: 1,
                blocked: 0,
                asked: 0,
                completed: 1,
                bytes_out: 100,
                bytes_in: 0,
                duration_ms: 0,
            },
        ];
        sort_destinations(&mut v);
        assert_eq!(v.first().map(|d| d.host.as_str()), Some("b"));
    }
}
