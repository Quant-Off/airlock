use std::path::{Path, PathBuf};
use std::process::Command;

use airlock_audit as audit;
use airlock_audit::{
    ANCHOR_FILE, AnchorLog, AuditLog, Decision, Enforcement, Event, GenesisInfo, Granted,
    Mediation, Record,
};
use airlock_i18n::tr;
use airlock_policy::{Action, Evaluation, FileMode, MatchedRule, Policy, Tier};

use crate::approve::{ApprovalRequest, Approver};
use crate::enforcer::Enforcer;
use crate::error::{BrokerError, Result};

/// 프록시 채널 통과가 감사에 남을 때 쓰는 규칙 id.
///
/// 규칙 없는 allow 로 남기면 정책이 연 것처럼 보이므로 출처를 분명히 적습니다
pub const PROXY_RULE_ID: &str = "airlock:egress-proxy";

/// 행위 주체를 관측하지 못한 판정이 감사에 남을 때 쓰는 actor.
///
/// 프록시 경로는 연결의 peer pid 를 알지 못합니다. 브로커 자신의 actor 를 쓰면 브로커가
/// 한 일처럼 보이고, 관측된 pid 를 쓰면 없는 관측을 지어내는 것이 됩니다. 모른다는 사실
/// 자체를 이름으로 남깁니다
pub const UNKNOWN_ACTOR: &str = "airlock:unknown-peer";

/// 아웃바운드 결과 기록이 감사에 남을 때 쓰는 규칙 id.
///
/// `EgressSummary` 는 판정이 아니라 사실 기록입니다. `decision` 자리는 스키마 때문에
/// `allow` 지만 그것을 허용한 규칙은 없습니다. 규칙 없는 allow 로 남기면 `[defaults]` 가
/// 열어 준 것처럼 보이므로, 판정이 아니라는 사실 자체를 이름으로 남깁니다
pub const EGRESS_SUMMARY_RULE_ID: &str = "airlock:egress-summary";

/// 감사 엔트리의 `actor` 자리에 들어갈 주체.
///
/// 세 경우가 로그에서 서로 구분되어야 합니다. 브로커가 스스로 부른 판정, 중계 층이 pid
/// 까지 관측한 판정, 주체를 모르는 채로 내린 판정은 사후 조사에서 뜻이 전혀 다릅니다
/// (`docs/limitations.md` 7.6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    /// 브로커가 직접 부른 판정. 세션 actor 를 그대로 씁니다
    Broker,
    /// 중계 층이 관측한 실제 행위 주체의 pid
    Observed(u32),
    /// 행위 주체를 관측할 수 없는 경로
    Unknown,
}

pub fn decision_of(action: Action) -> Decision {
    match action {
        Action::Allow => Decision::Allow,
        Action::Deny => Decision::Deny,
        Action::Ask => Decision::Ask,
        Action::Forbid => Decision::Forbid,
    }
}

pub fn audit_mode_of(mode: FileMode) -> audit::FileMode {
    match mode {
        FileMode::Read => audit::FileMode::Read,
        FileMode::Write => audit::FileMode::Write,
        FileMode::Create => audit::FileMode::Create,
        FileMode::Delete => audit::FileMode::Delete,
        FileMode::Metadata => audit::FileMode::Metadata,
        FileMode::Exec => audit::FileMode::Exec,
    }
}

/// 감사 층의 프로토콜 태그를 정책 어휘로 옮깁니다.
///
/// 정책에는 UDP 가 없으므로 `Udp` 는 `Tcp` 로 낮춥니다. `Tcp` 는 "관측 층이 프로토콜을
/// 모른다" 는 뜻이라 평문 바닥이 발동하지 않는 쪽이고, UDP 만 통과시키는 특례가 생기지
/// 않습니다. 태그 번호는 두 타입이 같지만 변환을 명시적으로 두어 한쪽이 늘어날 때
/// 컴파일이 깨지게 합니다
///
/// # Arguments
/// `protocol` - 감사 층이 기록할 프로토콜 태그
pub fn policy_protocol_of(protocol: audit::Protocol) -> airlock_policy::Protocol {
    match protocol {
        audit::Protocol::Tcp | audit::Protocol::Udp => airlock_policy::Protocol::Tcp,
        audit::Protocol::Tls => airlock_policy::Protocol::Tls,
        audit::Protocol::Http => airlock_policy::Protocol::Http,
    }
}

fn exit_status_of(status: &std::process::ExitStatus) -> audit::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        audit::ExitStatus::Exited {
            code: code.cast_unsigned(),
        }
    } else if let Some(signal) = status.signal() {
        audit::ExitStatus::Signaled {
            signal: signal.cast_unsigned(),
        }
    } else {
        audit::ExitStatus::Unknown
    }
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub audit_dir: PathBuf,
    pub actor: String,
    pub cwd: PathBuf,
    pub argv: Vec<String>,
    pub fsync_per_entry: bool,
    pub policy_source: Option<String>,
    pub airlock_version: String,
    /// 요청된 중계 수준. 이 플랫폼에서 실제로 적용되는 값은
    /// [`effective_mediation`]이 정하며, 제네시스에는 적용된 값이 기록됩니다
    pub mediation: Mediation,
    /// 세션 상위 앵커 체인을 둘 디렉토리. `None`이면 [`anchor_dir_for`]가 정합니다
    pub anchor_dir: Option<PathBuf>,
}

/// 이 세션의 앵커 루트를 정합니다.
///
/// 명시값이 없으면 감사 루트를 씁니다. 세션 디렉토리는 `<감사루트>/sessions/<세션>`
/// 이므로 `sessions`를 한 단계 더 거슬러 올라갑니다 (`docs/audit-format.md` 8.1).
/// 그 레이아웃이 아니면 세션 디렉토리 바로 위를 씁니다. 어느 쪽이든 앵커는 세션
/// 디렉토리 바깥이라 세션 통째 삭제가 흔적을 남깁니다.
///
/// # Arguments
/// `audit_dir` - 이 세션의 체인이 들어갈 디렉토리
/// `explicit` - 사용자가 지정한 앵커 루트
pub fn anchor_dir_for(audit_dir: &Path, explicit: Option<&Path>) -> PathBuf {
    if let Some(dir) = explicit {
        return dir.to_path_buf();
    }
    let Some(parent) = audit_dir.parent() else {
        return audit_dir.to_path_buf();
    };
    if parent.file_name() == Some(std::ffi::OsStr::new("sessions"))
        && let Some(root) = parent.parent()
    {
        return root.to_path_buf();
    }
    parent.to_path_buf()
}

/// 앵커 append 를 직렬화하는 잠금 파일 이름.
///
/// 앵커 루트는 여러 airlock 프로세스가 공유합니다. 이름을 점으로 시작해 세션 디렉토리
/// 목록과 섞이지 않게 둡니다
pub const ANCHOR_LOCK_FILE: &str = ".anchors.lock";

/// 자식이 끝난 뒤 프록시 릴레이가 결과를 남길 때까지 기다리는 상한.
///
/// 자식은 이미 종료했으므로 그 자식이 열어 둔 연결은 대개 곧바로 닫힙니다. 상한을 두는
/// 이유는 자식이 남긴 긴 연결 하나에 세션 종료가 무한히 묶이지 않게 하기 위함입니다
pub const PROXY_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// 앵커 루트를 만들고 프로세스 사이 잠금을 잡습니다.
///
/// [`AnchorLog::open`]은 기존 체인을 끝까지 읽어 head를 잡은 뒤 이어 붙입니다. 두 세션이
/// 같은 앵커 루트에서 동시에 끝나면 둘 다 같은 head를 읽고 같은 seq로 써서 체인이 깨지고,
/// 깨진 체인에는 그 뒤로 아무도 이어 붙이지 못합니다. 앵커는 세션당 한 줄뿐이라 이 잠금이
/// 성능을 지배하지 않습니다.
///
/// 반환한 파일이 살아 있는 동안 잠금이 유지되며 닫히면 커널이 놓습니다.
///
/// # Arguments
/// `dir` - 앵커 루트
///
/// # Errors
/// 디렉토리를 만들지 못하거나 잠금 파일을 열지 못하면 실패합니다. 잠금 없이 이어 붙이는
/// 경로는 두지 않습니다. 체인을 깨뜨리는 쪽이 앵커를 못 남기는 쪽보다 나쁩니다.
fn lock_anchor_dir(dir: &Path) -> std::io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let path = dir.join(ANCHOR_LOCK_FILE);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)?;

    // # Safety
    // flock 은 유효한 fd 하나와 상수 플래그만 받고 메모리를 건드리지 않습니다. 잠금은
    // 열린 파일 서술에 붙으므로 같은 프로세스의 다른 열기끼리도 서로를 배제합니다
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

/// 세션 하나의 앵커 기록 결과.
///
/// 실패를 `Ok`로 삼키지 않는 자리입니다. 앵커 없는 세션은 감사 보증이 약해진 세션이며,
/// 그 사실이 보고에 남아야 사용자가 알아챌 수 있습니다
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorOutcome {
    Written { path: PathBuf, seq: u64 },
    Failed { path: PathBuf, why: String },
}

impl AnchorOutcome {
    pub fn failure(&self) -> Option<&str> {
        match self {
            Self::Written { .. } => None,
            Self::Failed { why, .. } => Some(why),
        }
    }

    pub fn path(&self) -> &Path {
        match self {
            Self::Written { path, .. } | Self::Failed { path, .. } => path,
        }
    }
}

/// 세션을 닫은 결과.
#[derive(Debug, Clone)]
pub struct Closed {
    pub head_seq: Option<u64>,
    pub head_hash: audit::Hash,
    pub anchor: AnchorOutcome,
}

/// 요청한 중계 수준이 이 플랫폼에서 실제로 무엇이 되는지.
///
/// Linux에서는 `crate::notify::Level`로 옮겨져 seccomp user notification 필터가 됩니다.
/// 다른 플랫폼에는 중계 기구가 아예 없으므로 무엇을 요청해도 `Off`입니다
pub fn effective_mediation(requested: Mediation) -> Mediation {
    #[cfg(target_os = "linux")]
    {
        requested
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = requested;
        Mediation::Off
    }
}

/// 중계 층이 이 플랫폼에서 무엇을 못 보는지.
///
/// 요청한 수준이 조용히 무시되면 감사 로그가 실제보다 완전해 보입니다. 값이 무시되었다는
/// 사실 자체를 배너와 제네시스 양쪽에 남깁니다
pub fn mediation_gaps(requested: Mediation) -> Vec<String> {
    let effective = effective_mediation(requested);
    let mut gaps = Vec::new();

    if effective != requested {
        gaps.push(tr!(
            format!(
                "이 플랫폼에는 런타임 중계 기구가 없어 --mediate {}가 적용되지 않음. \
                 감사 로그에는 중계 수준 {}가 기록됨",
                requested.as_str(),
                effective.as_str()
            ),
            format!(
                "this platform has no runtime mediation mechanism, so --mediate {} does \
                 not apply; the audit log records mediation level {}",
                requested.as_str(),
                effective.as_str()
            )
        ));
    }

    match effective {
        Mediation::Off => gaps.push(
            tr!(
                "중계가 꺼져 있어 자식 프로세스의 exec·연결·파일 열기가 감사에 남지 않음. \
                 체인에는 세션 단위 기록만 있음",
                "mediation is off, so the child's execs, connections, and file opens are \
                 not audited; the chain only has session-level records"
            )
            .to_string(),
        ),
        Mediation::ExecNet => gaps.push(
            tr!(
                "파일 열기는 중계하지 않음. 파일 접근은 커널 강제만 받고 감사에는 남지 않음 \
                 (--mediate full로 켤 수 있으나 느려짐)",
                "file opens are not mediated; file access is only kernel-enforced and is \
                 not audited (--mediate full can enable it, at a slowdown)"
            )
            .to_string(),
        ),
        Mediation::Full => {}
    }

    if effective.observes() {
        gaps.push(
            tr!(
                "중계 층이 읽은 경로와 커널이 실제로 여는 대상은 다를 수 있음(TOCTOU). \
                 실제 경계는 커널 강제 층이며 중계는 기록과 승인 채널임",
                "the path the mediation layer read and what the kernel actually opens can \
                 differ (TOCTOU); the real boundary is the kernel enforcement layer, and \
                 mediation is a recording and approval channel"
            )
            .to_string(),
        );
    }
    gaps
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub action: Action,
    pub seq: u64,
}

impl Outcome {
    pub fn permitted(&self) -> bool {
        self.action == Action::Allow
    }
}

pub struct Session {
    policy: Policy,
    log: AuditLog,
    approver: Box<dyn Approver>,
    actor: String,
    cwd: PathBuf,
    asked: u64,
    denied: u64,
    proxy: Option<std::net::SocketAddr>,
    anchor_dir: PathBuf,
    /// 목적지별 누적 반출 바이트. `max_bytes_out` 판정의 입력입니다
    egress_bytes_out: std::collections::HashMap<(String, u16), u64>,
    /// `SessionEnd` 를 이미 썼는지. 그 뒤의 append 는 거부합니다
    closed: bool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("dir", &self.log.dir())
            .field("actor", &self.actor)
            .field("asked", &self.asked)
            .field("denied", &self.denied)
            .finish()
    }
}

impl Session {
    pub fn start(
        policy: Policy,
        enforcement: Enforcement,
        approver: Box<dyn Approver>,
        config: &SessionConfig,
    ) -> Result<Self> {
        let session_id = audit::SessionId::generate().map_err(|source| BrokerError::Io {
            what: tr!("세션 식별자 생성", "session identifier generation").to_string(),
            source,
        })?;

        let log = AuditLog::create(
            &config.audit_dir,
            session_id,
            enforcement,
            config.fsync_per_entry,
            GenesisInfo {
                airlock_version: config.airlock_version.clone(),
                argv: config.argv.clone(),
                cwd: config.cwd.to_string_lossy().into_owned(),
                policy_digest: audit::Hash::from_bytes(policy.digest()),
                policy_source: config.policy_source.clone(),
                mediation: config.mediation,
                // 사람 식별자와 정책 서명자는 아직 관측 경로가 없습니다. 자리를 채우려고
                // 계정 이름을 넣으면 없는 책임 주체를 지어내는 것이 됩니다
                operator: None,
                policy_signer: None,
            },
        )?;

        Ok(Self {
            policy,
            log,
            approver,
            actor: config.actor.clone(),
            cwd: config.cwd.clone(),
            asked: 0,
            denied: 0,
            proxy: None,
            anchor_dir: anchor_dir_for(&config.audit_dir, config.anchor_dir.as_deref()),
            egress_bytes_out: std::collections::HashMap::new(),
            closed: false,
        })
    }

    /// 이 세션이 앵커를 남길 디렉토리.
    pub fn anchor_dir(&self) -> &Path {
        &self.anchor_dir
    }

    /// 이 세션의 egress 프록시 주소를 알려 줍니다.
    ///
    /// 중계 층은 자식이 프록시로 가는 루프백 연결도 그대로 봅니다. 정책에는 그
    /// 주소를 여는 규칙이 없어 `[defaults].egress`로 떨어져 막히므로, 브로커가
    /// 자기 채널임을 알고 통과시켜야 합니다. 실제 목적지 판정은 프록시가 합니다
    pub fn set_proxy_endpoint(&mut self, addr: std::net::SocketAddr) {
        self.proxy = Some(addr);
    }

    /// 관측된 주소가 이 세션의 프록시 채널인지 봅니다.
    fn is_proxy_endpoint(&self, host: &str, port: u16) -> bool {
        let Some(proxy) = self.proxy else {
            return false;
        };
        if port != proxy.port() {
            return false;
        }
        // 중계 층은 sockaddr 에서 읽은 IP 문자열을 넘기므로 표기 차이를 없애려면
        // 문자열이 아니라 주소로 비교해야 합니다
        host.parse::<std::net::IpAddr>()
            .map(|ip| ip == proxy.ip())
            .unwrap_or(false)
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn audit_dir(&self) -> &Path {
        self.log.dir()
    }

    pub fn head_seq(&self) -> Option<u64> {
        self.log.head_seq()
    }

    pub fn head_hash(&self) -> audit::Hash {
        self.log.head_hash()
    }

    pub fn asked_count(&self) -> u64 {
        self.asked
    }

    pub fn denied_count(&self) -> u64 {
        self.denied
    }

    fn resolve(&self, eval: &Evaluation) -> (String, String) {
        match &eval.path {
            Some(np) => (
                np.requested.to_string_lossy().into_owned(),
                np.resolved.to_string_lossy().into_owned(),
            ),
            None => (String::new(), String::new()),
        }
    }

    /// 이 판정을 누구의 것으로 기록할지 정합니다.
    ///
    /// # Arguments
    /// `actor` - 호출부가 관측한 주체
    fn actor_label(&self, actor: Actor) -> String {
        match actor {
            Actor::Broker => self.actor.clone(),
            Actor::Observed(pid) => format!("pid:{pid}"),
            Actor::Unknown => UNKNOWN_ACTOR.to_string(),
        }
    }

    fn commit(
        &mut self,
        event: Event,
        eval: &Evaluation,
        request: ApprovalRequest,
        actor: Actor,
    ) -> Result<Outcome> {
        // 닫힌 세션에는 붙이지 않습니다. 늦게 도착한 판정 하나를 남기려다 체인이 앵커보다
        // 길어지면 세션 전체가 "종료 후 덧붙이기" 로 보고됩니다. 호출부는 이 오류를
        // 거부로 처리하므로 늦은 연결은 통과하지 못합니다
        if self.closed {
            return Err(BrokerError::SessionClosed);
        }
        let decision = decision_of(eval.action);
        let mut record = Record::new(self.actor_label(actor), event, decision);
        if let Some(rule) = &eval.rule {
            record = record.with_rule(rule.id.clone());
        }
        let entry = self.log.append(record)?;

        if eval.action != Action::Ask {
            if eval.action.blocks() {
                self.denied = self.denied.saturating_add(1);
            }
            return Ok(Outcome {
                action: eval.action,
                seq: entry.seq,
            });
        }

        self.asked = self.asked.saturating_add(1);
        let granted = self.approver.ask(&request.with_rule(eval.rule.clone()));
        let effective = match granted {
            Granted::Approved => Action::Allow,
            Granted::Refused | Granted::TimedOut => Action::Deny,
        };
        if effective.blocks() {
            self.denied = self.denied.saturating_add(1);
        }

        let note = self.approver.note();
        // 신원은 승인 채널이 스스로 관측한 것만 씁니다. 사람이 답하지 않는 승인자는
        // 반드시 None 이며, 그 구분이 감사 로그에서 자동 승인을 드러냅니다
        let identity = self.approver.identity();
        self.log.append(Record::new(
            audit::BROKER_ACTOR,
            Event::Approval {
                for_seq: entry.seq,
                granted,
                note,
                approver_uid: identity.as_ref().map(|i| i.uid),
                approver_tty: identity.and_then(|i| i.tty),
            },
            decision_of(effective),
        ))?;

        Ok(Outcome {
            action: effective,
            seq: entry.seq,
        })
    }

    /// 파일 접근 하나를 판정하고 기록합니다.
    ///
    /// # Arguments
    /// `path` - 관측된 경로
    /// `mode` - 접근 모드
    /// `actor` - 이 접근을 실제로 시도한 주체
    pub fn check_file(&mut self, path: &Path, mode: FileMode, actor: Actor) -> Result<Outcome> {
        let cwd = self.cwd.clone();
        let eval = self.policy.evaluate_file(path, mode, &cwd);
        let (requested, resolved) = self.resolve(&eval);

        let mut request = ApprovalRequest::new(tr!("파일 접근 시도", "file access attempt"))
            .fact(tr!("요청 경로", "requested path"), requested.clone())
            .fact(tr!("모드", "mode"), mode.as_str());
        if requested != resolved {
            request = request.fact(tr!("해소 경로", "resolved path"), resolved.clone());
        }

        let event = Event::FileAccess {
            path_requested: requested,
            path_resolved: resolved,
            mode: audit_mode_of(mode),
        };
        self.commit(event, &eval, request, actor)
    }

    /// 프로세스 실행 하나를 판정하고 기록합니다.
    ///
    /// # Arguments
    /// `program` - 관측된 프로그램 경로
    /// `argv` - 관측된 argv
    /// `actor` - 이 실행을 실제로 시도한 주체
    pub fn check_exec(&mut self, program: &Path, argv: &[String], actor: Actor) -> Result<Outcome> {
        let cwd = self.cwd.clone();
        let eval = self.policy.evaluate_exec(program, argv, &cwd);
        let (requested, resolved) = self.resolve(&eval);

        let mut request = ApprovalRequest::new(tr!("프로세스 실행 시도", "process exec attempt"))
            .fact(tr!("프로그램", "program"), requested.clone())
            .fact("argv", format!("{argv:?}"))
            .fact("cwd", cwd.to_string_lossy().into_owned());
        if requested != resolved {
            request = request.fact(tr!("해소 경로", "resolved path"), resolved.clone());
        }

        let event = Event::Exec {
            program: resolved.clone(),
            argv: argv.to_vec(),
            cwd: cwd.to_string_lossy().into_owned(),
        };
        self.commit(event, &eval, request, actor)
    }

    /// 아웃바운드 연결 하나를 판정하고 기록합니다.
    ///
    /// # Arguments
    /// `host` - 관측된 호스트 문자열
    /// `port` - 목적지 포트
    /// `protocol` - 관측 층이 판단한 프로토콜. 중계 층은 항상 `Tcp`를 넘김
    /// `actor` - 이 연결을 실제로 시도한 주체
    pub fn check_egress(
        &mut self,
        host: &str,
        port: u16,
        protocol: audit::Protocol,
        actor: Actor,
    ) -> Result<Outcome> {
        let eval = if self.is_proxy_endpoint(host, port) {
            Evaluation {
                action: Action::Allow,
                rule: Some(MatchedRule {
                    id: PROXY_RULE_ID.to_string(),
                    tier: Tier::SelfProtect,
                    action: Action::Allow,
                    pattern: format!("{host}:{port}"),
                    reason: Some(
                        tr!(
                            "브로커 egress 프록시 채널. 목적지 판정은 프록시가 함",
                            "broker egress proxy channel; destination decisions are made by the proxy"
                        )
                        .into(),
                    ),
                }),
                path: None,
            }
        } else {
            // 누적 반출량을 함께 넘겨 총량 한도까지 한 지점에서 판정합니다. 브로커가 따로
            // 한도를 검사하면 두 판정 지점이 언젠가 갈라집니다
            self.policy.evaluate_egress_with_usage(
                host,
                port,
                policy_protocol_of(protocol),
                self.bytes_out_to(host, port),
            )
        };
        let request =
            ApprovalRequest::new(tr!("아웃바운드 연결 시도", "outbound connection attempt"))
                .fact(tr!("호스트", "host"), host.to_string())
                .fact(tr!("포트", "port"), port.to_string())
                .fact(tr!("프로토콜", "protocol"), protocol.as_str());

        let event = Event::Egress {
            host: host.to_string(),
            port,
            protocol,
        };
        self.commit(event, &eval, request, actor)
    }

    /// 이 세션에서 그 목적지로 지금까지 반출한 누적 바이트.
    ///
    /// 프록시 층이 결과를 남긴 만큼만 셉니다. 프록시 없는 세션에서는 언제나 0 이며, 곧
    /// `max_bytes_out` 이 한 번도 걸리지 않습니다 (`docs/limitations.md`).
    ///
    /// # Arguments
    /// `host` - 관측된 호스트 문자열
    /// `port` - 목적지 포트
    pub fn bytes_out_to(&self, host: &str, port: u16) -> u64 {
        self.egress_bytes_out
            .get(&(quota_key(host), port))
            .copied()
            .unwrap_or(0)
    }

    /// 끝난 아웃바운드 연결 하나의 결과를 기록합니다.
    ///
    /// **정책을 다시 평가하지 않습니다.** 판정은 연결 시작 시점에 이미 끝났고 이것은 그
    /// 결과입니다. `decision` 이 `allow` 인 것은 스키마 때문이며 규칙 id 가 사실 기록임을
    /// 밝힙니다.
    ///
    /// 누적 반출량을 여기서 갱신합니다. 곧 `max_bytes_out` 이 다음 연결부터 걸립니다.
    ///
    /// # Arguments
    /// `host` - 프록시가 관측한 목적지 호스트
    /// `port` - 목적지 포트
    /// `protocol` - 프록시가 관측한 프로토콜
    /// `bytes_out` - 목적지로 실제로 나간 바이트
    /// `bytes_in` - 목적지에서 실제로 받은 바이트
    /// `duration_ms` - 연결이 살아 있던 밀리초
    /// `actor` - 이 연결을 낸 주체. 프록시 경로는 관측하지 못함
    #[allow(clippy::too_many_arguments)]
    pub fn record_egress_summary(
        &mut self,
        host: &str,
        port: u16,
        protocol: audit::Protocol,
        bytes_out: u64,
        bytes_in: u64,
        duration_ms: u64,
        actor: Actor,
    ) -> Result<()> {
        if self.closed {
            return Err(BrokerError::SessionClosed);
        }
        self.log.append(
            Record::new(
                self.actor_label(actor),
                Event::EgressSummary {
                    host: host.to_string(),
                    port,
                    protocol,
                    bytes_out,
                    bytes_in,
                    duration_ms,
                },
                Decision::Allow,
            )
            .with_rule(EGRESS_SUMMARY_RULE_ID),
        )?;

        // 기록에 성공한 뒤에만 누적합니다. 실패한 append 의 바이트를 세면 감사에 없는
        // 반출이 한도 계산에만 반영되어 로그와 판정이 갈라집니다
        let slot = self
            .egress_bytes_out
            .entry((quota_key(host), port))
            .or_insert(0);
        *slot = slot.saturating_add(bytes_out);
        Ok(())
    }

    /// `SessionEnd`를 쓰고 세션 상위 앵커에 최종 head를 남깁니다.
    ///
    /// 앵커는 반드시 `SessionEnd` 다음입니다. 먼저 쓰면 앵커가 가리키는 head 뒤로 엔트리가
    /// 하나 더 자라서, 정상 종료가 "종료 후 덧붙이기"로 보고됩니다.
    ///
    /// # Arguments
    /// `status` - 자식의 종료 상태. 자식이 뜨지 못했으면 `None`
    ///
    /// # Errors
    /// `SessionEnd` 기록에 실패하면 실패합니다. 앵커 기록 실패는 여기서 오류가 되지
    /// 않고 [`Closed::anchor`]에 담겨 올라갑니다. 이미 끝난 자식 실행을 되돌릴 수는
    /// 없으므로 사실을 보고에 남기고 호출부가 판단하게 합니다
    pub fn finish(&mut self, status: Option<&std::process::ExitStatus>) -> Result<Closed> {
        if self.closed {
            return Err(BrokerError::SessionClosed);
        }
        let audit_status = match status {
            Some(s) => exit_status_of(s),
            None => audit::ExitStatus::Unknown,
        };
        // 여기서부터 이 세션은 닫힌 것으로 봅니다. 아직 살아 있는 프록시 릴레이가 결과를
        // 들고 와도 거부되며, 그 사실은 경고로 나갑니다
        self.closed = true;
        self.log.append(Record::new(
            audit::BROKER_ACTOR,
            Event::SessionEnd {
                status: audit_status,
            },
            Decision::Allow,
        ))?;

        let head_seq = self.log.head_seq();
        let head_hash = self.log.head_hash();
        Ok(Closed {
            head_seq,
            head_hash,
            anchor: self.append_anchor(head_seq, head_hash),
        })
    }

    /// 이 세션의 최종 head를 앵커 체인에 잇습니다.
    ///
    /// # Arguments
    /// `head_seq` - 세션 체인의 마지막 seq
    /// `head_hash` - 세션 체인의 마지막 hash
    fn append_anchor(&self, head_seq: Option<u64>, head_hash: audit::Hash) -> AnchorOutcome {
        let path = self.anchor_dir.join(ANCHOR_FILE);
        let Some(seq) = head_seq else {
            return AnchorOutcome::Failed {
                path,
                why: tr!(
                    "세션 체인이 비어 있어 앵커할 head 가 없음",
                    "the session chain is empty, so there is no head to anchor"
                )
                .to_string(),
            };
        };
        let session = self.log.session();
        // 잠금을 먼저 잡습니다. AnchorLog::open 이 head 를 읽는 순간부터 append 가 끝날
        // 때까지 다른 세션이 끼어들면 두 줄이 같은 seq 를 갖게 됩니다
        let _guard = match lock_anchor_dir(&self.anchor_dir) {
            Ok(g) => g,
            Err(e) => {
                return AnchorOutcome::Failed {
                    path,
                    why: tr!(
                        format!("앵커 잠금을 잡지 못함: {e}"),
                        format!("failed to take the anchor lock: {e}")
                    ),
                };
            }
        };
        match AnchorLog::open(&self.anchor_dir) {
            Ok(mut log) => match log.append(session, seq, head_hash) {
                Ok(entry) => AnchorOutcome::Written {
                    path,
                    seq: entry.seq,
                },
                Err(e) => AnchorOutcome::Failed {
                    path,
                    why: e.to_string(),
                },
            },
            Err(e) => AnchorOutcome::Failed {
                path,
                why: e.to_string(),
            },
        }
    }
}

/// 누적 반출량을 셀 때 쓰는 목적지 키.
///
/// 정책 엔진과 같은 정규화를 씁니다. 표기가 다르면 같은 목적지가 두 칸으로 나뉘어 한도가
/// 표기를 바꾸는 것만으로 초기화됩니다. 정규화할 수 없는 호스트는 원문 그대로 두며, 그런
/// 호스트는 정책 엔진에서도 어느 규칙에도 매칭되지 않아 한도가 붙을 일이 없습니다
///
/// # Arguments
/// `host` - 관측된 호스트 문자열
fn quota_key(host: &str) -> String {
    airlock_policy::host::normalize_host(host).unwrap_or_else(|| host.to_string())
}

pub fn which(program: &str) -> Option<PathBuf> {
    let candidate = Path::new(program);
    if candidate.components().count() > 1 || program.starts_with('/') {
        return if candidate.is_file() {
            Some(candidate.to_path_buf())
        } else {
            None
        };
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let full = dir.join(program);
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

/// 로더 주입에 쓰이는 환경 변수 접두.
///
/// 이 값들이 살아 있으면 정책이 경로로 허용한 프로그램 안에서 남의 코드가 돕니다.
/// `kind = "exec"` allowlist 가 통째로 무의미해지므로 전달하지 않습니다
const INJECTION_PREFIXES: &[&str] = &["LD_", "DYLD_"];

/// 쉘이 시작할 때 읽어 실행하는 환경 변수.
const INJECTION_EXACT: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "IFS",
    "PS4",
    "PERL5OPT",
    "PERL5LIB",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "NODE_OPTIONS",
    "RUBYOPT",
    "GIT_EXTERNAL_DIFF",
    "GIT_SSH_COMMAND",
];

/// 호스트 데몬 소켓을 가리키는 환경 변수.
///
/// 시크릿 경로 기본 deny 의 연장입니다. `~/.ssh` 를 막으면서 같은 키로 서명해 주는
/// ssh-agent 소켓의 주소를 건네는 것은 모순이고, `DOCKER_HOST` 가 가리키는 소켓은
/// 호스트 루트와 다름없는 능력입니다. 완화 어휘가 정책에 생기기 전까지는 벗깁니다
/// (`docs/limitations.md` 9.6)
const SOCKET_HANDLE_EXACT: &[&str] = &["SSH_AUTH_SOCK", "DOCKER_HOST"];

/// 자식에게 넘기지 않을 환경 변수인지.
///
/// # Arguments
/// `key` - UTF-8 로 읽힌 변수 이름
fn env_is_stripped(key: &str) -> bool {
    INJECTION_PREFIXES.iter().any(|p| key.starts_with(p))
        || INJECTION_EXACT.contains(&key)
        || SOCKET_HANDLE_EXACT.contains(&key)
        // 감사 로그 위치를 알려 줄 이유가 없습니다
        || key == "AIRLOCK_AUDIT_DIR"
}

/// 자식에게 넘길 환경에서 코드 주입 통로와 호스트 데몬 소켓 핸들을 걷어냅니다.
///
/// 통째로 비우지 않는 이유는 에이전트가 `PATH`, `HOME`, `TERM` 없이는 정상 동작하지
/// 않기 때문입니다. 대신 로더와 인터프리터가 시작 시점에 실행하는 값과 소켓을 가리키는
/// 값만 지웁니다.
///
/// # Arguments
/// `cmd` - 환경을 정리할 명령
fn sanitize_env(cmd: &mut Command) {
    sanitize_env_from(cmd, std::env::vars_os().map(|(k, _)| k));
}

/// [`sanitize_env`] 의 본체. 검사할 변수 이름을 밖에서 받아 프로세스 환경을 건드리지
/// 않고도 검증할 수 있게 합니다.
///
/// # Arguments
/// `cmd` - 환경을 정리할 명령
/// `keys` - 자식에게 상속될 후보 변수 이름
fn sanitize_env_from(cmd: &mut Command, keys: impl IntoIterator<Item = std::ffi::OsString>) {
    for key in keys {
        let Some(k) = key.to_str() else {
            // UTF-8이 아닌 변수 이름은 검사할 수 없으므로 넘기지 않습니다
            cmd.env_remove(&key);
            continue;
        };
        if env_is_stripped(k) {
            cmd.env_remove(&key);
        }
    }
}

#[derive(Debug)]
pub struct RunReport {
    pub audit_dir: PathBuf,
    pub head_seq: Option<u64>,
    pub head_hash: audit::Hash,
    pub exit_code: Option<i32>,
    /// 자식이 시그널로 죽었을 때의 시그널 번호. `exit_code`가 없으면 이쪽을 봅니다
    pub signal: Option<i32>,
    pub asked: u64,
    pub denied: u64,
    pub enforcement: Enforcement,
    /// 실제로 적용된 중계 수준
    pub mediation: Mediation,
    pub gaps: Vec<String>,
    /// 세션 상위 앵커 기록 결과.
    ///
    /// 실패해도 자식의 종료 코드는 덮지 않습니다. 이미 끝난 실행을 되돌릴 수 없기
    /// 때문입니다. 대신 이 값이 실패를 담고 있으면 호출부가 눈에 띄게 보고해야 합니다
    pub anchor: AnchorOutcome,
}

impl RunReport {
    /// 브로커 자신의 종료 코드.
    ///
    /// 자식이 시그널로 죽은 것을 성공으로 보고하면 래퍼를 CI에 넣은 순간 실패가 사라집니다.
    /// 쉘 관례대로 128에 시그널 번호를 더해 돌려줍니다
    pub fn exit_status(&self) -> i32 {
        if let Some(code) = self.exit_code {
            return code;
        }
        if let Some(signal) = self.signal {
            return 128i32.saturating_add(signal);
        }
        if self.denied > 0 { 77 } else { 70 }
    }
}

pub fn run(
    program: &str,
    args: &[String],
    policy: Policy,
    mut enforcer: Box<dyn Enforcer>,
    approver: Box<dyn Approver>,
    config: &SessionConfig,
    proxy: Option<airlock_proxy::ProxyServer>,
) -> Result<RunReport> {
    let resolved =
        which(program).ok_or_else(|| BrokerError::ProgramNotFound(program.to_string()))?;
    // 최상위 프로그램을 prepare 보다 먼저 알려 줍니다. wrap 시점에도 같은 보정이 있지만,
    // 그때는 배너가 이미 나간 뒤라 규칙 수와 gap 이 실제로 걸릴 프로파일과 어긋납니다
    enforcer.set_program(&resolved);
    enforcer.prepare(&policy)?;

    let enforcement = enforcer.kind();
    let mut gaps = enforcer.gaps();
    gaps.extend(mediation_gaps(config.mediation));

    /// 자식이 프록시를 거쳐 나가도록 환경을 잡습니다.
    ///
    /// `NO_PROXY`를 비우는 것이 핵심입니다. 상속된 값이 남아 있으면 거기 적힌
    /// 호스트가 프록시를 건너뛰고, 커널 층이 그 연결을 막아 원인을 알기 어려운
    /// 실패가 됩니다
    ///
    /// # Arguments
    /// `cmd` - 환경을 잡을 명령
    /// `addr` - 프록시가 듣고 있는 루프백 주소
    fn inject_proxy_env(cmd: &mut Command, addr: std::net::SocketAddr) {
        let url = format!("http://{addr}");
        for key in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            cmd.env(key, &url);
        }
        cmd.env("NO_PROXY", "");
        cmd.env("no_proxy", "");
    }

    let mut cmd = Command::new(&resolved);
    cmd.args(args);
    cmd.current_dir(&config.cwd);
    sanitize_env(&mut cmd);
    if let Some(p) = &proxy {
        inject_proxy_env(&mut cmd, p.addr());
    }

    // 중계 훅을 강제 층보다 먼저 겁니다. listener fd를 부모에게 넘기는 sendmsg가
    // 샌드박스 적용 전에 끝나야 합니다
    #[cfg(target_os = "linux")]
    let channel = setup_mediation(&mut cmd, config.mediation);

    // 제네시스에는 요청값이 아니라 실제로 걸린 수준을 씁니다. 중계를 켤 수 없었는데
    // 요청값을 기록하면 로그가 실제보다 완전해 보입니다
    #[cfg(target_os = "linux")]
    let effective = if channel.is_some() {
        effective_mediation(config.mediation)
    } else {
        Mediation::Off
    };
    #[cfg(not(target_os = "linux"))]
    let effective = effective_mediation(config.mediation);

    let config = &SessionConfig {
        mediation: effective,
        ..config.clone()
    };

    let mut session = Session::start(policy, enforcement, approver, config)?;
    if let Some(p) = &proxy {
        session.set_proxy_endpoint(p.addr());
    }

    let mut argv = Vec::with_capacity(args.len().saturating_add(1));
    argv.push(program.to_string());
    argv.extend_from_slice(args);

    // 이 판정은 브로커가 spawn 전에 직접 부르는 것이므로 관측된 자식 pid 가 없습니다
    let outcome = session.check_exec(&resolved, &argv, Actor::Broker)?;
    if !outcome.permitted() {
        let asked = session.asked_count();
        let denied = session.denied_count();
        let closed = session.finish(None)?;
        return Ok(RunReport {
            audit_dir: config.audit_dir.clone(),
            head_seq: closed.head_seq,
            head_hash: closed.head_hash,
            exit_code: None,
            signal: None,
            asked,
            denied,
            enforcement,
            mediation: effective,
            gaps,
            anchor: closed.anchor,
        });
    }

    enforcer.wrap(&mut cmd)?;

    let shared = std::sync::Arc::new(std::sync::Mutex::new(session));

    // 프록시도 spawn 전에 띄웁니다. 자식이 첫 연결을 보낼 때 accept 루프가 이미
    // 돌고 있어야 합니다
    let proxy_thread = proxy.map(|server| {
        let gate: std::sync::Arc<dyn airlock_proxy::EgressGate> = std::sync::Arc::new(
            crate::egress::SessionGate::new(std::sync::Arc::clone(&shared)),
        );
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&stop);
        // 살아 있는 연결 수는 serve 가 소유권을 가져가기 전에 받아 두어야 합니다
        let live = server.live_connections();
        let handle = std::thread::spawn(move || server.serve(gate, flag));
        (stop, handle, live)
    });

    // 감독 스레드를 spawn보다 먼저 띄웁니다. spawn은 자식이 exec을 마쳐야 돌아오는데
    // 그 exec 자체가 알림으로 멈추므로, 같은 스레드에서 기다리면 서로를 막습니다
    #[cfg(target_os = "linux")]
    let (supervisor, child_end) = start_supervisor(channel, &shared);

    let spawned = cmd.spawn().map_err(|source| BrokerError::Io {
        what: tr!(
            format!("{} 실행", resolved.display()),
            format!("running {}", resolved.display())
        ),
        source,
    });

    // 부모가 들고 있는 자식 쪽 소켓을 닫아야 자식이 죽었을 때 감독 스레드가 EOF를 봅니다
    #[cfg(target_os = "linux")]
    drop(child_end);

    let mut child = spawned?;

    let status = child.wait().map_err(|source| BrokerError::Io {
        what: tr!(
            format!("{} 대기", resolved.display()),
            format!("waiting for {}", resolved.display())
        ),
        source,
    })?;

    // 자식이 모두 끝나면 커널이 listener를 닫아 RECV가 실패로 빠져나옵니다
    #[cfg(target_os = "linux")]
    if let Some((stop, handle)) = supervisor {
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = handle.join();
    }

    // accept 루프만 멈춥니다. 살아 있는 릴레이 스레드는 자기 연결이 끝나면
    // 알아서 돌아오므로, 여기서 join 을 기다리면 자식이 남긴 긴 연결에 세션
    // 종료가 묶입니다
    if let Some((stop, _, _)) = &proxy_thread {
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    // 다만 아주 짧게는 기다립니다. 릴레이는 자기 연결이 끝날 때 반출량을 감사에 남기는데,
    // 그것이 session_end 뒤에 붙으면 체인이 앵커보다 길어져 세션 전체가 "종료 후 덧붙이기"
    // 로 보고됩니다. 상한을 두는 이유는 자식이 남긴 긴 연결에 종료가 묶이지 않게 하기
    // 위함이며, 상한을 넘겨 도착한 결과는 기록되지 않고 경고로 나갑니다
    if let Some((_, _, live)) = &proxy_thread {
        let deadline = std::time::Instant::now() + PROXY_DRAIN_TIMEOUT;
        while live.load(std::sync::atomic::Ordering::Relaxed) > 0
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    drop(proxy_thread);

    let mut session = match shared.lock() {
        Ok(s) => s,
        Err(poisoned) => poisoned.into_inner(),
    };
    let asked = session.asked_count();
    let denied = session.denied_count();
    let closed = session.finish(Some(&status))?;

    Ok(RunReport {
        audit_dir: config.audit_dir.clone(),
        head_seq: closed.head_seq,
        head_hash: closed.head_hash,
        exit_code: status.code(),
        signal: {
            use std::os::unix::process::ExitStatusExt;
            status.signal()
        },
        asked,
        denied,
        enforcement,
        mediation: effective,
        gaps,
        anchor: closed.anchor,
    })
}

#[cfg(target_os = "linux")]
fn setup_mediation(cmd: &mut Command, level: Mediation) -> Option<crate::notify::NotifyChannel> {
    use crate::notify::{Level, NotifyChannel};
    use std::os::unix::process::CommandExt;

    let level = match level {
        Mediation::Off => return None,
        Mediation::ExecNet => Level::ExecNet,
        Mediation::Full => Level::Full,
    };
    let channel = match NotifyChannel::new(level) {
        Ok(c) => c,
        Err(e) => {
            // 중계를 조용히 끄면 감사 로그가 실제보다 완전해 보입니다
            eprintln!(
                "{}",
                tr!(
                    format!("airlock: 경고 런타임 중계를 켤 수 없음: {e}. 세션 단위 기록만 남음"),
                    format!(
                        "airlock: warning: cannot enable runtime mediation: {e}; only \
                         session-level records remain"
                    )
                )
            );
            return None;
        }
    };
    let hook = channel.child_hook();
    // # Safety
    // pre_exec은 fork 이후 exec 이전의 자식에서 실행됩니다. 브로커는 spawn 시점에
    // 단일 스레드이고 필터는 fork 전에 만들어 두었으므로 새 할당이 없습니다
    unsafe {
        cmd.pre_exec(hook);
    }
    Some(channel)
}

#[cfg(target_os = "linux")]
type Supervisor = (
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::thread::JoinHandle<()>,
);

/// 감독 스레드를 띄우고 (핸들, 부모가 닫아야 할 자식 쪽 소켓)을 돌려줍니다.
///
/// listener fd 수신을 스레드 안에서 하는 것이 핵심입니다. 호출한 스레드는 곧바로
/// `spawn`으로 넘어가야 자식의 첫 exec 알림에 응답이 갈 수 있습니다
#[cfg(target_os = "linux")]
fn start_supervisor(
    channel: Option<crate::notify::NotifyChannel>,
    shared: &std::sync::Arc<std::sync::Mutex<Session>>,
) -> (Option<Supervisor>, Option<std::os::fd::OwnedFd>) {
    let Some(channel) = channel else {
        return (None, None);
    };
    let (parent, child_end) = channel.split();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let session = std::sync::Arc::clone(shared);
    let flag = std::sync::Arc::clone(&stop);
    let handle = std::thread::spawn(move || match parent.receive() {
        Ok(listener) => crate::notify::supervise(listener, session, flag),
        Err(e) => {
            // 자식이 필터를 걸지 못했거나 먼저 죽었습니다. 감사가 실제보다 완전해
            // 보이지 않도록 사실을 알립니다
            eprintln!(
                "{}",
                tr!(
                    format!("airlock: 경고 중계 listener를 받지 못함: {e}"),
                    format!("airlock: warning: failed to receive the mediation listener: {e}")
                )
            );
        }
    });
    (Some((stop, handle)), Some(child_end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use airlock_audit::CanonicalTag;

    #[test]
    fn action_maps_to_decision_one_to_one() {
        assert_eq!(decision_of(Action::Allow), Decision::Allow);
        assert_eq!(decision_of(Action::Deny), Decision::Deny);
        assert_eq!(decision_of(Action::Ask), Decision::Ask);
        assert_eq!(decision_of(Action::Forbid), Decision::Forbid);
    }

    #[test]
    fn file_mode_maps_one_to_one() {
        for m in FileMode::ALL {
            assert_eq!(audit_mode_of(m).tag(), m.tag(), "{m} 태그 불일치");
        }
    }

    #[test]
    fn which_finds_absolute_programs() {
        assert_eq!(which("/bin/echo"), Some(PathBuf::from("/bin/echo")));
        assert_eq!(which("/bin/definitely-not-here"), None);
    }

    #[test]
    fn which_searches_path_for_bare_names() {
        let found = which("echo").expect("echo를 PATH에서 찾지 못함");
        assert!(found.is_absolute());
        assert!(found.ends_with("echo"));
    }

    #[test]
    fn which_rejects_missing_bare_names() {
        assert_eq!(which("airlock-no-such-binary-xyz"), None);
    }

    #[test]
    fn udp_is_evaluated_as_tcp_not_as_plaintext() {
        use airlock_policy::Protocol as P;
        assert_eq!(policy_protocol_of(audit::Protocol::Tcp), P::Tcp);
        assert_eq!(
            policy_protocol_of(audit::Protocol::Udp),
            P::Tcp,
            "정책 어휘에 없는 UDP 가 특례로 통과하면 안 됨"
        );
        assert_eq!(policy_protocol_of(audit::Protocol::Tls), P::Tls);
        assert_eq!(policy_protocol_of(audit::Protocol::Http), P::Http);
        assert!(
            !policy_protocol_of(audit::Protocol::Udp).is_plaintext(),
            "모르는 것을 평문으로 단정하면 감사 로그가 거짓 보증을 함"
        );
    }

    #[test]
    fn protocol_tags_agree_across_the_two_crates() {
        for p in [
            audit::Protocol::Tcp,
            audit::Protocol::Tls,
            audit::Protocol::Http,
        ] {
            assert_eq!(
                policy_protocol_of(p).tag(),
                p.tag(),
                "{p} 태그가 두 크레이트에서 어긋남"
            );
        }
    }

    #[test]
    fn the_default_anchor_root_is_outside_the_session_directory() {
        let session = Path::new("/tmp/root/sessions/1700-42");
        assert_eq!(
            anchor_dir_for(session, None),
            PathBuf::from("/tmp/root"),
            "앵커가 감사 루트에 있어야 세션 통째 삭제가 흔적을 남김"
        );
        // sessions 레이아웃이 아니면 바로 위를 씁니다. 어느 쪽이든 세션 바깥입니다
        assert_eq!(
            anchor_dir_for(Path::new("/tmp/flat/one"), None),
            PathBuf::from("/tmp/flat")
        );
        assert_eq!(
            anchor_dir_for(session, Some(Path::new("/mnt/wormvol"))),
            PathBuf::from("/mnt/wormvol"),
            "명시한 앵커 루트가 이겨야 분리가 가능함"
        );
    }

    /// 소켓 핸들 변수는 시크릿 경로 기본 deny 의 연장으로 자식에게 넘기지 않습니다
    #[test]
    fn socket_handles_and_injection_hooks_are_stripped_from_the_child_env() {
        use std::ffi::OsString;

        let mut cmd = std::process::Command::new("/usr/bin/true");
        let keys = [
            "SSH_AUTH_SOCK",
            "DOCKER_HOST",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
            "BASH_ENV",
            "AIRLOCK_AUDIT_DIR",
            "PATH",
            "HOME",
            "TERM",
        ]
        .into_iter()
        .map(OsString::from);
        super::sanitize_env_from(&mut cmd, keys);

        let removed: Vec<String> = cmd
            .get_envs()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        for key in [
            "SSH_AUTH_SOCK",
            "DOCKER_HOST",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
            "BASH_ENV",
            "AIRLOCK_AUDIT_DIR",
        ] {
            assert!(
                removed.iter().any(|r| r == key),
                "{key} 가 자식에게 넘어감: {removed:?}"
            );
        }
        for key in ["PATH", "HOME", "TERM"] {
            assert!(
                !removed.iter().any(|r| r == key),
                "{key} 는 보존해야 함: {removed:?}"
            );
        }
        assert!(super::env_is_stripped("SSH_AUTH_SOCK"));
        assert!(super::env_is_stripped("DOCKER_HOST"));
        assert!(!super::env_is_stripped("DOCKER_HOSTNAME"));
        assert!(!super::env_is_stripped("SSH_AUTH_SOCKET"));
    }
}
