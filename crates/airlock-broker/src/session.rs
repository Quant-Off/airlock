use std::path::{Path, PathBuf};
use std::process::Command;

use airlock_audit as audit;
use airlock_audit::{AuditLog, Decision, Enforcement, Event, GenesisInfo, Granted, Record};
use airlock_policy::{Action, Evaluation, FileMode, Policy};

use crate::approve::{ApprovalRequest, Approver};
use crate::enforcer::Enforcer;
use crate::error::{BrokerError, Result};

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
    /// 자식의 syscall을 어디까지 브로커로 중계할지. Linux에서만 의미가 있습니다
    pub mediation: Mediation,
}

/// 런타임 중계 수준.
///
/// Linux에서는 `crate::notify::Level`로 옮겨져 seccomp user notification 필터가 됩니다.
/// 다른 플랫폼에는 중계 기구가 없으므로 값이 무시되고 그 사실이 gap으로 노출됩니다
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mediation {
    Off,
    #[default]
    ExecNet,
    Full,
}

impl Mediation {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "exec-net" => Some(Self::ExecNet),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::ExecNet => "exec-net",
            Self::Full => "full",
        }
    }
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
            what: "세션 식별자 생성".to_string(),
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
        })
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

    fn commit(
        &mut self,
        event: Event,
        eval: &Evaluation,
        request: ApprovalRequest,
    ) -> Result<Outcome> {
        let decision = decision_of(eval.action);
        let mut record = Record::new(self.actor.clone(), event, decision);
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
        self.log.append(Record::new(
            audit::BROKER_ACTOR,
            Event::Approval {
                for_seq: entry.seq,
                granted,
                note,
            },
            decision_of(effective),
        ))?;

        Ok(Outcome {
            action: effective,
            seq: entry.seq,
        })
    }

    pub fn check_file(&mut self, path: &Path, mode: FileMode) -> Result<Outcome> {
        let cwd = self.cwd.clone();
        let eval = self.policy.evaluate_file(path, mode, &cwd);
        let (requested, resolved) = self.resolve(&eval);

        let mut request = ApprovalRequest::new("파일 접근 시도")
            .fact("요청 경로", requested.clone())
            .fact("모드", mode.as_str());
        if requested != resolved {
            request = request.fact("해소 경로", resolved.clone());
        }

        let event = Event::FileAccess {
            path_requested: requested,
            path_resolved: resolved,
            mode: audit_mode_of(mode),
        };
        self.commit(event, &eval, request)
    }

    pub fn check_exec(&mut self, program: &Path, argv: &[String]) -> Result<Outcome> {
        let cwd = self.cwd.clone();
        let eval = self.policy.evaluate_exec(program, argv, &cwd);
        let (requested, resolved) = self.resolve(&eval);

        let mut request = ApprovalRequest::new("프로세스 실행 시도")
            .fact("프로그램", requested.clone())
            .fact("argv", format!("{argv:?}"))
            .fact("cwd", cwd.to_string_lossy().into_owned());
        if requested != resolved {
            request = request.fact("해소 경로", resolved.clone());
        }

        let event = Event::Exec {
            program: resolved.clone(),
            argv: argv.to_vec(),
            cwd: cwd.to_string_lossy().into_owned(),
        };
        self.commit(event, &eval, request)
    }

    pub fn check_egress(
        &mut self,
        host: &str,
        port: u16,
        protocol: audit::Protocol,
    ) -> Result<Outcome> {
        let eval = self.policy.evaluate_egress(host, port);
        let request = ApprovalRequest::new("아웃바운드 연결 시도")
            .fact("호스트", host.to_string())
            .fact("포트", port.to_string());

        let event = Event::Egress {
            host: host.to_string(),
            port,
            protocol,
        };
        self.commit(event, &eval, request)
    }

    pub fn finish(&mut self, status: Option<&std::process::ExitStatus>) -> Result<audit::Hash> {
        let audit_status = match status {
            Some(s) => exit_status_of(s),
            None => audit::ExitStatus::Unknown,
        };
        self.log.append(Record::new(
            audit::BROKER_ACTOR,
            Event::SessionEnd {
                status: audit_status,
            },
            Decision::Allow,
        ))?;
        Ok(self.log.head_hash())
    }
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

#[derive(Debug)]
pub struct RunReport {
    pub audit_dir: PathBuf,
    pub head_seq: Option<u64>,
    pub head_hash: audit::Hash,
    pub exit_code: Option<i32>,
    pub asked: u64,
    pub denied: u64,
    pub enforcement: Enforcement,
    pub gaps: Vec<String>,
}

pub fn run(
    program: &str,
    args: &[String],
    policy: Policy,
    mut enforcer: Box<dyn Enforcer>,
    approver: Box<dyn Approver>,
    config: &SessionConfig,
) -> Result<RunReport> {
    let resolved =
        which(program).ok_or_else(|| BrokerError::ProgramNotFound(program.to_string()))?;
    enforcer.prepare(&policy)?;

    let enforcement = enforcer.kind();
    let gaps = enforcer.gaps();

    let mut session = Session::start(policy, enforcement, approver, config)?;

    let mut argv = Vec::with_capacity(args.len().saturating_add(1));
    argv.push(program.to_string());
    argv.extend_from_slice(args);

    let outcome = session.check_exec(&resolved, &argv)?;
    if !outcome.permitted() {
        let asked = session.asked_count();
        let denied = session.denied_count();
        let head_seq = session.head_seq();
        let hash = session.finish(None)?;
        return Ok(RunReport {
            audit_dir: config.audit_dir.clone(),
            head_seq,
            head_hash: hash,
            exit_code: None,
            asked,
            denied,
            enforcement,
            gaps,
        });
    }

    let mut cmd = Command::new(&resolved);
    cmd.args(args);
    cmd.current_dir(&config.cwd);

    // 중계 훅을 강제 층보다 먼저 겁니다. listener fd를 부모에게 넘기는 sendmsg가
    // 샌드박스 적용 전에 끝나야 합니다
    #[cfg(target_os = "linux")]
    let channel = setup_mediation(&mut cmd, config.mediation);

    enforcer.wrap(&mut cmd)?;

    let shared = std::sync::Arc::new(std::sync::Mutex::new(session));

    // 감독 스레드를 spawn보다 먼저 띄웁니다. spawn은 자식이 exec을 마쳐야 돌아오는데
    // 그 exec 자체가 알림으로 멈추므로, 같은 스레드에서 기다리면 서로를 막습니다
    #[cfg(target_os = "linux")]
    let (supervisor, child_end) = start_supervisor(channel, &shared);

    let spawned = cmd.spawn().map_err(|source| BrokerError::Io {
        what: format!("{} 실행", resolved.display()),
        source,
    });

    // 부모가 들고 있는 자식 쪽 소켓을 닫아야 자식이 죽었을 때 감독 스레드가 EOF를 봅니다
    #[cfg(target_os = "linux")]
    drop(child_end);

    let mut child = spawned?;

    let status = child.wait().map_err(|source| BrokerError::Io {
        what: format!("{} 대기", resolved.display()),
        source,
    })?;

    // 자식이 모두 끝나면 커널이 listener를 닫아 RECV가 실패로 빠져나옵니다
    #[cfg(target_os = "linux")]
    if let Some((stop, handle)) = supervisor {
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = handle.join();
    }

    let mut session = match shared.lock() {
        Ok(s) => s,
        Err(poisoned) => poisoned.into_inner(),
    };
    let asked = session.asked_count();
    let denied = session.denied_count();
    let head_seq = session.head_seq();
    let hash = session.finish(Some(&status))?;

    Ok(RunReport {
        audit_dir: config.audit_dir.clone(),
        head_seq,
        head_hash: hash,
        exit_code: status.code(),
        asked,
        denied,
        enforcement,
        gaps,
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
            eprintln!("airlock: 경고 런타임 중계를 켤 수 없음: {e}. 세션 단위 기록만 남음");
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
            eprintln!("airlock: 경고 중계 listener를 받지 못함: {e}");
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
}
