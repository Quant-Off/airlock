//! 정책·감사·승인을 잇는 접합부를 검사합니다.
//!
//! # Features
//! `Session`은 결정을 평가하고 엔트리를 쓰고 필요하면 사람에게 묻는 세 층의 접합부입니다.
//! 이 파일은 플랫폼 강제 층 없이 그 접합부만 봅니다. 강제 층 검사는
//! `enforce.rs`(macOS)와 `landlock_enforce.rs`(Linux)가 담당합니다.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use airlock_audit::{
    CHAIN_FILE, Decision, Enforcement, Entry, Event, Granted, Mediation, Protocol, verify_dir,
};
use airlock_broker::{Actor, AnchorOutcome, ApprovalRequest, Approver, Session, SessionConfig};
use airlock_policy::{Action, FileMode, LoadContext, Policy};

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "airlock-session-{tag}-{}-{}",
            std::process::id(),
            airlock_audit::now_unix_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        // 정규화한 경로를 씁니다. macOS 의 /tmp 는 /private/tmp 심볼릭 링크라서, 정규화
        // 전 경로로 규칙을 쓰면 4.1절 양방향 평가가 해소 경로에서 규칙을 못 찾아 거부합니다
        Self(std::fs::canonicalize(&p).unwrap())
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// 규칙이 허용하는 작업 공간
    fn ws(&self) -> PathBuf {
        self.0.join("ws")
    }

    fn session_dir(&self) -> PathBuf {
        self.0.join("sessions/one")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 미리 정한 답을 돌려주고 몇 번 물었는지 세는 승인자
#[derive(Debug)]
struct Scripted {
    answer: Granted,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Scripted {
    fn new(answer: Granted) -> Self {
        Self {
            answer,
            asked: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn log(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.asked)
    }
}

impl Approver for Scripted {
    fn ask(&mut self, request: &ApprovalRequest) -> Granted {
        if let Ok(mut v) = self.asked.lock() {
            v.push(request.headline.clone());
        }
        self.answer
    }

    fn describe(&self) -> String {
        format!("테스트 승인자 ({:?})", self.answer)
    }

    fn note(&self) -> Option<String> {
        Some("테스트".to_string())
    }
}

fn policy(scratch: &Scratch, rules: &str) -> Policy {
    let src = format!(
        r#"
version = 1
name = "session-test"
[defaults]
file = "deny"
exec = "deny"
egress = "deny"
{rules}
"#
    );
    let ctx = LoadContext::new(scratch.path().join("home"), scratch.path().join("audit"));
    Policy::load_str(&src, &ctx).unwrap()
}

fn config(scratch: &Scratch, mediation: Mediation) -> SessionConfig {
    SessionConfig {
        audit_dir: scratch.session_dir(),
        actor: "pid:1 test".to_string(),
        cwd: scratch.path().to_path_buf(),
        argv: vec!["airlock".to_string(), "run".to_string()],
        fsync_per_entry: true,
        policy_source: None,
        airlock_version: "0.0.0-test".to_string(),
        mediation,
        anchor_dir: None,
    }
}

fn start(scratch: &Scratch, policy: Policy, answer: Granted) -> (Session, Arc<Mutex<Vec<String>>>) {
    let approver = Scripted::new(answer);
    let log = approver.log();
    let session = Session::start(
        policy,
        Enforcement::Observe,
        Box::new(approver),
        &config(scratch, Mediation::ExecNet),
    )
    .unwrap();
    (session, log)
}

fn entries(dir: &Path) -> Vec<Entry> {
    std::fs::read_to_string(dir.join(CHAIN_FILE))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

// ---------- 결정이 엔트리가 되는지 ----------

#[test]
fn allowed_file_access_is_recorded_without_asking() {
    let s = Scratch::new("allow");
    let p = policy(
        &s,
        &format!(
            r#"
[[rules]]
id = "ws"
kind = "file"
path = "{}/**"
action = "allow"
"#,
            s.ws().display()
        ),
    );
    let (mut session, asked) = start(&s, p, Granted::Refused);

    let target = s.ws().join("main.rs");
    let out = session
        .check_file(&target, FileMode::Read, Actor::Broker)
        .unwrap();
    assert_eq!(out.action, Action::Allow);
    assert!(out.permitted());
    assert_eq!(session.asked_count(), 0);
    assert_eq!(session.denied_count(), 0);
    assert!(
        asked.lock().unwrap().is_empty(),
        "allow인데 사람에게 물었음"
    );

    let es = entries(&s.session_dir());
    assert_eq!(es.len(), 2, "제네시스와 파일 접근 두 개여야 함");
    assert_eq!(es[1].decision, Decision::Allow);
    assert_eq!(es[1].rule.as_deref(), Some("ws"));
    match &es[1].event {
        Event::FileAccess { path_requested, .. } => {
            assert_eq!(path_requested, &target.to_string_lossy());
        }
        other => panic!("파일 접근 엔트리가 아님: {other:?}"),
    }
}

#[test]
fn denied_file_access_is_recorded_and_counted() {
    let s = Scratch::new("deny");
    let p = policy(&s, "");
    let (mut session, _) = start(&s, p, Granted::Approved);

    let out = session
        .check_file(
            Path::new("/tmp/elsewhere/x"),
            FileMode::Write,
            Actor::Broker,
        )
        .unwrap();
    assert_eq!(out.action, Action::Deny);
    assert!(!out.permitted());
    assert_eq!(session.denied_count(), 1);
    assert_eq!(session.asked_count(), 0, "deny는 사람에게 묻지 않음");

    let es = entries(&s.session_dir());
    assert_eq!(es[1].decision, Decision::Deny);
    assert_eq!(es[1].rule, None, "기본값 적용은 rule이 비어야 함");
}

#[test]
fn forbidden_secret_is_recorded_as_forbid() {
    let s = Scratch::new("forbid");
    let home = s.path().join("home");
    let p = policy(
        &s,
        r#"
[[rules]]
id = "everything"
kind = "file"
path = "/**"
action = "allow"
"#,
    );
    let (mut session, _) = start(&s, p, Granted::Approved);

    let key = home.join(".ssh/id_ed25519");
    let out = session
        .check_file(&key, FileMode::Read, Actor::Broker)
        .unwrap();
    assert_eq!(
        out.action,
        Action::Forbid,
        "전부 허용하는 사용자 규칙이 내장 forbid를 덮었음"
    );
    let es = entries(&s.session_dir());
    assert_eq!(es[1].decision, Decision::Forbid);
    assert_eq!(es[1].rule.as_deref(), Some("ssh-private-keys"));
}

// ---------- ask 와 승인 ----------

#[test]
fn ask_writes_the_attempt_before_the_answer() {
    let s = Scratch::new("ask-order");
    let p = policy(
        &s,
        &format!(
            r#"
[[rules]]
id = "shell-config"
kind = "file"
path = "{}/config"
action = "ask"
"#,
            s.ws().display()
        ),
    );
    let (mut session, asked) = start(&s, p, Granted::Approved);

    let out = session
        .check_file(&s.ws().join("config"), FileMode::Write, Actor::Broker)
        .unwrap();
    assert_eq!(out.action, Action::Allow, "승인했는데 허용되지 않았음");
    assert_eq!(session.asked_count(), 1);
    assert_eq!(session.denied_count(), 0);
    assert_eq!(asked.lock().unwrap().len(), 1);

    let es = entries(&s.session_dir());
    assert_eq!(es.len(), 3);
    assert_eq!(
        es[1].decision,
        Decision::Ask,
        "시도 자체가 ask로 먼저 기록되어야 함"
    );
    match &es[2].event {
        Event::Approval {
            for_seq,
            granted,
            note,
            approver_uid,
            approver_tty,
        } => {
            assert_eq!(*for_seq, es[1].seq, "승인 엔트리가 시도를 가리켜야 함");
            assert_eq!(*granted, Granted::Approved);
            assert_eq!(note.as_deref(), Some("테스트"));
            assert_eq!(
                (*approver_uid, approver_tty.as_deref()),
                (None, None),
                "신원을 관측하지 않는 승인자가 사람 신원을 남기면 안 됨"
            );
        }
        other => panic!("승인 엔트리가 아님: {other:?}"),
    }
    assert_eq!(es[2].decision, Decision::Allow, "승인 결과가 결정에 반영됨");
    assert_eq!(es[2].actor, "airlock", "승인 엔트리는 브로커가 씀");
}

#[test]
fn refusal_turns_ask_into_deny() {
    let s = Scratch::new("ask-refuse");
    let p = policy(
        &s,
        &format!(
            r#"
[[rules]]
id = "shell-config"
kind = "file"
path = "{}/config"
action = "ask"
"#,
            s.ws().display()
        ),
    );
    let (mut session, _) = start(&s, p, Granted::Refused);

    let out = session
        .check_file(&s.ws().join("config"), FileMode::Write, Actor::Broker)
        .unwrap();
    assert_eq!(out.action, Action::Deny);
    assert_eq!(session.asked_count(), 1);
    assert_eq!(session.denied_count(), 1);

    let es = entries(&s.session_dir());
    assert_eq!(es[2].decision, Decision::Deny);
}

#[test]
fn timeout_is_recorded_as_such_and_denies() {
    let s = Scratch::new("ask-timeout");
    let p = policy(
        &s,
        &format!(
            r#"
[[rules]]
id = "shell-config"
kind = "file"
path = "{}/config"
action = "ask"
"#,
            s.ws().display()
        ),
    );
    let (mut session, _) = start(&s, p, Granted::TimedOut);

    let out = session
        .check_file(&s.ws().join("config"), FileMode::Write, Actor::Broker)
        .unwrap();
    assert_eq!(out.action, Action::Deny, "응답이 없으면 거부여야 함");
    assert_eq!(session.denied_count(), 1);

    let es = entries(&s.session_dir());
    match &es[2].event {
        Event::Approval { granted, .. } => assert_eq!(
            *granted,
            Granted::TimedOut,
            "거부와 무응답이 로그에서 구분되어야 함"
        ),
        other => panic!("승인 엔트리가 아님: {other:?}"),
    }
    assert_eq!(es[2].decision, Decision::Deny);
}

// ---------- exec 과 egress ----------

#[test]
fn exec_records_program_and_argv() {
    let s = Scratch::new("exec");
    // 스크래치 안의 경로를 씁니다. 배포판마다 /bin 이 /usr/bin 심볼릭 링크라서
    // 시스템 경로로 규칙을 쓰면 해소 경로가 갈라져 결정이 달라집니다
    let tool = s.path().join("bin/tool");
    std::fs::create_dir_all(tool.parent().unwrap()).unwrap();
    std::fs::write(&tool, b"#!/bin/sh\n").unwrap();

    let p = policy(
        &s,
        &format!(
            r#"
[[rules]]
id = "allow-tool"
kind = "exec"
program = "{}"
action = "allow"
"#,
            tool.display()
        ),
    );
    let (mut session, _) = start(&s, p, Granted::Refused);

    let argv = vec![tool.to_string_lossy().into_owned(), "hi".to_string()];
    let out = session.check_exec(&tool, &argv, Actor::Broker).unwrap();
    assert_eq!(out.action, Action::Allow);

    let es = entries(&s.session_dir());
    match &es[1].event {
        Event::Exec {
            program,
            argv: got,
            cwd,
        } => {
            assert_eq!(program, &tool.to_string_lossy());
            assert_eq!(got, &argv, "argv 원본이 그대로 남아야 함");
            assert_eq!(cwd, &s.path().to_string_lossy());
        }
        other => panic!("exec 엔트리가 아님: {other:?}"),
    }
}

#[test]
fn egress_records_host_and_port() {
    let s = Scratch::new("egress");
    let p = policy(
        &s,
        r#"
[[rules]]
id = "api"
kind = "egress"
host = "api.anthropic.com"
port = 443
action = "allow"
"#,
    );
    let (mut session, _) = start(&s, p, Granted::Refused);

    let allowed = session
        .check_egress("api.anthropic.com", 443, Protocol::Tls, Actor::Broker)
        .unwrap();
    assert_eq!(allowed.action, Action::Allow);

    let blocked = session
        .check_egress("169.254.169.254", 80, Protocol::Http, Actor::Broker)
        .unwrap();
    assert_eq!(blocked.action, Action::Deny);
    assert_eq!(session.denied_count(), 1);

    let es = entries(&s.session_dir());
    match &es[2].event {
        Event::Egress {
            host,
            port,
            protocol,
        } => {
            assert_eq!(host, "169.254.169.254");
            assert_eq!(*port, 80);
            assert_eq!(*protocol, Protocol::Http);
        }
        other => panic!("egress 엔트리가 아님: {other:?}"),
    }
}

// ---------- 제네시스와 종료 ----------

#[test]
fn genesis_records_the_effective_mediation_level() {
    for level in [Mediation::Off, Mediation::ExecNet, Mediation::Full] {
        let s = Scratch::new("genesis");
        let approver = Scripted::new(Granted::Refused);
        let mut session = Session::start(
            policy(&s, ""),
            Enforcement::Observe,
            Box::new(approver),
            &config(&s, level),
        )
        .unwrap();
        session.finish(None).unwrap();

        let es = entries(&s.session_dir());
        match &es[0].event {
            Event::SessionStart { mediation, .. } => assert_eq!(
                *mediation, level,
                "제네시스가 중계 수준을 담지 않으면 exec 엔트리 없음이 무엇을 뜻하는지 알 수 없음"
            ),
            other => panic!("제네시스가 session_start가 아님: {other:?}"),
        }
    }
}

#[test]
fn finish_records_the_exit_status_and_chain_verifies() {
    let s = Scratch::new("finish");
    let p = policy(
        &s,
        &format!(
            r#"
[[rules]]
id = "shell-config"
kind = "file"
path = "{}/config"
action = "ask"
"#,
            s.ws().display()
        ),
    );
    let (mut session, _) = start(&s, p, Granted::Approved);
    session
        .check_file(&s.ws().join("config"), FileMode::Write, Actor::Broker)
        .unwrap();
    session
        .check_file(&s.path().join("nope"), FileMode::Read, Actor::Broker)
        .unwrap();

    let status = std::process::Command::new("/bin/sh")
        .args(["-c", "exit 3"])
        .status()
        .unwrap();
    let closed = session.finish(Some(&status)).unwrap();

    let es = entries(&s.session_dir());
    match es.last().map(|e| &e.event) {
        Some(Event::SessionEnd { status }) => assert_eq!(
            *status,
            airlock_audit::ExitStatus::Exited { code: 3 },
            "종료 코드가 그대로 남아야 함"
        ),
        other => panic!("세션 종료 엔트리가 아님: {other:?}"),
    }
    assert_eq!(
        closed.head_hash,
        es.last().unwrap().hash,
        "돌려준 체인 헤드가 다름"
    );
    assert!(
        matches!(closed.anchor, AnchorOutcome::Written { .. }),
        "세션 종료가 앵커를 남기지 않았음: {:?}",
        closed.anchor
    );

    let report = verify_dir(s.session_dir()).unwrap();
    assert_eq!(report.entries, es.len() as u64);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| matches!(w, airlock_audit::Warning::ObserveOnlyEntries { .. })),
        "observe 세션은 강제되지 않았음이 보고되어야 함: {:?}",
        report.warnings
    );
}

#[test]
fn signaled_child_is_recorded_as_signaled() {
    let s = Scratch::new("signal");
    let (mut session, _) = start(&s, policy(&s, ""), Granted::Refused);

    let status = std::process::Command::new("/bin/sh")
        .args(["-c", "kill -TERM $$"])
        .status()
        .unwrap();
    session.finish(Some(&status)).unwrap();

    let es = entries(&s.session_dir());
    match es.last().map(|e| &e.event) {
        Some(Event::SessionEnd { status }) => assert_eq!(
            *status,
            airlock_audit::ExitStatus::Signaled { signal: 15 },
            "시그널 종료가 정상 종료처럼 남으면 안 됨"
        ),
        other => panic!("세션 종료 엔트리가 아님: {other:?}"),
    }
    verify_dir(s.session_dir()).unwrap();
}

// ---------- 승인자 신원 ----------

#[test]
fn an_automatic_approval_never_looks_like_a_human_one() {
    let s = Scratch::new("auto-approve");
    let p = policy(
        &s,
        &format!(
            r#"
[[rules]]
id = "shell-config"
kind = "file"
path = "{}/config"
action = "ask"
"#,
            s.ws().display()
        ),
    );
    let mut session = Session::start(
        p,
        Enforcement::Observe,
        Box::new(airlock_broker::ApproveAll),
        &config(&s, Mediation::ExecNet),
    )
    .unwrap();

    let out = session
        .check_file(&s.ws().join("config"), FileMode::Write, Actor::Broker)
        .unwrap();
    assert_eq!(out.action, Action::Allow);

    let es = entries(&s.session_dir());
    match es.last().map(|e| &e.event) {
        Some(Event::Approval {
            approver_uid,
            approver_tty,
            note,
            ..
        }) => {
            assert_eq!(
                (*approver_uid, approver_tty.as_deref()),
                (None, None),
                "--yes 자동 승인이 사람 신원을 남기면 승인 통제 자체가 무의미해짐"
            );
            assert!(note.is_some(), "자동 승인이라는 사실이 남아야 함");
        }
        other => panic!("승인 엔트리가 아님: {other:?}"),
    }
}

// ---------- actor 실체화 ----------

#[test]
fn the_log_tells_broker_observed_and_unknown_apart() {
    let s = Scratch::new("actor");
    let p = policy(
        &s,
        &format!(
            r#"
[[rules]]
id = "ws"
kind = "file"
path = "{}/**"
action = "allow"
"#,
            s.ws().display()
        ),
    );
    let (mut session, _) = start(&s, p, Granted::Refused);

    session
        .check_file(&s.ws().join("a"), FileMode::Read, Actor::Broker)
        .unwrap();
    session
        .check_file(&s.ws().join("b"), FileMode::Read, Actor::Observed(41233))
        .unwrap();
    session
        .check_file(&s.ws().join("c"), FileMode::Read, Actor::Unknown)
        .unwrap();

    let es = entries(&s.session_dir());
    let actors: Vec<&str> = es[1..4].iter().map(|e| e.actor.as_str()).collect();
    assert_eq!(actors[0], "pid:1 test", "브로커 판정은 세션 actor 를 씀");
    assert_eq!(
        actors[1], "pid:41233",
        "중계가 관측한 pid 가 그대로 남아야 어느 자손이 열었는지 복원됨"
    );
    assert_eq!(
        actors[2],
        airlock_broker::UNKNOWN_ACTOR,
        "주체를 모르는 판정이 브로커 자신처럼 보이면 안 됨"
    );
    assert_ne!(actors[0], actors[1]);
    assert_ne!(actors[0], actors[2]);
    assert_ne!(actors[1], actors[2]);
    verify_dir(s.session_dir()).unwrap();
}

// ---------- 평문 바닥 ----------

#[test]
fn plaintext_egress_is_floored_even_on_an_allowed_host() {
    let s = Scratch::new("plaintext");
    let p = policy(
        &s,
        r#"
[[rules]]
id = "mirror"
kind = "egress"
host = "mirror.example.com"
port = 80
action = "allow"
"#,
    );
    let (mut session, _) = start(&s, p, Granted::Refused);

    let tls = session
        .check_egress("mirror.example.com", 80, Protocol::Tls, Actor::Unknown)
        .unwrap();
    assert_eq!(
        tls.action,
        Action::Allow,
        "호스트 allow 는 그대로 통해야 함"
    );

    let plain = session
        .check_egress("mirror.example.com", 80, Protocol::Http, Actor::Unknown)
        .unwrap();
    assert_eq!(
        plain.action,
        Action::Deny,
        "호스트만 적은 allow 가 평문까지 암묵 허가하면 안 됨"
    );

    let es = entries(&s.session_dir());
    let last = es.last().unwrap();
    assert_eq!(last.decision, Decision::Deny);
    assert_eq!(
        last.rule.as_deref(),
        Some(airlock_policy::PLAINTEXT_FLOOR_ID),
        "어느 규칙이 막았는지 감사 로그만 보고 알 수 있어야 함"
    );
    match &last.event {
        Event::Egress { protocol, .. } => assert_eq!(*protocol, Protocol::Http),
        other => panic!("egress 엔트리가 아님: {other:?}"),
    }
}

// ---------- 앵커 ----------

#[test]
fn finishing_anchors_the_session_outside_its_own_directory() {
    let s = Scratch::new("anchor");
    let (mut session, _) = start(&s, policy(&s, ""), Granted::Refused);
    let anchors = session.anchor_dir().to_path_buf();

    let closed = session.finish(None).unwrap();
    let AnchorOutcome::Written { path, .. } = &closed.anchor else {
        panic!("앵커가 기록되지 않았음: {:?}", closed.anchor);
    };
    assert!(path.is_file(), "{} 가 만들어지지 않았음", path.display());
    assert!(
        !path.starts_with(s.session_dir()),
        "앵커가 세션 디렉토리 안에 있으면 세션 통째 삭제로 함께 사라짐: {}",
        path.display()
    );

    let report = airlock_audit::verify_anchors(&anchors).unwrap();
    assert_eq!(report.entries, 1);

    let verified = verify_dir(s.session_dir()).unwrap();
    let check = airlock_audit::check_session(
        &anchors,
        &verified.session,
        verified.head_seq,
        &verified.head_hash,
    )
    .unwrap();
    assert!(
        matches!(check, airlock_audit::AnchorCheck::Matches { .. }),
        "앵커와 세션 head 가 어긋남: {check:?}"
    );
}

#[test]
fn an_explicit_anchor_root_is_honoured() {
    let s = Scratch::new("anchor-explicit");
    let separated = s.path().join("elsewhere/anchors");
    let cfg = SessionConfig {
        anchor_dir: Some(separated.clone()),
        ..config(&s, Mediation::ExecNet)
    };
    let mut session = Session::start(
        policy(&s, ""),
        Enforcement::Observe,
        Box::new(Scripted::new(Granted::Refused)),
        &cfg,
    )
    .unwrap();

    let closed = session.finish(None).unwrap();
    assert_eq!(closed.anchor.failure(), None, "{:?}", closed.anchor);
    assert!(
        separated.join(airlock_audit::ANCHOR_FILE).is_file(),
        "명시한 앵커 루트에 쓰이지 않았음"
    );
}

#[test]
fn a_second_session_extends_the_same_anchor_chain() {
    let s = Scratch::new("anchor-chain");
    for name in ["one", "two"] {
        let cfg = SessionConfig {
            audit_dir: s.path().join("sessions").join(name),
            ..config(&s, Mediation::ExecNet)
        };
        let mut session = Session::start(
            policy(&s, ""),
            Enforcement::Observe,
            Box::new(Scripted::new(Granted::Refused)),
            &cfg,
        )
        .unwrap();
        assert_eq!(session.finish(None).unwrap().anchor.failure(), None);
    }

    let report = airlock_audit::verify_anchors(s.path()).unwrap();
    assert_eq!(report.entries, 2, "두 세션이 한 체인에 이어져야 함");
    assert_eq!(report.sessions, 2);
}

#[test]
fn concurrent_sessions_do_not_corrupt_the_shared_anchor_chain() {
    let s = Scratch::new("anchor-race");
    let root = s.path().to_path_buf();
    let mut handles = Vec::new();
    for i in 0..6 {
        let dir = root.join("sessions").join(format!("s{i}"));
        let home = root.join("home");
        let audit = root.join("audit");
        let cwd = root.clone();
        handles.push(std::thread::spawn(move || {
            let ctx = LoadContext::new(&home, &audit);
            let policy = Policy::baseline_only(&ctx).unwrap();
            let cfg = SessionConfig {
                audit_dir: dir,
                actor: "pid:1 test".to_string(),
                cwd,
                argv: vec!["airlock".to_string()],
                fsync_per_entry: false,
                policy_source: None,
                airlock_version: "0.0.0-test".to_string(),
                mediation: Mediation::ExecNet,
                anchor_dir: None,
            };
            let mut session = Session::start(
                policy,
                Enforcement::Observe,
                Box::new(Scripted::new(Granted::Refused)),
                &cfg,
            )
            .unwrap();
            session.finish(None).unwrap().anchor
        }));
    }

    for h in handles {
        let anchor = h.join().unwrap();
        assert_eq!(anchor.failure(), None, "{anchor:?}");
    }

    // 잠금이 없으면 두 세션이 같은 head 를 읽고 같은 seq 로 써서 체인이 깨집니다.
    // 깨진 체인에는 그 뒤로 아무도 이어 붙이지 못합니다
    let report = airlock_audit::verify_anchors(s.path()).unwrap();
    assert_eq!(report.entries, 6);
    assert_eq!(report.sessions, 6);
}

#[test]
fn an_unwritable_anchor_root_is_reported_not_swallowed() {
    let s = Scratch::new("anchor-fail");
    // 앵커 루트 자리에 파일을 놓아 디렉토리 생성을 실패시킵니다
    let blocked = s.path().join("blocked");
    std::fs::write(&blocked, b"not a directory").unwrap();
    let cfg = SessionConfig {
        anchor_dir: Some(blocked.join("under")),
        ..config(&s, Mediation::ExecNet)
    };
    let mut session = Session::start(
        policy(&s, ""),
        Enforcement::Observe,
        Box::new(Scripted::new(Granted::Refused)),
        &cfg,
    )
    .unwrap();

    let closed = session.finish(None).unwrap();
    assert!(
        closed.anchor.failure().is_some(),
        "앵커 실패를 성공으로 보고하면 앵커 없는 세션이 앵커된 세션처럼 보임: {:?}",
        closed.anchor
    );
    // 세션 체인 자체는 정상입니다. 앵커 실패가 감사 로그를 망가뜨리지는 않습니다
    verify_dir(s.session_dir()).unwrap();
}

#[test]
fn every_decision_lands_in_the_chain_in_order() {
    let s = Scratch::new("order");
    let p = policy(
        &s,
        &format!(
            r#"
[[rules]]
id = "ws"
kind = "file"
path = "{}/**"
action = "allow"
"#,
            s.ws().display()
        ),
    );
    let (mut session, _) = start(&s, p, Granted::Refused);

    session
        .check_file(&s.ws().join("a"), FileMode::Read, Actor::Broker)
        .unwrap();
    session
        .check_file(&s.path().join("other/b"), FileMode::Read, Actor::Broker)
        .unwrap();
    session
        .check_file(&s.ws().join("c"), FileMode::Write, Actor::Broker)
        .unwrap();
    session.finish(None).unwrap();

    let es = entries(&s.session_dir());
    let decisions: Vec<Decision> = es.iter().map(|e| e.decision).collect();
    assert_eq!(
        decisions,
        vec![
            Decision::Allow,
            Decision::Allow,
            Decision::Deny,
            Decision::Allow,
            Decision::Allow
        ]
    );
    for (i, e) in es.iter().enumerate() {
        assert_eq!(e.seq, i as u64, "seq에 빈틈이 있음");
    }
    verify_dir(s.session_dir()).unwrap();
}

// ---------- 아웃바운드 결과 기록과 총량 한도 ----------

fn quota_policy(scratch: &Scratch, limit: u64) -> Policy {
    policy(
        scratch,
        &format!(
            r#"
[[rules]]
id = "mirror"
kind = "egress"
host = "mirror.example.com"
port = 443
max_bytes_out = {limit}
action = "allow"
"#
        ),
    )
}

#[test]
fn an_egress_summary_is_a_fact_not_a_decision() {
    let s = Scratch::new("summary");
    let (mut session, _) = start(&s, quota_policy(&s, 1_000_000), Granted::Refused);
    session
        .check_egress("mirror.example.com", 443, Protocol::Tls, Actor::Unknown)
        .unwrap();
    session
        .record_egress_summary(
            "mirror.example.com",
            443,
            Protocol::Tls,
            4_096,
            8_192,
            250,
            Actor::Unknown,
        )
        .unwrap();
    session.finish(None).unwrap();

    let es = entries(&s.session_dir());
    let summary = es
        .iter()
        .find(|e| matches!(e.event, Event::EgressSummary { .. }))
        .expect("결과 엔트리가 남아야 함");
    assert_eq!(summary.decision, Decision::Allow);
    assert_eq!(
        summary.rule.as_deref(),
        Some("airlock:egress-summary"),
        "규칙 없는 allow 로 남기면 [defaults] 가 열어 준 것처럼 보임"
    );
    match &summary.event {
        Event::EgressSummary {
            host,
            port,
            bytes_out,
            bytes_in,
            duration_ms,
            ..
        } => {
            assert_eq!(host, "mirror.example.com");
            assert_eq!(*port, 443);
            assert_eq!(*bytes_out, 4_096);
            assert_eq!(*bytes_in, 8_192);
            assert_eq!(*duration_ms, 250);
        }
        other => panic!("결과 엔트리가 아님: {other:?}"),
    }
    // 시도 엔트리와 결과 엔트리는 서로 다른 사실이며 둘 다 남아야 합니다
    assert!(es.iter().any(|e| matches!(e.event, Event::Egress { .. })));
    verify_dir(s.session_dir()).unwrap();
}

#[test]
fn the_quota_blocks_the_next_connection_and_the_audit_says_why() {
    let s = Scratch::new("quota");
    let (mut session, _) = start(&s, quota_policy(&s, 1_000), Granted::Refused);

    // 한도를 넘길 연결 자체는 막지 못합니다. 바이트 수는 연결이 끝나야 알기 때문입니다
    let first = session
        .check_egress("mirror.example.com", 443, Protocol::Tls, Actor::Unknown)
        .unwrap();
    assert!(first.permitted());
    session
        .record_egress_summary(
            "mirror.example.com",
            443,
            Protocol::Tls,
            5_000,
            0,
            10,
            Actor::Unknown,
        )
        .unwrap();
    assert_eq!(session.bytes_out_to("mirror.example.com", 443), 5_000);

    // 다음 연결부터 막힙니다
    let second = session
        .check_egress("mirror.example.com", 443, Protocol::Tls, Actor::Unknown)
        .unwrap();
    assert!(!second.permitted(), "한도를 넘긴 뒤에는 막혀야 함");
    session.finish(None).unwrap();

    let es = entries(&s.session_dir());
    let blocked = es
        .iter()
        .filter(|e| matches!(e.event, Event::Egress { .. }))
        .nth(1)
        .expect("두 번째 시도 엔트리");
    assert_eq!(blocked.decision, Decision::Deny);
    assert_eq!(
        blocked.rule.as_deref(),
        Some(airlock_policy::QUOTA_ID),
        "초과 사실이 감사의 규칙 id 로 드러나야 함"
    );
    verify_dir(s.session_dir()).unwrap();
}

#[test]
fn the_quota_key_survives_host_spelling_changes() {
    // 표기를 바꾸는 것만으로 누적량이 초기화되면 한도가 아무것도 막지 못합니다
    let s = Scratch::new("quota-spelling");
    let (mut session, _) = start(&s, quota_policy(&s, 10), Granted::Refused);
    session
        .record_egress_summary(
            "MIRROR.Example.com.",
            443,
            Protocol::Tls,
            100,
            0,
            1,
            Actor::Unknown,
        )
        .unwrap();
    assert_eq!(session.bytes_out_to("mirror.example.com", 443), 100);
    let out = session
        .check_egress("mirror.example.com", 443, Protocol::Tls, Actor::Unknown)
        .unwrap();
    assert!(!out.permitted());
    session.finish(None).unwrap();
}

#[test]
fn the_quota_is_per_destination() {
    let s = Scratch::new("quota-dest");
    let p = policy(
        &s,
        r#"
[[rules]]
id = "mirror"
kind = "egress"
host = "*.example.com"
max_bytes_out = 10
action = "allow"
"#,
    );
    let (mut session, _) = start(&s, p, Granted::Refused);
    session
        .record_egress_summary(
            "a.example.com",
            443,
            Protocol::Tls,
            999,
            0,
            1,
            Actor::Unknown,
        )
        .unwrap();
    assert!(
        !session
            .check_egress("a.example.com", 443, Protocol::Tls, Actor::Unknown)
            .unwrap()
            .permitted()
    );
    assert!(
        session
            .check_egress("b.example.com", 443, Protocol::Tls, Actor::Unknown)
            .unwrap()
            .permitted(),
        "다른 목적지의 누적량까지 함께 막으면 안 됨"
    );
    // 포트가 다르면 다른 목적지입니다
    assert!(
        session
            .check_egress("a.example.com", 8443, Protocol::Tls, Actor::Unknown)
            .unwrap()
            .permitted()
    );
    session.finish(None).unwrap();
}

#[test]
fn a_closed_session_refuses_late_results() {
    // session_end 뒤에 붙는 엔트리는 체인을 앵커보다 길게 만들어 세션 전체를
    // "종료 후 덧붙이기" 로 보고하게 합니다
    let s = Scratch::new("late");
    let (mut session, _) = start(&s, quota_policy(&s, 1_000_000), Granted::Refused);
    let closed = session.finish(None).unwrap();

    let err = session.record_egress_summary(
        "mirror.example.com",
        443,
        Protocol::Tls,
        1,
        1,
        1,
        Actor::Unknown,
    );
    assert!(err.is_err(), "닫힌 세션이 늦은 결과를 받아들이면 안 됨");
    assert!(
        session
            .check_egress("mirror.example.com", 443, Protocol::Tls, Actor::Unknown)
            .is_err(),
        "닫힌 세션의 판정도 거부되어야 함"
    );

    let report = verify_dir(s.session_dir()).unwrap();
    assert_eq!(Some(report.head_seq), closed.head_seq);
    assert!(matches!(closed.anchor, AnchorOutcome::Written { .. }));
    airlock_audit::check_session(
        s.path(),
        &report.session,
        report.head_seq,
        &report.head_hash,
    )
    .expect("앵커와 체인이 어긋나면 안 됨");
}

// ---------- 프록시에서 감사까지의 전체 경로 ----------

/// 한 연결만 받아 고정 응답을 돌려주는 목적지. 받은 바이트 수를 돌려줍니다
fn echo_origin(reply: Vec<u8>) -> (std::net::SocketAddr, std::thread::JoinHandle<usize>) {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = l.local_addr().unwrap();
    let h = std::thread::spawn(move || {
        let Ok((mut s, _)) = l.accept() else { return 0 };
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        let mut got = 0usize;
        let mut buf = [0u8; 4096];
        while let Ok(n) = s.read(&mut buf) {
            if n == 0 {
                break;
            }
            got += n;
        }
        let _ = s.write_all(&reply);
        let _ = s.shutdown(Shutdown::Write);
        got
    });
    (addr, h)
}

#[test]
fn the_proxy_records_what_actually_left_the_machine() {
    use std::io::{BufRead, Read, Write};
    use std::net::{Shutdown, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};

    let s = Scratch::new("proxy-summary");
    let payload = vec![b'x'; 30_000];
    let reply = vec![b'y'; 7_000];
    let (origin, origin_h) = echo_origin(reply.clone());

    let p = policy(
        &s,
        &format!(
            r#"
[[rules]]
id = "loop"
kind = "egress"
host = "127.0.0.1"
port = {}
action = "allow"
"#,
            origin.port()
        ),
    );
    let (session, _) = start(&s, p, Granted::Refused);
    let shared = Arc::new(Mutex::new(session));

    let server = airlock_proxy::ProxyServer::bind().unwrap();
    let addr = server.addr();
    let live = server.live_connections();
    let gate: Arc<dyn airlock_proxy::EgressGate> =
        Arc::new(airlock_broker::SessionGate::new(Arc::clone(&shared)));
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let serving = std::thread::spawn(move || server.serve(gate, flag));

    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    c.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", origin.port()).as_bytes())
        .unwrap();
    let mut r = std::io::BufReader::new(c.try_clone().unwrap());
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    assert!(line.starts_with("HTTP/1.1 200"), "{line}");
    let mut blank = String::new();
    r.read_line(&mut blank).unwrap();
    c.write_all(&payload).unwrap();
    c.shutdown(Shutdown::Write).unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(got.len(), reply.len());
    assert_eq!(origin_h.join().unwrap(), payload.len());

    // 릴레이가 결과를 남길 때까지 기다립니다
    for _ in 0..200 {
        if live.load(Ordering::Relaxed) == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    stop.store(true, Ordering::Relaxed);
    let _ = serving.join();

    let mut session = shared.lock().unwrap();
    assert_eq!(
        session.bytes_out_to("127.0.0.1", origin.port()),
        payload.len() as u64,
        "누적 반출량이 실제 전송량과 달라짐"
    );
    session.finish(None).unwrap();
    drop(session);

    let es = entries(&s.session_dir());
    let summary = es
        .iter()
        .find_map(|e| match &e.event {
            Event::EgressSummary {
                bytes_out,
                bytes_in,
                protocol,
                ..
            } => Some((*bytes_out, *bytes_in, *protocol)),
            _ => None,
        })
        .expect("결과 엔트리가 남아야 함");
    assert_eq!(summary.0, payload.len() as u64, "반출 바이트가 실제와 다름");
    assert_eq!(summary.1, reply.len() as u64, "수신 바이트가 실제와 다름");
    assert_eq!(summary.2, Protocol::Tls);
    verify_dir(s.session_dir()).unwrap();
}
