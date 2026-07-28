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
use airlock_broker::{ApprovalRequest, Approver, Session, SessionConfig};
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
    let out = session.check_file(&target, FileMode::Read).unwrap();
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
        .check_file(Path::new("/tmp/elsewhere/x"), FileMode::Write)
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
    let out = session.check_file(&key, FileMode::Read).unwrap();
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
        .check_file(&s.ws().join("config"), FileMode::Write)
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
        } => {
            assert_eq!(*for_seq, es[1].seq, "승인 엔트리가 시도를 가리켜야 함");
            assert_eq!(*granted, Granted::Approved);
            assert_eq!(note.as_deref(), Some("테스트"));
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
        .check_file(&s.ws().join("config"), FileMode::Write)
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
        .check_file(&s.ws().join("config"), FileMode::Write)
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
    let out = session.check_exec(&tool, &argv).unwrap();
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
        .check_egress("api.anthropic.com", 443, Protocol::Tls)
        .unwrap();
    assert_eq!(allowed.action, Action::Allow);

    let blocked = session
        .check_egress("169.254.169.254", 80, Protocol::Http)
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
        .check_file(&s.ws().join("config"), FileMode::Write)
        .unwrap();
    session
        .check_file(&s.path().join("nope"), FileMode::Read)
        .unwrap();

    let status = std::process::Command::new("/bin/sh")
        .args(["-c", "exit 3"])
        .status()
        .unwrap();
    let head = session.finish(Some(&status)).unwrap();

    let es = entries(&s.session_dir());
    match es.last().map(|e| &e.event) {
        Some(Event::SessionEnd { status }) => assert_eq!(
            *status,
            airlock_audit::ExitStatus::Exited { code: 3 },
            "종료 코드가 그대로 남아야 함"
        ),
        other => panic!("세션 종료 엔트리가 아님: {other:?}"),
    }
    assert_eq!(head, es.last().unwrap().hash, "돌려준 체인 헤드가 다름");

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
        .check_file(&s.ws().join("a"), FileMode::Read)
        .unwrap();
    session
        .check_file(&s.path().join("other/b"), FileMode::Read)
        .unwrap();
    session
        .check_file(&s.ws().join("c"), FileMode::Write)
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
