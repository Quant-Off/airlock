#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};

use airlock_audit::{Enforcement, Event};
use airlock_broker::{
    ApproveAll, Enforcer, LandlockEnforcer, Mediation, ObserveEnforcer, ProfileOptions,
    SessionConfig,
};
use airlock_policy::{LoadContext, Policy};

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("airlock-med-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        Self(fs::canonicalize(&p).unwrap())
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn policy_from(scratch: &Path, extra: &str) -> Policy {
    let src = format!(
        r#"
version = 1
name = "mediation-test"
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
{extra}
"#
    );
    let ctx = LoadContext::new(scratch, scratch.join("audit"));
    Policy::load_str(&src, &ctx).unwrap()
}

fn config(scratch: &Path, level: Mediation, argv: Vec<String>) -> SessionConfig {
    SessionConfig {
        audit_dir: scratch.join("audit-session"),
        actor: "test".to_string(),
        cwd: scratch.to_path_buf(),
        argv,
        fsync_per_entry: false,
        policy_source: None,
        airlock_version: "test".to_string(),
        mediation: level,
    }
}

fn run_it(
    scratch: &Path,
    policy: Policy,
    level: Mediation,
    program: &str,
    args: &[&str],
) -> (airlock_broker::RunReport, Vec<airlock_audit::Entry>) {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let cfg = config(scratch, level, vec![program.to_string()]);
    let enforcer: Box<dyn Enforcer> = if LandlockEnforcer::available() {
        Box::new(
            LandlockEnforcer::new().with_options(ProfileOptions::default().with_workspace(scratch)),
        )
    } else {
        Box::new(ObserveEnforcer)
    };
    let report = airlock_broker::run(
        program,
        &owned,
        policy,
        enforcer,
        Box::new(ApproveAll),
        &cfg,
    )
    .unwrap();
    let (entries, problem) = airlock_audit::read_entries_lossy(&report.audit_dir).unwrap();
    assert!(problem.is_none(), "{problem:?}");
    (report, entries)
}

fn exec_programs(entries: &[airlock_audit::Entry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|e| match &e.event {
            Event::Exec { program, .. } => Some(program.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn child_process_execs_are_audited() {
    let s = Scratch::new("child-exec");
    let policy = policy_from(s.path(), "");
    let (_, entries) = run_it(
        s.path(),
        policy,
        Mediation::ExecNet,
        "/bin/sh",
        &["-c", "/bin/echo one; /bin/date"],
    );

    let programs = exec_programs(&entries);
    assert!(
        programs.iter().any(|p| p.ends_with("echo")),
        "자식 프로세스 exec이 기록되지 않음: {programs:?}"
    );
    assert!(
        programs.iter().any(|p| p.ends_with("date")),
        "두 번째 자식 exec이 기록되지 않음: {programs:?}"
    );
}

#[test]
fn mediation_off_records_only_the_top_level_exec() {
    let s = Scratch::new("off");
    let policy = policy_from(s.path(), "");
    let (_, entries) = run_it(
        s.path(),
        policy,
        Mediation::Off,
        "/bin/sh",
        &["-c", "/bin/echo one; /bin/date"],
    );

    let programs = exec_programs(&entries);
    assert_eq!(
        programs.len(),
        1,
        "중계를 끄면 최상위 exec 하나만 남아야 함: {programs:?}"
    );
}

#[test]
fn a_denied_child_exec_is_blocked_and_recorded() {
    let s = Scratch::new("deny-child");
    let policy = policy_from(
        s.path(),
        r#"
[[rules]]
id = "no-date"
kind = "exec"
program = "date"
action = "deny"
reason = "테스트"
"#,
    );
    let marker = s.path().join("ran.txt");
    let script = format!("/bin/date && /bin/touch {}", marker.display());
    let (_, entries) = run_it(
        s.path(),
        policy,
        Mediation::ExecNet,
        "/bin/sh",
        &["-c", &script],
    );

    assert!(
        !marker.exists(),
        "거부된 exec이 실제로 실행되어 다음 명령까지 진행함"
    );
    let denied = entries.iter().any(|e| {
        matches!(&e.event, Event::Exec { program, .. } if program.ends_with("date"))
            && e.decision == airlock_audit::Decision::Deny
    });
    assert!(denied, "거부 결정이 감사에 남지 않음");
}

#[test]
fn outbound_connections_are_audited() {
    if !Path::new("/bin/bash").exists() {
        eprintln!("bash가 없어 건너뜀");
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let s = Scratch::new("egress");
    let policy = policy_from(s.path(), "");
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");
    let (_, entries) = run_it(
        s.path(),
        policy,
        Mediation::ExecNet,
        "/bin/bash",
        &["-c", &script],
    );

    let seen = entries.iter().any(|e| {
        matches!(&e.event, Event::Egress { host, port: p, .. } if host == "127.0.0.1" && *p == port)
    });
    assert!(
        seen,
        "아웃바운드 연결이 감사에 남지 않음: {:?}",
        entries.iter().map(|e| e.event.kind()).collect::<Vec<_>>()
    );
}

#[test]
fn full_mediation_records_file_opens() {
    let s = Scratch::new("full");
    let target = s.path().join("readme.txt");
    fs::write(&target, b"data\n").unwrap();

    let policy = policy_from(s.path(), "");
    let (_, entries) = run_it(
        s.path(),
        policy,
        Mediation::Full,
        "/bin/cat",
        &[target.to_str().unwrap()],
    );

    let seen = entries.iter().any(|e| {
        matches!(&e.event, Event::FileAccess { path_requested, .. }
            if path_requested.ends_with("readme.txt"))
    });
    assert!(seen, "full 모드에서 파일 열기가 기록되지 않음");
}

#[test]
fn the_chain_still_verifies_with_mediation_on() {
    let s = Scratch::new("verify");
    let policy = policy_from(s.path(), "");
    let (report, _) = run_it(
        s.path(),
        policy,
        Mediation::ExecNet,
        "/bin/sh",
        &["-c", "/bin/echo a; /bin/echo b"],
    );

    let out = airlock_audit::verify_dir(&report.audit_dir).unwrap();
    assert!(out.entries > 4, "중계 엔트리가 더 있어야 함");
}

#[test]
fn enforcement_field_is_recorded_on_mediated_entries() {
    let s = Scratch::new("enf");
    let policy = policy_from(s.path(), "");
    let (_, entries) = run_it(
        s.path(),
        policy,
        Mediation::ExecNet,
        "/bin/sh",
        &["-c", "/bin/echo x"],
    );

    let expected = if LandlockEnforcer::available() {
        Enforcement::Landlock
    } else {
        Enforcement::Observe
    };
    assert!(
        entries.iter().all(|e| e.enforcement == expected),
        "모든 엔트리가 강제 수준을 달고 있어야 함"
    );
}
