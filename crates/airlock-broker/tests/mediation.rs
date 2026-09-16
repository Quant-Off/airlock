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
        anchor_dir: None,
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
        // 이 파일은 중계 층만 봅니다. 프록시를 띄우면 같은 연결이 두 번 기록되어
        // 무엇을 중계가 보았는지가 흐려집니다 (docs/egress-proxy.md 4.1)
        None,
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

fn file_decisions(
    entries: &[airlock_audit::Entry],
) -> Vec<(String, String, airlock_audit::Decision)> {
    entries
        .iter()
        .filter_map(|e| match &e.event {
            Event::FileAccess {
                path_requested,
                mode,
                ..
            } => Some((
                path_requested.clone(),
                mode.as_str().to_string(),
                e.decision,
            )),
            _ => None,
        })
        .collect()
}

/// `--mediate full` 은 rename 의 원본을 `delete` 로 판정합니다. 이름 변경은 openat 을 거치지
/// 않으므로 이것이 없으면 삭제 금지 규칙이 `mv` 한 번에 비껴갑니다
#[test]
fn full_mediation_refuses_a_rename_whose_source_may_not_be_deleted() {
    let s = Scratch::new("rename-deny");
    let keep = s.path().join("keep.txt");
    let moved = s.path().join("moved.txt");
    fs::write(&keep, b"stay\n").unwrap();

    let policy = policy_from(
        s.path(),
        &format!(
            r#"
[[rules]]
id = "keep-name"
kind = "file"
path = "{}"
mode = ["delete"]
action = "deny"
reason = "테스트"
"#,
            keep.display()
        ),
    );
    let (_, entries) = run_it(
        s.path(),
        policy,
        Mediation::Full,
        "/bin/mv",
        &[keep.to_str().unwrap(), moved.to_str().unwrap()],
    );

    assert!(keep.exists(), "삭제 금지 파일이 rename 으로 사라짐");
    assert!(!moved.exists(), "삭제 금지 파일이 새 이름으로 나타남");
    let decisions = file_decisions(&entries);
    assert!(
        decisions.iter().any(|(p, mode, d)| p.ends_with("keep.txt")
            && mode == "delete"
            && *d == airlock_audit::Decision::Deny),
        "원본에 대한 delete 거부가 감사에 남지 않음: {decisions:?}"
    );
}

/// 정책 파일 후보는 아직 없어도 생성이 거부되어야 합니다. Landlock 은 없는 inode 에 규칙을
/// 걸 수 없으므로 이 층이 rename 의 목적지를 `create` 로 판정해 막습니다
#[test]
fn full_mediation_refuses_planting_a_policy_file_by_rename() {
    let s = Scratch::new("plant");
    let evil = s.path().join("evil.toml");
    let planted = s.path().join("airlock.toml");
    fs::write(&evil, b"version = 1\n").unwrap();

    let ctx =
        LoadContext::new(s.path(), s.path().join("audit")).with_policy_files([planted.clone()]);
    let src = r#"
version = 1
name = "mediation-test"
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
"#;
    let policy = Policy::load_str(src, &ctx).unwrap();
    let (_, entries) = run_it(
        s.path(),
        policy,
        Mediation::Full,
        "/bin/mv",
        &[evil.to_str().unwrap(), planted.to_str().unwrap()],
    );

    assert!(!planted.exists(), "에이전트가 rename 으로 정책 파일을 심음");
    assert!(evil.exists(), "거부된 rename 이 원본을 없애면 안 됨");
    let decisions = file_decisions(&entries);
    assert!(
        decisions
            .iter()
            .any(|(p, mode, d)| p.ends_with("airlock.toml")
                && mode == "create"
                && *d == airlock_audit::Decision::Deny),
        "목적지에 대한 create 거부가 감사에 남지 않음: {decisions:?}"
    );
}

/// 허용된 rename 은 그대로 되어야 하고 원본 delete 와 목적지 create 가 둘 다 기록됩니다
#[test]
fn full_mediation_records_both_sides_of_an_allowed_rename() {
    let s = Scratch::new("rename-ok");
    let from = s.path().join("from.txt");
    let to = s.path().join("to.txt");
    fs::write(&from, b"go\n").unwrap();

    let policy = policy_from(s.path(), "");
    let (_, entries) = run_it(
        s.path(),
        policy,
        Mediation::Full,
        "/bin/mv",
        &[from.to_str().unwrap(), to.to_str().unwrap()],
    );

    assert!(to.exists() && !from.exists(), "허용된 rename 이 되지 않음");
    let decisions = file_decisions(&entries);
    assert!(
        decisions
            .iter()
            .any(|(p, mode, _)| p.ends_with("from.txt") && mode == "delete"),
        "원본 delete 판정이 없음: {decisions:?}"
    );
    assert!(
        decisions
            .iter()
            .any(|(p, mode, _)| p.ends_with("to.txt") && mode == "create"),
        "목적지 create 판정이 없음: {decisions:?}"
    );
}

/// 기본 수준은 rename 을 중계하지 않습니다. 느려지는 것은 `full` 을 고른 사람만 감수합니다
#[test]
fn exec_net_does_not_mediate_renames() {
    let s = Scratch::new("rename-execnet");
    let from = s.path().join("from.txt");
    let to = s.path().join("to.txt");
    fs::write(&from, b"go\n").unwrap();

    let policy = policy_from(s.path(), "");
    let (_, entries) = run_it(
        s.path(),
        policy,
        Mediation::ExecNet,
        "/bin/mv",
        &[from.to_str().unwrap(), to.to_str().unwrap()],
    );

    assert!(to.exists(), "exec-net 에서 rename 이 막히면 안 됨");
    assert!(
        file_decisions(&entries).is_empty(),
        "exec-net 은 파일 판정을 남기지 않아야 함"
    );
}
