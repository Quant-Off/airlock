#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use airlock_broker::{Enforcer, LandlockEnforcer, ProfileOptions};
use airlock_policy::{LoadContext, Policy};

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!(
            "airlock-landlock-{tag}-{}-{nanos}",
            std::process::id()
        ));
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

fn skip_if_unsupported() -> bool {
    if LandlockEnforcer::available() {
        return false;
    }
    eprintln!("커널이 Landlock을 지원하지 않아 건너뜀");
    true
}

fn run_under_sandbox(policy: &Policy, workspace: &Path, argv: &[&str]) -> bool {
    let opts = ProfileOptions::default().with_workspace(workspace);
    let mut enforcer = LandlockEnforcer::new().with_options(opts);
    enforcer.prepare(policy).unwrap();

    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    enforcer.wrap(&mut cmd).unwrap();
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

fn read_under_sandbox(policy: &Policy, workspace: &Path, target: &Path) -> bool {
    let t = target.to_string_lossy().into_owned();
    run_under_sandbox(policy, workspace, &["/bin/cat", &t])
}

fn permissive_policy(scratch: &Path) -> Policy {
    let src = r#"
version = 1
name = "landlock-test"
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
"#;
    let ctx = LoadContext::new(scratch, scratch.join("audit"));
    Policy::load_str(src, &ctx).unwrap()
}

fn policy_denying(scratch: &Path, secret: &Path) -> Policy {
    let src = format!(
        r#"
version = 1
name = "landlock-test"
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
[[rules]]
id = "test-secret"
kind = "file"
path = "{}"
action = "deny"
reason = "테스트용 시크릿"
"#,
        secret.display()
    );
    let ctx = LoadContext::new(scratch, scratch.join("audit"));
    Policy::load_str(&src, &ctx).unwrap()
}

#[test]
fn allowed_file_is_readable_and_denied_file_is_not() {
    if skip_if_unsupported() {
        return;
    }
    let s = Scratch::new("basic");
    let allowed = s.path().join("allowed.txt");
    let secret = s.path().join("secret.txt");
    fs::write(&allowed, b"public\n").unwrap();
    fs::write(&secret, b"TOP SECRET\n").unwrap();

    let policy = policy_denying(s.path(), &secret);

    assert!(
        read_under_sandbox(&policy, s.path(), &allowed),
        "허용된 파일을 읽지 못함. 계획이 과도하게 좁음"
    );
    assert!(
        !read_under_sandbox(&policy, s.path(), &secret),
        "거부된 파일이 읽힘. 커널 강제가 걸리지 않음"
    );
}

#[test]
fn env_file_inside_the_workspace_is_denied_by_the_baseline() {
    if skip_if_unsupported() {
        return;
    }
    let s = Scratch::new("env");
    let api = s.path().join("api");
    fs::create_dir_all(&api).unwrap();
    let env = api.join(".env");
    let normal = api.join("main.rs");
    fs::write(&env, b"SECRET_KEY=1\n").unwrap();
    fs::write(&normal, b"fn main() {}\n").unwrap();

    // 작업 공간 전체를 열어 주는 정책이어도 .env는 베이스라인 forbid입니다
    let policy = permissive_policy(s.path());

    assert!(
        read_under_sandbox(&policy, s.path(), &normal),
        "작업 공간의 평범한 파일을 읽지 못함"
    );
    assert!(
        !read_under_sandbox(&policy, s.path(), &env),
        "작업 공간 안의 .env가 읽힘. Landlock은 허용 트리에서 부분 제외를 표현할 수 없으므로 \
         계획 단계에서 빼야 함"
    );
}

#[test]
fn nested_env_file_is_denied_without_breaking_siblings() {
    if skip_if_unsupported() {
        return;
    }
    let s = Scratch::new("nested");
    let deep = s.path().join("a/b/c");
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join(".env.production"), b"K=1\n").unwrap();
    fs::write(deep.join("ok.txt"), b"fine\n").unwrap();
    fs::write(s.path().join("a/top.txt"), b"fine\n").unwrap();

    let policy = permissive_policy(s.path());

    assert!(
        !read_under_sandbox(&policy, s.path(), &deep.join(".env.production")),
        "깊은 곳의 .env.production이 읽힘"
    );
    assert!(
        read_under_sandbox(&policy, s.path(), &deep.join("ok.txt")),
        "같은 디렉토리의 형제 파일까지 막히면 안 됨"
    );
    assert!(
        read_under_sandbox(&policy, s.path(), &s.path().join("a/top.txt")),
        "상위 디렉토리의 파일까지 막히면 안 됨"
    );
}

#[test]
fn writing_outside_any_granted_root_is_denied() {
    if skip_if_unsupported() {
        return;
    }
    let s = Scratch::new("write-out");
    // /tmp는 임시 디렉토리로 통째로 열리므로 밖을 시험하려면 열리지 않은 곳을 씁니다
    let outside = PathBuf::from("/var/tmp/airlock-outside-probe");
    fs::create_dir_all("/var/tmp").ok();
    fs::write(&outside, b"x\n").unwrap();

    let policy = permissive_policy(s.path());

    assert!(
        !run_under_sandbox(
            &policy,
            s.path(),
            &[
                "/bin/sh",
                "-c",
                &format!("echo pwned > {}", outside.display())
            ]
        ),
        "허용되지 않은 경로에 쓰기가 성공함"
    );
    assert_eq!(
        fs::read_to_string(&outside).unwrap(),
        "x\n",
        "파일 내용이 바뀜"
    );
    let _ = fs::remove_file(&outside);
}

#[test]
fn system_paths_are_read_only() {
    if skip_if_unsupported() {
        return;
    }
    let s = Scratch::new("sysro");
    let policy = permissive_policy(s.path());

    assert!(
        run_under_sandbox(&policy, s.path(), &["/bin/cat", "/etc/hostname"]),
        "시스템 경로 읽기가 막히면 프로그램이 뜨지 못함"
    );
    assert!(
        !run_under_sandbox(
            &policy,
            s.path(),
            &["/bin/sh", "-c", "echo pwned > /etc/airlock-probe"]
        ),
        "읽기 전용으로 준 시스템 경로에 쓰기가 성공함"
    );
    assert!(!Path::new("/etc/airlock-probe").exists());
}

#[test]
fn workspace_writes_still_work() {
    if skip_if_unsupported() {
        return;
    }
    let s = Scratch::new("write-in");
    let policy = permissive_policy(s.path());
    let target = s.path().join("out.txt");

    assert!(
        run_under_sandbox(
            &policy,
            s.path(),
            &["/bin/sh", "-c", &format!("echo ok > {}", target.display())]
        ),
        "작업 공간 안 쓰기가 막힘. 계획이 과도하게 좁음"
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), "ok\n");
}

#[test]
fn enforcer_reports_abi_and_gaps() {
    if skip_if_unsupported() {
        return;
    }
    let s = Scratch::new("gaps");
    let policy = permissive_policy(s.path());
    let mut e =
        LandlockEnforcer::new().with_options(ProfileOptions::default().with_workspace(s.path()));
    e.prepare(&policy).unwrap();

    assert_eq!(e.kind(), airlock_audit::Enforcement::Landlock);
    assert!(e.describe().contains("ABI v"), "{}", e.describe());

    let gaps = e.gaps();
    assert!(
        gaps.iter().any(|g| g.contains("ask")),
        "ask가 deny로 내려간다는 사실을 노출해야 함: {gaps:?}"
    );
    assert!(
        gaps.iter().any(|g| g.contains("UDP")),
        "UDP 미강제를 노출해야 함: {gaps:?}"
    );
}

fn policy_allowing_port(scratch: &Path, port: u16) -> Policy {
    let src = format!(
        r#"
version = 1
name = "landlock-net"
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
[[rules]]
id = "one-port"
kind = "egress"
host = "*"
port = {port}
action = "deny"
[[rules]]
id = "loopback"
kind = "egress"
host = "127.0.0.1"
port = {port}
action = "allow"
"#
    );
    let ctx = LoadContext::new(scratch, scratch.join("audit"));
    Policy::load_str(&src, &ctx).unwrap()
}

fn connect_under_sandbox(policy: &Policy, workspace: &Path, port: u16) -> bool {
    run_under_sandbox(
        policy,
        workspace,
        &[
            "/bin/bash",
            "-c",
            &format!("exec 3<>/dev/tcp/127.0.0.1/{port}"),
        ],
    )
}

#[test]
fn tcp_connect_is_denied_without_an_egress_allow_rule() {
    if skip_if_unsupported() {
        return;
    }
    if !Path::new("/bin/bash").exists() {
        eprintln!("bash가 없어 건너뜀");
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let s = Scratch::new("net-deny");
    let policy = permissive_policy(s.path());

    assert!(
        !connect_under_sandbox(&policy, s.path(), port),
        "egress allow 규칙이 하나도 없는데 TCP 연결이 성공함"
    );
}

#[test]
fn tcp_connect_is_allowed_on_a_permitted_port() {
    if skip_if_unsupported() {
        return;
    }
    if !Path::new("/bin/bash").exists() {
        eprintln!("bash가 없어 건너뜀");
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let s = Scratch::new("net-allow");
    let policy = policy_allowing_port(s.path(), port);

    assert!(
        connect_under_sandbox(&policy, s.path(), port),
        "정책이 허용한 포트로의 연결이 막힘"
    );

    // 허용하지 않은 다른 포트는 계속 막혀야 합니다
    let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let other_port = other.local_addr().unwrap().port();
    assert!(
        !connect_under_sandbox(&policy, s.path(), other_port),
        "허용하지 않은 포트로의 연결이 성공함"
    );
}

#[test]
fn wrap_before_prepare_is_an_error() {
    if skip_if_unsupported() {
        return;
    }
    let e = LandlockEnforcer::new();
    let mut cmd = Command::new("/bin/true");
    assert!(e.wrap(&mut cmd).is_err());
}

// ---------- 심볼릭 링크 ----------

/// 작업 공간 안의 링크가 정책이 막은 대상을 열어 주는지 봅니다.
///
/// 시크릿을 가짜 home 아래에 두어 베이스라인 forbid 가 걸리게 합니다. 스크래치가 `/tmp`
/// 안에 있고 `/tmp` 는 임시 디렉토리로 통째로 열리므로, 단순히 작업 공간 밖에 두는 것만
/// 으로는 대조군이 성립하지 않습니다
#[test]
fn symlink_does_not_open_a_forbidden_target() {
    if skip_if_unsupported() {
        return;
    }
    let s = Scratch::new("symlink");

    let home = s.path().join("home");
    let ssh = home.join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    let secret = ssh.join("id_ed25519");
    fs::write(&secret, b"PRIVATE KEY\n").unwrap();

    // 작업 공간. .env 하나만 있어도 이 디렉토리는 Partial 이 되어 자식이 개별 규칙을 받습니다
    let ws = s.path().join("ws");
    fs::create_dir_all(&ws).unwrap();
    fs::write(ws.join(".env"), b"K=1\n").unwrap();
    fs::write(ws.join("ok.txt"), b"fine\n").unwrap();
    std::os::unix::fs::symlink(&ssh, ws.join("link")).unwrap();
    std::os::unix::fs::symlink(&secret, ws.join("key")).unwrap();

    let src = r#"
version = 1
name = "landlock-symlink"
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
"#;
    let ctx = LoadContext::new(&home, s.path().join("audit"));
    let policy = Policy::load_str(src, &ctx).unwrap();

    assert!(
        read_under_sandbox(&policy, &ws, &ws.join("ok.txt")),
        "작업 공간의 평범한 파일을 읽지 못함. 이 테스트의 대조군이 무의미해짐"
    );
    assert!(
        !read_under_sandbox(&policy, &ws, &secret),
        "정책이 막은 경로를 직접 열었는데 읽힘. 계획 자체가 잘못됨"
    );
    assert!(
        !read_under_sandbox(&policy, &ws, &ws.join("key")),
        "파일 링크를 통해 시크릿이 읽힘. 링크 자신에게 규칙을 걸면 대상 inode 가 열림"
    );
    assert!(
        !read_under_sandbox(&policy, &ws, &ws.join("link/id_ed25519")),
        "ln -s ~/.ssh link 하나로 시크릿 트리 전체가 열림"
    );
}

#[test]
fn a_directory_that_cannot_be_listed_is_not_granted_wholesale() {
    if skip_if_unsupported() {
        return;
    }
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("root 는 나열 권한 검사를 우회하므로 건너뜀");
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let s = Scratch::new("unlistable");
    let ws = s.path().join("ws");
    let closed = ws.join("closed");
    fs::create_dir_all(&closed).unwrap();
    fs::write(closed.join("inside.txt"), b"hidden\n").unwrap();
    fs::write(ws.join("ok.txt"), b"fine\n").unwrap();
    // 나열은 못 하지만 통과는 되는 디렉토리. 이름을 아는 하위는 DAC 로는 열립니다
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o311)).unwrap();

    let policy = permissive_policy(&ws);

    let readable = read_under_sandbox(&policy, &ws, &ws.join("ok.txt"));
    let hidden = read_under_sandbox(&policy, &ws, &closed.join("inside.txt"));

    fs::set_permissions(&closed, fs::Permissions::from_mode(0o755)).unwrap();

    assert!(readable, "형제 파일 읽기가 막히면 계획이 과도하게 좁음");
    assert!(
        !hidden,
        "나열할 수 없는 디렉토리의 하위가 검사 없이 통째로 허용됨"
    );
}
