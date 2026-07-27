#![cfg(target_os = "macos")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use airlock_broker::{Enforcer, ProfileOptions, SeatbeltEnforcer, Strategy};
use airlock_policy::{LoadContext, Policy};
use unicode_normalization::UnicodeNormalization;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!(
            "airlock-enforce-{tag}-{}-{nanos}",
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

fn policy_denying(scratch: &Path, secret: &Path) -> Policy {
    let src = format!(
        r#"
version = 1
name = "enforce-test"
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

fn read_under_sandbox(
    strategy: Strategy,
    policy: &Policy,
    workspace: &Path,
    target: &Path,
) -> bool {
    let opts = ProfileOptions::default().with_workspace(workspace);
    let mut enforcer = SeatbeltEnforcer::new()
        .with_options(opts)
        .with_strategy(strategy);
    enforcer.prepare(policy).unwrap();

    let mut cmd = Command::new("/bin/cat");
    cmd.arg(target)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    enforcer.wrap(&mut cmd).unwrap();

    cmd.status().map(|s| s.success()).unwrap_or(false)
}

fn check_strategy(strategy: Strategy, tag: &str) {
    let s = Scratch::new(tag);
    let allowed = s.path().join("allowed.txt");
    let secret = s.path().join("secret.txt");
    fs::write(&allowed, b"public data\n").unwrap();
    fs::write(&secret, b"TOP SECRET\n").unwrap();

    let policy = policy_denying(s.path(), &secret);

    assert!(
        read_under_sandbox(strategy, &policy, s.path(), &allowed),
        "{strategy:?}: 허용된 파일을 읽지 못함. 프로파일이 과도하게 좁음"
    );
    assert!(
        !read_under_sandbox(strategy, &policy, s.path(), &secret),
        "{strategy:?}: 거부된 파일이 읽힘. 커널 강제가 걸리지 않음"
    );
}

#[test]
fn sandbox_init_enforces_file_denies() {
    check_strategy(Strategy::SandboxInit, "ffi");
}

#[test]
fn sandbox_exec_enforces_file_denies() {
    check_strategy(Strategy::SandboxExec, "exec");
}

#[test]
fn baseline_secrets_are_denied_under_enforcement() {
    let s = Scratch::new("baseline");
    let fake_home = s.path().join("home");
    let ssh = fake_home.join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    let key = ssh.join("id_ed25519");
    fs::write(&key, b"PRIVATE KEY\n").unwrap();

    let ctx = LoadContext::new(&fake_home, fake_home.join(".local/share/airlock"));
    let policy = Policy::load_str(
        r#"
version = 1
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
"#,
        &ctx,
    )
    .unwrap();

    assert!(
        !read_under_sandbox(Strategy::SandboxInit, &policy, s.path(), &key),
        "베이스라인 forbid 시크릿이 커널 강제까지 내려가지 않음"
    );

    let ordinary = fake_home.join("notes.txt");
    fs::write(&ordinary, b"hello\n").unwrap();
    assert!(
        read_under_sandbox(Strategy::SandboxInit, &policy, s.path(), &ordinary),
        "평범한 파일이 막힘"
    );
}

#[test]
fn non_ascii_wildcard_deny_actually_enforces() {
    let s = Scratch::new("hangul");
    let dir = s.path().join("작업");
    fs::create_dir_all(&dir).unwrap();
    let secret = dir.join("비밀.pem");
    fs::write(&secret, b"PRIVATE\n").unwrap();
    let normal = dir.join("공개.txt");
    fs::write(&normal, b"hello\n").unwrap();

    let src = format!(
        r#"
version = 1
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
[[rules]]
id = "hangul-pem"
kind = "file"
path = "{}/작업/*.pem"
action = "deny"
reason = "한글 경로 와일드카드 강제 검증"
"#,
        s.path().display()
    );
    let ctx = LoadContext::new(s.path(), s.path().join("audit"));
    let policy = Policy::load_str(&src, &ctx).unwrap();

    assert!(
        read_under_sandbox(Strategy::SandboxInit, &policy, s.path(), &normal),
        "한글 경로의 일반 파일이 막힘"
    );
    assert!(
        !read_under_sandbox(Strategy::SandboxInit, &policy, s.path(), &secret),
        "한글 경로 와일드카드 deny가 커널에서 강제되지 않음. 정규식 바이트가 깨졌을 수 있음"
    );
}

#[test]
fn nfd_on_disk_names_are_still_denied() {
    let s = Scratch::new("nfd");
    let dir = s.path().join("작업");
    fs::create_dir_all(&dir).unwrap();

    let nfd_name: String = "비밀".nfd().collect();
    assert_ne!(nfd_name, "비밀");
    let secret_nfd = dir.join(format!("{nfd_name}.pem"));
    fs::write(&secret_nfd, b"PRIVATE\n").unwrap();
    let normal = dir.join("공개.txt");
    fs::write(&normal, b"hello\n").unwrap();

    let src = format!(
        r#"
version = 1
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
[[rules]]
id = "hangul-pem"
kind = "file"
path = "{}/작업/비밀*.pem"
action = "deny"
reason = "정규화 표기 우회 강제 검증"
"#,
        s.path().display()
    );
    let ctx = LoadContext::new(s.path(), s.path().join("audit"));
    let policy = Policy::load_str(&src, &ctx).unwrap();

    assert!(
        read_under_sandbox(Strategy::SandboxInit, &policy, s.path(), &normal),
        "한글 경로의 일반 파일이 막힘"
    );
    assert!(
        !read_under_sandbox(Strategy::SandboxInit, &policy, s.path(), &secret_nfd),
        "NFD 온디스크 이름이 NFC deny 규칙을 우회함"
    );
    let secret_nfc = dir.join("비밀.pem");
    assert!(
        !read_under_sandbox(Strategy::SandboxInit, &policy, s.path(), &secret_nfc),
        "NFC 표기 접근이 커널에서 강제되지 않음"
    );
}

#[test]
fn env_file_regex_actually_enforces() {
    let s = Scratch::new("envfile");
    let proj = s.path().join("proj");
    fs::create_dir_all(&proj).unwrap();
    let env = proj.join(".env");
    fs::write(&env, b"API_KEY=secret\n").unwrap();
    let normal = proj.join("main.rs");
    fs::write(&normal, b"fn main() {}\n").unwrap();

    let ctx = LoadContext::new(s.path(), s.path().join("audit"));
    let policy = Policy::load_str(
        r#"
version = 1
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
"#,
        &ctx,
    )
    .unwrap();

    assert!(
        read_under_sandbox(Strategy::SandboxInit, &policy, s.path(), &normal),
        "일반 소스 파일이 막힘"
    );
    assert!(
        !read_under_sandbox(Strategy::SandboxInit, &policy, s.path(), &env),
        "`**/.env` 정규식이 커널에서 실제로 강제되지 않음"
    );
}
