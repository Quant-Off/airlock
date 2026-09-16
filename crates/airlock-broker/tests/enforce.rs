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

// ---------- exec 과 아웃바운드 ----------

fn run_under_sandbox(policy: &Policy, workspace: &Path, argv: &[&str]) -> bool {
    let opts = ProfileOptions::default().with_workspace(workspace);
    let mut enforcer = SeatbeltEnforcer::new().with_options(opts);
    enforcer.prepare(policy).unwrap();

    let (program, rest) = argv.split_first().expect("빈 argv");
    let mut cmd = Command::new(program);
    cmd.args(rest)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    enforcer.wrap(&mut cmd).unwrap();
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

fn policy_with(scratch: &Path, rules: &str) -> Policy {
    let src = format!(
        r#"
version = 1
name = "enforce-test"
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
{rules}
"#
    );
    let ctx = LoadContext::new(scratch, scratch.join("audit"));
    Policy::load_str(&src, &ctx).unwrap()
}

#[test]
fn exec_deny_is_enforced_by_the_kernel() {
    let s = Scratch::new("exec-deny");

    let permissive = policy_with(s.path(), "");
    assert!(
        run_under_sandbox(
            &permissive,
            s.path(),
            &["/bin/sh", "-c", "exec /usr/bin/true"]
        ),
        "제한 없는 정책에서 exec 이 실패하면 이 테스트의 대조군이 무의미함"
    );

    let denied = policy_with(
        s.path(),
        r#"
[[rules]]
id = "no-true"
kind = "exec"
program = "/usr/bin/true"
action = "deny"
reason = "테스트용 exec 차단"
"#,
    );
    assert!(
        !run_under_sandbox(&denied, s.path(), &["/bin/sh", "-c", "exec /usr/bin/true"]),
        "exec deny 규칙이 커널에서 강제되지 않음"
    );
}

#[test]
fn exec_deny_by_basename_is_enforced_by_the_kernel() {
    let s = Scratch::new("exec-basename");
    let denied = policy_with(
        s.path(),
        r#"
[[rules]]
id = "no-true-anywhere"
kind = "exec"
program = "true"
action = "deny"
reason = "이름만으로 차단"
"#,
    );
    assert!(
        !run_under_sandbox(&denied, s.path(), &["/bin/sh", "-c", "exec /usr/bin/true"]),
        "파일 이름만 지정한 exec deny 가 강제되지 않음"
    );
}

#[test]
fn outbound_is_blocked_when_the_policy_allows_no_egress() {
    use std::net::TcpListener;

    let s = Scratch::new("egress");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepting = std::thread::spawn(move || {
        // 대조군이 실제로 연결에 성공할 수 있어야 함
        for _ in 0..2 {
            if listener.accept().is_err() {
                break;
            }
        }
    });

    let port_s = port.to_string();
    let argv = ["/usr/bin/nc", "-z", "127.0.0.1", port_s.as_str()];

    let open = policy_with(
        s.path(),
        &format!(
            r#"
[[rules]]
id = "loopback"
kind = "egress"
host = "127.0.0.1"
port = {port}
action = "allow"
"#
        ),
    );
    assert!(
        run_under_sandbox(&open, s.path(), &argv),
        "egress allow 규칙이 있는데 연결이 막히면 프로파일이 과도하게 좁음"
    );

    let closed = policy_with(s.path(), "");
    assert!(
        !run_under_sandbox(&closed, s.path(), &argv),
        "egress allow 규칙이 없는 정책에서 아웃바운드가 나갔음. \
         [defaults].egress = \"deny\"와 정면으로 모순됨"
    );

    drop(accepting);
}

fn run_under_sandbox_with(opts: ProfileOptions, policy: &Policy, argv: &[&str]) -> bool {
    let mut enforcer = SeatbeltEnforcer::new().with_options(opts);
    enforcer.prepare(policy).unwrap();

    let (program, rest) = argv.split_first().expect("빈 argv");
    let mut cmd = Command::new(program);
    cmd.args(rest)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    enforcer.wrap(&mut cmd).unwrap();
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

/// 바깥에서 띄운 유닉스 소켓 리스너.
///
/// 짧은 경로가 필요합니다. `sockaddr_un` 의 경로 상한(104 바이트) 때문에 temp_dir
/// 아래 긴 이름은 bind 자체가 실패합니다
fn unix_listener(tag: &str) -> (PathBuf, std::os::unix::net::UnixListener) {
    let path = PathBuf::from(format!("/tmp/airlock-{tag}-{}.sock", std::process::id()));
    let _ = fs::remove_file(&path);
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    (path, listener)
}

/// 프록시 모드에서 유닉스 소켓은 허용 목록 밖이면 커널이 거부해야 합니다.
///
/// `(remote unix)` 통째 개방이 남아 있으면 ssh-agent 와 docker.sock 이 프록시도
/// 감사도 거치지 않는 출구가 됩니다. 대조군으로 egress allow 모드에서는 같은 연결이
/// 성공하는 것을 확인해, 실패가 프로파일 때문이지 환경 때문이 아님을 고정합니다
#[test]
fn a_proxy_refuses_unix_sockets_outside_the_allow_list() {
    let s = Scratch::new("unix-proxy");
    let (sock, listener) = unix_listener("unix-proxy");
    let accepting = std::thread::spawn(move || {
        for _ in 0..2 {
            if listener.accept().is_err() {
                break;
            }
        }
    });

    let sock_s = sock.to_string_lossy().into_owned();
    // `-z` 는 유닉스 소켓에서 성공해도 1 을 돌려주므로 실제 연결 뒤 stdin EOF 로 끝냅니다
    let argv = ["/usr/bin/nc", "-U", "-w", "1", sock_s.as_str()];
    let policy = policy_with(
        s.path(),
        r#"
[[rules]]
id = "anthropic"
kind = "egress"
host = "api.anthropic.com"
port = 443
action = "allow"
"#,
    );

    // 대조군. 프록시 없는 egress allow 모드는 아웃바운드가 통째로 열립니다
    assert!(
        run_under_sandbox_with(
            ProfileOptions::default().with_workspace(s.path()),
            &policy,
            &argv
        ),
        "대조군인 egress allow 모드에서 유닉스 소켓 연결이 실패하면 이 테스트가 무의미함"
    );

    let proxy = std::net::SocketAddr::from(([127, 0, 0, 1], 18899));
    assert!(
        !run_under_sandbox_with(
            ProfileOptions::default()
                .with_workspace(s.path())
                .with_proxy(proxy),
            &policy,
            &argv
        ),
        "프록시 모드에서 허용 목록 밖의 유닉스 소켓에 연결됨. (remote unix) 통째 개방이 남아 있음"
    );

    drop(accepting);
    let _ = fs::remove_file(&sock);
}

/// 허용 목록의 시스템 소켓은 프록시 모드에서도 닿아야 합니다. 이름 해석이 그 위에 있습니다.
///
/// `nc` 는 stream 소켓만 다루고 syslog 소켓은 datagram 이라 perl 로 두 타입을 다 시도합니다
#[test]
fn a_proxy_still_reaches_the_listed_system_sockets() {
    const PERL: &str = "/usr/bin/perl";
    if !Path::new(PERL).is_file() {
        return;
    }
    let s = Scratch::new("unix-mdns");
    let policy = policy_with(
        s.path(),
        r#"
[[rules]]
id = "anthropic"
kind = "egress"
host = "api.anthropic.com"
port = 443
action = "allow"
"#,
    );
    let proxy = std::net::SocketAddr::from(([127, 0, 0, 1], 18899));
    let opts = ProfileOptions::default()
        .with_workspace(s.path())
        .with_proxy(proxy);
    let probe = "use Socket; my $p = shift; \
        for my $t (SOCK_STREAM, SOCK_DGRAM) { \
            socket(my $s, PF_UNIX, $t, 0) or next; \
            exit 0 if connect($s, sockaddr_un($p)); \
        } exit 1";
    for sock in airlock_broker::profile::PROXY_UNIX_SOCKET_LITERALS {
        if !Path::new(sock).exists() {
            continue;
        }
        assert!(
            run_under_sandbox_with(opts.clone(), &policy, &[PERL, "-e", probe, sock]),
            "허용 목록의 {sock} 에 연결되지 않음. 리터럴 방출이 깨졌거나 경로가 vnode 경로와 다름"
        );
    }
}

// ---------- exec 화이트리스트 ----------

fn whitelist_policy(scratch: &Path, rules: &str) -> Policy {
    let src = format!(
        r#"
version = 1
name = "enforce-exec"
[defaults]
file = "allow"
exec = "ask"
egress = "deny"
{rules}
"#
    );
    let ctx = LoadContext::new(scratch, scratch.join("audit"));
    Policy::load_str(&src, &ctx).unwrap()
}

/// 대조군 쉘.
///
/// `/bin/sh`는 쓰지 않습니다. macOS 의 `/bin/sh`는 dyld variant 기구로 `/bin/bash`를
/// 다시 exec 하므로, 화이트리스트에 `/bin/bash`가 함께 없으면 최상위 프로그램인데도
/// 뜨지 못합니다. 그 성질은 [`a_variant_binary_needs_its_variant_allowed`]가 따로 고정합니다
const SHELL: &str = "/bin/zsh";

/// 허용 목록 밖의 프로그램은 커널이 막아야 합니다.
///
/// 최상위 쉘은 언제나 허용되므로 쉘은 뜨고 그 안의 exec 만 실패합니다
#[test]
fn exec_outside_the_whitelist_is_denied() {
    let s = Scratch::new("exec-white");
    let policy = whitelist_policy(s.path(), "");

    assert!(
        run_under_sandbox(&policy, s.path(), &[SHELL, "-c", "exit 0"]),
        "최상위 프로그램이 뜨지 못하면 이 테스트의 대조군이 무의미함"
    );
    assert!(
        !run_under_sandbox(&policy, s.path(), &[SHELL, "-c", "exec /usr/bin/true"]),
        "허용 목록에 없는 프로그램이 실행됨. (allow process-exec*) 무조건 개방이 남아 있음"
    );
}

#[test]
fn an_exec_allow_rule_lets_the_program_run() {
    let s = Scratch::new("exec-allow-rule");
    let policy = whitelist_policy(
        s.path(),
        r#"
[[rules]]
id = "probe"
kind = "exec"
program = "/usr/bin/true"
action = "allow"
"#,
    );
    assert!(
        run_under_sandbox(&policy, s.path(), &[SHELL, "-c", "exec /usr/bin/true"]),
        "정책이 허용한 프로그램이 막힘. 화이트리스트가 과도하게 좁음"
    );
}

/// 최상위 프로그램에 실행 허용이 없으면 프로세스가 아예 뜨지 못합니다
#[test]
fn the_top_level_program_always_runs() {
    let s = Scratch::new("exec-top");
    let policy = whitelist_policy(s.path(), "");
    assert!(
        run_under_sandbox(&policy, s.path(), &["/usr/bin/true"]),
        "허용 규칙이 하나도 없어도 최상위 프로그램은 실행되어야 함"
    );
    assert!(
        run_under_sandbox(&policy, s.path(), &[SHELL, "-c", "exit 0"]),
        "쉘도 최상위면 떠야 함"
    );
}

/// SBPL 은 마지막 규칙이 이깁니다. 화이트리스트를 deny 뒤에 두면 deny 가 무력화됩니다
#[test]
fn an_exec_deny_still_wins_over_the_whitelist() {
    let s = Scratch::new("exec-order");
    let policy = whitelist_policy(
        s.path(),
        r#"
[[rules]]
id = "no-true"
kind = "exec"
program = "/usr/bin/true"
action = "deny"

[[rules]]
id = "tools"
kind = "file"
path = "/usr/**"
mode = ["read", "exec"]
action = "allow"
"#,
    );

    // 대조군. 같은 트리 허용으로 다른 프로그램은 실제로 실행됩니다
    assert!(
        run_under_sandbox(&policy, s.path(), &[SHELL, "-c", "exec /usr/bin/uname"]),
        "허용 트리 안의 다른 프로그램까지 막히면 이 테스트의 대조군이 무의미함"
    );
    assert!(
        !run_under_sandbox(&policy, s.path(), &[SHELL, "-c", "exec /usr/bin/true"]),
        "허용 트리 뒤의 exec deny 가 무력화됨. 방출 순서가 뒤집혔음"
    );
}

/// `[defaults].exec = "allow"` 정책은 이전과 똑같이 동작해야 합니다
#[test]
fn the_exec_allow_default_does_not_regress() {
    let s = Scratch::new("exec-legacy");
    let permissive = policy_with(s.path(), "");
    assert!(
        run_under_sandbox(
            &permissive,
            s.path(),
            &["/bin/sh", "-c", "exec /usr/bin/true"]
        ),
        "exec = \"allow\" 정책에서 실행이 막히면 회귀임"
    );
}

/// 작업 공간에 써 넣은 스크립트로 인터프리터를 부르는 우회를 막아야 합니다
#[test]
fn a_script_dropped_into_the_workspace_cannot_summon_an_interpreter() {
    let s = Scratch::new("exec-drop");
    let script = s.path().join("payload.sh");
    fs::write(&script, format!("#!{SHELL}\nexit 0\n").as_bytes()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let path = script.to_string_lossy().into_owned();
    let argv = [SHELL, "-c", path.as_str()];

    let permissive = policy_with(s.path(), "");
    assert!(
        run_under_sandbox(&permissive, s.path(), &argv),
        "exec = \"allow\" 에서 실행되지 않으면 이 테스트의 대조군이 무의미함"
    );

    let policy = whitelist_policy(s.path(), "");
    assert!(
        !run_under_sandbox(&policy, s.path(), &argv),
        "작업 공간의 스크립트가 인터프리터를 불러 실행됨"
    );
}

/// macOS 의 dyld variant 기구는 최상위 프로그램 허용만으로 덮이지 않습니다.
///
/// `/bin/sh` 는 자기 자신을 `/bin/bash` 로 다시 exec 합니다. 화이트리스트에 그 대상이
/// 없으면 최상위 프로그램인데도 커널이 막습니다. 정책에서 variant 를 함께 허용하면
/// 풀립니다. 이 성질을 고정해 두지 않으면 나중에 조용히 바뀝니다
#[test]
fn a_variant_binary_needs_its_variant_allowed() {
    let s = Scratch::new("exec-variant");

    let bare = whitelist_policy(s.path(), "");
    assert!(
        !run_under_sandbox(&bare, s.path(), &["/bin/sh", "-c", "exit 0"]),
        "/bin/sh 가 variant 허용 없이 떴음. 이 한계가 사라졌다면 문서를 고쳐야 함"
    );

    let with_variant = whitelist_policy(
        s.path(),
        r#"
[[rules]]
id = "bash-variant"
kind = "exec"
program = "/bin/bash"
action = "allow"
"#,
    );
    assert!(
        run_under_sandbox(&with_variant, s.path(), &["/bin/sh", "-c", "exit 0"]),
        "variant 대상을 허용해도 /bin/sh 가 뜨지 못함"
    );
}

/// 화이트리스트 모드에서 `ask` exec 규칙은 허용 목록에 넣지 않아 커널이 거부합니다.
/// 그 사실을 배너가 말해야 합니다
#[test]
fn the_whitelist_declares_what_it_does_to_ask_rules() {
    let s = Scratch::new("exec-ask-gap");
    let policy = whitelist_policy(s.path(), "");
    let mut e =
        SeatbeltEnforcer::new().with_options(ProfileOptions::default().with_workspace(s.path()));
    e.prepare(&policy).unwrap();

    let gaps = e.gaps();
    assert!(
        gaps.iter()
            .any(|g| g.contains("화이트리스트에 넣지 않으므로")),
        "ask exec 규칙이 커널에서 어떻게 되는지 밝혀야 함: {gaps:?}"
    );
}
