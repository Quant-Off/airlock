//! 이 모듈은 정책을 macOS Seatbelt 프로파일(SBPL)로 번역합니다.
//!
//! # Features
//! 프로파일은 deny-default이며 SBPL은 마지막 규칙이 이기므로, 시스템 기본 허용을 먼저
//! 깔고 정책의 차단 규칙을 맨 뒤에 둡니다. 파일 규칙과 exec 경로 규칙, 아웃바운드
//! 전체 차단까지는 커널에서 강제되지만 호스트·포트 단위 egress와 argv 조건은 SBPL로
//! 표현할 수 없습니다. 옮기지 못한 규칙은 조용히 버리지 않고 `untranslatable`로
//! 돌려주어 배너의 한계 목록에 그대로 나오게 합니다
//!
//! `[defaults].exec` 가 `allow` 가 아니면 `(allow process-exec*)` 무조건 개방을 걷어내고
//! 정책이 허용한 경로에만 `process-exec*` 를 엽니다. 곧 exec 이 블랙리스트에서
//! 화이트리스트로 뒤집힙니다. 최상위 프로그램은 언제나 허용 목록에 들어갑니다.
//! 그것이 빠지면 프로세스가 아예 뜨지 못하기 때문입니다

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use airlock_policy::rule::{Matcher, ProgramMatch};
use airlock_policy::{Action, FileMode, ModeSet, Policy};

use crate::sbpl;

const SYSTEM_READ_SUBPATHS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library/Frameworks",
    "/Library/Preferences",
    "/opt/homebrew",
    "/opt/local",
    "/etc",
    "/private/etc",
    "/private/var/db/timezone",
    "/private/var/db/dyld",
    "/dev",
    "/Applications",
];

/// 자식에게 열어 주는 장치 노드.
///
/// `/dev/tty`는 일부러 뺐습니다. 그것은 제어 터미널이며 승인 프롬프트가 나가는 통로입니다.
/// 자식이 열 수 있으면 가짜 승인 화면을 그리거나 사용자가 입력한 답을 먼저 읽어 갈 수 있어
/// `ask`가 무의미해집니다. 상속된 stdin·stdout·stderr는 그대로 두므로 보통의 대화형
/// 프로그램은 영향받지 않습니다
const DEV_RW_LITERALS: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/dtracehelper",
];

#[derive(Debug, Clone)]
pub struct ProfileOptions {
    pub allow_network: bool,
    pub workspace: Option<std::path::PathBuf>,
    pub temp_dirs: Vec<std::path::PathBuf>,
    /// 최상위로 실행할 프로그램의 절대 경로.
    ///
    /// exec 화이트리스트 모드에서 이 경로가 허용 목록에 빠지면 커널이 첫 `execve` 를
    /// 거부해 프로세스가 아예 뜨지 못합니다. 강제 층은 `wrap` 시점에 실제로 spawn 될
    /// 명령에서 이 값을 다시 채우므로 호출자가 비워 두어도 됩니다
    pub program: Option<std::path::PathBuf>,
    /// egress 프록시가 듣고 있는 루프백 주소.
    ///
    /// 값이 있으면 아웃바운드를 이 주소 하나로 좁힙니다. 그래야 프록시가 유일한
    /// 출구가 되고 호스트 단위 정책이 처음으로 강제됩니다
    pub proxy: Option<std::net::SocketAddr>,
}

impl Default for ProfileOptions {
    fn default() -> Self {
        Self {
            allow_network: true,
            workspace: None,
            temp_dirs: default_temp_dirs(),
            program: None,
            proxy: None,
        }
    }
}

fn default_temp_dirs() -> Vec<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        vec![std::path::PathBuf::from("/private/var/folders")]
    }
    #[cfg(not(target_os = "macos"))]
    {
        vec![std::path::PathBuf::from("/tmp")]
    }
}

impl ProfileOptions {
    pub fn with_workspace(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.workspace = Some(path.into());
        self
    }

    pub fn with_network(mut self, allow: bool) -> Self {
        self.allow_network = allow;
        self
    }

    pub fn with_temp_dir(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.temp_dirs.push(path.into());
        self
    }

    pub fn with_proxy(mut self, addr: std::net::SocketAddr) -> Self {
        self.proxy = Some(addr);
        self
    }

    pub fn with_program(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.program = Some(path.into());
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeneratedProfile {
    pub text: String,
    /// SBPL로 옮길 수 없어 커널이 판정하지 못하는 규칙의 id와 사유
    pub untranslatable: Vec<String>,
    /// 일부러 방출하지 않은 `ask` exec 규칙의 id. 사유는 [`exec_ask_note`]
    pub ask_exec: Vec<String>,
    /// exec 화이트리스트 모드인지. `[defaults].exec != "allow"` 이면 참
    pub exec_whitelist: bool,
    /// 화이트리스트 모드에서 `process-exec*` 가 열린 대상. 렌더된 SBPL 필터 문자열
    pub exec_allow: Vec<String>,
}

fn mode_reads(modes: ModeSet) -> bool {
    modes.contains(FileMode::Read)
        || modes.contains(FileMode::Metadata)
        || modes.contains(FileMode::Exec)
}

fn mode_writes(modes: ModeSet) -> bool {
    modes.contains(FileMode::Write)
        || modes.contains(FileMode::Create)
        || modes.contains(FileMode::Delete)
}

/// exec 을 커널 화이트리스트로 걸어야 하는지.
///
/// `[defaults].exec = "allow"` 인 정책은 이전 동작을 그대로 둡니다. 그 설정은 "실행은
/// 기본 허용"이라고 말하고 있으므로, 화이트리스트로 뒤집으면 같은 정책 파일의 뜻이
/// 바뀝니다. `ask`/`deny`/`forbid` 일 때만 뒤집습니다
///
/// # Arguments
/// `policy` - 판단할 정책
pub fn exec_whitelist_mode(policy: &Policy) -> bool {
    policy.defaults().exec != Action::Allow
}

/// `PATH` 안에서 같은 이름의 실행 파일을 전부 찾습니다.
///
/// `program = "cargo"` 처럼 이름만 적은 규칙은 경로를 말하지 않습니다. 허용 방향에서는
/// "이름이 cargo 인 아무 경로"로 넓히면 에이전트가 작업 공간에 써 넣은 `cargo` 까지
/// 실행 대상이 되므로, 지금 `PATH` 에서 실제로 해소되는 경로만 허용 목록에 넣습니다.
/// 제한 방향(`deny`)은 반대로 이름 정규식을 그대로 써서 넓게 잡습니다
///
/// # Arguments
/// `name` - 찾을 파일 이름
pub fn resolve_in_path(name: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if name.is_empty() || name.contains('/') {
        return out;
    }
    let Some(path) = std::env::var_os("PATH") else {
        return out;
    };
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let full = dir.join(name);
        if full.is_file() && !out.contains(&full) {
            out.push(full);
        }
    }
    out
}

/// 실제로 spawn 될 프로그램의 절대 경로를 구합니다.
///
/// `Command` 는 이름만 받으면 `PATH` 로 해소하므로 강제 층도 같은 해소를 해야 커널
/// 허용 목록과 실제 `execve` 대상이 어긋나지 않습니다
///
/// # Arguments
/// `raw` - `Command::get_program()` 이 돌려준 값
pub fn resolve_program(raw: &OsStr) -> Option<PathBuf> {
    let candidate = Path::new(raw);
    if candidate.is_absolute() || candidate.components().count() > 1 {
        return candidate.is_file().then(|| candidate.to_path_buf());
    }
    let name = candidate.to_str()?;
    resolve_in_path(name).into_iter().next()
}

/// 프로파일 주석에 넣을 문자열에서 줄을 깨는 문자를 지웁니다.
///
/// 정책 로더가 규칙 id를 이미 영숫자와 몇 개 기호로 제한하지만, 주석 한 줄이 깨지면
/// 뒤 내용이 살아 있는 지시문이 되어 프로파일 전체가 뒤집힙니다. 강제 층은 로더의
/// 검증을 신뢰하지 않고 방출 시점에서 한 번 더 막습니다.
fn comment(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect()
}

pub fn generate(policy: &Policy, opts: &ProfileOptions) -> GeneratedProfile {
    let mut out = String::new();
    let mut untranslatable = Vec::new();
    let mut ask_exec = Vec::new();
    let mut exec_allow = Vec::new();
    let exec_whitelist = exec_whitelist_mode(policy);

    out.push_str("(version 1)\n");
    out.push_str(";; airlock 생성 프로파일. deny-default이며 마지막 규칙이 이김\n");
    out.push_str("(deny default)\n");
    out.push_str("(deny file-write* (with no-report))\n\n");

    out.push_str(";; --- 프로세스 기본 동작 ---\n");
    out.push_str("(allow process-fork)\n");
    if exec_whitelist {
        // 무조건 개방을 걷어내면 exec 이 블랙리스트에서 화이트리스트로 뒤집힙니다.
        // 허용은 아래 정책 allow 절에서 경로마다 하나씩 나갑니다
        out.push_str(";; exec 은 정책 allow 절에서 경로별로만 열림. 무조건 개방 없음\n");
    } else {
        out.push_str("(allow process-exec*)\n");
    }
    out.push_str("(allow signal (target self))\n");
    out.push_str("(allow sysctl-read)\n");
    out.push_str("(allow ipc-posix-shm)\n");
    out.push_str("(allow file-ioctl)\n");
    // mach 서비스는 통째로 열되 정책 밖 유출 통로로 알려진 것부터 되막습니다. 목록을
    // 화이트리스트로 뒤집으면 개발 툴체인이 버전마다 깨지므로 deny 를 뒤에 둡니다
    out.push_str("(allow mach-lookup)\n");
    out.push_str(";; 클립보드는 정책 모델 밖의 읽기 쓰기 통로임\n");
    out.push_str("(deny mach-lookup (global-name \"com.apple.pasteboard.1\"))\n");
    out.push_str("(deny mach-lookup (global-name \"com.apple.pboard\"))\n\n");

    out.push_str(";; --- 경로 해석 ---\n");
    out.push_str(";; 루트 노드 자체를 읽지 못하면 어떤 절대 경로도 해석되지 않아\n");
    out.push_str(";; dyld가 라이브러리를 찾기 전에 프로세스가 죽음\n");
    out.push_str("(allow file-read* (literal \"/\"))\n");
    out.push_str(";; 조상 디렉토리 탐색용. 아래 차단 규칙이 뒤에서 덮음\n");
    out.push_str("(allow file-read-metadata)\n\n");

    out.push_str(";; --- 시스템 읽기 ---\n");
    for p in SYSTEM_READ_SUBPATHS {
        out.push_str(&format!(
            "(allow file-read* (subpath {}))\n",
            sbpl::quote(p)
        ));
    }
    out.push('\n');

    out.push_str(";; --- 장치 노드 읽기 쓰기 ---\n");
    for p in DEV_RW_LITERALS {
        out.push_str(&format!(
            "(allow file-read* file-write* (literal {}))\n",
            sbpl::quote(p)
        ));
    }
    out.push('\n');

    if !opts.temp_dirs.is_empty() {
        out.push_str(";; --- 임시 디렉토리 ---\n");
        for dir in &opts.temp_dirs {
            match sbpl::subpath(dir) {
                Some(t) => {
                    out.push_str(&format!("(allow file-read* file-write* {})\n", t.render()))
                }
                None => untranslatable.push(format!("temp-dir {}", dir.display())),
            }
        }
        out.push('\n');
    }

    if let Some(ws) = &opts.workspace {
        out.push_str(";; --- 작업 공간 ---\n");
        match sbpl::subpath(ws) {
            Some(t) => out.push_str(&format!(
                "(allow file-read* file-write* {})\n\n",
                t.render()
            )),
            None => untranslatable.push(format!("workspace {}", ws.display())),
        }
    }

    out.push_str(";; --- 네트워크 ---\n");
    if let Some(proxy) = opts.proxy.filter(|_| opts.allow_network) {
        // 아웃바운드가 프록시 하나로 좁혀지므로 호스트 규칙은 여기서 처음으로
        // 실제 경계를 갖습니다. 판정은 프록시가 하고 커널은 우회를 막습니다
        out.push_str(";; 아웃바운드를 egress 프록시 하나로 좁힘\n");
        out.push_str(";; 호스트 판정은 프록시가 하고 커널은 다른 출구를 막음\n");
        out.push_str(&format!(
            "(allow network-outbound (remote ip {}))\n",
            sbpl::quote(&format!("localhost:{}", proxy.port()))
        ));
        // 유닉스 소켓까지 막으면 시스템 라이브러리가 대부분 동작하지 않습니다
        out.push_str("(allow network-outbound (remote unix))\n\n");
    } else if network_allowed(policy, opts) {
        out.push_str(";; 주의 호스트 단위 제어는 Seatbelt로 표현할 수 없음\n");
        out.push_str(";; egress 정책은 프록시 층에서 강제함\n");
        out.push_str("(allow network-outbound)\n");
        out.push_str("(allow network-bind (local ip))\n\n");
        // 아웃바운드가 열린 채로는 egress 제한 규칙 중 어느 것도 커널이 판정하지 못합니다
        for rule in restrictive_egress_ids(policy) {
            untranslatable.push(format!("{rule} (호스트·포트 egress)"));
        }
    } else {
        out.push_str(";; 정책에 egress allow 규칙이 없어 아웃바운드를 통째로 차단함\n");
        out.push_str(";; deny-default 프로파일이므로 규칙을 방출하지 않는 것이 곧 차단임\n\n");
    }

    out.push_str(";; --- 정책 allow 규칙 ---\n");
    emit_file_rules(policy, &mut out, &mut untranslatable, |a| {
        a == Action::Allow
    });
    if exec_whitelist {
        emit_exec_allow(policy, opts, &mut out, &mut untranslatable, &mut exec_allow);
    }

    out.push_str("\n;; --- 정책 차단 규칙. 마지막에 두어 어떤 allow도 덮지 못하게 함 ---\n");
    emit_file_rules(policy, &mut out, &mut untranslatable, |a| {
        matches!(a, Action::Deny | Action::Forbid | Action::Ask)
    });
    emit_exec_rules(policy, &mut out, &mut untranslatable, &mut ask_exec);

    GeneratedProfile {
        text: out,
        untranslatable,
        ask_exec,
        exec_whitelist,
        exec_allow,
    }
}

/// 아웃바운드를 열어도 되는지.
///
/// `--no-network`가 우선이며, 그다음은 정책입니다. egress allow 규칙이 하나도 없으면
/// 모든 연결이 `[defaults].egress`(allow 금지, 곧 deny 또는 ask)로 떨어지므로 통째로
/// 막습니다. 같은 정책이 Landlock에서 TCP 전면 차단이 되는 것과 결론을 맞춥니다
fn network_allowed(policy: &Policy, opts: &ProfileOptions) -> bool {
    if !opts.allow_network {
        return false;
    }
    tiers(policy)
        .into_iter()
        .flatten()
        .any(|r| r.action == Action::Allow && matches!(r.matcher, Matcher::Egress { .. }))
}

fn restrictive_egress_ids(policy: &Policy) -> Vec<String> {
    tiers(policy)
        .into_iter()
        .flatten()
        .filter(|r| r.action != Action::Allow && matches!(r.matcher, Matcher::Egress { .. }))
        .map(|r| r.id.clone())
        .collect()
}

fn tiers(policy: &Policy) -> [&[airlock_policy::Rule]; 3] {
    [
        policy.self_protect_rules(),
        policy.user_rules(),
        policy.baseline_rules(),
    ]
}

/// 정책이 허용한 실행 대상만 `process-exec*` 로 엽니다.
///
/// 화이트리스트 모드에서만 부릅니다. 방출 위치는 정책 allow 절이며, 뒤에 오는
/// [`emit_exec_rules`] 의 deny 가 여전히 이깁니다. SBPL 은 마지막 규칙이 이기므로
/// 이 순서를 바꾸면 deny 가 무력화됩니다.
///
/// 최상위 프로그램을 항상 먼저 넣습니다. 그것이 빠지면 커널이 첫 `execve` 를 거부해
/// 프로세스가 뜨지 못하고, 사용자는 정책 문제인지 환경 문제인지 알 수 없습니다.
///
/// # Arguments
/// `policy` - 옮길 정책
/// `opts` - 최상위 프로그램이 들어 있는 프로파일 옵션
/// `out` - 프로파일 문자열
/// `untranslatable` - 옮기지 못한 규칙을 쌓을 곳
/// `emitted` - 실제로 열린 대상을 쌓을 곳
fn emit_exec_allow(
    policy: &Policy,
    opts: &ProfileOptions,
    out: &mut String,
    untranslatable: &mut Vec<String>,
    emitted: &mut Vec<String>,
) {
    out.push_str(";; --- exec 화이트리스트. 여기 없는 프로그램은 커널이 거부함 ---\n");

    let mut emit = |target: &sbpl::Target, id: &str, out: &mut String| {
        let rendered = target.render();
        out.push_str(&format!(
            "(allow process-exec* {rendered}) ;; {}\n",
            comment(id)
        ));
        emitted.push(rendered);
    };

    if let Some(program) = &opts.program {
        match sbpl::literal(program) {
            Some(t) => emit(&t, "airlock:top-level", out),
            None => untranslatable.push(format!(
                "최상위 프로그램 {} (경로가 UTF-8이 아니라 SBPL 대상으로 옮길 수 없음)",
                program.display()
            )),
        }
    }

    for tier in tiers(policy) {
        for rule in tier {
            if rule.action != Action::Allow {
                continue;
            }
            for target in exec_allow_targets(&rule.matcher, &rule.id, untranslatable) {
                emit(&target, &rule.id, out);
            }
        }
    }
}

/// allow 규칙 하나가 여는 실행 대상.
///
/// 이름만 적은 규칙은 지금 `PATH` 에서 해소되는 경로만 냅니다. 해소되지 않으면 조용히
/// 넘기지 않고 옮기지 못한 규칙으로 보고합니다. 그 프로그램은 커널에서 실행되지 않습니다
///
/// # Arguments
/// `matcher` - 규칙의 매처
/// `id` - 규칙 id. 보고 문자열에만 씁니다
/// `untranslatable` - 옮기지 못한 규칙을 쌓을 곳
fn exec_allow_targets(
    matcher: &Matcher,
    id: &str,
    untranslatable: &mut Vec<String>,
) -> Vec<sbpl::Target> {
    match matcher {
        Matcher::Exec { program, .. } => match program {
            Some(ProgramMatch::Path(pattern)) => {
                let targets = sbpl::target_for(pattern).into_iter().collect::<Vec<_>>();
                if targets.is_empty() {
                    untranslatable.push(format!(
                        "{} (exec allow 경로 패턴을 SBPL 대상으로 옮길 수 없음)",
                        comment(id)
                    ));
                }
                targets
            }
            Some(ProgramMatch::Basename(name)) => {
                let found = resolve_in_path(name);
                if found.is_empty() {
                    untranslatable.push(format!(
                        "{} (program = \"{}\" 을 PATH 에서 찾지 못해 exec 허용에 넣지 않았음)",
                        comment(id),
                        comment(name)
                    ));
                }
                found.iter().filter_map(|p| sbpl::literal(p)).collect()
            }
            None => {
                untranslatable.push(format!(
                    "{} (프로그램 조건이 없는 exec allow 는 대상을 특정할 수 없음)",
                    comment(id)
                ));
                Vec::new()
            }
        },
        Matcher::File { paths, modes } if modes.contains(FileMode::Exec) => {
            let mut out = Vec::new();
            for pattern in paths {
                match sbpl::target_for(pattern) {
                    Some(t) => out.push(t),
                    None => untranslatable.push(format!(
                        "{} {} (exec 허용 경로를 SBPL 대상으로 옮길 수 없음)",
                        comment(id),
                        comment(pattern.raw())
                    )),
                }
            }
            out
        }
        _ => Vec::new(),
    }
}

/// exec 제한 규칙을 `process-exec*` 차단으로 옮깁니다.
///
/// `ask`는 일부러 방출하지 않습니다. macOS에서 답을 받을 수 있는 ask는 브로커가 spawn
/// 전에 묻는 최상위 exec 하나뿐인데, 그것을 프로파일에서 deny로 내려 버리면 사람이
/// 승인한 실행이 커널에서 막혀 아무 방법으로도 진행할 수 없습니다. 파일 규칙의
/// `ask` -> `deny` 강하와 다른 이유가 여기에 있습니다
fn emit_exec_rules(
    policy: &Policy,
    out: &mut String,
    untranslatable: &mut Vec<String>,
    ask_exec: &mut Vec<String>,
) {
    for tier in tiers(policy) {
        for rule in tier {
            let Matcher::Exec { .. } = &rule.matcher else {
                continue;
            };
            if rule.action == Action::Allow {
                // 허용은 이 함수의 몫이 아닙니다. 블랙리스트 모드에서는 위에서 통째로
                // 열려 있고, 화이트리스트 모드에서는 emit_exec_allow 가 앞서 방출합니다
                continue;
            }
            if rule.action == Action::Ask {
                ask_exec.push(rule.id.clone());
                continue;
            }
            match exec_targets(&rule.matcher) {
                Ok(targets) => {
                    for target in targets {
                        out.push_str(&format!(
                            "(deny process-exec* {}) ;; {}\n",
                            target.render(),
                            comment(&rule.id)
                        ));
                    }
                }
                Err(why) => untranslatable.push(format!("{} ({why})", comment(&rule.id))),
            }
        }
    }
}

fn exec_targets(matcher: &Matcher) -> std::result::Result<Vec<sbpl::Target>, &'static str> {
    let Matcher::Exec {
        program,
        argv_contains,
        argv_pattern,
    } = matcher
    else {
        return Err("exec 규칙이 아님");
    };
    if !argv_contains.is_empty() || argv_pattern.is_some() {
        // argv를 보고 좁힌 규칙을 프로그램 경로만으로 옮기면 정책보다 넓게 막습니다
        return Err("argv 조건은 Seatbelt가 볼 수 없어 표현 불가");
    }
    let Some(pm) = program else {
        return Err("프로그램 조건이 없어 실행 대상을 특정할 수 없음");
    };
    let targets = match pm {
        ProgramMatch::Basename(name) => sbpl::basename_targets(name),
        ProgramMatch::Path(pattern) => sbpl::targets_for(pattern),
    };
    if targets.is_empty() {
        return Err("경로 패턴을 SBPL 대상으로 옮길 수 없음");
    }
    Ok(targets)
}

fn emit_file_rules(
    policy: &Policy,
    out: &mut String,
    untranslatable: &mut Vec<String>,
    keep: impl Fn(Action) -> bool,
) {
    for tier in tiers(policy) {
        for rule in tier {
            if !keep(rule.action) {
                continue;
            }
            // exec 과 egress 는 이 함수의 대상이 아닙니다. 각각 emit_exec_rules 와
            // 네트워크 절이 처리하며, 여기서 조용히 버리면 강제되지 않는 규칙이
            // 강제된 것처럼 보입니다
            let Matcher::File { paths, modes } = &rule.matcher else {
                continue;
            };
            let verb = if rule.action == Action::Allow {
                "allow"
            } else {
                "deny"
            };
            let mut ops = Vec::new();
            if mode_reads(*modes) {
                ops.push("file-read*");
            }
            if mode_writes(*modes) {
                ops.push("file-write*");
            }
            if ops.is_empty() {
                continue;
            }
            for pattern in paths {
                // 제한 규칙만 정규화 변형을 함께 방출합니다. allow를 넓히면
                // 정규화 표기가 다른 별개 경로까지 열릴 수 있습니다 (4.3절 비대칭)
                let targets = if rule.action == Action::Allow {
                    sbpl::target_for(pattern).into_iter().collect::<Vec<_>>()
                } else {
                    sbpl::targets_for(pattern)
                };
                if targets.is_empty() {
                    untranslatable.push(format!(
                        "{} {}",
                        comment(&rule.id),
                        comment(pattern.raw())
                    ));
                }
                for target in targets {
                    out.push_str(&format!(
                        "({verb} {} {}) ;; {}\n",
                        ops.join(" "),
                        target.render(),
                        comment(&rule.id)
                    ));
                }
            }
        }
    }
}

pub fn ask_rules_are_denied_note() -> &'static str {
    "Seatbelt는 사람 승인을 표현할 수 없으므로 ask 파일 규칙은 프로파일에서 deny로 내려감"
}

/// 화이트리스트 모드에서 `ask` exec 규칙이 어떻게 되는지.
///
/// 허용 목록에 넣지 않으므로 커널이 실행을 거부합니다. 방출하지 않는다는 기구는 같지만
/// 결과가 반대이므로 배너 문구도 달라야 합니다
pub fn exec_ask_whitelist_note() -> &'static str {
    "ask exec 규칙은 화이트리스트에 넣지 않으므로 커널이 실행을 거부함. macOS 에는 중계 층이 \
     없어 사람에게 물을 방법이 없으며, 최상위 exec 하나만 브로커가 spawn 전에 물음"
}

pub fn exec_ask_note() -> &'static str {
    "ask exec 규칙은 커널에서 강제되지 않음. macOS 에서 답을 받을 수 있는 ask 는 브로커가 \
     spawn 전에 묻는 최상위 exec 하나뿐이라, deny 로 내리면 승인된 실행까지 막히기 때문임"
}

#[cfg(test)]
mod tests {
    use super::*;
    use airlock_policy::LoadContext;

    fn ctx() -> LoadContext {
        LoadContext::new("/Users/me", "/Users/me/.local/share/airlock")
    }

    fn baseline() -> Policy {
        Policy::baseline_only(&ctx()).unwrap()
    }

    #[test]
    fn profile_is_deny_default() {
        let p = generate(&baseline(), &ProfileOptions::default());
        assert!(p.text.starts_with("(version 1)\n"));
        assert!(
            p.text.contains("(deny default)"),
            "allow-default 프로파일은 탈출 사례가 있으므로 절대 생성하지 않음"
        );
        let deny_idx = p.text.find("(deny default)").unwrap();
        let first_allow = p.text.find("(allow").unwrap();
        assert!(deny_idx < first_allow, "deny default가 allow 앞에 와야 함");
    }

    #[test]
    fn secret_denies_come_after_allows() {
        let opts = ProfileOptions::default().with_workspace("/Users/me/work");
        let p = generate(&baseline(), &opts);

        let ws_allow = p
            .text
            .find(r#"(allow file-read* file-write* (subpath "/Users/me/work"))"#)
            .expect("작업 공간 allow 없음");
        let ssh_deny = p
            .text
            .find(r#"(subpath "/Users/me/.ssh")"#)
            .expect("ssh deny 없음");
        assert!(
            ws_allow < ssh_deny,
            "SBPL은 마지막 규칙이 이기므로 시크릿 deny가 뒤에 와야 함"
        );
    }

    #[test]
    fn every_forbid_secret_appears_as_deny() {
        let p = generate(&baseline(), &ProfileOptions::default());
        for expected in [
            r#"(subpath "/Users/me/.ssh")"#,
            r#"(subpath "/Users/me/.aws")"#,
            r#"(subpath "/Users/me/.gnupg")"#,
            r#"(subpath "/Users/me/.kube")"#,
            r#"(literal "/etc/shadow")"#,
        ] {
            assert!(p.text.contains(expected), "{expected} 누락");
        }
    }

    #[test]
    fn ask_rules_degrade_to_deny() {
        let p = generate(&baseline(), &ProfileOptions::default());
        let zshrc = p
            .text
            .lines()
            .find(|l| l.contains("/Users/me/.zshrc"))
            .expect("shell-init 규칙 없음");
        assert!(
            zshrc.starts_with("(deny"),
            "Seatbelt는 ask를 표현할 수 없으니 deny로 내려가야 함: {zshrc}"
        );
    }

    #[test]
    fn env_files_are_expressed_as_regex() {
        let p = generate(&baseline(), &ProfileOptions::default());
        assert!(
            p.text.contains(r##"(regex #"^(/[^/]+)*/\.env$")"##),
            "{}",
            p.text
        );
    }

    #[test]
    fn user_allow_rules_are_emitted() {
        let src = r#"
version = 1
[[rules]]
id = "workspace"
kind = "file"
path = "/Users/me/proj/**"
action = "allow"
"#;
        let policy = Policy::load_str(src, &ctx()).unwrap();
        let p = generate(&policy, &ProfileOptions::default());
        assert!(
            p.text.contains(
                r#"(allow file-read* file-write* (subpath "/Users/me/proj")) ;; workspace"#
            ),
            "{}",
            p.text
        );
    }

    #[test]
    fn read_only_rule_omits_write_operation() {
        let src = r#"
version = 1
[[rules]]
id = "readonly"
kind = "file"
path = "/Users/me/data/**"
mode = ["read"]
action = "allow"
"#;
        let policy = Policy::load_str(src, &ctx()).unwrap();
        let p = generate(&policy, &ProfileOptions::default());
        let line = p
            .text
            .lines()
            .find(|l| l.contains(";; readonly"))
            .expect("규칙 없음");
        assert!(line.contains("file-read*"));
        assert!(!line.contains("file-write*"), "{line}");
    }

    fn with_egress(extra: &str) -> Policy {
        let src = format!(
            r#"
version = 1
[defaults]
egress = "deny"
{extra}
"#
        );
        Policy::load_str(&src, &ctx()).unwrap()
    }

    #[test]
    fn egress_deny_default_closes_outbound_entirely() {
        let p = generate(&baseline(), &ProfileOptions::default());
        assert!(
            !p.text.contains("(allow network-outbound)"),
            "egress allow 규칙이 없는 정책이 아웃바운드를 열면 정책과 정면으로 모순됨: {}",
            p.text
        );
        assert!(
            p.text.contains("아웃바운드를 통째로 차단함"),
            "차단했다는 사실을 프로파일이 밝혀야 함"
        );
    }

    fn proxy_addr(port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn a_proxy_narrows_outbound_to_the_proxy_port() {
        let policy = with_egress(
            r#"
[[rules]]
id = "anthropic"
kind = "egress"
host = "api.anthropic.com"
port = 443
action = "allow"
"#,
        );
        let opts = ProfileOptions::default().with_proxy(proxy_addr(18899));
        let p = generate(&policy, &opts);
        // 전면 허용이 남아 있으면 프록시를 무시한 연결이 그대로 나갑니다
        assert!(!p.text.contains("(allow network-outbound)\n"), "{}", p.text);
        assert!(
            p.text
                .contains("(allow network-outbound (remote ip \"localhost:18899\"))"),
            "{}",
            p.text
        );
    }

    #[test]
    fn a_proxy_stops_declaring_host_rules_as_untranslatable() {
        let policy = with_egress(
            r#"
[[rules]]
id = "anthropic"
kind = "egress"
host = "api.anthropic.com"
port = 443
action = "allow"
"#,
        );
        let opts = ProfileOptions::default().with_proxy(proxy_addr(18899));
        let p = generate(&policy, &opts);
        // 프록시가 붙으면 이 규칙은 실제로 판정되므로 옮기지 못한 규칙이 아닙니다
        assert!(
            !p.untranslatable.iter().any(|u| u.contains("anthropic")),
            "{:?}",
            p.untranslatable
        );
    }

    #[test]
    fn no_network_beats_the_proxy() {
        let policy = with_egress(
            r#"
[[rules]]
id = "anthropic"
kind = "egress"
host = "api.anthropic.com"
port = 443
action = "allow"
"#,
        );
        let opts = ProfileOptions::default()
            .with_proxy(proxy_addr(18899))
            .with_network(false);
        let p = generate(&policy, &opts);
        assert!(!p.text.contains("network-outbound"), "{}", p.text);
    }

    #[test]
    fn egress_allow_rule_opens_outbound_and_declares_the_gap() {
        let policy = with_egress(
            r#"
[[rules]]
id = "anthropic"
kind = "egress"
host = "api.anthropic.com"
port = 443
action = "allow"
"#,
        );
        let p = generate(&policy, &ProfileOptions::default());
        assert!(p.text.contains("(allow network-outbound)"), "{}", p.text);
        assert!(
            p.text
                .contains("호스트 단위 제어는 Seatbelt로 표현할 수 없음"),
            "강제할 수 없는 부분을 프로파일이 침묵하면 안 됨"
        );
    }

    #[test]
    fn egress_denies_are_untranslatable_once_outbound_is_open() {
        let policy = with_egress(
            r#"
[[rules]]
id = "anthropic"
kind = "egress"
host = "api.anthropic.com"
port = 443
action = "allow"

[[rules]]
id = "no-metadata"
kind = "egress"
host = "169.254.169.254"
action = "deny"
"#,
        );
        let p = generate(&policy, &ProfileOptions::default());
        assert!(
            p.untranslatable.iter().any(|u| u.contains("no-metadata")),
            "커널이 판정하지 못하는 egress 규칙이 조용히 사라지면 안 됨: {:?}",
            p.untranslatable
        );
    }

    #[test]
    fn exec_deny_reaches_the_profile() {
        let src = r#"
version = 1
[defaults]
exec = "allow"
[[rules]]
id = "no-curl"
kind = "exec"
program = "curl"
action = "deny"
"#;
        let policy = Policy::load_str(src, &ctx()).unwrap();
        let p = generate(&policy, &ProfileOptions::default());
        assert!(
            p.text
                .contains(r##"(deny process-exec* (regex #"^.*/curl$")) ;; no-curl"##),
            "exec deny 가 커널까지 내려가야 함: {}",
            p.text
        );
        let deny_idx = p.text.find(";; no-curl").expect("규칙 없음");
        let allow_idx = p
            .text
            .find("(allow process-exec*)")
            .expect("기본 허용 없음");
        assert!(
            allow_idx < deny_idx,
            "SBPL은 마지막 규칙이 이기므로 exec deny 가 기본 허용 뒤에 와야 함"
        );
    }

    // ---------- exec 화이트리스트 ----------

    fn whitelist(extra: &str) -> Policy {
        let src = format!(
            r#"
version = 1
[defaults]
file = "allow"
exec = "ask"
egress = "deny"
{extra}
"#
        );
        Policy::load_str(&src, &ctx()).unwrap()
    }

    /// `[defaults].exec` 가 `allow` 가 아니면 무조건 개방이 남아 있으면 안 됩니다.
    /// 한 줄이 남으면 exec 정책 전체가 커널에서 무의미해집니다
    #[test]
    fn the_whitelist_removes_the_unconditional_exec_opening() {
        let p = generate(&whitelist(""), &ProfileOptions::default());
        assert!(p.exec_whitelist);
        assert!(
            !p.text.contains("(allow process-exec*)\n"),
            "무조건 개방이 남아 있음: {}",
            p.text
        );
        assert!(
            !p.text.contains("(allow process-exec*)"),
            "필터 없는 process-exec* 허용이 남아 있음: {}",
            p.text
        );
    }

    #[test]
    fn the_exec_allow_default_keeps_the_previous_behaviour() {
        let src = r#"
version = 1
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
"#;
        let policy = Policy::load_str(src, &ctx()).unwrap();
        let p = generate(&policy, &ProfileOptions::default());
        assert!(!p.exec_whitelist);
        assert!(
            p.text.contains("(allow process-exec*)\n"),
            "exec = \"allow\" 정책의 동작이 바뀌면 회귀임: {}",
            p.text
        );
        assert!(p.exec_allow.is_empty());
    }

    /// 최상위 프로그램이 빠지면 프로세스가 아예 뜨지 못합니다
    #[test]
    fn the_top_level_program_is_always_allowed() {
        let opts = ProfileOptions::default().with_program("/bin/zsh");
        let p = generate(&whitelist(""), &opts);
        assert!(
            p.text
                .contains(r#"(allow process-exec* (literal "/bin/zsh")) ;; airlock:top-level"#),
            "{}",
            p.text
        );
        assert!(!p.exec_allow.is_empty());
    }

    #[test]
    fn exec_allow_rules_open_exactly_their_paths() {
        let policy = whitelist(
            r#"
[[rules]]
id = "tool"
kind = "exec"
program = "/usr/bin/git"
action = "allow"

[[rules]]
id = "toolchain"
kind = "file"
path = "/opt/homebrew/**"
mode = ["read", "exec"]
action = "allow"
"#,
        );
        let p = generate(&policy, &ProfileOptions::default());
        assert!(
            p.text
                .contains(r#"(allow process-exec* (literal "/usr/bin/git")) ;; tool"#),
            "{}",
            p.text
        );
        assert!(
            p.text
                .contains(r#"(allow process-exec* (subpath "/opt/homebrew")) ;; toolchain"#),
            "{}",
            p.text
        );
    }

    /// SBPL 은 마지막 규칙이 이깁니다. 허용을 차단 뒤에 두면 deny 가 무력화됩니다
    #[test]
    fn exec_denies_still_come_after_the_whitelist() {
        let policy = whitelist(
            r#"
[[rules]]
id = "no-nc"
kind = "exec"
program = "/usr/bin/nc"
action = "deny"

[[rules]]
id = "tools"
kind = "file"
path = "/usr/**"
mode = ["read", "exec"]
action = "allow"
"#,
        );
        let p = generate(&policy, &ProfileOptions::default());
        let allow_idx = p.text.find(";; tools").expect("화이트리스트 없음");
        let deny_idx = p.text.find(";; no-nc").expect("차단 규칙 없음");
        assert!(
            allow_idx < deny_idx,
            "exec deny 가 화이트리스트 앞으로 오면 무력화됨: {}",
            p.text
        );
    }

    /// 이름만 적은 allow 는 지금 PATH 에서 해소되는 경로만 엽니다.
    ///
    /// `^.*/name$` 정규식으로 넓히면 에이전트가 작업 공간에 써 넣은 동명 바이너리까지
    /// 실행 대상이 되어 화이트리스트가 통째로 무너집니다
    #[test]
    fn a_basename_allow_resolves_through_path_instead_of_widening() {
        let policy = whitelist(
            r#"
[[rules]]
id = "shell"
kind = "exec"
program = "sh"
action = "allow"
"#,
        );
        let p = generate(&policy, &ProfileOptions::default());
        assert!(
            !p.text.contains(r##"(regex #"^.*/sh$")"##),
            "이름 정규식으로 넓히면 동명 바이너리가 전부 열림: {}",
            p.text
        );
        let resolved = resolve_in_path("sh");
        if resolved.is_empty() {
            assert!(
                p.untranslatable.iter().any(|u| u.contains("shell")),
                "해소되지 않은 allow 를 조용히 버리면 안 됨: {:?}",
                p.untranslatable
            );
        } else {
            assert!(p.text.contains(";; shell"), "{}", p.text);
        }
    }

    #[test]
    fn an_unresolvable_basename_allow_is_declared() {
        let policy = whitelist(
            r#"
[[rules]]
id = "ghost"
kind = "exec"
program = "airlock-no-such-program-xyz"
action = "allow"
"#,
        );
        let p = generate(&policy, &ProfileOptions::default());
        assert!(
            p.untranslatable
                .iter()
                .any(|u| u.contains("ghost") && u.contains("PATH")),
            "{:?}",
            p.untranslatable
        );
    }

    #[test]
    fn resolve_program_follows_path_like_command_does() {
        assert_eq!(
            resolve_program(std::ffi::OsStr::new("/bin/sh")),
            Some(PathBuf::from("/bin/sh"))
        );
        assert_eq!(
            resolve_program(std::ffi::OsStr::new("/no/such/binary")),
            None
        );
        let by_name = resolve_program(std::ffi::OsStr::new("sh"));
        assert!(by_name.is_some_and(|p| p.is_absolute()), "PATH 해소 실패");
    }

    #[test]
    fn exec_deny_by_path_uses_a_literal_target() {
        let src = r#"
version = 1
[[rules]]
id = "no-nc"
kind = "exec"
program = "/usr/bin/nc"
action = "deny"
"#;
        let policy = Policy::load_str(src, &ctx()).unwrap();
        let p = generate(&policy, &ProfileOptions::default());
        assert!(
            p.text
                .contains(r#"(deny process-exec* (literal "/usr/bin/nc")) ;; no-nc"#),
            "{}",
            p.text
        );
    }

    #[test]
    fn exec_rule_with_argv_condition_is_untranslatable() {
        let src = r#"
version = 1
[[rules]]
id = "no-force-push"
kind = "exec"
program = "git"
argv_contains = ["--force"]
action = "deny"
"#;
        let policy = Policy::load_str(src, &ctx()).unwrap();
        let p = generate(&policy, &ProfileOptions::default());
        assert!(
            !p.text.contains(";; no-force-push"),
            "argv 조건을 프로그램 경로만으로 옮기면 정책보다 넓게 막음: {}",
            p.text
        );
        assert!(
            p.untranslatable
                .iter()
                .any(|u| u.contains("no-force-push") && u.contains("argv")),
            "{:?}",
            p.untranslatable
        );
    }

    #[test]
    fn network_can_be_denied_entirely() {
        let opts = ProfileOptions::default().with_network(false);
        let p = generate(&baseline(), &opts);
        assert!(!p.text.contains("(allow network-outbound)"));
    }

    #[test]
    fn self_protect_rules_reach_the_profile() {
        let p = generate(&baseline(), &ProfileOptions::default());
        assert!(
            p.text.contains(";; self:audit-log"),
            "감사 로그 보호가 커널 강제까지 내려가야 함"
        );
    }

    #[test]
    fn every_baseline_file_rule_is_translatable() {
        let policy = baseline();
        let p = generate(&policy, &ProfileOptions::default());
        let file_ids: Vec<&str> = policy
            .baseline_rules()
            .iter()
            .chain(policy.self_protect_rules())
            .filter(|r| matches!(r.matcher, Matcher::File { .. }))
            .map(|r| r.id.as_str())
            .collect();
        for id in file_ids {
            assert!(
                !p.untranslatable.iter().any(|u| u.starts_with(id)),
                "베이스라인 파일 규칙 {id}가 프로파일로 옮겨지지 않았음: {:?}",
                p.untranslatable
            );
        }
        assert!(
            p.untranslatable.is_empty(),
            "베이스라인에 옮기지 못한 규칙이 있음: {:?}",
            p.untranslatable
        );
    }

    #[test]
    fn baseline_exec_asks_are_declared_not_dropped() {
        let p = generate(&baseline(), &ProfileOptions::default());
        for id in ["danger-rm", "sudo-exec", "pipe-curl-to-shell"] {
            assert!(
                p.ask_exec.iter().any(|u| u == id),
                "강제되지 않는 exec 규칙 {id}가 조용히 사라졌음: {:?}",
                p.ask_exec
            );
        }
    }

    #[test]
    fn comment_strips_control_characters() {
        // 규칙 id 는 정책 로더가 이미 제한하지만 강제 층은 그 검증을 신뢰하지 않습니다.
        // 주석 한 줄이 깨지면 뒤 내용이 살아 있는 지시문이 되어 프로파일이 뒤집힙니다
        let payload = "ok\n(allow file-read* file-write* (subpath \"/\"))\n;;";
        let out = comment(payload);
        assert!(!out.contains('\n'), "개행이 남으면 주석을 탈출함: {out}");
        assert_eq!(out.lines().count(), 1, "한 줄로 남아야 함: {out}");
        for raw in ["a\rb", "a\u{1b}[2Kb", "a\u{0}b"] {
            let got = comment(raw);
            assert!(
                !got.chars().any(char::is_control),
                "{raw:?}에 제어 문자가 남음: {got}"
            );
        }
        assert_eq!(comment("build-cache.v2_x-y"), "build-cache.v2_x-y");
    }

    #[test]
    fn generated_profile_is_balanced() {
        let p = generate(&baseline(), &ProfileOptions::default());
        let mut depth = 0i32;
        let mut in_string = false;
        let mut prev = '\0';
        for c in p.text.chars() {
            match c {
                '"' if prev != '\\' => in_string = !in_string,
                '(' if !in_string => depth += 1,
                ')' if !in_string => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0, "괄호가 먼저 닫힘");
            prev = c;
        }
        assert_eq!(depth, 0, "괄호가 맞지 않음");
    }
}
