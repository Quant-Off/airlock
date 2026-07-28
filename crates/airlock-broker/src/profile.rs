//! 이 모듈은 정책을 macOS Seatbelt 프로파일(SBPL)로 번역합니다.
//!
//! # Features
//! 프로파일은 deny-default이며 SBPL은 마지막 규칙이 이기므로, 시스템 기본 허용을 먼저
//! 깔고 정책의 차단 규칙을 맨 뒤에 둡니다. 파일 규칙과 exec 경로 규칙, 아웃바운드
//! 전체 차단까지는 커널에서 강제되지만 호스트·포트 단위 egress와 argv 조건은 SBPL로
//! 표현할 수 없습니다. 옮기지 못한 규칙은 조용히 버리지 않고 `untranslatable`로
//! 돌려주어 배너의 한계 목록에 그대로 나오게 합니다

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

const DEV_RW_LITERALS: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
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
}

impl Default for ProfileOptions {
    fn default() -> Self {
        Self {
            allow_network: true,
            workspace: None,
            temp_dirs: default_temp_dirs(),
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
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeneratedProfile {
    pub text: String,
    /// SBPL로 옮길 수 없어 커널이 판정하지 못하는 규칙의 id와 사유
    pub untranslatable: Vec<String>,
    /// 일부러 방출하지 않은 `ask` exec 규칙의 id. 사유는 [`exec_ask_note`]
    pub ask_exec: Vec<String>,
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

pub fn generate(policy: &Policy, opts: &ProfileOptions) -> GeneratedProfile {
    let mut out = String::new();
    let mut untranslatable = Vec::new();
    let mut ask_exec = Vec::new();

    out.push_str("(version 1)\n");
    out.push_str(";; airlock 생성 프로파일. deny-default이며 마지막 규칙이 이김\n");
    out.push_str("(deny default)\n");
    out.push_str("(deny file-write* (with no-report))\n\n");

    out.push_str(";; --- 프로세스 기본 동작 ---\n");
    out.push_str("(allow process-fork)\n");
    out.push_str("(allow process-exec*)\n");
    out.push_str("(allow signal (target self))\n");
    out.push_str("(allow sysctl-read)\n");
    out.push_str("(allow mach-lookup)\n");
    out.push_str("(allow ipc-posix-shm)\n");
    out.push_str("(allow file-ioctl)\n\n");

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
    if network_allowed(policy, opts) {
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

    out.push_str("\n;; --- 정책 차단 규칙. 마지막에 두어 어떤 allow도 덮지 못하게 함 ---\n");
    emit_file_rules(policy, &mut out, &mut untranslatable, |a| {
        matches!(a, Action::Deny | Action::Forbid | Action::Ask)
    });
    emit_exec_rules(policy, &mut out, &mut untranslatable, &mut ask_exec);

    GeneratedProfile {
        text: out,
        untranslatable,
        ask_exec,
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
                // 위에서 process-exec*를 통째로 열어 두었으므로 더 넓힐 것이 없습니다
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
                            rule.id
                        ));
                    }
                }
                Err(why) => untranslatable.push(format!("{} ({why})", rule.id)),
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
                    untranslatable.push(format!("{} {}", rule.id, pattern.raw()));
                }
                for target in targets {
                    out.push_str(&format!(
                        "({verb} {} {}) ;; {}\n",
                        ops.join(" "),
                        target.render(),
                        rule.id
                    ));
                }
            }
        }
    }
}

pub fn ask_rules_are_denied_note() -> &'static str {
    "Seatbelt는 사람 승인을 표현할 수 없으므로 ask 파일 규칙은 프로파일에서 deny로 내려감"
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
