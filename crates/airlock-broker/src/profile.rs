use airlock_policy::rule::Matcher;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedProfile {
    pub text: String,
    pub untranslatable: Vec<String>,
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

    if opts.allow_network {
        out.push_str(";; --- 네트워크 ---\n");
        out.push_str(";; 주의 호스트 단위 제어는 Seatbelt로 표현할 수 없음\n");
        out.push_str(";; egress 정책은 프록시 층에서 강제함\n");
        out.push_str("(allow network-outbound)\n");
        out.push_str("(allow network-bind (local ip))\n\n");
    }

    out.push_str(";; --- 정책 allow 규칙 ---\n");
    emit_file_rules(policy, &mut out, &mut untranslatable, |a| {
        a == Action::Allow
    });

    out.push_str("\n;; --- 정책 차단 규칙. 마지막에 두어 어떤 allow도 덮지 못하게 함 ---\n");
    emit_file_rules(policy, &mut out, &mut untranslatable, |a| {
        matches!(a, Action::Deny | Action::Forbid | Action::Ask)
    });

    GeneratedProfile {
        text: out,
        untranslatable,
    }
}

fn emit_file_rules(
    policy: &Policy,
    out: &mut String,
    untranslatable: &mut Vec<String>,
    keep: impl Fn(Action) -> bool,
) {
    let tiers: [&[airlock_policy::Rule]; 3] = [
        policy.self_protect_rules(),
        policy.user_rules(),
        policy.baseline_rules(),
    ];
    for tier in tiers {
        for rule in tier {
            if !keep(rule.action) {
                continue;
            }
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
    "Seatbelt는 사람 승인을 표현할 수 없으므로 ask 규칙은 프로파일에서 deny로 내려감"
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

    #[test]
    fn network_section_records_the_enforcement_gap() {
        let p = generate(&baseline(), &ProfileOptions::default());
        assert!(
            p.text
                .contains("호스트 단위 제어는 Seatbelt로 표현할 수 없음"),
            "강제할 수 없는 부분을 프로파일이 침묵하면 안 됨"
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
    fn baseline_profile_has_no_untranslatable_rules() {
        let p = generate(&baseline(), &ProfileOptions::default());
        assert!(
            p.untranslatable.is_empty(),
            "내장 베이스라인은 전부 SBPL로 표현되어야 함: {:?}",
            p.untranslatable
        );
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
