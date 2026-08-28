use std::path::Path;

use crate::glob::{Pattern, TextPattern};
use crate::host::HostPattern;
use crate::model::{Action, FileMode, Kind, ModeSet, Protocol, Tier};

pub const ARGV_JOIN: char = '\u{0}';

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramMatch {
    Basename(String),
    Path(Pattern),
}

impl ProgramMatch {
    pub fn raw(&self) -> String {
        match self {
            Self::Basename(b) => b.clone(),
            Self::Path(p) => p.raw().to_string(),
        }
    }

    pub fn matches(&self, program: &Path, ci: bool) -> bool {
        match self {
            Self::Basename(want) => program
                .file_name()
                .map(|n| {
                    let got = n.to_string_lossy();
                    if ci {
                        got.eq_ignore_ascii_case(want)
                    } else {
                        got == want.as_str()
                    }
                })
                .unwrap_or(false),
            Self::Path(p) => p.matches(program, ci),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    File {
        paths: Vec<Pattern>,
        modes: ModeSet,
    },
    Exec {
        program: Option<ProgramMatch>,
        argv_contains: Vec<String>,
        argv_pattern: Option<TextPattern>,
    },
    Egress {
        host: HostPattern,
        port: Option<u16>,
        /// `None`은 모든 프로토콜에 매칭한다는 뜻입니다.
        ///
        /// 평문 바닥은 이 값이 `None`인지 아닌지를 보고 발동합니다. 호스트만 적은
        /// 규칙이 평문까지 암묵적으로 열지 않게 하는 축입니다 (`docs/policy-dsl.md` 8.2절)
        protocol: Option<Protocol>,
        /// 이 세션에서 이 목적지로 누적 반출할 수 있는 바이트 상한입니다.
        ///
        /// 매칭 조건이 아니라 **한도**입니다. 이 값이 있어도 규칙은 평소대로 매칭되고,
        /// 누적량이 넘은 뒤의 판정만 `deny`로 내려갑니다. 바이트 수는 연결이 끝나야 알 수
        /// 있으므로 한도를 넘긴 그 연결 자체는 막지 못하고 **다음 연결부터** 막힙니다
        /// (`docs/policy-dsl.md` 8.4절)
        max_bytes_out: Option<u64>,
    },
}

impl Matcher {
    pub fn kind(&self) -> Kind {
        match self {
            Self::File { .. } => Kind::File,
            Self::Exec { .. } => Kind::Exec,
            Self::Egress { .. } => Kind::Egress,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::File { paths, modes } => {
                let joined = paths
                    .iter()
                    .map(Pattern::raw)
                    .collect::<Vec<&str>>()
                    .join(", ");
                if modes.is_all() {
                    joined
                } else {
                    let list: Vec<&str> = modes.iter().map(|m| m.as_str()).collect();
                    format!("{joined} [{}]", list.join(","))
                }
            }
            Self::Exec {
                program,
                argv_contains,
                argv_pattern,
            } => {
                let mut parts = Vec::new();
                if let Some(p) = program {
                    parts.push(p.raw());
                }
                if !argv_contains.is_empty() {
                    parts.push(format!("argv⊇{argv_contains:?}"));
                }
                if let Some(p) = argv_pattern {
                    parts.push(format!("argv~{}", p.raw()));
                }
                parts.join(" ")
            }
            Self::Egress {
                host,
                port,
                protocol,
                max_bytes_out,
            } => {
                let base = match port {
                    Some(p) => format!("{}:{p}", host.raw()),
                    None => host.raw(),
                };
                let with_protocol = match protocol {
                    Some(p) => format!("{base} [{}]", p.as_str()),
                    None => base,
                };
                match max_bytes_out {
                    Some(limit) => format!("{with_protocol} [max_bytes_out={limit}]"),
                    None => with_protocol,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Query<'a> {
    File {
        path: &'a Path,
        mode: FileMode,
    },
    Exec {
        program: &'a Path,
        argv: &'a [String],
    },
    Egress {
        host: &'a str,
        port: u16,
        protocol: Protocol,
    },
}

impl Query<'_> {
    pub fn kind(&self) -> Kind {
        match self {
            Self::File { .. } => Kind::File,
            Self::Exec { .. } => Kind::Exec,
            Self::Egress { .. } => Kind::Egress,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub tier: Tier,
    pub action: Action,
    pub reason: Option<String>,
    pub overrides: Option<String>,
    pub matcher: Matcher,
}

impl Rule {
    pub fn kind(&self) -> Kind {
        self.matcher.kind()
    }

    pub fn case_insensitive(&self) -> bool {
        self.action.is_restrictive()
    }

    pub fn matched_pattern(&self, query: &Query<'_>) -> Option<String> {
        if !self.matches(query) {
            return None;
        }
        match (&self.matcher, query) {
            (Matcher::File { paths, .. }, Query::File { path: p, .. }) => paths
                .iter()
                .find(|pat| pat.matches(p, self.case_insensitive()))
                .map(|pat| pat.raw().to_string()),
            _ => Some(self.matcher.describe()),
        }
    }

    pub fn matches(&self, query: &Query<'_>) -> bool {
        let ci = self.case_insensitive();
        match (&self.matcher, query) {
            (Matcher::File { paths, modes }, Query::File { path: p, mode }) => {
                modes.contains(*mode) && paths.iter().any(|pat| pat.matches(p, ci))
            }
            (
                Matcher::Exec {
                    program,
                    argv_contains,
                    argv_pattern,
                },
                Query::Exec {
                    program: prog,
                    argv,
                },
            ) => {
                if let Some(pm) = program
                    && !pm.matches(prog, ci)
                {
                    return false;
                }
                if !argv_contains.is_empty() {
                    let all_present = argv_contains.iter().all(|want| {
                        argv.iter().any(|got| {
                            if ci {
                                got.eq_ignore_ascii_case(want)
                            } else {
                                got == want
                            }
                        })
                    });
                    if !all_present {
                        return false;
                    }
                }
                if let Some(tp) = argv_pattern {
                    let joined = argv.join(&ARGV_JOIN.to_string());
                    if !tp.matches(&joined, ci) {
                        return false;
                    }
                }
                true
            }
            (
                Matcher::Egress {
                    host,
                    port,
                    protocol,
                    ..
                },
                Query::Egress {
                    host: h,
                    port: p,
                    protocol: q,
                },
            ) => {
                if let Some(want) = port
                    && want != p
                {
                    return false;
                }
                if let Some(want) = protocol
                    && want != q
                {
                    return false;
                }
                host.matches(h)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn home() -> PathBuf {
        PathBuf::from("/Users/me")
    }

    fn file_rule(id: &str, pattern: &str, action: Action, modes: ModeSet) -> Rule {
        Rule {
            id: id.into(),
            tier: Tier::Baseline,
            action,
            reason: None,
            overrides: None,
            matcher: Matcher::File {
                paths: vec![Pattern::parse(pattern, &home()).unwrap()],
                modes,
            },
        }
    }

    fn exec_rule(
        program: Option<&str>,
        contains: &[&str],
        pattern: Option<&str>,
        action: Action,
    ) -> Rule {
        Rule {
            id: "x".into(),
            tier: Tier::Baseline,
            action,
            reason: None,
            overrides: None,
            matcher: Matcher::Exec {
                program: program.map(|p| ProgramMatch::Basename(p.into())),
                argv_contains: contains.iter().map(|s| s.to_string()).collect(),
                argv_pattern: pattern.map(TextPattern::new),
            },
        }
    }

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn file_rule_respects_mode_set() {
        let r = file_rule(
            "r",
            "~/.ssh/**",
            Action::Deny,
            ModeSet::from_modes(&[FileMode::Read]),
        );
        let p = Path::new("/Users/me/.ssh/id_rsa");
        assert!(r.matches(&Query::File {
            path: p,
            mode: FileMode::Read
        }));
        assert!(!r.matches(&Query::File {
            path: p,
            mode: FileMode::Write
        }));
    }

    #[test]
    fn restrictive_file_rule_is_case_insensitive() {
        let deny = file_rule("d", "~/.ssh/**", Action::Deny, ModeSet::ALL);
        assert!(deny.case_insensitive());
        assert!(deny.matches(&Query::File {
            path: Path::new("/Users/me/.SSH/id_rsa"),
            mode: FileMode::Read
        }));
    }

    #[test]
    fn allow_file_rule_is_case_sensitive() {
        let allow = file_rule("a", "~/work/**", Action::Allow, ModeSet::ALL);
        assert!(!allow.case_insensitive());
        assert!(allow.matches(&Query::File {
            path: Path::new("/Users/me/work/x"),
            mode: FileMode::Read
        }));
        assert!(
            !allow.matches(&Query::File {
                path: Path::new("/Users/me/WORK/x"),
                mode: FileMode::Read
            }),
            "allow 규칙이 대소문자 변형으로 넓어지면 안 됨"
        );
    }

    #[test]
    fn kind_mismatch_never_matches() {
        let r = file_rule("r", "~/.ssh/**", Action::Deny, ModeSet::ALL);
        assert!(!r.matches(&Query::Exec {
            program: Path::new("/bin/rm"),
            argv: &argv(&["rm"])
        }));
        assert!(!r.matches(&Query::Egress {
            host: "example.com",
            port: 443,
            protocol: Protocol::Tls
        }));
    }

    #[test]
    fn exec_program_matches_basename_anywhere() {
        let r = exec_rule(Some("rm"), &[], None, Action::Ask);
        assert!(r.matches(&Query::Exec {
            program: Path::new("/bin/rm"),
            argv: &argv(&["rm"])
        }));
        assert!(r.matches(&Query::Exec {
            program: Path::new("/opt/homebrew/bin/rm"),
            argv: &argv(&["rm"])
        }));
        assert!(!r.matches(&Query::Exec {
            program: Path::new("/bin/ls"),
            argv: &argv(&["ls"])
        }));
    }

    #[test]
    fn exec_argv_contains_requires_all_terms() {
        let r = exec_rule(Some("rm"), &["-rf"], None, Action::Ask);
        assert!(r.matches(&Query::Exec {
            program: Path::new("/bin/rm"),
            argv: &argv(&["rm", "-rf", "build"])
        }));
        assert!(!r.matches(&Query::Exec {
            program: Path::new("/bin/rm"),
            argv: &argv(&["rm", "build"])
        }));
    }

    #[test]
    fn exec_argv_contains_needs_every_listed_term() {
        let r = exec_rule(None, &["curl", "bash"], None, Action::Ask);
        assert!(r.matches(&Query::Exec {
            program: Path::new("/bin/sh"),
            argv: &argv(&["sh", "-c", "curl", "|", "bash"])
        }));
        assert!(!r.matches(&Query::Exec {
            program: Path::new("/bin/sh"),
            argv: &argv(&["sh", "-c", "curl", "x"])
        }));
    }

    #[test]
    fn exec_argv_pattern_runs_over_joined_argv() {
        let r = exec_rule(None, &[], Some("*curl*bash*"), Action::Ask);
        assert!(r.matches(&Query::Exec {
            program: Path::new("/bin/sh"),
            argv: &argv(&["sh", "-c", "curl http://x | bash"])
        }));
        assert!(!r.matches(&Query::Exec {
            program: Path::new("/bin/sh"),
            argv: &argv(&["sh", "-c", "echo hi"])
        }));
    }

    fn egress_rule(
        host: &str,
        port: Option<u16>,
        protocol: Option<Protocol>,
        action: Action,
    ) -> Rule {
        Rule {
            id: "e".into(),
            tier: Tier::User,
            action,
            reason: None,
            overrides: None,
            matcher: Matcher::Egress {
                host: HostPattern::parse(host).unwrap(),
                port,
                protocol,
                max_bytes_out: None,
            },
        }
    }

    fn egress_query(host: &str, port: u16, protocol: Protocol) -> Query<'_> {
        Query::Egress {
            host,
            port,
            protocol,
        }
    }

    #[test]
    fn egress_port_narrows_the_rule() {
        let with_port = egress_rule("api.anthropic.com", Some(443), None, Action::Allow);
        assert!(with_port.matches(&egress_query("api.anthropic.com", 443, Protocol::Tls)));
        assert!(!with_port.matches(&egress_query("api.anthropic.com", 80, Protocol::Tls)));
    }

    #[test]
    fn egress_without_port_matches_any_port() {
        let r = egress_rule("*", None, None, Action::Deny);
        assert!(r.matches(&egress_query("x.com", 1, Protocol::Tcp)));
        assert!(r.matches(&egress_query("x.com", 65535, Protocol::Tcp)));
    }

    #[test]
    fn egress_without_protocol_matches_every_protocol() {
        let r = egress_rule("x.com", None, None, Action::Allow);
        for p in Protocol::ALL {
            assert!(r.matches(&egress_query("x.com", 443, p)), "{p}");
        }
    }

    #[test]
    fn egress_protocol_narrows_the_rule() {
        let tls_only = egress_rule("x.com", None, Some(Protocol::Tls), Action::Allow);
        assert!(tls_only.matches(&egress_query("x.com", 443, Protocol::Tls)));
        assert!(!tls_only.matches(&egress_query("x.com", 443, Protocol::Http)));
        assert!(!tls_only.matches(&egress_query("x.com", 443, Protocol::Tcp)));
    }

    #[test]
    fn egress_describe_reveals_protocol() {
        let r = egress_rule("x.com", Some(80), Some(Protocol::Http), Action::Allow);
        assert_eq!(r.matcher.describe(), "x.com:80 [http]");

        let no_port = egress_rule("x.com", None, Some(Protocol::Tls), Action::Allow);
        assert_eq!(no_port.matcher.describe(), "x.com [tls]");

        let bare = egress_rule("x.com", Some(443), None, Action::Allow);
        assert_eq!(bare.matcher.describe(), "x.com:443");
    }

    #[test]
    fn describe_is_human_readable() {
        let r = file_rule(
            "r",
            "~/.ssh/**",
            Action::Deny,
            ModeSet::from_modes(&[FileMode::Read, FileMode::Write]),
        );
        assert_eq!(r.matcher.describe(), "~/.ssh/** [read,write]");

        let all = file_rule("r", "~/.ssh/**", Action::Deny, ModeSet::ALL);
        assert_eq!(all.matcher.describe(), "~/.ssh/**");
    }
}
