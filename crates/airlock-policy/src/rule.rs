use std::path::Path;

use crate::glob::{Pattern, TextPattern};
use crate::host::HostPattern;
use crate::model::{Action, FileMode, Kind, ModeSet, Tier};

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
            Self::Egress { host, port } => match port {
                Some(p) => format!("{}:{p}", host.raw()),
                None => host.raw(),
            },
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
                if let Some(pm) = program {
                    if !pm.matches(prog, ci) {
                        return false;
                    }
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
            (Matcher::Egress { host, port }, Query::Egress { host: h, port: p }) => {
                if let Some(want) = port {
                    if want != p {
                        return false;
                    }
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
            port: 443
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

    #[test]
    fn egress_port_narrows_the_rule() {
        let with_port = Rule {
            id: "e".into(),
            tier: Tier::User,
            action: Action::Allow,
            reason: None,
            overrides: None,
            matcher: Matcher::Egress {
                host: HostPattern::parse("api.anthropic.com").unwrap(),
                port: Some(443),
            },
        };
        assert!(with_port.matches(&Query::Egress {
            host: "api.anthropic.com",
            port: 443
        }));
        assert!(!with_port.matches(&Query::Egress {
            host: "api.anthropic.com",
            port: 80
        }));
    }

    #[test]
    fn egress_without_port_matches_any_port() {
        let r = Rule {
            id: "e".into(),
            tier: Tier::User,
            action: Action::Deny,
            reason: None,
            overrides: None,
            matcher: Matcher::Egress {
                host: HostPattern::parse("*").unwrap(),
                port: None,
            },
        };
        assert!(r.matches(&Query::Egress {
            host: "x.com",
            port: 1
        }));
        assert!(r.matches(&Query::Egress {
            host: "x.com",
            port: 65535
        }));
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
