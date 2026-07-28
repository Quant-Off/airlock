use std::path::Path;

use airlock_policy::glob::{Pattern, SegmentKind};
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Literal(String),
    Subpath(String),
    Regex(String),
}

impl Target {
    pub fn render(&self) -> String {
        match self {
            Self::Literal(p) => format!("(literal {})", quote(p)),
            Self::Subpath(p) => format!("(subpath {})", quote(p)),
            Self::Regex(r) => format!("(regex #{})", quote_regex(r)),
        }
    }
}

pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

pub fn quote_regex(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        if c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

fn escape_regex_char(c: char, out: &mut String) {
    match c {
        '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
            out.push('\\');
            out.push(c);
        }
        other => out.push(other),
    }
}

fn escape_regex_str(s: &str, out: &mut String) {
    for c in s.chars() {
        escape_regex_char(c, out);
    }
}

pub fn target_for(pattern: &Pattern) -> Option<Target> {
    if let Some(root) = pattern.subtree_root() {
        return root.to_str().map(|s| Target::Subpath(s.to_string()));
    }
    if let Some(exact) = pattern.as_absolute_path() {
        return exact.to_str().map(|s| Target::Literal(s.to_string()));
    }

    let segments = pattern.segments();
    let mut re = String::from("^");
    let mut idx = 0usize;
    let total = segments.len();
    for seg in &segments {
        idx += 1;
        match seg {
            SegmentKind::AnyDepth => {
                if idx == total {
                    re.push_str("(/.*)?");
                } else {
                    re.push_str("(/[^/]+)*");
                }
            }
            SegmentKind::Literal(b) => {
                let Ok(s) = std::str::from_utf8(b) else {
                    return None;
                };
                re.push('/');
                escape_regex_str(s, &mut re);
            }
            SegmentKind::Wildcard(b) => {
                let Ok(s) = std::str::from_utf8(b) else {
                    return None;
                };
                re.push('/');
                for c in s.chars() {
                    match c {
                        '*' => re.push_str("[^/]*"),
                        '?' => re.push_str("[^/]"),
                        other => escape_regex_char(other, &mut re),
                    }
                }
            }
        }
    }
    re.push('$');
    Some(Target::Regex(re))
}

pub fn literal(path: &Path) -> Option<Target> {
    path.to_str().map(|s| Target::Literal(s.to_string()))
}

pub fn subpath(path: &Path) -> Option<Target> {
    path.to_str().map(|s| Target::Subpath(s.to_string()))
}

fn forms_of(s: &str) -> Vec<String> {
    if s.is_ascii() {
        return vec![s.to_string()];
    }
    let mut out = vec![s.to_string()];
    let nfc: String = s.nfc().collect();
    if !out.contains(&nfc) {
        out.push(nfc);
    }
    let nfd: String = s.nfd().collect();
    if !out.contains(&nfd) {
        out.push(nfd);
    }
    out
}

fn variants_of(target: Target) -> Vec<Target> {
    match target {
        Target::Literal(s) => forms_of(&s).into_iter().map(Target::Literal).collect(),
        Target::Subpath(s) => forms_of(&s).into_iter().map(Target::Subpath).collect(),
        Target::Regex(s) => forms_of(&s).into_iter().map(Target::Regex).collect(),
    }
}

pub fn targets_for(pattern: &Pattern) -> Vec<Target> {
    target_for(pattern).map(variants_of).unwrap_or_default()
}

/// 파일 이름만 지정한 exec 규칙을 경로 정규식으로 옮깁니다.
///
/// `program = "curl"`은 경로를 특정하지 않으므로 `subpath`나 `literal`로 옮길 수 없고,
/// 마지막 세그먼트가 그 이름인 모든 경로를 잡는 정규식이 됩니다
pub fn basename_targets(name: &str) -> Vec<Target> {
    let mut re = String::from("^.*/");
    escape_regex_str(name, &mut re);
    re.push('$');
    variants_of(Target::Regex(re))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn home() -> PathBuf {
        PathBuf::from("/Users/me")
    }

    fn t(raw: &str) -> Target {
        target_for(&Pattern::parse(raw, &home()).unwrap()).unwrap()
    }

    #[test]
    fn non_ascii_pattern_bytes_survive_regex_rendering() {
        match t("~/작업/*.pem") {
            Target::Regex(re) => assert_eq!(re, r"^/Users/me/작업/[^/]*\.pem$"),
            other => panic!("regex가 아님: {other:?}"),
        }
        match t("~/도구/비밀?.txt") {
            Target::Regex(re) => assert_eq!(re, r"^/Users/me/도구/비밀[^/]\.txt$"),
            other => panic!("regex가 아님: {other:?}"),
        }
    }

    #[test]
    fn non_ascii_targets_emit_both_normalization_forms() {
        let nfd: String = "작업".nfd().collect();
        assert_ne!(nfd, "작업");

        let ts = targets_for(&Pattern::parse("~/작업/*.pem", &home()).unwrap());
        assert_eq!(ts.len(), 2, "NFC와 NFD 두 형태가 나와야 함: {ts:?}");
        assert!(
            ts.iter()
                .any(|t| matches!(t, Target::Regex(r) if r.contains("작업")))
        );
        assert!(
            ts.iter()
                .any(|t| matches!(t, Target::Regex(r) if r.contains(&nfd)))
        );

        let subs = targets_for(&Pattern::parse("~/작업/**", &home()).unwrap());
        assert_eq!(subs.len(), 2);
        assert!(subs.iter().all(|t| matches!(t, Target::Subpath(_))));

        let lits = targets_for(&Pattern::parse("~/작업/키.pem", &home()).unwrap());
        assert_eq!(lits.len(), 2);
        assert!(lits.iter().all(|t| matches!(t, Target::Literal(_))));

        let ascii = targets_for(&Pattern::parse("~/work/*.pem", &home()).unwrap());
        assert_eq!(ascii.len(), 1, "ASCII 패턴에 중복 형태를 만들지 않음");
    }

    #[test]
    fn subtree_pattern_becomes_subpath() {
        assert_eq!(t("~/.ssh/**"), Target::Subpath("/Users/me/.ssh".into()));
        assert_eq!(
            t("/etc/sudoers.d/**"),
            Target::Subpath("/etc/sudoers.d".into())
        );
    }

    #[test]
    fn exact_pattern_becomes_literal() {
        assert_eq!(t("~/.netrc"), Target::Literal("/Users/me/.netrc".into()));
        assert_eq!(t("/etc/shadow"), Target::Literal("/etc/shadow".into()));
    }

    #[test]
    fn wildcard_pattern_becomes_regex() {
        assert_eq!(t("**/.env"), Target::Regex(r"^(/[^/]+)*/\.env$".into()));
        assert_eq!(
            t("~/.cargo/credentials*"),
            Target::Regex(r"^/Users/me/\.cargo/credentials[^/]*$".into())
        );
    }

    #[test]
    fn trailing_any_depth_after_wildcard_segment() {
        assert_eq!(
            t("~/Library/*/Google/**"),
            Target::Regex(r"^/Users/me/Library/[^/]*/Google(/.*)?$".into())
        );
    }

    #[test]
    fn regex_metacharacters_in_literals_are_escaped() {
        let target = t("**/.env.*");
        let Target::Regex(re) = target else {
            panic!("regex 기대");
        };
        assert!(re.contains(r"\.env\."), "{re}");
    }

    #[test]
    fn quote_escapes_embedded_quotes_and_backslashes() {
        assert_eq!(quote(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote(r"a\b"), r#""a\\b""#);
    }

    #[test]
    fn render_shapes() {
        assert_eq!(
            Target::Subpath("/a/b".into()).render(),
            r#"(subpath "/a/b")"#
        );
        assert_eq!(Target::Literal("/a".into()).render(), r#"(literal "/a")"#);
        assert_eq!(
            Target::Regex("^/a$".into()).render(),
            r##"(regex #"^/a$")"##
        );
    }

    #[test]
    fn regex_backslashes_survive_rendering() {
        let rendered = t("**/.env").render();
        assert_eq!(rendered, r##"(regex #"^(/[^/]+)*/\.env$")"##);
        assert!(
            !rendered.contains(r"\\."),
            "백슬래시를 이중 이스케이프하면 정규식이 `\\` 다음 임의 문자를 뜻하게 되어 .env deny가 무력화됨: {rendered}"
        );
    }

    #[test]
    fn regex_quoting_escapes_only_double_quotes() {
        assert_eq!(quote_regex(r"^\.env$"), r#""^\.env$""#);
        assert_eq!(quote_regex(r#"a"b"#), r#""a\"b""#);
    }

    #[test]
    fn path_quoting_still_escapes_backslashes() {
        assert_eq!(
            Target::Literal(r"/tmp/a\b".into()).render(),
            r#"(literal "/tmp/a\\b")"#
        );
    }

    #[test]
    fn question_mark_maps_to_single_non_slash() {
        let Target::Regex(re) = t("/tmp/a?c") else {
            panic!("regex 기대");
        };
        assert_eq!(re, "^/tmp/a[^/]c$");
    }
}
