use std::fmt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use unicode_normalization::UnicodeNormalization;

const MAX_DOUBLE_STARS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    Empty,
    NotAbsolute(String),
    UserHome(String),
    DotSegment(String),
    EmbeddedDoubleStar(String),
    TooManyDoubleStars(String),
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "빈 패턴"),
            Self::NotAbsolute(p) => write!(
                f,
                "`{p}`는 절대 경로가 아님. `/`, `~/`, `**/` 중 하나로 시작해야 함"
            ),
            Self::UserHome(p) => write!(f, "`{p}`의 `~user` 형태는 v1에서 지원하지 않음"),
            Self::DotSegment(p) => write!(f, "`{p}`에 `.` 또는 `..` 세그먼트가 있음"),
            Self::EmbeddedDoubleStar(p) => write!(
                f,
                "`{p}`의 `**`는 세그먼트 전체여야 함. 세그먼트 일부로 쓸 수 없음"
            ),
            Self::TooManyDoubleStars(p) => {
                write!(f, "`{p}`의 `**`가 {MAX_DOUBLE_STARS}개를 넘음")
            }
        }
    }
}

impl std::error::Error for PatternError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    DoubleStar,
    Exact(Vec<u8>),
    Wild(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    raw: String,
    segs: Vec<Seg>,
}

impl Pattern {
    pub fn parse(raw: &str, home: &Path) -> Result<Self, PatternError> {
        if raw.is_empty() {
            return Err(PatternError::Empty);
        }

        // 세그먼트는 바이트로 만듭니다. 홈 경로는 유효한 UTF-8이라는 보장이 없고,
        // 손실 변환하면 `~/.ssh/**` 같은 베이스라인 forbid가 존재하지 않는
        // 경로에 걸려 시크릿 보호가 통째로 빗나갑니다 (5절)
        let expanded: Vec<u8> = if raw == "~" {
            home.as_os_str().as_bytes().to_vec()
        } else if let Some(rest) = raw.strip_prefix("~/") {
            let mut p = home.as_os_str().as_bytes().to_vec();
            if p.last() != Some(&b'/') {
                p.push(b'/');
            }
            p.extend_from_slice(rest.as_bytes());
            p
        } else if raw.starts_with('~') {
            return Err(PatternError::UserHome(raw.to_string()));
        } else if raw.starts_with('/') || raw.starts_with("**/") || raw == "**" {
            raw.as_bytes().to_vec()
        } else {
            return Err(PatternError::NotAbsolute(raw.to_string()));
        };

        let mut segs = Vec::new();
        let mut double_stars = 0usize;
        for part in expanded.split(|b| *b == b'/') {
            if part.is_empty() {
                continue;
            }
            if part == b"." || part == b".." {
                return Err(PatternError::DotSegment(raw.to_string()));
            }
            if part == b"**" {
                double_stars += 1;
                if double_stars > MAX_DOUBLE_STARS {
                    return Err(PatternError::TooManyDoubleStars(raw.to_string()));
                }
                segs.push(Seg::DoubleStar);
                continue;
            }
            if part.windows(2).any(|w| w == b"**") {
                return Err(PatternError::EmbeddedDoubleStar(raw.to_string()));
            }
            let bytes = part.to_vec();
            if bytes.contains(&b'*') || bytes.contains(&b'?') {
                segs.push(Seg::Wild(bytes));
            } else {
                segs.push(Seg::Exact(bytes));
            }
        }

        Ok(Self {
            raw: raw.to_string(),
            segs,
        })
    }

    pub fn literal(path: &Path) -> Self {
        Self {
            raw: path.to_string_lossy().into_owned(),
            segs: literal_segs(path),
        }
    }

    pub fn literal_subtree(path: &Path) -> Self {
        let mut segs = literal_segs(path);
        segs.push(Seg::DoubleStar);
        Self {
            raw: format!("{}/**", path.to_string_lossy()),
            segs,
        }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn witness(&self) -> PathBuf {
        let mut out: Vec<u8> = Vec::new();
        for seg in &self.segs {
            out.push(b'/');
            match seg {
                Seg::DoubleStar => out.push(b'x'),
                Seg::Exact(b) => out.extend_from_slice(b),
                Seg::Wild(b) => {
                    for byte in b {
                        match byte {
                            b'*' => {}
                            b'?' => out.push(b'x'),
                            other => out.push(*other),
                        }
                    }
                    if out.last() == Some(&b'/') {
                        out.push(b'x');
                    }
                }
            }
        }
        if out.is_empty() {
            out.push(b'/');
        }
        PathBuf::from(std::ffi::OsString::from_vec(out))
    }

    pub fn matches(&self, path: &Path, case_insensitive: bool) -> bool {
        let bytes = path.as_os_str().as_bytes();
        let segments: Vec<&[u8]> = bytes
            .split(|b| *b == b'/')
            .filter(|s| !s.is_empty())
            .collect();
        match_segs(&self.segs, &segments, case_insensitive)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentKind<'a> {
    AnyDepth,
    Literal(&'a [u8]),
    Wildcard(&'a [u8]),
}

impl Pattern {
    pub fn segments(&self) -> Vec<SegmentKind<'_>> {
        self.segs
            .iter()
            .map(|s| match s {
                Seg::DoubleStar => SegmentKind::AnyDepth,
                Seg::Exact(b) => SegmentKind::Literal(b),
                Seg::Wild(b) => SegmentKind::Wildcard(b),
            })
            .collect()
    }

    pub fn is_wildcard_free(&self) -> bool {
        self.segs.iter().all(|s| matches!(s, Seg::Exact(_)))
    }

    pub fn subtree_root(&self) -> Option<PathBuf> {
        let (last, head) = self.segs.split_last()?;
        if !matches!(last, Seg::DoubleStar) {
            return None;
        }
        if !head.iter().all(|s| matches!(s, Seg::Exact(_))) {
            return None;
        }
        let mut out: Vec<u8> = Vec::new();
        for s in head {
            if let Seg::Exact(b) = s {
                out.push(b'/');
                out.extend_from_slice(b);
            }
        }
        if out.is_empty() {
            out.push(b'/');
        }
        Some(PathBuf::from(std::ffi::OsString::from_vec(out)))
    }

    pub fn as_absolute_path(&self) -> Option<PathBuf> {
        if !self.is_wildcard_free() {
            return None;
        }
        let mut out: Vec<u8> = Vec::new();
        for s in &self.segs {
            if let Seg::Exact(b) = s {
                out.push(b'/');
                out.extend_from_slice(b);
            }
        }
        if out.is_empty() {
            out.push(b'/');
        }
        Some(PathBuf::from(std::ffi::OsString::from_vec(out)))
    }
}

#[cfg(test)]
mod home_bytes_tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn non_utf8_home_anchors_the_pattern_exactly() {
        let home = PathBuf::from(OsStr::from_bytes(b"/home/\xff\xfeuser"));
        let p = Pattern::parse("~/.ssh/**", &home).unwrap();

        let secret = PathBuf::from(OsStr::from_bytes(b"/home/\xff\xfeuser/.ssh/id_rsa"));
        assert!(
            p.matches(&secret, true),
            "홈이 UTF-8이 아니어도 시크릿 규칙이 걸려야 함"
        );

        // 손실 변환되면 U+FFFD가 섞인 이 경로에 걸리게 됩니다
        let lossy = PathBuf::from("/home/\u{fffd}\u{fffd}user/.ssh/id_rsa");
        assert!(
            !p.matches(&lossy, true),
            "손실 변환된 경로에 걸리면 실제 시크릿은 빗나감"
        );
    }

    #[test]
    fn non_utf8_home_bare_tilde_is_exact() {
        let home = PathBuf::from(OsStr::from_bytes(b"/home/\xff\xfeuser"));
        let p = Pattern::parse("~", &home).unwrap();
        assert!(p.matches(&home, true));
    }
}

fn literal_segs(path: &Path) -> Vec<Seg> {
    path.as_os_str()
        .as_bytes()
        .split(|b| *b == b'/')
        .filter(|s| !s.is_empty())
        .map(|s| Seg::Exact(s.to_vec()))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextPattern {
    raw: String,
}

impl TextPattern {
    pub fn new(raw: impl Into<String>) -> Self {
        Self { raw: raw.into() }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn matches(&self, text: &str, case_insensitive: bool) -> bool {
        wildcard_match(self.raw.as_bytes(), text.as_bytes(), case_insensitive)
    }
}

fn match_segs(pat: &[Seg], path: &[&[u8]], ci: bool) -> bool {
    match pat.split_first() {
        None => path.is_empty(),
        Some((Seg::DoubleStar, rest)) => {
            if rest.is_empty() {
                return true;
            }
            (0..=path.len()).any(|i| match_segs(rest, &path[i..], ci))
        }
        Some((seg, rest)) => match path.split_first() {
            None => false,
            Some((head, tail)) => match_one(seg, head, ci) && match_segs(rest, tail, ci),
        },
    }
}

fn match_one(seg: &Seg, text: &[u8], ci: bool) -> bool {
    match seg {
        Seg::DoubleStar => true,
        Seg::Exact(p) => {
            if ci {
                if eq_ascii_ci(p, text) {
                    return true;
                }
                match (nfc_bytes(p), nfc_bytes(text)) {
                    (None, None) => false,
                    (np, nt) => {
                        eq_ascii_ci(np.as_deref().unwrap_or(p), nt.as_deref().unwrap_or(text))
                    }
                }
            } else {
                p.as_slice() == text
            }
        }
        Seg::Wild(p) => {
            if wildcard_match(p, text, ci) {
                return true;
            }
            if !ci {
                return false;
            }
            match (nfc_bytes(p), nfc_bytes(text)) {
                (None, None) => false,
                (np, nt) => wildcard_match(
                    np.as_deref().unwrap_or(p),
                    nt.as_deref().unwrap_or(text),
                    ci,
                ),
            }
        }
    }
}

fn nfc_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_ascii() {
        return None;
    }
    let s = std::str::from_utf8(bytes).ok()?;
    Some(s.nfc().collect::<String>().into_bytes())
}

fn eq_ascii_ci(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn byte_eq(a: u8, b: u8, ci: bool) -> bool {
    if ci {
        a.eq_ignore_ascii_case(&b)
    } else {
        a == b
    }
}

fn wildcard_match(pat: &[u8], text: &[u8], ci: bool) -> bool {
    let mut p = 0usize;
    let mut t = 0usize;
    let mut star: Option<usize> = None;
    let mut star_t = 0usize;

    while t < text.len() {
        let cur = pat.get(p).copied();
        match cur {
            Some(b'?') => {
                p += 1;
                t += 1;
            }
            Some(b'*') => {
                star = Some(p);
                star_t = t;
                p += 1;
            }
            Some(c) if byte_eq(c, text[t], ci) => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some(sp) => {
                    p = sp + 1;
                    star_t += 1;
                    t = star_t;
                }
                None => return false,
            },
        }
    }

    while pat.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pat.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> PathBuf {
        PathBuf::from("/Users/me")
    }

    fn pat(raw: &str) -> Pattern {
        Pattern::parse(raw, &home()).unwrap()
    }

    fn hit(raw: &str, path: &str) -> bool {
        pat(raw).matches(Path::new(path), false)
    }

    fn hit_ci(raw: &str, path: &str) -> bool {
        pat(raw).matches(Path::new(path), true)
    }

    // ---------- 파싱 검증 ----------

    #[test]
    fn rejects_relative_patterns() {
        assert!(matches!(
            Pattern::parse("work/**", &home()),
            Err(PatternError::NotAbsolute(_))
        ));
        assert!(matches!(
            Pattern::parse(".ssh/id_rsa", &home()),
            Err(PatternError::NotAbsolute(_))
        ));
    }

    #[test]
    fn rejects_user_home_form() {
        assert!(matches!(
            Pattern::parse("~root/.ssh/**", &home()),
            Err(PatternError::UserHome(_))
        ));
    }

    #[test]
    fn rejects_dot_segments() {
        assert!(matches!(
            Pattern::parse("/a/../b", &home()),
            Err(PatternError::DotSegment(_))
        ));
        assert!(matches!(
            Pattern::parse("/a/./b", &home()),
            Err(PatternError::DotSegment(_))
        ));
    }

    #[test]
    fn rejects_embedded_double_star() {
        assert!(matches!(
            Pattern::parse("/a**b", &home()),
            Err(PatternError::EmbeddedDoubleStar(_))
        ));
    }

    #[test]
    fn rejects_double_star_flood() {
        let p = "/**/**/**/**/**/x";
        assert!(matches!(
            Pattern::parse(p, &home()),
            Err(PatternError::TooManyDoubleStars(_))
        ));
    }

    #[test]
    fn tilde_expands_to_home() {
        let p = pat("~/.ssh/**");
        assert!(p.matches(Path::new("/Users/me/.ssh/id_rsa"), false));
        assert!(!p.matches(Path::new("/Users/other/.ssh/id_rsa"), false));
        assert_eq!(p.raw(), "~/.ssh/**");
    }

    // ---------- `*`는 `/`를 넘지 않습니다 ----------

    #[test]
    fn single_star_stays_inside_one_segment() {
        assert!(hit("/a/*", "/a/b"));
        assert!(!hit("/a/*", "/a/b/c"));
        assert!(hit("/a/*.rs", "/a/main.rs"));
        assert!(!hit("/a/*.rs", "/a/sub/main.rs"));
    }

    #[test]
    fn question_mark_is_one_byte_inside_a_segment() {
        assert!(hit("/a/?", "/a/b"));
        assert!(!hit("/a/?", "/a/bc"));
        assert!(!hit("/a/?", "/a/b/c"));
    }

    // ---------- `**` 의미론 ----------

    #[test]
    fn double_star_matches_zero_segments() {
        assert!(hit("/a/**", "/a"));
        assert!(hit("~/.ssh/**", "/Users/me/.ssh"));
    }

    #[test]
    fn double_star_matches_any_depth() {
        assert!(hit("/a/**", "/a/b"));
        assert!(hit("/a/**", "/a/b/c/d/e"));
        assert!(!hit("/a/**", "/b/a"));
    }

    #[test]
    fn leading_double_star_matches_anywhere() {
        assert!(hit("**/.env", "/Users/me/proj/.env"));
        assert!(hit("**/.env", "/.env"));
        assert!(hit("**/.env*", "/a/b/.env.local"));
        assert!(hit("**/.env*", "/a/.env"));
        assert!(!hit("**/.env", "/a/.environment"));
    }

    #[test]
    fn middle_double_star() {
        assert!(hit("/a/**/z", "/a/z"));
        assert!(hit("/a/**/z", "/a/b/z"));
        assert!(hit("/a/**/z", "/a/b/c/z"));
        assert!(!hit("/a/**/z", "/a/b/c"));
    }

    #[test]
    fn exact_pattern_is_anchored_at_root() {
        assert!(hit("/a/b", "/a/b"));
        assert!(!hit("/a/b", "/x/a/b"));
        assert!(!hit("/a/b", "/a/b/c"));
        assert!(!hit("/a/b", "/a"));
    }

    #[test]
    fn redundant_slashes_are_ignored() {
        assert!(hit("/a/b", "/a//b"));
        assert!(hit("/a/b", "//a/b"));
    }

    // ---------- 대소문자 ----------

    #[test]
    fn case_insensitive_mode_catches_case_variants() {
        assert!(hit_ci("~/.ssh/**", "/Users/me/.SSH/id_rsa"));
        assert!(hit_ci("~/.ssh/**", "/Users/me/.Ssh/id_rsa"));
        assert!(hit_ci("**/.env", "/a/.ENV"));
    }

    #[test]
    fn case_sensitive_mode_does_not_widen() {
        assert!(!hit("~/.ssh/**", "/Users/me/.SSH/id_rsa"));
        assert!(!hit("~/work/**", "/Users/me/WORK/x"));
        assert!(hit("~/work/**", "/Users/me/work/x"));
    }

    #[test]
    fn nfd_variants_match_in_insensitive_mode() {
        let nfd_dir: String = "작업".nfd().collect();
        let nfd_file: String = "비밀".nfd().collect();
        assert_ne!(nfd_dir, "작업");

        assert!(hit_ci(
            "~/작업/비밀.pem",
            &format!("/Users/me/{nfd_dir}/{nfd_file}.pem")
        ));
        assert!(hit_ci(
            "~/작업/*.pem",
            &format!("/Users/me/{nfd_dir}/{nfd_file}.pem")
        ));
        let nfc_from_nfd_pattern = Pattern::parse(&format!("~/{nfd_dir}/*.pem"), &home()).unwrap();
        assert!(nfc_from_nfd_pattern.matches(Path::new("/Users/me/작업/키.pem"), true));
    }

    #[test]
    fn sensitive_mode_does_not_widen_across_normalization() {
        let nfd_dir: String = "작업".nfd().collect();
        assert!(!hit("~/작업/**", &format!("/Users/me/{nfd_dir}/x")));
        assert!(hit("~/작업/**", "/Users/me/작업/x"));
    }

    #[test]
    fn case_insensitive_wildcards_too() {
        assert!(hit_ci("**/id_*", "/a/ID_RSA"));
        assert!(!hit("**/id_*", "/a/ID_RSA"));
    }

    // ---------- 와일드카드 백트래킹 ----------

    #[test]
    fn wildcard_backtracking_is_correct() {
        assert!(wildcard_match(b"*", b"", false));
        assert!(wildcard_match(b"**", b"anything", false));
        assert!(wildcard_match(b"a*b*c", b"abc", false));
        assert!(wildcard_match(b"a*b*c", b"axxbyyc", false));
        assert!(!wildcard_match(b"a*b*c", b"axxbyy", false));
        assert!(wildcard_match(b"*.env", b".env", false));
        assert!(wildcard_match(b".env*", b".env", false));
        assert!(!wildcard_match(b"a?c", b"ac", false));
        assert!(wildcard_match(b"a?c", b"abc", false));
    }

    #[test]
    fn pathological_wildcard_terminates() {
        let pattern = b"*a*a*a*a*a*a*a*a*b";
        let text = vec![b'a'; 200];
        assert!(!wildcard_match(pattern, &text, false));
    }

    #[test]
    fn non_utf8_path_bytes_still_match() {
        use std::ffi::OsStr;
        let raw = b"/Users/me/.ssh/\xff\xfekey";
        let path = Path::new(OsStr::from_bytes(raw));
        assert!(pat("~/.ssh/**").matches(path, false));
    }

    #[test]
    fn secret_patterns_from_baseline_hit_real_paths() {
        assert!(hit("~/.aws/**", "/Users/me/.aws/credentials"));
        assert!(hit("~/.config/gcloud/**", "/Users/me/.config/gcloud/x/y"));
        assert!(hit("**/.env", "/Users/me/proj/api/.env"));
        assert!(hit("~/.netrc", "/Users/me/.netrc"));
        assert!(!hit("~/.netrc", "/Users/me/.netrc.bak"));
    }
}
