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

    /// 앞쪽 고정 구간이 다른 실제 경로로 해소되면 그 표기의 패턴을 하나 더 만듭니다.
    ///
    /// macOS 에서 `/etc`, `/var`, `/tmp` 는 `/private/*` 로 가는 firmlink 입니다. 요청이
    /// `/private/etc/sudoers` 로 오면 요청 경로도 해소 경로도 `/etc/...` 가 아니므로
    /// `/etc/sudoers` 로 적은 forbid 가 통째로 비켜 갑니다. 반대로 `/tmp/**` 로 적은
    /// allow 는 해소 경로가 `/private/tmp/...` 라 아무 것도 열지 못합니다. 양쪽 표기를
    /// 모두 규칙에 넣어야 정책이 적은 대로 걸립니다.
    pub fn resolved_variant(&self) -> Option<Pattern> {
        // 앞에서부터 고정 세그먼트만 모읍니다. 와일드카드가 나오면 거기서 멈춥니다
        let fixed: Vec<&Vec<u8>> = self
            .segs
            .iter()
            .take_while(|s| matches!(s, Seg::Exact(_)))
            .map(|s| match s {
                Seg::Exact(b) => b,
                _ => unreachable!("take_while 가 Exact 만 남김"),
            })
            .collect();
        if fixed.is_empty() {
            return None;
        }

        // 존재하는 가장 긴 접두를 찾습니다. `/etc/shadow` 처럼 대상 파일이 없어도
        // `/etc` 는 해소되므로 앞에서부터 줄여 가며 봅니다
        let mut taken = fixed.len();
        let (prefix_path, canonical) = loop {
            if taken == 0 {
                return None;
            }
            let mut prefix: Vec<u8> = Vec::new();
            for seg in fixed.iter().take(taken) {
                prefix.push(b'/');
                prefix.extend_from_slice(seg);
            }
            let candidate = PathBuf::from(std::ffi::OsString::from_vec(prefix));
            if let Ok(c) = std::fs::canonicalize(&candidate) {
                break (candidate, c);
            }
            taken -= 1;
        };
        if canonical == prefix_path {
            return None;
        }

        let mut segs = literal_segs(&canonical);
        segs.extend(self.segs.iter().skip(taken).cloned());

        // raw 는 사람이 읽는 설명이므로 앞부분만 바꿔 붙입니다. 원래 raw 가 그 접두로
        // 시작하지 않으면(홈 확장 등) 접두를 통째로 갈아 끼웁니다
        let old_prefix = prefix_path.to_string_lossy().into_owned();
        let tail = self.raw.strip_prefix(&old_prefix).unwrap_or("");
        Some(Pattern {
            raw: format!("{}{tail}", canonical.to_string_lossy()),
            segs,
        })
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

/// 패턴 세그먼트와 경로 세그먼트를 맞춰 봅니다.
///
/// `(패턴 위치, 경로 위치)` 쌍으로 메모이제이션합니다. 같은 쌍을 두 번 계산하지 않으므로
/// 비용이 두 길이의 곱으로 묶입니다. 메모 없이 `**` 마다 되돌아가면 `**` 개수만큼 지수가
/// 붙어, 경로가 긴 요청 하나로 판정이 초 단위까지 늘어납니다. 경로는 공격자가 정합니다.
fn match_segs(pat: &[Seg], path: &[&[u8]], ci: bool) -> bool {
    let mut memo = vec![None; pat.len().saturating_add(1) * path.len().saturating_add(1)];
    match_segs_memo(pat, path, ci, 0, 0, &mut memo)
}

fn match_segs_memo(
    pat: &[Seg],
    path: &[&[u8]],
    ci: bool,
    pi: usize,
    ti: usize,
    memo: &mut [Option<bool>],
) -> bool {
    let width = path.len().saturating_add(1);
    let key = pi * width + ti;
    if let Some(hit) = memo[key] {
        return hit;
    }

    let out = match pat.get(pi) {
        None => ti == path.len(),
        Some(Seg::DoubleStar) => {
            if pi + 1 == pat.len() {
                true
            } else {
                (ti..=path.len()).any(|i| match_segs_memo(pat, path, ci, pi + 1, i, memo))
            }
        }
        Some(seg) => match path.get(ti) {
            None => false,
            Some(head) => {
                match_one(seg, head, ci) && match_segs_memo(pat, path, ci, pi + 1, ti + 1, memo)
            }
        },
    };

    memo[key] = Some(out);
    out
}

fn match_one(seg: &Seg, text: &[u8], ci: bool) -> bool {
    match seg {
        Seg::DoubleStar => true,
        Seg::Exact(p) => {
            if ci {
                if eq_ascii_ci(p, text) {
                    return true;
                }
                if let (Some(fp), Some(ft)) = (fold_bytes(p), fold_bytes(text))
                    && fp == ft
                {
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
            if let (Some(fp), Some(ft)) = (fold_bytes(p), fold_bytes(text))
                && wildcard_match(&fp, &ft, false)
            {
                return true;
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

/// 케이스 무시 파일시스템이 같은 이름으로 보는 것들을 한 표기로 모읍니다.
///
/// ASCII 만 접으면 부족합니다. APFS 는 유니코드 표까지 써서 접기 때문에 `U+017F`(ſ)가
/// `s` 와 같은 파일이 되고, NFC 는 이 글자를 건드리지 않습니다. 그래서 `~/.awſ/credentials`
/// 로 쓰면 `~/.aws/**` deny 를 비켜 가면서 커널에는 `~/.aws/credentials` 로 들어갑니다.
/// NFC 로 모은 뒤 대문자로 접으면 ſ 는 S 가 되고 é/É 같은 비ASCII 짝도 함께 잡힙니다.
///
/// 넓어지는 방향이므로 제한적인 규칙(`deny`, `forbid`, `ask`)에만 씁니다.
fn fold_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(bytes).ok()?;
    Some(s.nfc().collect::<String>().to_uppercase().into_bytes())
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
