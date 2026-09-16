use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use airlock_i18n::tr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPath {
    pub requested: PathBuf,
    pub resolved: PathBuf,
}

impl NormalizedPath {
    pub fn diverges(&self) -> bool {
        self.requested != self.resolved
    }
}

/// `HOME`을 읽습니다.
///
/// 값이 없거나 절대 경로가 아니면 `None`입니다. 예전에는 `/`로 물러섰지만, 그러면
/// `~/.ssh/**` 같은 베이스라인 forbid가 전부 `/.ssh/**`로 붕괴해 진짜 홈이 무방비가
/// 됩니다. 시크릿 보호가 조용히 사라지는 유일한 방향이므로 실패로 다룹니다.
pub fn home_dir_checked() -> Option<PathBuf> {
    let raw = std::env::var_os("HOME").filter(|h| !h.is_empty())?;
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return None;
    }
    Some(std::fs::canonicalize(&path).unwrap_or(path))
}

pub fn home_dir() -> PathBuf {
    home_dir_checked().unwrap_or_else(|| PathBuf::from("/"))
}

/// 신뢰 경계를 정의하는 파일을 출처 확인과 함께 읽습니다.
///
/// `O_NOFOLLOW`로 열어 마지막 구성 요소가 심볼릭 링크면 거부하고, 열린 fd를 그대로
/// `fstat` 해 TOCTOU 없이 소유자와 권한을 봅니다. 검사한 fd에서 그대로 읽으므로 검사 후
/// 파일이 바뀌어도 읽는 대상은 달라지지 않습니다.
///
/// # Arguments
/// `path` - 읽을 파일
///
/// # Errors
/// 열기·읽기 실패, 심볼릭 링크, 호출자 소유가 아닌 파일, 그룹이나 그 밖의 사용자가 쓸 수
/// 있는 파일은 전부 거부합니다.
///
/// # Safety
/// `libc::getuid`는 인자가 없고 실패하지 않으며 스레드 상태를 건드리지 않습니다. 반환값은
/// 항상 유효한 uid이므로 이 호출에는 지켜야 할 사전 조건이 없습니다.
pub fn read_trusted(path: &Path) -> Result<String, crate::error::LoadError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let io_err = |source| crate::error::LoadError::Io {
        path: path.to_path_buf(),
        source,
    };

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io_err)?;

    let meta = file.metadata().map_err(io_err)?;
    let uid = unsafe { libc::getuid() };
    if meta.uid() != uid {
        return Err(crate::error::LoadError::UntrustedFile {
            path: path.to_path_buf(),
            why: tr!(
                format!("uid {}의 소유임. 호출자는 uid {uid}", meta.uid()),
                format!("owned by uid {}; the caller is uid {uid}", meta.uid())
            ),
        });
    }
    // 022. 그룹이나 그 밖의 사용자가 쓸 수 있으면 그들이 곧 정책 작성자입니다
    if meta.mode() & 0o022 != 0 {
        return Err(crate::error::LoadError::UntrustedFile {
            path: path.to_path_buf(),
            why: tr!(
                format!(
                    "권한이 {:04o}로 다른 사용자가 쓸 수 있음",
                    meta.mode() & 0o7777
                ),
                format!(
                    "mode {:04o} lets other users write to it",
                    meta.mode() & 0o7777
                )
            ),
        });
    }

    let mut src = String::new();
    file.read_to_string(&mut src).map_err(io_err)?;
    Ok(src)
}

pub fn expand_tilde(raw: &Path, home: &Path) -> PathBuf {
    let bytes = raw.as_os_str().as_bytes();
    if bytes == b"~" {
        return home.to_path_buf();
    }
    if let Some(rest) = bytes.strip_prefix(b"~/") {
        let mut out = home.to_path_buf();
        out.push(Path::new(OsStr::from_bytes(rest)));
        return out;
    }
    raw.to_path_buf()
}

pub fn lexical_clean(path: &Path) -> PathBuf {
    let bytes = path.as_os_str().as_bytes();
    let mut stack: Vec<&[u8]> = Vec::new();
    for seg in bytes.split(|b| *b == b'/') {
        match seg {
            b"" | b"." => {}
            b".." => {
                stack.pop();
            }
            s => stack.push(s),
        }
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len().saturating_add(1));
    for s in &stack {
        out.push(b'/');
        out.extend_from_slice(s);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    PathBuf::from(OsString::from_vec(out))
}

/// 커널이 따라가는 링크 홉 상한입니다. 넘으면 커널은 ELOOP 를 돌려줍니다
const MAX_SYMLINK_HOPS: usize = 40;

fn segments(path: &Path) -> Vec<OsString> {
    path.as_os_str()
        .as_bytes()
        .split(|b| *b == b'/')
        .filter(|s| !s.is_empty() && *s != b".")
        .map(|s| OsString::from_vec(s.to_vec()))
        .collect()
}

/// 심볼릭 링크를 커널과 같은 순서로 해소합니다.
///
/// 경로가 통째로 존재하면 `canonicalize` 가 곧 커널의 답입니다. 존재하지 않으면(매달린
/// 링크, 아직 만들어지지 않은 꼬리) 루트부터 한 구성 요소씩 걷습니다. 링크를 만나면 그
/// 대상을 남은 구성 요소 앞에 끼워 넣고, 상대 대상은 **해소된** 부모에 붙입니다. 어휘적
/// 부모에 붙이면 `ws/dir -> /out/dir`, `/out/dir/x -> ../id_rsa` 에서 커널은
/// `/out/id_rsa` 를 여는데 엔진은 `ws/id_rsa` 를 판정합니다 (4절). `..` 는 그 시점까지
/// 해소된 경로에서 한 단계 올라가며, 없는 구성 요소부터는 나머지를 어휘적으로 붙입니다.
fn resolve_symlinks(absolute: &Path) -> PathBuf {
    if let Ok(p) = std::fs::canonicalize(absolute) {
        return p;
    }
    walk_symlinks(absolute)
}

fn walk_symlinks(absolute: &Path) -> PathBuf {
    let mut pending: VecDeque<OsString> = segments(absolute).into();
    let mut resolved = PathBuf::from("/");
    let mut hops = 0usize;

    // 존재하는 접두는 디스크에 적힌 대소문자로 맞춥니다. 대소문자를 구분하지 않는 볼륨에서
    // 요청 표기와 실제 표기가 다르면 그 차이가 감사에 남아야 합니다
    let append_rest = |existing: PathBuf, seg: &OsStr, rest: VecDeque<OsString>| {
        let mut out = std::fs::canonicalize(&existing).unwrap_or(existing);
        out.push(seg);
        for s in rest {
            out.push(s);
        }
        out
    };

    while let Some(seg) = pending.pop_front() {
        if seg.as_os_str() == OsStr::new("..") {
            resolved.pop();
            continue;
        }
        let candidate = resolved.join(&seg);
        let Ok(meta) = std::fs::symlink_metadata(&candidate) else {
            return append_rest(resolved, &seg, pending);
        };
        if !meta.file_type().is_symlink() {
            resolved = candidate;
            continue;
        }
        hops = hops.saturating_add(1);
        if hops > MAX_SYMLINK_HOPS {
            return append_rest(resolved, &seg, pending);
        }
        let Ok(target) = std::fs::read_link(&candidate) else {
            return append_rest(resolved, &seg, pending);
        };
        if target.is_absolute() {
            resolved = PathBuf::from("/");
        }
        for s in segments(&target).into_iter().rev() {
            pending.push_front(s);
        }
    }
    resolved
}

/// 첫 NUL 바이트에서 경로를 자릅니다.
///
/// 커널은 C 문자열을 받으므로 NUL 뒤는 존재하지 않는 것과 같습니다. 정책이 뒤까지 읽으면
/// `~/.ssh/id_ed25519\0/../../work/ok.txt` 가 작업 공간 파일로 판정되는데 커널은 개인키를
/// 엽니다. 커널이 보는 것과 같은 것을 보게 맞춥니다.
fn truncate_at_nul(path: &Path) -> PathBuf {
    let bytes = path.as_os_str().as_bytes();
    match bytes.iter().position(|b| *b == 0) {
        None => path.to_path_buf(),
        Some(i) => PathBuf::from(OsString::from_vec(bytes[..i].to_vec())),
    }
}

pub fn normalize(raw: &Path, cwd: &Path, home: &Path) -> NormalizedPath {
    let raw = &truncate_at_nul(raw);
    let expanded = expand_tilde(raw, home);
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        let mut p = cwd.to_path_buf();
        p.push(expanded);
        p
    };
    let requested = fold_firmlink(&lexical_clean(&absolute));
    let resolved = fold_firmlink(&lexical_clean(&resolve_symlinks(&absolute)));
    NormalizedPath {
        requested,
        resolved,
    }
}

/// macOS firmlink 의 Data 볼륨 표기를 루트 표기로 접습니다.
///
/// `/Users/x/.ssh` 와 `/System/Volumes/Data/Users/x/.ssh` 는 같은 디렉토리인데
/// `canonicalize` 는 firmlink 를 넘지 않으므로 후자를 후자로 돌려줍니다. 그대로 두면
/// `~/.ssh/**` forbid 를 비롯한 전 티어가 후자를 놓칩니다. 요청 경로와 규칙 경로 양쪽에
/// 같은 접기를 적용해 두 표기가 하나로 수렴하게 합니다. firmlink 표에 있는 대상에만
/// 적용하며 다른 플랫폼에서는 아무것도 하지 않습니다.
#[cfg(target_os = "macos")]
pub fn fold_firmlink(path: &Path) -> PathBuf {
    firmlink::fold(path, firmlink::table())
}

#[cfg(not(target_os = "macos"))]
pub fn fold_firmlink(path: &Path) -> PathBuf {
    path.to_path_buf()
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod firmlink {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};

    pub const TABLE_PATH: &str = "/usr/share/firmlinks";
    const DATA_VOLUME: &[&[u8]] = &[b"System", b"Volumes", b"Data"];
    const MAX_TABLE_BYTES: u64 = 64 * 1024;

    /// macOS 10.15 이후 시스템 볼륨의 기본 firmlink 목록입니다. 표를 읽지 못할 때만 씁니다
    const BUILTIN: &[(&str, &str)] = &[
        ("/AppleInternal", "AppleInternal"),
        ("/Applications", "Applications"),
        ("/Library", "Library"),
        ("/System/Library/Caches", "System/Library/Caches"),
        ("/System/Library/Assets", "System/Library/Assets"),
        (
            "/System/Library/PreinstalledAssets",
            "System/Library/PreinstalledAssets",
        ),
        ("/System/Library/AssetsV2", "System/Library/AssetsV2"),
        (
            "/System/Library/PreinstalledAssetsV2",
            "System/Library/PreinstalledAssetsV2",
        ),
        (
            "/System/Library/CoreServices/CoreTypes.bundle/Contents/Library",
            "System/Library/CoreServices/CoreTypes.bundle/Contents/Library",
        ),
        ("/System/Library/Speech", "System/Library/Speech"),
        ("/Users", "Users"),
        ("/Volumes", "Volumes"),
        ("/cores", "cores"),
        ("/opt", "opt"),
        ("/pkg", "pkg"),
        ("/private", "private"),
        ("/usr/local", "usr/local"),
        ("/usr/libexec/cups", "usr/libexec/cups"),
        ("/usr/share/snmp", "usr/share/snmp"),
    ];

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Firmlink {
        pub root: Vec<Vec<u8>>,
        pub data: Vec<Vec<u8>>,
    }

    fn split_segments(raw: &[u8]) -> Option<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for seg in raw.split(|b| *b == b'/') {
            if seg.is_empty() {
                continue;
            }
            if seg == b"." || seg == b".." || seg.contains(&0) {
                return None;
            }
            out.push(seg.to_vec());
        }
        if out.is_empty() {
            return None;
        }
        Some(out)
    }

    fn starts_with_ci(segs: &[Vec<u8>], prefix: &[&[u8]]) -> bool {
        segs.len() >= prefix.len()
            && segs
                .iter()
                .zip(prefix)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// 표의 한 줄을 검증합니다. 루트 열은 절대 경로, Data 열은 상대 경로여야 하며 둘 다
    /// `.`/`..`/NUL 이 없어야 합니다. 루트가 Data 볼륨 아래이면 접기가 되돌아가므로 버립니다
    pub fn parse_entry(root: &str, data: &str) -> Option<Firmlink> {
        let root = root.trim();
        let data = data.trim();
        if !root.starts_with('/') || data.starts_with('/') {
            return None;
        }
        let root = split_segments(root.as_bytes())?;
        let data = split_segments(data.as_bytes())?;
        if starts_with_ci(&root, DATA_VOLUME) {
            return None;
        }
        Some(Firmlink { root, data })
    }

    pub fn parse_table(src: &str) -> Vec<Firmlink> {
        let mut out: Vec<Firmlink> = Vec::new();
        for line in src.lines() {
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let mut cols = line.split('\t');
            let (Some(root), Some(data), None) = (cols.next(), cols.next(), cols.next()) else {
                continue;
            };
            if let Some(entry) = parse_entry(root, data)
                && !out.contains(&entry)
            {
                out.push(entry);
            }
        }
        out
    }

    pub fn builtin() -> Vec<Firmlink> {
        BUILTIN
            .iter()
            .filter_map(|(root, data)| parse_entry(root, data))
            .collect()
    }

    /// 표 파일을 출처 확인과 함께 읽습니다. root 소유이고 다른 사용자가 쓸 수 없어야 하며
    /// 심볼릭 링크면 거부합니다. 내용은 데이터로만 다룹니다
    fn load_table() -> Option<Vec<Firmlink>> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(TABLE_PATH)
            .ok()?;
        let meta = file.metadata().ok()?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return None;
        }
        let mut src = String::new();
        file.take(MAX_TABLE_BYTES).read_to_string(&mut src).ok()?;
        let parsed = parse_table(&src);
        if parsed.is_empty() {
            return None;
        }
        Some(parsed)
    }

    pub fn table() -> &'static [Firmlink] {
        static TABLE: std::sync::OnceLock<Vec<Firmlink>> = std::sync::OnceLock::new();
        TABLE.get_or_init(|| load_table().unwrap_or_else(builtin))
    }

    /// `/System/Volumes/Data/<data>/rest` 를 `<root>/rest` 로 접습니다.
    ///
    /// 표에 있는 대상에만 적용하며 가장 긴 대상을 고릅니다. APFS 시스템 볼륨은 대소문자를
    /// 구분하지 않으므로 접두와 대상은 ASCII 대소문자를 무시하고 맞춥니다. 나머지는 그대로
    /// 둡니다.
    pub fn fold(path: &Path, table: &[Firmlink]) -> PathBuf {
        let Some(segs) = split_segments(path.as_os_str().as_bytes()) else {
            return path.to_path_buf();
        };
        if !starts_with_ci(&segs, DATA_VOLUME) {
            return path.to_path_buf();
        }
        let rest = &segs[DATA_VOLUME.len()..];
        let best = table
            .iter()
            .filter(|f| {
                rest.len() >= f.data.len()
                    && f.data
                        .iter()
                        .zip(rest)
                        .all(|(a, b)| a.eq_ignore_ascii_case(b))
            })
            .max_by_key(|f| f.data.len());
        let Some(best) = best else {
            return path.to_path_buf();
        };
        let mut out: Vec<u8> = Vec::with_capacity(path.as_os_str().len());
        for seg in best.root.iter().chain(rest[best.data.len()..].iter()) {
            out.push(b'/');
            out.extend_from_slice(seg);
        }
        PathBuf::from(OsString::from_vec(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn home() -> PathBuf {
        PathBuf::from("/Users/me")
    }

    fn cwd() -> PathBuf {
        PathBuf::from("/Users/me/work")
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            p.push(format!("airlock-path-{tag}-{}-{nanos}", std::process::id()));
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

    #[test]
    fn tilde_expansion() {
        assert_eq!(
            expand_tilde(Path::new("~/.ssh/id_rsa"), &home()),
            PathBuf::from("/Users/me/.ssh/id_rsa")
        );
        assert_eq!(expand_tilde(Path::new("~"), &home()), home());
        assert_eq!(
            expand_tilde(Path::new("~root/x"), &home()),
            PathBuf::from("~root/x")
        );
        assert_eq!(
            expand_tilde(Path::new("/abs/path"), &home()),
            PathBuf::from("/abs/path")
        );
    }

    #[test]
    fn lexical_dot_dot_is_resolved() {
        assert_eq!(
            lexical_clean(Path::new("/Users/me/.ssh/../.ssh/id_rsa")),
            PathBuf::from("/Users/me/.ssh/id_rsa")
        );
        assert_eq!(
            lexical_clean(Path::new("/Users/me/work/../.ssh/id_rsa")),
            PathBuf::from("/Users/me/.ssh/id_rsa")
        );
    }

    #[test]
    fn lexical_single_dot_and_double_slash_removed() {
        assert_eq!(
            lexical_clean(Path::new("/Users/me/./.ssh//id_rsa")),
            PathBuf::from("/Users/me/.ssh/id_rsa")
        );
        assert_eq!(
            lexical_clean(Path::new("/Users/me/.ssh/./id_rsa")),
            PathBuf::from("/Users/me/.ssh/id_rsa")
        );
    }

    #[test]
    fn dot_dot_above_root_is_absorbed() {
        assert_eq!(
            lexical_clean(Path::new("/../../../../etc/shadow")),
            PathBuf::from("/etc/shadow")
        );
        assert_eq!(
            lexical_clean(Path::new("/a/../../../etc/shadow")),
            PathBuf::from("/etc/shadow")
        );
    }

    #[test]
    fn root_stays_root() {
        assert_eq!(lexical_clean(Path::new("/")), PathBuf::from("/"));
        assert_eq!(lexical_clean(Path::new("/..")), PathBuf::from("/"));
        assert_eq!(lexical_clean(Path::new("//")), PathBuf::from("/"));
    }

    #[test]
    fn relative_paths_resolve_against_cwd() {
        let n = normalize(Path::new("src/main.rs"), &cwd(), &home());
        assert_eq!(n.requested, PathBuf::from("/Users/me/work/src/main.rs"));
    }

    #[test]
    fn relative_dot_dot_escapes_cwd() {
        let n = normalize(Path::new("../.ssh/id_rsa"), &cwd(), &home());
        assert_eq!(n.requested, PathBuf::from("/Users/me/.ssh/id_rsa"));
    }

    #[test]
    fn non_utf8_segments_survive_normalization() {
        let raw = OsStr::from_bytes(b"/a/\xff\xfe/../b");
        let out = lexical_clean(Path::new(raw));
        assert_eq!(out, PathBuf::from("/a/b"));
    }

    #[test]
    fn symlink_to_secret_dir_is_resolved() {
        let s = Scratch::new("symlink");
        let secret = s.path().join("dot-ssh");
        fs::create_dir(&secret).unwrap();
        fs::write(secret.join("id_rsa"), b"key").unwrap();

        let link = s.path().join("link");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let n = normalize(&link.join("id_rsa"), &cwd(), &home());
        assert_eq!(n.requested, link.join("id_rsa"));
        assert_eq!(n.resolved, secret.join("id_rsa"));
        assert!(
            n.diverges(),
            "심볼릭 링크 우회가 요청·해소 경로 불일치로 드러나야 함"
        );
    }

    #[test]
    fn intermediate_segment_symlink_is_resolved() {
        let s = Scratch::new("mid-symlink");
        let real = s.path().join("real");
        fs::create_dir_all(real.join("deep")).unwrap();
        fs::write(real.join("deep/secret"), b"x").unwrap();

        let link = s.path().join("alias");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let n = normalize(&link.join("deep/secret"), &cwd(), &home());
        assert_eq!(n.resolved, real.join("deep/secret"));
    }

    #[test]
    fn dot_dot_after_symlink_follows_the_link_target() {
        let s = Scratch::new("link-dotdot");
        fs::create_dir_all(s.path().join("target/inner")).unwrap();
        std::os::unix::fs::symlink(s.path().join("target/inner"), s.path().join("link")).unwrap();

        let n = normalize(&s.path().join("link/../escaped"), &cwd(), &home());
        assert_eq!(n.requested, s.path().join("escaped"));
        assert_eq!(
            n.resolved,
            s.path().join("target/escaped"),
            "커널은 link를 먼저 해석한 뒤 ..를 적용함. 어휘적 정리를 먼저 하면 다른 경로를 판정하게 됨"
        );
        assert!(n.diverges());
    }

    #[test]
    fn nonexistent_tail_resolves_longest_existing_prefix() {
        let s = Scratch::new("nonexistent");
        let real = s.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = s.path().join("alias");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let n = normalize(&link.join("a/b/c.txt"), &cwd(), &home());
        assert_eq!(n.resolved, real.join("a/b/c.txt"));
    }

    #[test]
    fn dot_dot_through_nonexistent_segment_is_cleaned() {
        let n = normalize(
            Path::new("/Users/me/.ssh/nonexistent/../id_rsa"),
            &cwd(),
            &home(),
        );
        assert_eq!(n.requested, PathBuf::from("/Users/me/.ssh/id_rsa"));
    }

    #[test]
    fn dot_dot_in_a_nonexistent_tail_still_resolves_the_existing_prefix() {
        let s = Scratch::new("dotdot-tail");
        let real = s.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = s.path().join("alias");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // alias는 존재하고 없는것은 없습니다. 접두 해소를 포기하면 alias가 링크임을 놓칩니다
        let n = normalize(&link.join("없는것/../target"), &cwd(), &home());
        assert_eq!(
            n.resolved,
            real.join("target"),
            "꼬리에 ..가 있어도 존재하는 접두의 심볼릭 링크는 해소되어야 함"
        );
    }

    #[test]
    fn identical_paths_do_not_diverge() {
        let s = Scratch::new("identity");
        fs::write(s.path().join("f"), b"x").unwrap();
        let n = normalize(&s.path().join("f"), &cwd(), &home());
        assert!(!n.diverges());
    }

    #[test]
    fn relative_link_target_is_resolved_against_the_resolved_parent() {
        let s = Scratch::new("rel-link");
        let outside = s.path().join("outside");
        fs::create_dir_all(outside.join("dir")).unwrap();
        fs::write(outside.join("id_rsa"), b"key").unwrap();
        std::os::unix::fs::symlink("../id_rsa", outside.join("dir/x")).unwrap();
        let ws = s.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        std::os::unix::fs::symlink(outside.join("dir"), ws.join("dir")).unwrap();

        let n = normalize(&ws.join("dir/x"), &cwd(), &home());
        assert_eq!(n.requested, ws.join("dir/x"));
        assert_eq!(
            n.resolved,
            outside.join("id_rsa"),
            "커널은 ws/dir 를 outside/dir 로 해소한 뒤 ../id_rsa 를 붙임. 어휘적 부모에 붙이면 ws/id_rsa 가 됨"
        );
    }

    #[test]
    fn dangling_relative_link_is_resolved_against_the_resolved_parent() {
        let s = Scratch::new("rel-dangling");
        let outside = s.path().join("outside");
        fs::create_dir_all(outside.join("dir")).unwrap();
        std::os::unix::fs::symlink("../id_rsa", outside.join("dir/x")).unwrap();
        let ws = s.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        std::os::unix::fs::symlink(outside.join("dir"), ws.join("dir")).unwrap();

        let n = normalize(&ws.join("dir/x"), &cwd(), &home());
        assert_eq!(
            n.resolved,
            outside.join("id_rsa"),
            "대상이 아직 없어도 해소된 부모 기준이어야 함"
        );
    }

    #[test]
    fn dangling_link_chain_keeps_the_resolved_parent_at_every_hop() {
        let s = Scratch::new("rel-chain");
        let ws = s.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        std::os::unix::fs::symlink("b", ws.join("a")).unwrap();
        std::os::unix::fs::symlink("../outside/c", ws.join("b")).unwrap();

        let n = normalize(&ws.join("a"), &cwd(), &home());
        assert_eq!(n.resolved, s.path().join("outside/c"));
    }

    #[test]
    fn dangling_link_below_a_missing_tail_is_appended_lexically() {
        let s = Scratch::new("rel-tail");
        let ws = s.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        std::os::unix::fs::symlink("../elsewhere", ws.join("dir")).unwrap();

        let n = normalize(&ws.join("dir/sub/../f"), &cwd(), &home());
        assert_eq!(n.resolved, s.path().join("elsewhere/f"));
    }

    #[test]
    fn symlink_loops_terminate() {
        let s = Scratch::new("loop");
        std::os::unix::fs::symlink("b", s.path().join("a")).unwrap();
        std::os::unix::fs::symlink("a", s.path().join("b")).unwrap();

        let n = normalize(&s.path().join("a/x"), &cwd(), &home());
        assert!(n.resolved.starts_with(s.path()));
    }

    #[test]
    fn firmlink_table_ignores_malformed_lines() {
        let src = "\
# comment
/Users\tUsers

/private\tprivate\r
no-tab-here
/three\tcolumns\there
/dots\tUsers/../etc
/dot\t./Users
/nul\tUs\0ers
/empty\t
\tUsers
/Users\tUsers
/usr/local\tusr/local
";
        let table = firmlink::parse_table(src);
        let names: Vec<String> = table
            .iter()
            .map(|f| String::from_utf8_lossy(&f.data.concat()).into_owned())
            .collect();
        assert_eq!(names, vec!["Users", "private", "usrlocal"]);
        assert_eq!(table[2].root, vec![b"usr".to_vec(), b"local".to_vec()]);
    }

    #[test]
    fn firmlink_table_rejects_entries_with_the_wrong_absoluteness() {
        assert!(
            firmlink::parse_entry("Users", "Users").is_none(),
            "루트는 절대 경로여야 함"
        );
        assert!(
            firmlink::parse_entry("/Users", "/Users").is_none(),
            "Data 열은 상대 경로여야 함"
        );
        assert!(
            firmlink::parse_entry("/", "Users").is_none(),
            "루트가 / 이면 접기가 무의미함"
        );
        assert!(
            firmlink::parse_entry("/System/Volumes/Data/Users", "Users").is_none(),
            "루트가 Data 볼륨 아래이면 접기가 되돌아감"
        );
        assert!(firmlink::parse_entry("/Users", "Users").is_some());
        assert!(firmlink::parse_entry(" /Users ", " Users ").is_some());
    }

    #[test]
    fn builtin_firmlink_table_is_valid_and_covers_home() {
        let table = firmlink::builtin();
        assert!(table.len() >= 19);
        assert!(table.iter().any(|f| f.data == vec![b"Users".to_vec()]));
        assert!(table.iter().any(|f| f.data == vec![b"private".to_vec()]));
    }

    fn sample_table() -> Vec<firmlink::Firmlink> {
        firmlink::parse_table("/Users\tUsers\n/usr/local\tusr/local\n/alias\tdata/real\n")
    }

    #[test]
    fn firmlink_fold_rewrites_only_listed_targets() {
        let t = sample_table();
        assert_eq!(
            firmlink::fold(Path::new("/System/Volumes/Data/Users/me/.ssh/id_rsa"), &t),
            PathBuf::from("/Users/me/.ssh/id_rsa")
        );
        assert_eq!(
            firmlink::fold(Path::new("/System/Volumes/Data/Users"), &t),
            PathBuf::from("/Users")
        );
        assert_eq!(
            firmlink::fold(Path::new("/System/Volumes/Data/Usersx/me"), &t),
            PathBuf::from("/System/Volumes/Data/Usersx/me"),
            "세그먼트 경계를 지켜야 함"
        );
        assert_eq!(
            firmlink::fold(Path::new("/System/Volumes/Data/etc/shadow"), &t),
            PathBuf::from("/System/Volumes/Data/etc/shadow"),
            "표에 없는 대상은 그대로"
        );
        assert_eq!(
            firmlink::fold(Path::new("/System/Volumes/Data"), &t),
            PathBuf::from("/System/Volumes/Data")
        );
        assert_eq!(
            firmlink::fold(Path::new("/Users/me/.ssh/id_rsa"), &t),
            PathBuf::from("/Users/me/.ssh/id_rsa")
        );
        assert_eq!(
            firmlink::fold(Path::new("/System/Volumes/Data/data/real/x"), &t),
            PathBuf::from("/alias/x"),
            "루트 열과 Data 열이 다르면 표대로 옮겨야 함"
        );
    }

    #[test]
    fn firmlink_fold_prefers_the_longest_target_and_ignores_ascii_case() {
        let t = firmlink::parse_table("/usr\tusr\n/usr/local\tusr/local\n");
        assert_eq!(
            firmlink::fold(Path::new("/System/Volumes/Data/usr/local/bin/x"), &t),
            PathBuf::from("/usr/local/bin/x")
        );
        assert_eq!(
            firmlink::fold(Path::new("/system/volumes/data/USR/Local/bin/x"), &t),
            PathBuf::from("/usr/local/bin/x")
        );
        assert_eq!(
            firmlink::fold(Path::new("/System/Volumes/Data/usr/bin/x"), &t),
            PathBuf::from("/usr/bin/x")
        );
    }

    #[test]
    fn firmlink_fold_leaves_dot_segments_alone() {
        let t = sample_table();
        assert_eq!(
            firmlink::fold(Path::new("/System/Volumes/Data/Users/../etc"), &t),
            PathBuf::from("/System/Volumes/Data/Users/../etc"),
            "접기는 어휘적 정리 뒤에 오므로 .. 가 남은 경로는 건드리지 않음"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn data_volume_spelling_of_home_is_folded_on_macos() {
        assert_eq!(
            fold_firmlink(Path::new("/System/Volumes/Data/Users/me/.ssh/id_rsa")),
            PathBuf::from("/Users/me/.ssh/id_rsa")
        );
        assert_eq!(
            fold_firmlink(Path::new("/System/Volumes/Data/private/etc/sudoers")),
            PathBuf::from("/private/etc/sudoers")
        );
        let n = normalize(
            Path::new("/System/Volumes/Data/Users/me/.ssh/id_rsa"),
            &cwd(),
            &home(),
        );
        assert_eq!(n.requested, PathBuf::from("/Users/me/.ssh/id_rsa"));
        assert_eq!(n.resolved, PathBuf::from("/Users/me/.ssh/id_rsa"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn fold_is_identity_off_macos() {
        let p = Path::new("/System/Volumes/Data/Users/me/.ssh/id_rsa");
        assert_eq!(fold_firmlink(p), p.to_path_buf());
    }
}
