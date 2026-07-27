use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

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

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
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

fn resolve_symlinks(absolute: &Path) -> PathBuf {
    if let Ok(p) = std::fs::canonicalize(absolute) {
        return p;
    }
    // 존재하지 않는 경로는 존재하는 최장 접두를 해소하고 나머지를 어휘적으로 붙입니다.
    // 꼬리에 `..`가 섞여 있어도 접두 해소를 포기하지 않아야 합니다. 포기하면
    // `link/없는것/../x`에서 link가 해소되지 않아 커널과 다른 경로를 판정합니다 (4절)
    let mut suffix: Vec<OsString> = Vec::new();
    let mut cur: &Path = absolute;
    while let Some(parent) = cur.parent() {
        let name = cur
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_else(|| OsString::from(".."));
        suffix.push(name);
        if let Ok(base) = std::fs::canonicalize(parent) {
            let mut out = base;
            for n in suffix.iter().rev() {
                out.push(n);
            }
            return out;
        }
        if parent == cur {
            break;
        }
        cur = parent;
    }
    absolute.to_path_buf()
}

pub fn normalize(raw: &Path, cwd: &Path, home: &Path) -> NormalizedPath {
    let expanded = expand_tilde(raw, home);
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        let mut p = cwd.to_path_buf();
        p.push(expanded);
        p
    };
    let requested = lexical_clean(&absolute);
    let resolved = lexical_clean(&resolve_symlinks(&absolute));
    NormalizedPath {
        requested,
        resolved,
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
}
