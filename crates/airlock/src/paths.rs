use std::path::{Path, PathBuf};

use airlock_policy::path::home_dir;

pub const POLICY_FILE_NAMES: &[&str] = &["airlock.toml", ".airlock.toml"];

pub fn audit_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("AIRLOCK_AUDIT_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(dir);
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(xdg).join("airlock");
    }
    home_dir().join(".local/share/airlock")
}

pub fn session_dir(root: &Path) -> PathBuf {
    let nanos = airlock_audit::now_unix_nanos();
    root.join("sessions")
        .join(format!("{nanos}-{}", std::process::id()))
}

pub fn discover_policy(explicit: Option<&Path>, cwd: &Path) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    for name in POLICY_FILE_NAMES {
        let candidate = cwd.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let user = home_dir().join(".config/airlock/policy.toml");
    if user.is_file() {
        return Some(user);
    }
    None
}

pub fn latest_session(root: &Path) -> Option<PathBuf> {
    let sessions = root.join("sessions");
    let mut best: Option<(String, PathBuf)> = None;
    for entry in std::fs::read_dir(&sessions).ok()? {
        let Ok(entry) = entry else { continue };
        if !entry.path().join(airlock_audit::CHAIN_FILE).is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let replace = match &best {
            None => true,
            Some((current, _)) => sort_key(&name) > sort_key(current),
        };
        if replace {
            best = Some((name, entry.path()));
        }
    }
    best.map(|(_, p)| p)
}

fn sort_key(name: &str) -> (u128, String) {
    let nanos = name
        .split('-')
        .next()
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(0);
    (nanos, name.to_string())
}

pub fn all_sessions(root: &Path) -> Vec<PathBuf> {
    let sessions = root.join("sessions");
    let Ok(dir) = std::fs::read_dir(&sessions) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = dir
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.join(airlock_audit::CHAIN_FILE).is_file())
        .collect();
    out.sort_by_key(|p| sort_key(&p.file_name().unwrap_or_default().to_string_lossy()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_dirs_sort_by_timestamp_not_lexically() {
        let a = sort_key("900-1");
        let b = sort_key("1000-1");
        assert!(b > a, "숫자 정렬이어야 함");
    }

    #[test]
    fn policy_discovery_prefers_explicit() {
        let explicit = PathBuf::from("/tmp/explicit.toml");
        assert_eq!(
            discover_policy(Some(&explicit), Path::new("/tmp")),
            Some(explicit)
        );
    }

    #[test]
    fn session_dir_is_under_sessions() {
        let d = session_dir(Path::new("/tmp/root"));
        assert!(d.starts_with("/tmp/root/sessions"));
    }
}
