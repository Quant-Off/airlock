use std::path::{Path, PathBuf};

use airlock_policy::path::home_dir;

pub const POLICY_FILE_NAMES: &[&str] = &["airlock.toml", ".airlock.toml"];

/// 상대 경로를 cwd 기준 절대 경로로 바꿉니다.
///
/// 자기보호 규칙과 커널 프로파일은 절대 경로만 다룹니다. 상대 경로가 그대로 흘러가면
/// `airlock.toml`이 `/airlock.toml`이 되어 아무것도 보호하지 못하고, SBPL `subpath`는
/// 절대 경로가 아닌 값을 받지 못합니다.
///
/// # Arguments
/// `path` - 절대화할 경로
/// `cwd` - 기준이 되는 현재 디렉토리
pub fn absolutize(path: &Path, cwd: &Path) -> PathBuf {
    // 존재하면 심볼릭 링크와 . .. 까지 해소합니다. 존재하지 않아도 절대 경로는 보장합니다
    let joined = absolutize_lexical(path, cwd);
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// 심볼릭 링크를 해소하지 않고 절대 경로로만 만듭니다.
///
/// 정책 파일을 열 때 씁니다. 미리 해소해 버리면 `O_NOFOLLOW`가 볼 링크가 남지 않아
/// 링크 검사가 무의미해집니다.
///
/// # Arguments
/// `path` - 절대화할 경로
/// `cwd` - 기준이 되는 현재 디렉토리
pub fn absolutize_lexical(path: &Path, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

/// 자기보호로 막아야 할 경로의 모든 표기를 모읍니다.
///
/// 어휘적 절대 경로와 해소된 경로를 모두 넣습니다. macOS는 `/tmp`가 `/private/tmp`로 가는
/// firmlink이므로 한쪽만 막으면 다른 쪽 표기로 그대로 지나갑니다.
///
/// # Arguments
/// `path` - 막을 경로
/// `cwd` - 기준이 되는 현재 디렉토리
pub fn protect_forms(path: &Path, cwd: &Path) -> Vec<PathBuf> {
    let lexical = absolutize_lexical(path, cwd);
    let canonical = std::fs::canonicalize(&lexical).unwrap_or_else(|_| lexical.clone());
    if canonical == lexical {
        vec![lexical]
    } else {
        vec![lexical, canonical]
    }
}

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

/// 정책 파일 탐색 후보를 순서대로 돌려줍니다.
///
/// 존재 여부를 보지 않습니다. 자기보호는 아직 비어 있는 후보까지 막아야 하기 때문입니다.
/// 비어 있는 자리에 대상이 정책을 만들어 두면 다음 실행이 그것을 읽습니다.
///
/// # Arguments
/// `cwd` - 현재 디렉토리
pub fn policy_candidates(cwd: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = POLICY_FILE_NAMES.iter().map(|n| cwd.join(n)).collect();
    out.push(home_dir().join(".config/airlock/policy.toml"));
    out
}

pub fn discover_policy(explicit: Option<&Path>, cwd: &Path) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    policy_candidates(cwd).into_iter().find(|c| c.is_file())
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
