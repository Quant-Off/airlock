//! 이 모듈은 airlock 출력의 로케일을 결정하고 메시지 쌍에서 하나를 고릅니다.
//!
//! # Features
//! 로케일은 표시 계층만 바꿉니다. 감사 로그의 기계 판독 필드(kind, status, verdict)와
//! 정책 다이제스트는 로케일과 무관하게 고정입니다. 그래서 로케일은 정책 파일이 아니라
//! 별도 구성 파일(`~/.config/airlock/config.toml`)에 둡니다. 정책 다이제스트가 표시
//! 언어 때문에 달라지면 감사 로그에 소음이 생깁니다.
//!
//! 결정 순서는 `AIRLOCK_LANG` 환경 변수, 구성 파일의 `locale` 키,
//! `LC_ALL`/`LC_MESSAGES`/`LANG` 접두 감지, 기본값 한국어입니다. 값을 읽지 못하면
//! 조용히 다음 순서로 내려갑니다. 로케일은 표시 전용이라 실패가 보안 판정을 바꾸지
//! 않습니다.
//!
//! # Examples
//! ```rust,ignore
//! airlock_i18n::init();
//! let msg = airlock_i18n::tr!("정책 검증 통과", "policy verified");
//! ```

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};

/// 출력 언어.
///
/// 기본값은 한국어입니다. 이 프로젝트의 원문 언어이며, 어떤 환경 신호도 없을 때
/// 기존 동작이 그대로 유지되어야 합니다
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Locale {
    #[default]
    Ko,
    En,
}

impl Locale {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ko => "ko",
            Self::En => "en",
        }
    }

    /// 로케일 문자열을 읽습니다.
    ///
    /// `ko`, `en` 과 `ko_KR.UTF-8` 같은 POSIX 로케일 표기의 접두를 받습니다. 모르는
    /// 값은 `None` 이며 호출부가 다음 결정 순서로 내려갑니다
    ///
    /// # Arguments
    /// `s` - 로케일 문자열
    pub fn parse(s: &str) -> Option<Self> {
        let t = s.trim().to_ascii_lowercase();
        let prefix = t.split(['_', '-', '.', '@']).next().unwrap_or_default();
        match prefix {
            "ko" => Some(Self::Ko),
            "en" => Some(Self::En),
            _ => None,
        }
    }
}

static LOCALE: AtomicU8 = AtomicU8::new(0);

pub fn locale() -> Locale {
    if LOCALE.load(Ordering::Relaxed) == 1 {
        Locale::En
    } else {
        Locale::Ko
    }
}

pub fn set_locale(l: Locale) {
    let v = match l {
        Locale::Ko => 0,
        Locale::En => 1,
    };
    LOCALE.store(v, Ordering::Relaxed);
}

/// 두 언어 메시지에서 현재 로케일의 것을 고릅니다.
///
/// 첫 인자가 한국어, 둘째가 영문입니다. 포맷이 필요하면 각 인자를 `format!` 으로
/// 감쌉니다. 선택된 쪽만 평가됩니다
///
/// # Examples
/// ```rust,ignore
/// tr!("정책 검증 통과", "policy verified");
/// tr!(format!("{n}개 세션", n = 3), format!("{n} sessions", n = 3));
/// ```
#[macro_export]
macro_rules! tr {
    ($ko:expr, $en:expr $(,)?) => {
        match $crate::locale() {
            $crate::Locale::Ko => $ko,
            $crate::Locale::En => $en,
        }
    };
}

/// 로케일 구성 파일 경로.
///
/// `XDG_CONFIG_HOME` 이 절대 경로면 그 아래, 아니면 `~/.config/airlock/config.toml`
/// 입니다. `HOME` 이 없거나 절대 경로가 아니면 `None` 입니다. 상대 경로 홈을 받으면
/// 실행 위치에 따라 다른 파일을 읽게 되므로 받지 않습니다
pub fn config_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(xdg);
        if p.is_absolute() {
            return Some(p.join("airlock/config.toml"));
        }
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    if !home.is_absolute() {
        return None;
    }
    Some(home.join(".config/airlock/config.toml"))
}

/// 환경과 구성 텍스트만으로 로케일을 정합니다.
///
/// 파일과 전역 상태를 건드리지 않아 테스트에서 결정 순서를 고정할 수 있습니다
///
/// # Arguments
/// `env` - 환경 변수 조회
/// `config` - 구성 파일 내용. 없으면 `None`
pub fn resolve(env: impl Fn(&str) -> Option<String>, config: Option<&str>) -> Locale {
    if let Some(l) = env("AIRLOCK_LANG").as_deref().and_then(Locale::parse) {
        return l;
    }
    if let Some(l) = config.and_then(locale_from_config) {
        return l;
    }
    for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Some(l) = env(key).as_deref().and_then(Locale::parse) {
            return l;
        }
    }
    Locale::default()
}

/// 구성 텍스트의 최상위 `locale` 키를 읽습니다.
///
/// TOML 파서를 쓰지 않습니다. 이 크레이트는 브로커와 정책 엔진의 의존성 트리에
/// 들어가므로 의존을 하나도 두지 않습니다 (`docs/setup-wizard.md` 의 UI 의존성 경계).
/// 읽는 것이 짧은 문자열 하나뿐이라 최소 스캐너로 충분합니다.
///
/// 첫 테이블 머리에서 멈춥니다. 테이블 안의 `locale` 은 최상위 키가 아니므로 읽으면
/// 안 됩니다. 따옴표 없는 값은 받지 않습니다. 모르는 것을 추측하는 것보다 다음 결정
/// 순서로 내려가는 쪽이 낫습니다
///
/// # Arguments
/// `text` - 구성 파일 내용
fn locale_from_config(text: &str) -> Option<Locale> {
    for line in text.lines() {
        let t = line.trim_start();
        if t.starts_with('[') {
            break;
        }
        if let Some(raw) = t.strip_prefix("locale") {
            let rest = raw.trim_start();
            if let Some(value) = rest.strip_prefix('=') {
                return quoted(value).and_then(Locale::parse);
            }
        }
    }
    None
}

/// 큰따옴표로 감싼 값의 알맹이.
///
/// # Arguments
/// `raw` - `=` 뒤의 나머지
fn quoted(raw: &str) -> Option<&str> {
    let rest = raw.trim_start().strip_prefix('"')?;
    let end = rest.find('"')?;
    rest.get(..end)
}

/// 구성 텍스트에서 `locale` 줄만 바꾸거나 새로 넣습니다.
///
/// 다른 줄은 한 바이트도 건드리지 않습니다. 전체를 파싱해 다시 쓰면 사람이 적어 둔
/// 주석과 배치가 바뀌고, 파서가 이해하지 못하는 파일을 통째로 잃습니다.
///
/// 최상위 `locale` 줄이 없으면 첫 테이블 머리 **앞**에 넣습니다. 끝에 붙이면 그 키가
/// 마지막 테이블 안으로 들어가 최상위 키가 아니게 됩니다
///
/// # Arguments
/// `text` - 기존 구성 파일 내용. 파일이 없으면 빈 문자열
/// `l` - 저장할 로케일
fn rewrite_locale(text: &str, l: Locale) -> String {
    let entry = format!("locale = \"{}\"", l.as_str());
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();

    let mut table_at = None;
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if t.starts_with('[') {
            table_at = Some(i);
            break;
        }
        if let Some(raw) = t.strip_prefix("locale")
            && raw.trim_start().starts_with('=')
        {
            lines[i] = entry;
            return join(&lines);
        }
    }

    match table_at {
        Some(i) => lines.insert(i, entry),
        None => lines.push(entry),
    }
    join(&lines)
}

fn join(lines: &[String]) -> String {
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// 실제 환경에서 로케일을 정합니다.
pub fn detect() -> Locale {
    let config = config_path().and_then(|p| std::fs::read_to_string(p).ok());
    resolve(
        |key| std::env::var(key).ok().filter(|v| !v.is_empty()),
        config.as_deref(),
    )
}

/// 프로세스 시작 시 한 번 부릅니다. 이후 출력이 감지된 로케일을 따릅니다
pub fn init() {
    set_locale(detect());
}

/// 로케일을 구성 파일에 남깁니다.
///
/// `locale` 줄 하나만 바꾸거나 넣고 나머지 줄은 그대로 둡니다. 주석과 다른 키가 보존되며,
/// 이 크레이트가 이해하지 못하는 내용이 있어도 잃지 않습니다
///
/// # Arguments
/// `l` - 저장할 로케일
///
/// # Errors
/// 홈을 알 수 없거나 읽기와 쓰기가 실패하면 그 사유를 냅니다
pub fn save_locale(l: Locale) -> std::io::Result<PathBuf> {
    let path = config_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            tr!(
                "HOME이 비어 있거나 절대 경로가 아니라 구성 파일 위치를 정할 수 없음",
                "cannot locate the config file because HOME is empty or not absolute"
            ),
        )
    })?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, rewrite_locale(&existing, l))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn parse_accepts_posix_locale_forms() {
        assert_eq!(Locale::parse("ko"), Some(Locale::Ko));
        assert_eq!(Locale::parse("en"), Some(Locale::En));
        assert_eq!(Locale::parse("ko_KR.UTF-8"), Some(Locale::Ko));
        assert_eq!(Locale::parse("en_US.UTF-8"), Some(Locale::En));
        assert_eq!(Locale::parse("en-GB"), Some(Locale::En));
        assert_eq!(Locale::parse("EN"), Some(Locale::En));
    }

    #[test]
    fn unknown_locales_are_refused_not_guessed() {
        for bad in ["", "C", "POSIX", "fr_FR.UTF-8", "kor", "eng", "korean"] {
            assert_eq!(Locale::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn airlock_lang_wins_over_everything() {
        let l = resolve(
            env_of(&[("AIRLOCK_LANG", "en"), ("LANG", "ko_KR.UTF-8")]),
            Some("locale = \"ko\"\n"),
        );
        assert_eq!(l, Locale::En);
    }

    #[test]
    fn config_wins_over_system_lang() {
        let l = resolve(
            env_of(&[("LANG", "ko_KR.UTF-8")]),
            Some("locale = \"en\"\n"),
        );
        assert_eq!(l, Locale::En);
    }

    #[test]
    fn system_lang_is_the_fallback() {
        assert_eq!(
            resolve(env_of(&[("LANG", "en_US.UTF-8")]), None),
            Locale::En
        );
        assert_eq!(
            resolve(
                env_of(&[("LC_ALL", "en_US.UTF-8"), ("LANG", "ko_KR.UTF-8")]),
                None
            ),
            Locale::En
        );
    }

    #[test]
    fn the_default_is_korean() {
        assert_eq!(resolve(env_of(&[]), None), Locale::Ko);
        assert_eq!(resolve(env_of(&[("LANG", "C")]), None), Locale::Ko);
    }

    #[test]
    fn invalid_override_falls_through() {
        let l = resolve(
            env_of(&[("AIRLOCK_LANG", "fr"), ("LANG", "en_US.UTF-8")]),
            Some("locale = \"broken"),
        );
        assert_eq!(l, Locale::En);
    }

    #[test]
    fn a_locale_inside_a_table_is_not_a_top_level_key() {
        assert_eq!(locale_from_config("[other]\nlocale = \"en\"\n"), None);
        assert_eq!(
            locale_from_config("locale = \"en\"\n[other]\nlocale = \"ko\"\n"),
            Some(Locale::En)
        );
    }

    #[test]
    fn rewriting_replaces_only_the_locale_line() {
        let before = "# 사람이 적은 주석\nlocale = \"ko\"\nfuture_key = 1\n";
        let after = rewrite_locale(before, Locale::En);
        assert_eq!(
            after,
            "# 사람이 적은 주석\nlocale = \"en\"\nfuture_key = 1\n"
        );
    }

    #[test]
    fn rewriting_lands_before_the_first_table() {
        let after = rewrite_locale("future_key = 1\n\n[other]\nkey = 2\n", Locale::En);
        assert_eq!(
            after,
            "future_key = 1\n\nlocale = \"en\"\n[other]\nkey = 2\n"
        );
        assert_eq!(locale_from_config(&after), Some(Locale::En));
    }

    #[test]
    fn rewriting_an_absent_file_makes_a_single_line() {
        assert_eq!(rewrite_locale("", Locale::Ko), "locale = \"ko\"\n");
    }

    #[test]
    fn rewriting_keeps_content_it_does_not_understand() {
        let before = "not toml [\nlocale = \"ko\"\n";
        let after = rewrite_locale(before, Locale::En);
        assert!(after.contains("not toml ["), "{after}");
        assert!(after.contains("locale = \"en\""), "{after}");
    }

    #[test]
    fn config_with_other_keys_still_yields_locale() {
        assert_eq!(
            locale_from_config("# 주석\nfuture_key = 1\nlocale = \"en\"\n"),
            Some(Locale::En)
        );
        assert_eq!(locale_from_config("locale = 3\n"), None);
        assert_eq!(locale_from_config("not toml ["), None);
    }
}
