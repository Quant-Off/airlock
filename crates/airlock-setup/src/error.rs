use std::fmt;

use airlock_i18n::tr;

#[derive(Debug)]
pub enum SetupError {
    NoTty,
    UnknownPreset(String),
    Io(std::io::Error),
    Toml(toml_edit::TomlError),
    Policy(airlock_policy::LoadError),
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTty => f.write_str(tr!(
                "대화형 터미널(TTY)에서만 실행할 수 있음",
                "can only run on an interactive terminal (TTY)"
            )),
            Self::UnknownPreset(id) => write!(
                f,
                "{}",
                tr!(
                    format!("알 수 없는 프리셋: {id}"),
                    format!("unknown preset: {id}")
                )
            ),
            Self::Io(e) => write!(
                f,
                "{}",
                tr!(format!("입출력 오류: {e}"), format!("I/O error: {e}"))
            ),
            Self::Toml(e) => write!(
                f,
                "{}",
                tr!(
                    format!("프리셋 TOML 오류: {e}"),
                    format!("preset TOML error: {e}")
                )
            ),
            Self::Policy(e) => write!(
                f,
                "{}",
                tr!(
                    format!("정책 검증 실패: {e}"),
                    format!("policy validation failed: {e}")
                )
            ),
        }
    }
}

impl std::error::Error for SetupError {}

impl From<std::io::Error> for SetupError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<toml_edit::TomlError> for SetupError {
    fn from(e: toml_edit::TomlError) -> Self {
        Self::Toml(e)
    }
}

impl From<airlock_policy::LoadError> for SetupError {
    fn from(e: airlock_policy::LoadError) -> Self {
        Self::Policy(e)
    }
}
