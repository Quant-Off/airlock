use std::fmt;

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
            Self::NoTty => write!(f, "대화형 터미널(TTY)에서만 실행할 수 있음"),
            Self::UnknownPreset(id) => write!(f, "알 수 없는 프리셋: {id}"),
            Self::Io(e) => write!(f, "입출력 오류: {e}"),
            Self::Toml(e) => write!(f, "프리셋 TOML 오류: {e}"),
            Self::Policy(e) => write!(f, "정책 검증 실패: {e}"),
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
