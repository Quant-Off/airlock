use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json(serde_json::Error),
    SessionDirExists(PathBuf),
    ChainMissing(PathBuf),
    SeqOverflow,
}

impl Error {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{} 입출력 실패: {source}", path.display()),
            Self::Json(e) => write!(f, "JSON 직렬화 실패: {e}"),
            Self::SessionDirExists(p) => write!(
                f,
                "{} 이미 존재함. 기존 체인에 이어 붙이는 것은 허용하지 않음",
                p.display()
            ),
            Self::ChainMissing(p) => write!(f, "{}에 chain.jsonl이 없음", p.display()),
            Self::SeqOverflow => write!(f, "seq가 u64 범위를 넘음"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
