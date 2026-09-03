use std::fmt;
use std::path::PathBuf;

use airlock_i18n::tr;

#[derive(Debug)]
pub enum Error {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json(serde_json::Error),
    SessionDirExists(PathBuf),
    ChainMissing(PathBuf),
    AnchorChainBroken {
        path: PathBuf,
        detail: String,
    },
    ReviewChainBroken {
        path: PathBuf,
        detail: String,
    },
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
            Self::Io { path, source } => write!(
                f,
                "{}",
                tr!(
                    format!("{} 입출력 실패: {source}", path.display()),
                    format!("I/O failure on {}: {source}", path.display())
                )
            ),
            Self::Json(e) => write!(
                f,
                "{}",
                tr!(
                    format!("JSON 직렬화 실패: {e}"),
                    format!("JSON serialization failure: {e}")
                )
            ),
            Self::SessionDirExists(p) => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "{} 이미 존재함. 기존 체인에 이어 붙이는 것은 허용하지 않음",
                        p.display()
                    ),
                    format!(
                        "{} already exists; appending to an existing chain is not allowed",
                        p.display()
                    )
                )
            ),
            Self::ChainMissing(p) => write!(
                f,
                "{}",
                tr!(
                    format!("{}에 chain.jsonl이 없음", p.display()),
                    format!("no chain.jsonl in {}", p.display())
                )
            ),
            Self::AnchorChainBroken { path, detail } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "{} 앵커 체인이 이미 깨져 있음: {detail}. 깨진 체인 위에 이어 붙이면 그 뒤쪽이 정당해 보임",
                        path.display()
                    ),
                    format!(
                        "the anchor chain at {} is already broken: {detail}; appending on top of a broken chain makes what follows look legitimate",
                        path.display()
                    )
                )
            ),
            Self::ReviewChainBroken { path, detail } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "{} 확인 체인이 이미 깨져 있음: {detail}. 깨진 체인 위에 이어 붙이면 그 뒤쪽이 정당해 보임",
                        path.display()
                    ),
                    format!(
                        "the review chain at {} is already broken: {detail}; appending on top of a broken chain makes what follows look legitimate",
                        path.display()
                    )
                )
            ),
            Self::SeqOverflow => {
                f.write_str(tr!("seq가 u64 범위를 넘음", "seq exceeds the u64 range"))
            }
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
