use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum BrokerError {
    Audit(airlock_audit::Error),
    Policy(airlock_policy::LoadError),
    Io {
        what: String,
        source: std::io::Error,
    },
    ProgramNotFound(String),
    Blocked {
        what: String,
        rule: Option<String>,
        reason: Option<String>,
    },
    EnforcerUnavailable {
        name: &'static str,
        why: String,
    },
    ProfileNotRepresentable(Vec<String>),
    NoControlTerminal,
    InvalidPath(PathBuf),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audit(e) => write!(f, "감사 로그 실패: {e}"),
            Self::Policy(e) => write!(f, "정책 로드 실패: {e}"),
            Self::Io { what, source } => write!(f, "{what}: {source}"),
            Self::ProgramNotFound(p) => write!(f, "실행할 프로그램을 찾을 수 없음: {p}"),
            Self::Blocked { what, rule, reason } => {
                write!(f, "{what}이(가) 정책에 의해 차단됨")?;
                if let Some(r) = rule {
                    write!(f, " (규칙 {r})")?;
                }
                if let Some(r) = reason {
                    write!(f, ": {r}")?;
                }
                Ok(())
            }
            Self::EnforcerUnavailable { name, why } => {
                write!(f, "{name} 강제 백엔드를 쓸 수 없음: {why}")
            }
            Self::ProfileNotRepresentable(items) => write!(
                f,
                "강제 프로파일로 표현할 수 없는 규칙이 있음: {}",
                items.join(", ")
            ),
            Self::NoControlTerminal => write!(
                f,
                "/dev/tty를 열 수 없어 승인을 받을 수 없음. ask 결정은 거부로 처리됨"
            ),
            Self::InvalidPath(p) => write!(f, "경로를 다룰 수 없음: {}", p.display()),
        }
    }
}

impl std::error::Error for BrokerError {}

impl From<airlock_audit::Error> for BrokerError {
    fn from(e: airlock_audit::Error) -> Self {
        Self::Audit(e)
    }
}

impl From<airlock_policy::LoadError> for BrokerError {
    fn from(e: airlock_policy::LoadError) -> Self {
        Self::Policy(e)
    }
}

pub type Result<T> = std::result::Result<T, BrokerError>;
