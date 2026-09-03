use std::fmt;
use std::path::PathBuf;

use airlock_i18n::tr;

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
    /// 이미 닫힌 세션에 엔트리를 붙이려 했습니다.
    ///
    /// `SessionEnd` 뒤에 자란 체인은 앵커보다 앞서 나가서 "종료 후 덧붙이기" 로 보고됩니다.
    /// 늦게 도착한 사실 하나를 남기려다 세션 전체의 무결성 보고를 깨뜨리지 않습니다
    SessionClosed,
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audit(e) => write!(
                f,
                "{}",
                tr!(
                    format!("감사 로그 실패: {e}"),
                    format!("audit log failure: {e}")
                )
            ),
            Self::Policy(e) => write!(
                f,
                "{}",
                tr!(
                    format!("정책 로드 실패: {e}"),
                    format!("policy load failure: {e}")
                )
            ),
            Self::Io { what, source } => write!(f, "{what}: {source}"),
            Self::ProgramNotFound(p) => write!(
                f,
                "{}",
                tr!(
                    format!("실행할 프로그램을 찾을 수 없음: {p}"),
                    format!("cannot find the program to run: {p}")
                )
            ),
            Self::Blocked { what, rule, reason } => {
                write!(
                    f,
                    "{}",
                    tr!(
                        format!("{what}이(가) 정책에 의해 차단됨"),
                        format!("{what} was blocked by policy")
                    )
                )?;
                if let Some(r) = rule {
                    write!(f, "{}", tr!(format!(" (규칙 {r})"), format!(" (rule {r})")))?;
                }
                if let Some(r) = reason {
                    write!(f, ": {r}")?;
                }
                Ok(())
            }
            Self::EnforcerUnavailable { name, why } => {
                write!(
                    f,
                    "{}",
                    tr!(
                        format!("{name} 강제 백엔드를 쓸 수 없음: {why}"),
                        format!("the {name} enforcement backend is unavailable: {why}")
                    )
                )
            }
            Self::ProfileNotRepresentable(items) => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "강제 프로파일로 표현할 수 없는 규칙이 있음: {}",
                        items.join(", ")
                    ),
                    format!(
                        "rules that cannot be expressed in the enforcement profile: {}",
                        items.join(", ")
                    )
                )
            ),
            Self::NoControlTerminal => write!(
                f,
                "{}",
                tr!(
                    "/dev/tty를 열 수 없어 승인을 받을 수 없음. ask 결정은 거부로 처리됨",
                    "cannot open /dev/tty to obtain approval; ask decisions are treated as refusals"
                )
            ),
            Self::InvalidPath(p) => write!(
                f,
                "{}",
                tr!(
                    format!("경로를 다룰 수 없음: {}", p.display()),
                    format!("cannot handle the path: {}", p.display())
                )
            ),
            Self::SessionClosed => write!(
                f,
                "{}",
                tr!(
                    "세션이 이미 닫힘. session_end 뒤에 엔트리를 붙이면 앵커보다 체인이 길어져 \
                     종료 후 덧붙이기로 보고됨",
                    "the session is already closed; an entry appended after session_end makes \
                     the chain longer than the anchor and is reported as appending after close"
                )
            ),
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
