use std::fmt;
use std::path::PathBuf;

use crate::glob::PatternError;
use crate::host::HostError;
use crate::model::Kind;

#[derive(Debug)]
pub enum LoadError {
    Toml(Box<toml::de::Error>),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    UnsupportedVersion(u32),
    DuplicateId(String),
    UnknownAction {
        id: String,
        value: String,
    },
    UnknownKind {
        id: String,
        value: String,
    },
    UnknownMode {
        id: String,
        value: String,
    },
    MissingField {
        id: String,
        field: &'static str,
    },
    UnexpectedField {
        id: String,
        field: &'static str,
        kind: Kind,
    },
    EmptyModeSet {
        id: String,
    },
    Pattern {
        id: String,
        source: PatternError,
    },
    Host {
        id: String,
        source: HostError,
    },
    EgressDefaultAllow,
    ForbidDefault {
        kind: &'static str,
    },
    ForbidInUserRule {
        id: String,
    },
    EmptyOverrideTarget {
        id: String,
    },
    WildcardHostAllow {
        id: String,
    },
    UnknownOverrideTarget {
        id: String,
        target: String,
    },
    OverrideTargetNotForbid {
        id: String,
        target: String,
    },
    OverrideWithoutReason {
        id: String,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml(e) => write!(f, "TOML 파싱 실패: {e}"),
            Self::Io { path, source } => write!(f, "{} 읽기 실패: {source}", path.display()),
            Self::UnsupportedVersion(v) => {
                write!(f, "지원하지 않는 정책 version {v}. v1만 지원함")
            }
            Self::DuplicateId(id) => write!(f, "규칙 id `{id}`가 중복됨"),
            Self::UnknownAction { id, value } => write!(
                f,
                "`{id}`의 action `{value}`를 알 수 없음. allow, deny, ask, forbid 중 하나여야 함"
            ),
            Self::UnknownKind { id, value } => write!(
                f,
                "`{id}`의 kind `{value}`를 알 수 없음. file, exec, egress 중 하나여야 함"
            ),
            Self::UnknownMode { id, value } => write!(
                f,
                "`{id}`의 mode `{value}`를 알 수 없음. read, write, create, delete, metadata, exec 중 하나여야 함"
            ),
            Self::MissingField { id, field } => {
                write!(f, "`{id}`에 필수 필드 `{field}`가 없음")
            }
            Self::UnexpectedField { id, field, kind } => {
                write!(f, "`{id}`는 kind가 {kind}인데 `{field}` 필드를 가짐")
            }
            Self::EmptyModeSet { id } => {
                write!(
                    f,
                    "`{id}`의 mode가 빈 배열임. 아무것도 매칭하지 않는 규칙은 오류임"
                )
            }
            Self::Pattern { id, source } => write!(f, "`{id}` 패턴 오류: {source}"),
            Self::Host { id, source } => write!(f, "`{id}` 호스트 오류: {source}"),
            Self::EgressDefaultAllow => write!(
                f,
                "[defaults].egress는 allow가 될 수 없음. 아웃바운드 기본 허용은 데이터 반출 방어를 포기하는 설정임"
            ),
            Self::ForbidDefault { kind } => write!(
                f,
                "[defaults].{kind}는 forbid가 될 수 없음. forbid는 내장 베이스라인 전용임"
            ),
            Self::ForbidInUserRule { id } => write!(
                f,
                "`{id}`의 action이 forbid임. forbid는 내장 베이스라인 전용이며 사용자 규칙은 allow, deny, ask 중 하나를 씀"
            ),
            Self::EmptyOverrideTarget { id } => write!(
                f,
                "`{id}`의 overrides가 빈 문자열임. 완화 대상을 지목하지 않을 거면 필드를 빼야 함"
            ),
            Self::WildcardHostAllow { id } => write!(
                f,
                "`{id}`는 host = \"*\"를 allow함. 아웃바운드 전면 허용은 [defaults].egress = \"allow\"와 같으며 데이터 반출 방어를 포기하는 설정임"
            ),
            Self::UnknownOverrideTarget { id, target } => {
                write!(f, "`{id}`의 overrides 대상 `{target}`가 내장 규칙에 없음")
            }
            Self::OverrideTargetNotForbid { id, target } => {
                write!(f, "`{id}`의 overrides 대상 `{target}`는 forbid 규칙이 아님")
            }
            Self::OverrideWithoutReason { id } => write!(
                f,
                "`{id}`는 overrides를 쓰면서 reason이 비어 있음. 시크릿 보호 완화는 근거 없이 허용하지 않음"
            ),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<toml::de::Error> for LoadError {
    fn from(e: toml::de::Error) -> Self {
        Self::Toml(Box::new(e))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadWarning {
    ShadowedRule {
        id: String,
        by: String,
    },
    UnusedOverride {
        id: String,
        target: String,
    },
    HostRuleNeedsProxy {
        id: String,
    },
    IneffectiveRelaxation {
        id: String,
        forbid_id: String,
        probe: PathBuf,
    },
}

impl fmt::Display for LoadWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShadowedRule { id, by } => write!(
                f,
                "`{id}`는 앞선 규칙 `{by}`에 완전히 가려져 도달할 수 없음"
            ),
            Self::UnusedOverride { id, target } => write!(
                f,
                "`{id}`의 overrides = \"{target}\"는 실제로 아무 보호도 완화하지 않음"
            ),
            Self::HostRuleNeedsProxy { id } => write!(
                f,
                "`{id}`는 호스트 단위 egress 규칙임. egress 프록시 층 없이는 강제되지 않음"
            ),
            Self::IneffectiveRelaxation {
                id,
                forbid_id,
                probe,
            } => write!(
                f,
                "`{id}`는 {}를 열려고 하지만 forbid 규칙 `{forbid_id}`가 상위 tier에서 이김. 실제로 완화하려면 overrides = \"{forbid_id}\"와 reason을 명시해야 함",
                probe.display()
            ),
        }
    }
}
