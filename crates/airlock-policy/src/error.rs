use std::fmt;
use std::path::PathBuf;

use airlock_i18n::tr;

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
    /// 정책 파일의 출처를 믿을 수 없습니다.
    ///
    /// 심볼릭 링크이거나, 호출자 소유가 아니거나, 다른 사용자가 쓸 수 있는 경우입니다
    UntrustedFile {
        path: PathBuf,
        why: String,
    },
    DuplicateId(String),
    /// 규칙 id에 허용되지 않는 문자가 있습니다.
    ///
    /// id는 커널 강제 프로파일에 주석으로 들어가므로 개행이나 제어 문자가 섞이면
    /// 주석을 탈출해 프로파일을 다시 쓸 수 있습니다 (`docs/policy-dsl.md` 10절)
    InvalidId {
        id: String,
        offender: char,
    },
    /// 사용자 규칙 id가 내장 규칙 id와 겹칩니다.
    ///
    /// 감사 로그의 `rule` 필드는 티어를 담지 않으므로, 겹치면 그 결정을 낸 규칙이 어느
    /// 티어의 것인지 로그만으로 알 수 없습니다 (`docs/policy-dsl.md` 10절)
    ReservedId {
        id: String,
        tier: &'static str,
    },
    /// 사용자 규칙 id가 `airlock:` 이름 공간을 씁니다.
    ///
    /// 그 접두는 엔진과 브로커가 만드는 합성 규칙 전용입니다. 사용자가 같은 이름을 쓰면
    /// 감사 로그의 `rule` 필드만 보고 그 결정이 엔진이 씌운 바닥인지 사람이 적은 규칙인지
    /// 알 수 없어집니다 (`docs/policy-dsl.md` 10절)
    ReservedNamespace {
        id: String,
    },
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
    UnknownProtocol {
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
    /// 이미 막는 규칙에 `max_bytes_out` 을 적었습니다.
    QuotaOnBlockingRule {
        id: String,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml(e) => write!(
                f,
                "{}",
                tr!(format!("TOML 파싱 실패: {e}"), format!("failed to parse TOML: {e}"))
            ),
            Self::Io { path, source } => write!(
                f,
                "{}",
                tr!(
                    format!("{} 읽기 실패: {source}", path.display()),
                    format!("failed to read {}: {source}", path.display())
                )
            ),
            Self::UnsupportedVersion(v) => write!(
                f,
                "{}",
                tr!(
                    format!("지원하지 않는 정책 version {v}. v1만 지원함"),
                    format!("unsupported policy version {v}; only v1 is supported")
                )
            ),
            Self::UntrustedFile { path, why } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "{} 를 신뢰할 수 없음: {why}. 정책 파일은 신뢰 경계 전체를 정의하므로 \
                 호출자 소유이고 남이 쓸 수 없어야 함",
                        path.display()
                    ),
                    format!(
                        "cannot trust {}: {why}; the policy file defines the whole trust \
                 boundary, so it must be owned by the caller and writable by no one else",
                        path.display()
                    )
                )
            ),
            Self::DuplicateId(id) => write!(
                f,
                "{}",
                tr!(
                    format!("규칙 id `{id}`가 중복됨"),
                    format!("rule id `{id}` is duplicated")
                )
            ),
            Self::InvalidId { id, offender } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "규칙 id `{}`에 쓸 수 없는 문자 {:?}가 있음. \
                 id는 커널 프로파일에 주석으로 들어가므로 영숫자와 . _ - : 만 허용함",
                        id.escape_debug(),
                        offender
                    ),
                    format!(
                        "rule id `{}` contains a disallowed character {:?}; ids go into the \
                 kernel profile as comments, so only alphanumerics and . _ - : are allowed",
                        id.escape_debug(),
                        offender
                    )
                )
            ),
            Self::ReservedId { id, tier } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "규칙 id `{id}`가 내장 {tier} 규칙과 겹침. 감사 로그의 rule 필드가 \
                 어느 티어를 가리키는지 알 수 없게 되므로 다른 id를 쓸 것. \
                 내장 규칙을 완화하려면 id 대신 overrides로 지목할 것"
                    ),
                    format!(
                        "rule id `{id}` collides with the built-in {tier} rule; the audit log's \
                 rule field would no longer say which tier it points to, so use a different id. \
                 To relax a built-in rule, name it with overrides instead"
                    )
                )
            ),
            Self::ReservedNamespace { id } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "규칙 id `{id}`가 `airlock:` 이름 공간을 씀. 그 접두는 엔진이 만드는 합성 규칙 \
                 전용이라 사용자 규칙이 쓰면 감사 로그의 rule 필드가 무엇을 가리키는지 알 수 \
                 없어짐. 다른 id를 쓸 것"
                    ),
                    format!(
                        "rule id `{id}` uses the `airlock:` namespace; that prefix is reserved for \
                 synthetic rules the engine creates, and a user rule taking it leaves the audit \
                 log's rule field ambiguous. Use a different id"
                    )
                )
            ),
            Self::QuotaOnBlockingRule { id } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "`{id}`는 이미 막는 규칙인데 max_bytes_out을 적었음. 총량 한도는 통과시키는 \
                 규칙에만 뜻이 있으며, 적어 두면 총량 제한이 걸렸다고 잘못 믿게 됨"
                    ),
                    format!(
                        "`{id}` already blocks yet declares max_bytes_out; a byte quota only means \
                 something on a rule that lets traffic through, and writing it here invites the \
                 false belief that a quota is enforced"
                    )
                )
            ),
            Self::UnknownAction { id, value } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "`{id}`의 action `{value}`를 알 수 없음. allow, deny, ask, forbid 중 하나여야 함"
                    ),
                    format!(
                        "unknown action `{value}` in `{id}`; must be one of allow, deny, ask, forbid"
                    )
                )
            ),
            Self::UnknownKind { id, value } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "`{id}`의 kind `{value}`를 알 수 없음. file, exec, egress 중 하나여야 함"
                    ),
                    format!("unknown kind `{value}` in `{id}`; must be one of file, exec, egress")
                )
            ),
            Self::UnknownMode { id, value } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "`{id}`의 mode `{value}`를 알 수 없음. read, write, create, delete, metadata, exec 중 하나여야 함"
                    ),
                    format!(
                        "unknown mode `{value}` in `{id}`; must be one of read, write, create, delete, metadata, exec"
                    )
                )
            ),
            Self::UnknownProtocol { id, value } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "`{id}`의 protocol `{value}`를 알 수 없음. tcp, tls, http 중 하나여야 함"
                    ),
                    format!("unknown protocol `{value}` in `{id}`; must be one of tcp, tls, http")
                )
            ),
            Self::MissingField { id, field } => write!(
                f,
                "{}",
                tr!(
                    format!("`{id}`에 필수 필드 `{field}`가 없음"),
                    format!("`{id}` is missing the required field `{field}`")
                )
            ),
            Self::UnexpectedField { id, field, kind } => write!(
                f,
                "{}",
                tr!(
                    format!("`{id}`는 kind가 {kind}인데 `{field}` 필드를 가짐"),
                    format!("`{id}` has kind {kind} but carries the `{field}` field")
                )
            ),
            Self::EmptyModeSet { id } => write!(
                f,
                "{}",
                tr!(
                    format!("`{id}`의 mode가 빈 배열임. 아무것도 매칭하지 않는 규칙은 오류임"),
                    format!("`{id}` has an empty mode array; a rule that matches nothing is an error")
                )
            ),
            Self::Pattern { id, source } => write!(
                f,
                "{}",
                tr!(
                    format!("`{id}` 패턴 오류: {source}"),
                    format!("`{id}` pattern error: {source}")
                )
            ),
            Self::Host { id, source } => write!(
                f,
                "{}",
                tr!(
                    format!("`{id}` 호스트 오류: {source}"),
                    format!("`{id}` host error: {source}")
                )
            ),
            Self::EgressDefaultAllow => f.write_str(tr!(
                "[defaults].egress는 allow가 될 수 없음. 아웃바운드 기본 허용은 데이터 반출 방어를 포기하는 설정임",
                "[defaults].egress cannot be allow; allowing outbound by default abandons exfiltration defense"
            )),
            Self::ForbidDefault { kind } => write!(
                f,
                "{}",
                tr!(
                    format!("[defaults].{kind}는 forbid가 될 수 없음. forbid는 내장 베이스라인 전용임"),
                    format!(
                        "[defaults].{kind} cannot be forbid; forbid is reserved for the built-in baseline"
                    )
                )
            ),
            Self::ForbidInUserRule { id } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "`{id}`의 action이 forbid임. forbid는 내장 베이스라인 전용이며 사용자 규칙은 allow, deny, ask 중 하나를 씀"
                    ),
                    format!(
                        "`{id}` has action forbid; forbid is reserved for the built-in baseline, and user rules use one of allow, deny, ask"
                    )
                )
            ),
            Self::EmptyOverrideTarget { id } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "`{id}`의 overrides가 빈 문자열임. 완화 대상을 지목하지 않을 거면 필드를 빼야 함"
                    ),
                    format!(
                        "`{id}` has an empty overrides string; if no relaxation target is named, drop the field"
                    )
                )
            ),
            Self::WildcardHostAllow { id } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "`{id}`는 host = \"*\"를 allow함. 아웃바운드 전면 허용은 [defaults].egress = \"allow\"와 같으며 데이터 반출 방어를 포기하는 설정임"
                    ),
                    format!(
                        "`{id}` allows host = \"*\"; allowing all outbound equals [defaults].egress = \"allow\" and abandons exfiltration defense"
                    )
                )
            ),
            Self::UnknownOverrideTarget { id, target } => write!(
                f,
                "{}",
                tr!(
                    format!("`{id}`의 overrides 대상 `{target}`가 내장 규칙에 없음"),
                    format!("overrides target `{target}` of `{id}` is not a built-in rule")
                )
            ),
            Self::OverrideTargetNotForbid { id, target } => write!(
                f,
                "{}",
                tr!(
                    format!("`{id}`의 overrides 대상 `{target}`는 forbid 규칙이 아님"),
                    format!("overrides target `{target}` of `{id}` is not a forbid rule")
                )
            ),
            Self::OverrideWithoutReason { id } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "`{id}`는 overrides를 쓰면서 reason이 비어 있음. 시크릿 보호 완화는 근거 없이 허용하지 않음"
                    ),
                    format!(
                        "`{id}` uses overrides but reason is empty; relaxing secret protection is not allowed without a stated reason"
                    )
                )
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
    ProtocolRuleNeedsProxy {
        id: String,
    },
    QuotaRuleNeedsProxy {
        id: String,
    },
    PlaintextEgressAllowed,
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
                "{}",
                tr!(
                    format!("`{id}`는 앞선 규칙 `{by}`에 완전히 가려져 도달할 수 없음"),
                    format!(
                        "`{id}` is fully shadowed by the earlier rule `{by}` and can never be reached"
                    )
                )
            ),
            Self::UnusedOverride { id, target } => write!(
                f,
                "{}",
                tr!(
                    format!("`{id}`의 overrides = \"{target}\"는 실제로 아무 보호도 완화하지 않음"),
                    format!(
                        "overrides = \"{target}\" on `{id}` does not actually relax any protection"
                    )
                )
            ),
            Self::HostRuleNeedsProxy { id } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "`{id}`는 호스트 단위 egress 규칙임. `airlock run --egress-proxy`로 실행할 때만 \
                 강제되고, 그냥 실행하면 커널이 판정하지 못함"
                    ),
                    format!(
                        "`{id}` is a per-host egress rule; it is only enforced under \
                 `airlock run --egress-proxy`, and a plain run leaves the kernel unable to judge it"
                    )
                )
            ),
            Self::ProtocolRuleNeedsProxy { id } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "`{id}`는 protocol을 지정한 egress 규칙임. 중계 층은 connect(2)만 보고 모든 연결을 \
                 tcp로 보고하므로, `airlock run --egress-proxy` 없이는 tls와 http 규칙이 \
                 아무것도 매칭하지 않고 평문 바닥도 발동하지 않음"
                    ),
                    format!(
                        "`{id}` is an egress rule with a protocol condition; the mediation layer sees \
                 only connect(2) and reports every connection as tcp, so without \
                 `airlock run --egress-proxy` tls and http rules match nothing and the plaintext \
                 floor never fires"
                    )
                )
            ),
            Self::QuotaRuleNeedsProxy { id } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "`{id}`는 max_bytes_out을 적은 egress 규칙임. 반출 바이트는 프록시 층만 세므로 \
                 `airlock run --egress-proxy` 없이는 누적량이 늘 0이고 한도가 한 번도 걸리지 않음"
                    ),
                    format!(
                        "`{id}` is an egress rule with max_bytes_out; only the proxy layer counts \
                 outbound bytes, so without `airlock run --egress-proxy` the running total stays 0 \
                 and the limit never triggers"
                    )
                )
            ),
            Self::PlaintextEgressAllowed => f.write_str(tr!(
                "[defaults].egress_plaintext = \"allow\"는 평문 아웃바운드 바닥을 없앰. \
                 허용된 호스트로 나가는 본문이 경로 전체에 그대로 노출됨. \
                 특정 호스트만 열려면 그 규칙에 protocol = \"http\"를 적을 것",
                "[defaults].egress_plaintext = \"allow\" removes the plaintext outbound floor; \
                 bodies sent to allowed hosts are exposed along the whole path. To open only \
                 specific hosts, write protocol = \"http\" on those rules"
            )),
            Self::IneffectiveRelaxation {
                id,
                forbid_id,
                probe,
            } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "`{id}`는 {}를 열려고 하지만 forbid 규칙 `{forbid_id}`가 상위 tier에서 이김. 실제로 완화하려면 overrides = \"{forbid_id}\"와 reason을 명시해야 함",
                        probe.display()
                    ),
                    format!(
                        "`{id}` tries to open {} but the forbid rule `{forbid_id}` wins at a higher tier; to actually relax it, state overrides = \"{forbid_id}\" and a reason",
                        probe.display()
                    )
                )
            ),
        }
    }
}
