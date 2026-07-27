use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    Empty,
    NonAscii(String),
    BadChars(String),
    BareWildcardLabel(String),
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "빈 호스트 패턴"),
            Self::NonAscii(h) => write!(
                f,
                "`{h}`는 비ASCII 호스트임. v1은 IDN punycode 변환을 하지 않으므로 punycode로 직접 적어야 함"
            ),
            Self::BadChars(h) => write!(f, "`{h}`에 호스트명에 쓸 수 없는 문자가 있음"),
            Self::BareWildcardLabel(h) => write!(
                f,
                "`{h}` 형태는 지원하지 않음. `*`는 전체 또는 선행 `*.` 형태로만 씀"
            ),
        }
    }
}

impl std::error::Error for HostError {}

pub fn normalize_host(raw: &str) -> Option<String> {
    let t = raw.trim();
    let t = t.strip_suffix('.').unwrap_or(t);
    if t.is_empty() || !t.is_ascii() {
        return None;
    }
    if let Some(inner) = t.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        return inner
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ip.to_canonical().to_string());
    }
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Some(ip.to_canonical().to_string());
    }
    let ok = t
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    if !ok || t.starts_with('.') || t.contains("..") {
        return None;
    }
    Some(t.to_ascii_lowercase())
}

fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    Any,
    Exact(String),
    Suffix(String),
    Ip(IpAddr),
}

impl HostPattern {
    pub fn parse(raw: &str) -> Result<Self, HostError> {
        let t = raw.trim();
        if t.is_empty() {
            return Err(HostError::Empty);
        }
        if t == "*" {
            return Ok(Self::Any);
        }
        if let Some(rest) = t.strip_prefix("*.") {
            let norm = normalize_host(rest).ok_or_else(|| classify(rest))?;
            return Ok(Self::Suffix(norm));
        }
        if t.contains('*') {
            return Err(HostError::BareWildcardLabel(t.to_string()));
        }
        let norm = normalize_host(t).ok_or_else(|| classify(t))?;
        match norm.parse::<IpAddr>() {
            Ok(ip) => Ok(Self::Ip(ip)),
            Err(_) => Ok(Self::Exact(norm)),
        }
    }

    pub fn raw(&self) -> String {
        match self {
            Self::Any => "*".to_string(),
            Self::Exact(h) => h.clone(),
            Self::Suffix(h) => format!("*.{h}"),
            Self::Ip(ip) => ip.to_string(),
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        let Some(norm) = normalize_host(host) else {
            return false;
        };
        match self {
            Self::Any => true,
            Self::Ip(ip) => norm.parse::<IpAddr>().is_ok_and(|h| h == *ip),
            Self::Exact(e) => !is_ip_literal(&norm) && norm == *e,
            Self::Suffix(s) => {
                if is_ip_literal(&norm) {
                    return false;
                }
                norm.len() > s.len().saturating_add(1)
                    && norm.ends_with(s.as_str())
                    && norm.as_bytes().get(norm.len() - s.len() - 1) == Some(&b'.')
            }
        }
    }
}

fn classify(h: &str) -> HostError {
    if h.trim().is_empty() {
        HostError::Empty
    } else if !h.is_ascii() {
        HostError::NonAscii(h.to_string())
    } else {
        HostError::BadChars(h.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(raw: &str) -> HostPattern {
        HostPattern::parse(raw).unwrap()
    }

    #[test]
    fn exact_match() {
        let h = p("api.anthropic.com");
        assert!(h.matches("api.anthropic.com"));
        assert!(!h.matches("evil.api.anthropic.com"));
        assert!(!h.matches("anthropic.com"));
    }

    #[test]
    fn suffix_does_not_match_the_apex() {
        let h = p("*.githubusercontent.com");
        assert!(h.matches("raw.githubusercontent.com"));
        assert!(h.matches("a.b.githubusercontent.com"));
        assert!(
            !h.matches("githubusercontent.com"),
            "`*.x`가 apex를 먹으면 정책 의도가 넓어짐"
        );
    }

    #[test]
    fn suffix_requires_a_dot_boundary() {
        let h = p("*.example.com");
        assert!(!h.matches("notexample.com"));
        assert!(!h.matches("evilexample.com"));
        assert!(h.matches("sub.example.com"));
    }

    #[test]
    fn normalization_lowercases_and_strips_trailing_dot() {
        let h = p("example.com");
        assert!(h.matches("EXAMPLE.com"));
        assert!(h.matches("example.com."));
        assert!(h.matches("  Example.COM.  "));
    }

    #[test]
    fn pattern_itself_is_normalized() {
        assert_eq!(p("EXAMPLE.COM."), HostPattern::Exact("example.com".into()));
        assert_eq!(
            p("*.EXAMPLE.COM"),
            HostPattern::Suffix("example.com".into())
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_canonicalizes_to_ipv4() {
        let h = p("1.2.3.4");
        assert!(h.matches("::ffff:1.2.3.4"));
        assert!(h.matches("[::ffff:1.2.3.4]"));
        assert!(!h.matches("::ffff:1.2.3.5"));
        assert_eq!(p("::ffff:1.2.3.4"), p("1.2.3.4"));
        assert!(p("::ffff:1.2.3.4").matches("1.2.3.4"));
    }

    #[test]
    fn any_matches_everything_resolvable() {
        let h = p("*");
        assert!(h.matches("example.com"));
        assert!(h.matches("10.0.0.1"));
        assert!(!h.matches(""));
    }

    #[test]
    fn domain_patterns_never_match_ip_literals() {
        assert!(!p("example.com").matches("93.184.216.34"));
        assert!(!p("*.example.com").matches("93.184.216.34"));
        assert!(!p("*.example.com").matches("::1"));
    }

    #[test]
    fn ip_patterns_match_ips() {
        let h = p("10.0.0.1");
        assert_eq!(h, HostPattern::Ip("10.0.0.1".parse().unwrap()));
        assert!(h.matches("10.0.0.1"));
        assert!(!h.matches("10.0.0.2"));
        assert!(!h.matches("example.com"));
    }

    #[test]
    fn ipv6_forms_are_normalized() {
        let h = p("::1");
        assert!(h.matches("::1"));
        assert!(h.matches("[::1]"));
        assert!(h.matches("0:0:0:0:0:0:0:1"));
    }

    #[test]
    fn non_ascii_host_is_rejected_at_load() {
        assert!(matches!(
            HostPattern::parse("한국.com"),
            Err(HostError::NonAscii(_))
        ));
    }

    #[test]
    fn non_ascii_runtime_host_never_matches() {
        assert!(!p("*").matches("한국.com"));
        assert!(normalize_host("한국.com").is_none());
    }

    #[test]
    fn malformed_hosts_never_match() {
        assert!(normalize_host("").is_none());
        assert!(normalize_host(".").is_none());
        assert!(normalize_host(".example.com").is_none());
        assert!(normalize_host("a..b").is_none());
        assert!(normalize_host("a/b").is_none());
        assert!(normalize_host("a b").is_none());
    }

    #[test]
    fn mid_label_wildcard_is_rejected() {
        assert!(matches!(
            HostPattern::parse("api.*.com"),
            Err(HostError::BareWildcardLabel(_))
        ));
        assert!(matches!(
            HostPattern::parse("ev*l.com"),
            Err(HostError::BareWildcardLabel(_))
        ));
    }
}
