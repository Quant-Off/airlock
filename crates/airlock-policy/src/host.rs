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
    // Rust의 파서는 점 4개 십진 표기만 받지만 getaddrinfo는 8진, 16진, 정수 하나,
    // 생략형까지 받습니다. 여기서 잡지 않으면 169.254.169.254 deny를 2852039166으로
    // 그대로 지나갑니다
    if let Some(ip) = parse_inet_aton(t) {
        return Some(IpAddr::V4(ip).to_string());
    }
    let ok = t
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    if !ok || t.starts_with('.') || t.contains("..") {
        return None;
    }
    Some(t.to_ascii_lowercase())
}

/// `inet_aton` 의미론으로 IPv4를 읽습니다.
///
/// 1개에서 4개의 부분을 받고 각 부분은 10진, `0` 접두 8진, `0x` 접두 16진입니다. 마지막
/// 부분이 남은 바이트를 통째로 채웁니다. 곧 `127.1`은 127.0.0.1, `2130706433`도 같습니다.
///
/// # Arguments
/// `t` - 검사할 문자열
fn parse_inet_aton(t: &str) -> Option<std::net::Ipv4Addr> {
    // 순수 도메인 이름이 여기 걸리면 안 되므로 숫자 표기만 받습니다
    let parts: Vec<&str> = t.split('.').collect();
    if parts.is_empty() || parts.len() > 4 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let mut vals: Vec<u32> = Vec::with_capacity(parts.len());
    for p in &parts {
        let (digits, radix) = if let Some(h) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X"))
        {
            (h, 16)
        } else if p.len() > 1 && p.starts_with('0') {
            (&p[1..], 8)
        } else {
            (*p, 10)
        };
        if digits.is_empty() || !digits.bytes().all(|b| (b as char).is_digit(radix)) {
            return None;
        }
        vals.push(u32::from_str_radix(digits, radix).ok()?);
    }
    // 마지막을 뺀 나머지는 한 바이트씩이고, 마지막이 남은 자리를 전부 채웁니다
    let last = *vals.last()?;
    let head = &vals[..vals.len() - 1];
    if head.iter().any(|v| *v > 0xFF) {
        return None;
    }
    let tail_bytes = 4 - head.len() as u32;
    if tail_bytes < 4 && last >= 1u32 << (8 * tail_bytes) {
        return None;
    }
    let mut addr: u32 = 0;
    for (i, v) in head.iter().enumerate() {
        addr |= v << (8 * (3 - i as u32));
    }
    addr |= last;
    Some(std::net::Ipv4Addr::from(addr))
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
            // `*`는 "전부"라는 뜻이며 정규화할 수 없는 값도 전부에 들어갑니다. 여기서
            // false를 돌려주면 deny host="*"가 [defaults].egress보다 느슨해집니다
            return matches!(self, Self::Any);
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
    fn any_matches_everything_including_unparseable() {
        // `*`는 "전부"입니다. 정규화할 수 없는 값을 비켜 가면 deny host="*"가
        // [defaults].egress 보다 느슨해집니다. allow 에는 `*`를 쓸 수 없으므로
        // (engine 의 WildcardHostAllow) 이 넓힘이 통과를 만들지는 않습니다
        let h = p("*");
        assert!(h.matches("example.com"));
        assert!(h.matches("10.0.0.1"));
        assert!(h.matches(""));
        assert!(h.matches("한국.com"));
        assert!(h.matches("fe80::1%en0"));
        assert!(h.matches("exfil.com:443"));
        assert!(h.matches(".evil.com"));
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
    fn non_ascii_runtime_host_matches_nothing_but_any() {
        assert!(!p("example.com").matches("한국.com"));
        assert!(!p("*.com").matches("한국.com"));
        assert!(normalize_host("한국.com").is_none());
    }

    #[test]
    fn alternate_ipv4_notations_normalize_to_the_same_address() {
        // getaddrinfo 가 받는 표기를 정책도 같은 주소로 봐야 합니다. 그렇지 않으면
        // 클라우드 메타데이터 deny 를 정수 표기 하나로 지나갑니다
        let meta = p("169.254.169.254");
        for raw in [
            "169.254.169.254",
            "2852039166",
            "0xA9FEA9FE",
            "0xa9fea9fe",
            "169.254.43518",
            "169.16689662",
            "0251.0376.0251.0376",
        ] {
            assert!(
                meta.matches(raw),
                "{raw}가 메타데이터 주소로 정규화되어야 함"
            );
        }

        let loopback = p("127.0.0.1");
        for raw in ["127.0.0.1", "127.1", "2130706433", "0x7f000001"] {
            assert!(loopback.matches(raw), "{raw}가 루프백으로 정규화되어야 함");
        }
    }

    #[test]
    fn ordinary_domains_are_not_read_as_numeric_ipv4() {
        for raw in [
            "example.com",
            "a.b.c.d",
            "1foo.com",
            "0x.com",
            "8.8.8.8.com",
        ] {
            let norm = normalize_host(raw).unwrap_or_default();
            assert!(
                norm.parse::<IpAddr>().is_err(),
                "{raw}는 IP 로 읽히면 안 됨: {norm}"
            );
        }
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
