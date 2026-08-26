//! 이 모듈은 프록시가 목적지를 판정할 때 부르는 경계를 정의합니다.
//!
//! # Features
//! 프록시는 정책 엔진을 직접 알지 않습니다. 판정 지점이 둘이 되면 두 지점이
//! 언젠가 갈라지고, 갈라지는 순간 감사 로그가 거짓 보증을 하기 때문입니다.
//! 브로커가 [`EgressGate`] 구현으로 기존 `Session` 평가 경로를 넘겨 줍니다.

use std::fmt;

/// 관측한 층이 판단한 아웃바운드 프로토콜.
///
/// 감사 엔트리의 프로토콜 태그가 됩니다. 프록시가 방출할 수 있는 것은 둘뿐이며
/// `tcp`는 seccomp 중계 층의 몫입니다 (`docs/audit-format.md` 6.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// CONNECT 터널. 포트와 무관하게 종단 간 암호화 요청으로 기록함
    Tls,
    /// absolute-form 평문 요청
    Http,
}

/// 판정 결과.
///
/// `ask`는 이 타입에 없습니다. 승인 흐름은 게이트 구현 안에서 끝나고 프록시는
/// 최종 결론만 받습니다. 프록시가 승인 UI를 직접 다루면 `/dev/tty` 채널 분리
/// 원칙이 깨집니다 (`docs/design.md` 9.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    pub fn permitted(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// 연결하려는 목적지.
///
/// `host`는 요청 라인에서 읽은 문자열 그대로입니다. 소문자화나 후행 점 제거 같은
/// 정규화는 정책 엔진의 몫이라 여기서 하지 않습니다 (`docs/policy-dsl.md` 8절)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// 목적지 하나를 판정하는 경계.
///
/// 구현은 여러 스레드에서 동시에 불립니다. 승인 대기로 오래 막힐 수 있으며 그동안
/// 다른 연결도 함께 멈추는 것은 의도된 동작입니다. 승인 없이 통과시키는 것보다
/// 느린 편이 낫습니다
pub trait EgressGate: Send + Sync + fmt::Debug {
    /// # Arguments
    /// `host` - 요청 라인에서 읽은 호스트 문자열
    /// `port` - 목적지 포트
    /// `protocol` - 관측된 프로토콜 태그
    fn check(&self, host: &str, port: u16, protocol: Protocol) -> Decision;
}

/// 전부 거부하는 게이트.
///
/// 시험과 기본값용입니다. 게이트를 붙이지 못한 프록시가 조용히 열리는 것보다
/// 닫힌 채로 있는 편이 안전합니다
#[derive(Debug, Default)]
pub struct DenyAll;

impl EgressGate for DenyAll {
    fn check(&self, _host: &str, _port: u16, _protocol: Protocol) -> Decision {
        Decision::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct AllowAll;

    impl EgressGate for AllowAll {
        fn check(&self, _h: &str, _p: u16, _proto: Protocol) -> Decision {
            Decision::Allow
        }
    }

    #[test]
    fn deny_all_never_permits() {
        let g = DenyAll;
        assert!(!g.check("api.anthropic.com", 443, Protocol::Tls).permitted());
        assert!(!g.check("localhost", 80, Protocol::Http).permitted());
    }

    #[test]
    fn allow_all_permits() {
        let g = AllowAll;
        assert!(g.check("example.com", 443, Protocol::Tls).permitted());
    }

    #[test]
    fn ipv6_targets_render_with_brackets() {
        let t = Target::new("::1", 8080);
        assert_eq!(t.to_string(), "[::1]:8080");
    }

    #[test]
    fn ordinary_targets_render_plainly() {
        let t = Target::new("example.com", 443);
        assert_eq!(t.to_string(), "example.com:443");
    }
}
