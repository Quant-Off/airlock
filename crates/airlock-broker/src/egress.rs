//! 이 모듈은 egress 프록시의 판정 요청을 세션의 기존 평가 경로로 잇습니다.
//!
//! # Features
//! 프록시는 정책 엔진도 감사 로그도 직접 알지 않습니다. 여기서 `Session`을 감싸
//! [`airlock_proxy::EgressGate`]로 넘겨 주면, 호스트 판정과 `ask` 승인과 감사
//! 기록이 전부 기존 경로 하나로 모입니다. 판정 지점이 둘이 되면 언젠가 갈라지고,
//! 갈라지는 순간 감사 로그가 거짓 보증을 하게 됩니다.

use std::sync::{Arc, Mutex};

use airlock_audit::Protocol as AuditProtocol;
use airlock_proxy::{Decision, EgressGate, Protocol};

use crate::session::Session;

/// 세션을 프록시의 판정 경계로 넘기는 어댑터.
///
/// 여러 연결 스레드가 동시에 부르므로 세션 잠금을 두고 직렬화됩니다. 승인 대기
/// 동안 다른 연결도 함께 멈추는 것은 의도된 동작입니다
#[derive(Debug)]
pub struct SessionGate {
    session: Arc<Mutex<Session>>,
}

impl SessionGate {
    pub fn new(session: Arc<Mutex<Session>>) -> Self {
        Self { session }
    }
}

fn audit_protocol(protocol: Protocol) -> AuditProtocol {
    match protocol {
        Protocol::Tls => AuditProtocol::Tls,
        Protocol::Http => AuditProtocol::Http,
    }
}

impl EgressGate for SessionGate {
    fn check(&self, host: &str, port: u16, protocol: Protocol) -> Decision {
        // 잠금이 오염되었다는 것은 판정이나 기록 도중 패닉이 있었다는 뜻입니다.
        // 그 상태의 감사 로그를 믿고 통과시키는 것보다 닫는 편이 낫습니다
        let Ok(mut session) = self.session.lock() else {
            return Decision::Deny;
        };
        match session.check_egress(host, port, audit_protocol(protocol)) {
            Ok(outcome) if outcome.permitted() => Decision::Allow,
            // 기록에 실패한 판정은 통과시키지 않습니다. 감사에 남지 않은 연결을
            // 허용하면 로그가 세션의 전부라는 보증이 깨집니다
            _ => Decision::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_tags_carry_the_observing_layer() {
        assert_eq!(audit_protocol(Protocol::Tls), AuditProtocol::Tls);
        assert_eq!(audit_protocol(Protocol::Http), AuditProtocol::Http);
    }
}
