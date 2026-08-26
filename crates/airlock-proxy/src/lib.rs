//! 이 크레이트는 Airlock의 로컬 egress 프록시 층을 구현합니다 (`airlock.proxy.v1`).
//!
//! # Features
//! 규격은 `docs/egress-proxy.md`입니다. 자식 프로세스의 아웃바운드를 루프백의
//! CONNECT 프록시로 받아 목적지 호스트를 [`gate::EgressGate`]에 묻고, 허용된
//! 연결만 중계합니다. 프록시 자체에는 강제력이 없습니다. 커널 강제 층이 루프백
//! 외 아웃바운드를 막아 이 프록시를 유일한 출구로 만들 때만 경계가 성립합니다.
//!
//! v1은 TLS를 종단하지 않습니다. CONNECT 요청 라인의 호스트명까지만 보고 터널
//! 내용은 해석하지 않으므로 DLP는 이 층의 범위 밖입니다.
//!
//! 정책 엔진과 감사 로그에 의존하지 않습니다. 판정은 전부 [`gate::EgressGate`]
//! 뒤로 숨겨 이 크레이트를 네트워크 없이 통째로 시험할 수 있게 두었습니다.

pub mod gate;
pub mod http;
pub mod server;

pub use gate::{Decision, EgressGate, Protocol, Target};
pub use http::{MAX_HEADERS, MAX_REQUEST_LINE, Reject, Request};
pub use server::{ProxyServer, ServerOptions};
