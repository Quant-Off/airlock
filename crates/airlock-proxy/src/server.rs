//! 이 모듈은 루프백 리스너와 연결 처리 루프를 담습니다.
//!
//! # Features
//! `127.0.0.1`의 임의 포트에 바인드해 커널이 준 포트를 돌려줍니다. 포트를
//! 고정하지 않는 이유는 두 세션이 겹칠 때 충돌하고, 고정 포트는 같은 사용자의
//! 다른 프로세스가 선점해 자식의 아웃바운드를 가로챌 수 있기 때문입니다.
//!
//! 이름 해석은 판정 뒤에 합니다. 판정 전에 해석하면 거부될 호스트의 DNS 질의가
//! 이미 나가서 이름 자체가 반출 채널이 됩니다.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use crate::gate::{EgressGate, Protocol, Target};
use crate::http::{MAX_HEADERS, Reject, Request, parse_head};

/// accept 루프가 정지 신호를 확인하는 간격
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// 서버 동작 한도.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// 동시 연결 상한. 넘어서는 연결은 즉시 닫음
    pub max_connections: usize,
    /// 헤드를 다 받을 때까지 기다리는 시간
    pub head_timeout: Duration,
    /// 목적지 TCP 연결 대기 시간
    pub connect_timeout: Duration,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            max_connections: 256,
            head_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(15),
        }
    }
}

/// 루프백에 바인드된 프록시 리스너.
///
/// [`ProxyServer::addr`]가 주는 주소를 자식 환경의 프록시 변수와 커널 프로파일의
/// 유일한 아웃바운드 허용 대상 양쪽에 넣어야 경계가 성립합니다
#[derive(Debug)]
pub struct ProxyServer {
    listener: TcpListener,
    addr: SocketAddr,
    opts: ServerOptions,
}

impl ProxyServer {
    /// # Errors
    /// 루프백 바인드에 실패하면 그대로 냅니다
    pub fn bind() -> io::Result<Self> {
        Self::bind_with(ServerOptions::default())
    }

    /// # Errors
    /// 루프백 바인드나 주소 조회에 실패하면 그대로 냅니다
    pub fn bind_with(opts: ServerOptions) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            addr,
            opts,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// accept 루프를 돕니다. `stop`이 서면 돌아옵니다.
    pub fn serve(self, gate: Arc<dyn EgressGate>, stop: Arc<AtomicBool>) {
        let live = Arc::new(AtomicUsize::new(0));
        while !stop.load(Ordering::Relaxed) {
            let client = match self.listener.accept() {
                Ok((s, _)) => s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(POLL_INTERVAL);
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            // BSD 계열은 accept 한 소켓이 리스너의 O_NONBLOCK 을 물려받습니다. 그대로
            // 두면 릴레이의 첫 read 가 WouldBlock 으로 끊겨 터널이 즉시 닫힙니다.
            // Linux 는 물려주지 않지만 양쪽에서 같은 상태를 보장합니다
            if client.set_nonblocking(false).is_err() {
                let _ = client.shutdown(Shutdown::Both);
                continue;
            }
            if live.load(Ordering::Relaxed) >= self.opts.max_connections {
                let _ = client.shutdown(Shutdown::Both);
                continue;
            }
            live.fetch_add(1, Ordering::Relaxed);

            let gate = Arc::clone(&gate);
            let held = Arc::clone(&live);
            let opts = self.opts.clone();
            let own = self.addr;
            let spawned = thread::Builder::new()
                .name("airlock-proxy-conn".into())
                .spawn(move || {
                    handle(client, gate.as_ref(), own, &opts);
                    held.fetch_sub(1, Ordering::Relaxed);
                });
            // 스레드를 띄우지 못하면 연결을 여는 대신 닫습니다
            if spawned.is_err() {
                live.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

fn handle(mut client: TcpStream, gate: &dyn EgressGate, own: SocketAddr, opts: &ServerOptions) {
    let _ = client.set_read_timeout(Some(opts.head_timeout));
    let _ = client.set_write_timeout(Some(opts.head_timeout));

    let (head, rest) = match read_head(&mut client) {
        Ok(v) => v,
        Err(why) => {
            respond(&mut client, why.status_line());
            return;
        }
    };
    let request = match parse_head(&head) {
        Ok(r) => r,
        Err(why) => {
            respond(&mut client, why.status_line());
            return;
        }
    };

    let protocol = match &request {
        Request::Connect(_) => Protocol::Tls,
        Request::Forward { .. } => Protocol::Http,
    };
    let target = request.target().clone();

    if !gate.check(&target.host, target.port, protocol).permitted() {
        respond(&mut client, "HTTP/1.1 403 Forbidden");
        return;
    }

    let Some(addrs) = resolve(&target, own) else {
        respond(&mut client, "HTTP/1.1 502 Bad Gateway");
        return;
    };
    let Some(mut origin) = dial(&addrs, opts.connect_timeout) else {
        respond(&mut client, "HTTP/1.1 502 Bad Gateway");
        return;
    };

    match request {
        Request::Connect(_) => {
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .is_err()
            {
                return;
            }
        }
        Request::Forward { head, .. } => {
            if origin.write_all(&head).is_err() {
                return;
            }
        }
    }
    // 헤드 뒤에 딸려 온 바이트는 CONNECT면 터널 내용이고 평문이면 본문입니다.
    // 버리면 첫 요청이 조용히 잘립니다
    if !rest.is_empty() && origin.write_all(&rest).is_err() {
        return;
    }

    relay(client, origin);
}

/// 헤드 끝까지만 읽고 그 뒤에 딸려 온 바이트를 함께 돌려줍니다.
///
/// # Errors
/// 상한을 넘거나 헤드가 끝나기 전에 연결이 닫히면 [`Reject`]를 냅니다
fn read_head(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>), Reject> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let mut searched = 0usize;
    loop {
        let n = match stream.read(&mut chunk) {
            Ok(0) => return Err(Reject::Malformed),
            Ok(n) => n,
            Err(_) => return Err(Reject::Malformed),
        };
        buf.extend_from_slice(&chunk[..n]);
        // 경계가 두 청크에 걸칠 수 있어 3바이트만 되짚습니다
        let from = searched.saturating_sub(3);
        if let Some(pos) = find_head_end(&buf[from..]) {
            let end = from + pos;
            let rest = buf.split_off(end);
            return Ok((buf, rest));
        }
        searched = buf.len();
        if buf.len() > MAX_HEADERS {
            return Err(Reject::TooLarge);
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// 판정 뒤에 이름을 해석합니다.
///
/// 프록시 자신으로 향하는 주소는 걸러 냅니다. 자기 자신에 연결하면 스레드마다
/// 연결이 재귀적으로 늘어나 리스너가 고갈됩니다
fn resolve(target: &Target, own: SocketAddr) -> Option<Vec<SocketAddr>> {
    let addrs = (target.host.as_str(), target.port).to_socket_addrs().ok()?;
    let kept: Vec<SocketAddr> = addrs
        .filter(|a| !(a.port() == own.port() && a.ip().is_loopback()))
        .collect();
    if kept.is_empty() { None } else { Some(kept) }
}

fn dial(addrs: &[SocketAddr], timeout: Duration) -> Option<TcpStream> {
    addrs
        .iter()
        .find_map(|a| TcpStream::connect_timeout(a, timeout).ok())
}

fn respond(stream: &mut TcpStream, status_line: &str) {
    let body = format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.shutdown(Shutdown::Both);
}

/// 양방향 바이트 릴레이. 여기서부터는 내용을 해석하지 않습니다
fn relay(client: TcpStream, origin: TcpStream) {
    // 릴레이 구간은 오래 조용할 수 있어 헤드용 타임아웃을 걷어 냅니다
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    let _ = origin.set_read_timeout(None);
    let _ = origin.set_write_timeout(None);

    let (Ok(mut client_w), Ok(mut origin_w)) = (client.try_clone(), origin.try_clone()) else {
        return;
    };
    let mut client_r = client;
    let mut origin_r = origin;

    let up = thread::Builder::new()
        .name("airlock-proxy-up".into())
        .spawn(move || {
            let _ = io::copy(&mut client_r, &mut origin_w);
            let _ = origin_w.shutdown(Shutdown::Write);
        });
    let _ = io::copy(&mut origin_r, &mut client_w);
    let _ = client_w.shutdown(Shutdown::Write);
    if let Ok(h) = up {
        let _ = h.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::Decision;
    use std::io::BufRead;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Recorder {
        allow: bool,
        seen: Mutex<Vec<(String, u16, Protocol)>>,
    }

    impl Recorder {
        fn new(allow: bool) -> Arc<Self> {
            Arc::new(Self {
                allow,
                seen: Mutex::new(Vec::new()),
            })
        }
        fn calls(&self) -> Vec<(String, u16, Protocol)> {
            self.seen.lock().map(|g| g.clone()).unwrap_or_default()
        }
    }

    impl EgressGate for Recorder {
        fn check(&self, host: &str, port: u16, protocol: Protocol) -> Decision {
            if let Ok(mut g) = self.seen.lock() {
                g.push((host.to_string(), port, protocol));
            }
            if self.allow {
                Decision::Allow
            } else {
                Decision::Deny
            }
        }
    }

    struct Running {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl Drop for Running {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn start(gate: Arc<dyn EgressGate>) -> Running {
        let server = ProxyServer::bind().expect("바인드");
        let addr = server.addr();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || server.serve(gate, flag));
        Running {
            addr,
            stop,
            handle: Some(handle),
        }
    }

    /// 한 연결만 받아 고정 응답을 돌려주는 목적지
    fn echo_origin(
        reply: &'static str,
    ) -> (SocketAddr, thread::JoinHandle<Result<Vec<u8>, String>>) {
        let l = TcpListener::bind(("127.0.0.1", 0)).expect("바인드");
        let addr = l.local_addr().expect("주소");
        let h = thread::spawn(move || {
            let (mut s, _) = l.accept().map_err(|e| format!("accept 실패 {e}"))?;
            s.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut got = vec![0u8; 2048];
            let n = s.read(&mut got).map_err(|e| format!("read 실패 {e}"))?;
            got.truncate(n);
            let _ = s.write_all(reply.as_bytes());
            // Both으로 닫으면 아직 오가는 바이트가 RST를 유발해 릴레이가 깨집니다.
            // 실제 서버가 하는 절반 닫기를 그대로 흉내 냅니다
            let _ = s.shutdown(Shutdown::Write);
            Ok(got)
        });
        (addr, h)
    }

    fn send(addr: SocketAddr, req: &str) -> String {
        let mut s = TcpStream::connect(addr).expect("프록시 연결");
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        s.write_all(req.replace('\n', "\r\n").as_bytes())
            .expect("요청 전송");
        let mut out = String::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = s.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.push_str(&String::from_utf8_lossy(&buf[..n]));
            if out.len() > 8192 {
                break;
            }
        }
        out
    }

    fn status(resp: &str) -> String {
        resp.lines().next().unwrap_or_default().trim().to_string()
    }

    #[test]
    fn a_denied_target_gets_403_and_is_never_dialed() {
        let gate = Recorder::new(false);
        let run = start(gate.clone());
        let resp = send(run.addr, "CONNECT api.anthropic.com:443 HTTP/1.1\n\n");
        assert_eq!(status(&resp), "HTTP/1.1 403 Forbidden");
        assert_eq!(
            gate.calls(),
            vec![("api.anthropic.com".to_string(), 443, Protocol::Tls)]
        );
    }

    #[test]
    fn an_allowed_connect_tunnels_bytes_both_ways() {
        let (origin, origin_h) = echo_origin("pong");
        let gate = Recorder::new(true);
        let run = start(gate.clone());
        let mut s = TcpStream::connect(run.addr).expect("프록시 연결");
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", origin.port());
        s.write_all(req.as_bytes()).expect("요청");

        let mut r = io::BufReader::new(s.try_clone().expect("clone"));
        let mut line = String::new();
        r.read_line(&mut line).expect("상태 라인");
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        let mut blank = String::new();
        r.read_line(&mut blank).expect("빈 줄");

        s.write_all(b"ping").expect("터널 쓰기");
        let mut got = String::new();
        r.read_to_string(&mut got).expect("터널 읽기");
        assert_eq!(got, "pong");
        let seen = origin_h
            .join()
            .expect("origin 스레드")
            .expect("origin 수신");
        assert_eq!(seen, b"ping");
    }

    #[test]
    fn an_allowed_plaintext_request_is_rewritten_to_origin_form() {
        let (origin, origin_h) = echo_origin("HTTP/1.1 204 No Content\r\n\r\n");
        let gate = Recorder::new(true);
        let run = start(gate.clone());
        let req = format!(
            "GET http://127.0.0.1:{}/a HTTP/1.1\nHost: spoofed.test\nAccept: */*\n\n",
            origin.port()
        );
        let resp = send(run.addr, &req);
        assert_eq!(status(&resp), "HTTP/1.1 204 No Content");

        let raw = origin_h
            .join()
            .expect("origin 스레드")
            .expect("origin 수신");
        let seen = String::from_utf8(raw).expect("utf8");
        assert!(seen.starts_with("GET /a HTTP/1.1\r\n"), "{seen}");
        assert!(
            seen.contains(&format!("Host: 127.0.0.1:{}\r\n", origin.port())),
            "{seen}"
        );
        assert!(!seen.contains("spoofed.test"), "{seen}");
        assert_eq!(gate.calls()[0].2, Protocol::Http);
    }

    #[test]
    fn origin_form_requests_are_refused_before_the_gate() {
        let gate = Recorder::new(true);
        let run = start(gate.clone());
        let resp = send(run.addr, "GET /secret HTTP/1.1\nHost: example.com\n\n");
        assert_eq!(status(&resp), "HTTP/1.1 400 Bad Request");
        // 목적지를 특정할 수 없는 요청이 게이트에 닿으면 안 됩니다
        assert!(gate.calls().is_empty());
    }

    #[test]
    fn connecting_to_the_proxy_itself_is_refused() {
        let gate = Recorder::new(true);
        let run = start(gate.clone());
        let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\n\n", run.addr.port());
        let resp = send(run.addr, &req);
        assert_eq!(status(&resp), "HTTP/1.1 502 Bad Gateway");
    }

    #[test]
    fn an_unreachable_origin_reports_bad_gateway() {
        let gate = Recorder::new(true);
        let run = start(gate.clone());
        // 열어 두고 즉시 닫은 포트라 연결이 거부됩니다
        let dead = TcpListener::bind(("127.0.0.1", 0)).expect("바인드");
        let port = dead.local_addr().expect("주소").port();
        drop(dead);
        let resp = send(run.addr, &format!("CONNECT 127.0.0.1:{port} HTTP/1.1\n\n"));
        assert_eq!(status(&resp), "HTTP/1.1 502 Bad Gateway");
    }

    #[test]
    fn a_malformed_head_is_refused() {
        let gate = Recorder::new(true);
        let run = start(gate.clone());
        let resp = send(
            run.addr,
            "CONNECT example.com:443 HTTP/1.1\nBad Header: 1\n\n",
        );
        assert_eq!(status(&resp), "HTTP/1.1 400 Bad Request");
        assert!(gate.calls().is_empty());
    }

    #[test]
    fn the_bound_address_is_loopback() {
        let server = ProxyServer::bind().expect("바인드");
        assert!(server.addr().ip().is_loopback());
        assert_ne!(server.addr().port(), 0);
    }
}
