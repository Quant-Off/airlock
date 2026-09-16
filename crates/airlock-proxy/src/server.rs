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
use std::time::{Duration, Instant};

use crate::gate::{Direction, EgressGate, Protocol, Target};
use crate::http::{MAX_HEADERS, Reject, Request, parse_head};

/// accept 루프가 정지 신호를 확인하는 간격
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// 릴레이 한 번에 옮기는 최대 바이트
const RELAY_CHUNK: usize = 16 * 1024;

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
    live: Arc<AtomicUsize>,
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
            live: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// 지금 살아 있는 중계 연결 수.
    ///
    /// 세션을 닫기 전에 결과 기록이 끝났는지 보려면 이 값이 0 이 되기를 기다려야 합니다.
    /// 완료 훅은 연결 처리가 끝나기 직전에 불리므로, 0 이면 남은 결과가 없습니다.
    /// `serve` 가 소유권을 가져가므로 그 전에 받아 두어야 합니다
    pub fn live_connections(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.live)
    }

    /// accept 루프를 돕니다. `stop`이 서면 돌아옵니다.
    pub fn serve(self, gate: Arc<dyn EgressGate>, stop: Arc<AtomicBool>) {
        let live = Arc::clone(&self.live);
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

    // 판정 직후부터 잽니다. 이름 해석과 목적지 연결도 그 연결이 붙잡고 있던 시간입니다
    let started = Instant::now();

    let Some(addrs) = resolve(&target, own) else {
        respond(&mut client, "HTTP/1.1 502 Bad Gateway");
        return;
    };
    let Some(mut origin) = dial(&addrs, opts.connect_timeout) else {
        respond(&mut client, "HTTP/1.1 502 Bad Gateway");
        return;
    };

    // 헤드와 그 뒤에 딸려 온 바이트도 목적지로 나가는 바이트입니다. 빼고 세면 반출량이
    // 실제보다 작게 보고됩니다
    let mut preface: u64 = 0;
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
            preface = preface.saturating_add(head.len() as u64);
        }
    }
    // 헤드 뒤에 딸려 온 바이트는 CONNECT면 터널 내용이고 평문이면 본문입니다.
    // 버리면 첫 요청이 조용히 잘립니다
    if !rest.is_empty() {
        if origin.write_all(&rest).is_err() {
            return;
        }
        preface = preface.saturating_add(rest.len() as u64);
    }

    // 세지 못한 연결에서는 훅을 부르지 않습니다. 0은 "아무것도 나가지 않았다" 는 사실
    // 주장이라, 모르는 것을 0으로 남기면 감사 로그가 거짓 보증을 합니다
    let Some((up, down)) = relay(client, origin) else {
        return;
    };
    let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    gate.finished(
        &target.host,
        target.port,
        protocol,
        preface.saturating_add(up),
        down,
        elapsed,
    );
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

/// 양방향 바이트 릴레이. v1 은 여기서부터 내용을 해석하지 않습니다.
///
/// 방향별로 실제 옮긴 바이트를 `(반출, 수신)` 으로 돌려줍니다. 어느 한 방향이라도 세지
/// 못하면 `None` 입니다. 모르는 값을 0 으로 내면 호출부가 그것을 사실로 기록합니다.
///
/// # 다음 단계가 붙을 자리
/// 내용 검사기는 [`pump`] 안의 읽기와 쓰기 사이에 들어갑니다. [`Direction`] 이 그 경계의
/// 타입이며, TLS 종단과 시크릿 패턴 차단이 거기서 조각 하나를 보고 통과·차단을 정합니다.
/// v1 에는 구현이 없습니다. CONNECT 터널을 열어 두는 한 조각은 암호문이고, 그것을 읽으려면
/// 프록시가 인증서를 발급해 자식에게 신뢰시켜야 하며 그 결정은 이 층 밖입니다.
fn relay(client: TcpStream, origin: TcpStream) -> Option<(u64, u64)> {
    // 릴레이 구간은 오래 조용할 수 있어 헤드용 타임아웃을 걷어 냅니다
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    let _ = origin.set_read_timeout(None);
    let _ = origin.set_write_timeout(None);

    let (Ok(mut client_w), Ok(mut origin_w)) = (client.try_clone(), origin.try_clone()) else {
        return None;
    };
    let mut client_r = client;
    let mut origin_r = origin;

    let up = thread::Builder::new()
        .name("airlock-proxy-up".into())
        .spawn(move || {
            let n = pump(&mut client_r, &mut origin_w, Direction::Outbound);
            let _ = origin_w.shutdown(Shutdown::Write);
            n
        })
        .ok();
    let down = pump(&mut origin_r, &mut client_w, Direction::Inbound);
    let _ = client_w.shutdown(Shutdown::Write);
    // 스레드를 띄우지 못했거나 join 이 실패하면 반출량을 모릅니다. 수신 방향만 아는 채로
    // 반출을 0으로 보고하지 않습니다
    let up = up.and_then(|h| h.join().ok())?;
    Some((up, down))
}

/// 한 방향으로 바이트를 옮기고 실제로 옮긴 양을 셉니다.
///
/// `io::copy` 를 쓰지 않는 이유는 실패로 끝난 복사가 바이트 수를 통째로 버리기 때문입니다.
/// RST 로 끊긴 연결이 "0 바이트 반출" 로 보고되면 그것이 정확히 반출 탐지의 구멍이 됩니다.
///
/// 목적지에 **완전히 써 넣은** 조각만 셉니다. `write_all` 이 도중에 실패하면 몇 바이트가
/// 나갔는지 알 방법이 없으므로 그 조각은 세지 않습니다. 곧 이 값은 하한이며, 오차는 조각
/// 하나(`RELAY_CHUNK`)를 넘지 않습니다.
///
/// # Arguments
/// `src` - 읽을 쪽
/// `dst` - 쓸 쪽
/// `direction` - 이 조각의 방향. 내용 검사기가 붙을 자리의 타입 경계
fn pump(src: &mut TcpStream, dst: &mut TcpStream, direction: Direction) -> u64 {
    let mut buf = [0u8; RELAY_CHUNK];
    let mut total: u64 = 0;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        let Some(chunk) = buf.get(..n) else { break };

        // 내용 검사기(ContentInspector)가 붙을 자리입니다. `direction` 과 `chunk` 를 받아
        // 통과·차단을 정하며, 차단이면 여기서 루프를 끊고 연결을 닫습니다. v1 에는 구현이
        // 없고 조각은 손대지 않은 채 그대로 나갑니다
        let _ = direction;

        if dst.write_all(chunk).is_err() {
            break;
        }
        total = total.saturating_add(n as u64);
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::Decision;
    use std::io::BufRead;
    use std::sync::Mutex;

    /// 완료 훅이 남긴 사실
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Finished {
        host: String,
        port: u16,
        protocol: Protocol,
        bytes_out: u64,
        bytes_in: u64,
    }

    #[derive(Debug, Default)]
    struct Recorder {
        allow: bool,
        seen: Mutex<Vec<(String, u16, Protocol)>>,
        done: Mutex<Vec<Finished>>,
    }

    impl Recorder {
        fn new(allow: bool) -> Arc<Self> {
            Arc::new(Self {
                allow,
                seen: Mutex::new(Vec::new()),
                done: Mutex::new(Vec::new()),
            })
        }
        fn calls(&self) -> Vec<(String, u16, Protocol)> {
            self.seen.lock().map(|g| g.clone()).unwrap_or_default()
        }
        fn finished_calls(&self) -> Vec<Finished> {
            self.done.lock().map(|g| g.clone()).unwrap_or_default()
        }
        /// 완료 훅은 릴레이 스레드에서 오므로 잠시 기다립니다
        fn wait_finished(&self) -> Vec<Finished> {
            for _ in 0..200 {
                let got = self.finished_calls();
                if !got.is_empty() {
                    return got;
                }
                thread::sleep(Duration::from_millis(25));
            }
            self.finished_calls()
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

        fn finished(
            &self,
            host: &str,
            port: u16,
            protocol: Protocol,
            bytes_out: u64,
            bytes_in: u64,
            _duration_ms: u64,
        ) {
            if let Ok(mut g) = self.done.lock() {
                g.push(Finished {
                    host: host.to_string(),
                    port,
                    protocol,
                    bytes_out,
                    bytes_in,
                });
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
        send_raw(addr, req.replace('\n', "\r\n").as_bytes())
    }

    /// 바이트를 고치지 않고 그대로 보냅니다. 개행 조작 시험용
    fn send_raw(addr: SocketAddr, req: &[u8]) -> String {
        let mut s = TcpStream::connect(addr).expect("프록시 연결");
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        s.write_all(req).expect("요청 전송");
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

    /// 연결이 왔는지만 보는 목적지. 거부 경로에서 접속이 없음을 확인하는 용도
    fn silent_origin() -> (SocketAddr, TcpListener) {
        let l = TcpListener::bind(("127.0.0.1", 0)).expect("바인드");
        l.set_nonblocking(true).expect("nonblocking");
        let addr = l.local_addr().expect("주소");
        (addr, l)
    }

    fn was_dialed(l: &TcpListener) -> bool {
        thread::sleep(Duration::from_millis(50));
        match l.accept() {
            Ok(_) => true,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
            Err(e) => panic!("accept 오류 {e}"),
        }
    }

    /// 거부되는 헤드는 판정에 닿지 않고 접속도 기록도 남기지 않아야 합니다.
    /// 세 가지가 함께 없어야 판정과 접속과 기록이 같은 사실을 말합니다
    fn assert_refused_without_side_effects(label: &str, build: impl FnOnce(u16) -> Vec<u8>) {
        let (origin, l) = silent_origin();
        let gate = Recorder::new(true);
        let run = start(gate.clone());
        let resp = send_raw(run.addr, &build(origin.port()));
        assert_eq!(status(&resp), "HTTP/1.1 400 Bad Request", "{label}");
        assert!(gate.calls().is_empty(), "{label}: 판정에 닿으면 안 됨");
        assert!(!was_dialed(&l), "{label}: 업스트림에 접속하면 안 됨");
        assert!(
            gate.finished_calls().is_empty(),
            "{label}: 결과 기록이 남으면 안 됨"
        );
    }

    #[test]
    fn a_bare_lf_host_injection_is_refused_without_touching_the_gate_or_the_origin() {
        assert_refused_without_side_effects("bare LF Host 주입", |port| {
            format!("GET http://127.0.0.1:{port}/x HTTP/1.1\r\nX-A: x\nHost: evil.test\r\n\r\n")
                .into_bytes()
        });
        assert_refused_without_side_effects("CONNECT bare LF", |port| {
            format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nX-A: x\nHost: evil.test\r\n\r\n")
                .into_bytes()
        });
    }

    #[test]
    fn a_bare_cr_is_refused_without_touching_the_gate_or_the_origin() {
        assert_refused_without_side_effects("bare CR", |port| {
            format!("GET http://127.0.0.1:{port}/x HTTP/1.1\r\nX-A: x\rHost: evil.test\r\n\r\n")
                .into_bytes()
        });
    }

    #[test]
    fn an_obs_fold_is_refused_without_touching_the_gate_or_the_origin() {
        assert_refused_without_side_effects("obs-fold", |port| {
            format!("GET http://127.0.0.1:{port}/x HTTP/1.1\r\nX-A: 1\r\n\tHost: evil.test\r\n\r\n")
                .into_bytes()
        });
    }

    #[test]
    fn duplicate_host_headers_are_refused_without_touching_the_gate_or_the_origin() {
        assert_refused_without_side_effects("중복 Host", |port| {
            format!(
                "GET http://127.0.0.1:{port}/x HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n"
            )
            .into_bytes()
        });
    }

    #[test]
    fn an_unknown_minor_version_is_refused_without_touching_the_gate_or_the_origin() {
        assert_refused_without_side_effects("HTTP/1.x", |port| {
            format!("GET http://127.0.0.1:{port}/x HTTP/1.x\r\n\r\n").into_bytes()
        });
        assert_refused_without_side_effects("CONNECT HTTP/1.x", |port| {
            format!("CONNECT 127.0.0.1:{port} HTTP/1.x\r\n\r\n").into_bytes()
        });
    }

    #[test]
    fn a_control_character_in_a_value_is_refused_without_touching_the_gate_or_the_origin() {
        assert_refused_without_side_effects("제어 문자 값", |port| {
            format!("GET http://127.0.0.1:{port}/x HTTP/1.1\r\nX-A: a\u{1}b\r\n\r\n").into_bytes()
        });
        assert_refused_without_side_effects("DEL 값", |port| {
            format!("GET http://127.0.0.1:{port}/x HTTP/1.1\r\nX-A: a\u{7f}b\r\n\r\n").into_bytes()
        });
    }

    #[test]
    fn a_non_ascii_host_is_refused_before_the_gate() {
        // 루프백으로 유도할 수 없는 호스트라 접속 여부 대신 판정 도달 여부를 봅니다
        let gate = Recorder::new(true);
        let run = start(gate.clone());
        let resp = send(run.addr, "CONNECT 例え.jp:443 HTTP/1.1\n\n");
        assert_eq!(status(&resp), "HTTP/1.1 400 Bad Request");
        assert!(gate.calls().is_empty());
        let resp = send(run.addr, "GET http://exämple.com/x HTTP/1.1\n\n");
        assert_eq!(status(&resp), "HTTP/1.1 400 Bad Request");
        assert!(gate.calls().is_empty());
        assert!(gate.finished_calls().is_empty());
    }

    #[test]
    fn a_tab_inside_a_header_value_reaches_the_origin() {
        let (origin, origin_h) = echo_origin("HTTP/1.1 204 No Content\r\n\r\n");
        let gate = Recorder::new(true);
        let run = start(gate.clone());
        let req = format!(
            "GET http://127.0.0.1:{}/a HTTP/1.0\nX-A: a\tb\n\n",
            origin.port()
        );
        let resp = send(run.addr, &req);
        assert_eq!(status(&resp), "HTTP/1.1 204 No Content");
        let raw = origin_h
            .join()
            .expect("origin 스레드")
            .expect("origin 수신");
        let seen = String::from_utf8(raw).expect("utf8");
        assert!(seen.starts_with("GET /a HTTP/1.0\r\n"), "{seen}");
        assert!(seen.contains("X-A: a\tb\r\n"), "{seen}");
        assert_eq!(
            gate.calls(),
            vec![("127.0.0.1".to_string(), origin.port(), Protocol::Http)]
        );
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
    fn a_tunnel_reports_the_bytes_it_actually_moved() {
        // 루프백 에코 목적지로 실측합니다. 세는 값이 실제 전송량과 어긋나면 사후 모니터링이
        // 있는 것처럼 보이기만 하고 아무것도 보증하지 않습니다
        let payload = "x".repeat(40_000);
        let reply = "y".repeat(9_000);
        let l = TcpListener::bind(("127.0.0.1", 0)).expect("바인드");
        let origin = l.local_addr().expect("주소");
        let want_out = payload.len() as u64;
        let want_in = reply.len() as u64;
        let body = reply.clone();
        let origin_h = thread::spawn(move || -> usize {
            let Ok((mut s, _)) = l.accept() else { return 0 };
            s.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            let _ = s.write_all(body.as_bytes());
            let _ = s.shutdown(Shutdown::Write);
            got.len()
        });

        let gate = Recorder::new(true);
        let run = start(gate.clone());
        let mut s = TcpStream::connect(run.addr).expect("프록시 연결");
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        s.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", origin.port()).as_bytes())
            .expect("요청");

        let mut r = io::BufReader::new(s.try_clone().expect("clone"));
        let mut line = String::new();
        r.read_line(&mut line).expect("상태 라인");
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        let mut blank = String::new();
        r.read_line(&mut blank).expect("빈 줄");

        s.write_all(payload.as_bytes()).expect("터널 쓰기");
        s.shutdown(Shutdown::Write).expect("절반 닫기");
        let mut got = Vec::new();
        r.read_to_end(&mut got).expect("터널 읽기");
        assert_eq!(got.len(), reply.len());
        let seen = origin_h.join().expect("origin 스레드");
        assert_eq!(seen, payload.len(), "목적지가 받은 양");

        let done = gate.wait_finished();
        assert_eq!(done.len(), 1, "완료 훅이 한 번 와야 함: {done:?}");
        let f = done.first().expect("완료 훅");
        assert_eq!(f.host, "127.0.0.1");
        assert_eq!(f.port, origin.port());
        assert_eq!(f.protocol, Protocol::Tls);
        assert_eq!(f.bytes_out, want_out, "반출 바이트가 실제와 다름");
        assert_eq!(f.bytes_in, want_in, "수신 바이트가 실제와 다름");
    }

    #[test]
    fn a_plaintext_request_counts_its_head_as_outbound() {
        // 요청 헤드도 목적지로 나간 바이트입니다. 빼고 세면 반출량이 실제보다 작아집니다
        let (origin, origin_h) = echo_origin("HTTP/1.1 204 No Content\r\n\r\n");
        let gate = Recorder::new(true);
        let run = start(gate.clone());
        let req = format!(
            "GET http://127.0.0.1:{}/a HTTP/1.1\nHost: h\n\n",
            origin.port()
        );
        send(run.addr, &req);

        let raw = origin_h
            .join()
            .expect("origin 스레드")
            .expect("origin 수신");
        let done = gate.wait_finished();
        let f = done.first().expect("완료 훅");
        assert_eq!(
            f.bytes_out,
            raw.len() as u64,
            "목적지가 받은 헤드 길이와 반출 바이트가 같아야 함"
        );
        assert_eq!(f.protocol, Protocol::Http);
    }

    #[test]
    fn a_denied_target_never_reports_a_result() {
        // 나가지 않은 연결에 0 바이트 결과를 남기면 "시도했으나 아무것도 안 나갔다" 는
        // 없는 사실이 로그에 생깁니다
        let gate = Recorder::new(false);
        let run = start(gate.clone());
        send(run.addr, "CONNECT api.anthropic.com:443 HTTP/1.1\n\n");
        thread::sleep(Duration::from_millis(50));
        assert!(gate.finished_calls().is_empty());
    }

    #[test]
    fn an_unreachable_origin_never_reports_a_result() {
        let gate = Recorder::new(true);
        let run = start(gate.clone());
        let dead = TcpListener::bind(("127.0.0.1", 0)).expect("바인드");
        let port = dead.local_addr().expect("주소").port();
        drop(dead);
        send(run.addr, &format!("CONNECT 127.0.0.1:{port} HTTP/1.1\n\n"));
        thread::sleep(Duration::from_millis(50));
        assert!(gate.finished_calls().is_empty());
    }

    #[test]
    fn the_bound_address_is_loopback() {
        let server = ProxyServer::bind().expect("바인드");
        assert!(server.addr().ip().is_loopback());
        assert_ne!(server.addr().port(), 0);
    }
}
