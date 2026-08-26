//! 이 모듈은 프록시가 받는 요청 헤드를 해석하고 목적지를 뽑습니다.
//!
//! # Features
//! 자식이 보낸 바이트를 해석하는 코드이므로 신뢰 경계 안입니다. 받는 형태는
//! CONNECT 터널과 absolute-form 평문 요청 둘뿐이며 나머지는 전부 거부합니다.
//! 애매하게 받아 주는 파서는 프록시가 판정한 목적지와 실제로 나가는 목적지를
//! 갈라놓기 때문에, 조금이라도 규격을 벗어나면 거부하는 쪽을 택했습니다.
//!
//! 순수 함수만 두어 네트워크 없이 전부 시험할 수 있습니다.

use crate::gate::Target;

/// 요청 라인 상한
pub const MAX_REQUEST_LINE: usize = 8 * 1024;

/// 헤드 전체 상한
pub const MAX_HEADERS: usize = 64 * 1024;

/// 호스트명 상한. DNS 이름의 최대 길이임
const MAX_HOST: usize = 253;

/// 프록시가 소비하고 목적지로 넘기지 않는 헤더들.
///
/// `connection`과 `keep-alive`를 빼는 이유는 아래에서 `Connection: close`를 다시
/// 넣기 때문입니다. `host`는 URL의 authority로 다시 씁니다. 판정한 authority와
/// 목적지가 보는 Host가 다르면 가상 호스트 라우팅이 갈라져 정책이 무의미해집니다
const DROPPED_HEADERS: [&str; 5] = [
    "connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "host",
];

/// 헤드를 받아들이지 못한 사유.
///
/// 각 사유가 그대로 응답 코드가 됩니다
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// 규격을 벗어난 형태
    Malformed,
    /// 상한 초과
    TooLarge,
    /// origin-form 요청. 프록시로 왔는데 목적지가 없어 판정 대상을 특정할 수 없음
    NoTarget,
}

impl Reject {
    /// 이 사유에 대응하는 상태 라인.
    pub fn status_line(self) -> &'static str {
        match self {
            Self::Malformed | Self::NoTarget => "HTTP/1.1 400 Bad Request",
            Self::TooLarge => "HTTP/1.1 431 Request Header Fields Too Large",
        }
    }
}

/// 해석된 요청.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// CONNECT 터널. 200 응답 뒤로는 바이트를 해석하지 않음
    Connect(Target),
    /// absolute-form 평문 요청. `head`는 origin-form으로 고쳐 쓴 헤드 전체임
    Forward { target: Target, head: Vec<u8> },
}

impl Request {
    pub fn target(&self) -> &Target {
        match self {
            Self::Connect(t) => t,
            Self::Forward { target, .. } => target,
        }
    }
}

/// 헤드 전체를 해석합니다.
///
/// # Arguments
/// `head` - 요청 라인부터 헤더 끝까지의 바이트. 끝의 빈 줄을 포함함
///
/// # Errors
/// 규격을 벗어나거나 상한을 넘으면 [`Reject`]를 냅니다. 호출부는 그 상태 라인을
/// 그대로 응답하고 연결을 닫아야 합니다
pub fn parse_head(head: &[u8]) -> Result<Request, Reject> {
    if head.len() > MAX_HEADERS {
        return Err(Reject::TooLarge);
    }
    let text = std::str::from_utf8(head).map_err(|_| Reject::Malformed)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(Reject::Malformed)?;
    if request_line.len() > MAX_REQUEST_LINE {
        return Err(Reject::TooLarge);
    }

    let mut parts = request_line.split(' ');
    let (Some(method), Some(raw_target), Some(version)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err(Reject::Malformed);
    };
    // 공백이 더 있으면 목적지가 어디까지인지 두 해석이 가능해집니다
    if parts.next().is_some() {
        return Err(Reject::Malformed);
    }
    if !is_token(method) || !version.starts_with("HTTP/1.") {
        return Err(Reject::Malformed);
    }

    if method == "CONNECT" {
        let target = split_authority(raw_target, None)?;
        // 터널의 헤더는 목적지로 넘기지 않지만 형태는 그대로 확인합니다. 규격을
        // 벗어난 헤드를 받아 주면 이 프록시가 무엇을 받는지의 기준이 요청 종류마다
        // 달라지고, 그 차이가 곧 앞뒤 서버의 해석 차이가 됩니다
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (name, _) = line.split_once(':').ok_or(Reject::Malformed)?;
            if !is_token(name) {
                return Err(Reject::Malformed);
            }
        }
        return Ok(Request::Connect(target));
    }

    let rest = strip_scheme(raw_target).ok_or(Reject::NoTarget)?;
    let cut = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(cut);
    let target = split_authority(authority, Some(80))?;
    let path = if path.is_empty() { "/" } else { path };

    let mut out = String::with_capacity(head.len() + 32);
    out.push_str(method);
    out.push(' ');
    out.push_str(path);
    out.push(' ');
    out.push_str(version);
    out.push_str("\r\n");
    out.push_str("Host: ");
    out.push_str(&target.to_string());
    out.push_str("\r\n");

    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, _) = line.split_once(':').ok_or(Reject::Malformed)?;
        // 이름과 콜론 사이의 공백은 앞뒤 서버가 다르게 읽는 대표적인 스머글링
        // 벡터입니다. 이름 자체가 토큰이 아닌 경우도 같이 걸립니다
        if !is_token(name) {
            return Err(Reject::Malformed);
        }
        if DROPPED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    // 요청 하나마다 연결을 닫아 파이프라인된 뒷 요청이 판정 없이 같은 연결로
    // 흘러가지 않게 합니다
    out.push_str("Connection: close\r\n\r\n");

    Ok(Request::Forward {
        target,
        head: out.into_bytes(),
    })
}

/// `http://`만 벗겨 냅니다.
///
/// `https://`를 받지 않는 이유는 그 경우 프록시가 TLS를 직접 맺어야 하는데 v1이
/// 종단을 하지 않기 때문입니다. 클라이언트는 https에 CONNECT를 씁니다
fn strip_scheme(raw: &str) -> Option<&str> {
    let (scheme, rest) = raw.split_once("://")?;
    if scheme.eq_ignore_ascii_case("http") {
        Some(rest)
    } else {
        None
    }
}

/// `host:port` 또는 `[v6]:port` 형태를 가릅니다.
///
/// # Errors
/// 포트가 없는데 기본값도 주어지지 않았거나, 호스트가 규격을 벗어나면 거부합니다
fn split_authority(raw: &str, default_port: Option<u16>) -> Result<Target, Reject> {
    if raw.is_empty() {
        return Err(Reject::Malformed);
    }
    // userinfo는 목적지를 오인하게 만드는 고전적 수단이라 형태 자체를 거부합니다
    if raw.contains('@') {
        return Err(Reject::Malformed);
    }

    let (host, port_part) = if let Some(rest) = raw.strip_prefix('[') {
        let (inside, after) = rest.split_once(']').ok_or(Reject::Malformed)?;
        match after.strip_prefix(':') {
            Some(p) => (inside, Some(p)),
            None if after.is_empty() => (inside, None),
            None => return Err(Reject::Malformed),
        }
    } else {
        match raw.split_once(':') {
            // 대괄호 없는 다중 콜론은 v6 리터럴을 포트와 구분할 수 없습니다
            Some((h, p)) if !p.contains(':') => (h, Some(p)),
            Some(_) => return Err(Reject::Malformed),
            None => (raw, None),
        }
    };

    let port = match port_part {
        Some(p) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Reject::Malformed);
            }
            p.parse::<u16>().map_err(|_| Reject::Malformed)?
        }
        None => default_port.ok_or(Reject::Malformed)?,
    };
    if port == 0 {
        return Err(Reject::Malformed);
    }
    if !valid_host(host) {
        return Err(Reject::Malformed);
    }

    Ok(Target::new(host, port))
}

/// 호스트 문자열이 넘길 만한 형태인지 봅니다.
///
/// 정규화도 매칭도 하지 않습니다. 제어 문자와 구분자만 걸러 냅니다. 여기서
/// 소문자화 같은 변형을 하면 정책이 보는 문자열과 감사에 남는 문자열이 갈라집니다
fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOST {
        return false;
    }
    host.bytes().all(|b| {
        !b.is_ascii_control()
            && !b.is_ascii_whitespace()
            && !matches!(b, b'/' | b'\\' | b'@' | b'[' | b']' | b'#' | b'?' | b'%')
    })
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(s: &str) -> Vec<u8> {
        s.replace('\n', "\r\n").into_bytes()
    }

    #[test]
    fn connect_yields_the_authority() {
        let h = head("CONNECT api.anthropic.com:443 HTTP/1.1\nHost: api.anthropic.com:443\n\n");
        let r = parse_head(&h).expect("파싱 성공");
        assert_eq!(r.target(), &Target::new("api.anthropic.com", 443));
        assert!(matches!(r, Request::Connect(_)));
    }

    #[test]
    fn connect_without_a_port_is_refused() {
        // 기본 포트를 추측하면 판정한 포트와 실제 포트가 갈라집니다
        let h = head("CONNECT api.anthropic.com HTTP/1.1\n\n");
        assert_eq!(parse_head(&h), Err(Reject::Malformed));
    }

    #[test]
    fn connect_accepts_bracketed_v6() {
        let h = head("CONNECT [2606:4700::1]:443 HTTP/1.1\n\n");
        let r = parse_head(&h).expect("파싱 성공");
        assert_eq!(r.target(), &Target::new("2606:4700::1", 443));
    }

    #[test]
    fn bare_v6_without_brackets_is_refused() {
        let h = head("CONNECT 2606:4700::1:443 HTTP/1.1\n\n");
        assert_eq!(parse_head(&h), Err(Reject::Malformed));
    }

    #[test]
    fn origin_form_has_no_target() {
        let h = head("GET /path HTTP/1.1\nHost: example.com\n\n");
        assert_eq!(parse_head(&h), Err(Reject::NoTarget));
    }

    #[test]
    fn https_absolute_form_is_not_accepted() {
        // v1은 TLS를 종단하지 않으므로 https는 CONNECT로만 받습니다
        let h = head("GET https://example.com/x HTTP/1.1\n\n");
        assert_eq!(parse_head(&h), Err(Reject::NoTarget));
    }

    #[test]
    fn absolute_form_is_rewritten_to_origin_form() {
        let h = head("GET http://example.com/a?b=1 HTTP/1.1\nAccept: */*\n\n");
        let Request::Forward { target, head } = parse_head(&h).expect("파싱 성공") else {
            panic!("Forward 여야 함");
        };
        assert_eq!(target, Target::new("example.com", 80));
        let text = String::from_utf8(head).expect("utf8");
        assert!(text.starts_with("GET /a?b=1 HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("Accept: */*\r\n"), "{text}");
        assert!(text.ends_with("Connection: close\r\n\r\n"), "{text}");
    }

    #[test]
    fn absolute_form_without_a_path_gets_a_root_path() {
        let h = head("GET http://example.com HTTP/1.1\n\n");
        let Request::Forward { head, .. } = parse_head(&h).expect("파싱 성공") else {
            panic!("Forward 여야 함");
        };
        let text = String::from_utf8(head).expect("utf8");
        assert!(text.starts_with("GET / HTTP/1.1\r\n"), "{text}");
    }

    #[test]
    fn host_header_is_replaced_with_the_gated_authority() {
        // 판정한 authority와 목적지가 보는 Host가 다르면 vhost 라우팅이 갈라집니다
        let h = head("GET http://example.com/x HTTP/1.1\nHost: evil.test\n\n");
        let Request::Forward { head, .. } = parse_head(&h).expect("파싱 성공") else {
            panic!("Forward 여야 함");
        };
        let text = String::from_utf8(head).expect("utf8");
        assert!(text.contains("Host: example.com:80\r\n"), "{text}");
        assert!(!text.contains("evil.test"), "{text}");
    }

    #[test]
    fn hop_by_hop_headers_do_not_reach_the_origin() {
        let h = head(
            "GET http://example.com/x HTTP/1.1\nProxy-Authorization: Basic aaa\nProxy-Connection: keep-alive\nKeep-Alive: timeout=5\n\n",
        );
        let Request::Forward { head, .. } = parse_head(&h).expect("파싱 성공") else {
            panic!("Forward 여야 함");
        };
        let text = String::from_utf8(head).expect("utf8");
        assert!(!text.to_ascii_lowercase().contains("proxy-auth"), "{text}");
        assert!(
            !text.to_ascii_lowercase().contains("proxy-connection"),
            "{text}"
        );
        assert!(!text.to_ascii_lowercase().contains("keep-alive"), "{text}");
    }

    #[test]
    fn space_before_the_header_colon_is_refused() {
        // 앞뒤 서버가 다르게 읽는 대표적 스머글링 벡터입니다
        let h = head("GET http://example.com/x HTTP/1.1\nContent-Length : 5\n\n");
        assert_eq!(parse_head(&h), Err(Reject::Malformed));
    }

    #[test]
    fn folded_header_lines_are_refused() {
        let h = head("GET http://example.com/x HTTP/1.1\nX-A: 1\n  continued\n\n");
        assert_eq!(parse_head(&h), Err(Reject::Malformed));
    }

    #[test]
    fn userinfo_in_the_authority_is_refused() {
        let h = head("CONNECT user@evil.test:443 HTTP/1.1\n\n");
        assert_eq!(parse_head(&h), Err(Reject::Malformed));
    }

    #[test]
    fn an_extra_space_in_the_request_line_is_refused() {
        let h = head("GET http://example.com/x  HTTP/1.1\n\n");
        assert_eq!(parse_head(&h), Err(Reject::Malformed));
    }

    #[test]
    fn control_characters_in_the_host_are_refused() {
        let h = head("CONNECT exa\u{7}mple.com:443 HTTP/1.1\n\n");
        assert_eq!(parse_head(&h), Err(Reject::Malformed));
    }

    #[test]
    fn port_zero_is_refused() {
        let h = head("CONNECT example.com:0 HTTP/1.1\n\n");
        assert_eq!(parse_head(&h), Err(Reject::Malformed));
    }

    #[test]
    fn a_non_numeric_port_is_refused() {
        let h = head("CONNECT example.com:44a HTTP/1.1\n\n");
        assert_eq!(parse_head(&h), Err(Reject::Malformed));
    }

    #[test]
    fn a_port_above_the_range_is_refused() {
        let h = head("CONNECT example.com:70000 HTTP/1.1\n\n");
        assert_eq!(parse_head(&h), Err(Reject::Malformed));
    }

    #[test]
    fn an_oversized_head_is_rejected_as_too_large() {
        let mut s = String::from("CONNECT example.com:443 HTTP/1.1\r\n");
        for i in 0..4000 {
            s.push_str(&format!("X-Pad-{i}: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"));
        }
        s.push_str("\r\n");
        assert_eq!(parse_head(s.as_bytes()), Err(Reject::TooLarge));
    }

    #[test]
    fn a_non_utf8_head_is_refused() {
        assert_eq!(parse_head(&[0xff, 0xfe, 0x00]), Err(Reject::Malformed));
    }

    #[test]
    fn unknown_methods_still_need_an_absolute_target() {
        let h = head("PROPFIND /x HTTP/1.1\n\n");
        assert_eq!(parse_head(&h), Err(Reject::NoTarget));
    }

    #[test]
    fn reject_maps_to_a_status_line() {
        assert!(Reject::Malformed.status_line().contains("400"));
        assert!(Reject::NoTarget.status_line().contains("400"));
        assert!(Reject::TooLarge.status_line().contains("431"));
    }
}
