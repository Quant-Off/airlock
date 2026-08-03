//! 이 모듈은 `ask` 결정을 사람에게 물어 답을 받습니다.
//!
//! # Features
//! 프롬프트는 에이전트의 stdin·stdout과 분리된 `/dev/tty`로 직접 나갑니다
//! (`docs/design.md` 9.4). 화면에 넣는 값은 전부 브로커가 관측한 사실이며, 제어 문자와
//! 양방향 재정렬 문자는 보이는 형태로 바꿔 프롬프트 위조를 막습니다.
//!
//! 응답에는 상한 시간이 있습니다. 답이 오지 않으면 `TimedOut`으로 거부합니다. Linux
//! 중계 중에는 감독 스레드가 세션 잠금을 쥔 채 묻기 때문에, 상한이 없으면 답하지 않는
//! 동안 자식의 모든 exec과 연결이 함께 멈춥니다

use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use airlock_audit::Granted;
use airlock_canonical::display::sanitize;
use airlock_policy::MatchedRule;

/// 사람 응답을 기다리는 기본 상한.
///
/// 자리를 비운 사이 세션이 영구히 멈추지 않을 만큼 짧고, 승인 화면을 읽고 판단할 만큼
/// 깁니다. 만료는 거부로 처리하며 그 사실이 감사 로그에 `timed_out`으로 남습니다
pub const DEFAULT_ASK_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub headline: String,
    pub facts: Vec<(String, String)>,
    pub rule: Option<MatchedRule>,
}

impl ApprovalRequest {
    pub fn new(headline: impl Into<String>) -> Self {
        Self {
            headline: headline.into(),
            facts: Vec::new(),
            rule: None,
        }
    }

    pub fn fact(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.facts.push((label.into(), value.into()));
        self
    }

    pub fn with_rule(mut self, rule: Option<MatchedRule>) -> Self {
        self.rule = rule;
        self
    }
}

pub trait Approver: fmt::Debug + Send {
    fn ask(&mut self, request: &ApprovalRequest) -> Granted;
    fn describe(&self) -> String;

    fn note(&self) -> Option<String> {
        None
    }
}

#[derive(Debug, Default)]
pub struct RefuseAll {
    pub why: String,
}

impl Approver for RefuseAll {
    fn ask(&mut self, _request: &ApprovalRequest) -> Granted {
        Granted::Refused
    }

    fn describe(&self) -> String {
        if self.why.is_empty() {
            "비대화형 (모든 ask 거부)".to_string()
        } else {
            format!("비대화형 (모든 ask 거부): {}", self.why)
        }
    }
}

#[derive(Debug, Default)]
pub struct ApproveAll;

impl Approver for ApproveAll {
    fn ask(&mut self, _request: &ApprovalRequest) -> Granted {
        Granted::Approved
    }

    fn describe(&self) -> String {
        "자동 승인 (사람 판단 없음)".to_string()
    }

    fn note(&self) -> Option<String> {
        Some("자동 승인. 사람이 검토하지 않음".to_string())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TtyApprover {
    timeout: Duration,
}

impl Default for TtyApprover {
    fn default() -> Self {
        Self::new()
    }
}

impl TtyApprover {
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_ASK_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn available() -> bool {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
    }
}

/// fd에 읽을 것이 생길 때까지 기다립니다.
///
/// 만료되면 `false`입니다. 시그널로 깨어나면 남은 시간을 다시 계산해 이어 기다리므로,
/// 시그널이 반복될 때 상한이 늘어나지 않습니다
///
/// # Safety
/// `poll`은 `pollfd` 한 칸과 밀리초 상한만 받으며 fd 소유권을 가져가지 않습니다.
/// 호출자가 살아 있는 fd를 넘겨야 합니다
fn wait_readable(fd: RawFd, timeout: Duration) -> bool {
    let deadline = Instant::now().checked_add(timeout);
    loop {
        let remaining = match deadline {
            Some(d) => d.saturating_duration_since(Instant::now()),
            None => timeout,
        };
        if remaining.is_zero() {
            return false;
        }
        let ms = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&raw mut pfd, 1, ms) };
        if rc > 0 {
            return true;
        }
        if rc == 0 {
            return false;
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            // poll 자체가 실패하면 기다릴 방법이 없습니다. 만료와 같이 처리합니다
            return false;
        }
    }
}

fn render(request: &ApprovalRequest) -> String {
    let mut out = String::new();
    out.push_str("\n\x1b[1;33m┌─ airlock 승인 요청 ─────────────────────────────\x1b[0m\n");
    out.push_str(&format!(
        "\x1b[1;33m│\x1b[0m {}\n",
        sanitize(&request.headline)
    ));
    out.push_str("\x1b[1;33m│\x1b[0m\n");
    let width = request
        .facts
        .iter()
        .map(|(l, _)| l.chars().count())
        .max()
        .unwrap_or(0);
    for (label, value) in &request.facts {
        let pad = " ".repeat(width.saturating_sub(label.chars().count()));
        out.push_str(&format!(
            "\x1b[1;33m│\x1b[0m {}{pad}  {}\n",
            sanitize(label),
            sanitize(value)
        ));
    }
    if let Some(rule) = &request.rule {
        let pad = " ".repeat(width.saturating_sub(2));
        out.push_str(&format!(
            "\x1b[1;33m│\x1b[0m 규칙{pad}  {} ({} tier, {})\n",
            sanitize(&rule.id),
            rule.tier,
            sanitize(&rule.pattern)
        ));
        if let Some(reason) = &rule.reason {
            let pad = " ".repeat(width.saturating_sub(2));
            out.push_str(&format!(
                "\x1b[1;33m│\x1b[0m 근거{pad}  {}\n",
                sanitize(reason)
            ));
        }
    }
    out.push_str("\x1b[1;33m│\x1b[0m\n");
    out.push_str(
        "\x1b[1;33m│\x1b[0m \x1b[2m위 내용은 브로커가 직접 관측한 사실이며 에이전트가 제공한 설명이 아님\x1b[0m\n",
    );
    out.push_str("\x1b[1;33m└─────────────────────────────────────────────────\x1b[0m\n");
    out.push_str("허용하겠습니까? [y/N] ");
    out
}

impl Approver for TtyApprover {
    fn ask(&mut self, request: &ApprovalRequest) -> Granted {
        let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
            return Granted::Refused;
        };
        if tty.write_all(render(request).as_bytes()).is_err() {
            return Granted::Refused;
        }
        let _ = tty.flush();

        let Ok(read_side) = tty.try_clone() else {
            return Granted::Refused;
        };
        if !wait_readable(read_side.as_raw_fd(), self.timeout) {
            let _ = tty.write_all("\x1b[31m시간 초과 거부\x1b[0m\n\n".as_bytes());
            return Granted::TimedOut;
        }
        let mut reader = BufReader::new(read_side);
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => Granted::TimedOut,
            Ok(_) => {
                let answer = line.trim().to_ascii_lowercase();
                let granted = matches!(answer.as_str(), "y" | "yes");
                let _ = tty.write_all(
                    if granted {
                        "\x1b[32m허용\x1b[0m\n\n"
                    } else {
                        "\x1b[31m거부\x1b[0m\n\n"
                    }
                    .as_bytes(),
                );
                if granted {
                    Granted::Approved
                } else {
                    Granted::Refused
                }
            }
            Err(_) => Granted::Refused,
        }
    }

    fn describe(&self) -> String {
        format!(
            "/dev/tty 인라인 프롬프트 (응답 상한 {}초, 초과 시 거부)",
            self.timeout.as_secs()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use airlock_policy::{Action, Tier};

    fn request() -> ApprovalRequest {
        ApprovalRequest::new("파일 쓰기 시도")
            .fact("경로", "/Users/me/.zshrc")
            .fact("해소", "/Users/me/.zshrc")
            .fact("모드", "write")
            .with_rule(Some(MatchedRule {
                id: "shell-init-write".into(),
                tier: Tier::Baseline,
                action: Action::Ask,
                pattern: "~/.zshrc".into(),
                reason: Some("지속성 확보 경로".into()),
            }))
    }

    #[test]
    fn refuse_all_never_approves() {
        let mut a = RefuseAll::default();
        assert_eq!(a.ask(&request()), Granted::Refused);
    }

    #[test]
    fn rendered_prompt_shows_observed_facts_only() {
        let text = render(&request());
        assert!(text.contains("/Users/me/.zshrc"));
        assert!(text.contains("shell-init-write"));
        assert!(text.contains("지속성 확보 경로"));
        assert!(
            text.contains("에이전트가 제공한 설명이 아님"),
            "승인 피싱 방어 문구가 있어야 함"
        );
        assert!(text.ends_with("[y/N] "), "프롬프트가 입력 대기로 끝나야 함");
    }

    #[test]
    fn prompt_default_is_refusal() {
        let text = render(&request());
        assert!(
            text.contains("[y/N]"),
            "기본값이 거부임을 프롬프트가 드러내야 함"
        );
    }

    #[test]
    fn waiting_gives_up_when_nothing_arrives() {
        let mut fds = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let started = Instant::now();
        let ready = wait_readable(fds[0], Duration::from_millis(80));
        let waited = started.elapsed();
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        assert!(!ready, "아무것도 오지 않았는데 준비됨으로 봤음");
        assert!(
            waited >= Duration::from_millis(60),
            "상한을 기다리지 않고 즉시 돌아왔음: {waited:?}"
        );
        assert!(
            waited < Duration::from_secs(5),
            "상한을 넘겨 기다렸음: {waited:?}"
        );
    }

    #[test]
    fn waiting_returns_as_soon_as_input_arrives() {
        let mut fds = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let byte = b"y\n";
        assert_eq!(
            unsafe { libc::write(fds[1], byte.as_ptr().cast(), byte.len()) },
            2
        );
        let ready = wait_readable(fds[0], Duration::from_secs(30));
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        assert!(ready, "이미 입력이 있는데 기다리기만 했음");
    }

    #[test]
    fn tty_approver_declares_its_timeout() {
        let a = TtyApprover::new().with_timeout(Duration::from_secs(42));
        assert!(a.describe().contains("42"), "{}", a.describe());
        assert!(
            TtyApprover::new().timeout > Duration::ZERO,
            "상한이 없으면 감독 스레드가 세션 잠금을 쥔 채 영구히 멈춤"
        );
    }

    #[test]
    fn facts_are_aligned_by_longest_label() {
        let req = ApprovalRequest::new("t")
            .fact("경로", "/a")
            .fact("긴라벨이야", "/b");
        let text = render(&req);
        assert!(text.contains("긴라벨이야  /b"));
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;

    #[test]
    fn control_sequences_cannot_repaint_the_prompt() {
        let req = ApprovalRequest::new("프로세스 실행 시도")
            .fact("argv", "[\"sh\", \"\x1b[2J\x1b[H허용됨\n승인 완료\"]");
        let out = render(&req);
        assert!(
            !out.contains("\x1b[2J"),
            "화면 지우기 시퀀스가 살아남으면 승인 화면을 위조할 수 있음"
        );
        assert!(
            !out.contains("\x1b[H"),
            "커서 이동 시퀀스가 살아남으면 승인 화면을 덮어쓸 수 있음"
        );
        assert!(
            out.contains("\\u{001b}"),
            "제어 문자가 보이는 형태로 남아야 함: {out}"
        );
        assert!(
            out.matches('\n').count()
                == render(&ApprovalRequest::new("프로세스 실행 시도").fact("argv", "x"))
                    .matches('\n')
                    .count(),
            "값에 든 개행이 줄 수를 바꾸면 프롬프트 구조가 무너짐"
        );
    }

    #[test]
    fn bidi_override_is_neutralized() {
        let req = ApprovalRequest::new("파일 접근 시도").fact("요청 경로", "/tmp/\u{202E}gnp.exe");
        let out = render(&req);
        assert!(out.contains("\\u{202e}"), "{out}");
        assert!(!out.contains('\u{202E}'));
    }

    #[test]
    fn ordinary_paths_are_untouched() {
        let req = ApprovalRequest::new("파일 접근 시도").fact("요청 경로", "/Users/me/.ssh/config");
        let out = render(&req);
        assert!(out.contains("/Users/me/.ssh/config"), "{out}");
    }
}
