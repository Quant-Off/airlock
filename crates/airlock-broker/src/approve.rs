use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};

use airlock_audit::Granted;
use airlock_policy::MatchedRule;

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

#[derive(Debug)]
pub struct TtyApprover;

impl TtyApprover {
    pub fn available() -> bool {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
    }
}

/// 승인 화면에 그대로 넣으면 화면을 다시 칠하거나 글자 순서를 뒤집을 수 있는 문자인지 봅니다.
///
/// 제어 문자와 양방향 텍스트 재정렬 문자가 대상입니다. 경로와 argv는 신뢰할 수 없는
/// 입력이므로 여기를 통과하지 않으면 승인 프롬프트 자체가 위조 가능해집니다
fn is_display_unsafe(ch: char) -> bool {
    ch.is_control()
        || matches!(ch,
            '\u{200E}' | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}')
}

fn sanitize(value: &str) -> String {
    if !value.chars().any(is_display_unsafe) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if is_display_unsafe(ch) {
            out.push_str(&format!("\\u{{{:04x}}}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
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
        "/dev/tty 인라인 프롬프트".to_string()
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
