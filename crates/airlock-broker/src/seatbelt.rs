#![cfg(target_os = "macos")]

use std::ffi::{CString, c_char, c_int};
use std::process::Command;

use airlock_audit::Enforcement;
use airlock_policy::Policy;

use crate::enforcer::Enforcer;
use crate::error::{BrokerError, Result};
use crate::profile::{self, ProfileOptions};

// # Safety
// libSystem이 노출하는 Seatbelt C 심볼의 선언입니다. 시그니처가 실제 ABI와
// 어긋나면 호출 즉시 정의되지 않은 동작이 되기 때문에 sandbox.h 원형을 그대로 사용합니다.
// sandbox_init_with_parameters는 10.8부터 deprecated 지만 계속 동작하며
// 서명도 entitlement도 요구하지 않습니다.
unsafe extern "C" {
    fn sandbox_init_with_parameters(
        profile: *const c_char,
        flags: u64,
        parameters: *const *const c_char,
        errorbuf: *mut *mut c_char,
    ) -> c_int;

    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// 프로파일을 자식 프로세스에 거는 방식.
///
/// `SandboxInit`이 기본이며 `docs/design.md` 10.3이 정한 경로입니다. `SandboxExec`는
/// 생성된 SBPL을 Apple 자신의 `sandbox-exec`로 교차 검증하기 위한 경로이며,
/// 프로파일 전문이 argv에 실려 `ps`로 보이므로 정책 내용이 노출됩니다.
/// CLI는 이 방식을 선택하지 않습니다
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    SandboxInit,
    SandboxExec,
}

#[derive(Debug)]
pub struct SeatbeltEnforcer {
    options: ProfileOptions,
    strategy: Strategy,
    compiled: Option<CString>,
    untranslatable: Vec<String>,
    denied_overrides: Vec<String>,
}

impl Default for SeatbeltEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl SeatbeltEnforcer {
    pub fn new() -> Self {
        Self {
            options: ProfileOptions::default(),
            strategy: Strategy::SandboxInit,
            compiled: None,
            untranslatable: Vec::new(),
            denied_overrides: Vec::new(),
        }
    }

    pub fn with_options(mut self, options: ProfileOptions) -> Self {
        self.options = options;
        self
    }

    pub fn with_strategy(mut self, strategy: Strategy) -> Self {
        self.strategy = strategy;
        self
    }

    pub fn profile_text(&self) -> Option<&str> {
        self.compiled.as_ref().and_then(|c| c.to_str().ok())
    }
}

/// # Safety
/// `profile`은 `null` 종료된 유효한 SBPL 문자열을 가리켜야 합니다.
/// 반환값이 0이 아니면 커널이 프로파일 적용을 거부한 것입니다.
unsafe fn apply_profile(profile: &CString) -> std::io::Result<()> {
    let mut errbuf: *mut c_char = std::ptr::null_mut();
    let rc = unsafe {
        sandbox_init_with_parameters(profile.as_ptr(), 0, std::ptr::null(), &raw mut errbuf)
    };
    if rc == 0 {
        if !errbuf.is_null() {
            unsafe { sandbox_free_error(errbuf) };
        }
        return Ok(());
    }
    if !errbuf.is_null() {
        unsafe { sandbox_free_error(errbuf) };
    }
    Err(std::io::Error::other(
        "sandbox_init_with_parameters가 프로파일 적용을 거부함",
    ))
}

impl Enforcer for SeatbeltEnforcer {
    fn kind(&self) -> Enforcement {
        Enforcement::Seatbelt
    }

    fn describe(&self) -> String {
        match self.strategy {
            Strategy::SandboxInit => "seatbelt (sandbox_init_with_parameters)".to_string(),
            Strategy::SandboxExec => "seatbelt (sandbox-exec)".to_string(),
        }
    }

    fn prepare(&mut self, policy: &Policy) -> Result<()> {
        let generated = profile::generate(policy, &self.options);
        self.untranslatable = generated.untranslatable;
        self.denied_overrides = policy
            .user_rules()
            .iter()
            .filter(|r| {
                r.overrides.is_some() && matches!(r.matcher, airlock_policy::Matcher::File { .. })
            })
            .map(|r| r.id.clone())
            .collect();
        let text = CString::new(generated.text).map_err(|_| BrokerError::EnforcerUnavailable {
            name: "seatbelt",
            why: "프로파일에 null 바이트 존재".to_string(),
        })?;
        self.compiled = Some(text);
        Ok(())
    }

    fn wrap(&self, cmd: &mut Command) -> Result<()> {
        let Some(profile) = self.compiled.clone() else {
            return Err(BrokerError::EnforcerUnavailable {
                name: "seatbelt",
                why: "prepare가 먼저 호출되지 않음".to_string(),
            });
        };

        match self.strategy {
            Strategy::SandboxInit => {
                use std::os::unix::process::CommandExt;
                // # Safety
                // pre_exec은 fork 이후 exec 이전의 자식에서 실행됩니다. 이 시점에는
                // async-signal-safe 하지 않은 호출이 원칙적으로 금지되지만,
                // 브로커는 spawn 시점에 단일 스레드이므로 malloc 락 경합이 없습니다.
                // 프로파일 문자열은 fork 전에 CString으로 만들어 두어 자식에서
                // 새 할당 없이 포인터만 넘깁니다.
                unsafe {
                    cmd.pre_exec(move || apply_profile(&profile));
                }
                Ok(())
            }
            Strategy::SandboxExec => {
                let text = profile
                    .to_str()
                    .map_err(|_| BrokerError::EnforcerUnavailable {
                        name: "seatbelt",
                        why: "프로파일이 UTF-8이 아님".to_string(),
                    })?
                    .to_string();
                let program = cmd.get_program().to_os_string();
                let args: Vec<std::ffi::OsString> =
                    cmd.get_args().map(|a| a.to_os_string()).collect();

                let mut wrapped = Command::new("/usr/bin/sandbox-exec");
                wrapped.arg("-p").arg(text).arg(&program).args(&args);
                if let Some(dir) = cmd.get_current_dir() {
                    wrapped.current_dir(dir);
                }
                *cmd = wrapped;
                Ok(())
            }
        }
    }

    fn gaps(&self) -> Vec<String> {
        let mut gaps = vec![
            "호스트 단위 egress 정책은 Seatbelt로 강제되지 않음. 프록시 층이 필요함".to_string(),
            profile::ask_rules_are_denied_note().to_string(),
            "커널이 거부한 개별 파일·네트워크 접근은 감사 로그에 남지 않음. \
             체인에는 세션 단위 기록만 있음"
                .to_string(),
        ];
        if !self.untranslatable.is_empty() {
            gaps.push(format!(
                "프로파일로 옮기지 못한 규칙: {}",
                self.untranslatable.join(", ")
            ));
        }
        if !self.denied_overrides.is_empty() {
            gaps.push(format!(
                "override 완화는 커널 프로파일에 반영되지 않아 해당 경로가 커널에서 여전히 차단됨: {}",
                self.denied_overrides.join(", ")
            ));
        }
        if self.strategy == Strategy::SandboxExec {
            gaps.push(
                "sandbox-exec 방식은 프로파일 전문을 argv로 넘기므로 같은 머신의 \
                 다른 프로세스가 ps로 정책 내용을 읽을 수 있음. 교차 검증 전용임"
                    .to_string(),
            );
        }
        gaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use airlock_policy::LoadContext;

    fn policy() -> Policy {
        let ctx = LoadContext::new("/Users/me", "/tmp/airlock-audit");
        Policy::baseline_only(&ctx).unwrap()
    }

    #[test]
    fn prepare_compiles_a_profile() {
        let mut e = SeatbeltEnforcer::new();
        e.prepare(&policy()).unwrap();
        let text = e.profile_text().expect("프로파일 없음");
        assert!(text.contains("(deny default)"));
    }

    #[test]
    fn wrap_before_prepare_is_an_error() {
        let e = SeatbeltEnforcer::new();
        let mut cmd = Command::new("/bin/echo");
        assert!(matches!(
            e.wrap(&mut cmd),
            Err(BrokerError::EnforcerUnavailable { .. })
        ));
    }

    #[test]
    fn seatbelt_declares_its_enforcement_gaps() {
        let e = SeatbeltEnforcer::new();
        assert!(e.enforces());
        let gaps = e.gaps();
        assert!(gaps.iter().any(|g| g.contains("egress")));
        assert!(gaps.iter().any(|g| g.contains("ask")));
    }

    #[test]
    fn override_relaxations_are_declared_as_a_gap() {
        let ctx = LoadContext::new("/Users/me", "/tmp/airlock-audit");
        let src = r#"
version = 1
[[rules]]
id = "ci-env"
kind = "file"
path = "~/work/ci/.env"
action = "allow"
overrides = "env-files"
reason = "CI 로컬 재현에 필요"
"#;
        let p = Policy::load_str(src, &ctx).unwrap();
        let mut e = SeatbeltEnforcer::new();
        e.prepare(&p).unwrap();
        assert!(
            e.gaps().iter().any(|g| g.contains("ci-env")),
            "커널이 존중하지 않는 완화는 스스로 표시해야 함"
        );
    }

    #[test]
    fn sandbox_exec_strategy_rewrites_the_command() {
        let mut e = SeatbeltEnforcer::new().with_strategy(Strategy::SandboxExec);
        e.prepare(&policy()).unwrap();
        let mut cmd = Command::new("/bin/echo");
        cmd.arg("hi");
        e.wrap(&mut cmd).unwrap();
        assert_eq!(cmd.get_program(), "/usr/bin/sandbox-exec");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args.first().map(String::as_str), Some("-p"));
        assert!(args.iter().any(|a| a == "/bin/echo"));
        assert!(args.iter().any(|a| a == "hi"));
    }
}
