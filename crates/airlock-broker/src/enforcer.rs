use std::fmt;
use std::process::Command;

use airlock_audit::Enforcement;
use airlock_policy::Policy;

use crate::error::Result;

pub trait Enforcer: fmt::Debug {
    fn kind(&self) -> Enforcement;
    fn describe(&self) -> String;
    fn prepare(&mut self, policy: &Policy) -> Result<()>;
    fn wrap(&self, cmd: &mut Command) -> Result<()>;

    fn enforces(&self) -> bool {
        self.kind().enforces()
    }

    fn gaps(&self) -> Vec<String> {
        Vec::new()
    }
}

#[derive(Debug, Default)]
pub struct ObserveEnforcer;

impl Enforcer for ObserveEnforcer {
    fn kind(&self) -> Enforcement {
        Enforcement::Observe
    }

    fn describe(&self) -> String {
        "observe (강제 없음, 기록만)".to_string()
    }

    fn prepare(&mut self, _policy: &Policy) -> Result<()> {
        Ok(())
    }

    fn wrap(&self, _cmd: &mut Command) -> Result<()> {
        Ok(())
    }

    fn gaps(&self) -> Vec<String> {
        vec![
            "커널 강제 없음, 정책 위반이 기록되지만 차단되지 않음".to_string(),
            "브로커를 경유하지 않는 직접 파일 접근은 관측되지 않음".to_string(),
        ]
    }
}

pub fn default_enforcer() -> Box<dyn Enforcer> {
    #[cfg(target_os = "macos")]
    {
        Box::new(crate::seatbelt::SeatbeltEnforcer::new())
    }
    #[cfg(target_os = "linux")]
    {
        if crate::landlock::LandlockEnforcer::available() {
            Box::new(crate::landlock::LandlockEnforcer::new())
        } else {
            Box::new(ObserveEnforcer)
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Box::new(ObserveEnforcer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use airlock_policy::LoadContext;

    #[test]
    fn observe_reports_that_it_does_not_enforce() {
        let e = ObserveEnforcer;
        assert_eq!(e.kind(), Enforcement::Observe);
        assert!(!e.enforces());
        assert!(
            !e.gaps().is_empty(),
            "강제하지 않는 백엔드는 그 한계를 반드시 노출해야 함"
        );
    }

    #[test]
    fn observe_does_not_modify_the_command() {
        let ctx = LoadContext::new("/Users/me", "/tmp/audit");
        let policy = Policy::baseline_only(&ctx).unwrap();
        let mut e = ObserveEnforcer;
        e.prepare(&policy).unwrap();

        let mut cmd = Command::new("/bin/echo");
        cmd.arg("hi");
        e.wrap(&mut cmd).unwrap();
        assert_eq!(cmd.get_program(), "/bin/echo");
        assert_eq!(cmd.get_args().count(), 1);
    }
}
