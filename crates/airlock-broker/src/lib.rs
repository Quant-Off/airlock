pub mod approve;
pub mod enforcer;
pub mod error;
pub mod profile;
pub mod sbpl;
pub mod session;

#[cfg(target_os = "macos")]
pub mod seatbelt;

#[cfg(target_os = "linux")]
pub mod landlock;

#[cfg(target_os = "linux")]
pub mod notify;

pub use airlock_audit::Mediation;
pub use approve::{
    ApprovalRequest, ApproveAll, Approver, DEFAULT_ASK_TIMEOUT, RefuseAll, TtyApprover,
};
pub use enforcer::{Enforcer, ObserveEnforcer, default_enforcer};
pub use error::{BrokerError, Result};
pub use profile::{GeneratedProfile, ProfileOptions};
pub use session::{
    Outcome, RunReport, Session, SessionConfig, effective_mediation, mediation_gaps, run, which,
};

#[cfg(target_os = "macos")]
pub use seatbelt::{SeatbeltEnforcer, Strategy};

#[cfg(target_os = "linux")]
pub use landlock::LandlockEnforcer;
