use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    Allow,
    Ask,
    Deny,
    Forbid,
}

impl Action {
    pub fn tag(self) -> u8 {
        match self {
            Self::Allow => 1,
            Self::Deny => 2,
            Self::Ask => 3,
            Self::Forbid => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
            Self::Forbid => "forbid",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "ask" => Some(Self::Ask),
            "deny" => Some(Self::Deny),
            "forbid" => Some(Self::Forbid),
            _ => None,
        }
    }

    pub fn is_restrictive(self) -> bool {
        !matches!(self, Self::Allow)
    }

    pub fn blocks(self) -> bool {
        matches!(self, Self::Deny | Self::Forbid)
    }

    pub fn more_restrictive(self, other: Self) -> Self {
        if other > self { other } else { self }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    File,
    Exec,
    Egress,
}

impl Kind {
    pub fn tag(self) -> u8 {
        match self {
            Self::File => 1,
            Self::Exec => 2,
            Self::Egress => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Exec => "exec",
            Self::Egress => "egress",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "file" => Some(Self::File),
            "exec" => Some(Self::Exec),
            "egress" => Some(Self::Egress),
            _ => None,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileMode {
    Read,
    Write,
    Create,
    Delete,
    Metadata,
    Exec,
}

impl FileMode {
    pub const ALL: [FileMode; 6] = [
        Self::Read,
        Self::Write,
        Self::Create,
        Self::Delete,
        Self::Metadata,
        Self::Exec,
    ];

    pub fn tag(self) -> u8 {
        match self {
            Self::Read => 1,
            Self::Write => 2,
            Self::Create => 3,
            Self::Delete => 4,
            Self::Metadata => 5,
            Self::Exec => 6,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Create => "create",
            Self::Delete => "delete",
            Self::Metadata => "metadata",
            Self::Exec => "exec",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "create" => Some(Self::Create),
            "delete" => Some(Self::Delete),
            "metadata" => Some(Self::Metadata),
            "exec" => Some(Self::Exec),
            _ => None,
        }
    }

    fn bit(self) -> u8 {
        1u8 << (self.tag() - 1)
    }
}

impl fmt::Display for FileMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModeSet(u8);

impl ModeSet {
    pub const ALL: Self = Self(0b0011_1111);

    pub fn empty() -> Self {
        Self(0)
    }

    pub fn from_modes(modes: &[FileMode]) -> Self {
        let mut mask = 0u8;
        for m in modes {
            mask |= m.bit();
        }
        Self(mask)
    }

    pub fn contains(self, m: FileMode) -> bool {
        self.0 & m.bit() != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub fn is_all(self) -> bool {
        self == Self::ALL
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn iter(self) -> impl Iterator<Item = FileMode> {
        FileMode::ALL.into_iter().filter(move |m| self.contains(*m))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    SelfProtect,
    User,
    Baseline,
}

impl Tier {
    pub fn tag(self) -> u8 {
        match self {
            Self::SelfProtect => 0,
            Self::User => 1,
            Self::Baseline => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfProtect => "self-protect",
            Self::User => "user",
            Self::Baseline => "baseline",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Defaults {
    pub file: Action,
    pub exec: Action,
    pub egress: Action,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            file: Action::Ask,
            exec: Action::Ask,
            egress: Action::Deny,
        }
    }
}

impl Defaults {
    pub fn for_kind(&self, kind: Kind) -> Action {
        match kind {
            Kind::File => self.file,
            Kind::Exec => self.exec,
            Kind::Egress => self.egress,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restrictiveness_ordering() {
        assert!(Action::Forbid > Action::Deny);
        assert!(Action::Deny > Action::Ask);
        assert!(Action::Ask > Action::Allow);
    }

    #[test]
    fn more_restrictive_picks_the_stricter_side() {
        assert_eq!(Action::Allow.more_restrictive(Action::Deny), Action::Deny);
        assert_eq!(Action::Deny.more_restrictive(Action::Allow), Action::Deny);
        assert_eq!(Action::Ask.more_restrictive(Action::Forbid), Action::Forbid);
        assert_eq!(Action::Allow.more_restrictive(Action::Allow), Action::Allow);
    }

    #[test]
    fn tags_match_audit_decision_tags() {
        assert_eq!(Action::Allow.tag(), 1);
        assert_eq!(Action::Deny.tag(), 2);
        assert_eq!(Action::Ask.tag(), 3);
        assert_eq!(Action::Forbid.tag(), 4);
    }

    #[test]
    fn action_parse_rejects_unknown() {
        assert_eq!(Action::parse("deny"), Some(Action::Deny));
        assert_eq!(Action::parse("maybe"), None);
        assert_eq!(Action::parse("Deny"), None);
    }

    #[test]
    fn mode_set_all_contains_every_mode() {
        for m in FileMode::ALL {
            assert!(ModeSet::ALL.contains(m), "{m} 누락");
        }
        assert!(ModeSet::ALL.is_all());
        assert_eq!(ModeSet::ALL.iter().count(), 6);
    }

    #[test]
    fn mode_set_selective() {
        let s = ModeSet::from_modes(&[FileMode::Read, FileMode::Exec]);
        assert!(s.contains(FileMode::Read));
        assert!(s.contains(FileMode::Exec));
        assert!(!s.contains(FileMode::Write));
        assert!(!s.is_all());
        assert!(!s.is_empty());
    }

    #[test]
    fn empty_mode_set_matches_nothing() {
        let s = ModeSet::empty();
        assert!(s.is_empty());
        for m in FileMode::ALL {
            assert!(!s.contains(m));
        }
    }

    #[test]
    fn default_egress_is_deny() {
        let d = Defaults::default();
        assert_eq!(d.egress, Action::Deny);
        assert_eq!(d.for_kind(Kind::Egress), Action::Deny);
        assert_eq!(d.for_kind(Kind::File), Action::Ask);
    }

    #[test]
    fn tier_order_puts_self_protect_first() {
        assert!(Tier::SelfProtect < Tier::User);
        assert!(Tier::User < Tier::Baseline);
    }
}
