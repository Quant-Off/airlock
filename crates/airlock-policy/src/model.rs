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

/// egress 규칙과 질의에 붙는 프로토콜 축입니다.
///
/// 태그는 `airlock-audit`의 같은 이름 타입과 번호를 맞춥니다. 2는 감사 층의 `udp`
/// 자리라 비워 둡니다. 정책 어휘에는 아직 UDP가 없고, 번호가 어긋나면 감사 로그와
/// 정책이 같은 값을 다르게 부르게 됩니다
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Tls,
    Http,
}

impl Protocol {
    pub const ALL: [Protocol; 3] = [Self::Tcp, Self::Tls, Self::Http];

    pub fn tag(self) -> u8 {
        match self {
            Self::Tcp => 1,
            Self::Tls => 3,
            Self::Http => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Http => "http",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Self::Tcp),
            "tls" => Some(Self::Tls),
            "http" => Some(Self::Http),
            _ => None,
        }
    }

    /// 본문이 경계 밖에서 그대로 보이는 프로토콜인지 봅니다.
    ///
    /// `tcp`는 관측 층이 아무것도 모른다는 뜻이므로 평문으로 단정하지 않습니다.
    /// 모르는 것을 안다고 기록하면 감사 로그가 거짓 보증을 합니다
    pub fn is_plaintext(self) -> bool {
        matches!(self, Self::Http)
    }
}

impl fmt::Display for Protocol {
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
    /// 평문 아웃바운드가 넘을 수 없는 상한입니다.
    ///
    /// 다른 셋과 달리 "매칭되는 규칙이 없을 때의 답"이 아닙니다. 어떤 규칙이 답했든
    /// 그 위에 한 번 더 씌웁니다 (`docs/policy-dsl.md` 8.2절)
    pub egress_plaintext: Action,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            file: Action::Ask,
            exec: Action::Ask,
            egress: Action::Deny,
            egress_plaintext: Action::Deny,
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
    fn default_plaintext_egress_is_deny() {
        assert_eq!(Defaults::default().egress_plaintext, Action::Deny);
    }

    #[test]
    fn protocol_tags_match_audit_protocol_tags() {
        // airlock-audit 의 tagged_enum!(Protocol) 과 같은 번호여야 합니다.
        // 2 는 감사 층의 udp 자리이므로 비어 있습니다
        assert_eq!(Protocol::Tcp.tag(), 1);
        assert_eq!(Protocol::Tls.tag(), 3);
        assert_eq!(Protocol::Http.tag(), 4);
        assert!(Protocol::ALL.iter().all(|p| p.tag() != 2));
    }

    #[test]
    fn protocol_parse_rejects_unknown() {
        assert_eq!(Protocol::parse("http"), Some(Protocol::Http));
        assert_eq!(Protocol::parse("tls"), Some(Protocol::Tls));
        assert_eq!(Protocol::parse("tcp"), Some(Protocol::Tcp));
        assert_eq!(Protocol::parse("udp"), None);
        assert_eq!(Protocol::parse("HTTP"), None);
        assert_eq!(Protocol::parse("https"), None);
    }

    #[test]
    fn only_http_counts_as_plaintext() {
        assert!(Protocol::Http.is_plaintext());
        assert!(!Protocol::Tls.is_plaintext());
        // tcp 는 "모른다"는 뜻이지 "평문이다"가 아닙니다
        assert!(!Protocol::Tcp.is_plaintext());
    }

    #[test]
    fn protocol_round_trips_through_str() {
        for p in Protocol::ALL {
            assert_eq!(Protocol::parse(p.as_str()), Some(p));
            assert_eq!(p.to_string(), p.as_str());
        }
    }

    #[test]
    fn tier_order_puts_self_protect_first() {
        assert!(Tier::SelfProtect < Tier::User);
        assert!(Tier::User < Tier::Baseline);
    }
}
