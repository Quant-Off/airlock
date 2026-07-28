use airlock_canonical::hex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! hex_newtype {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const LEN: usize = $len;
            pub const ZERO: Self = Self([0u8; $len]);

            pub const fn from_bytes(b: [u8; $len]) -> Self {
                Self(b)
            }

            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub fn to_hex(&self) -> String {
                hex::encode(&self.0)
            }

            pub fn from_hex(s: &str) -> Result<Self, hex::HexError> {
                hex::decode_fixed::<$len>(s).map(Self)
            }

            pub fn is_zero(&self) -> bool {
                self.0.iter().all(|b| *b == 0)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::from_hex(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

hex_newtype!(Hash, 32);
hex_newtype!(SessionId, 16);

impl SessionId {
    pub fn generate() -> std::io::Result<Self> {
        use std::io::Read;
        let mut buf = [0u8; Self::LEN];
        let mut f = std::fs::File::open("/dev/urandom")?;
        f.read_exact(&mut buf)?;
        Ok(Self(buf))
    }
}

pub trait CanonicalTag {
    fn tag(&self) -> u8;
}

macro_rules! tagged_enum {
    (
        $(#[$outer:meta])*
        $name:ident { $($(#[$vattr:meta])* $variant:ident = $tag:expr => $repr:literal),+ $(,)? }
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        $(#[$outer])*
        pub enum $name {
            $(
                #[serde(rename = $repr)]
                $(#[$vattr])*
                $variant,
            )+
        }

        impl CanonicalTag for $name {
            fn tag(&self) -> u8 {
                match self {
                    $(Self::$variant => $tag,)+
                }
            }
        }

        impl $name {
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $repr,)+
                }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

tagged_enum!(Enforcement {
    Observe = 1 => "observe",
    Seatbelt = 2 => "seatbelt",
    Landlock = 3 => "landlock",
});

tagged_enum!(Decision {
    Allow = 1 => "allow",
    Deny = 2 => "deny",
    Ask = 3 => "ask",
    Forbid = 4 => "forbid",
});

tagged_enum!(FileMode {
    Read = 1 => "read",
    Write = 2 => "write",
    Create = 3 => "create",
    Delete = 4 => "delete",
    Metadata = 5 => "metadata",
    Exec = 6 => "exec",
});

tagged_enum!(Protocol {
    Tcp = 1 => "tcp",
    Udp = 2 => "udp",
    Tls = 3 => "tls",
    Http = 4 => "http",
});

tagged_enum!(Granted {
    Approved = 1 => "approved",
    Refused = 2 => "refused",
    TimedOut = 3 => "timed_out",
});

tagged_enum!(
    #[derive(Default)]
    Mediation {
        Off = 1 => "off",
        #[default]
        ExecNet = 2 => "exec-net",
        Full = 3 => "full",
    }
);

impl Mediation {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "exec-net" => Some(Self::ExecNet),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    pub fn observes(&self) -> bool {
        !matches!(self, Self::Off)
    }
}

impl Enforcement {
    pub fn enforces(&self) -> bool {
        !matches!(self, Self::Observe)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExitStatus {
    Exited { code: u32 },
    Signaled { signal: u32 },
    Unknown,
}

impl ExitStatus {
    pub fn tag(&self) -> u8 {
        match self {
            Self::Exited { .. } => 1,
            Self::Signaled { .. } => 2,
            Self::Unknown => 3,
        }
    }

    pub fn value(&self) -> u32 {
        match self {
            Self::Exited { code } => *code,
            Self::Signaled { signal } => *signal,
            Self::Unknown => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_hash_is_64_zeros() {
        assert_eq!(Hash::ZERO.to_hex(), "0".repeat(64));
        assert!(Hash::ZERO.is_zero());
    }

    #[test]
    fn hash_hex_roundtrip() {
        let h = Hash::from_bytes([0xab; 32]);
        assert_eq!(Hash::from_hex(&h.to_hex()).unwrap(), h);
    }

    #[test]
    fn hash_rejects_wrong_length() {
        assert!(Hash::from_hex("abcd").is_err());
    }

    #[test]
    fn session_id_is_16_bytes() {
        assert_eq!(SessionId::ZERO.to_hex().len(), 32);
    }

    #[test]
    fn generated_sessions_differ() {
        let a = SessionId::generate().unwrap();
        let b = SessionId::generate().unwrap();
        assert_ne!(a, b);
        assert!(!a.is_zero());
    }

    #[test]
    fn tags_match_spec() {
        assert_eq!(Enforcement::Observe.tag(), 1);
        assert_eq!(Enforcement::Seatbelt.tag(), 2);
        assert_eq!(Enforcement::Landlock.tag(), 3);
        assert_eq!(Decision::Allow.tag(), 1);
        assert_eq!(Decision::Deny.tag(), 2);
        assert_eq!(Decision::Ask.tag(), 3);
        assert_eq!(Decision::Forbid.tag(), 4);
        assert_eq!(FileMode::Read.tag(), 1);
        assert_eq!(FileMode::Exec.tag(), 6);
        assert_eq!(Protocol::Tcp.tag(), 1);
        assert_eq!(Granted::Approved.tag(), 1);
    }

    #[test]
    fn observe_does_not_enforce() {
        assert!(!Enforcement::Observe.enforces());
        assert!(Enforcement::Seatbelt.enforces());
        assert!(Enforcement::Landlock.enforces());
    }

    #[test]
    fn enum_serde_uses_spec_strings() {
        assert_eq!(
            serde_json::to_string(&Decision::Forbid).unwrap(),
            "\"forbid\""
        );
        assert_eq!(
            serde_json::from_str::<Enforcement>("\"landlock\"").unwrap(),
            Enforcement::Landlock
        );
        assert!(serde_json::from_str::<Decision>("\"maybe\"").is_err());
    }
}
