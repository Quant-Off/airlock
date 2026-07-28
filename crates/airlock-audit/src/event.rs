use airlock_canonical::Encoder;
use serde::{Deserialize, Serialize};

use crate::types::{CanonicalTag, ExitStatus, FileMode, Granted, Hash, Mediation, Protocol};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    SessionStart {
        airlock_version: String,
        argv: Vec<String>,
        cwd: String,
        policy_digest: Hash,
        policy_source: Option<String>,
        fsync_per_entry: bool,
        /// 이 세션에서 **실제로** 적용된 중계 수준. 요청값이 아닙니다
        mediation: Mediation,
    },
    SessionEnd {
        status: ExitStatus,
    },
    FileAccess {
        path_requested: String,
        path_resolved: String,
        mode: FileMode,
    },
    Exec {
        program: String,
        argv: Vec<String>,
        cwd: String,
    },
    Egress {
        host: String,
        port: u16,
        protocol: Protocol,
    },
    Approval {
        for_seq: u64,
        granted: Granted,
        note: Option<String>,
    },
    PolicyReload {
        policy_digest: Hash,
        policy_source: Option<String>,
    },
}

impl Event {
    pub fn tag(&self) -> u8 {
        match self {
            Self::SessionStart { .. } => 0x01,
            Self::SessionEnd { .. } => 0x02,
            Self::FileAccess { .. } => 0x10,
            Self::Exec { .. } => 0x11,
            Self::Egress { .. } => 0x12,
            Self::Approval { .. } => 0x20,
            Self::PolicyReload { .. } => 0x30,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::SessionStart { .. } => "session_start",
            Self::SessionEnd { .. } => "session_end",
            Self::FileAccess { .. } => "file_access",
            Self::Exec { .. } => "exec",
            Self::Egress { .. } => "egress",
            Self::Approval { .. } => "approval",
            Self::PolicyReload { .. } => "policy_reload",
        }
    }

    pub(crate) fn encode(&self, enc: &mut Encoder) {
        enc.tag(self.tag());
        match self {
            Self::SessionStart {
                airlock_version,
                argv,
                cwd,
                policy_digest,
                policy_source,
                fsync_per_entry,
                mediation,
            } => {
                enc.str(airlock_version)
                    .list_str(argv)
                    .str(cwd)
                    .bytes(policy_digest.as_bytes())
                    .opt_str(policy_source.as_deref())
                    .bool(*fsync_per_entry)
                    .tag(mediation.tag());
            }
            Self::SessionEnd { status } => {
                enc.tag(status.tag()).u32(status.value());
            }
            Self::FileAccess {
                path_requested,
                path_resolved,
                mode,
            } => {
                enc.str(path_requested).str(path_resolved).tag(mode.tag());
            }
            Self::Exec { program, argv, cwd } => {
                enc.str(program).list_str(argv).str(cwd);
            }
            Self::Egress {
                host,
                port,
                protocol,
            } => {
                enc.str(host).u32(u32::from(*port)).tag(protocol.tag());
            }
            Self::Approval {
                for_seq,
                granted,
                note,
            } => {
                enc.u64(*for_seq)
                    .tag(granted.tag())
                    .opt_str(note.as_deref());
            }
            Self::PolicyReload {
                policy_digest,
                policy_source,
            } => {
                enc.bytes(policy_digest.as_bytes())
                    .opt_str(policy_source.as_deref());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(e: &Event) -> Vec<u8> {
        let mut enc = Encoder::new();
        e.encode(&mut enc);
        enc.finish()
    }

    fn file_access(requested: &str, resolved: &str) -> Event {
        Event::FileAccess {
            path_requested: requested.to_string(),
            path_resolved: resolved.to_string(),
            mode: FileMode::Read,
        }
    }

    #[test]
    fn tags_match_spec() {
        assert_eq!(file_access("a", "a").tag(), 0x10);
        assert_eq!(
            Event::Exec {
                program: "rm".into(),
                argv: vec![],
                cwd: "/".into()
            }
            .tag(),
            0x11
        );
        assert_eq!(
            Event::Egress {
                host: "a".into(),
                port: 443,
                protocol: Protocol::Tls
            }
            .tag(),
            0x12
        );
        assert_eq!(
            Event::Approval {
                for_seq: 0,
                granted: Granted::Approved,
                note: None
            }
            .tag(),
            0x20
        );
    }

    #[test]
    fn requested_and_resolved_paths_are_distinguished() {
        let honest = file_access("/home/me/.ssh/id_rsa", "/home/me/.ssh/id_rsa");
        let via_link = file_access("/tmp/link/id_rsa", "/home/me/.ssh/id_rsa");
        assert_ne!(encoded(&honest), encoded(&via_link));
    }

    #[test]
    fn mode_changes_encoding() {
        let read = file_access("/a", "/a");
        let mut write = read.clone();
        if let Event::FileAccess { mode, .. } = &mut write {
            *mode = FileMode::Write;
        }
        assert_ne!(encoded(&read), encoded(&write));
    }

    #[test]
    fn argv_split_ambiguity_is_resolved() {
        let a = Event::Exec {
            program: "sh".into(),
            argv: vec!["sh".into(), "-c".into(), "rm -rf /".into()],
            cwd: "/".into(),
        };
        let b = Event::Exec {
            program: "sh".into(),
            argv: vec!["sh".into(), "-c rm".into(), "-rf /".into()],
            cwd: "/".into(),
        };
        assert_ne!(encoded(&a), encoded(&b));
    }

    #[test]
    fn serde_roundtrip_preserves_all_variants() {
        let events = vec![
            Event::SessionStart {
                airlock_version: "0.1.0".into(),
                argv: vec!["airlock".into(), "run".into()],
                cwd: "/tmp".into(),
                policy_digest: Hash::from_bytes([7; 32]),
                policy_source: Some("policy.toml".into()),
                fsync_per_entry: true,
                mediation: Mediation::ExecNet,
            },
            Event::SessionEnd {
                status: ExitStatus::Signaled { signal: 9 },
            },
            file_access("/a", "/b"),
            Event::Exec {
                program: "rm".into(),
                argv: vec!["rm".into(), "-rf".into()],
                cwd: "/".into(),
            },
            Event::Egress {
                host: "api.anthropic.com".into(),
                port: 443,
                protocol: Protocol::Tls,
            },
            Event::Approval {
                for_seq: 3,
                granted: Granted::Refused,
                note: None,
            },
            Event::PolicyReload {
                policy_digest: Hash::ZERO,
                policy_source: None,
            },
        ];
        for e in events {
            let json = serde_json::to_string(&e).unwrap();
            let back: Event = serde_json::from_str(&json).unwrap();
            assert_eq!(e, back, "round trip failed for {}", e.kind());
            assert_eq!(encoded(&e), encoded(&back));
        }
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let json = r#"{"type":"exec","program":"rm","argv":[],"cwd":"/","extra":1}"#;
        assert!(serde_json::from_str::<Event>(json).is_err());
    }

    #[test]
    fn unknown_event_type_is_rejected() {
        let json = r#"{"type":"mystery"}"#;
        assert!(serde_json::from_str::<Event>(json).is_err());
    }
}
