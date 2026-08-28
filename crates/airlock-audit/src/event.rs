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
        /// 감사 층이 `getuid(2)`로 직접 읽은 값. 호출자가 넘길 수 없습니다
        uid: u32,
        /// 감사 층이 `geteuid(2)`로 직접 읽은 값
        euid: u32,
        /// 사람 식별자 자리. 계정이 아니라 책임 주체를 가리키며 지금은 항상 `None`
        operator: Option<String>,
        /// 중앙 배포 정책의 서명자 자리. 서명 검증이 들어오기 전에는 항상 `None`
        policy_signer: Option<String>,
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
    EgressSummary {
        host: String,
        port: u16,
        protocol: Protocol,
        bytes_out: u64,
        bytes_in: u64,
        duration_ms: u64,
    },
    Approval {
        for_seq: u64,
        granted: Granted,
        note: Option<String>,
        /// 승인 프롬프트에 답한 주체의 uid. 관측할 수 없으면 `None`
        approver_uid: Option<u32>,
        /// 승인 프롬프트가 나간 터미널 장치 경로. 관측할 수 없으면 `None`
        approver_tty: Option<String>,
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
            Self::EgressSummary { .. } => 0x13,
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
            Self::EgressSummary { .. } => "egress_summary",
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
                uid,
                euid,
                operator,
                policy_signer,
            } => {
                enc.str(airlock_version)
                    .list_str(argv)
                    .str(cwd)
                    .bytes(policy_digest.as_bytes())
                    .opt_str(policy_source.as_deref())
                    .bool(*fsync_per_entry)
                    .tag(mediation.tag())
                    .u32(*uid)
                    .u32(*euid)
                    .opt_str(operator.as_deref())
                    .opt_str(policy_signer.as_deref());
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
            Self::EgressSummary {
                host,
                port,
                protocol,
                bytes_out,
                bytes_in,
                duration_ms,
            } => {
                enc.str(host)
                    .u32(u32::from(*port))
                    .tag(protocol.tag())
                    .u64(*bytes_out)
                    .u64(*bytes_in)
                    .u64(*duration_ms);
            }
            Self::Approval {
                for_seq,
                granted,
                note,
                approver_uid,
                approver_tty,
            } => {
                enc.u64(*for_seq)
                    .tag(granted.tag())
                    .opt_str(note.as_deref())
                    .opt_u64(approver_uid.map(u64::from))
                    .opt_str(approver_tty.as_deref());
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

    fn egress_summary() -> Event {
        Event::EgressSummary {
            host: "api.anthropic.com".into(),
            port: 443,
            protocol: Protocol::Tls,
            bytes_out: 1_024,
            bytes_in: 4_096,
            duration_ms: 250,
        }
    }

    fn session_start() -> Event {
        Event::SessionStart {
            airlock_version: "0.1.0".into(),
            argv: vec!["airlock".into(), "run".into()],
            cwd: "/tmp".into(),
            policy_digest: Hash::from_bytes([7; 32]),
            policy_source: Some("policy.toml".into()),
            fsync_per_entry: true,
            mediation: Mediation::ExecNet,
            uid: 501,
            euid: 501,
            operator: None,
            policy_signer: None,
        }
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
                note: None,
                approver_uid: None,
                approver_tty: None
            }
            .tag(),
            0x20
        );
        assert_eq!(egress_summary().tag(), 0x13);
        assert_eq!(egress_summary().kind(), "egress_summary");
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
            session_start(),
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
            egress_summary(),
            Event::Approval {
                for_seq: 3,
                granted: Granted::Refused,
                note: None,
                approver_uid: Some(501),
                approver_tty: Some("/dev/ttys004".into()),
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
    fn genesis_identity_fields_change_the_encoding() {
        let base = encoded(&session_start());

        let mut uid = session_start();
        if let Event::SessionStart { uid: u, .. } = &mut uid {
            *u = 0;
        }
        assert_ne!(encoded(&uid), base);

        let mut euid = session_start();
        if let Event::SessionStart { euid: e, .. } = &mut euid {
            *e = 0;
        }
        assert_ne!(encoded(&euid), base);

        let mut operator = session_start();
        if let Event::SessionStart { operator: o, .. } = &mut operator {
            *o = Some("felix".into());
        }
        assert_ne!(encoded(&operator), base);

        let mut signer = session_start();
        if let Event::SessionStart {
            policy_signer: p, ..
        } = &mut signer
        {
            *p = Some("secops".into());
        }
        assert_ne!(encoded(&signer), base);
    }

    #[test]
    fn uid_and_euid_are_not_interchangeable() {
        let mut a = session_start();
        if let Event::SessionStart { uid, euid, .. } = &mut a {
            *uid = 501;
            *euid = 0;
        }
        let mut b = session_start();
        if let Event::SessionStart { uid, euid, .. } = &mut b {
            *uid = 0;
            *euid = 501;
        }
        assert_ne!(
            encoded(&a),
            encoded(&b),
            "권한 상승 세션과 평범한 세션이 같은 바이트열이 되면 안 됨"
        );
    }

    #[test]
    fn approver_identity_changes_the_encoding() {
        let plain = Event::Approval {
            for_seq: 3,
            granted: Granted::Approved,
            note: Some("승인".into()),
            approver_uid: None,
            approver_tty: None,
        };
        let base = encoded(&plain);

        let mut with_uid = plain.clone();
        if let Event::Approval { approver_uid, .. } = &mut with_uid {
            *approver_uid = Some(0);
        }
        assert_ne!(encoded(&with_uid), base);

        let mut with_tty = plain.clone();
        if let Event::Approval { approver_tty, .. } = &mut with_tty {
            *approver_tty = Some("/dev/ttys004".into());
        }
        assert_ne!(encoded(&with_tty), base);
    }

    #[test]
    fn egress_summary_counters_change_the_encoding() {
        let base = encoded(&egress_summary());

        let mut out = egress_summary();
        if let Event::EgressSummary { bytes_out, .. } = &mut out {
            *bytes_out = 1_025;
        }
        assert_ne!(encoded(&out), base);

        let mut incoming = egress_summary();
        if let Event::EgressSummary { bytes_in, .. } = &mut incoming {
            *bytes_in = 0;
        }
        assert_ne!(encoded(&incoming), base);

        let mut dur = egress_summary();
        if let Event::EgressSummary { duration_ms, .. } = &mut dur {
            *duration_ms = 251;
        }
        assert_ne!(encoded(&dur), base);
    }

    #[test]
    fn egress_summary_is_not_egress() {
        let attempt = Event::Egress {
            host: "api.anthropic.com".into(),
            port: 443,
            protocol: Protocol::Tls,
        };
        assert_ne!(
            encoded(&attempt),
            encoded(&egress_summary()),
            "시도와 결과가 같은 바이트열이면 사후 모니터링이 불가능함"
        );
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
