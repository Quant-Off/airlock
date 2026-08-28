use airlock_canonical::Encoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::event::Event;
use crate::time::format_rfc3339_nanos;
use crate::types::{CanonicalTag, Decision, Enforcement, Hash, SessionId};

pub const DOMAIN: &[u8] = b"airlock.audit.v2\x00";

fn legacy_format_version() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub actor: String,
    pub event: Event,
    pub decision: Decision,
    pub rule: Option<String>,
}

impl Record {
    pub fn new(actor: impl Into<String>, event: Event, decision: Decision) -> Self {
        Self {
            actor: actor.into(),
            event,
            decision,
            rule: None,
        }
    }

    pub fn with_rule(mut self, rule: impl Into<String>) -> Self {
        self.rule = Some(rule.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    #[serde(default = "legacy_format_version")]
    pub v: u32,
    pub seq: u64,
    pub ts: u64,
    pub ts_rfc3339: String,
    pub session: SessionId,
    pub actor: String,
    pub enforcement: Enforcement,
    pub event: Event,
    pub decision: Decision,
    pub rule: Option<String>,
    pub prev: Hash,
    pub hash: Hash,
}

impl Entry {
    pub fn seal(
        seq: u64,
        ts: u64,
        session: SessionId,
        enforcement: Enforcement,
        prev: Hash,
        record: Record,
    ) -> Self {
        let Record {
            actor,
            event,
            decision,
            rule,
        } = record;
        let v = crate::FORMAT_VERSION;
        let hash = compute_hash(
            v,
            seq,
            &prev,
            ts,
            &session,
            &actor,
            enforcement,
            &event,
            decision,
            rule.as_deref(),
        );
        Self {
            v,
            seq,
            ts,
            ts_rfc3339: format_rfc3339_nanos(ts),
            session,
            actor,
            enforcement,
            event,
            decision,
            rule,
            prev,
            hash,
        }
    }

    pub fn recompute_hash(&self) -> Hash {
        compute_hash(
            self.v,
            self.seq,
            &self.prev,
            self.ts,
            &self.session,
            &self.actor,
            self.enforcement,
            &self.event,
            self.decision,
            self.rule.as_deref(),
        )
    }

    pub fn hash_is_valid(&self) -> bool {
        self.recompute_hash() == self.hash
    }
}

#[allow(clippy::too_many_arguments)]
pub fn compute_hash(
    v: u32,
    seq: u64,
    prev: &Hash,
    ts: u64,
    session: &SessionId,
    actor: &str,
    enforcement: Enforcement,
    event: &Event,
    decision: Decision,
    rule: Option<&str>,
) -> Hash {
    let mut enc = Encoder::with_domain(DOMAIN);
    enc.u32(v)
        .u64(seq)
        .bytes(prev.as_bytes())
        .u64(ts)
        .bytes(session.as_bytes())
        .str(actor)
        .tag(enforcement.tag());
    event.encode(&mut enc);
    enc.tag(decision.tag()).opt_str(rule);

    let digest = Sha256::digest(enc.as_slice());
    let mut out = [0u8; Hash::LEN];
    out.copy_from_slice(&digest);
    Hash::from_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FileMode;

    fn sample_event() -> Event {
        Event::FileAccess {
            path_requested: "/home/me/.ssh/id_rsa".into(),
            path_resolved: "/home/me/.ssh/id_rsa".into(),
            mode: FileMode::Read,
        }
    }

    fn sample(seq: u64, prev: Hash) -> Entry {
        Entry::seal(
            seq,
            1_700_000_000_000_000_000,
            SessionId::from_bytes([1; 16]),
            Enforcement::Observe,
            prev,
            Record::new("pid:1 test", sample_event(), Decision::Deny).with_rule("ssh-private-keys"),
        )
    }

    #[test]
    fn sealed_entry_verifies() {
        let e = sample(0, Hash::ZERO);
        assert!(e.hash_is_valid());
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(sample(0, Hash::ZERO).hash, sample(0, Hash::ZERO).hash);
    }

    #[test]
    fn every_hashed_field_changes_the_hash() {
        let base = sample(0, Hash::ZERO);

        let mut seq = base.clone();
        seq.seq = 1;
        assert_ne!(seq.recompute_hash(), base.hash);

        let mut ts = base.clone();
        ts.ts = base.ts + 1;
        assert_ne!(ts.recompute_hash(), base.hash);

        let mut session = base.clone();
        session.session = SessionId::from_bytes([2; 16]);
        assert_ne!(session.recompute_hash(), base.hash);

        let mut actor = base.clone();
        actor.actor = "pid:2 test".into();
        assert_ne!(actor.recompute_hash(), base.hash);

        let mut enforcement = base.clone();
        enforcement.enforcement = Enforcement::Landlock;
        assert_ne!(enforcement.recompute_hash(), base.hash);

        let mut decision = base.clone();
        decision.decision = Decision::Allow;
        assert_ne!(decision.recompute_hash(), base.hash);

        let mut rule = base.clone();
        rule.rule = None;
        assert_ne!(rule.recompute_hash(), base.hash);

        let mut prev = base.clone();
        prev.prev = Hash::from_bytes([9; 32]);
        assert_ne!(prev.recompute_hash(), base.hash);

        let mut event = base.clone();
        event.event = Event::FileAccess {
            path_requested: "/home/me/.ssh/id_rsa".into(),
            path_resolved: "/home/me/.ssh/id_rsa".into(),
            mode: FileMode::Write,
        };
        assert_ne!(event.recompute_hash(), base.hash);
    }

    #[test]
    fn sealed_entries_carry_the_current_format_version() {
        assert_eq!(sample(0, Hash::ZERO).v, crate::FORMAT_VERSION);
        assert_eq!(crate::FORMAT_VERSION, 2);
    }

    #[test]
    fn format_version_is_hashed() {
        let base = sample(0, Hash::ZERO);
        let mut downgraded = base.clone();
        downgraded.v = 1;
        assert_ne!(
            downgraded.recompute_hash(),
            base.hash,
            "버전이 해시 밖에 있으면 위조자가 옛 검증 규칙을 끌어올 수 있음"
        );
    }

    #[test]
    fn line_without_v_parses_as_version_one() {
        let e = sample(0, Hash::ZERO);
        let mut value: serde_json::Value = serde_json::to_value(&e).unwrap();
        value.as_object_mut().unwrap().remove("v");
        let back: Entry = serde_json::from_value(value).unwrap();
        assert_eq!(
            back.v, 1,
            "v 없는 줄이 파싱조차 실패하면 검증자가 옛 포맷과 위조를 구분할 수 없음"
        );
        assert!(!back.hash_is_valid());
    }

    #[test]
    fn rfc3339_is_not_hashed() {
        let mut tampered = sample(0, Hash::ZERO);
        tampered.ts_rfc3339 = "1999-01-01T00:00:00.000000000Z".into();
        assert!(tampered.hash_is_valid());
    }

    #[test]
    fn actor_rule_boundary_shift_changes_hash() {
        let a = Entry::seal(
            0,
            1,
            SessionId::ZERO,
            Enforcement::Observe,
            Hash::ZERO,
            Record::new("ab", sample_event(), Decision::Deny).with_rule("c"),
        );
        let b = Entry::seal(
            0,
            1,
            SessionId::ZERO,
            Enforcement::Observe,
            Hash::ZERO,
            Record::new("a", sample_event(), Decision::Deny).with_rule("bc"),
        );
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn empty_rule_differs_from_no_rule() {
        let empty = Entry::seal(
            0,
            1,
            SessionId::ZERO,
            Enforcement::Observe,
            Hash::ZERO,
            Record::new("a", sample_event(), Decision::Deny).with_rule(""),
        );
        let none = Entry::seal(
            0,
            1,
            SessionId::ZERO,
            Enforcement::Observe,
            Hash::ZERO,
            Record::new("a", sample_event(), Decision::Deny),
        );
        assert_ne!(empty.hash, none.hash);
    }

    #[test]
    fn domain_separation_is_applied() {
        let e = sample(0, Hash::ZERO);
        let mut without_domain = Encoder::new();
        without_domain
            .u32(e.v)
            .u64(e.seq)
            .bytes(e.prev.as_bytes())
            .u64(e.ts)
            .bytes(e.session.as_bytes())
            .str(&e.actor)
            .tag(e.enforcement.tag());
        e.event.encode(&mut without_domain);
        without_domain
            .tag(e.decision.tag())
            .opt_str(e.rule.as_deref());
        let naive = Sha256::digest(without_domain.as_slice());
        assert_ne!(naive.as_slice(), e.hash.as_bytes().as_slice());
    }

    #[test]
    fn v1_verifier_bytes_never_match_a_v2_entry() {
        let e = sample(0, Hash::ZERO);

        // 진짜 v1 검증자가 계산하던 바이트열 전체. 도메인이 v1 이고 u32(v) 가 없다
        let mut v1 = Encoder::with_domain(b"airlock.audit.v1\x00");
        v1.u64(e.seq)
            .bytes(e.prev.as_bytes())
            .u64(e.ts)
            .bytes(e.session.as_bytes())
            .str(&e.actor)
            .tag(e.enforcement.tag());
        e.event.encode(&mut v1);
        v1.tag(e.decision.tag()).opt_str(e.rule.as_deref());
        let legacy = Sha256::digest(v1.as_slice());

        assert_ne!(legacy.as_slice(), e.hash.as_bytes().as_slice());

        // v 만 1 로 낮춰 다시 계산해도 v2 도메인 위에서 계산되므로 v1 과 같아지지 않는다
        let mut downgraded = e.clone();
        downgraded.v = 1;
        assert_ne!(
            legacy.as_slice(),
            downgraded.recompute_hash().as_bytes().as_slice(),
            "버전을 낮춰 옛 검증자 바이트를 재현할 수 있으면 안 됨"
        );
    }

    #[test]
    fn json_roundtrip_preserves_hash() {
        let e = sample(5, Hash::from_bytes([3; 32]));
        let json = serde_json::to_string(&e).unwrap();
        let back: Entry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
        assert!(back.hash_is_valid());
    }

    #[test]
    fn json_rejects_unknown_fields() {
        let e = sample(0, Hash::ZERO);
        let mut value: serde_json::Value = serde_json::to_value(&e).unwrap();
        value["injected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Entry>(value).is_err());
    }
}
