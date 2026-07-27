use airlock_canonical::Encoder;
use sha2::{Digest, Sha256};

use crate::baseline::SELF_PROTECT_VERSION;
use crate::glob::Pattern;
use crate::model::Defaults;
use crate::rule::{Matcher, Rule};

pub const DOMAIN: &[u8] = b"airlock.policy.v1\x00";

fn encode_rule(enc: &mut Encoder, rule: &Rule) {
    enc.str(&rule.id)
        .tag(rule.tier.tag())
        .tag(rule.action.tag())
        .opt_str(rule.reason.as_deref())
        .opt_str(rule.overrides.as_deref())
        .tag(rule.kind().tag());

    match &rule.matcher {
        Matcher::File { paths, modes } => {
            let raws: Vec<&str> = paths.iter().map(Pattern::raw).collect();
            enc.list_str(&raws).tag(modes.bits());
        }
        Matcher::Exec {
            program,
            argv_contains,
            argv_pattern,
        } => {
            enc.opt_str(program.as_ref().map(|p| p.raw()).as_deref())
                .list_str(argv_contains)
                .opt_str(argv_pattern.as_ref().map(|p| p.raw()));
        }
        Matcher::Egress { host, port } => {
            enc.str(&host.raw()).opt_u64(port.map(u64::from));
        }
    }
}

pub fn compute(defaults: &Defaults, user: &[Rule], baseline: &[Rule]) -> [u8; 32] {
    let mut enc = Encoder::with_domain(DOMAIN);
    enc.str(SELF_PROTECT_VERSION)
        .tag(defaults.file.tag())
        .tag(defaults.exec.tag())
        .tag(defaults.egress.tag());

    enc.u64(user.len() as u64);
    for r in user {
        encode_rule(&mut enc, r);
    }
    enc.u64(baseline.len() as u64);
    for r in baseline {
        encode_rule(&mut enc, r);
    }

    let out = Sha256::digest(enc.as_slice());
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}
