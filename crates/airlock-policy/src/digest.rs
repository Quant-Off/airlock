use airlock_canonical::Encoder;
use sha2::{Digest, Sha256};

use crate::baseline::SELF_PROTECT_VERSION;
use crate::glob::Pattern;
use crate::model::Defaults;
use crate::rule::{Matcher, Rule};

/// 정규 인코딩의 도메인 분리 상수입니다.
///
/// 인코딩 스키마가 바뀌면 반드시 함께 올립니다. 같은 도메인 안에서 조용히 바꾸면
/// 옛 다이제스트와 위조된 다이제스트를 구분할 수 없습니다 (`docs/limitations.md` 7.9).
/// v2 에서 `protocol` 축과 `[defaults].egress_plaintext` 와 `max_bytes_out` 이 들어왔습니다.
/// 정책 파일 형식의 `version` 과는 다른 축이며 파일은 여전히 `version = 1` 입니다
pub const DOMAIN: &[u8] = b"airlock.policy.v2\x00";

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
        Matcher::Egress {
            host,
            port,
            protocol,
            max_bytes_out,
        } => {
            enc.str(&host.raw())
                .opt_u64(port.map(u64::from))
                .opt_u64(protocol.map(|p| u64::from(p.tag())))
                .opt_u64(*max_bytes_out);
        }
    }
}

pub fn compute(defaults: &Defaults, user: &[Rule], baseline: &[Rule]) -> [u8; 32] {
    let mut enc = Encoder::with_domain(DOMAIN);
    enc.str(SELF_PROTECT_VERSION)
        .tag(defaults.file.tag())
        .tag(defaults.exec.tag())
        .tag(defaults.egress.tag())
        .tag(defaults.egress_plaintext.tag());

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
