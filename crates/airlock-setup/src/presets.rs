#[derive(Debug, Clone, Copy)]
pub struct Preset {
    pub id: &'static str,
    pub label: &'static str,
    pub hint: &'static str,
    pub command_hint: &'static str,
    pub source: &'static str,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        id: "claude-code",
        label: "Claude Code",
        hint: "Claude Code 구동에 필요한 최소 개방",
        command_hint: "claude",
        source: include_str!("../presets/claude-code.toml"),
    },
    Preset {
        id: "strict",
        label: "Strict",
        hint: "기본 전부 deny, 명시한 것만 허용",
        command_hint: "<에이전트 명령>",
        source: include_str!("../presets/strict.toml"),
    },
    Preset {
        id: "developer",
        label: "Developer",
        hint: "파일 기본 allow, 위험 지점만 ask",
        command_hint: "<에이전트 명령>",
        source: include_str!("../presets/developer.toml"),
    },
];

pub fn find(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id == id)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use airlock_policy::{LoadContext, Policy};

    use super::*;

    #[test]
    fn all_presets_parse_and_name_matches_id() {
        let ctx = LoadContext::new("/home/tester", "/home/tester/.local/share/airlock");
        for preset in PRESETS {
            let policy = Policy::load_str(preset.source, &ctx).expect(preset.id);
            assert_eq!(policy.name(), preset.id);
        }
    }

    #[test]
    fn presets_stay_in_sync_with_examples() {
        let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/policy");
        if !examples.is_dir() {
            return;
        }
        for preset in PRESETS {
            let example = std::fs::read_to_string(examples.join(format!("{}.toml", preset.id)))
                .expect(preset.id);
            assert_eq!(
                example, preset.source,
                "{} 프리셋이 examples/policy와 어긋남",
                preset.id
            );
        }
    }
}
