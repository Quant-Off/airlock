use airlock_i18n::Locale;

#[derive(Debug, Clone, Copy)]
pub struct Preset {
    pub id: &'static str,
    pub label: &'static str,
    pub hint_ko: &'static str,
    pub hint_en: &'static str,
    pub command_hint_ko: &'static str,
    pub command_hint_en: &'static str,
    pub source_ko: &'static str,
    pub source_en: &'static str,
}

impl Preset {
    pub fn hint(&self, locale: Locale) -> &'static str {
        match locale {
            Locale::Ko => self.hint_ko,
            Locale::En => self.hint_en,
        }
    }

    pub fn command_hint(&self, locale: Locale) -> &'static str {
        match locale {
            Locale::Ko => self.command_hint_ko,
            Locale::En => self.command_hint_en,
        }
    }

    pub fn source(&self, locale: Locale) -> &'static str {
        match locale {
            Locale::Ko => self.source_ko,
            Locale::En => self.source_en,
        }
    }
}

pub const PRESETS: &[Preset] = &[
    Preset {
        id: "claude-code",
        label: "Claude Code",
        hint_ko: "Claude Code 구동에 필요한 최소 개방",
        hint_en: "the minimum opening Claude Code needs to run",
        command_hint_ko: "claude",
        command_hint_en: "claude",
        source_ko: include_str!("../presets/claude-code.toml"),
        source_en: include_str!("../presets/en/claude-code.toml"),
    },
    Preset {
        id: "strict",
        label: "Strict",
        hint_ko: "기본 전부 deny, 명시한 것만 허용",
        hint_en: "deny everything by default, allow only what is listed",
        command_hint_ko: "<에이전트 명령>",
        command_hint_en: "<agent command>",
        source_ko: include_str!("../presets/strict.toml"),
        source_en: include_str!("../presets/en/strict.toml"),
    },
    Preset {
        id: "developer",
        label: "Developer",
        hint_ko: "파일 기본 allow, 위험 지점만 ask",
        hint_en: "files allow by default, ask only at risky spots",
        command_hint_ko: "<에이전트 명령>",
        command_hint_en: "<agent command>",
        source_ko: include_str!("../presets/developer.toml"),
        source_en: include_str!("../presets/en/developer.toml"),
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
            for locale in [Locale::Ko, Locale::En] {
                let policy = Policy::load_str(preset.source(locale), &ctx).expect(preset.id);
                assert_eq!(policy.name(), preset.id);
            }
        }
    }

    #[test]
    fn en_presets_only_differ_in_comments() {
        let ctx = LoadContext::new("/home/tester", "/home/tester/.local/share/airlock");
        for preset in PRESETS {
            let ko = Policy::load_str(preset.source_ko, &ctx).expect(preset.id);
            let en = Policy::load_str(preset.source_en, &ctx).expect(preset.id);
            assert_eq!(
                ko.digest(),
                en.digest(),
                "{} 영문 프리셋의 의미가 한국어판과 어긋남",
                preset.id
            );
        }
    }

    #[test]
    fn presets_stay_in_sync_with_examples() {
        let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/policy");
        if !examples.is_dir() {
            return;
        }
        for preset in PRESETS {
            for (source, path) in [
                (preset.source_ko, format!("{}.toml", preset.id)),
                (preset.source_en, format!("en/{}.toml", preset.id)),
            ] {
                let example = std::fs::read_to_string(examples.join(&path)).expect(&path);
                assert_eq!(example, source, "{path} 프리셋이 examples/policy와 어긋남");
            }
        }
    }
}
