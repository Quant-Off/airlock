use toml_edit::{DocumentMut, value};

use crate::error::SetupError;

pub fn render(preset_source: &str, workspace: Option<&str>) -> Result<String, SetupError> {
    let mut doc: DocumentMut = preset_source.parse()?;
    if let Some(ws) = workspace
        && let Some(rules) = doc
            .get_mut("rules")
            .and_then(|r| r.as_array_of_tables_mut())
    {
        let glob = format!("{}/**", ws.trim_end_matches('/'));
        for rule in rules.iter_mut() {
            if rule.get("id").and_then(|v| v.as_str()) == Some("workspace") {
                rule["path"] = value(glob.clone());
            }
        }
    }
    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use airlock_i18n::Locale;
    use airlock_policy::{LoadContext, Policy};

    use super::*;
    use crate::presets;

    fn preset(id: &str) -> &'static presets::Preset {
        presets::find(id).expect(id)
    }

    #[test]
    fn substitutes_workspace_rule_path() {
        for id in ["claude-code", "strict"] {
            for locale in [Locale::Ko, Locale::En] {
                let rendered = render(preset(id).source(locale), Some("~/proj/demo")).expect(id);
                assert!(rendered.contains(r#"path = "~/proj/demo/**""#), "{id}");
                assert!(!rendered.contains(r#"path = "~/work/**""#), "{id}");
            }
        }
    }

    #[test]
    fn keeps_developer_preset_unchanged() {
        for locale in [Locale::Ko, Locale::En] {
            let source = preset("developer").source(locale);
            let rendered = render(source, Some("~/proj/demo")).expect("developer");
            assert_eq!(rendered, source);
        }
    }

    #[test]
    fn preserves_comments_and_stays_loadable() {
        let rendered =
            render(preset("claude-code").source(Locale::Ko), Some("/work/demo")).expect("render");
        assert!(rendered.contains("# 주의하세요!"));
        let ctx = LoadContext::new("/home/tester", "/home/tester/.local/share/airlock");
        Policy::load_str(&rendered, &ctx).expect("load");
    }

    #[test]
    fn preserves_english_comments_and_stays_loadable() {
        let rendered =
            render(preset("claude-code").source(Locale::En), Some("/work/demo")).expect("render");
        assert!(rendered.contains("# Watch out!"));
        assert!(!rendered.contains("주의하세요"));
        let ctx = LoadContext::new("/home/tester", "/home/tester/.local/share/airlock");
        Policy::load_str(&rendered, &ctx).expect("load");
    }

    #[test]
    fn trims_trailing_slash() {
        let rendered =
            render(preset("strict").source(Locale::Ko), Some("/work/demo/")).expect("render");
        assert!(rendered.contains(r#"path = "/work/demo/**""#));
    }
}
