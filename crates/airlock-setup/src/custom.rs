use airlock_i18n::Locale;
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, value};

const HEADER_KO: &str = "\
# airlock setup 대화형 직접 설정으로 생성한 정책입니다.
# 규격은 docs/policy-dsl.md, 작성 가이드는 docs/policy-guide.md를 참고하세요.
";

const HEADER_EN: &str = "\
# airlock setup generated this policy through the interactive custom flow.
# See docs/policy-dsl.md for the format and docs/policy-guide.md for guidance.
";

const EGRESS_CAVEAT_KO: &str = "\
# 주의! 호스트 단위 egress 규칙은 airlock run --egress-proxy로 실행할 때만
# 강제됩니다. macOS Seatbelt와 Linux Landlock은 호스트를 구분하지 못합니다
# (docs/egress-proxy.md).
";

const EGRESS_CAVEAT_EN: &str = "\
# Watch out! Host-level egress rules are only enforced when running with
# airlock run --egress-proxy. macOS Seatbelt and Linux Landlock cannot
# tell hosts apart (docs/egress-proxy.md).
";

const TOOLCHAIN_PATHS: &[&str] = &[
    "/usr/**",
    "/bin/**",
    "/opt/homebrew/**",
    "/System/**",
    "/Library/**",
];

const BUILD_CACHE_PATHS: &[&str] = &[
    "~/.cargo/registry/**",
    "~/.cargo/git/**",
    "~/.rustup/**",
    "~/.npm/_cacache/**",
];

#[derive(Debug)]
pub struct CustomAnswers {
    pub name: String,
    pub file_default: String,
    pub exec_default: String,
    pub egress_default: String,
    pub workspace: String,
    pub toolchain_read: bool,
    pub build_cache: bool,
    pub egress_hosts: Vec<(String, u16)>,
}

pub fn render(answers: &CustomAnswers, locale: Locale) -> String {
    let mut doc = DocumentMut::new();
    doc["version"] = value(1);
    doc["name"] = value(answers.name.as_str());

    let mut defaults = Table::new();
    defaults.decor_mut().set_prefix("\n");
    defaults["file"] = value(answers.file_default.as_str());
    defaults["exec"] = value(answers.exec_default.as_str());
    defaults["egress"] = value(answers.egress_default.as_str());
    doc["defaults"] = Item::Table(defaults);

    let mut rules = ArrayOfTables::new();
    rules.push(file_rule(
        "workspace",
        &[&format!("{}/**", answers.workspace.trim_end_matches('/'))],
        None,
    ));
    if answers.toolchain_read {
        rules.push(file_rule(
            "toolchain-read",
            TOOLCHAIN_PATHS,
            Some(&["read", "metadata", "exec"]),
        ));
    }
    if answers.build_cache {
        rules.push(file_rule("build-cache", BUILD_CACHE_PATHS, None));
    }
    for (host, port) in &answers.egress_hosts {
        rules.push(egress_rule(host, *port));
    }
    doc["rules"] = Item::ArrayOfTables(rules);

    let mut out = String::from(match locale {
        Locale::Ko => HEADER_KO,
        Locale::En => HEADER_EN,
    });
    if !answers.egress_hosts.is_empty() {
        out.push_str(match locale {
            Locale::Ko => EGRESS_CAVEAT_KO,
            Locale::En => EGRESS_CAVEAT_EN,
        });
    }
    out.push('\n');
    out.push_str(&doc.to_string());
    out
}

pub fn egress_rule_id(host: &str, port: u16) -> String {
    let mut id = format!("egress-{}", slug(host));
    if port != 443 {
        id.push_str(&format!("-{port}"));
    }
    id
}

fn file_rule(id: &str, paths: &[impl AsRef<str>], mode: Option<&[&str]>) -> Table {
    let mut t = Table::new();
    t.decor_mut().set_prefix("\n");
    t["id"] = value(id);
    t["kind"] = value("file");
    if let [single] = paths {
        t["path"] = value(single.as_ref());
    } else {
        let arr: Array = paths.iter().map(AsRef::as_ref).collect();
        t["path"] = value(arr);
    }
    if let Some(modes) = mode {
        let arr: Array = modes.iter().copied().collect();
        t["mode"] = value(arr);
    }
    t["action"] = value("allow");
    t
}

fn egress_rule(host: &str, port: u16) -> Table {
    let mut t = Table::new();
    t.decor_mut().set_prefix("\n");
    t["id"] = value(egress_rule_id(host, port));
    t["kind"] = value("egress");
    t["host"] = value(host);
    t["port"] = value(i64::from(port));
    t["action"] = value("allow");
    t
}

fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() { "host".into() } else { out }
}

#[cfg(test)]
mod tests {
    use airlock_policy::{LoadContext, Policy};

    use super::*;

    fn answers() -> CustomAnswers {
        CustomAnswers {
            name: "my-project".into(),
            file_default: "deny".into(),
            exec_default: "ask".into(),
            egress_default: "deny".into(),
            workspace: "~/proj/demo/".into(),
            toolchain_read: true,
            build_cache: true,
            egress_hosts: vec![
                ("api.anthropic.com".into(), 443),
                ("*.github.com".into(), 443),
                ("localhost".into(), 8080),
            ],
        }
    }

    #[test]
    fn rendered_policy_loads() {
        let rendered = render(&answers(), Locale::Ko);
        let ctx = LoadContext::new("/home/tester", "/home/tester/.local/share/airlock");
        let policy = Policy::load_str(&rendered, &ctx).expect("load");
        assert_eq!(policy.name(), "my-project");
    }

    #[test]
    fn contains_expected_rules_and_header() {
        let rendered = render(&answers(), Locale::Ko);
        assert!(rendered.starts_with("# airlock setup"));
        assert!(rendered.contains("--egress-proxy"));
        assert!(rendered.contains(r#"path = "~/proj/demo/**""#));
        assert!(rendered.contains(r#"id = "toolchain-read""#));
        assert!(rendered.contains(r#"id = "build-cache""#));
        assert!(rendered.contains(r#"id = "egress-api-anthropic-com""#));
        assert!(rendered.contains(r#"id = "egress-github-com""#));
        assert!(rendered.contains(r#"id = "egress-localhost-8080""#));
    }

    #[test]
    fn minimal_answers_load_without_optional_rules() {
        let a = CustomAnswers {
            toolchain_read: false,
            build_cache: false,
            egress_hosts: Vec::new(),
            egress_default: "ask".into(),
            ..answers()
        };
        let rendered = render(&a, Locale::Ko);
        assert!(!rendered.contains("toolchain-read"));
        assert!(!rendered.contains("--egress-proxy"));
        let ctx = LoadContext::new("/home/tester", "/home/tester/.local/share/airlock");
        Policy::load_str(&rendered, &ctx).expect("load");
    }

    #[test]
    fn english_locale_renders_english_comments_and_same_policy() {
        let ctx = LoadContext::new("/home/tester", "/home/tester/.local/share/airlock");
        let ko = render(&answers(), Locale::Ko);
        let en = render(&answers(), Locale::En);
        assert!(en.starts_with("# airlock setup"));
        assert!(en.contains("# Watch out!"));
        assert!(!en.contains("주의"));
        let ko_policy = Policy::load_str(&ko, &ctx).expect("ko");
        let en_policy = Policy::load_str(&en, &ctx).expect("en");
        assert_eq!(
            ko_policy.digest(),
            en_policy.digest(),
            "로케일이 정책 의미를 바꾸면 안 됨"
        );
    }

    #[test]
    fn slug_produces_valid_rule_ids() {
        for (host, port, want) in [
            ("*.github.com", 443, "egress-github-com"),
            ("api.example.com", 8443, "egress-api-example-com-8443"),
            ("UPPER.Case", 443, "egress-upper-case"),
        ] {
            assert_eq!(egress_rule_id(host, port), want);
        }
    }
}
