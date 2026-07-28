use std::fs;
use std::path::{Path, PathBuf};

use airlock_policy::error::LoadError;
use airlock_policy::{Action, FileMode, LoadContext, LoadWarning, Policy, Tier};
use unicode_normalization::UnicodeNormalization;

struct Home {
    dir: PathBuf,
}

impl Home {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!(
            "airlock-policy-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&p).unwrap();
        let dir = fs::canonicalize(&p).unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn join(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }

    fn ctx(&self) -> LoadContext {
        LoadContext::new(&self.dir, self.dir.join(".local/share/airlock"))
    }

    fn make_secret(&self) -> PathBuf {
        let ssh = self.join(".ssh");
        fs::create_dir_all(&ssh).unwrap();
        let key = ssh.join("id_ed25519");
        fs::write(&key, b"PRIVATE KEY").unwrap();
        key
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn read(policy: &Policy, home: &Home, raw: &str) -> Action {
    policy
        .evaluate_file(Path::new(raw), FileMode::Read, home.path())
        .action
}

// ---------- 평가 의미론 ----------

#[test]
fn baseline_applies_without_any_user_policy() {
    let h = Home::new("baseline");
    let p = Policy::baseline_only(&h.ctx()).unwrap();
    let key = h.join(".ssh/id_ed25519");
    assert_eq!(
        p.evaluate_file(&key, FileMode::Read, h.path()).action,
        Action::Forbid
    );
}

#[test]
fn self_protect_beats_user_allow() {
    let h = Home::new("tier0");
    let audit = h.join(".local/share/airlock");
    let src = format!(
        r#"
version = 1
[[rules]]
id = "wide-open"
kind = "file"
path = "{}/.local/**"
action = "allow"
"#,
        h.path().display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();

    let chain = audit.join("sessions/a/chain.jsonl");
    let ev = p.evaluate_file(&chain, FileMode::Write, h.path());
    assert_eq!(
        ev.action,
        Action::Deny,
        "감사 로그 쓰기가 사용자 allow로 열리면 로그는 증거가 아님"
    );
    let rule = ev.rule.unwrap();
    assert_eq!(rule.tier, Tier::SelfProtect);
    assert_eq!(rule.id, "self:audit-log");
}

#[test]
fn self_protect_cannot_be_overridden_even_with_overrides_clause() {
    let h = Home::new("tier0-override");
    let audit = h.join(".local/share/airlock");
    let src = format!(
        r#"
version = 1
[[rules]]
id = "try-open-audit"
kind = "file"
path = "{}/**"
action = "allow"
overrides = "ssh-private-keys"
reason = "감사 로그를 열어 보려는 시도"
"#,
        audit.display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();
    let ev = p.evaluate_file(&audit.join("chain.jsonl"), FileMode::Write, h.path());
    assert_eq!(ev.action, Action::Deny);
    assert_eq!(ev.rule.unwrap().tier, Tier::SelfProtect);
}

#[test]
fn first_matching_user_rule_wins() {
    let h = Home::new("order");
    let src = format!(
        r#"
version = 1
[[rules]]
id = "first-deny"
kind = "file"
path = "{home}/work/**"
action = "deny"
[[rules]]
id = "second-allow"
kind = "file"
path = "{home}/work/**"
action = "allow"
"#,
        home = h.path().display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();
    let ev = p.evaluate_file(&h.join("work/x.rs"), FileMode::Read, h.path());
    assert_eq!(ev.action, Action::Deny);
    assert_eq!(ev.rule.unwrap().id, "first-deny");
}

#[test]
fn user_rules_take_precedence_over_baseline() {
    let h = Home::new("user-over-baseline");
    let src = format!(
        r#"
version = 1
[[rules]]
id = "allow-zshrc-write"
kind = "file"
path = "{}/.zshrc"
mode = ["write"]
action = "allow"
"#,
        h.path().display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();
    let ev = p.evaluate_file(&h.join(".zshrc"), FileMode::Write, h.path());
    assert_eq!(ev.action, Action::Allow, "베이스라인 ask를 사용자가 완화");
    assert_eq!(ev.rule.unwrap().tier, Tier::User);
}

#[test]
fn unmatched_requests_fall_back_to_defaults() {
    let h = Home::new("defaults");
    let src = r#"
version = 1
[defaults]
file = "deny"
exec = "ask"
egress = "deny"
"#;
    let p = Policy::load_str(src, &h.ctx()).unwrap();
    let ev = p.evaluate_file(&h.join("random/file.txt"), FileMode::Read, h.path());
    assert_eq!(ev.action, Action::Deny);
    assert!(ev.rule.is_none(), "기본값 적용 시 규칙 귀속이 없어야 함");

    assert_eq!(p.evaluate_egress("example.com", 443).action, Action::Deny);
}

// ---------- 경로 정규화 적대적 시나리오 ----------

#[test]
fn dot_dot_traversal_into_secrets_is_blocked() {
    let h = Home::new("traversal");
    h.make_secret();
    let p = Policy::baseline_only(&h.ctx()).unwrap();

    let attempts = [
        ".ssh/../.ssh/id_ed25519",
        "work/../.ssh/id_ed25519",
        "./.ssh/./id_ed25519",
        ".ssh/nonexistent/../id_ed25519",
        "a/b/c/../../../.ssh/id_ed25519",
    ];
    for rel in attempts {
        let raw = h.join(rel);
        assert_eq!(
            p.evaluate_file(&raw, FileMode::Read, h.path()).action,
            Action::Forbid,
            "우회 성공: {rel}"
        );
    }
}

#[test]
fn redundant_separators_do_not_bypass() {
    let h = Home::new("slashes");
    h.make_secret();
    let p = Policy::baseline_only(&h.ctx()).unwrap();
    let weird = PathBuf::from(format!("{}//.ssh///id_ed25519", h.path().display()));
    assert_eq!(
        p.evaluate_file(&weird, FileMode::Read, h.path()).action,
        Action::Forbid
    );
}

#[test]
fn relative_path_against_cwd_is_blocked() {
    let h = Home::new("relative");
    h.make_secret();
    let p = Policy::baseline_only(&h.ctx()).unwrap();
    assert_eq!(read(&p, &h, ".ssh/id_ed25519"), Action::Forbid);
    assert_eq!(read(&p, &h, "~/.ssh/id_ed25519"), Action::Forbid);
}

#[test]
fn symlink_to_secret_directory_is_blocked() {
    let h = Home::new("symlink");
    let ssh = h.join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    fs::write(ssh.join("id_ed25519"), b"key").unwrap();

    let link = h.join("innocent");
    std::os::unix::fs::symlink(&ssh, &link).unwrap();

    let p = Policy::baseline_only(&h.ctx()).unwrap();
    let ev = p.evaluate_file(&link.join("id_ed25519"), FileMode::Read, h.path());
    assert_eq!(
        ev.action,
        Action::Forbid,
        "심볼릭 링크 경유 시크릿 접근이 통과함"
    );
    let np = ev.path.unwrap();
    assert!(
        np.diverges(),
        "요청 경로와 해소 경로가 다르다는 사실이 감사에 남아야 함"
    );
}

#[test]
fn symlink_file_directly_to_secret_is_blocked() {
    let h = Home::new("symlink-file");
    let key = h.make_secret();
    let link = h.join("notes.txt");
    std::os::unix::fs::symlink(&key, &link).unwrap();

    let p = Policy::baseline_only(&h.ctx()).unwrap();
    assert_eq!(
        p.evaluate_file(&link, FileMode::Read, h.path()).action,
        Action::Forbid
    );
}

#[test]
fn symlink_bypass_fails_even_when_user_allows_the_link_path() {
    let h = Home::new("symlink-allow");
    let key = h.make_secret();
    let link = h.join("work/notes.txt");
    fs::create_dir_all(h.join("work")).unwrap();
    std::os::unix::fs::symlink(&key, &link).unwrap();

    let src = format!(
        r#"
version = 1
[[rules]]
id = "workspace"
kind = "file"
path = "{}/work/**"
action = "allow"
"#,
        h.path().display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();
    let ev = p.evaluate_file(&link, FileMode::Read, h.path());
    assert_eq!(
        ev.action,
        Action::Forbid,
        "요청 경로만 보면 allow지만 해소 경로가 시크릿이므로 더 제한적인 쪽이 이겨야 함"
    );
}

#[test]
fn intermediate_symlink_segment_is_blocked() {
    let h = Home::new("mid-link");
    let ssh = h.join(".ssh");
    fs::create_dir_all(ssh.join("sub")).unwrap();
    fs::write(ssh.join("sub/key"), b"k").unwrap();

    let link = h.join("alias");
    std::os::unix::fs::symlink(&ssh, &link).unwrap();

    let p = Policy::baseline_only(&h.ctx()).unwrap();
    assert_eq!(
        p.evaluate_file(&link.join("sub/key"), FileMode::Read, h.path())
            .action,
        Action::Forbid
    );
}

#[test]
fn dot_dot_after_symlink_cannot_reach_secrets() {
    let h = Home::new("link-dotdot");
    h.make_secret();
    fs::create_dir_all(h.join("work")).unwrap();
    std::os::unix::fs::symlink(h.join(".ssh"), h.join("work/esc")).unwrap();

    let p = Policy::baseline_only(&h.ctx()).unwrap();
    let ev = p.evaluate_file(
        &h.join("work/esc/../.ssh/id_ed25519"),
        FileMode::Read,
        h.path(),
    );
    assert_eq!(
        ev.action,
        Action::Forbid,
        "커널은 esc를 .ssh로 해석한 뒤 ..를 적용해 홈의 .ssh에 도달함. 어휘적 정리만 하면 놓침"
    );
}

#[test]
fn case_variants_of_secret_paths_are_blocked() {
    let h = Home::new("case");
    let p = Policy::baseline_only(&h.ctx()).unwrap();
    for variant in [".SSH/id_rsa", ".Ssh/id_rsa", ".sSh/id_rsa"] {
        assert_eq!(
            read(&p, &h, variant),
            Action::Forbid,
            "대소문자 변형으로 우회: {variant}"
        );
    }
    assert_eq!(read(&p, &h, ".AWS/credentials"), Action::Forbid);
}

#[test]
fn allow_rules_do_not_widen_by_case() {
    let h = Home::new("case-allow");
    fs::create_dir_all(h.join("work")).unwrap();
    let src = format!(
        r#"
version = 1
[defaults]
file = "deny"
[[rules]]
id = "workspace"
kind = "file"
path = "{}/work/**"
action = "allow"
"#,
        h.path().display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();
    assert_eq!(read(&p, &h, "work/main.rs"), Action::Allow);
    assert_eq!(
        read(&p, &h, "WORK/main.rs"),
        Action::Deny,
        "allow 규칙이 대소문자 변형으로 넓어짐"
    );
}

#[test]
fn nfd_variants_of_deny_paths_are_blocked() {
    let h = Home::new("nfd-deny");
    let src = format!(
        r#"
version = 1
[[rules]]
id = "hangul-pem"
kind = "file"
path = "{}/작업/*.pem"
action = "deny"
reason = "정규화 우회 검증"
"#,
        h.path().display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();
    let nfd_dir: String = "작업".nfd().collect();
    assert_ne!(nfd_dir, "작업");
    assert_eq!(
        read(&p, &h, &format!("{}/{nfd_dir}/키.pem", h.path().display())),
        Action::Deny,
        "NFD 표기 접근이 NFC deny 규칙을 우회함"
    );
}

#[test]
fn allow_rules_do_not_widen_by_normalization() {
    let h = Home::new("nfd-allow");
    let src = format!(
        r#"
version = 1
[defaults]
file = "deny"
[[rules]]
id = "workspace"
kind = "file"
path = "{}/작업/**"
action = "allow"
"#,
        h.path().display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();
    assert_eq!(read(&p, &h, "작업/main.rs"), Action::Allow);
    let nfd_dir: String = "작업".nfd().collect();
    assert_eq!(
        read(&p, &h, &format!("{nfd_dir}/main.rs")),
        Action::Deny,
        "allow 규칙이 정규화 변형으로 넓어짐"
    );
}

#[test]
fn env_files_are_blocked_at_any_depth() {
    let h = Home::new("env");
    let p = Policy::baseline_only(&h.ctx()).unwrap();
    for rel in [
        ".env",
        "proj/.env",
        "proj/api/.env",
        "proj/.env.local",
        "a/b/c/d/.env.production",
    ] {
        assert_eq!(read(&p, &h, rel), Action::Forbid, "{rel}");
    }
    assert_ne!(read(&p, &h, "proj/environment.md"), Action::Forbid);
}

// ---------- 로드 검증 ----------

fn load_err(h: &Home, src: &str) -> LoadError {
    Policy::load_str(src, &h.ctx()).expect_err("로드가 실패해야 함")
}

#[test]
fn allowing_a_forbidden_secret_without_override_has_no_effect() {
    let h = Home::new("breach");
    let src = format!(
        r#"
version = 1
[[rules]]
id = "read-ssh"
kind = "file"
path = "{}/.ssh/**"
action = "allow"
"#,
        h.path().display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();
    assert_eq!(
        read(&p, &h, ".ssh/id_rsa"),
        Action::Forbid,
        "근거 없는 완화가 시크릿을 열어서는 안 됨"
    );
    assert!(
        p.warnings().iter().any(|w| matches!(
            w,
            LoadWarning::IneffectiveRelaxation { id, forbid_id, .. }
                if id == "read-ssh" && forbid_id == "ssh-private-keys"
        )),
        "무효한 규칙임을 알려야 함: {:?}",
        p.warnings()
    );
}

#[test]
fn asking_for_a_forbidden_secret_also_has_no_effect() {
    let h = Home::new("breach-ask");
    let src = format!(
        r#"
version = 1
[[rules]]
id = "ask-aws"
kind = "file"
path = "{}/.aws/credentials"
action = "ask"
"#,
        h.path().display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();
    assert_eq!(read(&p, &h, ".aws/credentials"), Action::Forbid);
}

#[test]
fn broad_workspace_allow_does_not_unprotect_env_files() {
    let h = Home::new("workspace-env");
    let src = format!(
        r#"
version = 1
[defaults]
file = "deny"
[[rules]]
id = "workspace"
kind = "file"
path = "{}/**"
action = "allow"
"#,
        h.path().display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();

    assert_eq!(read(&p, &h, "proj/src/main.rs"), Action::Allow);
    assert_eq!(
        read(&p, &h, "proj/.env"),
        Action::Forbid,
        "가장 흔한 규칙 하나가 시크릿 보호를 통째로 무력화하면 안 됨"
    );
    assert_eq!(read(&p, &h, ".ssh/id_rsa"), Action::Forbid);
    assert_eq!(read(&p, &h, ".aws/credentials"), Action::Forbid);
    assert_eq!(read(&p, &h, ".npmrc"), Action::Forbid);
}

#[test]
fn forbid_outranks_user_rules_but_self_protect_outranks_forbid_override() {
    let h = Home::new("tier-order");
    let audit = h.join(".local/share/airlock");
    let src = format!(
        r#"
version = 1
[[rules]]
id = "open-everything"
kind = "file"
path = "{home}/**"
action = "allow"
overrides = "ssh-private-keys"
reason = "ssh만 명시적으로 완화"
"#,
        home = h.path().display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();

    assert_eq!(
        read(&p, &h, ".ssh/id_rsa"),
        Action::Allow,
        "명시적으로 지목한 forbid는 완화됨"
    );
    assert_eq!(
        read(&p, &h, ".aws/credentials"),
        Action::Forbid,
        "지목하지 않은 다른 forbid는 그대로 유지됨"
    );
    assert_eq!(
        p.evaluate_file(&audit.join("chain.jsonl"), FileMode::Write, h.path())
            .action,
        Action::Deny,
        "tier 0 자기보호는 어떤 완화로도 뚫리지 않음"
    );
}

#[test]
fn explicit_override_with_reason_loads() {
    let h = Home::new("override-ok");
    let src = format!(
        r#"
version = 1
[[rules]]
id = "read-ssh-config"
kind = "file"
path = "{}/.ssh/**"
mode = ["read"]
action = "allow"
overrides = "ssh-private-keys"
reason = "배포 대상 호스트 별칭을 읽어야 함"
"#,
        h.path().display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();
    assert_eq!(read(&p, &h, ".ssh/config"), Action::Allow);
    assert_eq!(
        p.evaluate_file(&h.join(".ssh/id_rsa"), FileMode::Write, h.path())
            .action,
        Action::Forbid,
        "read만 완화했으므로 write는 여전히 forbid여야 함"
    );
}

#[test]
fn override_without_reason_fails_to_load() {
    let h = Home::new("override-noreason");
    let src = format!(
        r#"
version = 1
[[rules]]
id = "read-ssh"
kind = "file"
path = "{}/.ssh/**"
action = "allow"
overrides = "ssh-private-keys"
reason = "   "
"#,
        h.path().display()
    );
    assert!(matches!(
        load_err(&h, &src),
        LoadError::OverrideWithoutReason { .. }
    ));
}

#[test]
fn override_of_unknown_rule_fails_to_load() {
    let h = Home::new("override-unknown");
    let src = r#"
version = 1
[[rules]]
id = "x"
kind = "file"
path = "/tmp/x"
action = "allow"
overrides = "no-such-rule"
reason = "근거"
"#;
    assert!(matches!(
        load_err(&h, src),
        LoadError::UnknownOverrideTarget { .. }
    ));
}

#[test]
fn override_of_non_forbid_rule_fails_to_load() {
    let h = Home::new("override-nonforbid");
    let src = r#"
version = 1
[[rules]]
id = "x"
kind = "file"
path = "/tmp/x"
action = "allow"
overrides = "shell-init-write"
reason = "근거"
"#;
    assert!(matches!(
        load_err(&h, src),
        LoadError::OverrideTargetNotForbid { .. }
    ));
}

#[test]
fn egress_default_allow_is_rejected() {
    let h = Home::new("egress-default");
    let src = r#"
version = 1
[defaults]
egress = "allow"
"#;
    assert!(matches!(load_err(&h, src), LoadError::EgressDefaultAllow));
}

#[test]
fn unknown_key_is_rejected() {
    let h = Home::new("unknown-key");
    let src = r#"
version = 1
[[rules]]
id = "x"
kind = "file"
path = "/tmp/x"
action = "deny"
modes = ["read"]
"#;
    assert!(matches!(load_err(&h, src), LoadError::Toml(_)));
}

#[test]
fn unknown_action_is_rejected() {
    let h = Home::new("unknown-action");
    let src = r#"
version = 1
[[rules]]
id = "x"
kind = "file"
path = "/tmp/x"
action = "maybe"
"#;
    assert!(matches!(load_err(&h, src), LoadError::UnknownAction { .. }));
}

#[test]
fn unknown_mode_is_rejected() {
    let h = Home::new("unknown-mode");
    let src = r#"
version = 1
[[rules]]
id = "x"
kind = "file"
path = "/tmp/x"
mode = ["append"]
action = "deny"
"#;
    assert!(matches!(load_err(&h, src), LoadError::UnknownMode { .. }));
}

#[test]
fn relative_pattern_is_rejected() {
    let h = Home::new("relative-pattern");
    let src = r#"
version = 1
[[rules]]
id = "x"
kind = "file"
path = "work/**"
action = "deny"
"#;
    assert!(matches!(load_err(&h, src), LoadError::Pattern { .. }));
}

#[test]
fn embedded_double_star_is_rejected() {
    let h = Home::new("embedded");
    let src = r#"
version = 1
[[rules]]
id = "x"
kind = "file"
path = "/tmp/a**b"
action = "deny"
"#;
    assert!(matches!(load_err(&h, src), LoadError::Pattern { .. }));
}

#[test]
fn duplicate_ids_are_rejected() {
    let h = Home::new("dup");
    let src = r#"
version = 1
[[rules]]
id = "x"
kind = "file"
path = "/tmp/a"
action = "deny"
[[rules]]
id = "x"
kind = "file"
path = "/tmp/b"
action = "deny"
"#;
    assert!(matches!(load_err(&h, src), LoadError::DuplicateId(_)));
}

#[test]
fn user_rule_cannot_take_a_baseline_id() {
    let h = Home::new("reserved-baseline");
    let src = r#"
version = 1
[[rules]]
id = "ssh-private-keys"
kind = "file"
path = "/tmp/anything"
action = "allow"
"#;
    assert!(
        matches!(load_err(&h, src), LoadError::ReservedId { .. }),
        "내장 id를 그대로 쓴 규칙이 로드되면 감사 로그의 rule 필드가 어느 티어를 \
         가리키는지 알 수 없게 됨"
    );
}

#[test]
fn user_rule_cannot_take_a_self_protect_id() {
    let h = Home::new("reserved-self");
    let src = r#"
version = 1
[[rules]]
id = "self:audit-log"
kind = "file"
path = "/tmp/anything"
action = "allow"
"#;
    assert!(matches!(load_err(&h, src), LoadError::ReservedId { .. }));
}

#[test]
fn overrides_still_names_a_baseline_id() {
    let h = Home::new("reserved-override");
    let src = r#"
version = 1
[[rules]]
id = "read-ssh-config"
kind = "file"
path = "~/.ssh/config"
mode = ["read"]
action = "allow"
overrides = "ssh-private-keys"
reason = "배포 대상 호스트 별칭을 읽어야 함"
"#;
    assert!(
        Policy::load_str(src, &h.ctx()).is_ok(),
        "id 예약 검사가 overrides 지목까지 막으면 정당한 완화가 불가능해짐"
    );
}

#[test]
fn wrong_version_is_rejected() {
    let h = Home::new("version");
    assert!(matches!(
        load_err(&h, "version = 2"),
        LoadError::UnsupportedVersion(2)
    ));
}

#[test]
fn kind_mismatched_fields_are_rejected() {
    let h = Home::new("kind-fields");
    let src = r#"
version = 1
[[rules]]
id = "x"
kind = "file"
path = "/tmp/a"
action = "deny"
port = 443
"#;
    assert!(matches!(
        load_err(&h, src),
        LoadError::UnexpectedField { field: "port", .. }
    ));

    let src2 = r#"
version = 1
[[rules]]
id = "y"
kind = "egress"
host = "example.com"
action = "allow"
mode = ["read"]
"#;
    assert!(matches!(
        load_err(&h, src2),
        LoadError::UnexpectedField { field: "mode", .. }
    ));
}

#[test]
fn empty_mode_list_is_rejected() {
    let h = Home::new("empty-mode");
    let src = r#"
version = 1
[[rules]]
id = "x"
kind = "file"
path = "/tmp/a"
mode = []
action = "deny"
"#;
    assert!(matches!(load_err(&h, src), LoadError::EmptyModeSet { .. }));
}

#[test]
fn exec_rule_without_any_matcher_is_rejected() {
    let h = Home::new("exec-empty");
    let src = r#"
version = 1
[[rules]]
id = "x"
kind = "exec"
action = "ask"
"#;
    assert!(matches!(load_err(&h, src), LoadError::MissingField { .. }));
}

// ---------- 경고 ----------

#[test]
fn shadowed_rule_is_warned_not_fatal() {
    let h = Home::new("shadow");
    let src = format!(
        r#"
version = 1
[[rules]]
id = "broad"
kind = "file"
path = "{home}/work/**"
action = "deny"
[[rules]]
id = "narrow"
kind = "file"
path = "{home}/work/src/**"
action = "allow"
"#,
        home = h.path().display()
    );
    let p = Policy::load_str(&src, &h.ctx()).unwrap();
    assert!(
        p.warnings().iter().any(|w| matches!(
            w,
            LoadWarning::ShadowedRule { id, by } if id == "narrow" && by == "broad"
        )),
        "{:?}",
        p.warnings()
    );
}

#[test]
fn host_egress_rule_warns_that_it_needs_a_proxy() {
    let h = Home::new("host-warn");
    let src = r#"
version = 1
[[rules]]
id = "llm"
kind = "egress"
host = "api.anthropic.com"
port = 443
action = "allow"
"#;
    let p = Policy::load_str(src, &h.ctx()).unwrap();
    assert!(
        p.warnings()
            .iter()
            .any(|w| matches!(w, LoadWarning::HostRuleNeedsProxy { id } if id == "llm")),
        "강제되지 않는 규칙을 강제되는 것처럼 두면 안 됨: {:?}",
        p.warnings()
    );
}

#[test]
fn unused_override_is_warned() {
    let h = Home::new("unused-override");
    let src = r#"
version = 1
[[rules]]
id = "pointless"
kind = "file"
path = "/tmp/unrelated"
action = "allow"
overrides = "ssh-private-keys"
reason = "쓸 일이 없는 완화"
"#;
    let p = Policy::load_str(src, &h.ctx()).unwrap();
    assert!(
        p.warnings()
            .iter()
            .any(|w| matches!(w, LoadWarning::UnusedOverride { id, .. } if id == "pointless")),
        "{:?}",
        p.warnings()
    );
}

// ---------- exec과 egress ----------

#[test]
fn dangerous_exec_asks_by_default() {
    let h = Home::new("exec");
    let p = Policy::baseline_only(&h.ctx()).unwrap();
    let argv: Vec<String> = ["rm", "-rf", "build"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let ev = p.evaluate_exec(Path::new("/bin/rm"), &argv, h.path());
    assert_eq!(ev.action, Action::Ask);
    assert_eq!(ev.rule.unwrap().id, "danger-rm");
}

#[test]
fn sudo_asks_regardless_of_location() {
    let h = Home::new("sudo");
    let p = Policy::baseline_only(&h.ctx()).unwrap();
    let argv: Vec<String> = vec!["sudo".into(), "ls".into()];
    for prog in ["/usr/bin/sudo", "/opt/evil/sudo"] {
        let ev = p.evaluate_exec(Path::new(prog), &argv, h.path());
        assert_eq!(ev.action, Action::Ask, "{prog}");
    }
}

#[test]
fn egress_allowlist_permits_only_listed_hosts() {
    let h = Home::new("egress");
    let src = r#"
version = 1
[defaults]
egress = "deny"
[[rules]]
id = "llm"
kind = "egress"
host = "api.anthropic.com"
port = 443
action = "allow"
[[rules]]
id = "gh-raw"
kind = "egress"
host = "*.githubusercontent.com"
action = "allow"
"#;
    let p = Policy::load_str(src, &h.ctx()).unwrap();

    assert_eq!(
        p.evaluate_egress("api.anthropic.com", 443).action,
        Action::Allow
    );
    assert_eq!(
        p.evaluate_egress("api.anthropic.com", 80).action,
        Action::Deny
    );
    assert_eq!(
        p.evaluate_egress("raw.githubusercontent.com", 443).action,
        Action::Allow
    );
    assert_eq!(
        p.evaluate_egress("githubusercontent.com", 443).action,
        Action::Deny
    );
    assert_eq!(
        p.evaluate_egress("exfiltrate.example.com", 443).action,
        Action::Deny
    );
    assert_eq!(p.evaluate_egress("93.184.216.34", 443).action, Action::Deny);
}

// ---------- 다이제스트 ----------

#[test]
fn digest_ignores_comments_whitespace_and_key_order() {
    let h = Home::new("digest-stable");
    let a = r#"
version = 1
name = "p"
[[rules]]
id = "x"
kind = "file"
path = "/tmp/a"
action = "deny"
"#;
    let b = r#"
# 주석은 실효 정책이 아님

version = 1
name = "p"

[[rules]]
action  = "deny"
path    = "/tmp/a"
kind    = "file"
id      = "x"
"#;
    let pa = Policy::load_str(a, &h.ctx()).unwrap();
    let pb = Policy::load_str(b, &h.ctx()).unwrap();
    assert_eq!(pa.digest(), pb.digest());
}

#[test]
fn digest_changes_when_action_changes() {
    let h = Home::new("digest-action");
    let base = r#"
version = 1
[[rules]]
id = "x"
kind = "file"
path = "/tmp/a"
action = "deny"
"#;
    let flipped = base.replace(r#"action = "deny""#, r#"action = "ask""#);
    let pa = Policy::load_str(base, &h.ctx()).unwrap();
    let pb = Policy::load_str(&flipped, &h.ctx()).unwrap();
    assert_ne!(pa.digest(), pb.digest());
}

#[test]
fn digest_changes_when_rule_order_changes() {
    let h = Home::new("digest-order");
    let a = r#"
version = 1
[[rules]]
id = "one"
kind = "file"
path = "/tmp/a"
action = "deny"
[[rules]]
id = "two"
kind = "file"
path = "/tmp/b"
action = "allow"
"#;
    let b = r#"
version = 1
[[rules]]
id = "two"
kind = "file"
path = "/tmp/b"
action = "allow"
[[rules]]
id = "one"
kind = "file"
path = "/tmp/a"
action = "deny"
"#;
    let pa = Policy::load_str(a, &h.ctx()).unwrap();
    let pb = Policy::load_str(b, &h.ctx()).unwrap();
    assert_ne!(
        pa.digest(),
        pb.digest(),
        "순서가 의미를 바꾸므로 다이제스트도 달라야 함"
    );
}

#[test]
fn digest_changes_when_reason_changes() {
    let h = Home::new("digest-reason");
    let a = r#"
version = 1
[[rules]]
id = "x"
kind = "file"
path = "/tmp/a"
action = "deny"
reason = "첫 근거"
"#;
    let b = a.replace("첫 근거", "다른 근거");
    let pa = Policy::load_str(a, &h.ctx()).unwrap();
    let pb = Policy::load_str(&b, &h.ctx()).unwrap();
    assert_ne!(pa.digest(), pb.digest());
}

#[test]
fn digest_is_independent_of_session_specific_paths() {
    let h1 = Home::new("digest-portable-1");
    let h2 = Home::new("digest-portable-2");
    let src = r#"
version = 1
[[rules]]
id = "x"
kind = "file"
path = "~/work/**"
action = "allow"
"#;
    let p1 = Policy::load_str(src, &h1.ctx()).unwrap();
    let p2 = Policy::load_str(src, &h2.ctx()).unwrap();
    assert_eq!(
        p1.digest(),
        p2.digest(),
        "다이제스트는 작성된 규칙에 대한 것이어야 하며 머신별 경로에 흔들리면 비교가 불가능함"
    );
}

#[test]
fn baseline_only_digest_is_stable() {
    let h = Home::new("digest-baseline");
    let a = Policy::baseline_only(&h.ctx()).unwrap();
    let b = Policy::baseline_only(&h.ctx()).unwrap();
    assert_eq!(a.digest(), b.digest());
}

// ---------- 겹치는 forbid ----------

#[test]
fn overriding_one_forbid_does_not_open_an_overlapping_one() {
    let h = Home::new("overlap");
    let src = r#"
version = 1
[[rules]]
id = "open-ssh-dir"
kind = "file"
path = "~/.ssh/**"
action = "allow"
overrides = "ssh-private-keys"
reason = "테스트용 완화"
"#;
    let p = Policy::load_str(src, &h.ctx()).unwrap();

    assert_eq!(
        read(&p, &h, "~/.ssh/id_rsa"),
        Action::Allow,
        "지목한 forbid는 완화되어야 함"
    );
    for probe in ["~/.ssh/.env", "~/.ssh/.env.production"] {
        assert_eq!(
            read(&p, &h, probe),
            Action::Forbid,
            "{probe}: 지목하지 않은 env-files까지 함께 뚫려서는 안 됨"
        );
    }
}

#[test]
fn override_of_the_doc_example_is_not_reported_as_useless() {
    let h = Home::new("live-override");
    let src = r#"
version = 1
[[rules]]
id = "read-ssh-config"
kind = "file"
path = "~/.ssh/config"
mode = ["read"]
action = "allow"
overrides = "ssh-private-keys"
reason = "배포 대상 호스트 별칭을 읽어야 함"
"#;
    let p = Policy::load_str(src, &h.ctx()).unwrap();

    assert_eq!(read(&p, &h, "~/.ssh/config"), Action::Allow);
    assert!(
        !p.warnings()
            .iter()
            .any(|w| matches!(w, LoadWarning::UnusedOverride { .. })),
        "실제로 완화되는 규칙을 무효라고 경고하면 안 됨: {:?}",
        p.warnings()
    );
}

#[test]
fn override_that_reaches_nothing_is_still_warned() {
    let h = Home::new("dead-override");
    let src = r#"
version = 1
[[rules]]
id = "unrelated"
kind = "file"
path = "~/work/**"
action = "allow"
overrides = "ssh-private-keys"
reason = "관계 없는 경로"
"#;
    let p = Policy::load_str(src, &h.ctx()).unwrap();
    assert!(
        p.warnings()
            .iter()
            .any(|w| matches!(w, LoadWarning::UnusedOverride { .. })),
        "{:?}",
        p.warnings()
    );
}

// ---------- [defaults] ----------

#[test]
fn forbid_is_rejected_in_defaults() {
    let h = Home::new("defaults-forbid");
    let cases = [
        ("file", "version = 1\n[defaults]\nfile = \"forbid\"\n"),
        ("exec", "version = 1\n[defaults]\nexec = \"forbid\"\n"),
        ("egress", "version = 1\n[defaults]\negress = \"forbid\"\n"),
    ];
    for (kind, src) in cases {
        let err = Policy::load_str(src, &h.ctx()).unwrap_err();
        assert!(
            matches!(err, LoadError::ForbidDefault { .. }),
            "[defaults].{kind} = forbid는 거부되어야 함: {err}"
        );
    }

    // allow|deny|ask는 계속 받아들여야 합니다
    for action in ["allow", "deny", "ask"] {
        let src = format!("version = 1\n[defaults]\nfile = \"{action}\"\n");
        assert!(
            Policy::load_str(&src, &h.ctx()).is_ok(),
            "[defaults].file = {action}는 유효한 값임"
        );
    }
}

// ---------- 13절 의무: 모든 forbid probe ----------

#[test]
fn every_forbid_probe_resists_an_override_less_user_allow() {
    let h = Home::new("all-probes");
    let base = airlock_policy::baseline::build(h.path()).unwrap();
    assert!(!base.probes.is_empty());

    // 홈 전체와 /etc 전체를 여는, 상상 가능한 가장 넓은 사용자 allow
    let src = r#"
version = 1
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
[[rules]]
id = "open-home"
kind = "file"
path = "~/**"
action = "allow"
[[rules]]
id = "open-etc"
kind = "file"
path = "/etc/**"
action = "allow"
"#;
    let p = Policy::load_str(src, &h.ctx()).unwrap();

    for probe in &base.probes {
        for mode in FileMode::ALL {
            let ev = p.evaluate_file(&probe.path, mode, h.path());
            assert_eq!(
                ev.action,
                Action::Forbid,
                "{} ({mode})가 overrides 없는 넓은 allow로 열림. forbid={}",
                probe.path.display(),
                probe.rule_id
            );
        }
    }

    assert!(
        p.warnings()
            .iter()
            .any(|w| matches!(w, LoadWarning::IneffectiveRelaxation { .. })),
        "무효한 완화는 경고로 보고되어야 함: {:?}",
        p.warnings()
    );
}

// ---------- 13절 의무: 루트 위 탈출 ----------

#[test]
fn traversal_above_root_still_lands_on_system_credentials() {
    let h = Home::new("root-escape");
    let p = Policy::baseline_only(&h.ctx()).unwrap();

    // 루트 위로 올라가는 ..는 루트에서 흡수되므로, cwd 깊이와 무관하게
    // 충분히 많은 ..는 반드시 /etc/shadow로 떨어져야 합니다
    let deep_escape = format!("{}etc/shadow", "../".repeat(64));

    for raw in [
        deep_escape.as_str(),
        "/../../../../etc/shadow",
        "/etc/../etc/shadow",
        "/etc/./shadow",
        "//etc//shadow",
    ] {
        assert_eq!(
            read(&p, &h, raw),
            Action::Forbid,
            "{raw}가 system-credentials를 비껴감"
        );
    }
}

#[test]
fn forbid_is_rejected_in_user_rules() {
    let h = Home::new("user-forbid");
    let src = r#"
version = 1
[[rules]]
id = "my-rule"
kind = "file"
path = "~/secret/**"
action = "forbid"
"#;
    let err = Policy::load_str(src, &h.ctx()).unwrap_err();
    assert!(
        matches!(err, LoadError::ForbidInUserRule { .. }),
        "forbid는 내장 베이스라인 전용임: {err}"
    );
}

#[test]
fn non_ascii_host_pattern_is_rejected() {
    let h = Home::new("idn");
    let src = "version = 1\n[[rules]]\nid = \"idn\"\nkind = \"egress\"\nhost = \"한국.kr\"\naction = \"deny\"\n";
    assert!(
        Policy::load_str(src, &h.ctx()).is_err(),
        "v1은 IDN을 변환하지 않으므로 비ASCII 호스트 패턴은 로드 거부임"
    );

    let punycode = "version = 1\n[[rules]]\nid = \"idn\"\nkind = \"egress\"\nhost = \"xn--3e0b707e.kr\"\naction = \"deny\"\n";
    let p = Policy::load_str(punycode, &h.ctx()).unwrap();
    assert_eq!(
        p.evaluate_egress("xn--3e0b707e.kr", 443).action,
        Action::Deny
    );
}

// ---------- 로드 검증 보강 ----------

#[test]
fn empty_overrides_is_rejected_not_dropped() {
    let h = Home::new("empty-override");
    let src = r#"
version = 1
[[rules]]
id = "r"
kind = "file"
path = "~/.ssh/config"
action = "allow"
overrides = ""
reason = "근거"
"#;
    let err = Policy::load_str(src, &h.ctx()).unwrap_err();
    assert!(
        matches!(err, LoadError::EmptyOverrideTarget { .. }),
        "빈 overrides를 조용히 버리면 완화 의도가 사라짐: {err}"
    );
}

#[test]
fn wildcard_host_allow_is_rejected() {
    let h = Home::new("wildcard-egress");
    let allow_all = r#"
version = 1
[[rules]]
id = "open-everything"
kind = "egress"
host = "*"
action = "allow"
"#;
    let err = Policy::load_str(allow_all, &h.ctx()).unwrap_err();
    assert!(
        matches!(err, LoadError::WildcardHostAllow { .. }),
        "host = \"*\" allow는 [defaults].egress = allow와 같음: {err}"
    );

    // 전면 차단은 정당한 allowlist 패턴이므로 계속 허용합니다
    let deny_all = r#"
version = 1
[[rules]]
id = "llm"
kind = "egress"
host = "api.anthropic.com"
port = 443
action = "allow"
[[rules]]
id = "block-rest"
kind = "egress"
host = "*"
action = "deny"
"#;
    let p = Policy::load_str(deny_all, &h.ctx()).unwrap();
    assert_eq!(
        p.evaluate_egress("api.anthropic.com", 443).action,
        Action::Allow
    );
    assert_eq!(
        p.evaluate_egress("evil.example.com", 443).action,
        Action::Deny
    );
}

#[test]
fn ip_egress_rules_are_warned_as_unenforceable() {
    let h = Home::new("ip-egress");
    let src = r#"
version = 1
[[rules]]
id = "metadata-block"
kind = "egress"
host = "169.254.169.254"
action = "deny"
"#;
    let p = Policy::load_str(src, &h.ctx()).unwrap();
    assert!(
        p.warnings()
            .iter()
            .any(|w| matches!(w, LoadWarning::HostRuleNeedsProxy { .. })),
        "주소 단위 규칙도 포트 단위 백엔드로는 강제되지 않음: {:?}",
        p.warnings()
    );
}

// ---------- 가려진 규칙 경고 ----------

#[test]
fn a_narrow_earlier_rule_does_not_shadow_a_broader_later_rule() {
    let h = Home::new("no-false-shadow");
    let src = r#"
version = 1
[[rules]]
id = "narrow-first"
kind = "file"
path = "~/work/secret.txt"
action = "deny"
[[rules]]
id = "broad-second"
kind = "file"
path = "~/work/**"
action = "allow"
"#;
    let p = Policy::load_str(src, &h.ctx()).unwrap();
    assert!(
        !p.warnings()
            .iter()
            .any(|w| matches!(w, LoadWarning::ShadowedRule { .. })),
        "좁은 규칙 뒤의 넓은 규칙은 도달 가능함: {:?}",
        p.warnings()
    );
    assert_eq!(read(&p, &h, "~/work/other.txt"), Action::Allow);
    assert_eq!(read(&p, &h, "~/work/secret.txt"), Action::Deny);
}

#[test]
fn a_genuinely_unreachable_rule_is_still_warned() {
    let h = Home::new("true-shadow");
    let src = r#"
version = 1
[[rules]]
id = "broad-first"
kind = "file"
path = "~/work/**"
action = "allow"
[[rules]]
id = "unreachable-second"
kind = "file"
path = "~/work/sub/x.txt"
action = "deny"
"#;
    let p = Policy::load_str(src, &h.ctx()).unwrap();
    assert!(
        p.warnings().iter().any(|w| matches!(
            w,
            LoadWarning::ShadowedRule { id, .. } if id == "unreachable-second"
        )),
        "앞선 넓은 규칙에 완전히 가려진 규칙은 경고해야 함: {:?}",
        p.warnings()
    );
}

#[test]
fn suffix_egress_rule_shadows_a_later_exact_host() {
    let h = Home::new("egress-shadow");
    let src = r#"
version = 1
[[rules]]
id = "all-github"
kind = "egress"
host = "*.githubusercontent.com"
action = "allow"
[[rules]]
id = "one-github"
kind = "egress"
host = "raw.githubusercontent.com"
action = "deny"
"#;
    let p = Policy::load_str(src, &h.ctx()).unwrap();
    assert!(
        p.warnings().iter().any(|w| matches!(
            w,
            LoadWarning::ShadowedRule { id, .. } if id == "one-github"
        )),
        "접미 패턴이 뒤의 구체 호스트를 이미 덮음: {:?}",
        p.warnings()
    );
}
