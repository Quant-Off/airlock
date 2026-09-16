//! 이 파일은 빌드된 `airlock` 바이너리를 실제로 실행해 종료 코드와 감사 로그를 봅니다.
//!
//! # Features
//! 단위 테스트가 검사하지 못하는 것을 봅니다. 종료 코드 규약, 제네시스 argv 재구성,
//! 정책 로드 실패 시 fail-closed, 작업 공간 안전장치가 대상입니다. 강제 층 동작은
//! 플랫폼별 통합 테스트가 따로 검사합니다.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_airlock")
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("airlock-cli-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Self(std::fs::canonicalize(&p).unwrap())
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn audit(&self) -> PathBuf {
        self.0.join("audit")
    }

    /// 이 세션 하나가 남긴 디렉토리
    fn session(&self) -> PathBuf {
        let sessions = self.audit().join("sessions");
        std::fs::read_dir(&sessions)
            .unwrap_or_else(|e| panic!("{} 를 읽을 수 없음: {e}", sessions.display()))
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .next()
            .expect("세션 디렉토리가 없음")
    }

    fn chain(&self) -> String {
        std::fs::read_to_string(self.session().join("chain.jsonl")).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 격리된 환경에서 airlock 을 부릅니다.
///
/// `HOME`을 스크래치 안으로 옮겨 실행하는 사람의 실제 홈과 정책 파일을 건드리지 않습니다
fn airlock(s: &Scratch, cwd: &Path, args: &[&str]) -> Output {
    let home = s.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    Command::new(bin())
        .args(args)
        .current_dir(cwd)
        .env("HOME", &home)
        .env("AIRLOCK_LANG", "ko")
        .env_remove("AIRLOCK_AUDIT_DIR")
        .env_remove("XDG_DATA_HOME")
        .output()
        .expect("airlock 실행 실패")
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// 사람이 읽는 보고가 stdout 과 stderr 중 어디로 가는지에 테스트가 매달리지 않게 합니다
fn printed(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(out))
}

/// 이 테스트들이 쓰는 쉘.
///
/// macOS 의 `/bin/sh` 는 dyld variant 기구로 자기를 `/bin/bash` 로 다시 exec 합니다.
/// `[defaults].exec` 이 allow 가 아닌 정책에서는 exec 이 커널 화이트리스트가 되므로,
/// 최상위 프로그램만 허용해서는 그 재실행이 막혀 프로세스가 뜨지 못합니다
/// (`docs/limitations.md` 4.13). 그 성질 자체는 강제 층 테스트가 따로 고정하므로
/// 여기서는 variant 를 쓰지 않는 쉘을 고릅니다
fn shell() -> &'static str {
    if cfg!(target_os = "macos") {
        "/bin/zsh"
    } else {
        "/bin/sh"
    }
}

fn work_dir(s: &Scratch) -> PathBuf {
    let ws = s.path().join("work");
    std::fs::create_dir_all(&ws).unwrap();
    ws
}

// ---------- 정상 경로 ----------

#[test]
fn run_records_a_verifiable_session() {
    let s = Scratch::new("ok");
    let ws = work_dir(&s);
    let out = airlock(
        &s,
        &ws,
        &[
            "run",
            "--audit-dir",
            s.audit().to_str().unwrap(),
            "--yes",
            "--",
            "/bin/echo",
            "hello",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");

    let verify = airlock(&s, &ws, &["audit", "verify", s.session().to_str().unwrap()]);
    assert_eq!(code(&verify), 0, "{}", stderr(&verify));
}

#[test]
fn genesis_argv_reconstructs_the_real_invocation() {
    let s = Scratch::new("argv");
    let ws = work_dir(&s);
    let out = airlock(
        &s,
        &ws,
        &[
            "run",
            "--audit-dir",
            s.audit().to_str().unwrap(),
            "--yes",
            "--no-network",
            "--mediate",
            "off",
            "--",
            "/bin/echo",
            "hi",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let genesis = s.chain().lines().next().unwrap().to_string();
    for expected in [
        "--yes",
        "--no-network",
        "--mediate",
        "off",
        "--workspace",
        ws.to_str().unwrap(),
    ] {
        assert!(
            genesis.contains(expected),
            "제네시스 argv 에 {expected} 가 없음. 승인 통제를 포기한 세션인지 \
             로그만으로 알 수 없게 됨: {genesis}"
        );
    }
    assert!(
        genesis.contains(r#""mediation":"off""#),
        "제네시스가 중계 수준을 담지 않음: {genesis}"
    );
}

// ---------- 종료 코드 ----------

#[test]
fn a_denied_program_does_not_look_like_success() {
    let s = Scratch::new("denied");
    let ws = work_dir(&s);
    std::fs::write(
        ws.join("airlock.toml"),
        r#"
version = 1
name = "deny-all-exec"
[defaults]
file = "allow"
exec = "deny"
egress = "deny"
"#,
    )
    .unwrap();

    let out = airlock(
        &s,
        &ws,
        &[
            "run",
            "--audit-dir",
            s.audit().to_str().unwrap(),
            "--",
            "/bin/echo",
            "nope",
        ],
    );
    assert_eq!(
        code(&out),
        77,
        "차단된 실행이 성공으로 보이면 CI 에 넣은 순간 실패가 사라짐: {}",
        stderr(&out)
    );
    assert!(s.chain().contains(r#""decision":"deny""#), "{}", s.chain());
}

#[test]
fn a_signaled_child_does_not_look_like_success() {
    let s = Scratch::new("signal");
    let ws = work_dir(&s);
    let out = airlock(
        &s,
        &ws,
        &[
            "run",
            "--audit-dir",
            s.audit().to_str().unwrap(),
            "--yes",
            "--",
            shell(),
            "-c",
            "kill -TERM $$",
        ],
    );
    assert_eq!(
        code(&out),
        143,
        "시그널 종료는 128+시그널 이어야 함: {}",
        stderr(&out)
    );
    assert!(
        s.chain().contains(r#""kind":"signaled""#),
        "감사 로그가 시그널 종료를 남기지 않음: {}",
        s.chain()
    );
}

#[test]
fn a_broken_policy_stops_the_run() {
    let s = Scratch::new("badpolicy");
    let ws = work_dir(&s);
    std::fs::write(
        ws.join("airlock.toml"),
        "version = 1\n[[rules]]\nid = \"x\"\n",
    )
    .unwrap();

    let out = airlock(
        &s,
        &ws,
        &[
            "run",
            "--audit-dir",
            s.audit().to_str().unwrap(),
            "--yes",
            "--",
            "/bin/echo",
            "hi",
        ],
    );
    assert_eq!(code(&out), 78, "{}", stderr(&out));
    assert!(
        !s.audit().exists(),
        "정책이 적용되지 않았는데 세션이 시작되었음"
    );
    assert!(stderr(&out).contains("실행을 중단함"), "{}", stderr(&out));
}

#[test]
fn a_reserved_rule_id_stops_the_run() {
    let s = Scratch::new("reserved");
    let ws = work_dir(&s);
    std::fs::write(
        ws.join("airlock.toml"),
        r#"
version = 1
[[rules]]
id = "ssh-private-keys"
kind = "file"
path = "/tmp/x"
action = "allow"
"#,
    )
    .unwrap();

    let out = airlock(
        &s,
        &ws,
        &[
            "run",
            "--audit-dir",
            s.audit().to_str().unwrap(),
            "--yes",
            "--",
            "/bin/echo",
            "hi",
        ],
    );
    assert_eq!(code(&out), 78, "{}", stderr(&out));
    assert!(stderr(&out).contains("내장"), "{}", stderr(&out));
}

#[test]
fn an_unknown_mediation_level_is_rejected() {
    let s = Scratch::new("mediate");
    let ws = work_dir(&s);
    let out = airlock(
        &s,
        &ws,
        &[
            "run",
            "--audit-dir",
            s.audit().to_str().unwrap(),
            "--mediate",
            "sometimes",
            "--",
            "/bin/echo",
            "hi",
        ],
    );
    assert_eq!(code(&out), 64, "{}", stderr(&out));
    assert!(!s.audit().exists(), "인자가 틀렸는데 세션이 시작되었음");
}

// ---------- 작업 공간 안전장치 ----------

#[test]
fn running_in_the_home_directory_is_refused() {
    let s = Scratch::new("home");
    let home = s.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    let out = airlock(
        &s,
        &home,
        &[
            "run",
            "--audit-dir",
            s.audit().to_str().unwrap(),
            "--yes",
            "--",
            "/bin/echo",
            "hi",
        ],
    );
    assert_eq!(
        code(&out),
        64,
        "홈 전체가 쓰기 허용으로 열렸음: {}",
        stderr(&out)
    );
    assert!(stderr(&out).contains("작업 공간"), "{}", stderr(&out));
}

#[test]
fn an_explicit_home_workspace_warns_but_runs() {
    let s = Scratch::new("home-explicit");
    let home = s.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    let out = airlock(
        &s,
        &home,
        &[
            "run",
            "--audit-dir",
            s.audit().to_str().unwrap(),
            "--workspace",
            home.to_str().unwrap(),
            "--yes",
            "--",
            "/bin/echo",
            "hi",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("경고 작업 공간이 홈 전체"),
        "명시했다고 조용해지면 안 됨: {}",
        stderr(&out)
    );
}

// ---------- 감사 뷰어 ----------

#[test]
fn tampering_with_the_chain_fails_verification() {
    let s = Scratch::new("tamper");
    let ws = work_dir(&s);
    let out = airlock(
        &s,
        &ws,
        &[
            "run",
            "--audit-dir",
            s.audit().to_str().unwrap(),
            "--yes",
            "--",
            "/bin/echo",
            "hi",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let chain = s.session().join("chain.jsonl");
    let body = std::fs::read_to_string(&chain).unwrap();
    std::fs::write(
        &chain,
        body.replace(r#""decision":"allow""#, r#""decision":"deny""#),
    )
    .unwrap();

    let verify = airlock(&s, &ws, &["audit", "verify", s.session().to_str().unwrap()]);
    assert_ne!(code(&verify), 0, "변조된 체인이 검증을 통과했음");
    assert!(printed(&verify).contains("변조"), "{}", printed(&verify));
}

#[test]
fn show_marks_the_mediation_level() {
    let s = Scratch::new("show");
    let ws = work_dir(&s);
    airlock(
        &s,
        &ws,
        &[
            "run",
            "--audit-dir",
            s.audit().to_str().unwrap(),
            "--yes",
            "--mediate",
            "off",
            "--",
            "/bin/echo",
            "hi",
        ],
    );

    let show = airlock(&s, &ws, &["audit", "show", s.session().to_str().unwrap()]);
    assert_eq!(code(&show), 0, "{}", stderr(&show));
    let text = String::from_utf8_lossy(&show.stdout).into_owned();
    assert!(text.contains("중계=off"), "{text}");
}

// ---------- 정책 프리셋 ----------

#[test]
fn shipped_policy_presets_load() {
    let s = Scratch::new("presets");
    let ws = work_dir(&s);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("워크스페이스 루트를 찾을 수 없음")
        .to_path_buf();

    for name in ["strict.toml", "developer.toml"] {
        let preset = root.join("examples/policy").join(name);
        assert!(preset.is_file(), "{} 이 없음", preset.display());
        let out = airlock(
            &s,
            &ws,
            &["policy", "check", "--policy", preset.to_str().unwrap()],
        );
        assert_eq!(code(&out), 0, "{name}: {}", stderr(&out));
    }
}

// ---------- 매일 이상여부 점검과 책임자 확인 ----------

/// 세션 하나를 남기고 그 감사 루트를 돌려줍니다
fn one_session(s: &Scratch, ws: &Path) {
    let out = airlock(
        s,
        ws,
        &[
            "run",
            "--audit-dir",
            s.audit().to_str().unwrap(),
            "--yes",
            "--",
            "/bin/echo",
            "hi",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
}

fn report(s: &Scratch, ws: &Path, extra: &[&str]) -> Output {
    let root = s.audit();
    let root = root.to_str().unwrap();
    let mut args = vec!["audit", "report", "--audit-root", root];
    args.extend_from_slice(extra);
    airlock(s, ws, &args)
}

fn report_json(s: &Scratch, ws: &Path) -> serde_json::Value {
    let out = report(s, ws, &["--json"]);
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("JSON 을 파싱하지 못함: {e}\n{}", printed(&out)))
}

#[test]
fn a_clean_report_exits_zero() {
    let s = Scratch::new("report-ok");
    let ws = work_dir(&s);
    one_session(&s, &ws);

    let out = report(&s, &ws, &[]);
    assert_eq!(code(&out), 0, "{}", printed(&out));
    let text = printed(&out);
    assert!(text.contains("이상 없음"), "{text}");
    assert!(
        text.contains("확인 기록 없음"),
        "확인 기록이 없다는 사실이 드러나야 함: {text}"
    );
}

#[test]
fn a_tampered_chain_makes_the_report_exit_non_zero() {
    let s = Scratch::new("report-tamper");
    let ws = work_dir(&s);
    one_session(&s, &ws);

    let chain = s.session().join("chain.jsonl");
    let body = std::fs::read_to_string(&chain).unwrap();
    std::fs::write(&chain, body.replacen("\"allow\"", "\"deny\"", 1)).unwrap();

    let out = report(&s, &ws, &[]);
    assert_ne!(
        code(&out),
        0,
        "변조된 체인이 통과하면 안 됨: {}",
        printed(&out)
    );
    assert_eq!(code(&out), 2, "{}", printed(&out));
    assert!(printed(&out).contains("integrity"), "{}", printed(&out));
}

#[test]
fn a_missing_anchor_makes_the_report_exit_non_zero() {
    // 탐지 불가는 통과가 아닙니다
    let s = Scratch::new("report-noanchor");
    let ws = work_dir(&s);
    one_session(&s, &ws);
    std::fs::remove_file(s.audit().join("anchors.jsonl")).unwrap();

    let out = report(&s, &ws, &[]);
    assert_eq!(code(&out), 2, "{}", printed(&out));
    assert!(printed(&out).contains("탐지"), "{}", printed(&out));
}

#[test]
fn a_deleted_session_directory_is_caught_by_the_anchor_chain() {
    // 남은 세션만 훑으면 세션 통째 삭제가 "이상 없음" 으로 보고됩니다
    let s = Scratch::new("report-deleted");
    let ws = work_dir(&s);
    one_session(&s, &ws);
    std::fs::remove_dir_all(s.audit().join("sessions")).unwrap();

    let out = report(&s, &ws, &[]);
    assert_eq!(code(&out), 2, "{}", printed(&out));
    assert!(
        printed(&out).contains("session_missing"),
        "{}",
        printed(&out)
    );
}

/// append 권한만 가진 공격자가 하는 일. 세션 체인 끝에 자체 정합적인 엔트리 `count` 개를
/// 잇고, `fix_head` 면 head.json 도 새 끝으로 맞춥니다. 마지막 엔트리의 (seq, hash) 를
/// 돌려줍니다
fn forge_tail(dir: &Path, count: u64, fix_head: bool) -> (u64, airlock_audit::Hash) {
    use airlock_audit::{Decision, Entry, Event, FileMode, Head, Record};
    use std::io::Write;

    let chain = dir.join("chain.jsonl");
    let entries: Vec<Entry> = std::fs::read_to_string(&chain)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let mut last = entries.last().unwrap().clone();
    let mut body = String::new();
    for _ in 0..count {
        let forged = Entry::seal(
            last.seq + 1,
            last.ts + 1,
            last.session,
            last.enforcement,
            last.hash,
            Record::new(
                "pid:1 test",
                Event::FileAccess {
                    path_requested: "/Users/me/.ssh/id_ed25519".into(),
                    path_resolved: "/Users/me/.ssh/id_ed25519".into(),
                    mode: FileMode::Read,
                },
                Decision::Allow,
            ),
        );
        body.push_str(&serde_json::to_string(&forged).unwrap());
        body.push('\n');
        last = forged;
    }
    std::fs::OpenOptions::new()
        .append(true)
        .open(&chain)
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    if fix_head {
        std::fs::write(
            dir.join("head.json"),
            serde_json::to_string_pretty(&Head {
                version: 1,
                seq: last.seq,
                hash: last.hash,
                session: last.session,
            })
            .unwrap(),
        )
        .unwrap();
    }
    (last.seq, last.hash)
}

#[test]
fn appending_after_close_with_a_fresh_anchor_fails_verify_and_report() {
    // H2. chain.jsonl 과 anchors.jsonl 에 append 만 할 수 있는 공격자가 종료된 세션에 위조
    // 엔트리를 잇고 새 head 를 가리키는 앵커 한 줄을 더한다. 재앵커링을 "체크포인트" 로
    // 허용하면 verify 는 0, report 는 이상 없음이 된다
    let s = Scratch::new("report-reanchor");
    let ws = work_dir(&s);
    one_session(&s, &ws);

    let session_dir = s.session();
    let first: airlock_audit::Entry =
        serde_json::from_str(s.chain().lines().next().unwrap()).unwrap();
    let (seq, hash) = forge_tail(&session_dir, 2, true);
    airlock_audit::AnchorLog::open(s.audit())
        .unwrap()
        .append(first.session, seq, hash)
        .unwrap();

    let verify = airlock(
        &s,
        &ws,
        &[
            "audit",
            "verify",
            "--anchor-dir",
            s.audit().to_str().unwrap(),
            session_dir.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&verify), 2, "{}", printed(&verify));
    assert!(
        printed(&verify).contains("다시 앵커함"),
        "두 번째 앵커 줄이 실패로 보고되어야 함: {}",
        printed(&verify)
    );

    let out = report(&s, &ws, &[]);
    assert_eq!(code(&out), 2, "{}", printed(&out));
    assert!(
        printed(&out).contains("anchor_chain_broken"),
        "{}",
        printed(&out)
    );

    let json = report_json(&s, &ws);
    let kinds: Vec<&str> = json["anomalies"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["kind"].as_str())
        .collect();
    assert!(kinds.contains(&"anchor_chain_broken"), "{kinds:?}");
    // session_end 뒤의 엔트리는 세션 체인 층에서도 따로 걸린다
    assert!(kinds.contains(&"integrity"), "{kinds:?}");
    assert_eq!(json["exit_code"], 2, "{json}");
}

#[test]
fn appending_after_session_end_without_a_new_anchor_fails() {
    let s = Scratch::new("report-after-end");
    let ws = work_dir(&s);
    one_session(&s, &ws);

    let session_dir = s.session();
    forge_tail(&session_dir, 1, true);

    let verify = airlock(
        &s,
        &ws,
        &[
            "audit",
            "verify",
            "--anchor-dir",
            s.audit().to_str().unwrap(),
            session_dir.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&verify), 2, "{}", printed(&verify));
    assert!(
        printed(&verify).contains("session_end"),
        "{}",
        printed(&verify)
    );

    let out = report(&s, &ws, &[]);
    assert_eq!(code(&out), 2, "{}", printed(&out));
}

#[test]
fn an_anchored_session_with_a_lagging_head_is_an_evidence_anomaly() {
    // SIGKILL 로 죽어 앵커가 없는 세션에 공격자가 엔트리 하나를 잇고(head.json 은 못 건드림)
    // 첫 앵커를 대신 쓴다. 세션 체인만 보면 크래시 잔여 경고이고 앵커는 head 와 일치한다
    use airlock_audit::{
        AnchorLog, AuditLog, Decision, Enforcement, Event, FileMode, GenesisInfo, Hash, Mediation,
        Record, SessionId,
    };

    let s = Scratch::new("report-anchored-lag");
    let ws = work_dir(&s);
    let dir = s.audit().join("sessions").join("1700000000000000000-1");
    let id = SessionId::from_bytes([4; 16]);
    {
        let mut log = AuditLog::create(
            &dir,
            id,
            Enforcement::Observe,
            true,
            GenesisInfo {
                airlock_version: "0.0.0-test".into(),
                argv: vec!["airlock".into(), "run".into()],
                cwd: "/tmp".into(),
                policy_digest: Hash::ZERO,
                policy_source: None,
                mediation: Mediation::Off,
                operator: None,
                policy_signer: None,
            },
        )
        .unwrap();
        log.append(Record::new(
            "pid:1 test",
            Event::FileAccess {
                path_requested: "/tmp/a".into(),
                path_resolved: "/tmp/a".into(),
                mode: FileMode::Read,
            },
            Decision::Allow,
        ))
        .unwrap();
    }
    let (seq, hash) = forge_tail(&dir, 1, false);
    AnchorLog::open(s.audit())
        .unwrap()
        .append(id, seq, hash)
        .unwrap();

    let verify = airlock(
        &s,
        &ws,
        &[
            "audit",
            "verify",
            "--anchor-dir",
            s.audit().to_str().unwrap(),
            dir.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&verify), 2, "{}", printed(&verify));
    assert!(
        printed(&verify).contains("크래시 잔여일 수 없음"),
        "{}",
        printed(&verify)
    );

    let out = report(&s, &ws, &[]);
    assert_eq!(code(&out), 2, "{}", printed(&out));
    assert!(
        printed(&out).contains("anchored_head_lag"),
        "{}",
        printed(&out)
    );
    let json = report_json(&s, &ws);
    assert_eq!(
        json["sessions"][0]["anchor"]["status"], "mismatch",
        "{json}"
    );
}

#[test]
fn a_tampered_review_chain_makes_the_report_exit_non_zero() {
    let s = Scratch::new("report-review-tamper");
    let ws = work_dir(&s);
    one_session(&s, &ws);
    let ack = airlock(
        &s,
        &ws,
        &["audit", "ack", "--audit-root", s.audit().to_str().unwrap()],
    );
    assert_eq!(code(&ack), 0, "{}", printed(&ack));

    let reviews = s.audit().join("reviews.jsonl");
    let body = std::fs::read_to_string(&reviews).unwrap();
    std::fs::write(&reviews, body.replacen("\"clean\"", "\"anomalous\"", 1)).unwrap();

    let out = report(&s, &ws, &[]);
    assert_eq!(code(&out), 2, "{}", printed(&out));
    assert!(
        printed(&out).contains("review_chain_broken"),
        "{}",
        printed(&out)
    );
}

#[test]
fn a_deleted_review_line_is_caught() {
    let s = Scratch::new("report-review-delete");
    let ws = work_dir(&s);
    one_session(&s, &ws);
    for _ in 0..2 {
        let ack = airlock(
            &s,
            &ws,
            &["audit", "ack", "--audit-root", s.audit().to_str().unwrap()],
        );
        assert_eq!(code(&ack), 0, "{}", printed(&ack));
    }

    let reviews = s.audit().join("reviews.jsonl");
    let body = std::fs::read_to_string(&reviews).unwrap();
    let kept: Vec<&str> = body.lines().skip(1).collect();
    std::fs::write(&reviews, format!("{}\n", kept.join("\n"))).unwrap();

    let out = report(&s, &ws, &[]);
    assert_eq!(code(&out), 2, "{}", printed(&out));
}

#[test]
fn ack_records_the_reviewer_and_the_report_shows_it() {
    let s = Scratch::new("ack");
    let ws = work_dir(&s);
    one_session(&s, &ws);

    let ack = airlock(
        &s,
        &ws,
        &[
            "audit",
            "ack",
            "--audit-root",
            s.audit().to_str().unwrap(),
            "--note",
            "일일 점검 완료",
        ],
    );
    assert_eq!(code(&ack), 0, "{}", printed(&ack));
    assert!(printed(&ack).contains("확인 기록"), "{}", printed(&ack));

    let after = report(&s, &ws, &[]);
    assert_eq!(code(&after), 0, "{}", printed(&after));
    let text = printed(&after);
    assert!(text.contains("마지막 확인"), "{text}");
    assert!(text.contains("일일 점검 완료"), "{text}");
    assert!(!text.contains("확인 기록 없음"), "{text}");

    // 확인자 uid 는 커널이 읽은 값이어야 합니다
    let json = report_json(&s, &ws);
    let last = &json["review"]["last"];
    assert!(last["reviewer_uid"].is_number(), "{json}");
    assert!(last["reviewer_euid"].is_number(), "{json}");
    assert_eq!(last["verdict"], "clean", "{json}");
    assert_eq!(json["review"]["status"], "ok", "{json}");
}

#[test]
fn a_new_session_after_the_last_ack_is_revealed() {
    // 매일 점검이 밀렸는지 사람이 보는 유일한 방법입니다
    let s = Scratch::new("ack-stale");
    let ws = work_dir(&s);
    one_session(&s, &ws);
    let ack = airlock(
        &s,
        &ws,
        &["audit", "ack", "--audit-root", s.audit().to_str().unwrap()],
    );
    assert_eq!(code(&ack), 0, "{}", printed(&ack));

    one_session(&s, &ws);
    let out = report(&s, &ws, &[]);
    let text = printed(&out);
    assert!(text.contains("미확인"), "새 세션이 드러나야 함: {text}");

    let json = report_json(&s, &ws);
    assert_eq!(json["review"]["sessions_after_last_review"], 1, "{json}");
}

#[test]
fn acking_a_different_range_does_not_cover_this_one() {
    // 사람이 보지 않은 범위에 도장을 옮겨 찍을 수 없어야 합니다
    let s = Scratch::new("ack-range");
    let ws = work_dir(&s);
    one_session(&s, &ws);

    let ack = airlock(
        &s,
        &ws,
        &[
            "audit",
            "ack",
            "--audit-root",
            s.audit().to_str().unwrap(),
            "--since",
            "2000-01-01",
            "--until",
            "2000-01-02",
        ],
    );
    assert_eq!(code(&ack), 0, "{}", printed(&ack));

    let json = report_json(&s, &ws);
    let last = &json["review"]["last"];
    assert_eq!(last["since"], "2000-01-01", "{json}");
    assert!(
        last["sessions"].as_array().map(|v| v.len()) == Some(0),
        "그 범위에는 세션이 없었으므로 이 범위를 확인한 것이 아님: {json}"
    );
    assert_ne!(
        last["report_digest"], json["report_digest"],
        "다른 범위의 다이제스트가 이 범위의 것과 같으면 안 됨: {json}"
    );
}

#[test]
fn a_bad_date_is_a_usage_error() {
    let s = Scratch::new("report-baddate");
    let ws = work_dir(&s);
    one_session(&s, &ws);
    for bad in ["2026-13-01", "20260826", "2026-02-30"] {
        let out = report(&s, &ws, &["--since", bad]);
        assert_eq!(code(&out), 64, "{bad}: {}", printed(&out));
    }
}

#[test]
fn the_json_report_has_a_stable_schema_and_no_colour_codes() {
    let s = Scratch::new("report-json");
    let ws = work_dir(&s);
    one_session(&s, &ws);

    let out = report(&s, &ws, &["--json"]);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(!text.contains('\u{1b}'), "JSON 에 색상 코드가 섞이면 안 됨");

    let json: serde_json::Value = serde_json::from_str(&text).expect("JSON 파싱");
    assert_eq!(json["schema"], "airlock.audit-report.v1");
    for key in [
        "generated_ts",
        "root",
        "anchor_dir",
        "range",
        "body_digest",
        "report_digest",
        "verdict",
        "exit_code",
        "anchor_chain",
        "review",
        "sessions",
        "totals",
        "anomalies",
    ] {
        assert!(!json[key].is_null(), "{key} 가 없음: {json}");
    }
    let session = &json["sessions"][0];
    for key in [
        "dir",
        "session",
        "started_ts",
        "integrity",
        "anchor",
        "decisions",
        "approvals",
        "denied_exec",
        "egress",
    ] {
        assert!(!session[key].is_null(), "sessions[0].{key} 가 없음: {json}");
    }
    assert_eq!(session["integrity"]["status"], "ok", "{json}");
    assert_eq!(session["anchor"]["status"], "matches", "{json}");
    assert_eq!(json["exit_code"], 0, "{json}");
}

#[test]
fn an_auto_approved_session_never_looks_human_confirmed() {
    // --yes 세션의 승인은 사람 신원이 없습니다. 그것을 사람 확인처럼 보이게 하면
    // 승인 통제 자체가 무의미해집니다
    let s = Scratch::new("report-auto");
    let ws = work_dir(&s);
    // 베이스라인의 sudo-exec 이 ask 이므로 --yes 가 그것을 자동 승인합니다
    let out = airlock(
        &s,
        &ws,
        &[
            "run",
            "--audit-dir",
            s.audit().to_str().unwrap(),
            "--observe",
            "--yes",
            "--",
            "/usr/bin/sudo",
            "-V",
        ],
    );
    let _ = out;

    let json = report_json(&s, &ws);
    let approvals = &json["sessions"][0]["approvals"];
    assert_eq!(
        approvals["identified"], 0,
        "자동 승인이 사람 승인으로 세어지면 안 됨: {json}"
    );
    if approvals["unidentified"].as_u64().unwrap_or(0) > 0 {
        assert!(
            printed(&report(&s, &ws, &[])).contains("신원없음"),
            "신원 없는 승인이 화면에 드러나야 함"
        );
        // --strict-approval 은 신원 없이 허용된 건만 이상으로 셉니다
        if approvals["auto_granted"].as_u64().unwrap_or(0) > 0 {
            let strict = report(&s, &ws, &["--strict-approval"]);
            assert_eq!(code(&strict), 3, "{}", printed(&strict));
        }
    }
}

#[test]
fn an_unanswered_ask_is_an_operational_anomaly() {
    // 사람이 답하지 않고 죽은 세션을 직접 만듭니다. 브로커 경로로는 승인자가 언제나
    // 무언가를 답하므로 이 상태는 크래시로만 생깁니다
    use airlock_audit::{
        AnchorLog, AuditLog, Decision, Enforcement, Event, GenesisInfo, Hash, Mediation, Record,
        SessionId,
    };

    let s = Scratch::new("report-unanswered");
    let ws = work_dir(&s);
    let dir = s.audit().join("sessions").join("1700000000000000000-1");
    let id = SessionId::from_bytes([3; 16]);
    let (head_seq, head_hash) = {
        let mut log = AuditLog::create(
            &dir,
            id,
            Enforcement::Observe,
            true,
            GenesisInfo {
                airlock_version: "0.0.0-test".into(),
                argv: vec!["airlock".into(), "run".into()],
                cwd: "/tmp".into(),
                policy_digest: Hash::ZERO,
                policy_source: None,
                mediation: Mediation::Off,
                operator: None,
                policy_signer: None,
            },
        )
        .unwrap();
        log.append(
            Record::new(
                "pid:1 test",
                Event::Exec {
                    program: "/bin/rm".into(),
                    argv: vec!["rm".into(), "-rf".into()],
                    cwd: "/tmp".into(),
                },
                Decision::Ask,
            )
            .with_rule("danger-rm"),
        )
        .unwrap();
        (log.head_seq().unwrap(), log.head_hash())
    };
    AnchorLog::open(s.audit())
        .unwrap()
        .append(id, head_seq, head_hash)
        .unwrap();

    let out = report(&s, &ws, &[]);
    assert_eq!(code(&out), 3, "{}", printed(&out));
    assert!(
        printed(&out).contains("unanswered_ask"),
        "{}",
        printed(&out)
    );

    let json = report_json(&s, &ws);
    assert_eq!(
        json["sessions"][0]["approvals"]["unanswered_ask"], 1,
        "{json}"
    );
    assert_eq!(json["exit_code"], 3, "{json}");
    assert_eq!(json["verdict"], "anomalous", "{json}");
}
