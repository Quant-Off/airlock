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
            "/bin/sh",
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
