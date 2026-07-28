use std::fs;
use std::path::{Path, PathBuf};

use airlock_audit::{
    AuditLog, CHAIN_FILE, Decision, Enforcement, Entry, Event, FileMode, GenesisInfo, Granted,
    HEAD_FILE, Hash, Head, Mediation, Record, SessionId, Warning, now_unix_nanos, verify_dir,
};

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "airlock-tamper-{name}-{}-{}",
            std::process::id(),
            now_unix_nanos()
        ));
        Self(p)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn genesis() -> GenesisInfo {
    GenesisInfo {
        airlock_version: "0.1.0".into(),
        argv: vec!["airlock".into(), "run".into(), "--".into(), "claude".into()],
        cwd: "/Users/me/work".into(),
        policy_digest: Hash::from_bytes([0x42; 32]),
        policy_source: Some("airlock.toml".into()),
        mediation: Mediation::ExecNet,
    }
}

fn file_read(path: &str) -> Event {
    Event::FileAccess {
        path_requested: path.into(),
        path_resolved: path.into(),
        mode: FileMode::Read,
    }
}

fn build_chain(dir: &Path, enforcement: Enforcement) -> Vec<Entry> {
    let mut log = AuditLog::create(
        dir,
        SessionId::from_bytes([0xAB; 16]),
        enforcement,
        true,
        genesis(),
    )
    .unwrap();

    let mut out = Vec::new();
    out.push(
        log.append(Record::new(
            "pid:100 claude",
            file_read("/Users/me/work/src/main.rs"),
            Decision::Allow,
        ))
        .unwrap(),
    );
    let ask = log
        .append(
            Record::new(
                "pid:100 claude",
                Event::Exec {
                    program: "rm".into(),
                    argv: vec!["rm".into(), "-rf".into(), "build".into()],
                    cwd: "/Users/me/work".into(),
                },
                Decision::Ask,
            )
            .with_rule("danger-rm"),
        )
        .unwrap();
    out.push(ask.clone());
    out.push(
        log.append(Record::new(
            "airlock",
            Event::Approval {
                for_seq: ask.seq,
                granted: Granted::Approved,
                note: Some("사용자 승인".into()),
            },
            Decision::Allow,
        ))
        .unwrap(),
    );
    out.push(
        log.append(
            Record::new(
                "pid:100 claude",
                file_read("/Users/me/.ssh/id_ed25519"),
                Decision::Deny,
            )
            .with_rule("ssh-private-keys"),
        )
        .unwrap(),
    );
    out
}

fn read_entries(dir: &Path) -> Vec<Entry> {
    fs::read_to_string(dir.join(CHAIN_FILE))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn write_entries(dir: &Path, entries: &[Entry]) {
    let mut body = String::new();
    for e in entries {
        body.push_str(&serde_json::to_string(e).unwrap());
        body.push('\n');
    }
    fs::write(dir.join(CHAIN_FILE), body).unwrap();
}

fn reanchor(dir: &Path, entries: &[Entry]) {
    let last = entries.last().unwrap();
    let head = Head {
        version: 1,
        seq: last.seq,
        hash: last.hash,
        session: last.session,
    };
    fs::write(
        dir.join(HEAD_FILE),
        serde_json::to_string_pretty(&head).unwrap(),
    )
    .unwrap();
}

// ---------- 정상 경로 ----------

#[test]
fn clean_chain_verifies() {
    let s = Scratch::new("clean");
    build_chain(s.path(), Enforcement::Landlock);
    let report = verify_dir(s.path()).unwrap();
    assert_eq!(report.entries, 5);
    assert_eq!(report.head_seq, 4);
    assert!(report.is_clean(), "예상치 못한 경고: {:?}", report.warnings);
}

#[test]
fn observe_mode_is_reported_as_unenforced() {
    let s = Scratch::new("observe");
    build_chain(s.path(), Enforcement::Observe);
    let report = verify_dir(s.path()).unwrap();
    assert!(
        report
            .warnings
            .iter()
            .any(|w| matches!(w, Warning::ObserveOnlyEntries { count: 5 })),
        "observe 기록이 강제된 것처럼 보고되면 안 됨: {:?}",
        report.warnings
    );
}

// ---------- 변조 탐지 ----------

#[test]
fn modified_field_is_detected() {
    let s = Scratch::new("modify");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    entries[4].decision = Decision::Allow;
    write_entries(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::HashMismatch { seq: 4, .. }),
        "시크릿 접근 거부를 허용으로 바꾼 변조를 놓쳤음: {err}"
    );
}

#[test]
fn modified_path_is_detected() {
    let s = Scratch::new("modify-path");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    entries[4].event = file_read("/Users/me/work/harmless.txt");
    write_entries(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(matches!(
        err,
        airlock_audit::Failure::HashMismatch { seq: 4, .. }
    ));
}

#[test]
fn deleted_middle_entry_is_detected() {
    let s = Scratch::new("delete");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    entries.remove(2);
    write_entries(s.path(), &entries);
    reanchor(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(
            err,
            airlock_audit::Failure::SeqGap {
                expected: 2,
                got: 3
            }
        ),
        "{err}"
    );
}

#[test]
fn reordered_entries_are_detected() {
    let s = Scratch::new("reorder");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    entries.swap(1, 2);
    write_entries(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(
            err,
            airlock_audit::Failure::SeqGap {
                expected: 1,
                got: 2
            }
        ),
        "{err}"
    );
}

#[test]
fn inserted_entry_with_resealed_hash_is_detected() {
    let s = Scratch::new("insert");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    let forged = Entry::seal(
        3,
        entries[3].ts,
        entries[3].session,
        entries[3].enforcement,
        entries[2].hash,
        Record::new(
            "pid:100 claude",
            file_read("/Users/me/work/injected.rs"),
            Decision::Allow,
        ),
    );
    assert!(forged.hash_is_valid());
    entries[3] = forged;
    write_entries(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::PrevMismatch { seq: 4, .. }),
        "자체 정합적인 위조 엔트리 삽입을 놓쳤음: {err}"
    );
}

#[test]
fn relinked_prev_is_detected() {
    let s = Scratch::new("relink");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    entries[3].prev = entries[1].hash;
    entries[3].hash = entries[3].recompute_hash();
    write_entries(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::PrevMismatch { seq: 3, .. }),
        "{err}"
    );
}

#[test]
fn truncated_tail_is_detected_by_anchor() {
    let s = Scratch::new("truncate");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    entries.truncate(3);
    write_entries(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::HeadMismatch { .. }),
        "시크릿 접근 기록을 잘라낸 것을 놓쳤음: {err}"
    );
}

#[test]
fn truncated_final_line_is_detected() {
    let s = Scratch::new("partial");
    build_chain(s.path(), Enforcement::Landlock);

    let raw = fs::read_to_string(s.path().join(CHAIN_FILE)).unwrap();
    let cut = raw.len() - 30;
    fs::write(s.path().join(CHAIN_FILE), &raw[..cut]).unwrap();

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::TruncatedFinalLine { line: 5 }),
        "{err}"
    );
}

#[test]
fn grafted_entry_from_other_session_is_detected() {
    let s = Scratch::new("graft");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    entries[2].session = SessionId::from_bytes([0xCD; 16]);
    entries[2].hash = entries[2].recompute_hash();
    write_entries(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::SessionMismatch { seq: 2, .. }),
        "{err}"
    );
}

#[test]
fn genesis_prev_must_be_zero() {
    let s = Scratch::new("genesis-prev");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    entries[0].prev = Hash::from_bytes([1; 32]);
    entries[0].hash = entries[0].recompute_hash();
    write_entries(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::GenesisPrevNotZero { .. }),
        "{err}"
    );
}

#[test]
fn genesis_must_be_session_start() {
    let s = Scratch::new("genesis-kind");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    entries[0].event = file_read("/etc/passwd");
    entries[0].hash = entries[0].recompute_hash();
    write_entries(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(
            err,
            airlock_audit::Failure::GenesisNotSessionStart { got: "file_access" }
        ),
        "{err}"
    );
}

#[test]
fn empty_chain_is_rejected() {
    let s = Scratch::new("empty");
    build_chain(s.path(), Enforcement::Landlock);
    fs::write(s.path().join(CHAIN_FILE), "").unwrap();

    let err = verify_dir(s.path()).unwrap_err();
    assert!(matches!(err, airlock_audit::Failure::ChainEmpty), "{err}");
}

#[test]
fn malformed_json_is_rejected() {
    let s = Scratch::new("malformed");
    build_chain(s.path(), Enforcement::Landlock);

    let raw = fs::read_to_string(s.path().join(CHAIN_FILE)).unwrap();
    let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
    lines[2] = "{not json at all}".into();
    fs::write(s.path().join(CHAIN_FILE), lines.join("\n") + "\n").unwrap();

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::MalformedLine { line: 3, .. }),
        "{err}"
    );
}

// ---------- 승인 무결성 ----------

#[test]
fn approval_without_matching_ask_is_rejected() {
    let s = Scratch::new("approval-noask");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    if let Event::Approval { for_seq, .. } = &mut entries[3].event {
        *for_seq = 1;
    }
    entries[3].hash = entries[3].recompute_hash();
    entries[4].prev = entries[3].hash;
    entries[4].hash = entries[4].recompute_hash();
    write_entries(s.path(), &entries);
    reanchor(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(
            err,
            airlock_audit::Failure::ApprovalTargetNotAsk { seq: 3, for_seq: 1 }
        ),
        "ask가 아닌 행위에 승인을 붙인 위조를 놓쳤음: {err}"
    );
}

#[test]
fn approval_referencing_future_entry_is_rejected() {
    let s = Scratch::new("approval-future");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    if let Event::Approval { for_seq, .. } = &mut entries[3].event {
        *for_seq = 99;
    }
    entries[3].hash = entries[3].recompute_hash();
    entries[4].prev = entries[3].hash;
    entries[4].hash = entries[4].recompute_hash();
    write_entries(s.path(), &entries);
    reanchor(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(
            err,
            airlock_audit::Failure::ApprovalTargetMissing {
                seq: 3,
                for_seq: 99
            }
        ),
        "{err}"
    );
}

#[test]
fn unanswered_ask_is_warned() {
    let s = Scratch::new("unanswered");
    let mut log = AuditLog::create(
        s.path(),
        SessionId::from_bytes([1; 16]),
        Enforcement::Landlock,
        true,
        genesis(),
    )
    .unwrap();
    log.append(
        Record::new(
            "pid:1 claude",
            file_read("/Users/me/.aws/credentials"),
            Decision::Ask,
        )
        .with_rule("aws-credentials"),
    )
    .unwrap();

    let report = verify_dir(s.path()).unwrap();
    assert!(
        report
            .warnings
            .iter()
            .any(|w| matches!(w, Warning::UnansweredAsk { seq: 1 })),
        "{:?}",
        report.warnings
    );
}

// ---------- 앵커 ----------

#[test]
fn missing_anchor_is_fatal() {
    let s = Scratch::new("no-head");
    build_chain(s.path(), Enforcement::Landlock);
    fs::remove_file(s.path().join(HEAD_FILE)).unwrap();

    let err = verify_dir(s.path()).unwrap_err();
    assert!(matches!(err, airlock_audit::Failure::HeadAbsent), "{err}");
}

#[test]
fn corrupt_anchor_is_fatal() {
    let s = Scratch::new("bad-head");
    build_chain(s.path(), Enforcement::Landlock);
    fs::write(s.path().join(HEAD_FILE), b"not json at all").unwrap();

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::HeadUnreadable { .. }),
        "{err}"
    );
}

#[test]
fn truncation_plus_anchor_deletion_is_still_fatal() {
    let s = Scratch::new("truncate-and-unanchor");
    build_chain(s.path(), Enforcement::Landlock);

    let entries = read_entries(s.path());
    write_entries(s.path(), &entries[..entries.len() - 2]);
    fs::remove_file(s.path().join(HEAD_FILE)).unwrap();

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::HeadAbsent),
        "잘라내기 후 앵커를 지우면 검증이 통과해서는 안 됨: {err}"
    );
}

#[test]
fn unsupported_anchor_version_is_fatal() {
    let s = Scratch::new("head-version");
    build_chain(s.path(), Enforcement::Landlock);

    let entries = read_entries(s.path());
    let last = entries.last().unwrap();
    let head = Head {
        version: 999,
        seq: last.seq,
        hash: last.hash,
        session: last.session,
    };
    fs::write(
        s.path().join(HEAD_FILE),
        serde_json::to_string(&head).unwrap(),
    )
    .unwrap();

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(
            err,
            airlock_audit::Failure::HeadVersionUnsupported { got: 999 }
        ),
        "{err}"
    );
}

#[test]
fn blank_line_inside_the_chain_is_fatal() {
    let s = Scratch::new("blank-line");
    build_chain(s.path(), Enforcement::Landlock);

    let path = s.path().join(CHAIN_FILE);
    let body = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<&str> = body.lines().collect();
    lines.insert(2, "");
    fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::BlankLine { line: 3 }),
        "{err}"
    );
}

#[test]
fn self_referencing_approval_is_fatal() {
    let s = Scratch::new("self-approval");
    build_chain(s.path(), Enforcement::Landlock);

    let entries = read_entries(s.path());
    let target = entries.last().unwrap();
    let forged = Entry::seal(
        target.seq.saturating_add(1),
        target.ts.saturating_add(1),
        target.session,
        Enforcement::Landlock,
        target.hash,
        Record::new(
            "airlock",
            Event::Approval {
                for_seq: target.seq.saturating_add(1),
                granted: Granted::Approved,
                note: None,
            },
            Decision::Ask,
        ),
    );

    let mut all = entries.clone();
    all.push(forged);
    write_entries(s.path(), &all);
    reanchor(s.path(), &all);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::ApprovalTargetMissing { .. }),
        "자기 자신을 승인하는 엔트리는 통과해서는 안 됨: {err}"
    );
}

#[test]
fn anchor_lagging_by_one_is_treated_as_crash_residue() {
    let s = Scratch::new("head-lag");
    build_chain(s.path(), Enforcement::Landlock);

    let entries = read_entries(s.path());
    reanchor(s.path(), &entries[..entries.len() - 1]);

    let report = verify_dir(s.path()).unwrap();
    assert!(
        report.warnings.iter().any(|w| matches!(
            w,
            Warning::HeadLagsByOne {
                head_seq: 3,
                chain_seq: 4
            }
        )),
        "{:?}",
        report.warnings
    );
}

#[test]
fn anchor_lagging_by_two_is_fatal() {
    let s = Scratch::new("head-lag2");
    build_chain(s.path(), Enforcement::Landlock);

    let entries = read_entries(s.path());
    reanchor(s.path(), &entries[..entries.len() - 2]);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::HeadMismatch { .. }),
        "{err}"
    );
}

#[test]
fn anchor_from_another_session_is_fatal() {
    let s = Scratch::new("head-session");
    build_chain(s.path(), Enforcement::Landlock);

    let entries = read_entries(s.path());
    let last = entries.last().unwrap();
    let head = Head {
        version: 1,
        seq: last.seq,
        hash: last.hash,
        session: SessionId::from_bytes([0xEE; 16]),
    };
    fs::write(
        s.path().join(HEAD_FILE),
        serde_json::to_string(&head).unwrap(),
    )
    .unwrap();

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::HeadSessionMismatch { .. }),
        "{err}"
    );
}

#[test]
fn mediation_level_changes_the_genesis_hash() {
    let a = Scratch::new("mediation-a");
    let b = Scratch::new("mediation-b");

    for (s, level) in [
        (&a, airlock_audit::Mediation::Off),
        (&b, airlock_audit::Mediation::Full),
    ] {
        let mut g = genesis();
        g.mediation = level;
        AuditLog::create(
            s.path(),
            SessionId::from_bytes([0xAB; 16]),
            Enforcement::Landlock,
            true,
            g,
        )
        .unwrap();
    }

    let ga = read_entries(a.path());
    let gb = read_entries(b.path());
    assert_ne!(
        ga.first().unwrap().hash,
        gb.first().unwrap().hash,
        "중계 수준이 다르면 제네시스 해시가 달라야 함"
    );
}

#[test]
fn whitespace_only_final_line_is_a_partial_write() {
    let s = Scratch::new("trailing-space");
    build_chain(s.path(), Enforcement::Landlock);

    let path = s.path().join(CHAIN_FILE);
    let mut body = fs::read_to_string(&path).unwrap();
    // 개행 없이 공백만 남은 마지막 줄. 쓰기 도중 중단된 흔적이며 눈에 보이지 않는다
    body.push_str("   ");
    fs::write(&path, body).unwrap();

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Failure::TruncatedFinalLine { .. }),
        "{err}"
    );
}
