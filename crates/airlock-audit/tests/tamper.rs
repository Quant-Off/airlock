use std::fs;
use std::path::{Path, PathBuf};

use airlock_canonical::Encoder;

use airlock_audit::{
    AuditLog, CHAIN_FILE, Decision, Enforcement, Entry, Event, ExitStatus, FileMode, GenesisInfo,
    Granted, HEAD_FILE, Hash, Head, Mediation, Record, SessionId, Warning, now_unix_nanos,
    verify_dir,
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
        operator: None,
        policy_signer: None,
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
                approver_uid: Some(501),
                approver_tty: Some("/dev/ttys004".into()),
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
                approver_uid: None,
                approver_tty: None,
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
    // 세션 체인 층만의 판정이다. 앵커가 있는 세션에서는 앵커 대조가 이것을 실패로 올린다
    // (tests/anchor.rs 의 an_anchored_session_with_a_lagging_head_is_a_failure)
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
    assert_eq!(report.head_lag(), Some(3));
    assert!(report.fsync_per_entry);
}

// ---------- session_end 이후 ----------

fn session_end() -> Event {
    Event::SessionEnd {
        status: ExitStatus::Exited { code: 0 },
    }
}

#[test]
fn a_chain_ending_with_session_end_is_clean_and_marked_ended() {
    let s = Scratch::new("ended");
    let mut log = AuditLog::create(
        s.path(),
        SessionId::from_bytes([0xAB; 16]),
        Enforcement::Landlock,
        true,
        genesis(),
    )
    .unwrap();
    log.append(Record::new("airlock", session_end(), Decision::Allow))
        .unwrap();

    let report = verify_dir(s.path()).unwrap();
    assert!(report.is_clean(), "{:?}", report.warnings);
    assert!(report.session_ended);

    let s2 = Scratch::new("not-ended");
    build_chain(s2.path(), Enforcement::Landlock);
    let report = verify_dir(s2.path()).unwrap();
    assert!(
        !report.session_ended,
        "session_end 가 없는 체인이 끝난 것으로 보이면 안 됨"
    );
}

#[test]
fn entries_after_session_end_are_fatal() {
    // 브로커는 session_end 뒤의 append 를 거부하므로 이 상태는 종료 뒤 덧붙이기로만 생긴다.
    // 앵커가 있든 없든 세션 체인 층에서 실패해야 한다
    let s = Scratch::new("after-end");
    let mut log = AuditLog::create(
        s.path(),
        SessionId::from_bytes([0xAB; 16]),
        Enforcement::Landlock,
        true,
        genesis(),
    )
    .unwrap();
    log.append(Record::new("airlock", session_end(), Decision::Allow))
        .unwrap();
    // AuditLog 자체는 닫힘을 모르므로 append 가 성공한다. 그것이 공격자가 하는 일이다
    log.append(Record::new(
        "pid:100 claude",
        file_read("/Users/me/.ssh/id_ed25519"),
        Decision::Allow,
    ))
    .unwrap();

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(
            err,
            airlock_audit::Failure::EntryAfterSessionEnd { end_seq: 1, seq: 2 }
        ),
        "session_end 뒤의 엔트리가 통과하면 종료된 세션에 무엇이든 덧붙일 수 있음: {err}"
    );
    assert!(err.to_string().contains("덧붙이기 의심"), "{err}");
}

#[test]
fn a_second_session_end_is_also_fatal() {
    let s = Scratch::new("double-end");
    let mut log = AuditLog::create(
        s.path(),
        SessionId::from_bytes([0xAB; 16]),
        Enforcement::Landlock,
        true,
        genesis(),
    )
    .unwrap();
    log.append(Record::new("airlock", session_end(), Decision::Allow))
        .unwrap();
    log.append(Record::new("airlock", session_end(), Decision::Allow))
        .unwrap();

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(
            err,
            airlock_audit::Failure::EntryAfterSessionEnd { end_seq: 1, seq: 2 }
        ),
        "{err}"
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

// ---------- 포맷 버전 (v1 -> v2) ----------

#[test]
fn downgraded_version_is_reported_as_old_format_not_tampering() {
    let s = Scratch::new("v-downgrade");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    entries[2].v = 1;
    write_entries(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(
            err,
            airlock_audit::Failure::FormatVersionUnsupported { seq: 2, got: 1 }
        ),
        "옛 포맷과 위조가 같은 사유로 보고되면 진짜 변조가 소음에 묻힘: {err}"
    );
    assert!(
        !matches!(err, airlock_audit::Failure::HashMismatch { .. }),
        "버전 검사가 해시 검사보다 먼저 오지 않았음: {err}"
    );
}

#[test]
fn self_consistent_v1_line_is_still_rejected() {
    let s = Scratch::new("v-resealed");
    build_chain(s.path(), Enforcement::Landlock);

    let mut entries = read_entries(s.path());
    // 버전을 낮추고 해시까지 다시 계산한 줄. 자체적으로는 정합적이다
    entries[2].v = 1;
    entries[2].hash = entries[2].recompute_hash();
    entries[3].prev = entries[2].hash;
    entries[3].hash = entries[3].recompute_hash();
    entries[4].prev = entries[3].hash;
    entries[4].hash = entries[4].recompute_hash();
    write_entries(s.path(), &entries);
    reanchor(s.path(), &entries);

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(
            err,
            airlock_audit::Failure::FormatVersionUnsupported { seq: 2, got: 1 }
        ),
        "버전을 낮춰 옛 검증 규칙을 끌어오는 것이 통과하면 안 됨: {err}"
    );
}

#[test]
fn version_is_bound_into_the_hash() {
    let s = Scratch::new("v-hashed");
    build_chain(s.path(), Enforcement::Landlock);

    let entries = read_entries(s.path());
    let mut downgraded = entries[2].clone();
    downgraded.v = 1;
    assert_ne!(
        downgraded.recompute_hash(),
        entries[2].hash,
        "v가 해시 밖에 있으면 위조자가 버전만 바꿔 끼울 수 있음"
    );
}

#[test]
fn v1_shaped_line_without_the_field_is_rejected_not_migrated() {
    let s = Scratch::new("v-missing");
    build_chain(s.path(), Enforcement::Landlock);

    // v 필드가 아예 없는 v1 형태 줄. 파싱은 성공해야 하고(그래야 사유가 정확해진다)
    // 검증은 포맷 불일치로 거부해야 한다
    let raw = fs::read_to_string(s.path().join(CHAIN_FILE)).unwrap();
    let mut body = String::new();
    for line in raw.lines() {
        let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
        value.as_object_mut().unwrap().remove("v");
        body.push_str(&serde_json::to_string(&value).unwrap());
        body.push('\n');
    }
    fs::write(s.path().join(CHAIN_FILE), body).unwrap();

    let err = verify_dir(s.path()).unwrap_err();
    assert!(
        matches!(
            err,
            airlock_audit::Failure::FormatVersionUnsupported { seq: 0, got: 1 }
        ),
        "v1 줄은 MalformedLine이 아니라 포맷 불일치로 보고되어야 함: {err}"
    );
    assert!(
        !matches!(err, airlock_audit::Failure::MalformedLine { .. }),
        "사유가 '필드 누락'으로 뭉개지면 7.9가 닫히지 않음: {err}"
    );
}

#[test]
fn v1_domain_bytes_never_match_a_v2_entry() {
    let s = Scratch::new("v-domain");
    build_chain(s.path(), Enforcement::Landlock);

    let entries = read_entries(s.path());
    let e = &entries[1];

    // 진짜 v1 검증자가 계산하던 바이트열의 앞부분. 도메인이 다르고 u32(v)가 없다
    let mut v1 = Encoder::with_domain(b"airlock.audit.v1\x00");
    v1.u64(e.seq)
        .bytes(e.prev.as_bytes())
        .u64(e.ts)
        .bytes(e.session.as_bytes())
        .str(&e.actor);
    let mut v2 = Encoder::with_domain(airlock_audit::DOMAIN);
    v2.u32(e.v)
        .u64(e.seq)
        .bytes(e.prev.as_bytes())
        .u64(e.ts)
        .bytes(e.session.as_bytes())
        .str(&e.actor);
    assert_ne!(
        v1.finish(),
        v2.finish(),
        "도메인까지 올리지 않으면 버전 신호가 단일 실패 지점이 됨"
    );

    // v만 1로 낮춰 다시 봉인해도 v2 도메인 위에서 계산되므로 v1 바이트와 무관하다
    let mut downgraded = e.clone();
    downgraded.v = 1;
    assert_ne!(downgraded.recompute_hash(), e.hash);
}

// ---------- v2에서 늘어난 필드가 실제로 해시에 들어가는가 ----------

fn sealed(event: Event) -> Entry {
    Entry::seal(
        0,
        1_700_000_000_000_000_000,
        SessionId::from_bytes([0xAB; 16]),
        Enforcement::Landlock,
        Hash::ZERO,
        Record::new("airlock", event, Decision::Allow),
    )
}

fn session_start(
    uid: u32,
    euid: u32,
    operator: Option<&str>,
    policy_signer: Option<&str>,
) -> Event {
    Event::SessionStart {
        airlock_version: "0.1.0".into(),
        argv: vec!["airlock".into(), "run".into()],
        cwd: "/Users/me/work".into(),
        policy_digest: Hash::from_bytes([0x42; 32]),
        policy_source: Some("airlock.toml".into()),
        fsync_per_entry: true,
        mediation: Mediation::ExecNet,
        uid,
        euid,
        operator: operator.map(str::to_string),
        policy_signer: policy_signer.map(str::to_string),
    }
}

#[test]
fn genesis_identity_fields_are_hashed() {
    let base = sealed(session_start(501, 501, None, None)).hash;

    assert_ne!(base, sealed(session_start(0, 501, None, None)).hash, "uid");
    assert_ne!(base, sealed(session_start(501, 0, None, None)).hash, "euid");
    assert_ne!(
        base,
        sealed(session_start(501, 501, Some("felix"), None)).hash,
        "operator"
    );
    assert_ne!(
        base,
        sealed(session_start(501, 501, None, Some("secops"))).hash,
        "policy_signer"
    );
    assert_ne!(
        sealed(session_start(501, 0, None, None)).hash,
        sealed(session_start(0, 501, None, None)).hash,
        "uid와 euid가 뒤바뀐 두 세션이 같은 해시를 가지면 안 됨"
    );
}

#[test]
fn approver_identity_is_hashed() {
    let approval = |uid: Option<u32>, tty: Option<&str>| {
        sealed(Event::Approval {
            for_seq: 0,
            granted: Granted::Approved,
            note: Some("사용자 승인".into()),
            approver_uid: uid,
            approver_tty: tty.map(str::to_string),
        })
        .hash
    };

    let base = approval(None, None);
    assert_ne!(base, approval(Some(501), None), "approver_uid");
    assert_ne!(base, approval(None, Some("/dev/ttys004")), "approver_tty");
    assert_ne!(
        approval(Some(0), None),
        approval(Some(501), None),
        "승인자 uid를 바꿔치기해도 해시가 그대로면 책임 확인이 무의미함"
    );
}

#[test]
fn egress_summary_fields_are_hashed() {
    let summary = |bytes_out: u64, bytes_in: u64, duration_ms: u64| {
        sealed(Event::EgressSummary {
            host: "api.anthropic.com".into(),
            port: 443,
            protocol: airlock_audit::Protocol::Tls,
            bytes_out,
            bytes_in,
            duration_ms,
        })
        .hash
    };

    let base = summary(1_024, 4_096, 250);
    assert_ne!(base, summary(1_025, 4_096, 250), "bytes_out");
    assert_ne!(base, summary(1_024, 4_097, 250), "bytes_in");
    assert_ne!(base, summary(1_024, 4_096, 251), "duration_ms");
    assert_ne!(
        base,
        summary(4_096, 1_024, 250),
        "송신량과 수신량이 뒤바뀐 기록이 같은 해시를 가지면 반출량을 위조할 수 있음"
    );
}

#[test]
fn egress_summary_survives_a_full_chain_roundtrip() {
    let s = Scratch::new("egress-summary");
    let mut log = AuditLog::create(
        s.path(),
        SessionId::from_bytes([0xAB; 16]),
        Enforcement::Landlock,
        true,
        genesis(),
    )
    .unwrap();
    log.append(Record::new(
        "pid:100 claude",
        Event::Egress {
            host: "api.anthropic.com".into(),
            port: 443,
            protocol: airlock_audit::Protocol::Tls,
        },
        Decision::Allow,
    ))
    .unwrap();
    let summary = log
        .append(Record::new(
            "airlock",
            Event::EgressSummary {
                host: "api.anthropic.com".into(),
                port: 443,
                protocol: airlock_audit::Protocol::Tls,
                bytes_out: 12_345,
                bytes_in: 67_890,
                duration_ms: 1_200,
            },
            Decision::Allow,
        ))
        .unwrap();

    let report = verify_dir(s.path()).unwrap();
    assert_eq!(report.entries, 3);
    assert_eq!(report.head_hash, summary.hash);

    let entries = read_entries(s.path());
    assert_eq!(entries[2].event.kind(), "egress_summary");
    assert_eq!(entries[2].event.tag(), 0x13);
    assert!(entries.iter().all(|e| e.v == 2));
}

#[test]
fn genesis_records_the_observed_uid() {
    let s = Scratch::new("genesis-uid");
    build_chain(s.path(), Enforcement::Landlock);

    let entries = read_entries(s.path());
    match &entries[0].event {
        Event::SessionStart {
            uid,
            euid,
            operator,
            policy_signer,
            ..
        } => {
            // 감사 층이 직접 읽은 값이어야 한다. 호출자는 넘길 수 없다
            //
            // # Safety
            // getuid(2)와 geteuid(2)는 인자가 없고 메모리를 건드리지 않으며 실패하지 않는다
            let (real_uid, real_euid) = unsafe { (libc::getuid(), libc::geteuid()) };
            assert_eq!(*uid, real_uid);
            assert_eq!(*euid, real_euid);
            assert!(operator.is_none());
            assert!(policy_signer.is_none());
        }
        other => panic!("제네시스가 session_start가 아님: {other:?}"),
    }
}
