use std::fs;
use std::path::{Path, PathBuf};

use airlock_audit::{
    ANCHOR_FILE, AnchorCheck, AnchorEntry, AnchorFailure, AnchorLog, AuditLog, CHAIN_FILE,
    Decision, Enforcement, Entry, Event, ExitStatus, FileMode, GenesisInfo, HEAD_FILE, Hash, Head,
    Mediation, Record, SessionId, Warning, check_session_report, now_unix_nanos, verify_anchors,
    verify_dir,
};

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "airlock-anchor-{name}-{}-{}",
            std::process::id(),
            now_unix_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn root(&self) -> &Path {
        &self.0
    }

    fn session_dir(&self, name: &str) -> PathBuf {
        self.0.join("sessions").join(name)
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

/// 세션 체인 하나를 만들고 최종 head 를 돌려줍니다.
fn build_session(dir: &Path, session: SessionId) -> (u64, Hash) {
    let mut log = AuditLog::create(dir, session, Enforcement::Landlock, true, genesis()).unwrap();
    log.append(Record::new(
        "pid:100 claude",
        file_read("/Users/me/work/src/main.rs"),
        Decision::Allow,
    ))
    .unwrap();
    log.append(
        Record::new(
            "pid:100 claude",
            file_read("/Users/me/.ssh/id_ed25519"),
            Decision::Deny,
        )
        .with_rule("ssh-private-keys"),
    )
    .unwrap();
    (log.head_seq().unwrap(), log.head_hash())
}

/// 브로커처럼 `session_end` 로 끝나는 세션 체인을 만들고 최종 head 를 돌려줍니다.
fn build_closed_session(dir: &Path, session: SessionId, fsync: bool) -> (u64, Hash) {
    let mut log = AuditLog::create(dir, session, Enforcement::Landlock, fsync, genesis()).unwrap();
    log.append(Record::new(
        "pid:100 claude",
        file_read("/Users/me/work/src/main.rs"),
        Decision::Allow,
    ))
    .unwrap();
    log.append(Record::new(
        "airlock",
        Event::SessionEnd {
            status: ExitStatus::Exited { code: 0 },
        },
        Decision::Allow,
    ))
    .unwrap();
    (log.head_seq().unwrap(), log.head_hash())
}

fn read_entries(dir: &Path) -> Vec<Entry> {
    fs::read_to_string(dir.join(CHAIN_FILE))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn write_head(dir: &Path, last: &Entry) {
    fs::write(
        dir.join(HEAD_FILE),
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

/// append 권한만 가진 공격자가 하는 일. 체인 끝에 자체 정합적인 엔트리 `count` 개를
/// 잇고, `fix_head` 면 head.json 도 새 끝으로 맞춥니다.
fn forge_tail(dir: &Path, count: u64, fix_head: bool) -> (u64, Hash) {
    let entries = read_entries(dir);
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
                "pid:100 claude",
                file_read("/Users/me/.ssh/id_ed25519"),
                Decision::Allow,
            ),
        );
        assert!(forged.hash_is_valid());
        body.push_str(&serde_json::to_string(&forged).unwrap());
        body.push('\n');
        last = forged;
    }
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(dir.join(CHAIN_FILE))
        .unwrap();
    f.write_all(body.as_bytes()).unwrap();
    if fix_head {
        write_head(dir, &last);
    }
    (last.seq, last.hash)
}

fn read_anchor_lines(root: &Path) -> Vec<AnchorEntry> {
    fs::read_to_string(root.join(ANCHOR_FILE))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn write_anchor_lines(root: &Path, entries: &[AnchorEntry]) {
    let mut body = String::new();
    for e in entries {
        body.push_str(&serde_json::to_string(e).unwrap());
        body.push('\n');
    }
    fs::write(root.join(ANCHOR_FILE), body).unwrap();
}

// ---------- 정상 경로 ----------

#[test]
fn anchored_sessions_verify() {
    let s = Scratch::new("clean");
    let mut anchors = AnchorLog::open(s.root()).unwrap();

    for i in 0..3u8 {
        let session = SessionId::from_bytes([i; 16]);
        let (head_seq, head_hash) = build_session(&s.session_dir(&format!("s{i}")), session);
        anchors.append(session, head_seq, head_hash).unwrap();
    }

    let report = verify_anchors(s.root()).unwrap();
    assert_eq!(report.entries, 3);
    assert_eq!(report.sessions, 3);
    assert_eq!(report.head_seq, 2);
    assert!(report.is_clean(), "예상치 못한 경고: {:?}", report.warnings);

    // 각 세션의 실제 head 가 앵커와 맞아야 한다
    for i in 0..3u8 {
        let session = SessionId::from_bytes([i; 16]);
        let chain = verify_dir(s.session_dir(&format!("s{i}"))).unwrap();
        let check = airlock_audit::anchor::check_session(
            s.root(),
            &session,
            chain.head_seq,
            &chain.head_hash,
        )
        .unwrap();
        assert!(matches!(check, AnchorCheck::Matches { .. }), "{check:?}");
    }
}

// ---------- 앵커 자체의 변조 ----------

#[test]
fn deleted_anchor_line_is_detected() {
    let s = Scratch::new("delete");
    let mut anchors = AnchorLog::open(s.root()).unwrap();
    for i in 0..3u8 {
        let session = SessionId::from_bytes([i; 16]);
        let (head_seq, head_hash) = build_session(&s.session_dir(&format!("s{i}")), session);
        anchors.append(session, head_seq, head_hash).unwrap();
    }

    let mut lines = read_anchor_lines(s.root());
    lines.remove(1);
    write_anchor_lines(s.root(), &lines);

    let err = verify_anchors(s.root()).unwrap_err();
    assert!(
        matches!(
            err,
            AnchorFailure::SeqGap {
                expected: 1,
                got: 2
            }
        ),
        "세션 하나를 통째로 지운 흔적을 놓쳤음: {err}"
    );
}

#[test]
fn truncated_anchor_tail_needs_an_offsite_copy() {
    let s = Scratch::new("truncate");
    let mut anchors = AnchorLog::open(s.root()).unwrap();
    for i in 0..3u8 {
        let session = SessionId::from_bytes([i; 16]);
        let (head_seq, head_hash) = build_session(&s.session_dir(&format!("s{i}")), session);
        anchors.append(session, head_seq, head_hash).unwrap();
    }

    // 마지막 세션의 앵커 줄과 세션 디렉토리를 함께 지운다
    let mut lines = read_anchor_lines(s.root());
    lines.truncate(2);
    write_anchor_lines(s.root(), &lines);
    fs::remove_dir_all(s.session_dir("s2")).unwrap();

    // 앵커 체인 자체는 여전히 정합적이다. 잘라내기는 이 파일만으로 탐지되지 않는다
    let report = verify_anchors(s.root()).unwrap();
    assert_eq!(report.entries, 2);
    // 그래서 앵커는 반출되어야 의미가 있다. 사본과 대조하면 seq 2 가 사라진 것이 드러난다
    assert_eq!(report.head_seq, 1);
}

#[test]
fn modified_anchor_line_is_detected() {
    let s = Scratch::new("modify");
    let mut anchors = AnchorLog::open(s.root()).unwrap();
    for i in 0..2u8 {
        let session = SessionId::from_bytes([i; 16]);
        let (head_seq, head_hash) = build_session(&s.session_dir(&format!("s{i}")), session);
        anchors.append(session, head_seq, head_hash).unwrap();
    }

    let mut lines = read_anchor_lines(s.root());
    lines[0].head_hash = Hash::from_bytes([0xEE; 32]);
    write_anchor_lines(s.root(), &lines);

    let err = verify_anchors(s.root()).unwrap_err();
    assert!(
        matches!(err, AnchorFailure::HashMismatch { seq: 0, .. }),
        "앵커가 가리키는 head 를 바꿔치기한 것을 놓쳤음: {err}"
    );
}

#[test]
fn resealed_anchor_line_breaks_the_next_link() {
    let s = Scratch::new("reseal");
    let mut anchors = AnchorLog::open(s.root()).unwrap();
    for i in 0..3u8 {
        let session = SessionId::from_bytes([i; 16]);
        let (head_seq, head_hash) = build_session(&s.session_dir(&format!("s{i}")), session);
        anchors.append(session, head_seq, head_hash).unwrap();
    }

    let mut lines = read_anchor_lines(s.root());
    // 줄 하나를 고치고 그 줄의 해시까지 다시 계산한다. 다음 줄의 prev 가 어긋난다
    lines[1] = AnchorEntry::seal(
        lines[1].seq,
        lines[1].ts,
        lines[1].session,
        lines[1].head_seq,
        Hash::from_bytes([0xEE; 32]),
        lines[1].prev,
    );
    assert!(lines[1].hash_is_valid());
    write_anchor_lines(s.root(), &lines);

    let err = verify_anchors(s.root()).unwrap_err();
    assert!(
        matches!(err, AnchorFailure::PrevMismatch { seq: 2, .. }),
        "{err}"
    );
}

#[test]
fn anchor_format_version_is_checked_before_the_hash() {
    let s = Scratch::new("version");
    let mut anchors = AnchorLog::open(s.root()).unwrap();
    let session = SessionId::from_bytes([1; 16]);
    let (head_seq, head_hash) = build_session(&s.session_dir("s0"), session);
    anchors.append(session, head_seq, head_hash).unwrap();

    let mut lines = read_anchor_lines(s.root());
    lines[0].v = 2;
    write_anchor_lines(s.root(), &lines);

    let err = verify_anchors(s.root()).unwrap_err();
    assert!(
        matches!(
            err,
            AnchorFailure::FormatVersionUnsupported { seq: 0, got: 2 }
        ),
        "{err}"
    );
}

#[test]
fn duplicated_session_anchor_is_detected() {
    let s = Scratch::new("duplicate");
    let mut anchors = AnchorLog::open(s.root()).unwrap();
    let session = SessionId::from_bytes([1; 16]);
    let (head_seq, head_hash) = build_session(&s.session_dir("s0"), session);
    anchors.append(session, head_seq, head_hash).unwrap();
    // 같은 세션을 같은 head 로 다시 앵커한다. 줄 복제다
    anchors.append(session, head_seq, head_hash).unwrap();

    let err = verify_anchors(s.root()).unwrap_err();
    assert!(
        matches!(
            err,
            AnchorFailure::SessionDuplicated {
                seq: 1,
                first_seq: 0,
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn regressed_head_seq_is_detected() {
    let s = Scratch::new("regress");
    let mut anchors = AnchorLog::open(s.root()).unwrap();
    let session = SessionId::from_bytes([1; 16]);
    let (head_seq, head_hash) = build_session(&s.session_dir("s0"), session);
    anchors.append(session, head_seq, head_hash).unwrap();
    // 더 짧은 상태로 다시 앵커하는 것은 되감기다
    anchors
        .append(session, head_seq - 1, Hash::from_bytes([0x11; 32]))
        .unwrap();

    let err = verify_anchors(s.root()).unwrap_err();
    assert!(
        matches!(err, AnchorFailure::HeadSeqRegressed { seq: 1, .. }),
        "{err}"
    );
}

#[test]
fn reanchoring_is_a_failure() {
    let s = Scratch::new("reanchor");
    let mut anchors = AnchorLog::open(s.root()).unwrap();
    let session = SessionId::from_bytes([1; 16]);
    anchors
        .append(session, 1, Hash::from_bytes([0x01; 32]))
        .unwrap();
    // 더 긴 head 로 다시 앵커한다. 브로커에는 체크포인트가 없으므로 이것은 종료 뒤
    // 덧붙이기의 흔적이지 정상 경로가 아니다
    anchors
        .append(session, 7, Hash::from_bytes([0x07; 32]))
        .unwrap();

    let err = verify_anchors(s.root()).unwrap_err();
    assert!(
        matches!(
            err,
            AnchorFailure::SessionReanchored {
                seq: 1,
                first_seq: 0,
                previous: 1,
                got: 7,
                ..
            }
        ),
        "같은 세션의 두 번째 앵커 줄이 경고로 통과하면 8.4 의 약속이 무효가 됨: {err}"
    );
    assert!(err.to_string().contains("덧붙이기 의심"), "{err}");

    // 조회도 "가장 나중 줄" 을 돌려주지 않고 실패해야 한다
    let err = airlock_audit::anchor::lookup(s.root(), &session).unwrap_err();
    assert!(
        matches!(err, AnchorFailure::SessionReanchored { .. }),
        "{err}"
    );

    // 깨진 체인 위에 이어 붙이기도 거부된다
    let err = AnchorLog::open(s.root()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Error::AnchorChainBroken { .. }),
        "{err}"
    );
}

// ---------- 앵커의 존재 이유: 세션 체인 재계산 탐지 ----------

#[test]
fn recomputed_session_chain_is_caught_by_the_anchor() {
    let s = Scratch::new("recompute");
    let session = SessionId::from_bytes([0xAB; 16]);
    let dir = s.session_dir("s0");
    let (head_seq, head_hash) = build_session(&dir, session);

    let mut anchors = AnchorLog::open(s.root()).unwrap();
    anchors.append(session, head_seq, head_hash).unwrap();

    // 공격자가 시크릿 접근 거부를 허용으로 바꾸고 체인 전체를 다시 봉인한다.
    // head.json 까지 맞춰 쓰므로 세션 디렉토리만으로는 아무 문제가 없어 보인다
    let entries: Vec<Entry> = fs::read_to_string(dir.join(CHAIN_FILE))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let mut prev = Hash::ZERO;
    let mut forged: Vec<Entry> = Vec::new();
    for e in &entries {
        let decision = if e.decision == Decision::Deny {
            Decision::Allow
        } else {
            e.decision
        };
        let sealed = Entry::seal(
            e.seq,
            e.ts,
            e.session,
            e.enforcement,
            prev,
            Record {
                actor: e.actor.clone(),
                event: e.event.clone(),
                decision,
                rule: e.rule.clone(),
            },
        );
        prev = sealed.hash;
        forged.push(sealed);
    }
    let mut body = String::new();
    for e in &forged {
        body.push_str(&serde_json::to_string(e).unwrap());
        body.push('\n');
    }
    fs::write(dir.join(CHAIN_FILE), body).unwrap();
    let last = forged.last().unwrap();
    fs::write(
        dir.join(HEAD_FILE),
        serde_json::to_string_pretty(&Head {
            version: 1,
            seq: last.seq,
            hash: last.hash,
            session: last.session,
        })
        .unwrap(),
    )
    .unwrap();

    // 세션 체인 자체는 깨끗하게 검증된다. 이것이 2.1 이 말하는 재계산 공격이다
    let report = verify_dir(&dir).unwrap();
    assert_eq!(report.head_seq, head_seq);
    assert_ne!(report.head_hash, head_hash);

    // 앵커와 대조해야 비로소 드러난다
    let err = airlock_audit::anchor::check_session(
        s.root(),
        &session,
        report.head_seq,
        &report.head_hash,
    )
    .unwrap_err();
    assert!(
        matches!(err, AnchorFailure::SessionHeadMismatch { .. }),
        "체인 재계산을 앵커가 못 잡으면 앵커의 존재 이유가 없음: {err}"
    );
    assert!(err.to_string().contains("재계산 의심"), "{err}");
}

#[test]
fn entries_appended_after_the_anchor_are_caught() {
    let s = Scratch::new("append-after");
    let session = SessionId::from_bytes([0xAB; 16]);
    let dir = s.session_dir("s0");

    let mut log = AuditLog::create(&dir, session, Enforcement::Landlock, true, genesis()).unwrap();
    log.append(Record::new(
        "pid:100 claude",
        file_read("/Users/me/work/src/main.rs"),
        Decision::Allow,
    ))
    .unwrap();

    let mut anchors = AnchorLog::open(s.root()).unwrap();
    anchors
        .append(session, log.head_seq().unwrap(), log.head_hash())
        .unwrap();

    // 세션 종료 뒤 엔트리를 하나 덧붙인다. 세션 체인만 보면 크래시 잔여로도 안 보인다
    log.append(Record::new(
        "pid:100 claude",
        file_read("/Users/me/.ssh/id_ed25519"),
        Decision::Allow,
    ))
    .unwrap();

    let report = verify_dir(&dir).unwrap();
    assert!(report.is_clean(), "{:?}", report.warnings);

    let err = airlock_audit::anchor::check_session(
        s.root(),
        &session,
        report.head_seq,
        &report.head_hash,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            AnchorFailure::EntriesAfterAnchor {
                anchor_head_seq: 1,
                chain_head_seq: 2,
                ..
            }
        ),
        "{err}"
    );
    assert!(err.to_string().contains("덧붙이기 의심"), "{err}");
}

// ---------- H2: append 권한만으로 종료된 세션을 늘리는 공격 ----------

#[test]
fn appending_after_close_and_reanchoring_is_caught() {
    // 공격자는 chain.jsonl 과 anchors.jsonl 에 append 만 할 수 있다. 종료된 세션에
    // 위조 엔트리를 잇고 새 head 를 가리키는 앵커 한 줄을 더한다. 세션 체인만 보면
    // 자체 정합적이고 head.json 도 맞다
    let s = Scratch::new("h2-reanchor");
    let session = SessionId::from_bytes([0xAB; 16]);
    let dir = s.session_dir("s0");
    let (head_seq, head_hash) = build_session(&dir, session);
    AnchorLog::open(s.root())
        .unwrap()
        .append(session, head_seq, head_hash)
        .unwrap();

    let (forged_seq, forged_hash) = forge_tail(&dir, 2, true);
    AnchorLog::open(s.root())
        .unwrap()
        .append(session, forged_seq, forged_hash)
        .unwrap();

    let report = verify_dir(&dir).unwrap();
    assert!(report.is_clean(), "{:?}", report.warnings);
    assert_eq!(report.head_seq, forged_seq);

    let err = verify_anchors(s.root()).unwrap_err();
    assert!(
        matches!(err, AnchorFailure::SessionReanchored { seq: 1, .. }),
        "두 번째 앵커 줄이 검증을 통과하면 종료 뒤 덧붙이기가 자유로움: {err}"
    );
    let err = check_session_report(s.root(), &report).unwrap_err();
    assert!(
        matches!(err, AnchorFailure::SessionReanchored { .. }),
        "{err}"
    );
}

#[test]
fn appending_after_session_end_is_caught_by_both_layers() {
    let s = Scratch::new("h2-session-end");
    let session = SessionId::from_bytes([0xAB; 16]);
    let dir = s.session_dir("s0");
    let (head_seq, head_hash) = build_closed_session(&dir, session, true);
    AnchorLog::open(s.root())
        .unwrap()
        .append(session, head_seq, head_hash)
        .unwrap();

    let (forged_seq, forged_hash) = forge_tail(&dir, 1, true);

    // 세션 체인 층. session_end 뒤의 엔트리는 앵커 유무와 무관하게 실패다
    let err = verify_dir(&dir).unwrap_err();
    assert!(
        matches!(
            err,
            airlock_audit::Failure::EntryAfterSessionEnd { end_seq: 2, seq: 3 }
        ),
        "{err}"
    );

    // 앵커 층. 새 앵커 없이도 체인이 앵커보다 길다
    let err = airlock_audit::anchor::check_session(s.root(), &session, forged_seq, &forged_hash)
        .unwrap_err();
    assert!(
        matches!(err, AnchorFailure::EntriesAfterAnchor { .. }),
        "{err}"
    );

    // 새 앵커를 더해도 그 줄 자체가 실패다
    AnchorLog::open(s.root())
        .unwrap()
        .append(session, forged_seq, forged_hash)
        .unwrap();
    let err = verify_anchors(s.root()).unwrap_err();
    assert!(
        matches!(err, AnchorFailure::SessionReanchored { .. }),
        "{err}"
    );
}

#[test]
fn an_anchored_session_with_a_lagging_head_is_a_failure() {
    // SIGKILL 로 죽어 앵커가 없는 세션. 공격자가 엔트리 하나를 잇고(head.json 은 건드리지
    // 못함) 첫 앵커를 대신 쓴다. 세션 체인만 보면 크래시 잔여 경고이고 앵커는 일치한다
    let s = Scratch::new("anchored-lag");
    let session = SessionId::from_bytes([0xAB; 16]);
    let dir = s.session_dir("s0");
    build_session(&dir, session);

    let (forged_seq, forged_hash) = forge_tail(&dir, 1, false);
    AnchorLog::open(s.root())
        .unwrap()
        .append(session, forged_seq, forged_hash)
        .unwrap();

    let report = verify_dir(&dir).unwrap();
    assert!(report.fsync_per_entry);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| matches!(w, Warning::HeadLagsByOne { .. })),
        "{:?}",
        report.warnings
    );
    // 원시 대조는 head 만 보므로 일치한다. 그래서 CLI 는 이것을 쓰면 안 된다
    let raw = airlock_audit::anchor::check_session(
        s.root(),
        &session,
        report.head_seq,
        &report.head_hash,
    )
    .unwrap();
    assert!(matches!(raw, AnchorCheck::Matches { .. }));

    let err = check_session_report(s.root(), &report).unwrap_err();
    assert!(
        matches!(
            err,
            AnchorFailure::AnchoredHeadLag {
                anchor_seq: 0,
                head_seq: 2,
                chain_seq: 3,
                ..
            }
        ),
        "앵커는 head.json 이 fsync 된 뒤에 쓰이므로 이 상태는 정상 경로로 생길 수 없음: {err}"
    );
    assert!(err.to_string().contains("크래시 잔여일 수 없음"), "{err}");
}

#[test]
fn a_no_fsync_session_keeps_the_head_lag_as_a_warning() {
    // fsync_per_entry: false 면 엔트리와 head.json 의 내구화 순서가 보장되지 않으므로
    // 앵커가 먼저 디스크에 닿은 뒤 크래시한 것과 구분할 수 없다
    let s = Scratch::new("nofsync-lag");
    let session = SessionId::from_bytes([0xAB; 16]);
    let dir = s.session_dir("s0");
    let mut log = AuditLog::create(&dir, session, Enforcement::Landlock, false, genesis()).unwrap();
    log.append(Record::new(
        "pid:100 claude",
        file_read("/Users/me/work/src/main.rs"),
        Decision::Allow,
    ))
    .unwrap();
    drop(log);

    let (forged_seq, forged_hash) = forge_tail(&dir, 1, false);
    AnchorLog::open(s.root())
        .unwrap()
        .append(session, forged_seq, forged_hash)
        .unwrap();

    let report = verify_dir(&dir).unwrap();
    assert!(!report.fsync_per_entry);
    assert!(report.head_lag().is_some(), "{:?}", report.warnings);
    let check = check_session_report(s.root(), &report).unwrap();
    assert!(matches!(check, AnchorCheck::Matches { .. }), "{check:?}");
}

#[test]
fn a_genuinely_closed_and_anchored_session_passes() {
    let s = Scratch::new("closed-ok");
    let session = SessionId::from_bytes([0xAB; 16]);
    let dir = s.session_dir("s0");
    let (head_seq, head_hash) = build_closed_session(&dir, session, true);
    AnchorLog::open(s.root())
        .unwrap()
        .append(session, head_seq, head_hash)
        .unwrap();

    let report = verify_dir(&dir).unwrap();
    assert!(report.is_clean(), "{:?}", report.warnings);
    assert!(report.session_ended);
    let check = check_session_report(s.root(), &report).unwrap();
    assert_eq!(check, AnchorCheck::Matches { anchor_seq: 0 });
}

#[test]
fn deleted_session_directory_leaves_a_trace() {
    let s = Scratch::new("session-deleted");
    let session = SessionId::from_bytes([0xAB; 16]);
    let dir = s.session_dir("s0");
    let (head_seq, head_hash) = build_session(&dir, session);

    let mut anchors = AnchorLog::open(s.root()).unwrap();
    anchors.append(session, head_seq, head_hash).unwrap();

    fs::remove_dir_all(&dir).unwrap();

    // 세션 디렉토리는 사라졌지만 앵커 줄이 남아 그 세션이 있었음을 증언한다
    let found = airlock_audit::anchor::lookup(s.root(), &session)
        .unwrap()
        .expect("앵커 줄이 있어야 함");
    assert_eq!(found.head_seq, head_seq);
    assert_eq!(found.head_hash, head_hash);
    assert!(!dir.exists());
}

// ---------- 앵커가 없을 때 ----------

#[test]
fn missing_anchor_file_is_reported_as_undetectable() {
    let s = Scratch::new("no-file");
    let session = SessionId::from_bytes([0xAB; 16]);
    build_session(&s.session_dir("s0"), session);

    let err = verify_anchors(s.root()).unwrap_err();
    assert!(matches!(err, AnchorFailure::FileAbsent), "{err}");
    assert!(
        err.to_string().contains("탐지할 수 없음"),
        "앵커 없음이 통과처럼 보이면 앵커 삭제가 가장 값싼 공격이 됨: {err}"
    );

    let err = airlock_audit::anchor::check_session(s.root(), &session, 2, &Hash::ZERO).unwrap_err();
    assert!(matches!(err, AnchorFailure::FileAbsent), "{err}");
}

#[test]
fn unanchored_session_is_reported_as_missing_not_ok() {
    let s = Scratch::new("unanchored");
    let anchored = SessionId::from_bytes([1; 16]);
    let orphan = SessionId::from_bytes([2; 16]);

    let (head_seq, head_hash) = build_session(&s.session_dir("s0"), anchored);
    let mut anchors = AnchorLog::open(s.root()).unwrap();
    anchors.append(anchored, head_seq, head_hash).unwrap();

    // SIGKILL 로 죽어 앵커되지 못한 세션
    let (orphan_seq, orphan_hash) = build_session(&s.session_dir("s1"), orphan);
    let check =
        airlock_audit::anchor::check_session(s.root(), &orphan, orphan_seq, &orphan_hash).unwrap();
    assert_eq!(check, AnchorCheck::Missing);
}

#[test]
fn appending_onto_a_broken_anchor_chain_is_refused() {
    let s = Scratch::new("broken");
    {
        let mut anchors = AnchorLog::open(s.root()).unwrap();
        anchors
            .append(SessionId::from_bytes([1; 16]), 2, Hash::from_bytes([2; 32]))
            .unwrap();
        anchors
            .append(SessionId::from_bytes([2; 16]), 3, Hash::from_bytes([3; 32]))
            .unwrap();
    }

    let mut lines = read_anchor_lines(s.root());
    lines[0].head_seq = 99;
    write_anchor_lines(s.root(), &lines);

    let err = AnchorLog::open(s.root()).unwrap_err();
    assert!(
        matches!(err, airlock_audit::Error::AnchorChainBroken { .. }),
        "깨진 체인 위에 이어 붙이면 그 뒤쪽이 정당해 보임: {err}"
    );
}

#[test]
fn truncated_final_anchor_line_is_detected() {
    let s = Scratch::new("partial");
    {
        let mut anchors = AnchorLog::open(s.root()).unwrap();
        anchors
            .append(SessionId::from_bytes([1; 16]), 2, Hash::from_bytes([2; 32]))
            .unwrap();
        anchors
            .append(SessionId::from_bytes([2; 16]), 3, Hash::from_bytes([3; 32]))
            .unwrap();
    }

    let path = s.root().join(ANCHOR_FILE);
    let raw = fs::read_to_string(&path).unwrap();
    fs::write(&path, &raw[..raw.len() - 30]).unwrap();

    let err = verify_anchors(s.root()).unwrap_err();
    assert!(
        matches!(err, AnchorFailure::TruncatedFinalLine { line: 2 }),
        "{err}"
    );
}

#[test]
fn blank_line_inside_the_anchor_chain_is_fatal() {
    let s = Scratch::new("blank");
    {
        let mut anchors = AnchorLog::open(s.root()).unwrap();
        anchors
            .append(SessionId::from_bytes([1; 16]), 2, Hash::from_bytes([2; 32]))
            .unwrap();
    }

    let path = s.root().join(ANCHOR_FILE);
    let raw = fs::read_to_string(&path).unwrap();
    fs::write(&path, format!("\n{raw}")).unwrap();

    let err = verify_anchors(s.root()).unwrap_err();
    assert!(matches!(err, AnchorFailure::BlankLine { line: 1 }), "{err}");
}
