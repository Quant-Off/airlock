//! 이 파일은 책임자 확인 체인을 실제 파일 위에서 두들깁니다.
//!
//! # Features
//! 확인 기록은 "사람이 매일 점검했다" 는 주장을 담습니다. 그 주장이 조용히 고쳐지거나
//! 지워지거나 다른 범위로 옮겨 찍힐 수 있으면 기록이 책임 근거가 아니라 알리바이가 됩니다.
//! 여기서는 줄 삭제·수정·재배치·복제와 범위 바꿔치기를 실제로 시도해 검증자가 잡는지 봅니다.

use std::fs;
use std::path::{Path, PathBuf};

use airlock_audit::{
    Error, Hash, REVIEW_FILE, ReviewEntry, ReviewFailure, ReviewLog, ReviewScope, ReviewSubject,
    ReviewWarning, SessionId, Verdict, check_review, latest_review, now_unix_nanos, verify_reviews,
};

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "airlock-review-{name}-{}-{}",
            std::process::id(),
            now_unix_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn root(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scope(day: &str, sessions: u8) -> ReviewScope {
    ReviewScope::new(
        Some(day.to_string()),
        Some(day.to_string()),
        (0..sessions).map(|i| SessionId::from_bytes([i; 16])),
    )
}

fn subject(day: &str, sessions: u8, body: u8) -> ReviewSubject {
    ReviewSubject::seal(scope(day, sessions), Hash::from_bytes([body; 32]))
}

fn stamp(root: &Path, day: &str, sessions: u8, body: u8) -> ReviewEntry {
    let mut log = ReviewLog::open(root).unwrap();
    log.append(&subject(day, sessions, body), Verdict::Clean, None)
        .unwrap()
}

fn lines(root: &Path) -> Vec<ReviewEntry> {
    fs::read_to_string(root.join(REVIEW_FILE))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn write_lines(root: &Path, entries: &[ReviewEntry]) {
    let mut body = String::new();
    for e in entries {
        body.push_str(&serde_json::to_string(e).unwrap());
        body.push('\n');
    }
    fs::write(root.join(REVIEW_FILE), body).unwrap();
}

// ---------- 정상 경로 ----------

#[test]
fn a_chain_of_stamps_verifies() {
    let s = Scratch::new("clean");
    for (i, day) in ["2026-08-24", "2026-08-25", "2026-08-26"]
        .iter()
        .enumerate()
    {
        stamp(s.root(), day, 1, i as u8);
    }
    let report = verify_reviews(s.root()).unwrap();
    assert_eq!(report.entries, 3);
    assert_eq!(report.head_seq, 2);
    assert_eq!(
        report.last.map(|e| e.since),
        Some(Some("2026-08-26".to_string()))
    );
}

#[test]
fn no_file_means_no_review_not_a_pass() {
    let s = Scratch::new("none");
    let err = verify_reviews(s.root()).unwrap_err();
    assert!(matches!(err, ReviewFailure::FileAbsent), "{err}");
    assert!(
        err.to_string().contains("확인 기록이 없음"),
        "확인 기록 없음이 사람이 읽는 말로 나와야 함: {err}"
    );
    assert!(matches!(
        latest_review(s.root()),
        Err(ReviewFailure::FileAbsent)
    ));
}

// ---------- 줄 수정 ----------

#[test]
fn editing_a_verdict_is_detected() {
    let s = Scratch::new("verdict");
    stamp(s.root(), "2026-08-26", 1, 1);
    let mut es = lines(s.root());
    es[0].verdict = Verdict::Anomalous;
    write_lines(s.root(), &es);

    let err = verify_reviews(s.root()).unwrap_err();
    assert!(
        matches!(err, ReviewFailure::HashMismatch { seq: 0, .. }),
        "{err}"
    );
}

#[test]
fn editing_the_reviewer_is_detected() {
    // 남의 계정으로 확인한 것처럼 고치는 것이 이 체인이 막아야 할 첫 번째 공격입니다
    let s = Scratch::new("reviewer");
    stamp(s.root(), "2026-08-26", 1, 1);
    let mut es = lines(s.root());
    es[0].reviewer_uid = 0;
    write_lines(s.root(), &es);
    assert!(matches!(
        verify_reviews(s.root()).unwrap_err(),
        ReviewFailure::HashMismatch { .. }
    ));

    let mut es = lines(s.root());
    es[0].reviewer_tty = Some("/dev/ttys999".into());
    write_lines(s.root(), &es);
    assert!(matches!(
        verify_reviews(s.root()).unwrap_err(),
        ReviewFailure::HashMismatch { .. }
    ));
}

#[test]
fn editing_the_scope_is_detected() {
    let s = Scratch::new("scope-edit");
    stamp(s.root(), "2026-08-26", 2, 1);
    let mut es = lines(s.root());
    es[0].since = Some("2026-01-01".into());
    write_lines(s.root(), &es);
    assert!(matches!(
        verify_reviews(s.root()).unwrap_err(),
        ReviewFailure::HashMismatch { .. }
    ));

    let mut es = lines(s.root());
    es[0].sessions.push(SessionId::from_bytes([9; 16]));
    write_lines(s.root(), &es);
    assert!(matches!(
        verify_reviews(s.root()).unwrap_err(),
        ReviewFailure::HashMismatch { .. }
    ));
}

#[test]
fn a_human_readable_timestamp_is_not_evidence() {
    // ts_rfc3339 은 해시 대상이 아닙니다. 그 사실이 문서와 어긋나면 도구가 위조된 문자열을
    // 사실로 읽습니다
    let s = Scratch::new("rfc");
    stamp(s.root(), "2026-08-26", 1, 1);
    let mut es = lines(s.root());
    es[0].ts_rfc3339 = "1999-01-01T00:00:00.000000000Z".into();
    write_lines(s.root(), &es);
    assert!(verify_reviews(s.root()).is_ok());
}

// ---------- 줄 삭제와 재배치 ----------

#[test]
fn deleting_a_middle_stamp_is_detected() {
    let s = Scratch::new("delete-mid");
    for (i, day) in ["2026-08-24", "2026-08-25", "2026-08-26"]
        .iter()
        .enumerate()
    {
        stamp(s.root(), day, 1, i as u8);
    }
    let mut es = lines(s.root());
    es.remove(1);
    write_lines(s.root(), &es);

    let err = verify_reviews(s.root()).unwrap_err();
    assert!(
        matches!(
            err,
            ReviewFailure::SeqGap {
                expected: 1,
                got: 2
            }
        ),
        "{err}"
    );
}

#[test]
fn deleting_the_last_stamp_is_detected_as_a_shorter_chain() {
    // 마지막 줄 삭제는 체인 안에서는 정합적입니다. 하루치 점검을 지운 사실은
    // 리포트가 세션과 대조해야 드러나며 이 층은 그것을 주장하지 않습니다
    let s = Scratch::new("delete-last");
    stamp(s.root(), "2026-08-25", 1, 1);
    stamp(s.root(), "2026-08-26", 1, 2);
    let mut es = lines(s.root());
    es.pop();
    write_lines(s.root(), &es);

    let report = verify_reviews(s.root()).unwrap();
    assert_eq!(report.head_seq, 0);
    assert_eq!(
        report.last.map(|e| e.since),
        Some(Some("2026-08-25".to_string())),
        "마지막 확인이 하루 뒤로 물러난 것으로 보여야 함"
    );
}

#[test]
fn reordering_stamps_is_detected() {
    let s = Scratch::new("reorder");
    stamp(s.root(), "2026-08-25", 1, 1);
    stamp(s.root(), "2026-08-26", 1, 2);
    let mut es = lines(s.root());
    es.swap(0, 1);
    write_lines(s.root(), &es);

    let err = verify_reviews(s.root()).unwrap_err();
    assert!(matches!(err, ReviewFailure::SeqGap { .. }), "{err}");
}

#[test]
fn duplicating_a_stamp_is_detected() {
    let s = Scratch::new("dup");
    let e = stamp(s.root(), "2026-08-26", 1, 1);
    let mut es = lines(s.root());
    es.push(e);
    write_lines(s.root(), &es);

    let err = verify_reviews(s.root()).unwrap_err();
    assert!(matches!(err, ReviewFailure::SeqGap { .. }), "{err}");
}

#[test]
fn a_resealed_forged_stamp_still_breaks_the_link() {
    // 해시를 다시 계산해 붙여도 prev 연결이 어긋납니다. 체인 전체를 다시 계산할 수 있는
    // 주체를 막지는 못하며 그것은 문서에 밝혀 둔 한계입니다
    let s = Scratch::new("reseal");
    stamp(s.root(), "2026-08-25", 1, 1);
    stamp(s.root(), "2026-08-26", 1, 2);
    let mut es = lines(s.root());
    es[0].verdict = Verdict::Anomalous;
    es[0].hash = es[0].recompute_hash();
    write_lines(s.root(), &es);

    let err = verify_reviews(s.root()).unwrap_err();
    assert!(
        matches!(err, ReviewFailure::PrevMismatch { seq: 1, .. }),
        "{err}"
    );
}

// ---------- 부분 쓰기 ----------

#[test]
fn a_truncated_final_line_is_detected() {
    let s = Scratch::new("truncated");
    stamp(s.root(), "2026-08-26", 1, 1);
    let path = s.root().join(REVIEW_FILE);
    let mut body = fs::read_to_string(&path).unwrap();
    body.truncate(body.len() - 20);
    fs::write(&path, body).unwrap();

    let err = verify_reviews(s.root()).unwrap_err();
    assert!(
        matches!(err, ReviewFailure::TruncatedFinalLine { .. }),
        "{err}"
    );
}

#[test]
fn a_blank_line_is_not_skipped() {
    let s = Scratch::new("blank");
    stamp(s.root(), "2026-08-26", 1, 1);
    let path = s.root().join(REVIEW_FILE);
    let body = fs::read_to_string(&path).unwrap();
    fs::write(&path, format!("\n{body}")).unwrap();

    let err = verify_reviews(s.root()).unwrap_err();
    assert!(matches!(err, ReviewFailure::BlankLine { line: 1 }), "{err}");
}

#[test]
fn an_unsupported_version_is_reported_as_a_format_mismatch() {
    let s = Scratch::new("version");
    stamp(s.root(), "2026-08-26", 1, 1);
    let mut es = lines(s.root());
    es[0].v = 2;
    write_lines(s.root(), &es);

    let err = verify_reviews(s.root()).unwrap_err();
    assert!(
        matches!(err, ReviewFailure::FormatVersionUnsupported { got: 2, .. }),
        "포맷 불일치가 내용 변조와 구분되어야 함: {err}"
    );
}

#[test]
fn a_broken_chain_cannot_be_extended() {
    let s = Scratch::new("extend-broken");
    stamp(s.root(), "2026-08-26", 1, 1);
    let mut es = lines(s.root());
    es[0].note = Some("나중에 끼워 넣음".into());
    write_lines(s.root(), &es);

    let err = ReviewLog::open(s.root()).unwrap_err();
    assert!(matches!(err, Error::ReviewChainBroken { .. }), "{err}");
}

// ---------- 범위와 다이제스트의 결합 ----------

#[test]
fn a_stamp_from_another_range_is_refused() {
    // 사람이 보지 않은 범위에 확인 도장을 옮겨 찍을 수 없어야 합니다
    let s = Scratch::new("wrong-range");
    let e = stamp(s.root(), "2026-08-26", 1, 1);

    check_review(&e, &subject("2026-08-26", 1, 1)).expect("같은 범위와 본문은 통과해야 함");

    let other_day = check_review(&e, &subject("2026-08-25", 1, 1)).unwrap_err();
    assert!(
        matches!(other_day, ReviewFailure::ScopeMismatch { seq: 0 }),
        "{other_day}"
    );

    let other_sessions = check_review(&e, &subject("2026-08-26", 2, 1)).unwrap_err();
    assert!(
        matches!(other_sessions, ReviewFailure::ScopeMismatch { seq: 0 }),
        "같은 날짜라도 본 세션이 다르면 같은 확인이 아님: {other_sessions}"
    );

    let other_body = check_review(&e, &subject("2026-08-26", 1, 9)).unwrap_err();
    assert!(
        matches!(other_body, ReviewFailure::DigestMismatch { seq: 0, .. }),
        "{other_body}"
    );
}

#[test]
fn a_forged_digest_from_another_scope_is_caught() {
    // 범위는 A 로 적고 다이제스트는 B 의 것을 넣은 줄을 직접 만들어 봅니다.
    // 체인 자체는 다시 계산해 정합적으로 만들 수 있으므로, 잡는 것은 대조 단계입니다
    let s = Scratch::new("forged-digest");
    stamp(s.root(), "2026-08-26", 1, 1);
    let mut es = lines(s.root());
    es[0].report_digest = subject("2026-08-25", 1, 1).digest();
    es[0].hash = es[0].recompute_hash();
    write_lines(s.root(), &es);

    // 체인은 통과합니다. 서명이 없으므로 다시 계산할 수 있는 주체를 막지 못합니다
    let last = latest_review(s.root()).unwrap().expect("확인 줄");
    let err = check_review(&last, &subject("2026-08-26", 1, 1)).unwrap_err();
    assert!(
        matches!(err, ReviewFailure::DigestMismatch { .. }),
        "그 범위의 리포트를 다시 계산하면 어긋남이 드러나야 함: {err}"
    );
}

#[test]
fn the_digest_cannot_be_supplied_by_the_caller() {
    // ReviewSubject 는 범위와 본문에서만 만들어집니다. 다이제스트를 밖에서 넣을 수 있으면
    // 범위와 어긋난 값을 기록할 수 있고 그것이 정확히 이 체인이 막으려는 것입니다
    let a = subject("2026-08-26", 1, 1);
    let b = ReviewSubject::seal(a.scope().clone(), a.body());
    assert_eq!(a.digest(), b.digest());
    assert_eq!(
        a.digest(),
        airlock_audit::report_digest(a.scope(), &a.body())
    );
}

// ---------- 확인자 신원 ----------

#[test]
fn a_stamp_without_an_observed_terminal_says_so() {
    // 터미널이 없는 자리에서 찍힌 도장을 사람이 앉아 있던 확인처럼 보이게 하면 안 됩니다
    let s = Scratch::new("tty");
    let e = stamp(s.root(), "2026-08-26", 1, 1);
    if !e.has_observed_terminal() {
        let report = verify_reviews(s.root()).unwrap();
        assert!(
            report
                .warnings
                .iter()
                .any(|w| matches!(w, ReviewWarning::TerminalNotObserved { seq: 0 })),
            "터미널 미관측이 경고로 나와야 함: {:?}",
            report.warnings
        );
    }
}

#[test]
fn permissions_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let s = Scratch::new("perms");
    stamp(s.root(), "2026-08-26", 1, 1);
    let mode = fs::metadata(s.root().join(REVIEW_FILE))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn the_review_file_is_not_the_anchor_file() {
    // 도메인과 파일 이름을 모두 분리해야 한쪽 줄을 다른 쪽 검증자에게 먹일 수 없습니다
    assert_ne!(REVIEW_FILE, airlock_audit::ANCHOR_FILE);
    assert_ne!(airlock_audit::REVIEW_DOMAIN, airlock_audit::ANCHOR_DOMAIN);
    assert_ne!(airlock_audit::REVIEW_DOMAIN, airlock_audit::DOMAIN);
    assert_ne!(airlock_audit::REPORT_DOMAIN, airlock_audit::REVIEW_DOMAIN);
}
