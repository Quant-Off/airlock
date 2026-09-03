//! 이 모듈은 점검 보고를 사람용과 JSON 두 갈래로 그립니다.
//!
//! # Features
//! 두 출력은 **같은 사실**을 담습니다. 사람용은 색과 상한이 있고 JSON 은 색도 상한도
//! 없습니다. SIEM 이 절단된 목록을 받으면 그 절단이 로그에 남지 않아 "전부 봤다" 로
//! 읽히기 때문입니다.
//!
//! 사람용 출력에 상한을 걸 때는 상한이 걸렸다는 사실 자체를 반드시 함께 찍습니다.
//! 조용한 절단은 점검이 거짓 보증을 하는 가장 흔한 경로입니다.

use airlock_audit::Verdict;
use airlock_canonical::display::sanitize;
use airlock_i18n::tr;
use serde_json::{Value, json};

use crate::report::{
    AnchorState, Anomaly, ChainState, Destination, Integrity, MAX_LISTED, Report, ReviewState,
    SCHEMA, SessionReport, TOP_DESTINATIONS,
};

/// 바이트 수를 사람이 읽는 크기로 바꿉니다.
///
/// # Arguments
/// `bytes` - 원본 바이트 수
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let name = UNITS.get(unit).copied().unwrap_or("B");
    if unit == 0 {
        format!("{bytes}{name}")
    } else {
        format!("{value:.1}{name}")
    }
}

/// 밀리초를 사람이 읽는 지속 시간으로 바꿉니다.
///
/// # Arguments
/// `ms` - 원본 밀리초
pub fn human_millis(ms: u64) -> String {
    if ms < 1_000 {
        return format!("{ms}ms");
    }
    let secs = ms / 1_000;
    let rest = ms % 1_000;
    if secs < 60 {
        return format!("{secs}.{rest:03}s");
    }
    format!("{}m{}s", secs / 60, secs % 60)
}

/// 해시가 보증하는 `ts` 에서 초 단위 표기를 다시 만듭니다.
///
/// 저장된 `ts_rfc3339` 은 해시 대상이 아니므로 위조할 수 있습니다. 화면에 닿는 값은 언제나
/// `ts` 에서 유도합니다.
///
/// # Arguments
/// `ts` - 유닉스 나노초
pub fn short_time(ts: u64) -> String {
    let full = airlock_audit::format_rfc3339_nanos(ts);
    let head = full.get(0..19).unwrap_or(&full).to_string();
    format!("{head}Z")
}

fn range_label(report: &Report) -> String {
    match (&report.since, &report.until) {
        (None, None) => tr!("전체", "all").to_string(),
        (Some(a), None) => tr!(
            format!("{} 이후", sanitize(a)),
            format!("since {}", sanitize(a))
        ),
        (None, Some(b)) => tr!(
            format!("{} 까지", sanitize(b)),
            format!("until {}", sanitize(b))
        ),
        (Some(a), Some(b)) => format!("{} .. {}", sanitize(a), sanitize(b)),
    }
}

/// 사람이 읽는 보고를 표준 출력으로 찍습니다.
///
/// # Arguments
/// `report` - 그릴 보고
pub fn human(report: &Report) {
    let digest: String = report
        .subject()
        .digest()
        .to_hex()
        .chars()
        .take(16)
        .collect();
    println!(
        "{}",
        tr!(
            "\x1b[1;36mairlock\x1b[0m 감사 점검 보고",
            "\x1b[1;36mairlock\x1b[0m audit check report"
        )
    );
    println!(
        "{}",
        tr!(
            format!("  감사루트 {}", report.root.display()),
            format!("  audit root  {}", report.root.display())
        )
    );
    println!(
        "{}",
        tr!(
            format!("  앵커루트 {}", report.anchor_dir.display()),
            format!("  anchor root {}", report.anchor_dir.display())
        )
    );
    println!(
        "{}",
        tr!(
            format!("  범위     {}", range_label(report)),
            format!("  range       {}", range_label(report))
        )
    );
    println!(
        "{}",
        tr!(
            format!("  생성     {}", short_time(report.generated_ts)),
            format!("  generated   {}", short_time(report.generated_ts))
        )
    );
    println!(
        "{}",
        tr!(
            format!("  다이제스트 {digest}"),
            format!("  digest      {digest}")
        )
    );
    if report.strict_approval {
        println!(
            "{}",
            tr!(
                "  승인정책 --strict-approval (자동 승인을 이상으로 셈)",
                "  approval    --strict-approval (counts automatic approvals as anomalies)"
            )
        );
    }
    println!();

    print_chain(report);
    print_review(report);
    println!();

    if report.sessions.is_empty() {
        println!("{}", tr!("범위 안에 세션이 없음", "no sessions in range"));
    } else {
        println!(
            "{}",
            tr!(
                format!("세션 {}개", report.sessions.len()),
                format!("{} sessions", report.sessions.len())
            )
        );
        for s in &report.sessions {
            print_session(s);
        }
    }
    println!();

    print_totals(report);
    println!();
    print_anomalies(report);
}

fn print_chain(report: &Report) {
    match &report.chain {
        ChainState::Ok {
            entries,
            sessions,
            head_seq,
            warnings,
        } => {
            println!(
                "{}",
                tr!(
                    format!(
                        "\x1b[32m앵커 확인\x1b[0m {} 줄, 세션 {sessions}개, head seq {head_seq}",
                        entries
                    ),
                    format!(
                        "\x1b[32manchors ok\x1b[0m {} lines, {sessions} sessions, head seq {head_seq}",
                        entries
                    )
                )
            );
            for w in warnings {
                println!(
                    "{}",
                    tr!(
                        format!("  \x1b[33m경고\x1b[0m {}", sanitize(w)),
                        format!("  \x1b[33mwarning\x1b[0m {}", sanitize(w))
                    )
                );
            }
        }
        ChainState::Absent => {
            println!(
                "{}",
                tr!(
                    "\x1b[1;31m앵커 없음\x1b[0m 탐지 불가이며 통과가 아님",
                    "\x1b[1;31manchors absent\x1b[0m undetectable, which is not a pass"
                )
            );
        }
        ChainState::Broken { detail } => {
            println!(
                "{}",
                tr!(
                    format!("\x1b[1;31m앵커 실패\x1b[0m {}", sanitize(detail)),
                    format!("\x1b[1;31manchor failure\x1b[0m {}", sanitize(detail))
                )
            );
        }
    }
}

fn print_review(report: &Report) {
    match &report.review {
        ReviewState::None => {
            println!(
                "{}",
                tr!(
                    format!(
                        "\x1b[33m확인 기록 없음\x1b[0m {} 에 아직 아무도 도장을 찍지 않았음. \
                 airlock audit ack 로 남길 것",
                        report.anchor_dir.join(airlock_audit::REVIEW_FILE).display()
                    ),
                    format!(
                        "\x1b[33mno review record\x1b[0m no one has stamped {} yet; \
                 leave one with airlock audit ack",
                        report.anchor_dir.join(airlock_audit::REVIEW_FILE).display()
                    )
                )
            );
        }
        ReviewState::Broken { detail } => {
            println!(
                "{}",
                tr!(
                    format!("\x1b[1;31m확인 체인 실패\x1b[0m {}", sanitize(detail)),
                    format!("\x1b[1;31mreview chain failure\x1b[0m {}", sanitize(detail))
                )
            );
        }
        ReviewState::Ok { last, warnings } => {
            let color = match last.verdict {
                Verdict::Clean => "\x1b[32m",
                Verdict::Anomalous => "\x1b[31m",
            };
            let tty = match &last.reviewer_tty {
                Some(t) => sanitize(t),
                None => tr!("\x1b[33m미관측\x1b[0m", "\x1b[33munobserved\x1b[0m").to_string(),
            };
            println!(
                "{}",
                tr!(
                    format!(
                        "마지막 확인 {} {color}{}\x1b[0m uid={} euid={} tty={tty}",
                        short_time(last.ts),
                        last.verdict.label(),
                        last.reviewer_uid,
                        last.reviewer_euid,
                    ),
                    format!(
                        "last review {} {color}{}\x1b[0m uid={} euid={} tty={tty}",
                        short_time(last.ts),
                        last.verdict.label(),
                        last.reviewer_uid,
                        last.reviewer_euid,
                    )
                )
            );
            let range_text = match (&last.since, &last.until) {
                (None, None) => tr!("전체", "all").to_string(),
                (Some(a), None) => tr!(
                    format!("{} 이후", sanitize(a)),
                    format!("since {}", sanitize(a))
                ),
                (None, Some(b)) => tr!(
                    format!("{} 까지", sanitize(b)),
                    format!("until {}", sanitize(b))
                ),
                (Some(a), Some(b)) => format!("{} .. {}", sanitize(a), sanitize(b)),
            };
            println!(
                "{}",
                tr!(
                    format!("  확인 범위 {} 세션 {}개", range_text, last.sessions.len()),
                    format!(
                        "  review range {} ({} sessions)",
                        range_text,
                        last.sessions.len()
                    )
                )
            );
            if let Some(n) = &last.note {
                println!(
                    "{}",
                    tr!(
                        format!("  메모     {}", sanitize(n)),
                        format!("  note     {}", sanitize(n))
                    )
                );
            }
            for w in warnings {
                println!(
                    "{}",
                    tr!(
                        format!("  \x1b[33m경고\x1b[0m {}", sanitize(w)),
                        format!("  \x1b[33mwarning\x1b[0m {}", sanitize(w))
                    )
                );
            }
        }
    }
    if report.sessions_after_review > 0 && !matches!(report.review, ReviewState::None) {
        println!(
            "{}",
            tr!(
                format!(
                    "  \x1b[33m미확인\x1b[0m 마지막 확인 이후 시작된 세션 {}개. 매일 점검이 밀려 있음",
                    report.sessions_after_review
                ),
                format!(
                    "  \x1b[33munreviewed\x1b[0m {} sessions started after the last review; the daily check is behind",
                    report.sessions_after_review
                )
            )
        );
    }
}

fn print_session(s: &SessionReport) {
    let (mark, detail) = match &s.integrity {
        Integrity::Ok { entries, .. } => (
            tr!("\x1b[32m무결성 확인\x1b[0m", "\x1b[32mintegrity ok\x1b[0m").to_string(),
            tr!(format!("{entries} 엔트리"), format!("{entries} entries")),
        ),
        Integrity::Failed { detail } => (
            tr!(
                "\x1b[1;31m무결성 실패\x1b[0m",
                "\x1b[1;31mintegrity failure\x1b[0m"
            )
            .to_string(),
            sanitize(detail),
        ),
    };
    let anchor = match &s.anchor {
        AnchorState::Matches { anchor_seq } => tr!(
            format!("앵커 seq {anchor_seq} 일치"),
            format!("anchor seq {anchor_seq} matches")
        ),
        AnchorState::Missing => tr!(
            "\x1b[33m앵커 줄 없음\x1b[0m",
            "\x1b[33mno anchor line\x1b[0m"
        )
        .to_string(),
        AnchorState::Mismatch { .. } => tr!(
            "\x1b[1;31m앵커 불일치\x1b[0m",
            "\x1b[1;31manchor mismatch\x1b[0m"
        )
        .to_string(),
        AnchorState::ChainAbsent => tr!(
            "\x1b[33m앵커 파일 없음\x1b[0m",
            "\x1b[33manchor file absent\x1b[0m"
        )
        .to_string(),
        AnchorState::ChainBroken => tr!(
            "\x1b[1;31m앵커 체인 손상\x1b[0m",
            "\x1b[1;31manchor chain damaged\x1b[0m"
        )
        .to_string(),
    };
    println!(
        "  {} {mark} {detail}  {anchor}  {}",
        s.name,
        short_time(s.started_ts)
    );
    if let Some(p) = &s.read_problem {
        println!(
            "{}",
            tr!(
                format!("    \x1b[1;31m읽기 문제\x1b[0m {p}"),
                format!("    \x1b[1;31mread problem\x1b[0m {p}")
            )
        );
    }
    println!(
        "{}",
        tr!(
            format!(
                "    결정   allow {} deny {} ask {} forbid {}",
                s.decisions.allow, s.decisions.deny, s.decisions.ask, s.decisions.forbid
            ),
            format!(
                "    decisions  allow {} deny {} ask {} forbid {}",
                s.decisions.allow, s.decisions.deny, s.decisions.ask, s.decisions.forbid
            )
        )
    );
    // 신원 없는 응답을 사람 승인과 같은 칸에 넣으면 --yes 자동 승인이 사람 확인처럼 읽힙니다
    let unidentified = if s.approvals.auto_granted > 0 {
        tr!(
            format!(
                "\x1b[33m신원없음 {} (허용 {})\x1b[0m",
                s.approvals.unidentified, s.approvals.auto_granted
            ),
            format!(
                "\x1b[33munidentified {} (granted {})\x1b[0m",
                s.approvals.unidentified, s.approvals.auto_granted
            )
        )
    } else {
        tr!(
            format!("신원없음 {}", s.approvals.unidentified),
            format!("unidentified {}", s.approvals.unidentified)
        )
    };
    println!(
        "{}",
        tr!(
            format!(
                "    승인   사람 {} {unidentified} (승인 {} 거부 {} 시간초과 {}) 미응답 ask {}",
                s.approvals.identified,
                s.approvals.approved,
                s.approvals.refused,
                s.approvals.timed_out,
                s.approvals.unanswered
            ),
            format!(
                "    approvals  human {} {unidentified} (approved {} refused {} timed out {}) unanswered ask {}",
                s.approvals.identified,
                s.approvals.approved,
                s.approvals.refused,
                s.approvals.timed_out,
                s.approvals.unanswered
            )
        )
    );
    for w in &s.warnings {
        println!(
            "{}",
            tr!(
                format!("    \x1b[33m경고\x1b[0m {}", sanitize(w)),
                format!("    \x1b[33mwarning\x1b[0m {}", sanitize(w))
            )
        );
    }

    if !s.denied_exec.is_empty() {
        println!(
            "{}",
            tr!(
                format!("    거부된 exec {}종", s.denied_exec.len()),
                format!("    denied exec {} kinds", s.denied_exec.len())
            )
        );
        for e in s.denied_exec.iter().take(MAX_LISTED) {
            let rule = e.rule.as_deref().unwrap_or(tr!("기본값", "default"));
            println!("      {} {:?} x{} [{rule}]", e.program, e.argv, e.count);
        }
        print_cap(
            s.denied_exec.len(),
            MAX_LISTED,
            tr!("거부된 exec", "denied exec"),
        );
    }

    if !s.destinations.is_empty() {
        println!(
            "{}",
            tr!(
                format!("    아웃바운드 {}개 목적지", s.destinations.len()),
                format!("    egress {} destinations", s.destinations.len())
            )
        );
        for d in s.destinations.iter().take(MAX_LISTED) {
            println!("      {}", destination_line(d));
        }
        print_cap(
            s.destinations.len(),
            MAX_LISTED,
            tr!("목적지", "destinations"),
        );
    }
}

fn destination_line(d: &Destination) -> String {
    // 거부된 시도는 애초에 중계되지 않으므로 결과가 없는 것이 정상입니다. 허용된 연결
    // 가운데 결과가 남지 않은 것만 "모름" 입니다
    let unknown = d.allowed.saturating_sub(d.completed);
    let tail = if d.completed > 0 {
        tr!(
            format!(
                " 반출 {} 수신 {} {} (연결 {})",
                human_bytes(d.bytes_out),
                human_bytes(d.bytes_in),
                human_millis(d.duration_ms),
                d.completed
            ),
            format!(
                " sent {} received {} {} (connections {})",
                human_bytes(d.bytes_out),
                human_bytes(d.bytes_in),
                human_millis(d.duration_ms),
                d.completed
            )
        )
    } else {
        String::new()
    };
    // 결과가 남지 않은 연결을 0 바이트로 보이게 하면 안 됩니다. 반출량을 모른다는 사실이
    // 화면에 그대로 나와야 합니다
    let gap = if unknown > 0 {
        tr!(
            format!(" \x1b[33m반출량 모름 {unknown}\x1b[0m"),
            format!(" \x1b[33munknown outcome {unknown}\x1b[0m")
        )
    } else {
        String::new()
    };
    tr!(
        format!(
            "{}:{} [{}] 시도 {} (허용 {} 거부 {} ask {}){tail}{gap}",
            d.host, d.port, d.protocol, d.attempts, d.allowed, d.blocked, d.asked
        ),
        format!(
            "{}:{} [{}] attempts {} (allowed {} blocked {} ask {}){tail}{gap}",
            d.host, d.port, d.protocol, d.attempts, d.allowed, d.blocked, d.asked
        )
    )
}

fn print_cap(total: usize, cap: usize, what: &str) {
    if total > cap {
        println!(
            "{}",
            tr!(
                format!(
                    "      \x1b[2m{what} {total}종 중 {cap}종만 표시. 전부 보려면 --json\x1b[0m"
                ),
                format!("      \x1b[2mshowing {cap} of {total} {what}; use --json for all\x1b[0m")
            )
        );
    }
}

fn print_totals(report: &Report) {
    let t = &report.totals;
    println!("{}", tr!("전체", "totals"));
    println!(
        "{}",
        tr!(
            format!("  세션       {}", t.sessions),
            format!("  sessions   {}", t.sessions)
        )
    );
    println!(
        "{}",
        tr!(
            format!("  읽지 못함  {}", t.unreadable),
            format!("  unreadable {}", t.unreadable)
        )
    );
    println!(
        "{}",
        tr!(
            format!("  총 차단    {}", t.blocked),
            format!("  blocked    {}", t.blocked)
        )
    );
    println!(
        "{}",
        tr!(
            format!("  총 ask     {} (미응답 {})", t.asked, t.unanswered_asks),
            format!(
                "  asked      {} (unanswered {})",
                t.asked, t.unanswered_asks
            )
        )
    );
    println!(
        "{}",
        tr!(
            format!(
                "  승인       사람 {} 신원없음 {} (그중 허용 {})",
                t.identified_approvals, t.unidentified_approvals, t.auto_granted
            ),
            format!(
                "  approvals  human {} unidentified {} (of which granted {})",
                t.identified_approvals, t.unidentified_approvals, t.auto_granted
            )
        )
    );
    println!(
        "{}",
        tr!(
            format!(
                "  총 반출    {} / 수신 {}",
                human_bytes(t.bytes_out),
                human_bytes(t.bytes_in)
            ),
            format!(
                "  sent       {} / received {}",
                human_bytes(t.bytes_out),
                human_bytes(t.bytes_in)
            )
        )
    );
    if t.destinations.is_empty() {
        return;
    }
    let shown = t.destinations.len().min(TOP_DESTINATIONS);
    println!(
        "{}",
        tr!(
            format!(
                "  반출 상위 {shown}개 목적지 (전체 {}개)",
                t.destinations.len()
            ),
            format!(
                "  top {shown} destinations by sent bytes (of {} total)",
                t.destinations.len()
            )
        )
    );
    for d in t.destinations.iter().take(TOP_DESTINATIONS) {
        println!("    {}", destination_line(d));
    }
    print_cap(
        t.destinations.len(),
        TOP_DESTINATIONS,
        tr!("목적지", "destinations"),
    );
}

fn print_anomalies(report: &Report) {
    if report.anomalies.is_empty() {
        println!(
            "{}",
            tr!("\x1b[32m이상 없음\x1b[0m", "\x1b[32mno anomalies\x1b[0m")
        );
        println!("{}", tr!("종료 코드 0", "exit code 0"));
        return;
    }
    println!(
        "{}",
        tr!(
            format!("\x1b[1;31m이상 {}건\x1b[0m", report.anomalies.len()),
            format!("\x1b[1;31m{} anomalies\x1b[0m", report.anomalies.len())
        )
    );
    for a in &report.anomalies {
        let session = a.session.as_deref().unwrap_or("-");
        println!(
            "  [{}] {} {} {}",
            a.severity.label(),
            session,
            a.kind,
            sanitize(&a.detail)
        );
    }
    println!(
        "{}",
        tr!(
            format!("종료 코드 {}", report.exit_code()),
            format!("exit code {}", report.exit_code())
        )
    );
}

/// SIEM 과 스크립트가 먹을 수 있는 JSON 표현을 만듭니다.
///
/// 색상 코드가 섞이지 않고 목록을 절단하지 않습니다.
///
/// # Arguments
/// `report` - 그릴 보고
pub fn json(report: &Report) -> Value {
    let subject = report.subject();
    json!({
        "schema": SCHEMA,
        "locale": airlock_i18n::locale().as_str(),
        "generated_ts": report.generated_ts,
        "generated_rfc3339": airlock_audit::format_rfc3339_nanos(report.generated_ts),
        "root": report.root.to_string_lossy(),
        "anchor_dir": report.anchor_dir.to_string_lossy(),
        "range": {"since": report.since, "until": report.until},
        "strict_approval": report.strict_approval,
        "body_digest": report.body_digest().to_hex(),
        "report_digest": subject.digest().to_hex(),
        "verdict": report.verdict().as_str(),
        "exit_code": report.exit_code(),
        "truncated": false,
        "anchor_chain": chain_json(report),
        "review": review_json(report),
        "sessions": report.sessions.iter().map(session_json).collect::<Vec<Value>>(),
        "totals": {
            "sessions": report.totals.sessions,
            "unreadable_sessions": report.totals.unreadable,
            "blocked": report.totals.blocked,
            "asked": report.totals.asked,
            "unanswered_asks": report.totals.unanswered_asks,
            "identified_approvals": report.totals.identified_approvals,
            "unidentified_approvals": report.totals.unidentified_approvals,
            "auto_granted": report.totals.auto_granted,
            "bytes_out": report.totals.bytes_out,
            "bytes_in": report.totals.bytes_in,
            "destinations": report.totals.destinations.iter().map(destination_json).collect::<Vec<Value>>(),
        },
        "anomalies": report.anomalies.iter().map(anomaly_json).collect::<Vec<Value>>(),
    })
}

fn chain_json(report: &Report) -> Value {
    match &report.chain {
        ChainState::Ok {
            entries,
            sessions,
            head_seq,
            warnings,
        } => json!({
            "status": "ok",
            "entries": entries,
            "sessions": sessions,
            "head_seq": head_seq,
            "warnings": warnings.iter().map(|w| sanitize(w)).collect::<Vec<String>>(),
            "detail": Value::Null,
        }),
        ChainState::Absent => json!({
            "status": "absent",
            "entries": 0,
            "sessions": 0,
            "head_seq": Value::Null,
            "warnings": Vec::<String>::new(),
            "detail": tr!(
                "anchors.jsonl 없음. 탐지 불가이며 통과가 아님",
                "anchors.jsonl absent; undetectable, which is not a pass"
            ),
        }),
        ChainState::Broken { detail } => json!({
            "status": "broken",
            "entries": 0,
            "sessions": 0,
            "head_seq": Value::Null,
            "warnings": Vec::<String>::new(),
            "detail": sanitize(detail),
        }),
    }
}

fn review_json(report: &Report) -> Value {
    let last = match &report.review {
        ReviewState::Ok { last, .. } => json!({
            "seq": last.seq,
            "ts": last.ts,
            "ts_rfc3339": airlock_audit::format_rfc3339_nanos(last.ts),
            "reviewer_uid": last.reviewer_uid,
            "reviewer_euid": last.reviewer_euid,
            "reviewer_tty": last.reviewer_tty.as_deref().map(sanitize),
            "verdict": last.verdict.as_str(),
            "since": last.since,
            "until": last.until,
            "sessions": last.sessions.iter().map(|s| s.to_hex()).collect::<Vec<String>>(),
            "report_digest": last.report_digest.to_hex(),
            "note": last.note.as_deref().map(sanitize),
        }),
        _ => Value::Null,
    };
    let warnings = match &report.review {
        ReviewState::Ok { warnings, .. } => warnings
            .iter()
            .map(|w| sanitize(w))
            .collect::<Vec<String>>(),
        _ => Vec::new(),
    };
    let detail = match &report.review {
        ReviewState::Broken { detail } => Value::String(sanitize(detail)),
        _ => Value::Null,
    };
    json!({
        "status": report.review.as_str(),
        "detail": detail,
        "warnings": warnings,
        "last": last,
        "sessions_after_last_review": report.sessions_after_review,
    })
}

fn session_json(s: &SessionReport) -> Value {
    let (status, entries, head_seq, head_hash, detail) = match &s.integrity {
        Integrity::Ok {
            entries,
            head_seq,
            head_hash,
        } => (
            "ok",
            json!(entries),
            json!(head_seq),
            json!(head_hash.to_hex()),
            Value::Null,
        ),
        Integrity::Failed { detail } => (
            "failed",
            Value::Null,
            Value::Null,
            Value::Null,
            Value::String(sanitize(detail)),
        ),
    };
    json!({
        "dir": s.dir.to_string_lossy(),
        "name": s.name,
        "session": s.session.map(|v| v.to_hex()),
        "started_ts": s.started_ts,
        "started_rfc3339": airlock_audit::format_rfc3339_nanos(s.started_ts),
        "integrity": {
            "status": status,
            "entries": entries,
            "head_seq": head_seq,
            "head_hash": head_hash,
            "detail": detail,
        },
        "read_problem": s.read_problem,
        "anchor": {
            "status": s.anchor.as_str(),
            "anchor_seq": match &s.anchor {
                AnchorState::Matches { anchor_seq } => json!(anchor_seq),
                _ => Value::Null,
            },
            "detail": match &s.anchor {
                AnchorState::Mismatch { detail } => Value::String(sanitize(detail)),
                _ => Value::Null,
            },
        },
        "warnings": s.warnings.iter().map(|w| sanitize(w)).collect::<Vec<String>>(),
        "decisions": {
            "allow": s.decisions.allow,
            "deny": s.decisions.deny,
            "ask": s.decisions.ask,
            "forbid": s.decisions.forbid,
        },
        "approvals": {
            "identified": s.approvals.identified,
            "unidentified": s.approvals.unidentified,
            "auto_granted": s.approvals.auto_granted,
            "approved": s.approvals.approved,
            "refused": s.approvals.refused,
            "timed_out": s.approvals.timed_out,
            "unanswered_ask": s.approvals.unanswered,
        },
        "denied_exec": s.denied_exec.iter().map(|e| json!({
            "program": e.program,
            "argv": e.argv,
            "rule": e.rule,
            "count": e.count,
        })).collect::<Vec<Value>>(),
        "egress": s.destinations.iter().map(destination_json).collect::<Vec<Value>>(),
        "anomalies": s.anomalies.iter().map(anomaly_json).collect::<Vec<Value>>(),
    })
}

fn destination_json(d: &Destination) -> Value {
    json!({
        "host": d.host,
        "port": d.port,
        "protocol": d.protocol,
        "attempts": d.attempts,
        "allowed": d.allowed,
        "blocked": d.blocked,
        "asked": d.asked,
        "completed": d.completed,
        // 허용되었는데 결과가 남지 않은 연결 수. 0 바이트와 구분되어야 합니다
        "unknown_outcome": d.allowed.saturating_sub(d.completed),
        "bytes_out": d.bytes_out,
        "bytes_in": d.bytes_in,
        "duration_ms": d.duration_ms,
    })
}

fn anomaly_json(a: &Anomaly) -> Value {
    json!({
        "severity": a.severity.as_str(),
        "kind": a.kind,
        "session": a.session,
        "detail": sanitize(&a.detail),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_render_in_binary_units() {
        assert_eq!(human_bytes(0), "0B");
        assert_eq!(human_bytes(1023), "1023B");
        assert_eq!(human_bytes(1024), "1.0KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.0MiB");
    }

    #[test]
    fn millis_render_readably() {
        assert_eq!(human_millis(999), "999ms");
        assert_eq!(human_millis(1_500), "1.500s");
        assert_eq!(human_millis(61_000), "1m1s");
    }

    #[test]
    fn time_comes_from_the_hashed_field() {
        assert_eq!(short_time(0), "1970-01-01T00:00:00Z");
    }
}
