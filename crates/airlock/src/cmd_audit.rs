use std::path::{Path, PathBuf};

use airlock_audit::{
    AnchorCheck, AnchorFailure, Entry, Event, ReviewLog, Warning, check_session, verify_anchors,
    verify_dir,
};
use airlock_canonical::display::sanitize;

use crate::paths;
use crate::render;
use crate::report::{Report, range_of};

#[derive(Debug, clap::Subcommand)]
pub enum AuditCommand {
    #[command(about = "해시체인 무결성을 검증함")]
    Verify {
        #[arg(value_name = "DIR", help = "세션 디렉토리. 생략하면 가장 최근 세션")]
        dir: Option<PathBuf>,
        #[arg(long, help = "모든 세션을 검증함")]
        all: bool,
        #[arg(
            long,
            value_name = "DIR",
            help = "세션 상위 앵커(anchors.jsonl)가 있는 디렉토리. \
                    airlock run --anchor-dir 로 분리했다면 같은 값을 넘겨야 함. \
                    생략하면 감사 루트"
        )]
        anchor_dir: Option<PathBuf>,
    },
    #[command(about = "감사 엔트리를 사람이 읽는 형태로 출력함")]
    Show {
        #[arg(value_name = "DIR")]
        dir: Option<PathBuf>,
        #[arg(long, default_value_t = 50, help = "출력할 최대 엔트리 수")]
        limit: usize,
        #[arg(long, help = "차단과 승인 요청만 보여줌")]
        decisions_only: bool,
    },
    #[command(about = "세션 목록을 보여줌")]
    List,

    #[command(
        about = "매일 이상여부 점검 보고를 만듦",
        long_about = "범위 안의 모든 세션을 검증하고 결정·승인·아웃바운드를 집계함. \
이상이 하나라도 있으면 종료 코드가 비영이므로 cron 이나 launchd 에 그대로 걸 수 있음. \
종료 코드는 0 이상 없음, 2 증거 이상(무결성·앵커·읽기 실패), 3 운영 이상(미응답 ask 등), \
64 인자 오류, 70 내부 오류임"
    )]
    Report {
        #[arg(long, value_name = "YYYY-MM-DD", help = "이 날짜 00:00:00 UTC 부터")]
        since: Option<String>,
        #[arg(
            long,
            value_name = "YYYY-MM-DD",
            help = "이 날짜 23:59:59 UTC 까지 (그 날을 통째로 포함함)"
        )]
        until: Option<String>,
        #[arg(long, help = "SIEM 과 스크립트가 먹을 수 있는 JSON 으로 출력함")]
        json: bool,
        #[arg(
            long,
            value_name = "DIR",
            help = "앵커(anchors.jsonl)와 확인 기록(reviews.jsonl)이 있는 디렉토리. \
                    생략하면 감사 루트"
        )]
        anchor_dir: Option<PathBuf>,
        #[arg(
            long,
            help = "사람 신원 없는 자동 승인을 이상으로 셈. 기본값은 표시만 함"
        )]
        strict_approval: bool,
    },

    #[command(
        about = "책임자가 점검했다는 사실을 기록함",
        long_about = "리포트를 다시 계산해 그 범위와 다이제스트를 확인 체인에 남김. \
확인자 uid 와 euid 는 커널에서 직접 읽고 터미널은 관측된 값만 남김. \
종료 코드는 리포트와 같으며 기록 자체가 실패하면 70 임"
    )]
    Ack {
        #[arg(long, value_name = "YYYY-MM-DD")]
        since: Option<String>,
        #[arg(long, value_name = "YYYY-MM-DD")]
        until: Option<String>,
        #[arg(long, value_name = "DIR")]
        anchor_dir: Option<PathBuf>,
        #[arg(long, value_name = "TEXT", help = "확인자가 남기는 메모")]
        note: Option<String>,
        #[arg(long, help = "자동 승인을 이상으로 세고 그 판정을 기록함")]
        strict_approval: bool,
    },
}

pub fn exec(cmd: AuditCommand, audit_root_override: Option<PathBuf>) -> i32 {
    let root = audit_root_override.unwrap_or_else(paths::audit_root);
    match cmd {
        AuditCommand::Verify {
            dir,
            all,
            anchor_dir,
        } => {
            let anchors = anchor_dir.unwrap_or_else(|| root.clone());
            let chain = report_anchor_chain(&anchors);
            if all {
                let sessions = paths::all_sessions(&root);
                if sessions.is_empty() {
                    eprintln!("airlock: {}에 세션이 없음", root.display());
                    return 1;
                }
                let mut worst = chain;
                for s in sessions {
                    worst = worst.max(verify_one(&s, &anchors));
                }
                return worst;
            }
            match resolve_dir(dir, &root) {
                Some(d) => chain.max(verify_one(&d, &anchors)),
                None => 1,
            }
        }
        AuditCommand::Show {
            dir,
            limit,
            decisions_only,
        } => match resolve_dir(dir, &root) {
            Some(d) => show(&d, limit, decisions_only),
            None => 1,
        },
        AuditCommand::List => list(&root),
        AuditCommand::Report {
            since,
            until,
            json,
            anchor_dir,
            strict_approval,
        } => report(&root, anchor_dir, since, until, json, strict_approval),
        AuditCommand::Ack {
            since,
            until,
            anchor_dir,
            note,
            strict_approval,
        } => ack(&root, anchor_dir, since, until, note, strict_approval),
    }
}

/// 점검 보고를 만들어 찍고 종료 코드를 정합니다.
///
/// # Arguments
/// `root` - 감사 루트
/// `anchor_dir` - 앵커와 확인 기록이 있는 디렉토리. 생략하면 감사 루트
/// `since` - 시작 날짜
/// `until` - 끝 날짜
/// `as_json` - JSON 출력 여부
/// `strict_approval` - 자동 승인을 이상으로 셀지 여부
fn report(
    root: &Path,
    anchor_dir: Option<PathBuf>,
    since: Option<String>,
    until: Option<String>,
    as_json: bool,
    strict_approval: bool,
) -> i32 {
    let anchors = anchor_dir.unwrap_or_else(|| root.to_path_buf());
    let range = match range_of(since.as_deref(), until.as_deref()) {
        Ok(r) => r,
        Err(why) => {
            eprintln!("airlock: {why}");
            return 64;
        }
    };
    let built = Report::build(root, &anchors, since, until, range, strict_approval);
    if as_json {
        match serde_json::to_string_pretty(&render::json(&built)) {
            Ok(text) => println!("{text}"),
            Err(e) => {
                // 직렬화가 실패하면 보고가 없는 것이므로 통과로 끝내지 않습니다
                eprintln!("airlock: 보고를 JSON 으로 만들지 못함: {e}");
                return 70;
            }
        }
    } else {
        render::human(&built);
    }
    built.exit_code()
}

/// 확인 도장을 남깁니다.
///
/// 리포트를 다시 계산해 그 범위와 다이제스트를 그대로 기록합니다. 호출자가 다이제스트를
/// 넘기는 경로는 없습니다. 사람이 보지 않은 범위에 도장을 찍을 수 없어야 하기 때문입니다.
///
/// # Arguments
/// `root` - 감사 루트
/// `anchor_dir` - 확인 기록을 둘 디렉토리
/// `since` - 시작 날짜
/// `until` - 끝 날짜
/// `note` - 확인자 메모
/// `strict_approval` - 자동 승인을 이상으로 셀지 여부
fn ack(
    root: &Path,
    anchor_dir: Option<PathBuf>,
    since: Option<String>,
    until: Option<String>,
    note: Option<String>,
    strict_approval: bool,
) -> i32 {
    let anchors = anchor_dir.unwrap_or_else(|| root.to_path_buf());
    let range = match range_of(since.as_deref(), until.as_deref()) {
        Ok(r) => r,
        Err(why) => {
            eprintln!("airlock: {why}");
            return 64;
        }
    };
    let built = Report::build(root, &anchors, since, until, range, strict_approval);
    let subject = built.subject();
    let verdict = built.verdict();

    let mut log = match ReviewLog::open(&anchors) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("airlock: 확인 기록을 열지 못함: {e}");
            return 70;
        }
    };
    let entry = match log.append(&subject, verdict, note.as_deref()) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("airlock: 확인 기록을 남기지 못함: {e}");
            return 70;
        }
    };

    // 방금 쓴 줄이 정말 이 범위와 이 리포트를 가리키는지 다시 봅니다. 기록과 대상이
    // 어긋난 채로 성공을 보고하면 그 도장이 알리바이가 됩니다
    if let Err(why) = airlock_audit::check_review(&entry, &subject) {
        eprintln!("airlock: 확인 기록이 리포트와 어긋남: {why}");
        return 70;
    }

    let tty = match &entry.reviewer_tty {
        Some(t) => sanitize(t),
        None => "\x1b[33m미관측\x1b[0m".to_string(),
    };
    println!(
        "\x1b[1;36mairlock\x1b[0m 확인 기록 seq {} {}",
        entry.seq,
        log.path().display()
    );
    println!(
        "  확인자   uid={} euid={} tty={tty}",
        entry.reviewer_uid, entry.reviewer_euid
    );
    println!("  시각     {}", render::short_time(entry.ts));
    println!(
        "  범위     {} 세션 {}개",
        match (&entry.since, &entry.until) {
            (None, None) => "전체".to_string(),
            (Some(a), None) => format!("{} 이후", sanitize(a)),
            (None, Some(b)) => format!("{} 까지", sanitize(b)),
            (Some(a), Some(b)) => format!("{} .. {}", sanitize(a), sanitize(b)),
        },
        entry.sessions.len()
    );
    println!("  다이제스트 {}", entry.report_digest);
    println!("  판정     {}", verdict.label());
    if !built.anomalies.is_empty() {
        println!(
            "  \x1b[1;31m이상 {}건\x1b[0m 확인 기록에 이상으로 남았음. airlock audit report 로 내용을 볼 것",
            built.anomalies.len()
        );
    }
    built.exit_code()
}

fn resolve_dir(dir: Option<PathBuf>, root: &Path) -> Option<PathBuf> {
    match dir {
        Some(d) => Some(d),
        None => match paths::latest_session(root) {
            Some(d) => Some(d),
            None => {
                eprintln!("airlock: {}에 세션이 없음", root.display());
                None
            }
        },
    }
}

/// 앵커 체인 자체의 무결성을 먼저 보고합니다.
///
/// 체인이 깨져 있으면 개별 세션 대조 결과를 믿을 수 없으므로 실패로 냅니다. 파일이 아예
/// 없는 것은 변조가 아니라 "탐지 불가"이므로 눈에 띄게 표시하되 종료 코드는 올리지
/// 않습니다. 크래시로 죽은 세션과 앵커 삭제를 이 층에서 구분할 방법이 없기 때문입니다
/// (`docs/audit-format.md` 8.4).
///
/// # Arguments
/// `anchors` - 앵커 루트
fn report_anchor_chain(anchors: &Path) -> i32 {
    match verify_anchors(anchors) {
        Ok(report) => {
            println!(
                "\x1b[32m앵커 확인\x1b[0m {} ({} 줄, 세션 {}개, head seq {})",
                anchors.join(airlock_audit::ANCHOR_FILE).display(),
                report.entries,
                report.sessions,
                report.head_seq
            );
            for w in &report.warnings {
                println!("  \x1b[33m경고\x1b[0m {w}");
            }
            0
        }
        Err(AnchorFailure::FileAbsent) => {
            println!(
                "\x1b[33m앵커 탐지불가\x1b[0m {}",
                anchors.join(airlock_audit::ANCHOR_FILE).display()
            );
            println!("  {}", AnchorFailure::FileAbsent);
            println!("  세션 통째 삭제와 체인 재계산을 이 검증으로는 알 수 없음. 통과가 아님");
            0
        }
        Err(failure) => {
            println!("\x1b[1;31m앵커 실패\x1b[0m {}", anchors.display());
            println!("  {failure}");
            2
        }
    }
}

/// 세션 체인의 head가 앵커 기록과 맞는지 대조해 한 줄로 보고합니다.
///
/// # Arguments
/// `anchors` - 앵커 루트
/// `report` - 이미 통과한 세션 체인 검증 결과
fn report_session_anchor(anchors: &Path, report: &airlock_audit::VerifyReport) -> i32 {
    match check_session(anchors, &report.session, report.head_seq, &report.head_hash) {
        Ok(AnchorCheck::Matches { anchor_seq }) => {
            println!("  앵커     seq {anchor_seq}에서 head 일치");
            0
        }
        // 앵커 줄이 없는 세션은 통과가 아니라 탐지 불가입니다. 이 세션이 통째로
        // 지워졌어도 알아낼 방법이 없다는 뜻이므로 그대로 적습니다
        Ok(AnchorCheck::Missing) => {
            println!(
                "  \x1b[33m앵커\x1b[0m     이 세션의 앵커 줄이 없음. 탐지 불가이며 통과가 아님"
            );
            0
        }
        Err(AnchorFailure::FileAbsent) => 0,
        Err(failure) => {
            println!("  \x1b[1;31m앵커 불일치\x1b[0m {failure}");
            2
        }
    }
}

fn verify_one(dir: &Path, anchors: &Path) -> i32 {
    match verify_dir(dir) {
        Ok(report) => {
            println!(
                "\x1b[32m무결성 확인\x1b[0m {} ({} 엔트리, head seq {})",
                dir.display(),
                report.entries,
                report.head_seq
            );
            println!("  세션     {}", report.session);
            println!("  체인헤드 {}", report.head_hash);
            for w in &report.warnings {
                let label = match w {
                    Warning::ObserveOnlyEntries { .. } => "\x1b[33m강제없음\x1b[0m",
                    _ => "\x1b[33m경고\x1b[0m",
                };
                println!("  {label} {w}");
            }
            report_session_anchor(anchors, &report)
        }
        Err(failure) => {
            println!("\x1b[1;31m무결성 실패\x1b[0m {}", dir.display());
            println!("  {failure}");
            2
        }
    }
}

fn decision_color(entry: &Entry) -> &'static str {
    match entry.decision {
        airlock_audit::Decision::Allow => "\x1b[32m",
        airlock_audit::Decision::Ask => "\x1b[33m",
        airlock_audit::Decision::Deny | airlock_audit::Decision::Forbid => "\x1b[31m",
    }
}

/// 승인자 신원을 사람이 읽는 한 조각으로 만듭니다.
///
/// 신원이 없는 승인은 `--yes` 자동 승인이거나 신원을 관측하지 못한 채널입니다. 그것을
/// 사람이 승인한 것처럼 보이게 하면 감사 로그가 거짓 보증을 하므로, 없다는 사실을
/// 그대로 적습니다.
///
/// # Arguments
/// `uid` - 승인에 답한 계정의 실효 uid
/// `tty` - 승인 프롬프트가 나간 터미널 장치 경로
fn approver(uid: Option<u32>, tty: Option<&str>) -> String {
    match (uid, tty) {
        (None, None) => "\x1b[33m승인자없음(사람 확인 아님)\x1b[0m".to_string(),
        (uid, tty) => {
            let uid = uid.map_or_else(|| "?".to_string(), |u| u.to_string());
            let tty = tty.map_or_else(|| "?".to_string(), sanitize);
            format!("승인자 uid={uid} tty={tty}")
        }
    }
}

fn describe_event(event: &Event) -> String {
    match event {
        Event::SessionStart {
            argv,
            policy_digest,
            policy_source,
            fsync_per_entry,
            mediation,
            ..
        } => {
            let short: String = policy_digest.to_hex().chars().take(12).collect();
            let source = policy_source
                .as_deref()
                .map(sanitize)
                .unwrap_or_else(|| "내장 베이스라인".to_string());
            let sync = if *fsync_per_entry {
                ""
            } else {
                " [fsync 없음]"
            };
            // 중계 수준을 함께 보여 줍니다. exec 엔트리가 없는 체인이 "아무 일도 없었음"
            // 인지 "중계가 꺼져 있어 보이지 않았음"인지 구분되어야 합니다
            format!(
                "세션 시작 정책={source} 다이제스트={short} 중계={}{sync} argv={argv:?}",
                mediation.as_str()
            )
        }
        Event::SessionEnd { status } => format!("세션 종료 {status:?}"),
        Event::FileAccess {
            path_requested,
            path_resolved,
            mode,
        } => {
            let requested = sanitize(path_requested);
            let resolved = sanitize(path_resolved);
            if requested == resolved {
                format!("파일 {mode} {requested}")
            } else {
                format!("파일 {mode} {requested} \x1b[35m-> {resolved}\x1b[0m")
            }
        }
        Event::Exec { program, argv, .. } => format!("실행 {} {argv:?}", sanitize(program)),
        Event::Egress {
            host,
            port,
            protocol,
        } => format!("아웃바운드 {protocol} {}:{port}", sanitize(host)),
        Event::EgressSummary {
            host,
            port,
            protocol,
            bytes_out,
            bytes_in,
            duration_ms,
        } => format!(
            "아웃바운드 종료 {protocol} {}:{port} 반출 {} 수신 {} {}",
            sanitize(host),
            render::human_bytes(*bytes_out),
            render::human_bytes(*bytes_in),
            render::human_millis(*duration_ms)
        ),
        Event::Approval {
            for_seq,
            granted,
            note,
            approver_uid,
            approver_tty,
        } => {
            let mut s = format!("승인응답 seq={for_seq} {granted}");
            s.push(' ');
            s.push_str(&approver(*approver_uid, approver_tty.as_deref()));
            if let Some(n) = note {
                s.push_str(&format!(" ({})", sanitize(n)));
            }
            s
        }
        Event::PolicyReload { policy_digest, .. } => {
            let short: String = policy_digest.to_hex().chars().take(12).collect();
            format!("정책 재적용 다이제스트={short}")
        }
    }
}

fn show(dir: &Path, limit: usize, decisions_only: bool) -> i32 {
    // 렌더링 전에 체인을 먼저 검증합니다. 위조된 엔트리를 아무 표시 없이 사람에게
    // 보여 주면 뷰어가 공격자의 출력 장치가 됩니다
    let integrity = airlock_audit::verify_dir(dir);

    let (entries, problem) = match airlock_audit::read_entries_lossy(dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("airlock: {e}");
            return 1;
        }
    };
    if let Some(p) = &problem {
        // 경고와 엔트리를 같은 스트림에 둡니다. 리다이렉트나 페이저로 경고만 사라지면
        // 조용히 뚫린 것과 같습니다
        println!("\x1b[1;31mairlock 경고\x1b[0m {p}");
    }

    if let Err(failure) = &integrity {
        println!(
            "\x1b[1;31m╔══ 무결성 실패 ═══════════════════════════════════\x1b[0m\n\
             \x1b[1;31m║\x1b[0m {failure}\n\
             \x1b[1;31m║\x1b[0m 아래 내용은 검증되지 않았으므로 증거로 쓸 수 없음\n\
             \x1b[1;31m╚═════════════════════════════════════════════════\x1b[0m"
        );
    }

    if entries.is_empty() {
        eprintln!("airlock: 읽을 수 있는 엔트리가 없음. airlock audit verify로 확인할 것");
        return 1;
    }

    let filtered: Vec<&Entry> = entries
        .iter()
        .filter(|e| {
            !decisions_only
                || matches!(
                    e.decision,
                    airlock_audit::Decision::Deny
                        | airlock_audit::Decision::Forbid
                        | airlock_audit::Decision::Ask
                )
        })
        .collect();

    let skipped = filtered.len().saturating_sub(limit);
    let window = if filtered.len() > limit {
        &filtered[filtered.len() - limit..]
    } else {
        &filtered[..]
    };

    if skipped > 0 {
        println!("\x1b[2m앞선 {skipped}개 엔트리 생략. --limit로 조절\x1b[0m");
    }

    for e in window {
        let color = decision_color(e);
        // 저장된 ts_rfc3339은 해시 대상이 아니므로 위조할 수 있습니다. 해시가 보증하는
        // ts에서 다시 만들어 표시합니다
        let derived = airlock_audit::format_rfc3339_nanos(e.ts);
        let time = derived.get(0..19).unwrap_or(&derived).to_string();
        let rule = e
            .rule
            .as_deref()
            .map(sanitize)
            .unwrap_or_else(|| "기본값".to_string());
        println!(
            "{:>5} {time}Z {color}{:<6}\x1b[0m {:<9} {} \x1b[2m[{rule}]\x1b[0m",
            e.seq,
            e.decision.as_str(),
            e.enforcement.as_str(),
            describe_event(&e.event)
        );
    }

    let observed = entries
        .iter()
        .filter(|e| e.enforcement == airlock_audit::Enforcement::Observe)
        .count();
    if observed > 0 {
        println!(
            "\n\x1b[33m주의\x1b[0m {observed}개 엔트리가 observe 모드임. 기록되었지만 강제되지 않음"
        );
    }

    // 검증 실패는 종료 코드로도 드러냅니다. 파이프라인이 show 만 부르고도 알아챌 수 있어야 합니다
    if integrity.is_err() || problem.is_some() {
        return 2;
    }
    0
}

fn list(root: &Path) -> i32 {
    let sessions = paths::all_sessions(root);
    if sessions.is_empty() {
        println!("{}에 세션이 없음", root.display());
        return 0;
    }
    println!("{} 아래 {}개 세션", root.display(), sessions.len());
    for s in sessions.iter().rev() {
        let name = s.file_name().unwrap_or_default().to_string_lossy();
        let status = match verify_dir(s) {
            Ok(r) => {
                let unenforced = r
                    .warnings
                    .iter()
                    .any(|w| matches!(w, Warning::ObserveOnlyEntries { .. }));
                if unenforced {
                    format!("\x1b[33mobserve\x1b[0m {} 엔트리", r.entries)
                } else {
                    format!("\x1b[32m정상\x1b[0m   {} 엔트리", r.entries)
                }
            }
            Err(_) => "\x1b[31m손상\x1b[0m".to_string(),
        };
        println!("  {name}  {status}");
    }
    0
}
