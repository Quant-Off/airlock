use std::path::{Path, PathBuf};

use airlock_audit::{Entry, Event, Warning, verify_dir};
use airlock_canonical::display::sanitize;

use crate::paths;

#[derive(Debug, clap::Subcommand)]
pub enum AuditCommand {
    #[command(about = "해시체인 무결성을 검증함")]
    Verify {
        #[arg(value_name = "DIR", help = "세션 디렉토리. 생략하면 가장 최근 세션")]
        dir: Option<PathBuf>,
        #[arg(long, help = "모든 세션을 검증함")]
        all: bool,
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
}

pub fn exec(cmd: AuditCommand, audit_root_override: Option<PathBuf>) -> i32 {
    let root = audit_root_override.unwrap_or_else(paths::audit_root);
    match cmd {
        AuditCommand::Verify { dir, all } => {
            if all {
                let sessions = paths::all_sessions(&root);
                if sessions.is_empty() {
                    eprintln!("airlock: {}에 세션이 없음", root.display());
                    return 1;
                }
                let mut failed = 0;
                for s in sessions {
                    if verify_one(&s) != 0 {
                        failed += 1;
                    }
                }
                return if failed == 0 { 0 } else { 1 };
            }
            match resolve_dir(dir, &root) {
                Some(d) => verify_one(&d),
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
    }
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

fn verify_one(dir: &Path) -> i32 {
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
            0
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
        Event::Approval {
            for_seq,
            granted,
            note,
        } => {
            let mut s = format!("승인응답 seq={for_seq} {granted}");
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
