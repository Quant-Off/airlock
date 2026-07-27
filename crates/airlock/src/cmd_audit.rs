use std::path::{Path, PathBuf};

use airlock_audit::{Entry, Event, Warning, verify_dir};

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
            ..
        } => {
            let short: String = policy_digest.to_hex().chars().take(12).collect();
            let source = policy_source.as_deref().unwrap_or("내장 베이스라인");
            let sync = if *fsync_per_entry {
                ""
            } else {
                " [fsync 없음]"
            };
            format!("세션 시작 정책={source} 다이제스트={short}{sync} argv={argv:?}")
        }
        Event::SessionEnd { status } => format!("세션 종료 {status:?}"),
        Event::FileAccess {
            path_requested,
            path_resolved,
            mode,
        } => {
            if path_requested == path_resolved {
                format!("파일 {mode} {path_requested}")
            } else {
                format!("파일 {mode} {path_requested} \x1b[35m-> {path_resolved}\x1b[0m")
            }
        }
        Event::Exec { program, argv, .. } => format!("실행 {program} {argv:?}"),
        Event::Egress {
            host,
            port,
            protocol,
        } => format!("아웃바운드 {protocol} {host}:{port}"),
        Event::Approval {
            for_seq,
            granted,
            note,
        } => {
            let mut s = format!("승인응답 seq={for_seq} {granted}");
            if let Some(n) = note {
                s.push_str(&format!(" ({n})"));
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
    let (entries, problem) = match airlock_audit::read_entries_lossy(dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("airlock: {e}");
            return 1;
        }
    };
    if let Some(p) = &problem {
        eprintln!("airlock: 경고 {p}");
        eprintln!("airlock: airlock audit verify로 무결성을 확인할 것");
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
        let time = e.ts_rfc3339.get(0..19).unwrap_or(&e.ts_rfc3339);
        let rule = e.rule.as_deref().unwrap_or("기본값");
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
