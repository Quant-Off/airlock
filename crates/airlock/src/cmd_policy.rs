use std::path::PathBuf;

use airlock_policy::{Action, FileMode, LoadContext, Policy};

use crate::paths;

#[derive(Debug, clap::Subcommand)]
pub enum PolicyCommand {
    #[command(about = "특정 요청에 대한 결정과 그 근거를 보여줌")]
    Explain {
        #[arg(long, value_name = "PATH", help = "파일 경로에 대한 결정")]
        file: Option<PathBuf>,

        #[arg(
            long,
            default_value = "read",
            help = "파일 모드 read|write|create|delete|metadata|exec"
        )]
        mode: String,

        #[arg(long, value_name = "PROGRAM", help = "실행 결정")]
        exec: Option<String>,

        #[arg(long, value_name = "HOST", help = "아웃바운드 호스트")]
        host: Option<String>,

        #[arg(long, default_value_t = 443, help = "아웃바운드 포트")]
        port: u16,

        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,

        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "ARGS"
        )]
        args: Vec<String>,
    },

    #[command(about = "정책을 로드하고 문제를 보고함")]
    Check {
        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,
    },

    #[command(about = "생성되는 OS 강제 프로파일을 그대로 출력함")]
    Profile {
        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
    },
}

fn load(
    explicit: Option<&std::path::Path>,
    audit_root: Option<PathBuf>,
) -> Result<(Policy, Option<PathBuf>), i32> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let audit_root = audit_root.unwrap_or_else(paths::audit_root);
    let mut ctx = LoadContext::new(airlock_policy::path::home_dir(), &audit_root);
    if let Ok(exe) = std::env::current_exe() {
        ctx = ctx.with_binary(exe);
    }

    let path = paths::discover_policy(explicit, &cwd);
    let policy = match &path {
        Some(p) => Policy::load_file(p, &ctx).map_err(|e| {
            eprintln!("airlock: {e}");
            78
        })?,
        None => Policy::baseline_only(&ctx).map_err(|e| {
            eprintln!("airlock: 내장 베이스라인 로드 실패: {e}");
            70
        })?,
    };
    Ok((policy, path))
}

pub fn exec(cmd: PolicyCommand, audit_root: Option<PathBuf>) -> i32 {
    match cmd {
        PolicyCommand::Explain {
            file,
            mode,
            exec,
            host,
            port,
            policy,
            args,
        } => {
            let (policy, _) = match load(policy.as_deref(), audit_root) {
                Ok(v) => v,
                Err(code) => return code,
            };
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

            if let Some(path) = file {
                let Some(mode) = FileMode::parse(&mode) else {
                    eprintln!("airlock: 알 수 없는 mode `{mode}`");
                    return 64;
                };
                let ev = policy.evaluate_file(&path, mode, &cwd);
                print_file(&ev, mode);
                return exit_for(ev.action);
            }

            if let Some(program) = exec {
                let resolved =
                    airlock_broker::which(&program).unwrap_or_else(|| PathBuf::from(&program));
                let mut argv = vec![program.clone()];
                argv.extend(args.iter().cloned());
                let ev = policy.evaluate_exec(&resolved, &argv, &cwd);
                print_exec(&ev, &argv);
                return exit_for(ev.action);
            }

            if let Some(host) = host {
                let ev = policy.evaluate_egress(&host, port);
                print_egress(&ev, &host, port);
                return exit_for(ev.action);
            }

            eprintln!("airlock: --file, --exec, --host 중 하나가 필요함");
            64
        }

        PolicyCommand::Check { policy } => {
            let (policy, path) = match load(policy.as_deref(), audit_root) {
                Ok(v) => v,
                Err(code) => return code,
            };
            let digest = airlock_audit::Hash::from_bytes(policy.digest());
            println!("\x1b[32m정책 로드 성공\x1b[0m");
            println!(
                "  출처       {}",
                path.map(|p| p.display().to_string())
                    .unwrap_or_else(|| "내장 베이스라인".to_string())
            );
            println!("  이름       {}", policy.name());
            println!("  다이제스트 {digest}");
            println!(
                "  규칙       tier0 {} / 사용자 {} / 베이스라인 {}",
                policy.self_protect_rules().len(),
                policy.user_rules().len(),
                policy.baseline_rules().len()
            );
            let d = policy.defaults();
            println!(
                "  기본값     file={} exec={} egress={}",
                d.file, d.exec, d.egress
            );

            if policy.warnings().is_empty() {
                println!("  경고       없음");
                0
            } else {
                println!("  경고       {}건", policy.warnings().len());
                for w in policy.warnings() {
                    println!("    \x1b[33m-\x1b[0m {w}");
                }
                0
            }
        }

        PolicyCommand::Profile { policy, workspace } => {
            let (policy, _) = match load(policy.as_deref(), audit_root) {
                Ok(v) => v,
                Err(code) => return code,
            };
            let opts = airlock_broker::ProfileOptions {
                workspace: workspace.or_else(|| std::env::current_dir().ok()),
                ..Default::default()
            };
            let generated = airlock_broker::profile::generate(&policy, &opts);
            print!("{}", generated.text);
            for item in &generated.untranslatable {
                eprintln!("airlock: 경고 프로파일로 옮기지 못한 규칙 {item}");
            }
            0
        }
    }
}

fn exit_for(action: Action) -> i32 {
    match action {
        Action::Allow => 0,
        Action::Ask => 3,
        Action::Deny | Action::Forbid => 4,
    }
}

fn colored(action: Action) -> String {
    let color = match action {
        Action::Allow => "\x1b[32m",
        Action::Ask => "\x1b[33m",
        Action::Deny | Action::Forbid => "\x1b[31m",
    };
    format!("{color}{action}\x1b[0m")
}

fn print_rule(ev: &airlock_policy::Evaluation) {
    match &ev.rule {
        Some(rule) => {
            println!("규칙     {} ({} tier)", rule.id, rule.tier);
            println!("매칭     {}", rule.pattern);
            if let Some(reason) = &rule.reason {
                println!("근거     {reason}");
            }
        }
        None => println!("규칙     없음 (기본값 적용)"),
    }
}

fn print_file(ev: &airlock_policy::Evaluation, mode: FileMode) {
    if let Some(np) = &ev.path {
        println!("요청     {}", np.requested.display());
        println!("해소     {}", np.resolved.display());
        if np.diverges() {
            println!("         \x1b[35m경로가 다름. 더 제한적인 쪽이 채택됨\x1b[0m");
        }
    }
    println!("모드     {mode}");
    println!("결정     {}", colored(ev.action));
    print_rule(ev);
}

fn print_exec(ev: &airlock_policy::Evaluation, argv: &[String]) {
    if let Some(np) = &ev.path {
        println!("프로그램 {}", np.requested.display());
        if np.diverges() {
            println!("해소     {}", np.resolved.display());
        }
    }
    println!("argv     {argv:?}");
    println!("결정     {}", colored(ev.action));
    print_rule(ev);
    if ev.action.is_restrictive() {
        println!(
            "\x1b[2m참고 exec 규칙은 보안 경계가 아니라 tripwire임. 실제 방어는 file과 egress 규칙에서 나옴\x1b[0m"
        );
    }
}

fn print_egress(ev: &airlock_policy::Evaluation, host: &str, port: u16) {
    println!("호스트   {host}:{port}");
    println!("결정     {}", colored(ev.action));
    print_rule(ev);
}
