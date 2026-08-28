use std::path::PathBuf;

use airlock_canonical::display::sanitize;
use airlock_policy::{Action, FileMode, LoadContext, PLAINTEXT_FLOOR_ID, Policy, Protocol};

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

        #[arg(
            long,
            default_value = "tcp",
            help = "아웃바운드 프로토콜 tcp|tls|http. 기본값 tcp는 관측 층이 프로토콜을 \
                    모른다는 뜻이며 중계 층이 넘기는 값과 같음"
        )]
        protocol: String,

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
    let audit_root = paths::absolutize(&audit_root.unwrap_or_else(paths::audit_root), &cwd);
    let path = paths::discover_policy(explicit, &cwd).map(|p| paths::absolutize_lexical(&p, &cwd));

    let mut candidates: Vec<PathBuf> = paths::policy_candidates(&cwd)
        .iter()
        .flat_map(|p| paths::protect_forms(p, &cwd))
        .collect();
    if let Some(p) = &path {
        for form in paths::protect_forms(p, &cwd) {
            if !candidates.contains(&form) {
                candidates.push(form);
            }
        }
    }

    let mut ctx = LoadContext::new(airlock_policy::path::home_dir(), &audit_root)
        .with_policy_files(candidates);
    if let Ok(exe) = std::env::current_exe() {
        ctx = ctx.with_binary(exe);
    }
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
            protocol,
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
                print_exec(
                    &ev,
                    &argv,
                    airlock_broker::profile::exec_whitelist_mode(&policy),
                );
                return exit_for(ev.action);
            }

            if let Some(host) = host {
                let Some(protocol) = Protocol::parse(&protocol) else {
                    eprintln!(
                        "airlock: 알 수 없는 protocol `{protocol}`. tcp, tls, http 중 하나여야 함"
                    );
                    return 64;
                };
                let ev = policy.evaluate_egress(&host, port, protocol);
                print_egress(&ev, &host, port, protocol);
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
                "  기본값     file={} exec={} egress={} egress_plaintext={}",
                d.file, d.exec, d.egress, d.egress_plaintext
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
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let opts = airlock_broker::ProfileOptions {
                workspace: Some(paths::absolutize(
                    &workspace.unwrap_or_else(|| cwd.clone()),
                    &cwd,
                )),
                ..Default::default()
            };
            let generated = airlock_broker::profile::generate(&policy, &opts);
            print!("{}", generated.text);
            for item in &generated.untranslatable {
                eprintln!(
                    "airlock: 경고 프로파일로 옮기지 못한 규칙 {}",
                    sanitize(item)
                );
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
            println!("규칙     {} ({} tier)", sanitize(&rule.id), rule.tier);
            println!("매칭     {}", sanitize(&rule.pattern));
            if let Some(reason) = &rule.reason {
                println!("근거     {}", sanitize(reason));
            }
        }
        None => println!("규칙     없음 (기본값 적용)"),
    }
}

fn print_file(ev: &airlock_policy::Evaluation, mode: FileMode) {
    if let Some(np) = &ev.path {
        println!("요청     {}", sanitize(&np.requested.display().to_string()));
        println!("해소     {}", sanitize(&np.resolved.display().to_string()));
        if np.diverges() {
            println!("         \x1b[35m경로가 다름. 더 제한적인 쪽이 채택됨\x1b[0m");
        }
    }
    println!("모드     {mode}");
    println!("결정     {}", colored(ev.action));
    print_rule(ev);
}

/// exec 결정을 출력합니다.
///
/// # Arguments
/// `ev` - 평가 결과
/// `argv` - 질의에 쓰인 argv
/// `whitelist` - 이 정책에서 exec 이 커널 화이트리스트로 걸리는지
fn print_exec(ev: &airlock_policy::Evaluation, argv: &[String], whitelist: bool) {
    if let Some(np) = &ev.path {
        println!("프로그램 {}", sanitize(&np.requested.display().to_string()));
        if np.diverges() {
            println!("해소     {}", sanitize(&np.resolved.display().to_string()));
        }
    }
    println!("argv     {argv:?}");
    println!("결정     {}", colored(ev.action));
    print_rule(ev);
    // 프로그램 경로와 argv 조건은 성질이 다릅니다. 둘을 한 문장으로 뭉뚱그리면 강제되는
    // 것을 강제되지 않는다고 말하거나 그 반대가 됩니다 (docs/policy-dsl.md 7.1)
    if whitelist {
        println!(
            "\x1b[2m참고 [defaults].exec 이 allow 가 아니므로 프로그램 경로는 커널 화이트리스트임. \
             argv 조건은 커널이 볼 수 없어 tripwire 로만 남음\x1b[0m"
        );
    } else if ev.action.is_restrictive() {
        println!(
            "\x1b[2m참고 [defaults].exec = allow 라 exec 화이트리스트를 걸지 않음. \
             이 규칙은 보안 경계가 아니라 tripwire 이며 실제 방어는 file 과 egress 규칙에서 나옴\x1b[0m"
        );
    }
}

fn print_egress(ev: &airlock_policy::Evaluation, host: &str, port: u16, protocol: Protocol) {
    println!("호스트   {}", sanitize(host));
    println!("포트     {port}");
    println!("프로토콜 {protocol}");
    println!("결정     {}", colored(ev.action));
    print_rule(ev);

    // 평문 바닥이 결정을 바꿨을 때만 엔진이 합성 규칙을 냅니다. 그 사실을 드러내지 않으면
    // 사용자는 자기가 적은 allow 규칙이 왜 통하지 않는지 알 수 없습니다
    if ev.rule.as_ref().is_some_and(|r| r.id == PLAINTEXT_FLOOR_ID) {
        println!(
            "\x1b[33m평문 바닥이 결정을 바꿨음.\x1b[0m [defaults].egress_plaintext 가 상한이며 \
             열려면 그 egress 규칙에 protocol = \"http\" 를 명시할 것"
        );
    }
    if protocol == Protocol::Tcp {
        println!(
            "\x1b[2m참고 protocol=tcp 는 관측 층이 프로토콜을 모른다는 뜻임. \
             중계 층만으로 도는 세션은 항상 이 값이라 평문 바닥이 발동하지 않음. \
             평문 판정은 airlock run --egress-proxy 위에서만 성립함\x1b[0m"
        );
    }
}
