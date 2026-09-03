mod cmd_audit;
mod cmd_policy;
mod cmd_run;
mod cmd_setup;
mod paths;
mod render;
mod report;

use std::path::PathBuf;

use airlock_i18n::tr;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "airlock",
    version,
    about = tr!(
        "AI 코딩 에이전트를 위한 로컬 제로트러스트 게이트웨이",
        "a local zero-trust gateway for AI coding agents"
    ),
    long_about = tr!(
        "에이전트의 파일 접근, 프로세스 실행, 아웃바운드 연결을 경계에서 중재하고 \
변조 탐지 가능한 해시체인 감사 로그로 남김",
        "mediates the agent's file access, process execution, and outbound connections \
at the boundary and records them in a tamper-evident hash-chained audit log"
    )
)]
struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "DIR",
        help = tr!(
            "감사 로그 루트로, AIRLOCK_AUDIT_DIR로도 지정할 수 있음",
            "audit log root, can also be set via AIRLOCK_AUDIT_DIR"
        )
    )]
    audit_root: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = tr!("브로커 아래에서 명령 실행", "run a command under the broker"))]
    Run(cmd_run::RunArgs),

    #[command(
        subcommand,
        about = tr!("감사 로그를 검증 및 조회", "verify and inspect the audit log")
    )]
    Audit(cmd_audit::AuditCommand),

    #[command(
        subcommand,
        about = tr!("정책을 검사 및 설명", "check and explain a policy")
    )]
    Policy(cmd_policy::PolicyCommand),

    #[command(
        about = tr!(
            "대화형으로 정책 파일 생성",
            "generate a policy file interactively"
        )
    )]
    Setup(cmd_setup::SetupArgs),
}

fn main() {
    airlock_i18n::init();
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Run(args) => cmd_run::exec(args, cli.audit_root),
        Command::Audit(cmd) => cmd_audit::exec(cmd, cli.audit_root),
        Command::Policy(cmd) => cmd_policy::exec(cmd, cli.audit_root),
        Command::Setup(args) => cmd_setup::exec(args, cli.audit_root),
    };
    std::process::exit(code);
}
