mod cmd_audit;
mod cmd_policy;
mod cmd_run;
mod paths;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "airlock",
    version,
    about = "AI 코딩 에이전트를 위한 로컬 제로트러스트 게이트웨이",
    long_about = "에이전트의 파일 접근, 프로세스 실행, 아웃바운드 연결을 경계에서 중재하고 \
변조 탐지 가능한 해시체인 감사 로그로 남김"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "DIR",
        help = "감사 로그 루트로, AIRLOCK_AUDIT_DIR로도 지정할 수 있음"
    )]
    audit_root: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "브로커 아래에서 명령 실행")]
    Run(cmd_run::RunArgs),

    #[command(subcommand, about = "감사 로그를 검증 및 조회")]
    Audit(cmd_audit::AuditCommand),

    #[command(subcommand, about = "정책을 검사 및 설명")]
    Policy(cmd_policy::PolicyCommand),
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Run(args) => cmd_run::exec(args, cli.audit_root),
        Command::Audit(cmd) => cmd_audit::exec(cmd, cli.audit_root),
        Command::Policy(cmd) => cmd_policy::exec(cmd, cli.audit_root),
    };
    std::process::exit(code);
}
