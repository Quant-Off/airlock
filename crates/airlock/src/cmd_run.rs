use std::path::PathBuf;

use airlock_broker::{
    ApproveAll, Approver, Enforcer, ObserveEnforcer, ProfileOptions, RefuseAll, SessionConfig,
    TtyApprover,
};
use airlock_policy::{LoadContext, Policy};

use crate::paths;

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    #[arg(long, value_name = "FILE", help = "정책 파일 경로")]
    pub policy: Option<PathBuf>,

    #[arg(long, help = "강제 없이 기록만 함 (학습 모드)")]
    pub observe: bool,

    #[arg(long, value_name = "DIR", help = "감사 로그 루트")]
    pub audit_dir: Option<PathBuf>,

    #[arg(long, value_name = "DIR", help = "쓰기 허용 작업 공간. 기본값은 cwd")]
    pub workspace: Option<PathBuf>,

    #[arg(long, help = "아웃바운드 네트워크를 통째로 차단함")]
    pub no_network: bool,

    #[arg(
        long,
        help = "모든 ask를 사람 확인 없이 승인함. 승인 통제를 포기하는 설정임"
    )]
    pub yes: bool,

    #[arg(
        long,
        help = "엔트리마다 fsync 하지 않음. 크래시 시 구간 손실을 감수함"
    )]
    pub no_fsync: bool,

    #[arg(
        long,
        default_value = "exec-net",
        value_name = "LEVEL",
        help = "런타임 중계 수준 off|exec-net|full. full은 파일 열기까지 기록하지만 느림 (Linux 전용)"
    )]
    pub mediate: String,

    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required = true,
        value_name = "CMD",
        help = "실행할 명령과 인자"
    )]
    pub command: Vec<String>,
}

pub fn exec(args: RunArgs, global_audit_root: Option<PathBuf>) -> i32 {
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("airlock: 현재 디렉토리를 알 수 없음: {e}");
            return 70;
        }
    };

    let Some(mediation) = airlock_broker::Mediation::parse(&args.mediate) else {
        eprintln!(
            "airlock: 알 수 없는 --mediate `{}`. off, exec-net, full 중 하나여야 함",
            args.mediate
        );
        return 64;
    };

    let audit_root = args
        .audit_dir
        .clone()
        .or(global_audit_root)
        .unwrap_or_else(paths::audit_root);
    let session_dir = paths::session_dir(&audit_root);
    let policy_path = paths::discover_policy(args.policy.as_deref(), &cwd);

    let mut ctx = LoadContext::new(airlock_policy::path::home_dir(), &audit_root);
    if let Ok(exe) = std::env::current_exe() {
        ctx = ctx.with_binary(exe);
    }

    let policy = match &policy_path {
        Some(p) => match Policy::load_file(p, &ctx) {
            Ok(policy) => policy,
            Err(e) => {
                eprintln!("airlock: {e}");
                eprintln!("airlock: 정책이 적용되지 않았으므로 실행을 중단함");
                return 78;
            }
        },
        None => match Policy::baseline_only(&ctx) {
            Ok(policy) => policy,
            Err(e) => {
                eprintln!("airlock: 내장 베이스라인 로드 실패: {e}");
                return 70;
            }
        },
    };

    for w in policy.warnings() {
        eprintln!("airlock: 경고 {w}");
    }

    let workspace = args.workspace.clone().unwrap_or_else(|| cwd.clone());
    let mut enforcer: Box<dyn Enforcer> = if args.observe {
        Box::new(ObserveEnforcer)
    } else {
        build_enforcer(&workspace, !args.no_network)
    };

    let approver: Box<dyn Approver> = if args.yes {
        eprintln!(
            "airlock: 경고 --yes는 모든 ask를 사람 확인 없이 승인함. 감사 로그에 자동 승인으로 기록됨"
        );
        Box::new(ApproveAll)
    } else if TtyApprover::available() {
        Box::new(TtyApprover)
    } else {
        eprintln!("airlock: 경고 /dev/tty가 없어 모든 ask를 거부함");
        Box::new(RefuseAll {
            why: "제어 터미널 없음".to_string(),
        })
    };

    let program = args.command.first().cloned().unwrap_or_default();
    let rest: Vec<String> = args.command.iter().skip(1).cloned().collect();

    let mut argv = vec!["airlock".to_string(), "run".to_string()];
    if args.observe {
        argv.push("--observe".to_string());
    }
    argv.push("--".to_string());
    argv.extend(args.command.iter().cloned());

    let config = SessionConfig {
        audit_dir: session_dir.clone(),
        actor: format!("pid:{} {program}", std::process::id()),
        cwd: cwd.clone(),
        argv,
        fsync_per_entry: !args.no_fsync,
        policy_source: policy_path
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned()),
        airlock_version: env!("CARGO_PKG_VERSION").to_string(),
        mediation,
    };

    // 배너가 강제 층의 한계를 그대로 보여주려면 정책에서 유도되는 gap이
    // 출력 전에 채워져 있어야 합니다. prepare는 결정적이라 run 안에서 다시 불려도 안전합니다
    if let Err(e) = enforcer.prepare(&policy) {
        eprintln!("airlock: {e}");
        return 70;
    }

    print_banner(&policy, enforcer.as_ref(), approver.as_ref(), &session_dir);

    let report = match airlock_broker::run(
        &program,
        &rest,
        policy,
        std::mem::replace(&mut enforcer, Box::new(ObserveEnforcer)),
        approver,
        &config,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("airlock: {e}");
            return 70;
        }
    };

    print_summary(&report);
    report
        .exit_code
        .unwrap_or(if report.denied > 0 { 77 } else { 0 })
}

fn build_enforcer(workspace: &std::path::Path, allow_network: bool) -> Box<dyn Enforcer> {
    #[cfg(target_os = "macos")]
    {
        let mut opts = ProfileOptions::default()
            .with_workspace(workspace)
            .with_network(allow_network);
        if let Some(tmp) = std::env::var_os("TMPDIR") {
            if let Ok(canon) = std::fs::canonicalize(PathBuf::from(tmp)) {
                opts = opts.with_temp_dir(canon);
            }
        }
        Box::new(airlock_broker::SeatbeltEnforcer::new().with_options(opts))
    }
    #[cfg(target_os = "linux")]
    {
        if !airlock_broker::LandlockEnforcer::available() {
            let _ = (workspace, allow_network);
            eprintln!(
                "airlock: 경고 커널이 Landlock을 지원하지 않음(5.13 이상 필요). observe 모드로 내려감"
            );
            return Box::new(ObserveEnforcer);
        }
        let mut opts = ProfileOptions::default()
            .with_workspace(workspace)
            .with_network(allow_network);
        if let Some(tmp) = std::env::var_os("TMPDIR")
            && let Ok(canon) = std::fs::canonicalize(PathBuf::from(tmp))
        {
            opts = opts.with_temp_dir(canon);
        }
        Box::new(airlock_broker::LandlockEnforcer::new().with_options(opts))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (workspace, allow_network);
        eprintln!("airlock: 경고 이 플랫폼의 커널 강제 백엔드가 아직 없음. observe 모드로 내려감");
        Box::new(ObserveEnforcer)
    }
}

fn print_banner(
    policy: &Policy,
    enforcer: &dyn Enforcer,
    approver: &dyn Approver,
    session_dir: &std::path::Path,
) {
    let digest = airlock_audit::Hash::from_bytes(policy.digest());
    let short: String = digest.to_hex().chars().take(12).collect();
    eprintln!("\x1b[1;36mairlock\x1b[0m {}", env!("CARGO_PKG_VERSION"));
    eprintln!(
        "  정책     {} ({} 규칙, 다이제스트 {short})",
        policy.name(),
        policy.rule_count()
    );
    eprintln!("  강제     {}", enforcer.describe());
    eprintln!("  승인     {}", approver.describe());
    eprintln!("  감사     {}", session_dir.display());
    for gap in enforcer.gaps() {
        eprintln!("  \x1b[33m한계\x1b[0m     {gap}");
    }
    eprintln!();
}

fn print_summary(report: &airlock_broker::RunReport) {
    let short: String = report.head_hash.to_hex().chars().take(12).collect();
    eprintln!();
    eprintln!("\x1b[1;36mairlock\x1b[0m 세션 종료");
    eprintln!("  강제     {}", report.enforcement);
    eprintln!("  승인요청 {}", report.asked);
    eprintln!("  차단     {}", report.denied);
    eprintln!("  체인헤드 {short}");
    eprintln!(
        "  검증     airlock audit verify {}",
        report.audit_dir.display()
    );
}
