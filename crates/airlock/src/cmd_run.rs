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

    let audit_root = paths::absolutize(
        &args
            .audit_dir
            .clone()
            .or(global_audit_root)
            .unwrap_or_else(paths::audit_root),
        &cwd,
    );
    let session_dir = paths::session_dir(&audit_root);
    // 여는 경로는 해소하지 않습니다. 미리 해소하면 O_NOFOLLOW 검사가 무의미해집니다
    let policy_path = paths::discover_policy(args.policy.as_deref(), &cwd)
        .map(|p| paths::absolutize_lexical(&p, &cwd));

    // 실제로 읽은 파일뿐 아니라 탐색 후보 전체를 자기보호 대상으로 둡니다
    let mut candidates: Vec<PathBuf> = paths::policy_candidates(&cwd)
        .iter()
        .flat_map(|p| paths::protect_forms(p, &cwd))
        .collect();
    if let Some(p) = &policy_path {
        for form in paths::protect_forms(p, &cwd) {
            if !candidates.contains(&form) {
                candidates.push(form);
            }
        }
    }

    // HOME이 없거나 상대 경로면 ~/ 앵커 forbid가 전부 엉뚱한 곳을 가리킵니다. 시크릿
    // 보호가 사라진 채로 도는 것보다 중단이 낫습니다
    let Some(home) = airlock_policy::path::home_dir_checked() else {
        eprintln!("airlock: HOME이 비어 있거나 절대 경로가 아님");
        eprintln!("airlock: ~/ 로 시작하는 시크릿 보호 규칙이 전부 무효가 되므로 실행을 중단함");
        return 78;
    };

    let mut ctx = LoadContext::new(home, &audit_root).with_policy_files(candidates);
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

    let workspace = paths::absolutize(&args.workspace.clone().unwrap_or_else(|| cwd.clone()), &cwd);
    if let Err(why) = check_workspace(&workspace, args.workspace.is_some()) {
        eprintln!("airlock: {why}");
        return 64;
    }

    let mut enforcer: Box<dyn Enforcer> = if args.observe {
        Box::new(ObserveEnforcer)
    } else {
        match build_enforcer(&workspace, !args.no_network) {
            Ok(e) => e,
            Err(why) => {
                eprintln!("airlock: {why}");
                eprintln!(
                    "airlock: 커널 강제 없이는 에이전트를 격리할 수 없으므로 실행을 중단함. \
                     기록만 원하면 --observe를 명시할 것"
                );
                return 70;
            }
        }
    };

    let approver: Box<dyn Approver> = if args.yes {
        eprintln!(
            "airlock: 경고 --yes는 모든 ask를 사람 확인 없이 승인함. 감사 로그에 자동 승인으로 기록됨"
        );
        Box::new(ApproveAll)
    } else if TtyApprover::available() {
        Box::new(TtyApprover::new())
    } else {
        eprintln!("airlock: 경고 /dev/tty가 없어 모든 ask를 거부함");
        Box::new(RefuseAll {
            why: "제어 터미널 없음".to_string(),
        })
    };

    let program = args.command.first().cloned().unwrap_or_default();
    let rest: Vec<String> = args.command.iter().skip(1).cloned().collect();

    let config = SessionConfig {
        audit_dir: session_dir.clone(),
        actor: format!("pid:{} {program}", std::process::id()),
        cwd: cwd.clone(),
        argv: genesis_argv(&args, &workspace),
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

    print_banner(
        &policy,
        enforcer.as_ref(),
        approver.as_ref(),
        &session_dir,
        &workspace,
        mediation,
    );

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
    report.exit_status()
}

/// 제네시스 엔트리에 남길 argv를 실제 호출대로 재구성합니다.
///
/// 결정의 의미를 바꾸는 플래그가 빠지면 사후 조사에서 그 세션이 무엇을 했는지 알 수
/// 없습니다. 특히 `--yes`는 승인 통제를 포기하는 설정인데, ask가 한 번도 없었던 세션은
/// approval 엔트리조차 없어 로그만으로 복원할 방법이 사라집니다
fn genesis_argv(args: &RunArgs, workspace: &std::path::Path) -> Vec<String> {
    let mut argv = vec!["airlock".to_string(), "run".to_string()];
    if let Some(p) = &args.policy {
        argv.push("--policy".to_string());
        argv.push(p.display().to_string());
    }
    if args.observe {
        argv.push("--observe".to_string());
    }
    if let Some(d) = &args.audit_dir {
        argv.push("--audit-dir".to_string());
        argv.push(d.display().to_string());
    }
    // 작업 공간은 기본값이 cwd 이므로 명시 여부와 무관하게 실제 값을 남깁니다.
    // 무엇이 쓰기 가능했는지는 사후 조사의 핵심입니다
    argv.push("--workspace".to_string());
    argv.push(workspace.display().to_string());
    if args.no_network {
        argv.push("--no-network".to_string());
    }
    if args.yes {
        argv.push("--yes".to_string());
    }
    if args.no_fsync {
        argv.push("--no-fsync".to_string());
    }
    argv.push("--mediate".to_string());
    argv.push(args.mediate.clone());
    argv.push("--".to_string());
    argv.extend(args.command.iter().cloned());
    argv
}

/// 작업 공간이 쓰기 허용으로 열려도 되는 범위인지 봅니다.
///
/// 작업 공간은 통째로 읽기 쓰기가 열립니다. 기본값이 cwd 이므로 홈에서 그냥 실행하면
/// 홈 전체가 쓰기 가능해지고, Linux 에서는 순회 예산까지 넘겨 조용히 gap 이 됩니다.
/// 격리를 택한다는 전제가 무너지므로 그 경우는 명시를 요구합니다
///
/// # Errors
/// 파일시스템 루트는 명시해도 거부합니다. 그 아래를 통째로 여는 것은 어떤 정책으로도
/// 정당화되지 않습니다
fn check_workspace(workspace: &std::path::Path, explicit: bool) -> Result<(), String> {
    let canon = |p: &std::path::Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let ws = canon(workspace);

    if ws.parent().is_none() {
        return Err(format!(
            "작업 공간이 파일시스템 루트({})임. 루트를 쓰기 허용으로 열지 않음. \
             --workspace 로 실제 작업 디렉토리를 지정할 것",
            ws.display()
        ));
    }

    let home = canon(&airlock_policy::path::home_dir());
    if ws == home {
        if !explicit {
            return Err(format!(
                "작업 공간이 홈 전체({})가 됨. 작업 공간은 통째로 쓰기 허용이므로 \
                 홈에서 그냥 실행하지 않음. 하위 디렉토리로 옮기거나 --workspace 로 \
                 좁혀서 지정할 것",
                ws.display()
            ));
        }
        eprintln!(
            "airlock: 경고 작업 공간이 홈 전체({})임. 홈 아래 모든 파일이 쓰기 허용됨",
            ws.display()
        );
    }
    Ok(())
}

/// 커널 강제 백엔드를 만듭니다.
///
/// # Errors
/// 이 플랫폼에 백엔드가 없거나 커널이 지원하지 않으면 그 사유를 담아 실패합니다. 호출부는
/// 실행을 중단해야 합니다. 강제를 관측으로 조용히 바꾸는 것은 격리를 포기하는 것이므로
/// 사용자가 `--observe`로 명시할 때만 허용합니다.
fn build_enforcer(
    workspace: &std::path::Path,
    allow_network: bool,
) -> Result<Box<dyn Enforcer>, String> {
    #[cfg(target_os = "macos")]
    {
        let mut opts = ProfileOptions::default()
            .with_workspace(workspace)
            .with_network(allow_network);
        if let Some(tmp) = std::env::var_os("TMPDIR")
            && let Ok(canon) = std::fs::canonicalize(PathBuf::from(tmp))
        {
            opts = opts.with_temp_dir(canon);
        }
        Ok(Box::new(
            airlock_broker::SeatbeltEnforcer::new().with_options(opts),
        ))
    }
    #[cfg(target_os = "linux")]
    {
        if !airlock_broker::LandlockEnforcer::available() {
            let _ = (workspace, allow_network);
            return Err("커널이 Landlock을 지원하지 않음(5.13 이상 필요)".to_string());
        }
        let mut opts = ProfileOptions::default()
            .with_workspace(workspace)
            .with_network(allow_network);
        if let Some(tmp) = std::env::var_os("TMPDIR")
            && let Ok(canon) = std::fs::canonicalize(PathBuf::from(tmp))
        {
            opts = opts.with_temp_dir(canon);
        }
        Ok(Box::new(
            airlock_broker::LandlockEnforcer::new().with_options(opts),
        ))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (workspace, allow_network);
        Err("이 플랫폼의 커널 강제 백엔드가 아직 없음".to_string())
    }
}

fn print_banner(
    policy: &Policy,
    enforcer: &dyn Enforcer,
    approver: &dyn Approver,
    session_dir: &std::path::Path,
    workspace: &std::path::Path,
    mediation: airlock_broker::Mediation,
) {
    let digest = airlock_audit::Hash::from_bytes(policy.digest());
    let short: String = digest.to_hex().chars().take(12).collect();
    let effective = airlock_broker::effective_mediation(mediation);
    eprintln!("\x1b[1;36mairlock\x1b[0m {}", env!("CARGO_PKG_VERSION"));
    eprintln!(
        "  정책     {} ({} 규칙, 다이제스트 {short})",
        policy.name(),
        policy.rule_count()
    );
    eprintln!("  강제     {}", enforcer.describe());
    if effective == mediation {
        eprintln!("  중계     {}", effective.as_str());
    } else {
        // 요청값과 적용값이 다르면 둘을 같이 보여 줍니다. 요청값만 보여 주면
        // 배너가 실제보다 강한 보증을 하는 것이 됩니다
        eprintln!(
            "  중계     {} (요청 {})",
            effective.as_str(),
            mediation.as_str()
        );
    }
    eprintln!("  작업공간 {}", workspace.display());
    eprintln!("  승인     {}", approver.describe());
    eprintln!("  감사     {}", session_dir.display());
    for gap in enforcer
        .gaps()
        .into_iter()
        .chain(airlock_broker::mediation_gaps(mediation))
    {
        eprintln!("  \x1b[33m한계\x1b[0m     {gap}");
    }
    eprintln!();
}

fn print_summary(report: &airlock_broker::RunReport) {
    let short: String = report.head_hash.to_hex().chars().take(12).collect();
    eprintln!();
    eprintln!("\x1b[1;36mairlock\x1b[0m 세션 종료");
    eprintln!("  강제     {}", report.enforcement);
    eprintln!("  중계     {}", report.mediation.as_str());
    if let Some(signal) = report.signal {
        eprintln!("  종료     시그널 {signal}");
    }
    eprintln!("  승인요청 {}", report.asked);
    eprintln!("  차단     {}", report.denied);
    eprintln!("  체인헤드 {short}");
    eprintln!(
        "  검증     airlock audit verify {}",
        report.audit_dir.display()
    );
}
