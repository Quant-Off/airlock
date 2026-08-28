use std::path::PathBuf;

use airlock_broker::{
    ApproveAll, Approver, Enforcer, ObserveEnforcer, ProfileOptions, RefuseAll, SessionConfig,
    TtyApprover,
};
use airlock_policy::{LoadContext, LoadWarning, Policy};

use crate::paths;

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    #[arg(long, value_name = "FILE", help = "정책 파일 경로")]
    pub policy: Option<PathBuf>,

    #[arg(long, help = "강제 없이 기록만 함 (학습 모드)")]
    pub observe: bool,

    #[arg(long, value_name = "DIR", help = "감사 로그 루트")]
    pub audit_dir: Option<PathBuf>,

    #[arg(
        long,
        value_name = "DIR",
        help = "세션 상위 앵커(anchors.jsonl)를 둘 디렉토리. 생략하면 감사 루트. \
                같은 트리에 두면 체인을 재계산할 수 있는 주체가 앵커도 같은 비용으로 \
                재계산하므로, 실질 탐지력은 다른 볼륨이나 원격 append-only 마운트로 \
                분리했을 때만 생김"
    )]
    pub anchor_dir: Option<PathBuf>,

    #[arg(long, value_name = "DIR", help = "쓰기 허용 작업 공간. 기본값은 cwd")]
    pub workspace: Option<PathBuf>,

    #[arg(long, help = "아웃바운드 네트워크를 통째로 차단함")]
    pub no_network: bool,

    #[arg(
        long,
        help = "아웃바운드를 로컬 egress 프록시로 강제 경유시켜 호스트 단위 정책을 강제함. \
                프록시 설정을 무시하는 도구는 연결에 실패함"
    )]
    pub egress_proxy: bool,

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

    let proxy_planned = args.egress_proxy && !args.no_network;
    for w in policy.warnings() {
        // 프록시가 붙으면 호스트도 프로토콜도 실제로 판정됩니다. 그때까지 경고를
        // 그대로 내면 해결된 경고가 매 실행마다 쌓여 진짜 경고를 덮습니다
        if proxy_planned
            && matches!(
                w,
                LoadWarning::HostRuleNeedsProxy { .. }
                    | LoadWarning::ProtocolRuleNeedsProxy { .. }
                    | LoadWarning::QuotaRuleNeedsProxy { .. }
            )
        {
            continue;
        }
        eprintln!("airlock: 경고 {w}");
    }

    let workspace = paths::absolutize(&args.workspace.clone().unwrap_or_else(|| cwd.clone()), &cwd);
    if let Err(why) = check_workspace(&workspace, args.workspace.is_some()) {
        eprintln!("airlock: {why}");
        return 64;
    }

    // 프로파일이 프록시 포트를 알아야 아웃바운드를 그 하나로 좁힐 수 있으므로
    // 강제 층을 세우기 전에 먼저 바인드합니다
    let proxy = if proxy_planned {
        match airlock_proxy::ProxyServer::bind() {
            Ok(server) => Some(server),
            Err(e) => {
                eprintln!("airlock: egress 프록시를 띄우지 못함: {e}");
                eprintln!(
                    "airlock: 프록시 없이 계속하면 호스트 정책이 강제되지 않으므로 실행을 중단함"
                );
                return 70;
            }
        }
    } else {
        if args.egress_proxy && args.no_network {
            eprintln!("airlock: --no-network가 있으므로 --egress-proxy는 무시됨");
        }
        None
    };

    let mut enforcer: Box<dyn Enforcer> = if args.observe {
        Box::new(ObserveEnforcer)
    } else {
        match build_enforcer(
            &workspace,
            !args.no_network,
            proxy.as_ref().map(|p| p.addr()),
        ) {
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
        anchor_dir: args.anchor_dir.as_ref().map(|d| paths::absolutize(d, &cwd)),
    };

    // 배너가 강제 층의 한계를 그대로 보여주려면 정책에서 유도되는 gap이
    // 출력 전에 채워져 있어야 합니다. prepare는 결정적이라 run 안에서 다시 불려도 안전합니다.
    // 최상위 프로그램도 먼저 알려 줍니다. 그것이 빠지면 exec 화이트리스트 모드에서
    // 배너의 규칙 수와 gap이 실제로 걸릴 프로파일과 한 박자 어긋납니다
    if let Some(resolved) = airlock_broker::which(&program) {
        enforcer.set_program(&resolved);
    }
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
        proxy.as_ref().map(|p| p.addr()),
        config.anchor_dir.as_deref(),
    );

    let report = match airlock_broker::run(
        &program,
        &rest,
        policy,
        std::mem::replace(&mut enforcer, Box::new(ObserveEnforcer)),
        approver,
        &config,
        proxy,
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
    // 앵커를 어디에 두었는지가 그 세션의 탐지력을 결정합니다. 같은 트리에 두었는지
    // 다른 볼륨으로 분리했는지는 사후에 로그만 보고 알 수 있어야 합니다
    if let Some(d) = &args.anchor_dir {
        argv.push("--anchor-dir".to_string());
        argv.push(d.display().to_string());
    }
    // 작업 공간은 기본값이 cwd 이므로 명시 여부와 무관하게 실제 값을 남깁니다.
    // 무엇이 쓰기 가능했는지는 사후 조사의 핵심입니다
    argv.push("--workspace".to_string());
    argv.push(workspace.display().to_string());
    if args.no_network {
        argv.push("--no-network".to_string());
    }
    // 이 플래그가 있었는지에 따라 호스트 규칙이 실제 경계였는지 의도 선언이었는지가
    // 갈립니다. 같은 정책 다이제스트로도 결론이 달라지므로 반드시 남깁니다
    if args.egress_proxy {
        argv.push("--egress-proxy".to_string());
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
    proxy: Option<std::net::SocketAddr>,
) -> Result<Box<dyn Enforcer>, String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn options(
        workspace: &std::path::Path,
        allow_network: bool,
        proxy: Option<std::net::SocketAddr>,
    ) -> ProfileOptions {
        let mut opts = ProfileOptions::default()
            .with_workspace(workspace)
            .with_network(allow_network);
        if let Some(addr) = proxy {
            opts = opts.with_proxy(addr);
        }
        if let Some(tmp) = std::env::var_os("TMPDIR")
            && let Ok(canon) = std::fs::canonicalize(PathBuf::from(tmp))
        {
            opts = opts.with_temp_dir(canon);
        }
        opts
    }

    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(
            airlock_broker::SeatbeltEnforcer::new().with_options(options(
                workspace,
                allow_network,
                proxy,
            )),
        ))
    }
    #[cfg(target_os = "linux")]
    {
        if !airlock_broker::LandlockEnforcer::available() {
            let _ = (workspace, allow_network, proxy);
            return Err("커널이 Landlock을 지원하지 않음(5.13 이상 필요)".to_string());
        }
        Ok(Box::new(
            airlock_broker::LandlockEnforcer::new().with_options(options(
                workspace,
                allow_network,
                proxy,
            )),
        ))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (workspace, allow_network, proxy);
        Err("이 플랫폼의 커널 강제 백엔드가 아직 없음".to_string())
    }
}

/// 관측 층이 프로토콜을 모른 채 도는 세션의 한계.
///
/// 중계 층은 `connect(2)`만 보므로 모든 연결을 `tcp`로 보고합니다
/// (`docs/limitations.md` 5.12). 곧 프록시가 없으면 `protocol` 조건 규칙이 아무것도
/// 매칭하지 않고 `[defaults].egress_plaintext` 바닥도 발동하지 않습니다. 정책이 평문을
/// 막는다는 보증은 프록시 층 위에서만 성립하므로, 그 사실을 배너가 직접 말해야 합니다.
///
/// # Arguments
/// `policy` - 이 세션의 정책
/// `proxy` - egress 프록시 주소. 없으면 프록시가 꺼진 세션
fn egress_observation_gaps(policy: &Policy, proxy: Option<std::net::SocketAddr>) -> Vec<String> {
    if proxy.is_some() {
        return Vec::new();
    }
    let mut gaps = vec![
        "중계 층은 connect(2)만 보므로 모든 연결을 protocol=tcp로 보고함. \
         프록시 없이는 protocol 조건 규칙이 아무것도 매칭하지 않음"
            .to_string(),
    ];
    let floor = policy.defaults().egress_plaintext;
    if floor.blocks() {
        gaps.push(format!(
            "[defaults].egress_plaintext = \"{floor}\" 가 이 세션에서는 한 번도 발동하지 않음. \
             평문 판정은 --egress-proxy 위에서만 성립하므로 지금은 평문 차단이 강제되지 않음"
        ));
    }
    let protocol_rules: Vec<&str> = policy
        .user_rules()
        .iter()
        .filter(|r| {
            matches!(
                &r.matcher,
                airlock_policy::Matcher::Egress {
                    protocol: Some(_),
                    ..
                }
            )
        })
        .map(|r| r.id.as_str())
        .collect();
    if !protocol_rules.is_empty() {
        gaps.push(format!(
            "protocol을 지정한 egress 규칙 {}개가 이 세션에서 죽어 있음: {}",
            protocol_rules.len(),
            protocol_rules.join(", ")
        ));
    }
    gaps
}

#[allow(clippy::too_many_arguments)]
fn print_banner(
    policy: &Policy,
    enforcer: &dyn Enforcer,
    approver: &dyn Approver,
    session_dir: &std::path::Path,
    workspace: &std::path::Path,
    mediation: airlock_broker::Mediation,
    proxy: Option<std::net::SocketAddr>,
    anchor_dir: Option<&std::path::Path>,
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
    match proxy {
        Some(addr) => eprintln!("  아웃바운드 {addr} 경유. 호스트 정책이 강제됨"),
        None => eprintln!("  아웃바운드 프록시 없음. 호스트 규칙은 의도 선언에 그침"),
    }
    eprintln!("  승인     {}", approver.describe());
    eprintln!("  감사     {}", session_dir.display());
    let anchors = airlock_broker::anchor_dir_for(session_dir, anchor_dir);
    if anchor_dir.is_some() {
        eprintln!("  앵커     {}", anchors.display());
    } else {
        // 같은 트리에 두면 체인을 다시 계산할 수 있는 주체가 앵커도 같은 비용으로 다시
        // 계산합니다. 분리하지 않았다는 사실을 배너가 감추면 없는 보증을 믿게 됩니다
        eprintln!(
            "  앵커     {} (감사 루트와 같은 트리. 재계산 탐지력 없음, --anchor-dir로 분리할 것)",
            anchors.display()
        );
    }
    for gap in enforcer
        .gaps()
        .into_iter()
        .chain(airlock_broker::mediation_gaps(mediation))
        .chain(egress_observation_gaps(policy, proxy))
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
    match report.anchor.failure() {
        None => eprintln!("  앵커     {}", report.anchor.path().display()),
        // 앵커 없는 세션은 감사 보증이 약해진 세션입니다. 자식은 이미 끝났으므로 종료
        // 코드를 덮지는 않지만, 조용히 넘기면 사용자가 그 사실을 영영 모릅니다
        Some(why) => {
            eprintln!(
                "  \x1b[1;31m앵커 실패\x1b[0m {} : {why}",
                report.anchor.path().display()
            );
            eprintln!(
                "  \x1b[1;31m경고\x1b[0m     이 세션은 상위 앵커에 남지 않았음. \
                 세션 통째 삭제와 체인 재계산을 탐지할 수 없음"
            );
        }
    }
    eprintln!(
        "  검증     airlock audit verify {}",
        report.audit_dir.display()
    );
}
