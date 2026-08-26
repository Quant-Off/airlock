use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use airlock_policy::{LoadContext, Policy};

use crate::custom::{self, CustomAnswers};
use crate::emit;
use crate::error::SetupError;
use crate::presets::{PRESETS, Preset, find};
use crate::theme::{self, AirlockTheme};

#[derive(Debug)]
pub struct SetupOptions {
    pub out: Option<PathBuf>,
    pub cwd: PathBuf,
    pub home: PathBuf,
    pub audit_root: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Written(PathBuf),
    Cancelled,
}

#[derive(Debug)]
enum Plan {
    Preset {
        preset: &'static Preset,
        workspace: String,
    },
    Custom(CustomAnswers),
}

impl Plan {
    fn label(&self) -> &str {
        match self {
            Self::Preset { preset, .. } => preset.label,
            Self::Custom(_) => "직접 설정",
        }
    }

    fn command_hint(&self) -> &str {
        match self {
            Self::Preset { preset, .. } => preset.command_hint,
            Self::Custom(_) => "<에이전트 명령>",
        }
    }

    fn workspace(&self) -> &str {
        match self {
            Self::Preset { workspace, .. } => workspace,
            Self::Custom(answers) => &answers.workspace,
        }
    }

    fn render(&self) -> Result<String, SetupError> {
        match self {
            Self::Preset { preset, workspace } => emit::render(preset.source, Some(workspace)),
            Self::Custom(answers) => Ok(custom::render(answers)),
        }
    }
}

pub fn run(opts: &SetupOptions) -> Result<Outcome, SetupError> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(SetupError::NoTty);
    }
    cliclack::set_theme(AirlockTheme);
    match flow(opts) {
        Err(SetupError::Io(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
            let _ = cliclack::outro_cancel("설정을 중단했습니다");
            Ok(Outcome::Cancelled)
        }
        other => other,
    }
}

fn flow(opts: &SetupOptions) -> Result<Outcome, SetupError> {
    cliclack::intro(theme::title())?;
    cliclack::log::remark("질문 몇 개로 정책 파일(airlock.toml)을 만듭니다")?;

    let plan = ask_plan(opts)?;

    let out = match opts.out.clone() {
        Some(p) => p,
        None => opts.cwd.join("airlock.toml"),
    };
    if out.exists() && !confirm_overwrite(&out)? {
        cliclack::outro_cancel("기존 정책을 보존하고 종료합니다")?;
        return Ok(Outcome::Cancelled);
    }

    let spinner = cliclack::spinner();
    spinner.start("정책을 생성하고 검증하는 중");
    let (rendered, warnings) = match build(&plan, opts) {
        Ok(v) => v,
        Err(e) => {
            spinner.error("정책 생성 실패");
            return Err(e);
        }
    };
    spinner.stop("정책 검증 통과");

    const MAX_WARNINGS: usize = 3;
    for warning in warnings.iter().take(MAX_WARNINGS) {
        cliclack::log::warning(warning)?;
    }
    if warnings.len() > MAX_WARNINGS {
        cliclack::log::remark(format!(
            "비슷한 경고 {}건 생략함. 전체는 airlock policy check로 확인하세요",
            warnings.len() - MAX_WARNINGS
        ))?;
    }

    std::fs::write(&out, &rendered)?;
    cliclack::log::success(format!("{} 작성됨", out.display()))?;

    cliclack::note(
        "설정 요약",
        format!(
            "구성: {}\n정책 파일: {}\n작업 공간: {}",
            plan.label(),
            out.display(),
            plan.workspace()
        ),
    )?;
    cliclack::outro(format!(
        "바로 실행: {}",
        theme::command(&run_hint(&plan, &out, opts))
    ))?;
    Ok(Outcome::Written(out))
}

fn ask_plan(opts: &SetupOptions) -> Result<Plan, SetupError> {
    let mut items: Vec<(&str, &str, &str)> =
        PRESETS.iter().map(|p| (p.id, p.label, p.hint)).collect();
    items.push(("custom", "직접 설정", "프리셋 없이 질문으로 처음부터 구성"));
    let id = cliclack::select("어떤 방식으로 시작할까요?")
        .items(&items)
        .interact()?;
    if id == "custom" {
        return Ok(Plan::Custom(ask_custom(opts)?));
    }
    let preset = find(id).ok_or_else(|| SetupError::UnknownPreset(id.to_string()))?;
    let workspace = ask_workspace(opts)?;
    Ok(Plan::Preset { preset, workspace })
}

fn ask_custom(opts: &SetupOptions) -> Result<CustomAnswers, SetupError> {
    let default_name = default_policy_name(&opts.cwd);
    let name: String = cliclack::input("정책 이름은?")
        .default_input(&default_name)
        .validate(|s: &String| {
            if s.trim().is_empty() {
                Err("이름을 입력하세요")
            } else {
                Ok(())
            }
        })
        .interact()?;

    let file_default = cliclack::select("파일 기본 동작은?")
        .items(&[
            ("deny", "deny", "목록 밖 경로는 차단 (권장)"),
            ("ask", "ask", "목록 밖 경로는 승인 요청"),
            ("allow", "allow", "베이스라인 보호만 남기고 개방"),
        ])
        .interact()?;
    let exec_default = cliclack::select("실행 기본 동작은?")
        .items(&[
            ("ask", "ask", "모르는 명령은 승인 요청 (권장)"),
            (
                "allow",
                "allow",
                "실행 허용. 위험 명령 ask는 베이스라인이 유지",
            ),
            ("deny", "deny", "목록 밖 명령은 차단"),
        ])
        .interact()?;
    let egress_default = cliclack::select("아웃바운드 기본 동작은?")
        .items(&[
            ("deny", "deny", "허용 목록 밖 차단 (권장)"),
            ("ask", "ask", "허용 목록 밖 승인 요청"),
        ])
        .interact()?;

    let workspace = ask_workspace(opts)?;

    let (toolchain_read, build_cache) = if file_default == "allow" {
        (false, false)
    } else {
        let toolchain = cliclack::confirm("시스템 툴체인 읽기·실행을 허용할까요? (/usr, /bin 등)")
            .initial_value(true)
            .interact()?;
        let cache = cliclack::confirm("빌드 캐시 접근을 허용할까요? (~/.cargo, ~/.rustup, ~/.npm)")
            .initial_value(true)
            .interact()?;
        (toolchain, cache)
    };

    let egress_hosts = ask_egress_hosts()?;

    Ok(CustomAnswers {
        name: name.trim().to_string(),
        file_default: file_default.to_string(),
        exec_default: exec_default.to_string(),
        egress_default: egress_default.to_string(),
        workspace,
        toolchain_read,
        build_cache,
        egress_hosts,
    })
}

fn ask_egress_hosts() -> Result<Vec<(String, u16)>, SetupError> {
    let mut hosts: Vec<(String, u16)> = Vec::new();
    loop {
        let prompt = if hosts.is_empty() {
            "허용할 아웃바운드 호스트는? (비우면 건너뜀)"
        } else {
            "호스트를 더 추가할까요? (비우면 완료)"
        };
        let raw: String = cliclack::input(prompt)
            .placeholder("api.example.com 또는 api.example.com:8443")
            .required(false)
            .validate(|s: &String| match parse_host(s) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            })
            .interact()?;
        match parse_host(&raw) {
            Ok(Some(entry)) => {
                if hosts.contains(&entry) {
                    cliclack::log::info(format!("{} 은(는) 이미 추가됨", entry.0))?;
                } else {
                    hosts.push(entry);
                }
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }
    Ok(hosts)
}

fn parse_host(raw: &str) -> Result<Option<(String, u16)>, &'static str> {
    let t = raw.trim();
    if t.is_empty() {
        return Ok(None);
    }
    if t.chars().any(char::is_whitespace) {
        return Err("공백 없이 입력하세요");
    }
    let (host, port) = match t.rsplit_once(':') {
        Some((h, p)) => {
            let port = p.parse::<u16>().map_err(|_| "포트는 1-65535 숫자입니다")?;
            (h, port)
        }
        None => (t, 443),
    };
    if host.is_empty() {
        return Err("호스트가 비어 있습니다");
    }
    Ok(Some((host.to_ascii_lowercase(), port)))
}

fn default_policy_name(cwd: &Path) -> String {
    let name = cwd
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('-').to_string();
    if cleaned.is_empty() {
        "custom".into()
    } else {
        cleaned
    }
}

fn ask_workspace(opts: &SetupOptions) -> Result<String, SetupError> {
    let default = opts.cwd.display().to_string();
    let workspace: String = cliclack::input("쓰기를 허용할 작업 공간 경로는?")
        .default_input(&default)
        .validate(|s: &String| {
            let t = s.trim();
            if t.is_empty() {
                Err("경로를 입력하세요")
            } else if t == "~" || t.starts_with('/') || t.starts_with("~/") {
                Ok(())
            } else {
                Err("절대 경로 또는 ~로 시작하는 경로만 받습니다")
            }
        })
        .interact()?;
    let workspace = workspace.trim().to_string();

    if workspace == "~" || Path::new(&workspace) == opts.home {
        cliclack::log::warning(
            "홈 전체를 작업 공간으로 열면 격리가 무의미해집니다. 프로젝트 디렉토리를 권장합니다",
        )?;
    }
    Ok(workspace)
}

fn confirm_overwrite(out: &Path) -> Result<bool, SetupError> {
    let keep = cliclack::confirm(format!(
        "{} 파일이 이미 있습니다. 덮어쓸까요?",
        out.display()
    ))
    .initial_value(false)
    .interact()?;
    Ok(keep)
}

fn build(plan: &Plan, opts: &SetupOptions) -> Result<(String, Vec<String>), SetupError> {
    let rendered = plan.render()?;
    let ctx = LoadContext::new(opts.home.clone(), opts.audit_root.clone());
    let policy = Policy::load_str(&rendered, &ctx)?;
    let warnings = policy.warnings().iter().map(ToString::to_string).collect();
    Ok((rendered, warnings))
}

fn run_hint(plan: &Plan, out: &Path, opts: &SetupOptions) -> String {
    let mut hint = String::from("airlock run ");
    if opts.out.is_some() {
        hint.push_str(&format!("--policy {} ", out.display()));
    }
    hint.push_str(&format!(
        "--workspace {} -- {}",
        plan.workspace(),
        plan.command_hint()
    ));
    hint
}
