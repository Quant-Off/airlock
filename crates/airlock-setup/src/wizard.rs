use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use airlock_i18n::{Locale, tr};
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
            Self::Custom(_) => tr!("직접 설정", "custom"),
        }
    }

    fn command_hint(&self) -> &str {
        match self {
            Self::Preset { preset, .. } => preset.command_hint(airlock_i18n::locale()),
            Self::Custom(_) => tr!("<에이전트 명령>", "<agent command>"),
        }
    }

    fn workspace(&self) -> &str {
        match self {
            Self::Preset { workspace, .. } => workspace,
            Self::Custom(answers) => &answers.workspace,
        }
    }

    fn render(&self) -> Result<String, SetupError> {
        let locale = airlock_i18n::locale();
        match self {
            Self::Preset { preset, workspace } => {
                emit::render(preset.source(locale), Some(workspace))
            }
            Self::Custom(answers) => Ok(custom::render(answers, locale)),
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
            let _ = cliclack::outro_cancel(tr!("설정을 중단했습니다", "setup cancelled"));
            Ok(Outcome::Cancelled)
        }
        other => other,
    }
}

fn flow(opts: &SetupOptions) -> Result<Outcome, SetupError> {
    cliclack::intro(theme::title())?;

    ask_locale()?;

    cliclack::log::remark(tr!(
        "질문 몇 개로 정책 파일(airlock.toml)을 만듭니다",
        "a few questions will produce a policy file (airlock.toml)"
    ))?;

    let plan = ask_plan(opts)?;

    let out = match opts.out.clone() {
        Some(p) => p,
        None => opts.cwd.join("airlock.toml"),
    };
    if out.exists() && !confirm_overwrite(&out)? {
        cliclack::outro_cancel(tr!(
            "기존 정책을 보존하고 종료합니다",
            "keeping the existing policy and exiting"
        ))?;
        return Ok(Outcome::Cancelled);
    }

    let spinner = cliclack::spinner();
    spinner.start(tr!(
        "정책을 생성하고 검증하는 중",
        "generating and validating the policy"
    ));
    let (rendered, warnings) = match build(&plan, opts) {
        Ok(v) => v,
        Err(e) => {
            spinner.error(tr!("정책 생성 실패", "policy generation failed"));
            return Err(e);
        }
    };
    spinner.stop(tr!("정책 검증 통과", "policy validated"));

    const MAX_WARNINGS: usize = 3;
    for warning in warnings.iter().take(MAX_WARNINGS) {
        cliclack::log::warning(warning)?;
    }
    if warnings.len() > MAX_WARNINGS {
        cliclack::log::remark(tr!(
            format!(
                "비슷한 경고 {}건 생략함. 전체는 airlock policy check로 확인하세요",
                warnings.len() - MAX_WARNINGS
            ),
            format!(
                "{} similar warning(s) omitted; see them all with airlock policy check",
                warnings.len() - MAX_WARNINGS
            )
        ))?;
    }

    std::fs::write(&out, &rendered)?;
    cliclack::log::success(tr!(
        format!("{} 작성됨", out.display()),
        format!("wrote {}", out.display())
    ))?;

    cliclack::note(
        tr!("설정 요약", "setup summary"),
        tr!(
            format!(
                "구성: {}\n정책 파일: {}\n작업 공간: {}",
                plan.label(),
                out.display(),
                plan.workspace()
            ),
            format!(
                "profile: {}\npolicy file: {}\nworkspace: {}",
                plan.label(),
                out.display(),
                plan.workspace()
            )
        ),
    )?;
    cliclack::outro(tr!(
        format!(
            "바로 실행: {}",
            theme::command(&run_hint(&plan, &out, opts))
        ),
        format!(
            "run it now: {}",
            theme::command(&run_hint(&plan, &out, opts))
        )
    ))?;
    Ok(Outcome::Written(out))
}

/// 출력 언어를 묻고 즉시 적용한 뒤 전역 구성 파일에 남깁니다.
///
/// 첫 질문이어야 나머지 질문이 고른 언어로 나갑니다. 저장 실패는 마법사를 멈출 일이
/// 아니므로 경고로만 남깁니다
fn ask_locale() -> Result<Locale, SetupError> {
    let current = airlock_i18n::locale();
    let picked = cliclack::select("Language · 언어")
        .items(&[("ko", "한국어", ""), ("en", "English", "")])
        .initial_value(current.as_str())
        .interact()?;
    let locale = Locale::parse(picked).unwrap_or_default();
    airlock_i18n::set_locale(locale);

    if locale != current || airlock_i18n::config_path().is_none_or(|p| !p.exists()) {
        match airlock_i18n::save_locale(locale) {
            Ok(path) => cliclack::log::remark(tr!(
                format!("출력 언어를 {} 에 저장했습니다", path.display()),
                format!("saved the output language to {}", path.display())
            ))?,
            Err(e) => cliclack::log::warning(tr!(
                format!("언어 설정을 저장하지 못함: {e}"),
                format!("could not save the language preference: {e}")
            ))?,
        }
    }
    Ok(locale)
}

fn ask_plan(opts: &SetupOptions) -> Result<Plan, SetupError> {
    let locale = airlock_i18n::locale();
    let mut items: Vec<(&str, &str, &str)> = PRESETS
        .iter()
        .map(|p| (p.id, p.label, p.hint(locale)))
        .collect();
    items.push((
        "custom",
        tr!("직접 설정", "Custom"),
        tr!(
            "프리셋 없이 질문으로 처음부터 구성",
            "build from scratch through questions, without a preset"
        ),
    ));
    let id = cliclack::select(tr!(
        "어떤 방식으로 시작할까요?",
        "how would you like to start?"
    ))
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
    let name: String = cliclack::input(tr!("정책 이름은?", "policy name?"))
        .default_input(&default_name)
        .validate(|s: &String| {
            if s.trim().is_empty() {
                Err(tr!("이름을 입력하세요", "enter a name"))
            } else {
                Ok(())
            }
        })
        .interact()?;

    let file_default = cliclack::select(tr!("파일 기본 동작은?", "default action for files?"))
        .items(&[
            (
                "deny",
                "deny",
                tr!(
                    "목록 밖 경로는 차단 (권장)",
                    "block unlisted paths (recommended)"
                ),
            ),
            (
                "ask",
                "ask",
                tr!(
                    "목록 밖 경로는 승인 요청",
                    "ask approval for unlisted paths"
                ),
            ),
            (
                "allow",
                "allow",
                tr!(
                    "베이스라인 보호만 남기고 개방",
                    "open up, keeping only baseline protections"
                ),
            ),
        ])
        .interact()?;
    let exec_default = cliclack::select(tr!("실행 기본 동작은?", "default action for exec?"))
        .items(&[
            (
                "ask",
                "ask",
                tr!(
                    "모르는 명령은 승인 요청 (권장)",
                    "ask approval for unknown commands (recommended)"
                ),
            ),
            (
                "allow",
                "allow",
                tr!(
                    "실행 허용. 위험 명령 ask는 베이스라인이 유지",
                    "allow exec; the baseline still asks on dangerous commands"
                ),
            ),
            (
                "deny",
                "deny",
                tr!("목록 밖 명령은 차단", "block unlisted commands"),
            ),
        ])
        .interact()?;
    let egress_default = cliclack::select(tr!(
        "아웃바운드 기본 동작은?",
        "default action for outbound connections?"
    ))
    .items(&[
        (
            "deny",
            "deny",
            tr!(
                "허용 목록 밖 차단 (권장)",
                "block outside the allowlist (recommended)"
            ),
        ),
        (
            "ask",
            "ask",
            tr!(
                "허용 목록 밖 승인 요청",
                "ask approval outside the allowlist"
            ),
        ),
    ])
    .interact()?;

    let workspace = ask_workspace(opts)?;

    let (toolchain_read, build_cache) = if file_default == "allow" {
        (false, false)
    } else {
        let toolchain = cliclack::confirm(tr!(
            "시스템 툴체인 읽기·실행을 허용할까요? (/usr, /bin 등)",
            "allow reading and executing the system toolchain? (/usr, /bin, ...)"
        ))
        .initial_value(true)
        .interact()?;
        let cache = cliclack::confirm(tr!(
            "빌드 캐시 접근을 허용할까요? (~/.cargo, ~/.rustup, ~/.npm)",
            "allow access to build caches? (~/.cargo, ~/.rustup, ~/.npm)"
        ))
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
            tr!(
                "허용할 아웃바운드 호스트는? (비우면 건너뜀)",
                "outbound hosts to allow? (leave empty to skip)"
            )
        } else {
            tr!(
                "호스트를 더 추가할까요? (비우면 완료)",
                "add another host? (leave empty to finish)"
            )
        };
        let raw: String = cliclack::input(prompt)
            .placeholder(tr!(
                "api.example.com 또는 api.example.com:8443",
                "api.example.com or api.example.com:8443"
            ))
            .required(false)
            .validate(|s: &String| match parse_host(s) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            })
            .interact()?;
        match parse_host(&raw) {
            Ok(Some(entry)) => {
                if hosts.contains(&entry) {
                    cliclack::log::info(tr!(
                        format!("{} 은(는) 이미 추가됨", entry.0),
                        format!("{} is already added", entry.0)
                    ))?;
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
        return Err(tr!("공백 없이 입력하세요", "enter it without whitespace"));
    }
    let (host, port) = match t.rsplit_once(':') {
        Some((h, p)) => {
            let port = p.parse::<u16>().map_err(|_| {
                tr!(
                    "포트는 1-65535 숫자입니다",
                    "the port must be a number between 1 and 65535"
                )
            })?;
            (h, port)
        }
        None => (t, 443),
    };
    if host.is_empty() {
        return Err(tr!("호스트가 비어 있습니다", "the host is empty"));
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
    let workspace: String = cliclack::input(tr!(
        "쓰기를 허용할 작업 공간 경로는?",
        "workspace path to allow writing in?"
    ))
    .default_input(&default)
    .validate(|s: &String| {
        let t = s.trim();
        if t.is_empty() {
            Err(tr!("경로를 입력하세요", "enter a path"))
        } else if t == "~" || t.starts_with('/') || t.starts_with("~/") {
            Ok(())
        } else {
            Err(tr!(
                "절대 경로 또는 ~로 시작하는 경로만 받습니다",
                "only absolute paths or paths starting with ~ are accepted"
            ))
        }
    })
    .interact()?;
    let workspace = workspace.trim().to_string();

    if workspace == "~" || Path::new(&workspace) == opts.home {
        cliclack::log::warning(tr!(
            "홈 전체를 작업 공간으로 열면 격리가 무의미해집니다. 프로젝트 디렉토리를 권장합니다",
            "opening your entire home as the workspace defeats isolation; a project \
             directory is recommended"
        ))?;
    }
    Ok(workspace)
}

fn confirm_overwrite(out: &Path) -> Result<bool, SetupError> {
    let keep = cliclack::confirm(tr!(
        format!("{} 파일이 이미 있습니다. 덮어쓸까요?", out.display()),
        format!("{} already exists. Overwrite it?", out.display())
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
