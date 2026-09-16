#![cfg(target_os = "linux")]

//! 이 모듈은 Linux Landlock LSM으로 파일과 TCP 포트 접근을 커널에서 강제합니다.
//!
//! # Features
//! Landlock은 allow만 표현할 수 있고 규칙이 inode에 걸립니다. 곧 `deny` 규칙을
//! 그대로 옮길 수 없고, 허용한 하위 트리 안에 있는 시크릿을 나중에 빼낼 방법이 없습니다.
//! 그래서 정책을 규칙으로 번역하는 대신 허용할 트리를 실제로 걸어 내려가며
//! 거부 결정이 나는 항목을 granting 대상에서 빼는 방식으로 계획을 세웁니다.
//! 하위에 거부 대상이 하나도 없는 디렉토리는 통째로 한 규칙으로 허용해 규칙 수를
//! 시크릿 경로의 깊이에 비례하게 유지합니다.
//!
//! 경로가 아니라 inode에 걸리므로 `docs/policy-dsl.md` 4.2절의 TOCTOU를 겪지 않습니다.
//!
//! `AccessFs::from_read` 는 `Execute` 를 포함합니다. 곧 읽기 권한을 그대로 주면 읽을 수
//! 있는 모든 파일이 실행 가능해집니다. `[defaults].exec` 가 `allow` 가 아니면 `Execute`
//! 를 읽기에서 떼어 내 허용 목록에만 부여하고, 그러면 커널이 강제하는 exec 화이트리스트가
//! 성립합니다. `allow` 인 정책은 이전 동작을 그대로 둡니다

use std::collections::BTreeSet;
use std::ffi::{CString, OsStr};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use airlock_audit::Enforcement;
use airlock_i18n::tr;
use airlock_policy::glob::Pattern;
use airlock_policy::rule::{Matcher, ProgramMatch};
use airlock_policy::{Action, FileMode, Policy};
use landlock::{
    ABI, Access, AccessFs, AccessNet, NetPort, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, Scope,
};

use crate::enforcer::Enforcer;
use crate::error::{BrokerError, Result};
use crate::notify::TtyGuard;
use crate::profile::{self, ProfileOptions};

/// 루트 하나를 걸어 내려가며 검사할 최대 디렉토리 항목 수.
///
/// 예산을 넘기면 남은 하위 트리를 허용하지 않고 gap으로 보고합니다. 넘겨서 통째로
/// 허용하면 그 안의 시크릿이 열리므로 제한 방향으로 실패시킵니다.
///
/// 예산은 **루트마다** 새로 줍니다. 하나로 공유하면 앞선 루트의 거대한 하위 트리가
/// 예산을 다 써서 그 뒤의 모든 루트가 규칙 없이 남습니다. `/usr` 아래에 큰 SDK 가
/// 깔린 머신에서 `/etc` 와 `/sbin` 이 통째로 빠져 프로그램이 뜨지 못하는 것이
/// 그 경우입니다
const WALK_BUDGET: usize = 200_000;

const SYSTEM_READ_PATHS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/opt",
    "/etc",
    "/proc/self",
];

/// exec 화이트리스트 모드에서 실행 권한을 함께 여는 런타임 루트.
///
/// 동적 링커(`ld-linux-*.so`, `ld-musl-*.so`)는 `execve` 대상 바이너리와 마찬가지로
/// `open_exec()` 로 열립니다. 그 경로는 `__FMODE_EXEC` 를 세우므로 커널의 `file_open`
/// 훅이 `LANDLOCK_ACCESS_FS_EXECUTE` 를 요구합니다. 곧 링커에 실행 권한이 없으면
/// 동적 링크된 프로그램은 하나도 뜨지 못합니다.
///
/// 여기서 링커를 실제로 실행해 확인할 수단이 없으므로 추측으로 좁히지 않고 링커가 사는
/// 루트를 통째로 엽니다. 그만큼 화이트리스트가 넓어지며 그 사실은 gap 으로 냅니다.
/// PT_INTERP 를 읽어 링커 하나로 좁히는 것은 Linux 에서 실제 실행 검증이 가능해진
/// 뒤에 할 일입니다
const EXEC_RUNTIME_PATHS: &[&str] = &["/lib", "/lib64", "/usr/lib", "/usr/lib64"];

/// 자식에게 열어 주는 장치 노드.
///
/// `/dev/tty`는 일부러 뺐습니다. 그것은 제어 터미널이며 승인 프롬프트가 나가는 통로입니다.
/// 자식이 열 수 있으면 가짜 승인 화면을 그리거나 사용자가 입력한 답을 먼저 읽어 갈 수 있어
/// `ask`가 무의미해집니다
const DEV_RW_PATHS: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
];

/// 읽기 권한. `Execute` 를 뺍니다.
///
/// `AccessFs::from_read` 는 `Execute | ReadFile | ReadDir` 입니다. 그대로 주면 읽을 수
/// 있는 모든 파일이 실행 가능해져 exec 정책이 커널에서 아무 의미도 갖지 못합니다
fn read_access(abi: ABI) -> landlock::BitFlags<AccessFs> {
    AccessFs::from_read(abi) & !AccessFs::Execute
}

/// 실행 권한만.
fn exec_access(abi: ABI) -> landlock::BitFlags<AccessFs> {
    if abi == ABI::Unsupported {
        return landlock::BitFlags::EMPTY;
    }
    AccessFs::Execute.into()
}

/// 읽기 쓰기 권한. `from_all` 도 `Execute` 를 포함하므로 함께 뺍니다.
///
/// 이것을 빼지 않으면 에이전트가 작업 공간에 써 넣은 바이너리가 그대로 실행됩니다
fn full_access(abi: ABI) -> landlock::BitFlags<AccessFs> {
    AccessFs::from_all(abi) & !AccessFs::Execute
}

/// 상위 디렉토리를 나열만 할 수 있게 하는 권한.
///
/// 하위에 시크릿이 있는 디렉토리에 줍니다. 이름은 보이지만 내용은 열 수 없으며,
/// 이는 Seatbelt 프로파일이 `file-read-metadata`를 여는 것과 같은 수준입니다
fn list_access() -> landlock::BitFlags<AccessFs> {
    AccessFs::ReadDir.into()
}

/// 규칙 하나가 걸릴 경로.
///
/// `follow`는 이 경로의 마지막 성분이 심볼릭 링크일 때 대상을 따라가도 되는지입니다.
/// 설정으로 들어온 루트는 따라가야 합니다. `/lib`가 `/usr/lib` 링크인 배포판이 많고
/// `/proc/self`는 자식에서 해소되어야 자기 pid를 가리키기 때문입니다. 반대로 순회 중
/// 발견한 항목은 절대 따라가지 않습니다. 계획을 세운 시점과 규칙을 거는 시점 사이에
/// 항목이 링크로 바뀌면 링크 대상 inode에 규칙이 걸리기 때문입니다
#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanPath {
    path: PathBuf,
    follow: bool,
    /// 이 경로가 디렉토리인지.
    ///
    /// 디렉토리 전용 권한(`ReadDir` 등)을 일반 파일에 걸면 커널이 EINVAL 을 돌려주고
    /// 크레이트는 그것을 호환성 강등으로 처리해 ruleset 을 `PartiallyEnforced` 로
    /// 만듭니다. 그러면 커널이 기능을 실제로 못 거는 경우와 구분되지 않아 부분 강제
    /// 경고가 늘 켜져 있게 되므로, 대상 종류에 맞는 권한만 겁니다
    dir: bool,
}

impl PlanPath {
    /// 설정에서 온 루트. 링크 해소를 허용합니다
    fn root(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let dir = path.is_dir();
        Self {
            path,
            follow: true,
            dir,
        }
    }

    /// 순회 중 발견한 항목. 링크 해소를 금지합니다
    fn child(path: impl Into<PathBuf>, dir: bool) -> Self {
        Self {
            path: path.into(),
            follow: false,
            dir,
        }
    }
}

/// 이 대상에 실제로 걸 권한.
///
/// 디렉토리가 아니면 디렉토리 전용 비트를 뺍니다
fn rule_access(
    target: &PlanPath,
    access: landlock::BitFlags<AccessFs>,
    abi: ABI,
) -> landlock::BitFlags<AccessFs> {
    if target.dir {
        access
    } else {
        access & AccessFs::from_file(abi)
    }
}

#[derive(Debug, Clone, Default)]
struct Plan {
    read_only: Vec<PlanPath>,
    read_write: Vec<PlanPath>,
    list_only: Vec<PlanPath>,
    /// 실행 권한을 줄 경로
    exec_paths: Vec<PlanPath>,
    /// exec 을 화이트리스트로 걸었는지.
    ///
    /// 거짓이면 `[defaults].exec = "allow"` 인 정책이므로 읽기 권한에 `Execute` 를 함께
    /// 실어 이전 동작을 유지합니다
    exec_whitelist: bool,
    tcp_connect: BTreeSet<u16>,
    unrestricted_net: bool,
    gaps: Vec<String>,
}

/// 지금 무엇을 위한 계획을 세우고 있는지.
///
/// 순회는 같은 코드를 쓰지만 평가할 모드와 결과를 쌓을 곳이 다릅니다. 실행 계획에서
/// 읽기 모드를 검사하면 읽기만 막힌 파일까지 실행 목록에서 빠지고, 반대로 읽기 계획에서
/// 실행 모드를 검사하면 실행만 막힌 파일이 읽히지도 않습니다
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlanKind {
    Read,
    Write,
    Exec,
}

impl PlanKind {
    fn modes(self) -> &'static [FileMode] {
        match self {
            Self::Read => &[FileMode::Read],
            Self::Write => &[FileMode::Read, FileMode::Write],
            Self::Exec => &[FileMode::Exec],
        }
    }

    fn push(self, plan: &mut Plan, target: PlanPath) {
        match self {
            Self::Read => plan.read_only.push(target),
            Self::Write => plan.read_write.push(target),
            Self::Exec => plan.exec_paths.push(target),
        }
    }

    /// 통째로 줄 수 없는 상위 디렉토리에 나열 권한을 줄지.
    ///
    /// 실행 계획은 주지 않습니다. `ReadDir` 는 읽기 권한이라 실행 계획이 읽기 경계를
    /// 넓히게 되고, Landlock 은 경로 통과에 어떤 권한도 요구하지 않으므로 실행에는
    /// 상위 권한이 필요하지도 않습니다
    fn lists_parents(self) -> bool {
        self != Self::Exec
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grant {
    /// 하위 전체가 허용 가능합니다. 부모가 통째로 한 규칙으로 덮습니다
    Whole,
    /// 하위 어딘가에 거부 대상이 있어 이 디렉토리는 통째로 줄 수 없습니다
    Partial,
    /// 이 항목 자체가 거부 대상입니다
    Denied,
}

/// 순회 중 정책 평가를 건너뛰어도 되는 항목을 값싸게 걸러 내는 사전 필터.
///
/// 큰 작업 공간에서는 항목마다 전체 규칙을 glob 매칭하는 비용이 시작 시간을 지배합니다.
/// 필터는 **보수적**입니다. 매칭 가능성이 조금이라도 있으면 통과시켜 실제 평가로 넘기므로
/// 결정이 달라지지 않고, 확실히 무관한 항목만 걸러 냅니다.
///
/// 비교는 전부 ASCII 소문자로 내려서 합니다. 제한 규칙은 엔진에서 대소문자를 무시하고
/// 매칭되므로(`Rule::case_insensitive`), 필터가 대소문자를 구분하면 대소문자 무구분
/// 마운트에서 `.SSH` 같은 표기가 걸러져 나가 결정이 뒤집힙니다
#[derive(Debug, Default)]
struct Prefilter {
    /// 구체 경로로 고정된 규칙의 접두. 소문자 바이트열
    anchors: Vec<Vec<u8>>,
    /// `**`로 시작해 어디서든 매칭될 수 있는 규칙의 마지막 세그먼트 리터럴 접두. 소문자
    anywhere: Vec<Vec<u8>>,
    /// 필터가 판단할 수 없는 모양이 있어 전부 평가해야 합니다
    always: bool,
}

impl Prefilter {
    fn build(policy: &Policy) -> Self {
        use airlock_policy::glob::SegmentKind;
        let mut out = Self::default();

        let tiers: [&[airlock_policy::Rule]; 3] = [
            policy.self_protect_rules(),
            policy.user_rules(),
            policy.baseline_rules(),
        ];
        for tier in tiers {
            for rule in tier {
                let Matcher::File { paths, .. } = &rule.matcher else {
                    continue;
                };
                for pattern in paths {
                    let segs = pattern.segments();
                    match segs.first() {
                        Some(SegmentKind::AnyDepth) => match segs.last() {
                            Some(SegmentKind::Literal(b)) => {
                                out.anywhere.push(b.to_ascii_lowercase());
                            }
                            Some(SegmentKind::Wildcard(w)) => {
                                // `*` 앞의 리터럴 접두까지만 봅니다. 접두가 비면
                                // 무엇이든 매칭될 수 있으므로 전부 평가합니다
                                let lit: Vec<u8> = w
                                    .iter()
                                    .take_while(|b| **b != b'*' && **b != b'?')
                                    .copied()
                                    .collect();
                                if lit.is_empty() {
                                    out.always = true;
                                } else {
                                    out.anywhere.push(lit.to_ascii_lowercase());
                                }
                            }
                            _ => out.always = true,
                        },
                        Some(SegmentKind::Literal(_)) => {
                            let mut anchor = PathBuf::from("/");
                            for seg in &segs {
                                match seg {
                                    SegmentKind::Literal(b) => {
                                        anchor.push(OsStr::from_bytes(b));
                                    }
                                    _ => break,
                                }
                            }
                            out.anchors
                                .push(anchor.as_os_str().as_bytes().to_ascii_lowercase());
                        }
                        _ => out.always = true,
                    }
                }
            }
        }
        out
    }

    /// 이 경로가 어떤 규칙에도 닿을 수 없으면 `false`
    fn may_match(&self, path: &Path) -> bool {
        if self.always {
            return true;
        }
        if let Some(name) = path.file_name() {
            let lower: Vec<u8> = name.as_bytes().to_ascii_lowercase();
            if self.anywhere.iter().any(|p| lower.starts_with(p)) {
                return true;
            }
        }
        // 규칙 접두가 이 경로 아래에 있거나, 이 경로가 규칙 접두 아래에 있으면 평가합니다.
        // 성분 경계를 보지 않는 바이트 접두 비교라 실제보다 조금 넓게 통과시키는데,
        // 넓게 통과시키는 쪽은 그냥 평가를 한 번 더 하는 것이라 결정에 영향이 없습니다
        let lower: Vec<u8> = path.as_os_str().as_bytes().to_ascii_lowercase();
        self.anchors
            .iter()
            .any(|a| lower.starts_with(a) || a.starts_with(&lower))
    }
}

struct Walker<'a> {
    policy: &'a Policy,
    filter: Prefilter,
    /// 루트 하나에 주는 예산
    budget_per_root: usize,
    /// 지금 걷고 있는 루트의 남은 예산
    remaining: usize,
    exhausted: Vec<PathBuf>,
    /// 나열할 수 없어 하위를 확인하지 못한 디렉토리
    unreadable: Vec<PathBuf>,
    /// 계획에서 제외한 심볼릭 링크 수
    links: usize,
}

impl<'a> Walker<'a> {
    fn new(policy: &'a Policy) -> Self {
        Self {
            policy,
            filter: Prefilter::build(policy),
            budget_per_root: WALK_BUDGET,
            remaining: WALK_BUDGET,
            exhausted: Vec::new(),
            unreadable: Vec::new(),
            links: 0,
        }
    }

    /// 루트 하나를 새로 걷기 시작합니다. 예산을 되돌립니다
    fn begin_root(&mut self) {
        self.remaining = self.budget_per_root;
    }

    /// 이 경로를 허용 계획에서 빼야 하는지 봅니다.
    ///
    /// 실제로 매칭된 **규칙**이 막을 때만 뺍니다. 매칭되는 규칙이 없어 `[defaults]`로
    /// 떨어진 경우는 빼지 않습니다. 시스템 경로와 작업 공간은 프로그램이 뜨기 위한
    /// 기반이고, Seatbelt 프로파일도 이를 먼저 열어 둔 뒤 정책 deny를 덧씌웁니다.
    /// 기본값까지 여기서 반영하면 `[defaults].file = "ask"`인 베이스라인 정책에서
    /// 아무것도 허용되지 않아 프로세스가 exec조차 하지 못합니다
    fn blocked(&self, path: &Path, modes: &[FileMode]) -> bool {
        if !self.filter.may_match(path) {
            return false;
        }
        modes.iter().any(|m| {
            // 순회 중인 경로는 이미 해소된 루트에 실제 항목 이름을 이어 붙인 것이라
            // 다시 해소할 필요가 없습니다. Landlock은 inode에 규칙을 걸므로 링크로
            // 허용 트리 밖을 가리켜도 그 대상 inode가 함께 열리지 않습니다 (4.2절)
            let ev = self.policy.evaluate_resolved_file(path, *m);
            // ask는 커널에서 표현할 수 없으므로 deny로 내려갑니다. Seatbelt와 같습니다
            ev.action != Action::Allow && ev.rule.is_some()
        })
    }

    /// 하위 트리를 후위 순회하며 허용 계획을 세웁니다.
    ///
    /// 반환값이 `Whole`이면 호출자가 이 경로 하나만 허용하면 됩니다. `Partial`이면
    /// `plan`에 이미 필요한 하위 규칙이 쌓였고 호출자는 이 경로에 나열 권한만 줍니다
    fn walk(&mut self, dir: &Path, kind: PlanKind, plan: &mut Plan) -> Grant {
        if self.blocked(dir, kind.modes()) {
            return Grant::Denied;
        }

        let Ok(entries) = std::fs::read_dir(dir) else {
            // 나열 실패를 세 가지로 나눕니다. 파일은 하위가 없으므로 그 자체를 허용하면
            // 되고, 순회 중 사라진 항목은 허용할 대상 자체가 없으며(규칙을 걸 때 open 이
            // 실패해 저절로 빠집니다), 디렉토리인데 열 수 없는 경우만 통째로 주지 않습니다.
            // 마지막을 구분하지 않으면 나열 불가 디렉토리의 하위가 검사 없이 열립니다
            return match std::fs::symlink_metadata(dir) {
                Ok(m) if !m.is_dir() => Grant::Whole,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Grant::Whole,
                _ => {
                    self.unreadable.push(dir.to_path_buf());
                    Grant::Denied
                }
            };
        };

        let mut children: Vec<(PathBuf, bool)> = Vec::new();
        // 예산이 끊긴 자리에서 바로 돌아가면 이미 검사를 마친 형제까지 규칙 없이 남습니다.
        // 끊겼다는 사실만 기록하고 나머지 처리는 아래 Partial 경로와 똑같이 갑니다
        let mut truncated = false;
        for entry in entries.flatten() {
            if self.remaining == 0 {
                truncated = true;
                self.exhausted.push(dir.to_path_buf());
                break;
            }
            self.remaining = self.remaining.saturating_sub(1);
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                // 종류를 모르는 항목은 계획에 넣지 않습니다. 판단 불가는 제한 방향입니다
                continue;
            };
            if kind.is_symlink() {
                // 심볼릭 링크는 규칙 대상이 아닙니다. 규칙이 inode 에 걸리므로 링크
                // 자신에게 규칙을 걸면 열리는 것은 링크가 가리키는 **대상** inode 입니다.
                // 여기서 계획에 넣으면 `ln -s ~/.ssh link` 하나로 대상 전체가 열립니다.
                // 링크를 통한 접근은 대상이 따로 허용되었을 때만 열려야 합니다
                self.links = self.links.saturating_add(1);
                continue;
            }
            children.push((path, kind.is_dir()));
        }

        // 계획은 read_dir 이 돌려주는 순서에 기대면 안 됩니다. 그 순서는 파일시스템의
        // 해시 순서라 같은 패키지 구성에서도 머신마다 다르고, 예산이 끊기는 지점이
        // 달라지면 같은 정책이 머신마다 다른 강제 범위를 냅니다
        children.sort_by(|a, b| a.0.cmp(&b.0));

        // 아래에서 개별 규칙을 주면 안 되는 자식입니다. `Partial` 은 자기 규칙을 이미
        // 쌓았고, `Denied` 는 아무것도 받으면 안 됩니다. 특히 나열할 수 없는 디렉토리는
        // 매칭되는 규칙이 없어 `blocked` 가 false 라, 여기서 걸러 내지 않으면 하위를
        // 검사하지도 못한 채 통째로 열립니다
        let mut skip: Vec<PathBuf> = Vec::new();
        let mut any_denied = false;
        let mut any_partial = false;

        for (path, is_dir) in &children {
            if *is_dir {
                match self.walk(path, kind, plan) {
                    Grant::Whole => {}
                    Grant::Partial => {
                        any_partial = true;
                        skip.push(path.clone());
                    }
                    Grant::Denied => {
                        any_denied = true;
                        skip.push(path.clone());
                    }
                }
            } else if self.blocked(path, kind.modes()) {
                any_denied = true;
            }
        }

        if !truncated && !any_denied && !any_partial {
            return Grant::Whole;
        }

        // 이 디렉토리는 통째로 줄 수 없습니다. 허용 가능한 자식만 개별로 줍니다
        for (path, is_dir) in &children {
            if skip.iter().any(|p| p == path) {
                continue;
            }
            if self.blocked(path, kind.modes()) {
                continue;
            }
            kind.push(plan, PlanPath::child(path, *is_dir));
        }
        // 상위는 나열만 허용합니다. 이름은 보이지만 내용은 열리지 않으며,
        // Seatbelt 프로파일이 file-read-metadata를 여는 것과 같은 수준입니다
        if kind.lists_parents() {
            plan.list_only.push(PlanPath::child(dir, true));
        }
        Grant::Partial
    }
}

fn add_root(walker: &mut Walker<'_>, root: &Path, kind: PlanKind, plan: &mut Plan) {
    if !root.exists() {
        return;
    }
    walker.begin_root();
    match walker.walk(root, kind, plan) {
        Grant::Whole => kind.push(plan, PlanPath::root(root)),
        Grant::Partial => {
            if kind.lists_parents() {
                plan.list_only.push(PlanPath::root(root));
            }
        }
        Grant::Denied => {}
    }
}

fn build_plan(policy: &Policy, opts: &ProfileOptions) -> Plan {
    let mut plan = Plan {
        exec_whitelist: profile::exec_whitelist_mode(policy),
        ..Plan::default()
    };
    let mut walker = Walker::new(policy);

    for p in SYSTEM_READ_PATHS {
        add_root(&mut walker, Path::new(p), PlanKind::Read, &mut plan);
    }
    for p in DEV_RW_PATHS {
        let path = Path::new(p);
        if path.exists() {
            plan.read_write.push(PlanPath::root(path));
        }
    }
    for dir in &opts.temp_dirs {
        add_root(&mut walker, dir, PlanKind::Write, &mut plan);
    }
    if let Some(ws) = &opts.workspace {
        add_root(&mut walker, ws, PlanKind::Write, &mut plan);
    }

    // 정책이 명시적으로 allow 한 파일 경로 중 구체 경로를 추가로 엽니다.
    // mode 를 그대로 따릅니다. 읽기만 허용한 규칙에 쓰기까지 열어 주면 정책 파일이
    // 말하는 것보다 커널이 넓어지고, 같은 정책이 macOS 와 Linux 에서 다르게 걸립니다
    for rule in policy.user_rules() {
        if rule.action != Action::Allow {
            continue;
        }
        let Matcher::File { paths, modes } = &rule.matcher else {
            continue;
        };
        let writable = modes.contains(FileMode::Write)
            || modes.contains(FileMode::Create)
            || modes.contains(FileMode::Delete);
        for pattern in paths {
            let raw = pattern.raw();
            if raw.contains('*') || raw.contains('?') {
                continue;
            }
            let candidate = pattern.witness();
            if candidate.exists() {
                let kind = if writable {
                    PlanKind::Write
                } else {
                    PlanKind::Read
                };
                add_root(&mut walker, &candidate, kind, &mut plan);
            }
        }
    }

    let exec_trees = plan_exec_allow(policy, opts, &mut walker, &mut plan);

    for dir in walker.exhausted.iter().take(5) {
        plan.gaps.push(tr!(
            format!(
                "{} 아래는 검사 예산({WALK_BUDGET} 항목)을 넘겨 허용하지 않았음. 필요하면 작업 공간을 좁혀야 함",
                dir.display()
            ),
            format!(
                "everything under {} was left ungranted because the walk budget \
                 ({WALK_BUDGET} entries) was exceeded; narrow the workspace if needed",
                dir.display()
            )
        ));
    }
    for dir in walker.unreadable.iter().take(5) {
        plan.gaps.push(tr!(
            format!(
                "{} 는 나열할 수 없어 하위를 검사하지 못했음. 통째로 허용하지 않았으므로 그 아래는 열리지 않음",
                dir.display()
            ),
            format!(
                "{} could not be listed, so its contents were not examined; it was not \
                 granted wholesale, so nothing under it opens",
                dir.display()
            )
        ));
    }
    if walker.links > 0 {
        plan.gaps.push(tr!(
            format!(
                "심볼릭 링크 {}개를 허용 계획에서 제외했음. 규칙이 inode 에 걸리므로 \
                 링크가 가리키는 대상이 따로 허용되지 않으면 링크로도 열리지 않음",
                walker.links
            ),
            format!(
                "{} symbolic links were left out of the grant plan; rules attach to \
                 inodes, so unless a link's target is granted separately it does not \
                 open through the link either",
                walker.links
            )
        ));
    }

    plan_exec_gap(policy, &exec_trees, &mut plan);
    plan_network(policy, opts, &mut plan);
    plan
}

/// glob 을 inode 규칙으로 옮길 수 있는 구체 경로.
///
/// `~/tools/**` 는 트리 루트로, `/usr/bin/nc` 는 그 파일 자체로 내려갑니다. 중간에
/// 와일드카드가 있는 패턴은 열 대상이 하나로 정해지지 않아 옮길 수 없습니다
///
/// # Arguments
/// `pattern` - 정책이 적은 경로 패턴
fn concrete_target(pattern: &Pattern) -> Option<PathBuf> {
    pattern
        .subtree_root()
        .or_else(|| pattern.as_absolute_path())
}

/// exec 허용 목록이 가리키는 경로를 모읍니다.
///
/// 옮기지 못한 규칙은 조용히 넘기지 않고 gap 으로 남깁니다. 허용 방향에서 조용히 빠지면
/// 그 프로그램이 커널에서 실행되지 않는데 사용자는 이유를 알 수 없습니다
///
/// # Arguments
/// `policy` - 허용 목록을 뽑을 정책
/// `gaps` - 옮기지 못한 규칙을 쌓을 곳
fn exec_allow_targets(policy: &Policy, gaps: &mut Vec<String>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let tiers: [&[airlock_policy::Rule]; 3] = [
        policy.self_protect_rules(),
        policy.user_rules(),
        policy.baseline_rules(),
    ];
    for tier in tiers {
        for rule in tier {
            if rule.action != Action::Allow {
                continue;
            }
            match &rule.matcher {
                Matcher::Exec { program, .. } => match program {
                    Some(ProgramMatch::Path(pattern)) => match concrete_target(pattern) {
                        Some(p) => out.push(p),
                        None => gaps.push(tr!(
                            format!(
                                "exec allow 규칙 {} 의 경로 패턴 {} 은 inode 규칙으로 옮길 수 없어 \
                                 실행 허용에 넣지 않았음. 이 규칙이 가리키는 프로그램은 커널이 거부함",
                                rule.id,
                                pattern.raw()
                            ),
                            format!(
                                "exec allow rule {} has path pattern {} that cannot become an \
                                 inode rule, so it was left out of the exec grants; the kernel \
                                 refuses the program this rule points to",
                                rule.id,
                                pattern.raw()
                            )
                        )),
                    },
                    Some(ProgramMatch::Basename(name)) => {
                        let found = profile::resolve_in_path(name);
                        if found.is_empty() {
                            gaps.push(tr!(
                                format!(
                                    "exec allow 규칙 {} 의 program = \"{name}\" 을 PATH 에서 찾지 \
                                     못해 실행 허용에 넣지 않았음. 이 프로그램은 커널이 거부함",
                                    rule.id
                                ),
                                format!(
                                    "exec allow rule {} has program = \"{name}\" which was not \
                                     found in PATH, so it was left out of the exec grants; the \
                                     kernel refuses this program",
                                    rule.id
                                )
                            ));
                        }
                        out.extend(found);
                    }
                    None => gaps.push(tr!(
                        format!(
                            "exec allow 규칙 {} 에 프로그램 조건이 없어 실행 대상을 특정할 수 없음. \
                             실행 허용에 넣지 않았음",
                            rule.id
                        ),
                        format!(
                            "exec allow rule {} has no program condition, so the exec target \
                             cannot be pinned down; it was left out of the exec grants",
                            rule.id
                        )
                    )),
                },
                Matcher::File { paths, modes } if modes.contains(FileMode::Exec) => {
                    for pattern in paths {
                        match concrete_target(pattern) {
                            Some(p) => out.push(p),
                            None => gaps.push(tr!(
                                format!(
                                    "규칙 {} 의 경로 {} 는 exec 모드를 허용하지만 inode 규칙으로 \
                                     옮길 수 없어 실행 허용에 넣지 않았음",
                                    rule.id,
                                    pattern.raw()
                                ),
                                format!(
                                    "rule {} allows exec mode on path {}, but it cannot become \
                                     an inode rule and was left out of the exec grants",
                                    rule.id,
                                    pattern.raw()
                                )
                            )),
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// 실행 허용 계획을 세우고 트리로 걸린 루트를 돌려줍니다.
///
/// 화이트리스트 모드가 아니면 아무것도 하지 않습니다. 그때는 읽기 권한에 `Execute` 가
/// 함께 실려 나가므로 별도 계획이 필요 없습니다.
///
/// # Arguments
/// `policy` - 허용 목록을 뽑을 정책
/// `opts` - 최상위 프로그램이 들어 있는 프로파일 옵션
/// `walker` - 트리를 걸어 내려갈 순회기
/// `plan` - 결과를 쌓을 계획
fn plan_exec_allow(
    policy: &Policy,
    opts: &ProfileOptions,
    walker: &mut Walker<'_>,
    plan: &mut Plan,
) -> Vec<PathBuf> {
    if !plan.exec_whitelist {
        return Vec::new();
    }

    let mut roots: Vec<PathBuf> = EXEC_RUNTIME_PATHS.iter().map(PathBuf::from).collect();
    roots.extend(exec_allow_targets(policy, &mut plan.gaps));
    if let Some(program) = &opts.program {
        roots.push(program.clone());
    }
    // 계획은 결정적이어야 합니다. 같은 정책이 호출 순서 때문에 다른 규칙 집합을 내면
    // 강제 범위가 머신마다 달라집니다
    roots.sort();
    roots.dedup();

    let mut trees = Vec::new();
    for root in &roots {
        if root.is_dir() {
            trees.push(root.clone());
        }
        add_root(walker, root, PlanKind::Exec, plan);
    }

    let runtime: Vec<&str> = EXEC_RUNTIME_PATHS
        .iter()
        .copied()
        .filter(|p| Path::new(p).exists())
        .collect();
    if !runtime.is_empty() {
        plan.gaps.push(tr!(
            format!(
                "동적 링커에 Execute 가 필요해 {} 를 실행 허용에 함께 넣었음. 그 아래의 실행 \
                 파일은 정책이 따로 허용하지 않아도 실행됨",
                runtime.join(", ")
            ),
            format!(
                "the dynamic linker needs Execute, so {} were added to the exec grants; \
                 executables under them run even without a separate policy allow",
                runtime.join(", ")
            )
        ));
    }
    plan.gaps.push(
        tr!(
            "mmap(PROT_EXEC) 은 Landlock 이 매개하지 않음. 읽을 수 있는 파일을 실행 가능하게 \
             매핑해 그 안으로 뛰는 경로는 화이트리스트 밖임",
            "mmap(PROT_EXEC) is not mediated by Landlock; mapping a readable file as \
             executable and jumping into it is outside the whitelist"
        )
        .to_string(),
    );

    trees
}

/// exec 제한 중 커널이 판정하지 못하는 것만 gap 으로 남깁니다.
///
/// 화이트리스트 모드에서는 허용 목록 밖의 프로그램이 커널에서 실제로 거부됩니다.
/// 그것을 gap 으로 적으면 강제되는 것을 강제되지 않는다고 말하는 셈이라 반대 방향의
/// 거짓말이 됩니다. 남는 것은 두 가지뿐입니다.
///
/// - argv 조건. 어떤 커널 인터페이스로도 표현할 수 없습니다.
/// - 실행 허용이 디렉토리 트리로 걸린 경우 그 트리 안의 제한 규칙. Landlock 은 허용한
///   트리 안에서 일부만 빼는 것을 표현할 수 없습니다.
///
/// `[defaults].exec = "allow"` 인 정책은 화이트리스트 자체가 없으므로 exec 제한이
/// 통째로 커널 밖입니다.
///
/// # Arguments
/// `policy` - 검사할 정책
/// `trees` - 실행 허용이 트리로 걸린 루트
/// `plan` - gap 을 쌓을 계획
fn plan_exec_gap(policy: &Policy, trees: &[PathBuf], plan: &mut Plan) {
    let tiers: [&[airlock_policy::Rule]; 3] = [
        policy.self_protect_rules(),
        policy.user_rules(),
        policy.baseline_rules(),
    ];

    let mut restrictive: Vec<&airlock_policy::Rule> = Vec::new();
    let mut argv_ids: Vec<&str> = Vec::new();
    for tier in tiers {
        for rule in tier {
            let names_exec = match &rule.matcher {
                Matcher::Exec {
                    argv_contains,
                    argv_pattern,
                    ..
                } => {
                    if !argv_contains.is_empty() || argv_pattern.is_some() {
                        argv_ids.push(&rule.id);
                    }
                    true
                }
                Matcher::File { modes, .. } => modes.contains(FileMode::Exec),
                Matcher::Egress { .. } => false,
            };
            if names_exec && rule.action.is_restrictive() {
                restrictive.push(rule);
            }
        }
    }

    if !plan.exec_whitelist {
        let mut ids: Vec<&str> = restrictive.iter().map(|r| r.id.as_str()).collect();
        if ids.is_empty() {
            return;
        }
        ids.sort_unstable();
        ids.dedup();
        plan.gaps.push(tr!(
            format!(
                "[defaults].exec = \"allow\" 라 exec 화이트리스트를 걸지 않았음. 읽을 수 있는 \
                 파일은 전부 실행할 수 있으며 아래 규칙은 중계 층이 관측할 뿐임: {}",
                ids.join(", ")
            ),
            format!(
                "[defaults].exec = \"allow\", so no exec whitelist was applied; every \
                 readable file can be executed, and the rules below are only observed by \
                 the mediation layer: {}",
                ids.join(", ")
            )
        ));
        return;
    }

    argv_ids.sort_unstable();
    argv_ids.dedup();
    if !argv_ids.is_empty() {
        plan.gaps.push(tr!(
            format!(
                "argv 조건은 커널이 볼 수 없어 프로그램 경로 단위로만 강제됨. 아래 규칙의 \
                 argv 판정은 중계 층에만 있음: {}",
                argv_ids.join(", ")
            ),
            format!(
                "argv conditions are invisible to the kernel, so enforcement is per \
                 program path only; the argv decisions of these rules exist only in the \
                 mediation layer: {}",
                argv_ids.join(", ")
            )
        ));
    }

    if trees.is_empty() {
        return;
    }
    let mut inside: Vec<&str> = restrictive
        .iter()
        .filter(|r| rule_touches_trees(r, trees))
        .map(|r| r.id.as_str())
        .collect();
    if inside.is_empty() {
        return;
    }
    inside.sort_unstable();
    inside.dedup();
    let listed: Vec<String> = trees.iter().map(|t| t.display().to_string()).collect();
    plan.gaps.push(tr!(
        format!(
            "실행 허용이 트리로 걸린 곳({}) 안의 exec 제한 규칙은 커널에서 걸러지지 않음. \
             Landlock 은 허용한 트리에서 일부만 빼는 것을 표현할 수 없음: {}",
            listed.join(", "),
            inside.join(", ")
        ),
        format!(
            "exec restriction rules inside tree-granted exec roots ({}) are not filtered \
             by the kernel; Landlock cannot express carving a part out of a granted \
             tree: {}",
            listed.join(", "),
            inside.join(", ")
        )
    ));
}

/// 이 제한 규칙이 실행 허용 트리 안을 가리키는지.
///
/// 프로그램 조건이 없는 규칙은 무엇이든 가리킬 수 있으므로 참으로 봅니다
///
/// # Arguments
/// `rule` - 검사할 제한 규칙
/// `trees` - 실행 허용이 트리로 걸린 루트
fn rule_touches_trees(rule: &airlock_policy::Rule, trees: &[PathBuf]) -> bool {
    let under = |p: &Path| trees.iter().any(|t| p.starts_with(t));
    match &rule.matcher {
        Matcher::Exec { program, .. } => match program {
            Some(ProgramMatch::Path(pattern)) => {
                concrete_target(pattern).is_some_and(|p| under(&p))
            }
            Some(ProgramMatch::Basename(name)) => {
                profile::resolve_in_path(name).iter().any(|p| under(p))
            }
            None => true,
        },
        Matcher::File { paths, modes } => {
            modes.contains(FileMode::Exec)
                && paths
                    .iter()
                    .any(|p| concrete_target(p).is_some_and(|c| under(&c)))
        }
        Matcher::Egress { .. } => false,
    }
}

fn plan_network(policy: &Policy, opts: &ProfileOptions, plan: &mut Plan) {
    if !opts.allow_network {
        return;
    }

    if let Some(proxy) = opts.proxy {
        // 나갈 수 있는 포트를 프록시 하나로 줄입니다. 정책의 포트 목록은 이제
        // 프록시가 대신 나가므로 자식에게 열어 줄 이유가 없습니다
        plan.tcp_connect.insert(proxy.port());
        // Landlock 은 포트까지만 봅니다. 자식이 아는 프록시 포트로 다른 호스트에
        // 연결하는 것을 막지 못하므로, 이 백엔드만으로는 프록시가 유일한 출구가
        // 되지 않습니다. netns 로 자식의 경로 자체를 끊는 것이 다음 단계입니다
        plan.gaps.push(
            tr!(
                "egress 프록시가 켜졌으나 Landlock 은 포트까지만 강제함. 자식이 같은 포트로 \
                 다른 호스트에 직접 연결하면 프록시를 건너뜀. network namespace 격리가 필요함",
                "the egress proxy is on, but Landlock only enforces down to the port; a \
                 child connecting directly to another host on the same port bypasses the \
                 proxy; network namespace isolation is needed"
            )
            .to_string(),
        );
        return;
    }

    let mut host_scoped = Vec::new();
    let mut protocol_scoped = Vec::new();
    let mut quota_scoped = Vec::new();
    for rule in policy.user_rules() {
        let Matcher::Egress {
            host,
            port,
            protocol,
            max_bytes_out,
        } = &rule.matcher
        else {
            continue;
        };
        if rule.action != Action::Allow {
            continue;
        }
        match port {
            Some(p) => {
                plan.tcp_connect.insert(*p);
            }
            None => {
                // 포트를 특정하지 않은 allow는 포트 단위로 옮길 수 없습니다
                plan.unrestricted_net = true;
            }
        }
        if !matches!(host, airlock_policy::host::HostPattern::Any) {
            host_scoped.push(rule.id.clone());
        }
        // 프로토콜 조건은 커널이 볼 수 없습니다. 포트만 열리므로 규칙이 말하는 것보다
        // 커널이 넓어집니다. 호스트 조건과 같은 이유이며 같은 방식으로 노출합니다
        if protocol.is_some() {
            protocol_scoped.push(rule.id.clone());
        }
        // 총량 한도도 커널 밖입니다. 반출 바이트는 프록시 층만 세며, 커널은 포트를 열거나
        // 닫을 뿐 얼마나 나갔는지 알지 못합니다
        if max_bytes_out.is_some() {
            quota_scoped.push(rule.id.clone());
        }
    }

    if plan.tcp_connect.is_empty() && !plan.unrestricted_net {
        // 아웃바운드 allow 규칙이 하나도 없습니다. TCP를 통째로 막습니다
        return;
    }

    if plan.unrestricted_net {
        // 포트를 적지 않은 allow 가 하나라도 있으면 TCP 제한 자체를 걸지 않습니다.
        // 이때 "포트까지는 강제한다"고 알리면 사실과 정반대가 됩니다
        plan.gaps.push(
            tr!(
                "포트를 특정하지 않은 egress allow 규칙이 있어 아웃바운드를 통째로 열었음. \
                 포트 제한도 걸리지 않으므로 규칙마다 port 를 적어야 함",
                "an egress allow rule without a specific port opened outbound entirely; \
                 not even port limits apply, so every rule should state a port"
            )
            .to_string(),
        );
    }

    if !host_scoped.is_empty() && !plan.unrestricted_net {
        plan.gaps.push(tr!(
            format!(
                "호스트 단위 egress 규칙은 Landlock으로 강제되지 않음. 포트까지만 강제하며 \
                 호스트 판정은 프록시 층이 필요함: {}",
                host_scoped.join(", ")
            ),
            format!(
                "per-host egress rules are not enforced by Landlock; enforcement stops at \
                 the port, and host decisions need the proxy layer: {}",
                host_scoped.join(", ")
            )
        ));
    }

    if !protocol_scoped.is_empty() {
        plan.gaps.push(tr!(
            format!(
                "protocol 조건이 붙은 egress allow 규칙의 포트가 커널에서는 조건 없이 열림. \
                 Landlock 은 프로토콜을 보지 못하므로 규칙보다 넓게 걸림: {}",
                protocol_scoped.join(", ")
            ),
            format!(
                "ports from egress allow rules with a protocol condition open \
                 unconditionally in the kernel; Landlock cannot see the protocol, so the \
                 grant is wider than the rule: {}",
                protocol_scoped.join(", ")
            )
        ));
    }

    if !quota_scoped.is_empty() {
        plan.gaps.push(tr!(
            format!(
                "max_bytes_out 은 커널이 강제하지 않음. 반출 바이트는 프록시 층만 세고, 한도를 \
                 넘긴 그 연결 자체는 막지 못하며 다음 연결부터 막힘: {}",
                quota_scoped.join(", ")
            ),
            format!(
                "max_bytes_out is not kernel-enforced; only the proxy layer counts \
                 outbound bytes, the connection that crosses the limit is not itself \
                 blocked, and blocking starts from the next connection: {}",
                quota_scoped.join(", ")
            )
        ));
    }
}

#[derive(Debug)]
pub struct LandlockEnforcer {
    options: ProfileOptions,
    plan: Option<Plan>,
    abi: ABI,
    gaps: Vec<String>,
    /// 중계 수준과 무관하게 거는 tty ioctl 거부 필터.
    ///
    /// Landlock 은 상속된 fd 에 아무것도 하지 못하므로 자식이 물려받은 제어 터미널에
    /// `TIOCSTI` 를 부르는 것을 막을 수 없습니다. 그 경로는 승인 프롬프트 위조이고,
    /// `--mediate off` 에서도 열려 있으면 안 되므로 강제 층이 seccomp 로 함께 겁니다
    tty_guard: Option<TtyGuard>,
}

impl Default for LandlockEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl LandlockEnforcer {
    pub fn new() -> Self {
        Self {
            options: ProfileOptions::default(),
            plan: None,
            abi: detect_abi(),
            gaps: Vec::new(),
            tty_guard: TtyGuard::new(),
        }
    }

    pub fn with_options(mut self, options: ProfileOptions) -> Self {
        self.options = options;
        self
    }

    pub fn abi(&self) -> ABI {
        self.abi
    }

    pub fn available() -> bool {
        detect_abi() != ABI::Unsupported
    }

    fn rule_count(&self) -> usize {
        self.plan.as_ref().map_or(0, |p| {
            p.read_only
                .len()
                .saturating_add(p.read_write.len())
                .saturating_add(p.list_only.len())
                .saturating_add(p.exec_paths.len())
        })
    }
}

fn detect_abi() -> ABI {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1;

    // # Safety
    // 인자가 (NULL, 0, VERSION)이면 커널은 아는 최대 ABI 버전을 돌려줄 뿐
    // 어떤 상태도 만들지 않습니다. 크레이트가 이 조회를 공개하지 않아 직접 부릅니다
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };

    match version {
        1 => ABI::V1,
        2 => ABI::V2,
        3 => ABI::V3,
        4 => ABI::V4,
        5 => ABI::V5,
        6 => ABI::V6,
        7 => ABI::V7,
        // 크레이트가 아는 상한을 넘는 커널은 상한으로 취급합니다. 모르는 기능을
        // 요구하지 않으므로 안전하며, best-effort로 아는 만큼만 겁니다
        n if n >= 8 => ABI::V8,
        _ => ABI::Unsupported,
    }
}

/// 규칙을 걸 대상 fd를 엽니다.
///
/// `O_PATH`는 파일을 여는 것이 아니라 경로를 가리키는 핸들만 얻습니다. 순회 중 발견한
/// 항목에는 `O_NOFOLLOW`를 함께 주어, 계획을 세운 뒤 항목이 링크로 바뀌어도 규칙이
/// 링크 대상에 걸리지 않게 합니다
///
/// # Safety
/// `libc::open`을 직접 부르는 이유는 `O_NOFOLLOW`를 붙일 방법이 표준 API에 없기
/// 때문입니다. 인자는 널 종료 문자열과 플래그 비트뿐이며, 성공 시 돌려받은 fd의
/// 소유권을 `OwnedFd`로 옮겨 누출과 이중 close를 막습니다
fn open_rule_target(target: &PlanPath) -> Option<OwnedFd> {
    let mut flags = libc::O_PATH | libc::O_CLOEXEC;
    if !target.follow {
        flags |= libc::O_NOFOLLOW;
    }
    let raw = CString::new(target.path.as_os_str().as_bytes()).ok()?;
    let fd = unsafe { libc::open(raw.as_ptr(), flags) };
    if fd < 0 {
        return None;
    }
    // # Safety
    // open이 방금 돌려준 유효한 fd이며 다른 소유자가 없습니다
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// 커널이 요청한 접근 종류 일부만 받아들였다는 사실을 알립니다.
///
/// 커널이 규칙을 부분만 걸었는데 조용히 넘어가면 강제되지 않은 것이 강제된 것처럼
/// 보입니다. 부분 강제를 실패로 처리하지 않는 이유는 `NotEnforced`와 달리 실제로
/// 무언가는 걸려 있고, 그 상태에서 실행을 막으면 구형 커널에서 아무것도 돌지 않기 때문입니다
///
/// # Safety
/// `pre_exec` 문맥에서 부르므로 할당 없이 정적 바이트열만 fd 2로 씁니다.
/// `write`는 async-signal-safe 하며 실패는 무시합니다
fn warn_partial() {
    let msg: &'static str = tr!(
        "airlock: 경고 커널이 Landlock 규칙을 부분만 적용했음. 일부 접근 종류가 강제되지 않음\n",
        "airlock: warning: the kernel applied the Landlock rules only partially; some \
         access kinds are not enforced\n"
    );
    unsafe {
        libc::write(2, msg.as_ptr().cast(), msg.len());
    }
}

fn apply(plan: &Plan, abi: ABI) -> std::io::Result<RulesetStatus> {
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(std::io::Error::other)?;

    // ABI v4부터 TCP 포트 규칙을 걸 수 있습니다. 그 아래 커널에서는 조용히 생략됩니다
    if abi >= ABI::V4 && !plan.unrestricted_net {
        ruleset = ruleset
            .handle_access(AccessNet::from_all(abi))
            .map_err(std::io::Error::other)?;
    }

    // ABI v6부터 도메인 밖으로 나가는 시그널과 추상 유닉스 소켓 연결을 막을 수 있습니다.
    // 이것이 없으면 격리된 프로세스가 브로커와 감독 스레드에 시그널을 보내고,
    // dbus 나 ssh-agent 같은 추상 소켓에 그대로 붙습니다
    if abi >= ABI::V6 {
        ruleset = ruleset
            .scope(Scope::from_all(abi))
            .map_err(std::io::Error::other)?;
    }

    let mut created = ruleset.create().map_err(std::io::Error::other)?;

    // 화이트리스트 모드가 아니면 읽기 권한에 Execute 를 도로 실어 이전 동작을 유지합니다.
    // `[defaults].exec = "allow"` 인 정책이 이 변경으로 실행을 잃으면 회귀입니다
    let ride_along = if plan.exec_whitelist {
        landlock::BitFlags::EMPTY
    } else {
        exec_access(abi)
    };

    for (paths, access) in [
        (&plan.read_only, read_access(abi) | ride_along),
        (&plan.read_write, full_access(abi) | ride_along),
        (&plan.list_only, list_access()),
        (&plan.exec_paths, exec_access(abi)),
    ] {
        for target in paths {
            let granted = rule_access(target, access, abi);
            if granted.is_empty() {
                continue;
            }
            let Some(fd) = open_rule_target(target) else {
                continue;
            };
            created = created
                .add_rule(PathBeneath::new(fd, granted))
                .map_err(std::io::Error::other)?;
        }
    }

    if abi >= ABI::V4 && !plan.unrestricted_net {
        for port in &plan.tcp_connect {
            created = created
                .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                .map_err(std::io::Error::other)?;
        }
    }

    let status = created.restrict_self().map_err(std::io::Error::other)?;
    Ok(status.ruleset)
}

impl Enforcer for LandlockEnforcer {
    fn kind(&self) -> Enforcement {
        Enforcement::Landlock
    }

    fn describe(&self) -> String {
        match self.abi {
            ABI::Unsupported => {
                tr!("landlock (커널 미지원)", "landlock (kernel unsupported)").to_string()
            }
            abi => tr!(
                format!(
                    "landlock (ABI v{}, 규칙 {}개)",
                    abi as u32,
                    self.rule_count()
                ),
                format!(
                    "landlock (ABI v{}, {} rules)",
                    abi as u32,
                    self.rule_count()
                )
            ),
        }
    }

    fn set_program(&mut self, program: &Path) {
        self.options.program = Some(program.to_path_buf());
    }

    fn prepare(&mut self, policy: &Policy) -> Result<()> {
        if self.abi == ABI::Unsupported {
            return Err(BrokerError::EnforcerUnavailable {
                name: "landlock",
                why: tr!(
                    "커널이 Landlock을 지원하지 않음. Linux 5.13 이상이 필요함",
                    "the kernel does not support Landlock; Linux 5.13 or later is required"
                )
                .to_string(),
            });
        }
        let plan = build_plan(policy, &self.options);
        self.gaps = plan.gaps.clone();
        self.plan = Some(plan);
        Ok(())
    }

    fn wrap(&self, cmd: &mut Command) -> Result<()> {
        let Some(mut plan) = self.plan.clone() else {
            return Err(BrokerError::EnforcerUnavailable {
                name: "landlock",
                why: tr!(
                    "prepare가 먼저 호출되지 않았음",
                    "prepare was not called first"
                )
                .to_string(),
            });
        };
        // 최상위 프로그램은 언제나 실행 허용에 들어가야 합니다. 빠지면 커널이 첫
        // execve 를 거부해 프로세스가 아예 뜨지 못합니다. 그 경로는 prepare 가 아니라
        // 실제로 spawn 할 명령을 받는 여기에서만 확실히 알 수 있습니다
        if plan.exec_whitelist {
            if let Some(program) = profile::resolve_program(cmd.get_program())
                && !plan.exec_paths.iter().any(|t| t.path == program)
            {
                plan.exec_paths.push(PlanPath::root(program));
            }
            if plan.exec_paths.is_empty() {
                return Err(BrokerError::EnforcerUnavailable {
                    name: "landlock",
                    why: tr!(
                        "[defaults].exec 이 allow 가 아니어서 exec 을 화이트리스트로 거는데 \
                         실행 허용 경로가 하나도 없음. 최상위 프로그램을 해소하지 못했거나 \
                         정책에 exec allow 규칙이 없음. 이대로 걸면 프로세스가 뜨지 못함",
                        "[defaults].exec is not allow, so exec is whitelisted, but there is \
                         not a single exec-granted path; the top-level program could not be \
                         resolved, or the policy has no exec allow rules; applying this \
                         would keep the process from starting"
                    )
                    .to_string(),
                });
            }
        }
        let abi = self.abi;
        let tty_guard = self.tty_guard.clone();

        use std::os::unix::process::CommandExt;
        // # Safety
        // pre_exec은 fork 이후 exec 이전의 자식에서 실행됩니다. 브로커는 spawn 시점에
        // 단일 스레드이므로 malloc 락 경합이 없습니다. 계획은 fork 전에 확정한 경로 목록이며
        // 자식에서는 그 경로를 열어 규칙으로 거는 일만 합니다. restrict_self는 호출한
        // 스레드에만 걸리는데, exec 직전의 자식은 스레드가 하나뿐이라 전체에 걸립니다.
        // tty 필터도 fork 전에 조립해 두었고 같은 이유로 자식 전체에 걸립니다
        unsafe {
            cmd.pre_exec(move || {
                if let Some(guard) = &tty_guard {
                    guard.install()?;
                }
                let status = apply(&plan, abi)?;
                if status == RulesetStatus::NotEnforced {
                    return Err(std::io::Error::other(tr!(
                        "Landlock 규칙이 적용되지 않았음. 강제 없이 실행하지 않음",
                        "Landlock rules were not applied; refusing to run without enforcement"
                    )));
                }
                if status != RulesetStatus::FullyEnforced {
                    warn_partial();
                }
                Ok(())
            });
        }
        Ok(())
    }

    fn gaps(&self) -> Vec<String> {
        let mut gaps = vec![
            tr!(
                "ask 규칙은 커널에서 표현할 수 없으므로 Landlock 계획에서 deny로 내려감",
                "ask rules cannot be expressed in the kernel, so the Landlock plan \
                 degrades them to deny"
            )
            .to_string(),
            tr!(
                "Landlock이 커널에서 거부한 접근 자체는 감사 로그에 남지 않음. \
                 체인에는 중계 층이 관측한 것만 기록됨",
                "accesses Landlock refused in the kernel are themselves absent from the \
                 audit log; the chain records only what the mediation layer observed"
            )
            .to_string(),
        ];
        if self.abi < ABI::V4 {
            gaps.push(tr!(
                format!(
                    "ABI v{}는 TCP 포트 규칙을 지원하지 않음(v4 필요). 아웃바운드가 강제되지 않음",
                    self.abi as u32
                ),
                format!(
                    "ABI v{} does not support TCP port rules (v4 required); outbound is \
                     not enforced",
                    self.abi as u32
                )
            ));
        }
        gaps.push(
            tr!(
                "UDP는 Landlock ABI v10부터이며 크레이트가 아직 노출하지 않음. \
                 UDP 아웃바운드는 강제되지 않음",
                "UDP arrives with Landlock ABI v10 and the crate does not expose it yet; \
                 UDP outbound is not enforced"
            )
            .to_string(),
        );
        if self.tty_guard.is_none() {
            gaps.push(
                tr!(
                    "이 아키텍처의 seccomp arch 값을 몰라 TIOCSTI/TIOCLINUX 거부 필터를 걸지 \
                     못함. 자식이 상속된 터미널에 입력을 밀어 넣어 승인 프롬프트를 위조할 수 있음",
                    "the seccomp arch value for this architecture is unknown, so the \
                     TIOCSTI/TIOCLINUX refusal filter is not installed; a child can push \
                     input into the inherited terminal and forge an approval prompt"
                )
                .to_string(),
            );
        }
        gaps.extend(self.gaps.iter().cloned());
        gaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use airlock_policy::LoadContext;
    use std::fs;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let p = std::env::temp_dir()
                .join(format!("airlock-plan-{tag}-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&p).unwrap();
            Self(fs::canonicalize(&p).unwrap())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn baseline(home: &Path) -> Policy {
        Policy::baseline_only(&LoadContext::new(home, home.join("audit"))).unwrap()
    }

    /// 예산은 루트마다 새로 주어야 합니다.
    ///
    /// 하나로 공유하면 앞선 루트가 예산을 다 쓴 뒤의 모든 루트가 규칙 없이 남고,
    /// `/usr` 에 큰 트리가 있는 머신에서 `/etc` 와 `/sbin` 이 통째로 빠집니다
    #[test]
    fn one_huge_root_does_not_starve_the_next_root() {
        let s = Scratch::new("starve");
        let big = s.0.join("big");
        let small = s.0.join("small");
        fs::create_dir_all(&big).unwrap();
        fs::create_dir_all(&small).unwrap();
        for i in 0..8 {
            fs::write(big.join(format!("f{i}")), b"x").unwrap();
        }
        fs::write(small.join("tool"), b"x").unwrap();

        let policy = baseline(&s.0);
        let mut walker = Walker::new(&policy);
        walker.budget_per_root = 4;
        let mut plan = Plan::default();

        add_root(&mut walker, &big, PlanKind::Read, &mut plan);
        assert!(
            !walker.exhausted.is_empty(),
            "첫 루트에서 예산이 소진되어야 함"
        );

        add_root(&mut walker, &small, PlanKind::Read, &mut plan);
        assert!(
            plan.read_only.iter().any(|p| p.path == small),
            "예산이 루트마다 새로 주어져 두 번째 루트가 통째로 허용되어야 함"
        );
    }

    /// 예산이 끊겨도 그 전에 검사를 마친 형제는 규칙을 받아야 합니다
    #[test]
    fn entries_examined_before_exhaustion_still_get_rules() {
        let s = Scratch::new("partial");
        let root = s.0.join("root");
        fs::create_dir_all(&root).unwrap();
        for i in 0..6 {
            fs::write(root.join(format!("f{i}")), b"x").unwrap();
        }

        let policy = baseline(&s.0);
        let mut walker = Walker::new(&policy);
        walker.budget_per_root = 3;
        let mut plan = Plan::default();
        add_root(&mut walker, &root, PlanKind::Read, &mut plan);

        assert_eq!(
            plan.read_only.len(),
            3,
            "예산 안에서 본 항목은 개별 규칙을 받아야 함"
        );
        assert!(
            plan.list_only.iter().any(|p| p.path == root),
            "상위는 나열만 허용으로 남아야 함"
        );
    }

    /// 계획은 read_dir 순서에 기대면 안 됩니다
    #[test]
    fn walk_order_is_deterministic() {
        let s = Scratch::new("order");
        let root = s.0.join("root");
        fs::create_dir_all(&root).unwrap();
        for name in ["zeta", "alpha", "mid", "beta"] {
            fs::create_dir_all(root.join(name)).unwrap();
            fs::write(root.join(name).join("x"), b"x").unwrap();
        }
        // 최상위 4개는 다 나열되고 그 아래로 내려갈 예산만 2개 남게 잡습니다.
        // 어디까지 내려갈 수 있는지가 read_dir 순서에 좌우되면 안 됩니다
        let policy = baseline(&s.0);
        let mut walker = Walker::new(&policy);
        walker.budget_per_root = 6;
        let mut plan = Plan::default();
        add_root(&mut walker, &root, PlanKind::Read, &mut plan);

        let seen: Vec<String> = plan
            .read_only
            .iter()
            .filter_map(|p| p.path.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .collect();
        assert_eq!(seen, vec!["alpha", "beta"], "이름 순으로 걸어야 함");
    }

    /// 디렉토리 전용 권한을 일반 파일에 걸면 커널이 EINVAL 을 내고 크레이트가
    /// ruleset 을 부분 강제로 표시합니다. 그러면 진짜 부분 강제와 구분되지 않습니다
    #[test]
    fn file_targets_do_not_get_directory_only_rights() {
        let file = PlanPath {
            path: PathBuf::from("/dev/null"),
            follow: true,
            dir: false,
        };
        let granted = rule_access(&file, full_access(ABI::V5), ABI::V5);
        assert!(!granted.contains(AccessFs::ReadDir));
        assert!(!granted.contains(AccessFs::MakeDir));
        assert!(granted.contains(AccessFs::ReadFile));
        assert!(granted.contains(AccessFs::WriteFile));

        let dir = PlanPath {
            path: PathBuf::from("/tmp"),
            follow: true,
            dir: true,
        };
        assert!(rule_access(&dir, read_access(ABI::V5), ABI::V5).contains(AccessFs::ReadDir));
    }

    /// 나열할 수 없는 디렉토리는 하위를 검사할 방법이 없으므로 규칙을 주면 안 됩니다.
    ///
    /// 매칭되는 규칙이 없어 `blocked` 가 false 라, 순회 결과를 따로 기억하지 않으면
    /// 개별 허용 단계에서 도로 열립니다
    #[test]
    fn an_unlistable_directory_gets_no_rule() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("root 는 나열 권한 검사를 우회하므로 건너뜀");
            return;
        }
        use std::os::unix::fs::PermissionsExt;

        let s = Scratch::new("unlistable");
        let root = s.0.join("root");
        let closed = root.join("closed");
        fs::create_dir_all(&closed).unwrap();
        fs::write(closed.join("inside"), b"x").unwrap();
        fs::write(root.join("ok"), b"x").unwrap();
        // 나열은 못 하지만 통과는 되는 디렉토리
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o311)).unwrap();

        let policy = baseline(&s.0);
        let mut walker = Walker::new(&policy);
        let mut plan = Plan::default();
        add_root(&mut walker, &root, PlanKind::Write, &mut plan);

        let _ = fs::set_permissions(&closed, fs::Permissions::from_mode(0o755));

        assert!(
            !plan.read_write.iter().any(|p| p.path == closed),
            "나열할 수 없는 디렉토리에 규칙이 걸림"
        );
        assert!(
            plan.read_write.iter().any(|p| p.path == root.join("ok")),
            "형제 파일은 그대로 허용되어야 함"
        );
    }

    #[test]
    fn the_tty_guard_rides_along_with_every_enforcer() {
        let e = LandlockEnforcer::new();
        assert!(
            e.tty_guard.is_some(),
            "지원 아키텍처에서는 TIOCSTI 거부 필터가 항상 있어야 함"
        );
        assert!(
            !e.gaps().iter().any(|g| g.contains("TIOCSTI")),
            "필터가 있는데 gap 으로 없다고 알리면 안 됨"
        );
    }

    #[test]
    fn dev_nodes_are_planned_as_non_directories() {
        let p = PlanPath::root("/dev/null");
        assert!(!p.dir, "문자 장치는 디렉토리가 아님");
    }

    // ---------- exec 화이트리스트 ----------

    fn policy_with(home: &Path, src: &str) -> Policy {
        Policy::load_str(src, &LoadContext::new(home, home.join("audit"))).unwrap()
    }

    /// `AccessFs::from_read` 는 `Execute` 를 포함합니다. 그대로 두면 읽을 수 있는 모든
    /// 파일이 실행 가능해져 exec 화이트리스트가 성립하지 않습니다
    #[test]
    fn read_and_write_access_no_longer_carry_execute() {
        for abi in [ABI::V1, ABI::V5, ABI::V8] {
            assert!(
                !read_access(abi).contains(AccessFs::Execute),
                "읽기 권한에 Execute 가 남아 있으면 exec 정책이 커널에서 무의미해짐"
            );
            assert!(
                !full_access(abi).contains(AccessFs::Execute),
                "쓰기 권한에 Execute 가 남으면 작업 공간에 써 넣은 바이너리가 실행됨"
            );
            assert!(exec_access(abi).contains(AccessFs::Execute));
            // 읽기 자체는 그대로여야 합니다
            assert!(read_access(abi).contains(AccessFs::ReadFile));
            assert!(read_access(abi).contains(AccessFs::ReadDir));
            assert!(full_access(abi).contains(AccessFs::WriteFile));
        }
        assert!(exec_access(ABI::Unsupported).is_empty());
    }

    #[test]
    fn the_exec_default_decides_whether_the_whitelist_is_built() {
        let s = Scratch::new("mode");
        let asking = baseline(&s.0);
        assert!(
            profile::exec_whitelist_mode(&asking),
            "[defaults].exec 기본값은 ask 이므로 화이트리스트여야 함"
        );

        let permissive = policy_with(
            &s.0,
            r#"
version = 1
[defaults]
file = "allow"
exec = "allow"
egress = "deny"
"#,
        );
        assert!(
            !profile::exec_whitelist_mode(&permissive),
            "exec = \"allow\" 정책은 이전 동작을 그대로 유지해야 함"
        );
    }

    #[test]
    fn exec_allow_rules_become_concrete_targets() {
        let s = Scratch::new("targets");
        let tool = s.0.join("tools/mytool");
        fs::create_dir_all(s.0.join("tools")).unwrap();
        fs::write(&tool, b"x").unwrap();

        let policy = policy_with(
            &s.0,
            &format!(
                r#"
version = 1
[defaults]
file = "allow"
exec = "ask"
egress = "deny"
[[rules]]
id = "tool"
kind = "exec"
program = "{}"
action = "allow"
[[rules]]
id = "tree"
kind = "file"
path = "{}/tools/**"
mode = ["read", "exec"]
action = "allow"
"#,
                tool.display(),
                s.0.display()
            ),
        );

        let mut gaps = Vec::new();
        let targets = exec_allow_targets(&policy, &mut gaps);
        assert!(targets.contains(&tool), "{targets:?}");
        assert!(targets.contains(&s.0.join("tools")), "{targets:?}");
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    /// 이름만 적은 규칙이 PATH 에서 해소되지 않으면 그 프로그램은 커널에서 실행되지
    /// 않습니다. 조용히 넘어가면 사용자가 이유를 알 수 없습니다
    #[test]
    fn an_unresolvable_basename_allow_is_reported_not_dropped() {
        let s = Scratch::new("basename");
        let policy = policy_with(
            &s.0,
            r#"
version = 1
[defaults]
file = "allow"
exec = "ask"
egress = "deny"
[[rules]]
id = "ghost"
kind = "exec"
program = "airlock-no-such-program-xyz"
action = "allow"
"#,
        );
        let mut gaps = Vec::new();
        let targets = exec_allow_targets(&policy, &mut gaps);
        assert!(targets.is_empty(), "{targets:?}");
        assert!(
            gaps.iter()
                .any(|g| g.contains("ghost") && g.contains("PATH")),
            "{gaps:?}"
        );
    }

    /// 화이트리스트가 실제로 강제하는 것을 gap 이라고 적으면 반대 방향의 거짓말입니다
    #[test]
    fn the_whitelist_does_not_declare_itself_unenforced() {
        let s = Scratch::new("gap");
        let policy = policy_with(
            &s.0,
            r#"
version = 1
[defaults]
file = "allow"
exec = "ask"
egress = "deny"
[[rules]]
id = "no-nc"
kind = "exec"
program = "/usr/bin/nc"
action = "deny"
"#,
        );

        let mut plan = Plan {
            exec_whitelist: true,
            ..Plan::default()
        };
        plan_exec_gap(&policy, &[], &mut plan);
        assert!(
            !plan
                .gaps
                .iter()
                .any(|g| g.contains("전부 실행할 수 있으며")),
            "화이트리스트가 걸린 상태에서 미강제라고 보고함: {:?}",
            plan.gaps
        );

        let mut legacy = Plan::default();
        plan_exec_gap(&policy, &[], &mut legacy);
        assert!(
            legacy.gaps.iter().any(|g| g.contains("no-nc")),
            "exec = \"allow\" 에서는 exec 제한이 커널 밖이라는 사실을 밝혀야 함: {:?}",
            legacy.gaps
        );
    }

    #[test]
    fn argv_conditions_stay_declared_as_a_gap() {
        let s = Scratch::new("argv");
        let policy = policy_with(
            &s.0,
            r#"
version = 1
[defaults]
file = "allow"
exec = "ask"
egress = "deny"
[[rules]]
id = "no-force-push"
kind = "exec"
program = "git"
argv_contains = ["--force"]
action = "deny"
"#,
        );
        let mut plan = Plan {
            exec_whitelist: true,
            ..Plan::default()
        };
        plan_exec_gap(&policy, &[], &mut plan);
        assert!(
            plan.gaps
                .iter()
                .any(|g| g.contains("argv") && g.contains("no-force-push")),
            "{:?}",
            plan.gaps
        );
    }

    /// 허용 트리 안의 제한은 Landlock 이 표현할 수 없습니다. 그것은 여전히 gap 입니다
    #[test]
    fn a_restriction_inside_a_granted_tree_is_declared() {
        let s = Scratch::new("tree-gap");
        let policy = policy_with(
            &s.0,
            r#"
version = 1
[defaults]
file = "allow"
exec = "ask"
egress = "deny"
[[rules]]
id = "no-nc"
kind = "exec"
program = "/usr/bin/nc"
action = "deny"
"#,
        );
        let mut plan = Plan {
            exec_whitelist: true,
            ..Plan::default()
        };
        plan_exec_gap(&policy, &[PathBuf::from("/usr")], &mut plan);
        assert!(
            plan.gaps
                .iter()
                .any(|g| g.contains("트리") && g.contains("no-nc")),
            "{:?}",
            plan.gaps
        );
    }

    /// 실행 계획은 읽기 경계를 넓히면 안 되고, 읽기 계획은 exec deny 때문에 좁아지면
    /// 안 됩니다. 두 계획이 같은 모드를 보면 어느 한쪽이 반드시 틀립니다
    #[test]
    fn the_exec_plan_and_the_read_plan_use_different_modes() {
        let s = Scratch::new("modes");
        let bin = s.0.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let ok = bin.join("ok");
        let blocked = bin.join("blocked");
        fs::write(&ok, b"x").unwrap();
        fs::write(&blocked, b"x").unwrap();

        let policy = policy_with(
            &s.0,
            &format!(
                r#"
version = 1
[defaults]
file = "allow"
exec = "ask"
egress = "deny"
[[rules]]
id = "no-exec-here"
kind = "file"
path = "{}"
mode = ["exec"]
action = "deny"
"#,
                blocked.display()
            ),
        );

        let mut walker = Walker::new(&policy);
        let mut plan = Plan {
            exec_whitelist: true,
            ..Plan::default()
        };
        add_root(&mut walker, &bin, PlanKind::Exec, &mut plan);

        assert!(
            plan.exec_paths.iter().any(|p| p.path == ok),
            "실행이 막히지 않은 파일은 허용되어야 함: {:?}",
            plan.exec_paths
        );
        assert!(
            !plan.exec_paths.iter().any(|p| p.path == blocked),
            "exec deny 가 걸린 파일이 실행 허용에 남음"
        );
        assert!(
            plan.list_only.is_empty(),
            "실행 계획이 읽기 권한(ReadDir)을 넓힘: {:?}",
            plan.list_only
        );

        // 같은 트리를 읽기로 계획하면 exec deny 는 아무것도 빼지 않아야 합니다
        let mut read_plan = Plan::default();
        add_root(&mut walker, &bin, PlanKind::Read, &mut read_plan);
        assert!(
            read_plan.read_only.iter().any(|p| p.path == bin),
            "exec deny 하나가 읽기 계획까지 좁힘: {read_plan:?}"
        );
    }
}
