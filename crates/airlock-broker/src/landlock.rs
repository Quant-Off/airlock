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

use std::collections::BTreeSet;
use std::ffi::{CString, OsStr};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use airlock_audit::Enforcement;
use airlock_policy::rule::Matcher;
use airlock_policy::{Action, FileMode, Policy};
use landlock::{
    ABI, Access, AccessFs, AccessNet, NetPort, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};

use crate::enforcer::Enforcer;
use crate::error::{BrokerError, Result};
use crate::profile::ProfileOptions;

/// 걸어 내려가며 검사할 최대 디렉토리 항목 수.
///
/// 예산을 넘기면 남은 하위 트리를 허용하지 않고 gap으로 보고합니다. 넘겨서 통째로
/// 허용하면 그 안의 시크릿이 열리므로 제한 방향으로 실패시킵니다
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

const DEV_RW_PATHS: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
];

fn read_access(abi: ABI) -> landlock::BitFlags<AccessFs> {
    AccessFs::from_read(abi)
}

fn full_access(abi: ABI) -> landlock::BitFlags<AccessFs> {
    AccessFs::from_all(abi)
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
}

impl PlanPath {
    /// 설정에서 온 루트. 링크 해소를 허용합니다
    fn root(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            follow: true,
        }
    }

    /// 순회 중 발견한 항목. 링크 해소를 금지합니다
    fn child(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            follow: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Plan {
    read_only: Vec<PlanPath>,
    read_write: Vec<PlanPath>,
    list_only: Vec<PlanPath>,
    tcp_connect: BTreeSet<u16>,
    unrestricted_net: bool,
    gaps: Vec<String>,
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
    budget: usize,
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
            budget: WALK_BUDGET,
            exhausted: Vec::new(),
            unreadable: Vec::new(),
            links: 0,
        }
    }

    /// 이 경로를 허용 계획에서 빼야 하는지 봅니다.
    ///
    /// 실제로 매칭된 **규칙**이 막을 때만 뺍니다. 매칭되는 규칙이 없어 `[defaults]`로
    /// 떨어진 경우는 빼지 않습니다. 시스템 경로와 작업 공간은 프로그램이 뜨기 위한
    /// 기반이고, Seatbelt 프로파일도 이를 먼저 열어 둔 뒤 정책 deny를 덧씌웁니다.
    /// 기본값까지 여기서 반영하면 `[defaults].file = "ask"`인 베이스라인 정책에서
    /// 아무것도 허용되지 않아 프로세스가 exec조차 하지 못합니다
    fn blocked(&self, path: &Path, writable: bool) -> bool {
        if !self.filter.may_match(path) {
            return false;
        }
        let modes: &[FileMode] = if writable {
            &[FileMode::Read, FileMode::Write]
        } else {
            &[FileMode::Read]
        };
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
    fn walk(&mut self, dir: &Path, writable: bool, plan: &mut Plan) -> Grant {
        if self.blocked(dir, writable) {
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
        for entry in entries.flatten() {
            if self.budget == 0 {
                self.exhausted.push(dir.to_path_buf());
                return Grant::Partial;
            }
            self.budget = self.budget.saturating_sub(1);
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

        let mut partial: Vec<PathBuf> = Vec::new();
        let mut any_denied = false;

        for (path, is_dir) in &children {
            if *is_dir {
                match self.walk(path, writable, plan) {
                    Grant::Whole => {}
                    Grant::Partial => partial.push(path.clone()),
                    Grant::Denied => any_denied = true,
                }
            } else if self.blocked(path, writable) {
                any_denied = true;
            }
        }

        if !any_denied && partial.is_empty() {
            return Grant::Whole;
        }

        // 이 디렉토리는 통째로 줄 수 없습니다. 허용 가능한 자식만 개별로 줍니다
        for (path, _) in &children {
            if partial.iter().any(|p| p == path) {
                continue;
            }
            if self.blocked(path, writable) {
                continue;
            }
            if writable {
                plan.read_write.push(PlanPath::child(path));
            } else {
                plan.read_only.push(PlanPath::child(path));
            }
        }
        // 상위는 나열만 허용합니다. 이름은 보이지만 내용은 열리지 않으며,
        // Seatbelt 프로파일이 file-read-metadata를 여는 것과 같은 수준입니다
        plan.list_only.push(PlanPath::child(dir));
        Grant::Partial
    }
}

fn add_root(walker: &mut Walker<'_>, root: &Path, writable: bool, plan: &mut Plan) {
    if !root.exists() {
        return;
    }
    match walker.walk(root, writable, plan) {
        Grant::Whole => {
            if writable {
                plan.read_write.push(PlanPath::root(root));
            } else {
                plan.read_only.push(PlanPath::root(root));
            }
        }
        Grant::Partial => plan.list_only.push(PlanPath::root(root)),
        Grant::Denied => {}
    }
}

fn build_plan(policy: &Policy, opts: &ProfileOptions) -> Plan {
    let mut plan = Plan::default();
    let mut walker = Walker::new(policy);

    for p in SYSTEM_READ_PATHS {
        add_root(&mut walker, Path::new(p), false, &mut plan);
    }
    for p in DEV_RW_PATHS {
        let path = Path::new(p);
        if path.exists() {
            plan.read_write.push(PlanPath::root(path));
        }
    }
    for dir in &opts.temp_dirs {
        add_root(&mut walker, dir, true, &mut plan);
    }
    if let Some(ws) = &opts.workspace {
        add_root(&mut walker, ws, true, &mut plan);
    }

    // 정책이 명시적으로 allow 한 파일 경로 중 구체 경로를 추가로 엽니다
    for rule in policy.user_rules() {
        if rule.action != Action::Allow {
            continue;
        }
        let Matcher::File { paths, .. } = &rule.matcher else {
            continue;
        };
        for pattern in paths {
            let raw = pattern.raw();
            if raw.contains('*') || raw.contains('?') {
                continue;
            }
            let candidate = pattern.witness();
            if candidate.exists() {
                add_root(&mut walker, &candidate, true, &mut plan);
            }
        }
    }

    for dir in walker.exhausted.iter().take(5) {
        plan.gaps.push(format!(
            "{} 아래는 검사 예산({WALK_BUDGET} 항목)을 넘겨 허용하지 않았음. 필요하면 작업 공간을 좁혀야 함",
            dir.display()
        ));
    }
    for dir in walker.unreadable.iter().take(5) {
        plan.gaps.push(format!(
            "{} 는 나열할 수 없어 하위를 검사하지 못했음. 통째로 허용하지 않았으므로 그 아래는 열리지 않음",
            dir.display()
        ));
    }
    if walker.links > 0 {
        plan.gaps.push(format!(
            "심볼릭 링크 {}개를 허용 계획에서 제외했음. 규칙이 inode 에 걸리므로 \
             링크가 가리키는 대상이 따로 허용되지 않으면 링크로도 열리지 않음",
            walker.links
        ));
    }

    plan_network(policy, opts, &mut plan);
    plan
}

fn plan_network(policy: &Policy, opts: &ProfileOptions, plan: &mut Plan) {
    if !opts.allow_network {
        return;
    }

    let mut host_scoped = Vec::new();
    for rule in policy.user_rules() {
        let Matcher::Egress { host, port } = &rule.matcher else {
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
    }

    if plan.tcp_connect.is_empty() && !plan.unrestricted_net {
        // 아웃바운드 allow 규칙이 하나도 없습니다. TCP를 통째로 막습니다
        return;
    }

    if !host_scoped.is_empty() {
        plan.gaps.push(format!(
            "호스트 단위 egress 규칙은 Landlock으로 강제되지 않음. 포트까지만 강제하며 \
             호스트 판정은 프록시 층이 필요함: {}",
            host_scoped.join(", ")
        ));
    }
}

#[derive(Debug)]
pub struct LandlockEnforcer {
    options: ProfileOptions,
    plan: Option<Plan>,
    abi: ABI,
    gaps: Vec<String>,
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
    const MSG: &str =
        "airlock: 경고 커널이 Landlock 규칙을 부분만 적용했음. 일부 접근 종류가 강제되지 않음\n";
    unsafe {
        libc::write(2, MSG.as_ptr().cast(), MSG.len());
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

    let mut created = ruleset.create().map_err(std::io::Error::other)?;

    for (paths, access) in [
        (&plan.read_only, read_access(abi)),
        (&plan.read_write, full_access(abi)),
        (&plan.list_only, list_access()),
    ] {
        for target in paths {
            let Some(fd) = open_rule_target(target) else {
                continue;
            };
            created = created
                .add_rule(PathBeneath::new(fd, access))
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
            ABI::Unsupported => "landlock (커널 미지원)".to_string(),
            abi => format!(
                "landlock (ABI v{}, 규칙 {}개)",
                abi as u32,
                self.rule_count()
            ),
        }
    }

    fn prepare(&mut self, policy: &Policy) -> Result<()> {
        if self.abi == ABI::Unsupported {
            return Err(BrokerError::EnforcerUnavailable {
                name: "landlock",
                why: "커널이 Landlock을 지원하지 않음. Linux 5.13 이상이 필요함".to_string(),
            });
        }
        let plan = build_plan(policy, &self.options);
        self.gaps = plan.gaps.clone();
        self.plan = Some(plan);
        Ok(())
    }

    fn wrap(&self, cmd: &mut Command) -> Result<()> {
        let Some(plan) = self.plan.clone() else {
            return Err(BrokerError::EnforcerUnavailable {
                name: "landlock",
                why: "prepare가 먼저 호출되지 않았음".to_string(),
            });
        };
        let abi = self.abi;

        use std::os::unix::process::CommandExt;
        // # Safety
        // pre_exec은 fork 이후 exec 이전의 자식에서 실행됩니다. 브로커는 spawn 시점에
        // 단일 스레드이므로 malloc 락 경합이 없습니다. 계획은 fork 전에 확정한 경로 목록이며
        // 자식에서는 그 경로를 열어 규칙으로 거는 일만 합니다. restrict_self는 호출한
        // 스레드에만 걸리는데, exec 직전의 자식은 스레드가 하나뿐이라 전체에 걸립니다
        unsafe {
            cmd.pre_exec(move || {
                let status = apply(&plan, abi)?;
                if status == RulesetStatus::NotEnforced {
                    return Err(std::io::Error::other(
                        "Landlock 규칙이 적용되지 않았음. 강제 없이 실행하지 않음",
                    ));
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
            "ask 규칙은 커널에서 표현할 수 없으므로 Landlock 계획에서 deny로 내려감".to_string(),
            "Landlock이 커널에서 거부한 접근 자체는 감사 로그에 남지 않음. \
             체인에는 중계 층이 관측한 것만 기록됨"
                .to_string(),
        ];
        if self.abi < ABI::V4 {
            gaps.push(format!(
                "ABI v{}는 TCP 포트 규칙을 지원하지 않음(v4 필요). 아웃바운드가 강제되지 않음",
                self.abi as u32
            ));
        }
        gaps.push(
            "UDP는 Landlock ABI v10부터이며 크레이트가 아직 노출하지 않음. \
             UDP 아웃바운드는 강제되지 않음"
                .to_string(),
        );
        gaps.extend(self.gaps.iter().cloned());
        gaps
    }
}
