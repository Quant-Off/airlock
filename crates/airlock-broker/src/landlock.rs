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
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use airlock_audit::Enforcement;
use airlock_policy::rule::Matcher;
use airlock_policy::{Action, FileMode, Policy};
use landlock::{
    ABI, Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
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

#[derive(Debug, Clone, Default)]
struct Plan {
    read_only: Vec<PathBuf>,
    read_write: Vec<PathBuf>,
    list_only: Vec<PathBuf>,
    tcp_connect: BTreeSet<u16>,
    tcp_bind: BTreeSet<u16>,
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
/// 결정이 달라지지 않고, 확실히 무관한 항목만 걸러 냅니다
#[derive(Debug, Default)]
struct Prefilter {
    /// 구체 경로로 고정된 규칙의 접두
    anchors: Vec<PathBuf>,
    /// `**`로 시작해 어디서든 매칭될 수 있는 규칙의 마지막 세그먼트 리터럴 접두
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
                            Some(SegmentKind::Literal(b)) => out.anywhere.push(b.to_vec()),
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
                                    out.anywhere.push(lit);
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
                            out.anchors.push(anchor);
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
            let name = name.as_bytes();
            let lower: Vec<u8> = name.to_ascii_lowercase();
            if self
                .anywhere
                .iter()
                .any(|p| lower.starts_with(&p.to_ascii_lowercase()))
            {
                return true;
            }
        }
        // 규칙 접두가 이 경로 아래에 있거나, 이 경로가 규칙 접두 아래에 있으면 평가합니다
        self.anchors
            .iter()
            .any(|a| path.starts_with(a) || a.starts_with(path))
    }
}

struct Walker<'a> {
    policy: &'a Policy,
    filter: Prefilter,
    budget: usize,
    exhausted: Vec<PathBuf>,
}

impl<'a> Walker<'a> {
    fn new(policy: &'a Policy) -> Self {
        Self {
            policy,
            filter: Prefilter::build(policy),
            budget: WALK_BUDGET,
            exhausted: Vec::new(),
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
            // 열 수 없는 디렉토리는 하위를 확인할 수 없습니다. 통째로 주지 않습니다
            return Grant::Whole;
        };

        let mut children: Vec<(PathBuf, bool)> = Vec::new();
        for entry in entries.flatten() {
            if self.budget == 0 {
                self.exhausted.push(dir.to_path_buf());
                return Grant::Partial;
            }
            self.budget = self.budget.saturating_sub(1);
            let path = entry.path();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            children.push((path, is_dir));
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
                plan.read_write.push(path.clone());
            } else {
                plan.read_only.push(path.clone());
            }
        }
        // 상위는 나열만 허용합니다. 이름은 보이지만 내용은 열리지 않으며,
        // Seatbelt 프로파일이 file-read-metadata를 여는 것과 같은 수준입니다
        plan.list_only.push(dir.to_path_buf());
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
                plan.read_write.push(root.to_path_buf());
            } else {
                plan.read_only.push(root.to_path_buf());
            }
        }
        Grant::Partial => plan.list_only.push(root.to_path_buf()),
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
            plan.read_write.push(path.to_path_buf());
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
        for path in paths {
            let Ok(fd) = PathFd::new(path) else {
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
        for port in &plan.tcp_bind {
            created = created
                .add_rule(NetPort::new(*port, AccessNet::BindTcp))
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
