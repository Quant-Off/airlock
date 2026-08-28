use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::baseline::{self, SelfProtectPaths};
use crate::digest;
use crate::dsl;
use crate::error::{LoadError, LoadWarning};
use crate::host::HostPattern;
use crate::model::{Action, Defaults, FileMode, Kind, Protocol, Tier};
use crate::path::{self as pathmod, NormalizedPath};
use crate::rule::{Matcher, Query, Rule};

/// 평문 바닥이 결정을 바꿨을 때 감사 로그와 explain 에 나가는 합성 규칙 id입니다.
///
/// 정책 파일이 쓸 수 없는 예약 id이며, 사용자 규칙이 같은 id를 쓰면 로드를 거부합니다.
/// 브로커의 `airlock:egress-proxy` 와 같은 `airlock:` 이름 공간입니다
pub const PLAINTEXT_FLOOR_ID: &str = "airlock:egress-plaintext";

/// 총량 한도가 결정을 바꿨을 때 감사 로그와 explain 에 나가는 합성 규칙 id입니다.
///
/// `PLAINTEXT_FLOOR_ID` 와 같은 이름 공간이며 사용자 규칙이 쓸 수 없습니다
pub const QUOTA_ID: &str = "airlock:egress-quota";

/// 엔진과 브로커가 만드는 합성 규칙 전용 이름 공간.
///
/// 사용자 규칙이 이 접두를 쓰면 감사 로그의 `rule` 필드만 보고 그 결정이 엔진이 씌운
/// 바닥인지 사람이 적은 규칙인지 알 수 없어집니다. 개별 id 를 하나씩 예약하는 대신 접두를
/// 통째로 막아 두면 나중에 늘어나는 합성 id 도 자동으로 보호됩니다
pub const RESERVED_PREFIX: &str = "airlock:";

#[derive(Debug, Clone)]
pub struct LoadContext {
    pub home: PathBuf,
    pub self_protect: SelfProtectPaths,
}

impl LoadContext {
    pub fn new(home: impl Into<PathBuf>, audit_root: impl Into<PathBuf>) -> Self {
        Self {
            home: home.into(),
            self_protect: SelfProtectPaths {
                audit_root: audit_root.into(),
                policy_files: Vec::new(),
                binary: None,
            },
        }
    }

    pub fn with_policy_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.self_protect.policy_files = vec![path.into()];
        self
    }

    /// 자기보호할 정책 파일 후보를 통째로 지정합니다.
    ///
    /// 탐색 후보는 아직 존재하지 않아도 막아야 합니다. 비어 있는 자리에 대상이 정책을
    /// 만들어 두면 다음 실행이 그것을 읽기 때문입니다.
    ///
    /// # Arguments
    /// `paths` - 막을 후보 경로 전체
    pub fn with_policy_files(mut self, paths: impl IntoIterator<Item = PathBuf>) -> Self {
        self.self_protect.policy_files = paths.into_iter().collect();
        self
    }

    pub fn with_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.self_protect.binary = Some(path.into());
        self
    }
}

/// 파일 규칙의 각 패턴에 해소된 표기를 하나씩 더합니다.
///
/// macOS 의 `/etc` -> `/private/etc` 같은 firmlink 때문입니다. 한쪽 표기로만 적힌 규칙은
/// 다른 표기의 요청을 만나면 매칭되지 않습니다.
///
/// # Arguments
/// `rule` - 패턴을 넓힐 규칙
fn add_resolved_variants(rule: &mut Rule) {
    let Matcher::File { paths, .. } = &mut rule.matcher else {
        return;
    };
    let mut extra: Vec<crate::glob::Pattern> = Vec::new();
    for p in paths.iter() {
        if let Some(v) = p.resolved_variant()
            && !paths.iter().any(|q| q.raw() == v.raw())
        {
            extra.push(v);
        }
    }
    paths.extend(extra);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRule {
    pub id: String,
    pub tier: Tier,
    pub action: Action,
    pub pattern: String,
    pub reason: Option<String>,
}

impl MatchedRule {
    fn of(rule: &Rule, query: &Query<'_>) -> Self {
        Self {
            id: rule.id.clone(),
            tier: rule.tier,
            action: rule.action,
            pattern: rule
                .matched_pattern(query)
                .unwrap_or_else(|| rule.matcher.describe()),
            reason: rule.reason.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub action: Action,
    pub rule: Option<MatchedRule>,
    pub path: Option<NormalizedPath>,
}

impl Evaluation {
    pub fn blocks(&self) -> bool {
        self.action.blocks()
    }

    pub fn needs_approval(&self) -> bool {
        self.action == Action::Ask
    }
}

#[derive(Debug, Clone)]
pub struct Policy {
    name: String,
    home: PathBuf,
    defaults: Defaults,
    self_protect: Vec<Rule>,
    baseline_forbid: Vec<Rule>,
    user: Vec<Rule>,
    baseline_rest: Vec<Rule>,
    baseline_all: Vec<Rule>,
    digest: [u8; 32],
    warnings: Vec<LoadWarning>,
}

impl Policy {
    pub fn baseline_only(ctx: &LoadContext) -> Result<Self, LoadError> {
        Self::build("baseline", Defaults::default(), Vec::new(), ctx)
    }

    pub fn load_str(src: &str, ctx: &LoadContext) -> Result<Self, LoadError> {
        let raw = dsl::parse(src)?;
        if raw.version != 1 {
            return Err(LoadError::UnsupportedVersion(raw.version));
        }

        let mut defaults = Defaults::default();
        if let Some(d) = &raw.defaults {
            if let Some(v) = &d.file {
                defaults.file = dsl::parse_action("[defaults].file", v)?;
            }
            if let Some(v) = &d.exec {
                defaults.exec = dsl::parse_action("[defaults].exec", v)?;
            }
            if let Some(v) = &d.egress {
                defaults.egress = dsl::parse_action("[defaults].egress", v)?;
            }
            if let Some(v) = &d.egress_plaintext {
                defaults.egress_plaintext = dsl::parse_action("[defaults].egress_plaintext", v)?;
            }
        }
        if defaults.egress == Action::Allow {
            return Err(LoadError::EgressDefaultAllow);
        }
        // egress_plaintext 의 allow 는 거부하지 않습니다. 여는 범위가 "모든 호스트"가
        // 아니라 "이미 허용된 호스트에 대한 평문"이라 훨씬 좁습니다. 대신 경고를 냅니다
        for (kind, action) in [
            ("file", defaults.file),
            ("exec", defaults.exec),
            ("egress", defaults.egress),
            ("egress_plaintext", defaults.egress_plaintext),
        ] {
            if action == Action::Forbid {
                return Err(LoadError::ForbidDefault { kind });
            }
        }

        let name = raw.name.clone().unwrap_or_else(|| "unnamed".to_string());
        let mut user = Vec::with_capacity(raw.rules.len());
        for r in raw.rules {
            user.push(dsl::to_rule(r, &ctx.home)?);
        }

        Self::build(&name, defaults, user, ctx)
    }

    /// 정책 파일을 읽어 로드합니다.
    ///
    /// # Errors
    /// 읽기에 실패하거나, 파일이 호출한 사용자의 것이 아니거나, 다른 사용자가 쓸 수 있으면
    /// 실패합니다. 정책 파일은 신뢰 경계 전체를 정의하므로 내용을 보기 전에 출처부터
    /// 확인합니다.
    pub fn load_file(path: &Path, ctx: &LoadContext) -> Result<Self, LoadError> {
        let src = crate::path::read_trusted(path)?;
        let ctx = LoadContext {
            home: ctx.home.clone(),
            self_protect: SelfProtectPaths {
                audit_root: ctx.self_protect.audit_root.clone(),
                policy_files: {
                    // 실제로 읽은 파일이 후보 목록에 없으면 더합니다
                    let mut v = ctx.self_protect.policy_files.clone();
                    if !v.iter().any(|p| p == path) {
                        v.push(path.to_path_buf());
                    }
                    v
                },
                binary: ctx.self_protect.binary.clone(),
            },
        };
        Self::load_str(&src, &ctx)
    }

    fn build(
        name: &str,
        defaults: Defaults,
        mut user: Vec<Rule>,
        ctx: &LoadContext,
    ) -> Result<Self, LoadError> {
        let mut base = baseline::build(&ctx.home).map_err(|source| LoadError::Pattern {
            id: "baseline".to_string(),
            source,
        })?;
        let mut self_protect = baseline::self_protect(&ctx.self_protect);

        // firmlink 로 다른 이름이 붙는 경로에 양쪽 표기를 모두 넣습니다. 티어를 가리지
        // 않고 적용해야 deny 가 비켜 가지도, allow 가 죽지도 않습니다
        for r in user
            .iter_mut()
            .chain(base.rules.iter_mut())
            .chain(self_protect.iter_mut())
        {
            add_resolved_variants(r);
        }

        // 내장 규칙 id는 예약어입니다. 겹치는 id를 허용하면 감사 로그의 rule 필드가
        // 어느 티어의 규칙을 가리키는지 알 수 없어집니다 (10절 3번)
        let reserved: Vec<(&str, &'static str)> = base
            .rules
            .iter()
            .map(|r| (r.id.as_str(), "베이스라인"))
            .chain(self_protect.iter().map(|r| (r.id.as_str(), "자기보호")))
            .chain(std::iter::once((PLAINTEXT_FLOOR_ID, "평문 바닥")))
            .collect();

        let mut seen: HashSet<&str> = HashSet::new();
        for r in &user {
            if !seen.insert(r.id.as_str()) {
                return Err(LoadError::DuplicateId(r.id.clone()));
            }
            if let Some((_, tier)) = reserved.iter().find(|(id, _)| *id == r.id.as_str()) {
                return Err(LoadError::ReservedId {
                    id: r.id.clone(),
                    tier,
                });
            }
            // 알려진 합성 id 뿐 아니라 이름 공간 전체를 막습니다. 나중에 늘어나는 합성 id
            // 하나를 예약 목록에 넣는 것을 잊어도 사용자가 그 이름을 가져갈 수 없습니다
            if r.id.starts_with(RESERVED_PREFIX) {
                return Err(LoadError::ReservedNamespace { id: r.id.clone() });
            }
            if r.action == Action::Forbid {
                return Err(LoadError::ForbidInUserRule { id: r.id.clone() });
            }
            // host = "*"를 allow하면 [defaults].egress = "allow"와 실효가 같습니다.
            // 2.2절이 문법 수준에서 막은 설정을 다른 문으로 들어와 세우는 것을 막습니다
            if r.action == Action::Allow
                && let Matcher::Egress {
                    host: HostPattern::Any,
                    ..
                } = &r.matcher
            {
                return Err(LoadError::WildcardHostAllow { id: r.id.clone() });
            }
        }

        let forbid_ids: HashSet<&str> = base
            .rules
            .iter()
            .filter(|r| r.action == Action::Forbid)
            .map(|r| r.id.as_str())
            .collect();

        for r in &user {
            if let Some(target) = &r.overrides {
                if !base.rules.iter().any(|b| &b.id == target) {
                    return Err(LoadError::UnknownOverrideTarget {
                        id: r.id.clone(),
                        target: target.clone(),
                    });
                }
                if !forbid_ids.contains(target.as_str()) {
                    return Err(LoadError::OverrideTargetNotForbid {
                        id: r.id.clone(),
                        target: target.clone(),
                    });
                }
                if r.reason.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(LoadError::OverrideWithoutReason { id: r.id.clone() });
                }
            }
        }

        // overrides가 실제로 무언가를 완화하는지는 그 규칙 자신이 닿는 범위로 판정합니다.
        // forbid의 probe 경로로 판정하면 probe를 비껴가는 정당한 완화가 무효로 보고됩니다
        let mut used_overrides: HashSet<String> = HashSet::new();
        for r in &user {
            let Some(target_id) = &r.overrides else {
                continue;
            };
            let Some(target) = base.rules.iter().find(|b| &b.id == target_id) else {
                continue;
            };
            if overlaps(r, target) {
                used_overrides.insert(r.id.clone());
            }
        }

        let mut ineffective: Vec<LoadWarning> = Vec::new();
        for probe in &base.probes {
            for mode in FileMode::ALL {
                let q = Query::File {
                    path: &probe.path,
                    mode,
                };
                let Some(hit) = user.iter().find(|r| r.matches(&q)) else {
                    continue;
                };
                if !matches!(hit.action, Action::Allow | Action::Ask) {
                    continue;
                }
                match &hit.overrides {
                    Some(t) if t == probe.rule_id => {}
                    _ => {
                        let warning = LoadWarning::IneffectiveRelaxation {
                            id: hit.id.clone(),
                            forbid_id: probe.rule_id.to_string(),
                            probe: probe.path.clone(),
                        };
                        if !ineffective.contains(&warning) {
                            ineffective.push(warning);
                        }
                    }
                }
            }
        }

        let digest = digest::compute(&defaults, &user, &base.rules);

        let mut warnings = collect_warnings(&defaults, &user, &used_overrides);
        warnings.extend(ineffective);

        let (baseline_forbid, baseline_rest): (Vec<Rule>, Vec<Rule>) = base
            .rules
            .iter()
            .cloned()
            .partition(|r| r.action == Action::Forbid);

        Ok(Self {
            name: name.to_string(),
            home: ctx.home.clone(),
            defaults,
            self_protect,
            baseline_forbid,
            user,
            baseline_rest,
            baseline_all: base.rules,
            digest,
            warnings,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn defaults(&self) -> Defaults {
        self.defaults
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn warnings(&self) -> &[LoadWarning] {
        &self.warnings
    }

    pub fn rule_count(&self) -> usize {
        self.self_protect
            .len()
            .saturating_add(self.user.len())
            .saturating_add(self.baseline_all.len())
    }

    pub fn user_rules(&self) -> &[Rule] {
        &self.user
    }

    pub fn baseline_rules(&self) -> &[Rule] {
        &self.baseline_all
    }

    pub fn self_protect_rules(&self) -> &[Rule] {
        &self.self_protect
    }

    fn lookup<'a>(&'a self, query: &Query<'_>) -> (Action, Option<&'a Rule>) {
        if let Some(rule) = self.self_protect.iter().find(|r| r.matches(query)) {
            return (rule.action, Some(rule));
        }

        let mut matched_forbid = self
            .baseline_forbid
            .iter()
            .filter(|r| r.matches(query))
            .peekable();
        if matched_forbid.peek().is_some() {
            let mut relaxation: Option<&Rule> = None;
            for forbid in matched_forbid {
                let named = self.user.iter().find(|u| {
                    u.overrides.as_deref() == Some(forbid.id.as_str()) && u.matches(query)
                });
                match named {
                    // 매칭된 forbid 하나라도 지목되지 않았으면 그 forbid가 이깁니다.
                    // 겹치는 보호를 지목 없이 함께 푸는 경로를 막습니다
                    None => return (forbid.action, Some(forbid)),
                    Some(u) => {
                        if relaxation.is_none() {
                            relaxation = Some(u);
                        }
                    }
                }
            }
            if let Some(u) = relaxation {
                return (u.action, Some(u));
            }
        }

        for tier in [&self.user, &self.baseline_rest] {
            if let Some(rule) = tier.iter().find(|r| r.matches(query)) {
                return (rule.action, Some(rule));
            }
        }

        (self.defaults.for_kind(query.kind()), None)
    }

    pub fn evaluate_file(&self, raw: &Path, mode: FileMode, cwd: &Path) -> Evaluation {
        let np = pathmod::normalize(raw, cwd, &self.home);
        let requested_query = Query::File {
            path: &np.requested,
            mode,
        };
        let (requested_action, requested_rule) = self.lookup(&requested_query);
        let (action, rule) = if np.diverges() {
            let resolved_query = Query::File {
                path: &np.resolved,
                mode,
            };
            let (resolved_action, resolved_rule) = self.lookup(&resolved_query);
            if resolved_action > requested_action {
                (
                    resolved_action,
                    resolved_rule.map(|r| MatchedRule::of(r, &resolved_query)),
                )
            } else {
                (
                    requested_action,
                    requested_rule.map(|r| MatchedRule::of(r, &requested_query)),
                )
            }
        } else {
            (
                requested_action,
                requested_rule.map(|r| MatchedRule::of(r, &requested_query)),
            )
        };

        Evaluation {
            action,
            rule,
            path: Some(np),
        }
    }

    /// 이미 해소된 절대 경로를 심볼릭 링크 해소 없이 평가합니다.
    ///
    /// 강제 층이 실제 디렉토리 항목을 순회하며 허용 계획을 세울 때 씁니다. 항목마다
    /// `canonicalize`를 부르면 큰 작업 공간에서 시작 시간이 초 단위로 늘어납니다.
    ///
    /// # Errors
    /// 경로가 이미 절대 경로이고 해소된 상태임을 호출자가 보장해야 합니다. 보장이
    /// 깨지면 4.1절의 양방향 평가가 생략되어 링크 우회를 놓칩니다. inode에 규칙을
    /// 거는 Landlock처럼 링크 우회가 구조적으로 불가능한 백엔드에서만 씁니다
    pub fn evaluate_resolved_file(&self, path: &Path, mode: FileMode) -> Evaluation {
        let query = Query::File { path, mode };
        let (action, rule) = self.lookup(&query);
        Evaluation {
            action,
            rule: rule.map(|r| MatchedRule::of(r, &query)),
            path: None,
        }
    }

    pub fn evaluate_exec(&self, program: &Path, argv: &[String], cwd: &Path) -> Evaluation {
        let np = pathmod::normalize(program, cwd, &self.home);
        let requested_query = Query::Exec {
            program: &np.requested,
            argv,
        };
        let (requested_action, requested_rule) = self.lookup(&requested_query);
        let (action, rule) = if np.diverges() {
            let resolved_query = Query::Exec {
                program: &np.resolved,
                argv,
            };
            let (resolved_action, resolved_rule) = self.lookup(&resolved_query);
            if resolved_action > requested_action {
                (
                    resolved_action,
                    resolved_rule.map(|r| MatchedRule::of(r, &resolved_query)),
                )
            } else {
                (
                    requested_action,
                    requested_rule.map(|r| MatchedRule::of(r, &requested_query)),
                )
            }
        } else {
            (
                requested_action,
                requested_rule.map(|r| MatchedRule::of(r, &requested_query)),
            )
        };

        Evaluation {
            action,
            rule,
            path: Some(np),
        }
    }

    /// 아웃바운드 연결 하나를 판정합니다.
    ///
    /// 누적 반출량을 모르는 호출부용입니다. 총량 한도는 발동하지 않습니다.
    ///
    /// # Arguments
    /// `host` - 관측된 호스트 문자열. 정규화는 이 안에서 함
    /// `port` - 목적지 포트
    /// `protocol` - 관측 층이 판단한 프로토콜. 중계 층은 항상 `Tcp`를 넘김
    pub fn evaluate_egress(&self, host: &str, port: u16, protocol: Protocol) -> Evaluation {
        self.evaluate_egress_with_usage(host, port, protocol, 0)
    }

    /// 아웃바운드 연결 하나를 누적 반출량과 함께 판정합니다.
    ///
    /// 4티어 평가가 끝난 뒤 두 바닥을 순서대로 씌웁니다. 먼저 매칭된 규칙의
    /// `max_bytes_out` 한도를 보고(8.4절), 그다음 평문 질의에 한해
    /// [`Defaults::egress_plaintext`] 바닥을 봅니다(8.2절).
    ///
    /// 판정 지점을 여기 하나로 두는 것이 핵심입니다. 브로커가 따로 한도를 검사하면 두
    /// 지점이 언젠가 갈라지고, 갈라지는 순간 감사 로그가 거짓 보증을 합니다.
    ///
    /// # Arguments
    /// `host` - 관측된 호스트 문자열. 정규화는 이 안에서 함
    /// `port` - 목적지 포트
    /// `protocol` - 관측 층이 판단한 프로토콜. 중계 층은 항상 `Tcp`를 넘김
    /// `bytes_out` - 이 세션에서 이 목적지로 이미 반출한 누적 바이트
    pub fn evaluate_egress_with_usage(
        &self,
        host: &str,
        port: u16,
        protocol: Protocol,
        bytes_out: u64,
    ) -> Evaluation {
        let query = Query::Egress {
            host,
            port,
            protocol,
        };
        let (action, matched) = self.lookup(&query);
        let declares_protocol = matches!(
            matched.map(|r| &r.matcher),
            Some(Matcher::Egress {
                protocol: Some(_),
                ..
            })
        );
        let rule = matched.map(|r| MatchedRule::of(r, &query));

        // 총량 한도. 바이트 수는 연결이 끝나야 알 수 있으므로 한도를 넘긴 그 연결 자체는
        // 막지 못하고 다음 연결부터 막힙니다. 초과 시 결정은 deny 로 고정합니다. ask 로
        // 두면 --yes 자동 승인이 한도를 그대로 무력화합니다
        if let Some(Matcher::Egress {
            max_bytes_out: Some(limit),
            ..
        }) = matched.map(|r| &r.matcher)
            && bytes_out > *limit
        {
            let floored = action.more_restrictive(Action::Deny);
            if floored != action {
                return Evaluation {
                    action: floored,
                    rule: Some(quota_rule(
                        floored,
                        rule.as_ref(),
                        host,
                        port,
                        *limit,
                        bytes_out,
                    )),
                    path: None,
                };
            }
        }

        // 호스트만 적은 allow 가 평문까지 암묵 허가하면 안 됩니다. 평문을 열려면 사람이
        // 규칙에 protocol = "http" 라고 직접 적어야 합니다
        if protocol.is_plaintext() && !declares_protocol {
            let floored = action.more_restrictive(self.defaults.egress_plaintext);
            if floored != action {
                return Evaluation {
                    action: floored,
                    rule: Some(plaintext_floor_rule(floored, rule.as_ref(), host, port)),
                    path: None,
                };
            }
        }

        Evaluation {
            action,
            rule,
            path: None,
        }
    }
}

/// 총량 한도가 내린 결정을 규칙 하나로 표현합니다.
///
/// 한도와 실제 누적량을 매칭 표기에 남깁니다. 감사 로그만 보고 "무엇이 얼마를 넘겨서
/// 막혔는가" 를 알 수 있어야 하기 때문입니다.
///
/// # Arguments
/// `action` - 한도를 씌운 뒤의 결정
/// `matched` - 한도를 씌우기 전에 답한 규칙
/// `host` - 질의 호스트
/// `port` - 질의 포트
/// `limit` - 규칙이 적은 한도
/// `used` - 이 세션에서 이 목적지로 이미 반출한 누적 바이트
fn quota_rule(
    action: Action,
    matched: Option<&MatchedRule>,
    host: &str,
    port: u16,
    limit: u64,
    used: u64,
) -> MatchedRule {
    let origin = matched
        .map(|m| m.id.as_str())
        .unwrap_or("[defaults].egress");
    MatchedRule {
        id: QUOTA_ID.to_string(),
        tier: Tier::Baseline,
        action,
        pattern: format!("{host}:{port} [max_bytes_out={limit} used={used}] <- {origin}"),
        reason: Some(
            "이 목적지로 누적 반출한 바이트가 max_bytes_out 을 넘음. 바이트 수는 연결이 끝나야 \
             알 수 있으므로 한도를 넘긴 그 연결 자체는 막지 못했고 이번 연결부터 막힘"
                .to_string(),
        ),
    }
}

/// 평문 바닥이 내린 결정을 규칙 하나로 표현합니다.
///
/// 원래 매칭된 규칙의 id를 매칭 표기 안에 남깁니다. 어느 규칙이 평문을 열려다 막혔는지
/// 감사 로그만 보고 알 수 있어야 하기 때문입니다.
///
/// # Arguments
/// `action` - 바닥을 씌운 뒤의 결정
/// `matched` - 바닥을 씌우기 전에 답한 규칙. 없으면 `[defaults]`가 답한 것임
/// `host` - 질의 호스트
/// `port` - 질의 포트
fn plaintext_floor_rule(
    action: Action,
    matched: Option<&MatchedRule>,
    host: &str,
    port: u16,
) -> MatchedRule {
    let pattern = match matched {
        Some(m) => format!("{} [http] <- {}", m.pattern, m.id),
        None => format!("{host}:{port} [http] <- [defaults].egress"),
    };
    MatchedRule {
        id: PLAINTEXT_FLOOR_ID.to_string(),
        tier: Tier::Baseline,
        action,
        pattern,
        reason: Some(
            "평문 아웃바운드는 [defaults].egress_plaintext 가 정한 바닥을 넘지 못함. \
             열려면 그 규칙에 protocol = \"http\" 를 명시할 것"
                .to_string(),
        ),
    }
}

fn collect_warnings(
    defaults: &Defaults,
    user: &[Rule],
    used_overrides: &HashSet<String>,
) -> Vec<LoadWarning> {
    let mut warnings = Vec::new();

    if defaults.egress_plaintext == Action::Allow {
        warnings.push(LoadWarning::PlaintextEgressAllowed);
    }

    for r in user {
        if let Some(target) = &r.overrides
            && !used_overrides.contains(&r.id)
        {
            warnings.push(LoadWarning::UnusedOverride {
                id: r.id.clone(),
                target: target.clone(),
            });
        }
        if let Matcher::Egress { host, protocol, .. } = &r.matcher {
            // 포트 단위까지만 강제하는 백엔드는 주소 단위 규칙을 표현할 수 없습니다.
            // IP 리터럴도 도메인 패턴과 마찬가지입니다. `*`는 전면 차단이라 표현 가능합니다
            if matches!(
                host,
                HostPattern::Exact(_) | HostPattern::Suffix(_) | HostPattern::Ip(_)
            ) {
                warnings.push(LoadWarning::HostRuleNeedsProxy { id: r.id.clone() });
            }
            // 중계 층은 connect(2)만 보고 모든 연결을 Tcp로 보고합니다
            // (docs/limitations.md 5.12). 프로토콜 조건은 프록시가 있어야 의미가 생깁니다
            if protocol.is_some() {
                warnings.push(LoadWarning::ProtocolRuleNeedsProxy { id: r.id.clone() });
            }
        }
        // 반출 바이트는 프록시 층만 셉니다. 중계 층은 connect(2) 만 보므로 누적량이 늘 0
        // 이고 한도가 한 번도 걸리지 않습니다
        if let Matcher::Egress {
            max_bytes_out: Some(_),
            ..
        } = &r.matcher
        {
            warnings.push(LoadWarning::QuotaRuleNeedsProxy { id: r.id.clone() });
        }
    }

    for (i, rule) in user.iter().enumerate() {
        let earlier = user.get(..i).unwrap_or(&[]);
        if let Some(by) = shadowed_by(rule, earlier) {
            warnings.push(LoadWarning::ShadowedRule {
                id: rule.id.clone(),
                by,
            });
        }
    }

    warnings
}

fn overlaps(rule: &Rule, target: &Rule) -> bool {
    let Matcher::File { paths, modes } = &rule.matcher else {
        return false;
    };
    paths.iter().any(|pattern| {
        let witness = pattern.witness();
        modes.iter().any(|mode| {
            target.matches(&Query::File {
                path: &witness,
                mode,
            })
        })
    })
}

fn egress_witness(host: &HostPattern) -> String {
    match host {
        HostPattern::Any => "airlock-witness.invalid".to_string(),
        HostPattern::Exact(h) => h.clone(),
        HostPattern::Suffix(s) => format!("airlock-witness.{s}"),
        HostPattern::Ip(ip) => ip.to_string(),
    }
}

/// 규칙이 앞선 규칙들에 **완전히** 가려져 도달 불가능한지 봅니다.
///
/// 대표 경로(witness) 하나라도 앞선 규칙이 덮지 못하면 그 규칙은 도달 가능하므로
/// 경고하지 않습니다. 하나만 덮여도 경고하면 좁은 규칙 뒤에 넓은 규칙을 두는
/// 정상적인 정책이 전부 오탐이 됩니다 (10절)
fn shadowed_by(rule: &Rule, earlier: &[Rule]) -> Option<String> {
    match &rule.matcher {
        Matcher::File { paths, modes } => {
            let mut covered_by: Option<String> = None;
            for pattern in paths {
                let witness = pattern.witness();
                for mode in modes.iter() {
                    let q = Query::File {
                        path: &witness,
                        mode,
                    };
                    let prev = earlier.iter().find(|p| p.matches(&q))?;
                    covered_by.get_or_insert_with(|| prev.id.clone());
                }
            }
            covered_by
        }
        Matcher::Egress {
            host,
            port,
            protocol,
            // 한도는 매칭 여부를 바꾸지 않으므로 도달 가능성 판정에 쓰이지 않습니다
            max_bytes_out: _,
        } => {
            let witness = egress_witness(host);
            let probe_port = port.unwrap_or(443);
            let probe_protocol = protocol.unwrap_or(Protocol::Tcp);
            let q = Query::Egress {
                host: &witness,
                port: probe_port,
                protocol: probe_protocol,
            };
            // 포트나 프로토콜을 생략한 규칙은 그 축 전체를 덮으므로, 앞선 규칙이 그것을
            // 덮으려면 마찬가지로 생략했거나 같은 값이어야 합니다
            earlier
                .iter()
                .find(|p| {
                    p.matches(&q)
                        && !matches!(
                            (&p.matcher, port),
                            (Matcher::Egress { port: Some(_), .. }, None)
                        )
                        && !matches!(
                            (&p.matcher, protocol),
                            (
                                Matcher::Egress {
                                    protocol: Some(_),
                                    ..
                                },
                                None
                            )
                        )
                })
                .map(|p| p.id.clone())
        }
        Matcher::Exec { .. } => earlier
            .iter()
            .find(|p| p.kind() == rule.kind() && p.matcher == rule.matcher)
            .map(|p| p.id.clone()),
    }
}

pub fn describe_kind(kind: Kind) -> &'static str {
    kind.as_str()
}
