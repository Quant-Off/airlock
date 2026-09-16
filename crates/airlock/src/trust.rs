use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use airlock_canonical::display::sanitize;
use airlock_i18n::tr;
use airlock_policy::Policy;

pub const TRUST_FILE: &str = "trusted-policies.jsonl";
pub const TRUST_VERSION: u64 = 1;

const DIGEST_HEX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRecord {
    pub path: PathBuf,
    pub digest: String,
    pub trusted_at: String,
    pub uid: u32,
}

#[derive(Debug)]
pub enum TrustState {
    Absent,
    Loaded(Vec<TrustRecord>),
    Distrusted(String),
}

#[derive(Debug)]
pub struct TrustStore {
    path: PathBuf,
    state: TrustState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    Matched(TrustRecord),
    Approved(TrustRecord),
}

impl Gate {
    pub fn record(&self) -> &TrustRecord {
        match self {
            Self::Matched(r) | Self::Approved(r) => r,
        }
    }
}

/// 실제 uid 입니다. 정책 파일에 적용하는 `read_trusted` 와 같은 축을 봅니다.
///
/// # Safety
/// `getuid(2)` 는 인자가 없고 메모리를 건드리지 않으며 POSIX 가 항상 성공을 보장합니다
fn real_uid() -> u32 {
    unsafe { libc::getuid() }
}

pub fn digest_hex(policy: &Policy) -> String {
    airlock_audit::Hash::from_bytes(policy.digest()).to_hex()
}

/// 기록의 키가 되는 경로입니다.
///
/// 로드는 링크를 따라가지 않는 어휘적 경로로 하지만, 기록은 `airlock policy trust` 와
/// `airlock run` 이 같은 파일을 같은 이름으로 불러야 하므로 해소된 절대 경로를 씁니다
pub fn trust_key(policy_path: &Path) -> PathBuf {
    std::fs::canonicalize(policy_path).unwrap_or_else(|_| policy_path.to_path_buf())
}

fn is_lower_hex(s: &str) -> bool {
    s.len() == DIGEST_HEX_LEN && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_line(line: &str) -> Result<TrustRecord, String> {
    let value: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let Some(obj) = value.as_object() else {
        return Err(tr!("객체가 아님", "not an object").to_string());
    };
    for key in obj.keys() {
        if !matches!(key.as_str(), "v" | "path" | "digest" | "trusted_at" | "uid") {
            return Err(tr!(
                format!("모르는 필드 {}", sanitize(key)),
                format!("unknown field {}", sanitize(key))
            ));
        }
    }
    match obj.get("v").and_then(serde_json::Value::as_u64) {
        Some(TRUST_VERSION) => {}
        _ => return Err(tr!("v 가 1 이 아님", "v is not 1").to_string()),
    }
    let path = obj
        .get("path")
        .and_then(serde_json::Value::as_str)
        .filter(|p| Path::new(p).is_absolute())
        .ok_or_else(|| tr!("path 가 절대 경로가 아님", "path is not absolute").to_string())?;
    let digest = obj
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .filter(|d| is_lower_hex(d))
        .ok_or_else(|| {
            tr!("digest 가 64자 hex 가 아님", "digest is not 64 hex chars").to_string()
        })?;
    let trusted_at = obj
        .get("trusted_at")
        .and_then(serde_json::Value::as_str)
        .filter(|t| !t.is_empty() && t.is_ascii())
        .ok_or_else(|| tr!("trusted_at 이 비어 있음", "trusted_at is empty").to_string())?;
    let uid = obj
        .get("uid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|u| u32::try_from(u).ok())
        .ok_or_else(|| tr!("uid 가 정수가 아님", "uid is not an integer").to_string())?;
    Ok(TrustRecord {
        path: PathBuf::from(path),
        digest: digest.to_string(),
        trusted_at: trusted_at.to_string(),
        uid,
    })
}

/// 기록 파일 전체를 해석합니다.
///
/// # Errors
/// 한 줄이라도 해석할 수 없으면 실패합니다. 잘못된 줄을 건너뛰면 그 뒤의 줄이 정당해
/// 보이므로 파일 전체를 불신합니다
pub fn parse_records(text: &str) -> Result<Vec<TrustRecord>, String> {
    if !text.is_empty() && !text.ends_with('\n') {
        return Err(tr!("마지막 줄이 잘림", "the final line is truncated").to_string());
    }
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let no = i.saturating_add(1);
        if line.trim().is_empty() {
            return Err(tr!(
                format!("{no}번째 줄이 비어 있음"),
                format!("line {no} is blank")
            ));
        }
        let rec = parse_line(line)
            .map_err(|why| tr!(format!("{no}번째 줄: {why}"), format!("line {no}: {why}")))?;
        out.push(rec);
    }
    Ok(out)
}

fn check_owner(meta: &std::fs::Metadata) -> Result<(), String> {
    if !meta.is_file() {
        return Err(tr!("일반 파일이 아님", "not a regular file").to_string());
    }
    let uid = real_uid();
    if meta.uid() != uid {
        return Err(tr!(
            format!("uid {}의 소유임. 호출자는 uid {uid}", meta.uid()),
            format!("owned by uid {}; the caller is uid {uid}", meta.uid())
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(tr!(
            format!(
                "권한이 {:04o}로 다른 사용자가 쓸 수 있음",
                meta.mode() & 0o7777
            ),
            format!(
                "mode {:04o} lets other users write to it",
                meta.mode() & 0o7777
            )
        ));
    }
    Ok(())
}

fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    if dir.exists() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        create_dir_private(parent)?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

impl TrustStore {
    /// 감사 루트의 기록을 읽습니다.
    ///
    /// 실패하지 않습니다. 파일이 없으면 기록이 없는 것이고, 읽을 수 없거나 출처가
    /// 의심스럽거나 한 줄이라도 깨져 있으면 파일 전체를 불신 상태로 둡니다
    pub fn open(audit_root: &Path) -> Self {
        let path = audit_root.join(TRUST_FILE);
        let state = match Self::read(&path) {
            Ok(None) => TrustState::Absent,
            Ok(Some(records)) => TrustState::Loaded(records),
            Err(why) => TrustState::Distrusted(why),
        };
        Self { path, state }
    }

    fn read(path: &Path) -> Result<Option<Vec<TrustRecord>>, String> {
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(tr!(format!("열 수 없음: {e}"), format!("cannot open: {e}")));
            }
        };
        let meta = file.metadata().map_err(|e| {
            tr!(
                format!("메타데이터 실패: {e}"),
                format!("metadata failed: {e}")
            )
        })?;
        check_owner(&meta)?;
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|e| tr!(format!("읽기 실패: {e}"), format!("read failed: {e}")))?;
        parse_records(&text).map(Some)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn state(&self) -> &TrustState {
        &self.state
    }

    pub fn distrust_reason(&self) -> Option<&str> {
        match &self.state {
            TrustState::Distrusted(why) => Some(why),
            _ => None,
        }
    }

    /// 같은 경로의 마지막 줄입니다.
    pub fn lookup(&self, key: &Path) -> Option<&TrustRecord> {
        match &self.state {
            TrustState::Loaded(records) => records.iter().rev().find(|r| r.path == key),
            _ => None,
        }
    }

    /// 경로마다 마지막 줄만 모읍니다. 처음 등장한 순서를 유지합니다.
    pub fn latest(&self) -> Vec<&TrustRecord> {
        let TrustState::Loaded(records) = &self.state else {
            return Vec::new();
        };
        let mut out: Vec<&TrustRecord> = Vec::new();
        for rec in records {
            match out.iter_mut().find(|r| r.path == rec.path) {
                Some(slot) => *slot = rec,
                None => out.push(rec),
            }
        }
        out
    }

    /// 승인 한 줄을 잇습니다.
    ///
    /// # Errors
    /// 불신 상태의 파일에는 잇지 않습니다. 잇더라도 다음 읽기가 파일 전체를 불신하므로
    /// 사람이 먼저 파일을 확인해야 합니다. 열기와 출처 검사와 쓰기와 fsync 실패도 실패입니다
    pub fn record(&mut self, key: &Path, digest: &str) -> Result<TrustRecord, String> {
        if let Some(why) = self.distrust_reason() {
            return Err(tr!(
                format!("기록 파일을 불신하므로 잇지 않음: {why}"),
                format!("refusing to append to a distrusted record file: {why}")
            ));
        }
        let Some(key_str) = key.to_str() else {
            return Err(tr!(
                "정책 경로가 UTF-8 이 아니라 기록할 수 없음",
                "the policy path is not UTF-8 and cannot be recorded"
            )
            .to_string());
        };
        if !is_lower_hex(digest) {
            return Err(tr!("다이제스트 형식이 틀림", "malformed digest").to_string());
        }
        if let Some(dir) = self.path.parent() {
            create_dir_private(dir).map_err(|e| {
                tr!(
                    format!(
                        "감사 루트 {} 를 만들지 못함: {e}",
                        sanitize(&dir.display().to_string())
                    ),
                    format!(
                        "cannot create the audit root {}: {e}",
                        sanitize(&dir.display().to_string())
                    )
                )
            })?;
        }
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_APPEND)
            .open(&self.path)
            .map_err(|e| tr!(format!("열 수 없음: {e}"), format!("cannot open: {e}")))?;
        let meta = file.metadata().map_err(|e| {
            tr!(
                format!("메타데이터 실패: {e}"),
                format!("metadata failed: {e}")
            )
        })?;
        check_owner(&meta)?;

        let rec = TrustRecord {
            path: key.to_path_buf(),
            digest: digest.to_string(),
            trusted_at: airlock_audit::format_rfc3339_nanos(airlock_audit::now_unix_nanos()),
            uid: real_uid(),
        };
        let line = format!(
            "{{\"v\":{TRUST_VERSION},\"path\":{},\"digest\":{},\"trusted_at\":{},\"uid\":{}}}\n",
            json_str(key_str),
            json_str(&rec.digest),
            json_str(&rec.trusted_at),
            rec.uid
        );
        file.write_all(line.as_bytes())
            .map_err(|e| tr!(format!("쓰기 실패: {e}"), format!("write failed: {e}")))?;
        file.sync_all()
            .map_err(|e| tr!(format!("fsync 실패: {e}"), format!("fsync failed: {e}")))?;

        match &mut self.state {
            TrustState::Loaded(records) => records.push(rec.clone()),
            state => *state = TrustState::Loaded(vec![rec.clone()]),
        }
        Ok(rec)
    }
}

fn short(digest: &str) -> String {
    digest.chars().take(12).collect()
}

fn describe_previous(previous: Option<&TrustRecord>) -> String {
    match previous {
        Some(p) => format!("{} ({})", p.digest, p.trusted_at),
        None => tr!("없음", "none").to_string(),
    }
}

fn render_prompt(
    key: &Path,
    digest: &str,
    previous: Option<&TrustRecord>,
    policy: &Policy,
) -> String {
    let mut out = String::new();
    out.push_str(tr!(
        "\n\x1b[1;33m┌─ airlock 정책 신뢰 확인 ────────────────────────\x1b[0m\n",
        "\n\x1b[1;33m┌─ airlock policy trust check ────────────────────\x1b[0m\n"
    ));
    let headline = match previous {
        Some(_) => tr!(
            "정책 파일이 기록된 다이제스트와 다름",
            "the policy file differs from the recorded digest"
        ),
        None => tr!(
            "처음 보는 정책 파일",
            "a policy file seen for the first time"
        ),
    };
    out.push_str(&format!(
        "\x1b[1;33m│\x1b[0m {headline}\n\x1b[1;33m│\x1b[0m\n"
    ));
    let rows: Vec<(String, String)> = vec![
        (
            tr!("경로", "path").to_string(),
            sanitize(&key.display().to_string()),
        ),
        (tr!("다이제스트", "digest").to_string(), digest.to_string()),
        (
            tr!("이전 기록", "recorded").to_string(),
            describe_previous(previous),
        ),
        (tr!("이름", "name").to_string(), sanitize(policy.name())),
        (
            tr!("규칙", "rules").to_string(),
            tr!(
                format!(
                    "사용자 {} / 베이스라인 {} / tier0 {}",
                    policy.user_rules().len(),
                    policy.baseline_rules().len(),
                    policy.self_protect_rules().len()
                ),
                format!(
                    "user {} / baseline {} / tier0 {}",
                    policy.user_rules().len(),
                    policy.baseline_rules().len(),
                    policy.self_protect_rules().len()
                )
            ),
        ),
    ];
    let width = rows
        .iter()
        .map(|(l, _)| l.chars().count())
        .max()
        .unwrap_or(0);
    for (label, value) in &rows {
        let pad = " ".repeat(width.saturating_sub(label.chars().count()));
        out.push_str(&format!("\x1b[1;33m│\x1b[0m {label}{pad}  {value}\n"));
    }
    out.push_str("\x1b[1;33m│\x1b[0m\n");
    out.push_str(tr!(
        "\x1b[1;33m│\x1b[0m \x1b[2m이 파일을 사람이 두었는지 확인할 것. 에이전트가 작업 공간에 심은 정책일 수 있음\x1b[0m\n",
        "\x1b[1;33m│\x1b[0m \x1b[2mconfirm that a person placed this file; an agent may have planted it in the workspace\x1b[0m\n"
    ));
    out.push_str("\x1b[1;33m└─────────────────────────────────────────────────\x1b[0m\n");
    out.push_str(tr!(
        "이 정책을 신뢰하고 기록하겠습니까? [y/N] ",
        "trust this policy and record it? [y/N] "
    ));
    out
}

pub fn answer_is_yes(line: &str) -> bool {
    matches!(line.trim(), "y" | "Y")
}

/// `/dev/tty` 를 새로 열어 사람에게 묻습니다.
///
/// 터미널이 없으면 `None` 입니다. 에이전트의 stdin 과 분리된 채널이어야 하므로
/// 표준 입력은 쓰지 않습니다
fn confirm_on_tty(
    key: &Path,
    digest: &str,
    previous: Option<&TrustRecord>,
    policy: &Policy,
) -> Option<bool> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    if tty
        .write_all(render_prompt(key, digest, previous, policy).as_bytes())
        .is_err()
    {
        return Some(false);
    }
    let _ = tty.flush();
    let read_side = tty.try_clone().ok()?;
    let mut line = String::new();
    let granted = match BufReader::new(read_side).read_line(&mut line) {
        Ok(n) if n > 0 => answer_is_yes(&line),
        _ => false,
    };
    let _ = tty.write_all(
        if granted {
            tr!(
                "\x1b[32m신뢰 기록됨\x1b[0m\n\n",
                "\x1b[32mtrusted and recorded\x1b[0m\n\n"
            )
        } else {
            tr!("\x1b[31m거부\x1b[0m\n\n", "\x1b[31mrefused\x1b[0m\n\n")
        }
        .as_bytes(),
    );
    Some(granted)
}

fn refuse(key: &Path, digest: &str, previous: Option<&TrustRecord>, asked: bool) -> i32 {
    let shown = sanitize(&key.display().to_string());
    match previous {
        Some(p) => eprintln!(
            "airlock: {}",
            tr!(
                format!(
                    "정책 파일 {shown} 의 다이제스트 {digest} 가 기록된 {} 와 다름",
                    p.digest
                ),
                format!(
                    "policy file {shown} has digest {digest}, which differs from the recorded {}",
                    p.digest
                )
            )
        ),
        None => eprintln!(
            "airlock: {}",
            tr!(
                format!("정책 파일 {shown} (다이제스트 {digest}) 은 신뢰 기록에 없음"),
                format!("policy file {shown} (digest {digest}) is not in the trust record")
            )
        ),
    }
    if !asked {
        eprintln!(
            "airlock: {}",
            tr!(
                "/dev/tty 가 없어 확인을 물을 수 없음",
                "cannot ask for confirmation because /dev/tty is unavailable"
            )
        );
    }
    eprintln!(
        "airlock: {}",
        tr!(
            format!("사람이 둔 파일이 맞으면 airlock policy trust {shown} 로 승인할 것"),
            format!("if a person placed this file, approve it with airlock policy trust {shown}")
        )
    );
    eprintln!(
        "airlock: {}",
        tr!(
            "정책 출처를 확인하지 못했으므로 실행을 중단함",
            "aborting because the policy source was not confirmed"
        )
    );
    78
}

fn refuse_distrusted(store: &TrustStore, why: &str) -> i32 {
    let shown = sanitize(&store.path().display().to_string());
    eprintln!(
        "airlock: {}",
        tr!(
            format!("경고 정책 신뢰 기록 {shown} 을 불신함: {why}"),
            format!("warning: distrusting the policy trust record {shown}: {why}")
        )
    );
    eprintln!(
        "airlock: {}",
        tr!(
            "파일을 직접 확인하고 지우거나 권한을 고친 뒤 airlock policy trust 로 다시 기록할 것",
            "inspect the file yourself, delete it or fix its permissions, then record again with \
             airlock policy trust"
        )
    );
    eprintln!(
        "airlock: {}",
        tr!(
            "정책 출처를 확인하지 못했으므로 실행을 중단함",
            "aborting because the policy source was not confirmed"
        )
    );
    78
}

/// `airlock run` 의 로드 시점 관문입니다.
///
/// 기록과 일치하면 조용히 통과합니다. 아니면 `/dev/tty` 로 묻고, 터미널이 없거나 답이
/// `y` 가 아니면 거부합니다. `--yes` 는 이 관문을 건너뛰지 못합니다
///
/// # Errors
/// 거부하면 종료 코드를 돌려줍니다
pub fn gate_run(policy_path: &Path, policy: &Policy, audit_root: &Path) -> Result<Gate, i32> {
    let mut store = TrustStore::open(audit_root);
    if let Some(why) = store.distrust_reason() {
        return Err(refuse_distrusted(&store, why));
    }
    let key = trust_key(policy_path);
    let digest = digest_hex(policy);
    let previous = store.lookup(&key).cloned();
    if let Some(p) = &previous
        && p.digest == digest
    {
        return Ok(Gate::Matched(p.clone()));
    }
    match confirm_on_tty(&key, &digest, previous.as_ref(), policy) {
        Some(true) => match store.record(&key, &digest) {
            Ok(rec) => Ok(Gate::Approved(rec)),
            Err(why) => {
                eprintln!(
                    "airlock: {}",
                    tr!(
                        format!("정책 신뢰 기록에 쓰지 못함: {why}"),
                        format!("failed to write the policy trust record: {why}")
                    )
                );
                eprintln!(
                    "airlock: {}",
                    tr!(
                        "승인을 남기지 못했으므로 실행을 중단함",
                        "aborting because the approval could not be recorded"
                    )
                );
                Err(78)
            }
        },
        Some(false) => Err(refuse(&key, &digest, previous.as_ref(), true)),
        None => Err(refuse(&key, &digest, previous.as_ref(), false)),
    }
}

pub fn describe_gate(gate: &Gate) -> String {
    let rec = gate.record();
    match gate {
        Gate::Matched(_) => tr!(
            format!("기록 일치 ({}, uid {})", rec.trusted_at, rec.uid),
            format!("record matches ({}, uid {})", rec.trusted_at, rec.uid)
        ),
        Gate::Approved(_) => tr!(
            "이번 실행에서 승인하고 기록함",
            "approved and recorded in this run"
        )
        .to_string(),
    }
}

/// 사람이 직접 내린 승인을 기록합니다. `airlock policy trust` 와 `airlock setup` 이 씁니다.
///
/// # Errors
/// 기록 파일이 불신 상태거나 쓰지 못하면 실패합니다
pub fn record_approval(
    policy_path: &Path,
    policy: &Policy,
    audit_root: &Path,
) -> Result<(TrustRecord, bool), String> {
    let mut store = TrustStore::open(audit_root);
    if let Some(why) = store.distrust_reason() {
        return Err(tr!(
            format!(
                "정책 신뢰 기록 {} 을 불신함: {why}. 파일을 직접 확인하고 지우거나 권한을 고칠 것",
                sanitize(&store.path().display().to_string())
            ),
            format!(
                "distrusting the policy trust record {}: {why}. Inspect the file yourself and \
                 delete it or fix its permissions",
                sanitize(&store.path().display().to_string())
            )
        ));
    }
    let key = trust_key(policy_path);
    let digest = digest_hex(policy);
    if let Some(existing) = store.lookup(&key)
        && existing.digest == digest
    {
        return Ok((existing.clone(), false));
    }
    store.record(&key, &digest).map(|r| (r, true))
}

pub fn trust_command(policy_path: &Path, policy: &Policy, audit_root: &Path) -> i32 {
    let store_path = audit_root.join(TRUST_FILE);
    match record_approval(policy_path, policy, audit_root) {
        Ok((rec, appended)) => {
            println!(
                "{}",
                if appended {
                    tr!(
                        "\x1b[32m정책 신뢰 기록됨\x1b[0m",
                        "\x1b[32mpolicy trusted and recorded\x1b[0m"
                    )
                } else {
                    tr!(
                        "\x1b[32m이미 같은 다이제스트로 기록되어 있음\x1b[0m",
                        "\x1b[32malready recorded with the same digest\x1b[0m"
                    )
                }
            );
            println!(
                "{}",
                tr!(
                    format!("  경로       {}", sanitize(&rec.path.display().to_string())),
                    format!("  path       {}", sanitize(&rec.path.display().to_string()))
                )
            );
            println!(
                "{}",
                tr!(
                    format!("  다이제스트 {}", rec.digest),
                    format!("  digest     {}", rec.digest)
                )
            );
            println!(
                "{}",
                tr!(
                    format!("  시각       {}", rec.trusted_at),
                    format!("  at         {}", rec.trusted_at)
                )
            );
            println!(
                "{}",
                tr!(
                    format!(
                        "  기록       {}",
                        sanitize(&store_path.display().to_string())
                    ),
                    format!(
                        "  record     {}",
                        sanitize(&store_path.display().to_string())
                    )
                )
            );
            0
        }
        Err(why) => {
            eprintln!("airlock: {why}");
            78
        }
    }
}

pub fn list_command(audit_root: &Path) -> i32 {
    let store = TrustStore::open(audit_root);
    let shown = sanitize(&store.path().display().to_string());
    match store.state() {
        TrustState::Absent => {
            println!(
                "{}",
                tr!(
                    format!("정책 신뢰 기록 없음 ({shown})"),
                    format!("no policy trust record ({shown})")
                )
            );
            0
        }
        TrustState::Distrusted(why) => {
            eprintln!(
                "airlock: {}",
                tr!(
                    format!("경고 정책 신뢰 기록 {shown} 을 불신함: {why}"),
                    format!("warning: distrusting the policy trust record {shown}: {why}")
                )
            );
            78
        }
        TrustState::Loaded(_) => {
            println!(
                "{}",
                tr!(
                    format!("정책 신뢰 기록 {shown}"),
                    format!("policy trust record {shown}")
                )
            );
            for rec in store.latest() {
                println!(
                    "  {}  {}  {}  uid {}",
                    short(&rec.digest),
                    rec.trusted_at,
                    sanitize(&rec.path.display().to_string()),
                    rec.uid
                );
                println!("    {}", rec.digest);
            }
            0
        }
    }
}

/// 감사 루트가 작업 공간 안에 있는지 봅니다.
///
/// 아직 없는 감사 루트는 해소되지 않아 `work/../audit` 같은 형태로 오므로, 접두 비교 전에
/// `..` 을 어휘적으로 정리합니다. 정리하지 않으면 작업 공간 밖의 루트를 안이라고 오판합니다
pub fn is_inside(audit_root: &Path, workspace: &Path) -> bool {
    airlock_policy::path::lexical_clean(audit_root)
        .starts_with(airlock_policy::path::lexical_clean(workspace))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            p.push(format!(
                "airlock-trust-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(std::fs::canonicalize(&p).unwrap())
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const D1: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const D2: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn line(path: &str, digest: &str) -> String {
        format!(
            "{{\"v\":1,\"path\":\"{path}\",\"digest\":\"{digest}\",\"trusted_at\":\"2026-01-01T00:00:00.000000000Z\",\"uid\":501}}\n"
        )
    }

    fn policy() -> Policy {
        let ctx = airlock_policy::LoadContext::new("/Users/me", "/Users/me/.local/share/airlock");
        Policy::baseline_only(&ctx).unwrap()
    }

    #[test]
    fn a_well_formed_line_parses() {
        let recs = parse_records(&line("/w/airlock.toml", D1)).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].path, PathBuf::from("/w/airlock.toml"));
        assert_eq!(recs[0].digest, D1);
        assert_eq!(recs[0].uid, 501);
    }

    #[test]
    fn the_last_line_for_a_path_wins() {
        let s = Scratch::new("last");
        let text = format!(
            "{}{}{}",
            line("/w/a.toml", D1),
            line("/w/b.toml", D1),
            line("/w/a.toml", D2)
        );
        std::fs::write(s.path().join(TRUST_FILE), text).unwrap();
        let store = TrustStore::open(s.path());
        assert_eq!(store.lookup(Path::new("/w/a.toml")).unwrap().digest, D2);
        assert_eq!(store.lookup(Path::new("/w/b.toml")).unwrap().digest, D1);
        assert!(store.lookup(Path::new("/w/c.toml")).is_none());
        let latest = store.latest();
        assert_eq!(latest.len(), 2, "경로마다 한 줄만 남아야 함");
        assert_eq!(
            latest[0].digest, D2,
            "처음 등장한 순서를 지키되 값은 마지막 줄"
        );
    }

    #[test]
    fn one_bad_line_distrusts_the_whole_file() {
        let s = Scratch::new("badline");
        let text = format!(
            "{}not json\n{}",
            line("/w/a.toml", D1),
            line("/w/b.toml", D1)
        );
        std::fs::write(s.path().join(TRUST_FILE), text).unwrap();
        let store = TrustStore::open(s.path());
        assert!(
            store.distrust_reason().is_some(),
            "잘못된 줄 하나가 있으면 파일 전체를 불신해야 함"
        );
        assert!(
            store.lookup(Path::new("/w/a.toml")).is_none(),
            "불신한 파일의 정상 줄이 유효하게 보이면 안 됨"
        );
    }

    #[test]
    fn unknown_fields_and_bad_values_are_malformed() {
        for bad in [
            "{\"v\":2,\"path\":\"/w/a\",\"digest\":\"DIGEST\",\"trusted_at\":\"t\",\"uid\":1}\n",
            "{\"v\":1,\"path\":\"w/a\",\"digest\":\"DIGEST\",\"trusted_at\":\"t\",\"uid\":1}\n",
            "{\"v\":1,\"path\":\"/w/a\",\"digest\":\"abc\",\"trusted_at\":\"t\",\"uid\":1}\n",
            "{\"v\":1,\"path\":\"/w/a\",\"digest\":\"DIGEST\",\"trusted_at\":\"\",\"uid\":1}\n",
            "{\"v\":1,\"path\":\"/w/a\",\"digest\":\"DIGEST\",\"trusted_at\":\"t\",\"uid\":-1}\n",
            "{\"v\":1,\"path\":\"/w/a\",\"digest\":\"DIGEST\",\"trusted_at\":\"t\",\"uid\":1,\"x\":1}\n",
            "[1]\n",
            "\n",
        ] {
            let text = bad.replace("DIGEST", D1);
            assert!(
                parse_records(&text).is_err(),
                "해석되면 안 되는 줄이 통과함: {text}"
            );
        }
    }

    #[test]
    fn a_truncated_final_line_is_malformed() {
        let text = line("/w/a.toml", D1);
        let cut = &text[..text.len() - 1];
        assert!(
            parse_records(cut).is_err(),
            "개행 없는 마지막 줄은 잘린 쓰기임"
        );
    }

    #[test]
    fn group_or_world_writable_files_are_distrusted() {
        let s = Scratch::new("perm");
        let file = s.path().join(TRUST_FILE);
        std::fs::write(&file, line("/w/a.toml", D1)).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o620)).unwrap();
        let store = TrustStore::open(s.path());
        assert!(
            store.distrust_reason().is_some(),
            "그룹 쓰기 비트가 있으면 불신"
        );
        assert!(store.lookup(Path::new("/w/a.toml")).is_none());

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let store = TrustStore::open(s.path());
        assert!(store.distrust_reason().is_none(), "0600 은 신뢰");
        assert!(store.lookup(Path::new("/w/a.toml")).is_some());
    }

    #[test]
    fn a_symlinked_record_file_is_distrusted() {
        let s = Scratch::new("symlink");
        let real = s.path().join("real.jsonl");
        std::fs::write(&real, line("/w/a.toml", D1)).unwrap();
        std::os::unix::fs::symlink(&real, s.path().join(TRUST_FILE)).unwrap();
        let store = TrustStore::open(s.path());
        assert!(store.distrust_reason().is_some(), "링크를 따라가면 안 됨");
    }

    #[test]
    fn a_missing_file_means_no_records() {
        let s = Scratch::new("absent");
        let store = TrustStore::open(&s.path().join("nope"));
        assert!(matches!(store.state(), TrustState::Absent));
        assert!(store.lookup(Path::new("/w/a.toml")).is_none());
        assert!(store.latest().is_empty());
    }

    #[test]
    fn recording_creates_a_private_file_and_reads_back() {
        let s = Scratch::new("record");
        let root = s.path().join("audit");
        let mut store = TrustStore::open(&root);
        let rec = store.record(Path::new("/w/a.toml"), D1).unwrap();
        assert_eq!(rec.uid, real_uid());
        assert!(rec.trusted_at.ends_with('Z'));

        let meta = std::fs::metadata(root.join(TRUST_FILE)).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600, "새 기록 파일은 0600 이어야 함");
        assert_eq!(
            std::fs::metadata(&root).unwrap().mode() & 0o777,
            0o700,
            "새 감사 루트는 0700 이어야 함"
        );

        store.record(Path::new("/w/a.toml"), D2).unwrap();
        let again = TrustStore::open(&root);
        assert!(again.distrust_reason().is_none());
        assert_eq!(again.lookup(Path::new("/w/a.toml")).unwrap().digest, D2);
        assert_eq!(again.latest().len(), 1);
    }

    #[test]
    fn recording_refuses_a_distrusted_file() {
        let s = Scratch::new("record-distrusted");
        std::fs::write(s.path().join(TRUST_FILE), "garbage\n").unwrap();
        let mut store = TrustStore::open(s.path());
        assert!(
            store.record(Path::new("/w/a.toml"), D1).is_err(),
            "불신한 파일에 잇는 것은 무의미하고 위험함"
        );
        let body = std::fs::read_to_string(s.path().join(TRUST_FILE)).unwrap();
        assert_eq!(body, "garbage\n", "불신한 파일이 바뀌면 안 됨");
    }

    #[test]
    fn recording_rejects_a_malformed_digest() {
        let s = Scratch::new("record-digest");
        let mut store = TrustStore::open(s.path());
        assert!(store.record(Path::new("/w/a.toml"), "ABC").is_err());
        assert!(!s.path().join(TRUST_FILE).exists());
    }

    #[test]
    fn approval_is_idempotent_for_the_same_digest() {
        let s = Scratch::new("idempotent");
        let root = s.path().join("audit");
        let policy_file = s.path().join("airlock.toml");
        std::fs::write(&policy_file, "version = 1\n").unwrap();
        let p = policy();
        let (_, first) = record_approval(&policy_file, &p, &root).unwrap();
        let (_, second) = record_approval(&policy_file, &p, &root).unwrap();
        assert!(first, "첫 승인은 기록되어야 함");
        assert!(!second, "같은 다이제스트를 다시 잇지 않음");
        let body = std::fs::read_to_string(root.join(TRUST_FILE)).unwrap();
        assert_eq!(body.lines().count(), 1);
        assert!(body.contains(&digest_hex(&p)));
    }

    #[test]
    fn the_digest_is_the_genesis_representation() {
        let p = policy();
        let hex = digest_hex(&p);
        assert!(is_lower_hex(&hex));
        assert_eq!(
            hex,
            airlock_audit::Hash::from_bytes(p.digest()).to_hex(),
            "감사 제네시스의 policy_digest 와 같은 표기여야 함"
        );
    }

    #[test]
    fn only_y_approves() {
        assert!(answer_is_yes("y\n"));
        assert!(answer_is_yes(" Y \n"));
        for no in ["", "\n", "n\n", "yes\n", "N\n", "1\n", "y y\n"] {
            assert!(!answer_is_yes(no), "{no:?} 가 승인으로 읽히면 안 됨");
        }
    }

    #[test]
    fn the_prompt_shows_only_observed_facts_and_defaults_to_refusal() {
        let p = policy();
        let key = Path::new("/w/\u{1b}[2Jairlock.toml");
        let prev = TrustRecord {
            path: key.to_path_buf(),
            digest: D2.to_string(),
            trusted_at: "2026-01-01T00:00:00.000000000Z".to_string(),
            uid: 501,
        };
        let text = render_prompt(key, D1, Some(&prev), &p);
        assert!(text.contains(D1));
        assert!(text.contains(D2), "이전 기록 다이제스트가 보여야 함");
        assert!(
            !text.contains("\x1b[2J"),
            "경로의 제어 문자가 살아남으면 안 됨"
        );
        assert!(text.ends_with("[y/N] "), "기본값이 거부여야 함");
        let fresh = render_prompt(key, D1, None, &p);
        assert!(fresh.contains(tr!("없음", "none")));
    }

    #[test]
    fn workspace_containment_is_prefix_based() {
        assert!(is_inside(Path::new("/w/audit"), Path::new("/w")));
        assert!(!is_inside(Path::new("/other"), Path::new("/w")));
        assert!(!is_inside(Path::new("/wx"), Path::new("/w")));
        assert!(
            !is_inside(Path::new("/w/work/../audit"), Path::new("/w/work")),
            "아직 없는 루트의 .. 이 정리되지 않으면 작업 공간 밖을 안이라고 오판함"
        );
        assert!(is_inside(
            Path::new("/w/work/x/../audit"),
            Path::new("/w/work")
        ));
    }
}
