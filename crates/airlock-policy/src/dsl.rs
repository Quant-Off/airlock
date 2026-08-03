use std::path::Path;

use serde::Deserialize;

use crate::error::LoadError;
use crate::glob::{Pattern, TextPattern};
use crate::host::HostPattern;
use crate::model::{Action, FileMode, Kind, ModeSet, Tier};
use crate::rule::{Matcher, ProgramMatch, Rule};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(s) => vec![s],
            Self::Many(v) => v,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDefaults {
    pub file: Option<String>,
    pub exec: Option<String>,
    pub egress: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    pub id: String,
    pub kind: String,
    pub action: String,
    pub reason: Option<String>,
    pub overrides: Option<String>,
    pub path: Option<OneOrMany>,
    pub mode: Option<Vec<String>>,
    pub program: Option<String>,
    pub argv_contains: Option<Vec<String>>,
    pub argv_pattern: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPolicy {
    pub version: u32,
    pub name: Option<String>,
    pub defaults: Option<RawDefaults>,
    #[serde(default)]
    pub rules: Vec<RawRule>,
}

pub fn parse(src: &str) -> Result<RawPolicy, LoadError> {
    Ok(toml::from_str(src)?)
}

/// 규칙 id에 쓸 수 있는 문자인지 봅니다.
///
/// id는 커널 강제 프로파일에 주석으로 그대로 들어갑니다. 개행이 섞이면 주석이 거기서
/// 끝나고 뒤 내용이 살아 있는 지시문이 되므로 프로파일 전체를 다시 쓸 수 있습니다.
fn id_char_ok(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':')
}

/// 규칙 id를 검증합니다.
///
/// # Errors
/// 빈 문자열이거나 [`id_char_ok`]가 거부하는 문자가 있으면 [`LoadError::InvalidId`]입니다.
pub fn validate_id(id: &str) -> Result<(), LoadError> {
    if id.is_empty() {
        return Err(LoadError::InvalidId {
            id: String::new(),
            offender: '\0',
        });
    }
    match id.chars().find(|c| !id_char_ok(*c)) {
        Some(offender) => Err(LoadError::InvalidId {
            id: id.to_string(),
            offender,
        }),
        None => Ok(()),
    }
}

pub fn parse_action(id: &str, value: &str) -> Result<Action, LoadError> {
    Action::parse(value).ok_or_else(|| LoadError::UnknownAction {
        id: id.to_string(),
        value: value.to_string(),
    })
}

fn reject(id: &str, kind: Kind, present: bool, field: &'static str) -> Result<(), LoadError> {
    if present {
        return Err(LoadError::UnexpectedField {
            id: id.to_string(),
            field,
            kind,
        });
    }
    Ok(())
}

fn modes_from(raw: &RawRule) -> Result<ModeSet, LoadError> {
    match &raw.mode {
        None => Ok(ModeSet::ALL),
        Some(list) => {
            if list.is_empty() {
                return Err(LoadError::EmptyModeSet { id: raw.id.clone() });
            }
            let mut modes = Vec::with_capacity(list.len());
            for m in list {
                modes.push(FileMode::parse(m).ok_or_else(|| LoadError::UnknownMode {
                    id: raw.id.clone(),
                    value: m.clone(),
                })?);
            }
            Ok(ModeSet::from_modes(&modes))
        }
    }
}

pub fn to_rule(raw: RawRule, home: &Path) -> Result<Rule, LoadError> {
    let id = raw.id.clone();
    validate_id(&id)?;
    let action = parse_action(&id, &raw.action)?;
    let kind = Kind::parse(&raw.kind).ok_or_else(|| LoadError::UnknownKind {
        id: id.clone(),
        value: raw.kind.clone(),
    })?;

    let matcher = match kind {
        Kind::File => {
            reject(&id, kind, raw.program.is_some(), "program")?;
            reject(&id, kind, raw.argv_contains.is_some(), "argv_contains")?;
            reject(&id, kind, raw.argv_pattern.is_some(), "argv_pattern")?;
            reject(&id, kind, raw.host.is_some(), "host")?;
            reject(&id, kind, raw.port.is_some(), "port")?;

            let modes = modes_from(&raw)?;
            let specs = raw.path.ok_or(LoadError::MissingField {
                id: id.clone(),
                field: "path",
            })?;
            let list = specs.into_vec();
            if list.is_empty() {
                return Err(LoadError::MissingField {
                    id: id.clone(),
                    field: "path",
                });
            }
            let mut paths = Vec::with_capacity(list.len());
            for p in &list {
                paths.push(
                    Pattern::parse(p, home).map_err(|source| LoadError::Pattern {
                        id: id.clone(),
                        source,
                    })?,
                );
            }
            Matcher::File { paths, modes }
        }
        Kind::Exec => {
            reject(&id, kind, raw.path.is_some(), "path")?;
            reject(&id, kind, raw.mode.is_some(), "mode")?;
            reject(&id, kind, raw.host.is_some(), "host")?;
            reject(&id, kind, raw.port.is_some(), "port")?;

            let program = match &raw.program {
                None => None,
                Some(p) if p.contains('/') => Some(ProgramMatch::Path(
                    Pattern::parse(p, home).map_err(|source| LoadError::Pattern {
                        id: id.clone(),
                        source,
                    })?,
                )),
                Some(p) => Some(ProgramMatch::Basename(p.clone())),
            };
            let argv_contains = raw.argv_contains.unwrap_or_default();
            let argv_pattern = raw.argv_pattern.map(TextPattern::new);

            if program.is_none() && argv_contains.is_empty() && argv_pattern.is_none() {
                return Err(LoadError::MissingField {
                    id: id.clone(),
                    field: "program 또는 argv_contains 또는 argv_pattern",
                });
            }
            Matcher::Exec {
                program,
                argv_contains,
                argv_pattern,
            }
        }
        Kind::Egress => {
            reject(&id, kind, raw.path.is_some(), "path")?;
            reject(&id, kind, raw.mode.is_some(), "mode")?;
            reject(&id, kind, raw.program.is_some(), "program")?;
            reject(&id, kind, raw.argv_contains.is_some(), "argv_contains")?;
            reject(&id, kind, raw.argv_pattern.is_some(), "argv_pattern")?;

            let host_raw = raw.host.ok_or(LoadError::MissingField {
                id: id.clone(),
                field: "host",
            })?;
            let host = HostPattern::parse(&host_raw).map_err(|source| LoadError::Host {
                id: id.clone(),
                source,
            })?;
            Matcher::Egress {
                host,
                port: raw.port,
            }
        }
    };

    // 빈 overrides를 조용히 버리면 완화하려던 의도가 흔적 없이 사라집니다.
    // 오타 난 키를 무시하지 않는 것과 같은 이유로 거부합니다 (2.1절)
    if let Some(o) = &raw.overrides
        && o.trim().is_empty()
    {
        return Err(LoadError::EmptyOverrideTarget { id });
    }

    Ok(Rule {
        id,
        tier: Tier::User,
        action,
        reason: raw.reason.filter(|r| !r.trim().is_empty()),
        overrides: raw.overrides,
        matcher,
    })
}
