use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::entry::{Entry, Record};
use crate::error::{Error, Result};
use crate::event::Event;
use crate::time::now_unix_nanos;
use crate::types::{Decision, Enforcement, Hash, Mediation, SessionId};

pub const CHAIN_FILE: &str = "chain.jsonl";
pub const HEAD_FILE: &str = "head.json";
pub const BROKER_ACTOR: &str = "airlock";

const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
pub const HEAD_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub version: u32,
    pub seq: u64,
    pub hash: Hash,
    pub session: SessionId,
}

#[derive(Debug, Clone)]
pub struct GenesisInfo {
    pub airlock_version: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub policy_digest: Hash,
    pub policy_source: Option<String>,
    pub mediation: Mediation,
}

#[derive(Debug)]
pub struct AuditLog {
    dir: PathBuf,
    chain: File,
    seq_next: u64,
    last_hash: Hash,
    session: SessionId,
    enforcement: Enforcement,
    fsync_per_entry: bool,
}

impl AuditLog {
    pub fn create(
        dir: impl AsRef<Path>,
        session: SessionId,
        enforcement: Enforcement,
        fsync_per_entry: bool,
        genesis: GenesisInfo,
    ) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        if dir.exists() {
            return Err(Error::SessionDirExists(dir));
        }
        if let Some(parent) = dir.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        fs::DirBuilder::new()
            .mode(DIR_MODE)
            .create(&dir)
            .map_err(|e| Error::io(&dir, e))?;

        let chain_path = dir.join(CHAIN_FILE);
        let chain = OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&chain_path)
            .map_err(|e| Error::io(&chain_path, e))?;

        let mut log = Self {
            dir,
            chain,
            seq_next: 0,
            last_hash: Hash::ZERO,
            session,
            enforcement,
            fsync_per_entry,
        };

        let genesis_event = Event::SessionStart {
            airlock_version: genesis.airlock_version,
            argv: genesis.argv,
            cwd: genesis.cwd,
            policy_digest: genesis.policy_digest,
            policy_source: genesis.policy_source,
            fsync_per_entry,
            mediation: genesis.mediation,
        };
        log.append(Record::new(BROKER_ACTOR, genesis_event, Decision::Allow))?;
        Ok(log)
    }

    pub fn append(&mut self, record: Record) -> Result<Entry> {
        let entry = Entry::seal(
            self.seq_next,
            now_unix_nanos(),
            self.session,
            self.enforcement,
            self.last_hash,
            record,
        );

        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');

        let chain_path = self.dir.join(CHAIN_FILE);
        self.chain
            .write_all(&line)
            .map_err(|e| Error::io(&chain_path, e))?;
        if self.fsync_per_entry {
            self.chain
                .sync_all()
                .map_err(|e| Error::io(&chain_path, e))?;
        }

        self.last_hash = entry.hash;
        self.seq_next = entry.seq.checked_add(1).ok_or(Error::SeqOverflow)?;
        self.write_head()?;

        Ok(entry)
    }

    fn write_head(&self) -> Result<()> {
        let head = Head {
            version: HEAD_VERSION,
            seq: self.seq_next.saturating_sub(1),
            hash: self.last_hash,
            session: self.session,
        };
        let body = serde_json::to_vec_pretty(&head)?;

        let tmp = self.dir.join("head.json.tmp");
        let final_path = self.dir.join(HEAD_FILE);
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(FILE_MODE)
                .open(&tmp)
                .map_err(|e| Error::io(&tmp, e))?;
            f.write_all(&body).map_err(|e| Error::io(&tmp, e))?;
            if self.fsync_per_entry {
                f.sync_all().map_err(|e| Error::io(&tmp, e))?;
            }
        }
        fs::rename(&tmp, &final_path).map_err(|e| Error::io(&final_path, e))?;
        if self.fsync_per_entry {
            // 디렉토리를 fsync 해야 rename이 내구성을 갖습니다. 여기서 실패를 삼키면
            // 앵커가 아직 디스크에 없는데도 4절 4단계로 넘어가 행위를 허용하게 됩니다
            let dir = File::open(&self.dir).map_err(|e| Error::io(&self.dir, e))?;
            dir.sync_all().map_err(|e| Error::io(&self.dir, e))?;
        }
        Ok(())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn session(&self) -> SessionId {
        self.session
    }

    pub fn enforcement(&self) -> Enforcement {
        self.enforcement
    }

    pub fn head_seq(&self) -> Option<u64> {
        self.seq_next.checked_sub(1)
    }

    pub fn head_hash(&self) -> Hash {
        self.last_hash
    }
}

pub fn read_entries_lossy(dir: impl AsRef<Path>) -> Result<(Vec<Entry>, Option<String>)> {
    use std::io::{BufRead, BufReader};

    let path = dir.as_ref().join(CHAIN_FILE);
    let file = File::open(&path).map_err(|e| Error::io(&path, e))?;
    let reader = BufReader::new(file);

    let mut entries = Vec::new();
    let mut problem = None;
    for (idx, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| Error::io(&path, e))?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Entry>(&line) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                problem = Some(format!(
                    "{}번째 줄부터 읽을 수 없음: {e}",
                    idx.saturating_add(1)
                ));
                break;
            }
        }
    }
    Ok((entries, problem))
}

pub fn read_head(dir: impl AsRef<Path>) -> Result<Head> {
    let path = dir.as_ref().join(HEAD_FILE);
    let body = fs::read(&path).map_err(|e| Error::io(&path, e))?;
    Ok(serde_json::from_slice(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FileMode;

    fn scratch(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "airlock-audit-test-{name}-{}-{}",
            std::process::id(),
            now_unix_nanos()
        ));
        p
    }

    fn genesis() -> GenesisInfo {
        GenesisInfo {
            airlock_version: "0.1.0".into(),
            argv: vec!["airlock".into(), "run".into(), "--".into(), "sh".into()],
            cwd: "/tmp".into(),
            policy_digest: Hash::from_bytes([0x11; 32]),
            policy_source: Some("policy.toml".into()),
            mediation: Mediation::ExecNet,
        }
    }

    fn new_log(name: &str) -> (AuditLog, PathBuf) {
        let dir = scratch(name);
        let log = AuditLog::create(
            &dir,
            SessionId::from_bytes([5; 16]),
            Enforcement::Observe,
            true,
            genesis(),
        )
        .unwrap();
        (log, dir)
    }

    fn file_event(path: &str) -> Event {
        Event::FileAccess {
            path_requested: path.into(),
            path_resolved: path.into(),
            mode: FileMode::Read,
        }
    }

    #[test]
    fn genesis_is_seq_zero_with_zero_prev() {
        let (log, dir) = new_log("genesis");
        assert_eq!(log.head_seq(), Some(0));

        let raw = fs::read_to_string(dir.join(CHAIN_FILE)).unwrap();
        let first: Entry = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(first.seq, 0);
        assert!(first.prev.is_zero());
        assert!(matches!(first.event, Event::SessionStart { .. }));
        assert!(first.hash_is_valid());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn appends_link_to_previous_hash() {
        let (mut log, dir) = new_log("link");
        let a = log
            .append(Record::new("pid:1", file_event("/a"), Decision::Allow))
            .unwrap();
        let b = log
            .append(Record::new("pid:1", file_event("/b"), Decision::Deny))
            .unwrap();

        assert_eq!(a.seq, 1);
        assert_eq!(b.seq, 2);
        assert_eq!(b.prev, a.hash);
        assert!(a.hash_is_valid() && b.hash_is_valid());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn head_anchor_tracks_last_entry() {
        let (mut log, dir) = new_log("head");
        let last = log
            .append(Record::new("pid:1", file_event("/a"), Decision::Allow))
            .unwrap();

        let head = read_head(&dir).unwrap();
        assert_eq!(head.version, HEAD_VERSION);
        assert_eq!(head.seq, last.seq);
        assert_eq!(head.hash, last.hash);
        assert_eq!(head.session, log.session());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_to_reuse_existing_session_dir() {
        let (_log, dir) = new_log("reuse");
        let err = AuditLog::create(
            &dir,
            SessionId::from_bytes([6; 16]),
            Enforcement::Observe,
            true,
            genesis(),
        );
        assert!(matches!(err, Err(Error::SessionDirExists(_))));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_log, dir) = new_log("perms");

        let dmode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, DIR_MODE);
        let fmode = fs::metadata(dir.join(CHAIN_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(fmode, FILE_MODE);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn policy_digest_is_bound_into_genesis_hash() {
        let dir_a = scratch("digest-a");
        let dir_b = scratch("digest-b");

        let mut g_b = genesis();
        g_b.policy_digest = Hash::from_bytes([0x22; 32]);

        let a = AuditLog::create(
            &dir_a,
            SessionId::ZERO,
            Enforcement::Observe,
            false,
            genesis(),
        )
        .unwrap();
        let b =
            AuditLog::create(&dir_b, SessionId::ZERO, Enforcement::Observe, false, g_b).unwrap();

        assert_ne!(a.head_hash(), b.head_hash());

        fs::remove_dir_all(&dir_a).ok();
        fs::remove_dir_all(&dir_b).ok();
    }

    #[test]
    fn each_line_is_one_json_object() {
        let (mut log, dir) = new_log("lines");
        for i in 0..5 {
            log.append(Record::new(
                "pid:1",
                file_event(&format!("/f{i}")),
                Decision::Allow,
            ))
            .unwrap();
        }
        let raw = fs::read_to_string(dir.join(CHAIN_FILE)).unwrap();
        assert!(raw.ends_with('\n'));
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 6);
        for l in lines {
            let e: Entry = serde_json::from_str(l).unwrap();
            assert!(e.hash_is_valid());
        }

        fs::remove_dir_all(&dir).ok();
    }
}
