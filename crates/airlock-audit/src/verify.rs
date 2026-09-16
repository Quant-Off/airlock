use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use airlock_i18n::tr;

use crate::entry::Entry;
use crate::error::Error;
use crate::event::Event;
use crate::log::{CHAIN_FILE, HEAD_FILE, HEAD_VERSION, Head, read_head};
use crate::types::{Decision, Enforcement, Hash, SessionId};

#[derive(Debug)]
pub enum Failure {
    ChainEmpty,
    FormatVersionUnsupported {
        seq: u64,
        got: u32,
    },
    MalformedLine {
        line: u64,
        detail: String,
    },
    TruncatedFinalLine {
        line: u64,
    },
    GenesisPrevNotZero {
        got: Hash,
    },
    GenesisNotSessionStart {
        got: &'static str,
    },
    SeqGap {
        expected: u64,
        got: u64,
    },
    SessionMismatch {
        seq: u64,
        expected: SessionId,
        got: SessionId,
    },
    PrevMismatch {
        seq: u64,
        expected: Hash,
        got: Hash,
    },
    HashMismatch {
        seq: u64,
        expected: Hash,
        got: Hash,
    },
    ApprovalTargetMissing {
        seq: u64,
        for_seq: u64,
    },
    ApprovalTargetNotAsk {
        seq: u64,
        for_seq: u64,
    },
    EntryAfterSessionEnd {
        end_seq: u64,
        seq: u64,
    },
    HeadMismatch {
        head: Box<Head>,
        chain_seq: u64,
        chain_hash: Hash,
    },
    HeadSessionMismatch {
        head_session: SessionId,
        chain_session: SessionId,
    },
    HeadAbsent,
    HeadUnreadable {
        detail: String,
    },
    HeadVersionUnsupported {
        got: u32,
    },
    BlankLine {
        line: u64,
    },
    Io(Error),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainEmpty => f.write_str(tr!("체인이 비어 있음", "the chain is empty")),
            Self::FormatVersionUnsupported { seq, got } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "seq {seq}의 포맷이 v{got}. 이 검증자는 v{}만 안다. 변조가 아니라 옛 포맷일 수 있으니 그 버전의 airlock으로 검증할 것",
                        crate::FORMAT_VERSION
                    ),
                    format!(
                        "seq {seq} has format v{got}; this verifier only knows v{}. It may be an old format rather than tampering, so verify with that version of airlock",
                        crate::FORMAT_VERSION
                    )
                )
            ),
            Self::MalformedLine { line, detail } => write!(
                f,
                "{}",
                tr!(
                    format!("{line}번째 줄 파싱 실패: {detail}"),
                    format!("failed to parse line {line}: {detail}")
                )
            ),
            Self::TruncatedFinalLine { line } => write!(
                f,
                "{}",
                tr!(
                    format!("{line}번째 줄이 개행 없이 잘림. 쓰기 중 중단 의심"),
                    format!(
                        "line {line} is truncated without a newline; suspected interruption mid-write"
                    )
                )
            ),
            Self::GenesisPrevNotZero { got } => write!(
                f,
                "{}",
                tr!(
                    format!("genesis의 prev가 0이 아님: {got}"),
                    format!("genesis prev is not zero: {got}")
                )
            ),
            Self::GenesisNotSessionStart { got } => write!(
                f,
                "{}",
                tr!(
                    format!("genesis 이벤트가 session_start가 아님: {got}"),
                    format!("genesis event is not session_start: {got}")
                )
            ),
            Self::SeqGap { expected, got } => write!(
                f,
                "{}",
                tr!(
                    format!("seq 빈틈. {expected} 기대, {got} 발견"),
                    format!("seq gap; expected {expected}, found {got}")
                )
            ),
            Self::SessionMismatch { seq, expected, got } => write!(
                f,
                "{}",
                tr!(
                    format!("seq {seq}의 session이 체인과 다름. {expected} 기대, {got} 발견"),
                    format!(
                        "session of seq {seq} differs from the chain; expected {expected}, found {got}"
                    )
                )
            ),
            Self::PrevMismatch { seq, expected, got } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "seq {seq}의 prev 불일치. {expected} 기대, {got} 발견. 삭제·삽입·재배치 의심"
                    ),
                    format!(
                        "seq {seq} prev mismatch; expected {expected}, found {got}. Suspected deletion, insertion, or reordering"
                    )
                )
            ),
            Self::HashMismatch { seq, expected, got } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "seq {seq}의 hash 불일치. 재계산 {expected}, 기록 {got}. 내용 변조 의심"
                    ),
                    format!(
                        "seq {seq} hash mismatch; recomputed {expected}, recorded {got}. Suspected content tampering"
                    )
                )
            ),
            Self::ApprovalTargetMissing { seq, for_seq } => write!(
                f,
                "{}",
                tr!(
                    format!("seq {seq} approval이 존재하지 않는 seq {for_seq}를 참조"),
                    format!("seq {seq} approval references nonexistent seq {for_seq}")
                )
            ),
            Self::ApprovalTargetNotAsk { seq, for_seq } => write!(
                f,
                "{}",
                tr!(
                    format!("seq {seq} approval의 대상 seq {for_seq}가 ask가 아님"),
                    format!("seq {seq} approval targets seq {for_seq}, which is not an ask")
                )
            ),
            Self::EntryAfterSessionEnd { end_seq, seq } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "seq {seq}가 session_end(seq {end_seq}) 뒤에 있음. 체인은 session_end로 끝나야 하므로 종료 뒤 덧붙이기 의심"
                    ),
                    format!(
                        "seq {seq} follows session_end (seq {end_seq}); the chain must end with session_end, so append after close is suspected"
                    )
                )
            ),
            Self::HeadMismatch {
                head,
                chain_seq,
                chain_hash,
            } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "앵커 불일치. head는 seq {} hash {}, 체인은 seq {chain_seq} hash {chain_hash}. 잘라내기 의심",
                        head.seq, head.hash
                    ),
                    format!(
                        "anchor mismatch; head says seq {} hash {}, the chain says seq {chain_seq} hash {chain_hash}. Suspected truncation",
                        head.seq, head.hash
                    )
                )
            ),
            Self::HeadSessionMismatch {
                head_session,
                chain_session,
            } => write!(
                f,
                "{}",
                tr!(
                    format!("앵커 session 불일치. head {head_session}, 체인 {chain_session}"),
                    format!("anchor session mismatch; head {head_session}, chain {chain_session}")
                )
            ),
            Self::HeadAbsent => f.write_str(tr!(
                "head.json 없음. 앵커 없이는 잘라내기를 탐지할 수 없음. 앵커 삭제 의심",
                "head.json missing; truncation cannot be detected without the anchor. Suspected anchor deletion"
            )),
            Self::HeadUnreadable { detail } => write!(
                f,
                "{}",
                tr!(
                    format!("head.json을 읽을 수 없음: {detail}. 앵커 없이는 잘라내기를 탐지할 수 없음"),
                    format!(
                        "cannot read head.json: {detail}; truncation cannot be detected without the anchor"
                    )
                )
            ),
            Self::HeadVersionUnsupported { got } => write!(
                f,
                "{}",
                tr!(
                    format!("head.json version {got}는 지원하지 않음. 1이어야 함"),
                    format!("head.json version {got} is not supported; it must be 1")
                )
            ),
            Self::BlankLine { line } => write!(
                f,
                "{}",
                tr!(
                    format!("{line}번째 줄이 비어 있음. 엔트리가 아닌 줄이 끼어들었음"),
                    format!("line {line} is blank; a non-entry line crept in")
                )
            ),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Failure {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    ClockWentBackwards { seq: u64, prev_ts: u64, ts: u64 },
    HeadLagsByOne { head_seq: u64, chain_seq: u64 },
    DuplicateApproval { seq: u64, for_seq: u64 },
    UnansweredAsk { seq: u64 },
    ObserveOnlyEntries { count: u64 },
    HeadMissing,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClockWentBackwards { seq, prev_ts, ts } => write!(
                f,
                "{}",
                tr!(
                    format!("seq {seq}에서 벽시계가 역행 ({prev_ts} -> {ts}). 시각 조정 가능성"),
                    format!(
                        "wall clock went backwards at seq {seq} ({prev_ts} -> {ts}); possible clock adjustment"
                    )
                )
            ),
            Self::HeadLagsByOne {
                head_seq,
                chain_seq,
            } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "앵커가 한 칸 뒤처짐 (head {head_seq}, 체인 {chain_seq}). 크래시 잔여로 판단"
                    ),
                    format!(
                        "the anchor lags by one (head {head_seq}, chain {chain_seq}); judged to be crash residue"
                    )
                )
            ),
            Self::DuplicateApproval { seq, for_seq } => write!(
                f,
                "{}",
                tr!(
                    format!("seq {seq}가 이미 응답된 seq {for_seq}를 다시 승인"),
                    format!("seq {seq} approves already-answered seq {for_seq} again")
                )
            ),
            Self::UnansweredAsk { seq } => write!(
                f,
                "{}",
                tr!(
                    format!("seq {seq}의 ask에 대한 approval 엔트리가 없음"),
                    format!("no approval entry for the ask at seq {seq}")
                )
            ),
            Self::ObserveOnlyEntries { count } => write!(
                f,
                "{}",
                tr!(
                    format!(
                        "{count}개 엔트리가 observe 모드에서 기록됨. 강제되지 않은 관찰 기록임"
                    ),
                    format!(
                        "{count} entries were recorded in observe mode; they are unenforced observations"
                    )
                )
            ),
            Self::HeadMissing => f.write_str(tr!(
                "head.json 없음. 잘라내기를 탐지할 수 없음",
                "head.json missing; truncation cannot be detected"
            )),
        }
    }
}

#[derive(Debug)]
pub struct VerifyReport {
    pub entries: u64,
    pub session: SessionId,
    pub head_seq: u64,
    pub head_hash: Hash,
    /// 제네시스가 기록한 값. 앵커 대조가 head.json 뒤처짐을 실패로 올릴지 정할 때 봅니다
    pub fsync_per_entry: bool,
    pub session_ended: bool,
    pub warnings: Vec<Warning>,
}

impl VerifyReport {
    pub fn is_clean(&self) -> bool {
        self.warnings.is_empty()
    }

    pub fn head_lag(&self) -> Option<u64> {
        self.warnings.iter().find_map(|w| match w {
            Warning::HeadLagsByOne { head_seq, .. } => Some(*head_seq),
            _ => None,
        })
    }
}

pub fn verify_dir(dir: impl AsRef<Path>) -> Result<VerifyReport, Failure> {
    let dir = dir.as_ref();

    let anchor = match read_head(dir) {
        Ok(head) => Ok(head),
        Err(source) => Err(if dir.join(HEAD_FILE).exists() {
            Failure::HeadUnreadable {
                detail: source.to_string(),
            }
        } else {
            Failure::HeadAbsent
        }),
    };

    let chain_path = dir.join(CHAIN_FILE);
    let file = File::open(&chain_path).map_err(|e| Failure::Io(Error::io(&chain_path, e)))?;

    match anchor {
        Ok(head) => verify_stream(BufReader::new(file), Some(head)),
        Err(anchor_failure) => {
            verify_stream(BufReader::new(file), None)?;
            Err(anchor_failure)
        }
    }
}

pub fn verify_stream<R: BufRead>(
    mut reader: R,
    head: Option<Head>,
) -> Result<VerifyReport, Failure> {
    let mut line_no: u64 = 0;
    let mut expected_seq: u64 = 0;
    let mut prev_hash = Hash::ZERO;
    let mut second_last_hash = Hash::ZERO;
    let mut session: Option<SessionId> = None;
    let mut last_ts: u64 = 0;
    let mut last_seq: u64 = 0;
    let mut observe_count: u64 = 0;
    let mut entry_count: u64 = 0;
    let mut fsync_per_entry = true;
    let mut ended_at: Option<u64> = None;

    let mut open_asks: HashSet<u64> = HashSet::new();
    let mut answered: HashSet<u64> = HashSet::new();
    let mut warnings: Vec<Warning> = Vec::new();

    let mut buf = String::new();
    loop {
        buf.clear();
        let read = reader
            .read_line(&mut buf)
            .map_err(|e| Failure::Io(Error::io("chain.jsonl", e)))?;
        if read == 0 {
            break;
        }
        let ended_with_newline = buf.ends_with('\n');
        let trimmed = buf.trim_end_matches(['\n', '\r']);
        line_no = line_no.saturating_add(1);

        // read가 0이 아니면 최소 한 바이트를 읽었습니다. 개행으로 끝나지 않은 마지막 줄은
        // 내용이 공백뿐이어도 쓰기 도중 중단된 흔적이므로 조용히 넘기지 않습니다
        if !ended_with_newline {
            return Err(Failure::TruncatedFinalLine { line: line_no });
        }
        if trimmed.trim().is_empty() {
            return Err(Failure::BlankLine { line: line_no });
        }

        let entry: Entry = serde_json::from_str(trimmed).map_err(|e| Failure::MalformedLine {
            line: line_no,
            detail: e.to_string(),
        })?;

        // 해시 검사보다 먼저 봅니다. 순서를 바꾸면 v1 체인이 HashMismatch, 곧 내용 변조
        // 의심으로 보고되어 옛 포맷과 위조가 구분되지 않습니다 (docs/audit-format.md 7.1)
        if entry.v != crate::FORMAT_VERSION {
            return Err(Failure::FormatVersionUnsupported {
                seq: entry.seq,
                got: entry.v,
            });
        }

        if entry.seq != expected_seq {
            return Err(Failure::SeqGap {
                expected: expected_seq,
                got: entry.seq,
            });
        }

        match session {
            None => session = Some(entry.session),
            Some(s) if s != entry.session => {
                return Err(Failure::SessionMismatch {
                    seq: entry.seq,
                    expected: s,
                    got: entry.session,
                });
            }
            _ => {}
        }

        if entry.seq == 0 {
            if !entry.prev.is_zero() {
                return Err(Failure::GenesisPrevNotZero { got: entry.prev });
            }
            if !matches!(entry.event, Event::SessionStart { .. }) {
                return Err(Failure::GenesisNotSessionStart {
                    got: entry.event.kind(),
                });
            }
        } else if entry.prev != prev_hash {
            return Err(Failure::PrevMismatch {
                seq: entry.seq,
                expected: prev_hash,
                got: entry.prev,
            });
        }

        let recomputed = entry.recompute_hash();
        if recomputed != entry.hash {
            return Err(Failure::HashMismatch {
                seq: entry.seq,
                expected: recomputed,
                got: entry.hash,
            });
        }

        if let Some(end_seq) = ended_at {
            return Err(Failure::EntryAfterSessionEnd {
                end_seq,
                seq: entry.seq,
            });
        }
        match &entry.event {
            Event::SessionStart {
                fsync_per_entry: per_entry,
                ..
            } => fsync_per_entry = *per_entry,
            Event::SessionEnd { .. } => ended_at = Some(entry.seq),
            _ => {}
        }

        if entry.seq > 0 && entry.ts < last_ts {
            warnings.push(Warning::ClockWentBackwards {
                seq: entry.seq,
                prev_ts: last_ts,
                ts: entry.ts,
            });
        }

        if entry.enforcement == Enforcement::Observe {
            observe_count = observe_count.saturating_add(1);
        }

        if let Event::Approval { for_seq, .. } = &entry.event {
            if *for_seq >= entry.seq {
                return Err(Failure::ApprovalTargetMissing {
                    seq: entry.seq,
                    for_seq: *for_seq,
                });
            }
            if !open_asks.contains(for_seq) {
                if answered.contains(for_seq) {
                    warnings.push(Warning::DuplicateApproval {
                        seq: entry.seq,
                        for_seq: *for_seq,
                    });
                } else {
                    return Err(Failure::ApprovalTargetNotAsk {
                        seq: entry.seq,
                        for_seq: *for_seq,
                    });
                }
            } else {
                open_asks.remove(for_seq);
                answered.insert(*for_seq);
            }
        }

        if entry.decision == Decision::Ask {
            open_asks.insert(entry.seq);
        }

        second_last_hash = prev_hash;
        prev_hash = entry.hash;
        last_ts = entry.ts;
        last_seq = entry.seq;
        expected_seq = entry.seq.saturating_add(1);
        entry_count = entry_count.saturating_add(1);
    }

    let session = session.ok_or(Failure::ChainEmpty)?;

    let mut unanswered: Vec<u64> = open_asks.into_iter().collect();
    unanswered.sort_unstable();
    for seq in unanswered {
        warnings.push(Warning::UnansweredAsk { seq });
    }

    if observe_count > 0 {
        warnings.push(Warning::ObserveOnlyEntries {
            count: observe_count,
        });
    }

    match head {
        None => warnings.push(Warning::HeadMissing),
        Some(h) => {
            if h.version != HEAD_VERSION {
                return Err(Failure::HeadVersionUnsupported { got: h.version });
            }
            if h.session != session {
                return Err(Failure::HeadSessionMismatch {
                    head_session: h.session,
                    chain_session: session,
                });
            }
            if h.seq == last_seq && h.hash == prev_hash {
                // 정상
            } else if last_seq > 0
                && h.seq == last_seq.saturating_sub(1)
                && h.hash == second_last_hash
            {
                warnings.push(Warning::HeadLagsByOne {
                    head_seq: h.seq,
                    chain_seq: last_seq,
                });
            } else {
                return Err(Failure::HeadMismatch {
                    head: Box::new(h),
                    chain_seq: last_seq,
                    chain_hash: prev_hash,
                });
            }
        }
    }

    Ok(VerifyReport {
        entries: entry_count,
        session,
        head_seq: last_seq,
        head_hash: prev_hash,
        fsync_per_entry,
        session_ended: ended_at.is_some(),
        warnings,
    })
}
