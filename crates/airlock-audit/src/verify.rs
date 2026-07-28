use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::entry::Entry;
use crate::error::Error;
use crate::event::Event;
use crate::log::{CHAIN_FILE, HEAD_FILE, HEAD_VERSION, Head, read_head};
use crate::types::{Decision, Enforcement, Hash, SessionId};

#[derive(Debug)]
pub enum Failure {
    ChainEmpty,
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
            Self::ChainEmpty => write!(f, "체인이 비어 있음"),
            Self::MalformedLine { line, detail } => {
                write!(f, "{line}번째 줄 파싱 실패: {detail}")
            }
            Self::TruncatedFinalLine { line } => {
                write!(f, "{line}번째 줄이 개행 없이 잘림. 쓰기 중 중단 의심")
            }
            Self::GenesisPrevNotZero { got } => {
                write!(f, "genesis의 prev가 0이 아님: {got}")
            }
            Self::GenesisNotSessionStart { got } => {
                write!(f, "genesis 이벤트가 session_start가 아님: {got}")
            }
            Self::SeqGap { expected, got } => {
                write!(f, "seq 빈틈. {expected} 기대, {got} 발견")
            }
            Self::SessionMismatch { seq, expected, got } => write!(
                f,
                "seq {seq}의 session이 체인과 다름. {expected} 기대, {got} 발견"
            ),
            Self::PrevMismatch { seq, expected, got } => write!(
                f,
                "seq {seq}의 prev 불일치. {expected} 기대, {got} 발견. 삭제·삽입·재배치 의심"
            ),
            Self::HashMismatch { seq, expected, got } => write!(
                f,
                "seq {seq}의 hash 불일치. 재계산 {expected}, 기록 {got}. 내용 변조 의심"
            ),
            Self::ApprovalTargetMissing { seq, for_seq } => {
                write!(f, "seq {seq} approval이 존재하지 않는 seq {for_seq}를 참조")
            }
            Self::ApprovalTargetNotAsk { seq, for_seq } => {
                write!(f, "seq {seq} approval의 대상 seq {for_seq}가 ask가 아님")
            }
            Self::HeadMismatch {
                head,
                chain_seq,
                chain_hash,
            } => write!(
                f,
                "앵커 불일치. head는 seq {} hash {}, 체인은 seq {chain_seq} hash {chain_hash}. 잘라내기 의심",
                head.seq, head.hash
            ),
            Self::HeadSessionMismatch {
                head_session,
                chain_session,
            } => write!(
                f,
                "앵커 session 불일치. head {head_session}, 체인 {chain_session}"
            ),
            Self::HeadAbsent => write!(
                f,
                "head.json 없음. 앵커 없이는 잘라내기를 탐지할 수 없음. 앵커 삭제 의심"
            ),
            Self::HeadUnreadable { detail } => write!(
                f,
                "head.json을 읽을 수 없음: {detail}. 앵커 없이는 잘라내기를 탐지할 수 없음"
            ),
            Self::HeadVersionUnsupported { got } => {
                write!(f, "head.json version {got}는 지원하지 않음. 1이어야 함")
            }
            Self::BlankLine { line } => {
                write!(
                    f,
                    "{line}번째 줄이 비어 있음. 엔트리가 아닌 줄이 끼어들었음"
                )
            }
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
                "seq {seq}에서 벽시계가 역행 ({prev_ts} -> {ts}). 시각 조정 가능성"
            ),
            Self::HeadLagsByOne {
                head_seq,
                chain_seq,
            } => write!(
                f,
                "앵커가 한 칸 뒤처짐 (head {head_seq}, 체인 {chain_seq}). 크래시 잔여로 판단"
            ),
            Self::DuplicateApproval { seq, for_seq } => {
                write!(f, "seq {seq}가 이미 응답된 seq {for_seq}를 다시 승인")
            }
            Self::UnansweredAsk { seq } => {
                write!(f, "seq {seq}의 ask에 대한 approval 엔트리가 없음")
            }
            Self::ObserveOnlyEntries { count } => write!(
                f,
                "{count}개 엔트리가 observe 모드에서 기록됨. 강제되지 않은 관찰 기록임"
            ),
            Self::HeadMissing => write!(f, "head.json 없음. 잘라내기를 탐지할 수 없음"),
        }
    }
}

#[derive(Debug)]
pub struct VerifyReport {
    pub entries: u64,
    pub session: SessionId,
    pub head_seq: u64,
    pub head_hash: Hash,
    pub warnings: Vec<Warning>,
}

impl VerifyReport {
    pub fn is_clean(&self) -> bool {
        self.warnings.is_empty()
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
        warnings,
    })
}
