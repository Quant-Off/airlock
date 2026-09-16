//! seccomp BPF 프로그램 조립. 커널 호출이 없는 순수 로직이라 모든 플랫폼에서 컴파일되고
//! 테스트되며, Linux 의 `notify` 모듈만 실제로 씁니다
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SockFilter {
    pub(crate) code: u16,
    pub(crate) jt: u8,
    pub(crate) jf: u8,
    pub(crate) k: u32,
}

pub(crate) const LD_W_ABS: u16 = 0x20;
pub(crate) const JMP_JEQ_K: u16 = 0x15;
pub(crate) const JMP_JGE_K: u16 = 0x35;
pub(crate) const RET_K: u16 = 0x06;

pub(crate) const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub(crate) const RET_ERRNO: u32 = 0x0005_0000;
pub(crate) const RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub(crate) const RET_ALLOW: u32 = 0x7fff_0000;

pub(crate) const OFF_NR: u32 = 0;
pub(crate) const OFF_ARCH: u32 = 4;

pub(crate) const fn off_arg_lo(index: u32) -> u32 {
    let base = 16 + index * 8;
    if cfg!(target_endian = "big") {
        base + 4
    } else {
        base
    }
}

pub(crate) const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

pub(crate) const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

fn offset(n: usize) -> u8 {
    u8::try_from(n).unwrap_or(u8::MAX)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layout {
    pub(crate) native_arch: u32,
    pub(crate) x32_bit: Option<u32>,
    pub(crate) ioctl_nr: u32,
    pub(crate) refused_ioctls: Vec<u32>,
    pub(crate) refused_errno: u32,
    pub(crate) mediated: Vec<u32>,
}

pub(crate) fn assemble(layout: &Layout) -> Vec<SockFilter> {
    let guard = layout.refused_ioctls.len();
    let mediated = layout.mediated.len();
    let mut prog = Vec::with_capacity(guard.saturating_add(mediated).saturating_add(12));

    prog.push(stmt(LD_W_ABS, OFF_ARCH));
    prog.push(jump(JMP_JEQ_K, layout.native_arch, 1, 0));
    prog.push(stmt(RET_K, RET_KILL_PROCESS));

    prog.push(stmt(LD_W_ABS, OFF_NR));
    if let Some(bit) = layout.x32_bit {
        prog.push(jump(JMP_JGE_K, bit, 0, 1));
        prog.push(stmt(RET_K, RET_KILL_PROCESS));
    }

    if guard > 0 {
        // ioctl 이 아니면 인자 적재, 비교 guard 개, 거부, 번호 재적재를 모두 건너뜁니다
        prog.push(jump(
            JMP_JEQ_K,
            layout.ioctl_nr,
            0,
            offset(guard.saturating_add(3)),
        ));
        prog.push(stmt(LD_W_ABS, off_arg_lo(1)));
        for (i, request) in layout.refused_ioctls.iter().enumerate() {
            let to_refuse = guard.saturating_sub(i).saturating_sub(1);
            let last = i.saturating_add(1) == guard;
            prog.push(jump(JMP_JEQ_K, *request, offset(to_refuse), u8::from(last)));
        }
        prog.push(stmt(RET_K, RET_ERRNO | (layout.refused_errno & 0xffff)));
        // 누산기에 ioctl 인자가 남아 있으므로 번호를 다시 적재해야 아래 비교가 맞습니다
        prog.push(stmt(LD_W_ABS, OFF_NR));
    }

    for (i, nr) in layout.mediated.iter().enumerate() {
        let to_notify = mediated.saturating_sub(i);
        prog.push(jump(JMP_JEQ_K, *nr, offset(to_notify), 0));
    }
    prog.push(stmt(RET_K, RET_ALLOW));
    if mediated > 0 {
        prog.push(stmt(RET_K, RET_USER_NOTIF));
    }
    prog
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCH: u32 = 0xc000_003e;
    const OTHER_ARCH: u32 = 0xc000_00b7;
    const X32: u32 = 0x4000_0000;
    const IOCTL: u32 = 16;
    const EXECVE: u32 = 59;
    const CONNECT: u32 = 42;
    const WRITE: u32 = 1;
    const TIOCSTI: u32 = 0x5412;
    const TIOCLINUX: u32 = 0x541C;
    const EPERM: u32 = 1;

    fn layout(mediated: Vec<u32>) -> Layout {
        Layout {
            native_arch: ARCH,
            x32_bit: Some(X32),
            ioctl_nr: IOCTL,
            refused_ioctls: vec![TIOCSTI, TIOCLINUX],
            refused_errno: EPERM,
            mediated,
        }
    }

    fn data(nr: u32, arch: u32, args: [u64; 6]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..4].copy_from_slice(&nr.to_ne_bytes());
        out[4..8].copy_from_slice(&arch.to_ne_bytes());
        for (i, a) in args.iter().enumerate() {
            let at = 16 + i * 8;
            out[at..at + 8].copy_from_slice(&a.to_ne_bytes());
        }
        out
    }

    fn run(prog: &[SockFilter], data: &[u8; 64]) -> u32 {
        let mut pc = 0usize;
        let mut acc = 0u32;
        for _ in 0..prog.len() + 1 {
            let insn = prog[pc];
            match insn.code {
                LD_W_ABS => {
                    let k = insn.k as usize;
                    let mut word = [0u8; 4];
                    word.copy_from_slice(&data[k..k + 4]);
                    acc = u32::from_ne_bytes(word);
                    pc += 1;
                }
                JMP_JEQ_K => {
                    pc += 1 + usize::from(if acc == insn.k { insn.jt } else { insn.jf });
                }
                JMP_JGE_K => {
                    pc += 1 + usize::from(if acc >= insn.k { insn.jt } else { insn.jf });
                }
                RET_K => return insn.k,
                other => panic!("모르는 opcode {other:#x}"),
            }
        }
        panic!("프로그램이 끝나지 않음");
    }

    fn ioctl(request: u64) -> [u8; 64] {
        data(IOCTL, ARCH, [3, request, 0, 0, 0, 0])
    }

    #[test]
    fn refused_ioctls_get_eperm_at_every_level() {
        for mediated in [vec![], vec![CONNECT, EXECVE]] {
            let prog = assemble(&layout(mediated));
            assert_eq!(run(&prog, &ioctl(u64::from(TIOCSTI))), RET_ERRNO | EPERM);
            assert_eq!(run(&prog, &ioctl(u64::from(TIOCLINUX))), RET_ERRNO | EPERM);
        }
    }

    #[test]
    fn only_the_low_32_bits_of_the_request_are_compared() {
        // 커널은 request 를 unsigned int 로 받으므로 상위 비트는 무시됩니다
        let prog = assemble(&layout(vec![EXECVE]));
        let high = 0x0000_0001_0000_0000u64 | u64::from(TIOCSTI);
        assert_eq!(run(&prog, &ioctl(high)), RET_ERRNO | EPERM);
        let high = 0xffff_ffff_0000_0000u64 | u64::from(TIOCLINUX);
        assert_eq!(run(&prog, &ioctl(high)), RET_ERRNO | EPERM);
    }

    #[test]
    fn other_ioctls_pass_and_the_accumulator_is_reloaded() {
        let prog = assemble(&layout(vec![0x5555, EXECVE]));
        assert_eq!(run(&prog, &ioctl(0x5401)), RET_ALLOW);
        // 재적재가 없으면 인자 0x5555 가 중계 번호 0x5555 와 맞아 USER_NOTIF 가 됩니다
        assert_eq!(run(&prog, &ioctl(0x5555)), RET_ALLOW);
        assert_eq!(run(&prog, &ioctl(0)), RET_ALLOW);
    }

    #[test]
    fn mediated_syscalls_notify_and_others_pass() {
        let prog = assemble(&layout(vec![CONNECT, EXECVE, 322]));
        for nr in [CONNECT, EXECVE, 322] {
            assert_eq!(run(&prog, &data(nr, ARCH, [0; 6])), RET_USER_NOTIF);
        }
        for nr in [WRITE, 0, 257, 1000] {
            assert_eq!(run(&prog, &data(nr, ARCH, [0; 6])), RET_ALLOW);
        }
    }

    #[test]
    fn a_long_mediated_list_still_jumps_correctly() {
        let nrs: Vec<u32> = (100..113).collect();
        let prog = assemble(&layout(nrs.clone()));
        for nr in nrs {
            assert_eq!(run(&prog, &data(nr, ARCH, [0; 6])), RET_USER_NOTIF);
        }
        assert_eq!(run(&prog, &data(113, ARCH, [0; 6])), RET_ALLOW);
        assert_eq!(run(&prog, &data(99, ARCH, [0; 6])), RET_ALLOW);
        assert_eq!(run(&prog, &ioctl(u64::from(TIOCSTI))), RET_ERRNO | EPERM);
    }

    #[test]
    fn a_foreign_architecture_is_killed_before_anything_else() {
        let prog = assemble(&layout(vec![EXECVE]));
        assert_eq!(
            run(&prog, &data(WRITE, OTHER_ARCH, [0; 6])),
            RET_KILL_PROCESS
        );
        assert_eq!(
            run(
                &prog,
                &data(IOCTL, OTHER_ARCH, [3, u64::from(TIOCSTI), 0, 0, 0, 0])
            ),
            RET_KILL_PROCESS
        );
    }

    #[test]
    fn x32_numbers_are_killed_only_when_the_bit_is_known() {
        let prog = assemble(&layout(vec![EXECVE]));
        assert_eq!(
            run(&prog, &data(X32 | IOCTL, ARCH, [0; 6])),
            RET_KILL_PROCESS
        );
        assert_eq!(
            run(&prog, &data(X32 | EXECVE, ARCH, [0; 6])),
            RET_KILL_PROCESS
        );

        let mut no_x32 = layout(vec![EXECVE]);
        no_x32.x32_bit = None;
        let prog = assemble(&no_x32);
        assert_eq!(run(&prog, &data(X32 | WRITE, ARCH, [0; 6])), RET_ALLOW);
    }

    #[test]
    fn every_jump_lands_inside_the_program_and_it_ends_in_ret() {
        for mediated in [vec![], vec![EXECVE], (1..14).collect()] {
            let prog = assemble(&layout(mediated));
            for (i, insn) in prog.iter().enumerate() {
                if insn.code == JMP_JEQ_K || insn.code == JMP_JGE_K {
                    assert!(
                        i + 1 + usize::from(insn.jt) < prog.len(),
                        "jt 가 밖으로 나감"
                    );
                    assert!(
                        i + 1 + usize::from(insn.jf) < prog.len(),
                        "jf 가 밖으로 나감"
                    );
                }
            }
            assert_eq!(prog.last().map(|i| i.code), Some(RET_K));
        }
    }

    #[test]
    fn an_empty_mediated_list_has_no_user_notif() {
        let prog = assemble(&layout(vec![]));
        assert!(
            !prog
                .iter()
                .any(|i| i.code == RET_K && i.k == RET_USER_NOTIF)
        );
        assert_eq!(prog.last().map(|i| i.k), Some(RET_ALLOW));
    }

    #[test]
    fn an_empty_refused_list_has_no_guard() {
        let mut no_guard = layout(vec![EXECVE]);
        no_guard.refused_ioctls.clear();
        let prog = assemble(&no_guard);
        assert!(
            !prog
                .iter()
                .any(|i| i.code == RET_K && i.k & 0xffff_0000 == RET_ERRNO)
        );
        assert_eq!(run(&prog, &ioctl(u64::from(TIOCSTI))), RET_ALLOW);
    }

    #[test]
    fn the_argument_offset_follows_the_kernel_layout() {
        assert_eq!(off_arg_lo(0) & !4, 16);
        assert_eq!(off_arg_lo(1) & !4, 24);
        assert_eq!(off_arg_lo(5) & !4, 56);
    }
}
