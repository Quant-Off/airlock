#![cfg(target_os = "linux")]

//! 이 모듈은 seccomp user notification으로 자식 프로세스의 파일·네트워크·exec 시도를
//! 브로커에 중계해 감사 엔트리를 남기고 `ask` 승인을 받습니다.
//!
//! # Features
//! `docs/design.md` 10.2절의 방침대로 C 라이브러리를 TCB에 넣지 않습니다. BPF 프로그램과
//! `seccomp_notif` 구조체를 `libc` 위에서 직접 조립합니다.
//!
//! 자식은 `pre_exec`에서 필터를 걸고 돌려받은 listener fd를 socketpair로 부모에게
//! 넘깁니다. 부모는 감독 스레드에서 알림을 받아 정책을 평가하고 응답합니다.
//!
//! # Errors
//! 이 층은 **보안 경계가 아니라 관측과 승인 채널입니다.** 경로 인자를 읽은 시점과 커널이
//! 실제로 여는 시점 사이에 링크가 바뀔 수 있어 구조적으로 TOCTOU를 안습니다
//! (`docs/policy-dsl.md` 4.2절). 실제 강제는 inode에 규칙을 거는 Landlock이 합니다.
//! 그래서 여기서 내리는 거부는 방어의 층 하나일 뿐이며, 이 층만 믿어서는 안 됩니다.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use airlock_audit::Protocol;
use airlock_policy::FileMode;

use crate::session::Session;

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
/// 프로세스 전체를 즉시 죽입니다.
///
/// 중계할 수 없는 ABI로 들어온 syscall에 씁니다. 통과시키면 그 ABI로 부른 exec과
/// connect가 승인 흐름을 통째로 우회하고, errno로 거부하면 프로그램이 무엇이 실패했는지
/// 모른 채 같은 호출을 반복합니다
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

/// x86_64에서 x32 ABI로 부른 syscall은 번호에 이 비트가 켜집니다.
///
/// `arch`는 여전히 `AUDIT_ARCH_X86_64`라서 아키텍처 검사를 통과하지만 번호 체계가
/// 달라 비교가 모두 빗나갑니다. 검사 없이 통과시키면 중계가 우회됩니다
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// _IOC(dir, type, nr, size) = (dir << 30) | (size << 16) | (type << 8) | nr, type = '!'
const fn ioc(dir: libc::c_ulong, nr: libc::c_ulong, size: libc::c_ulong) -> libc::c_ulong {
    (dir << 30) | (size << 16) | (0x21 << 8) | nr
}
const IOC_WRITE: libc::c_ulong = 1;
const IOC_READ: libc::c_ulong = 2;

const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = ioc(IOC_WRITE | IOC_READ, 0, 80);
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = ioc(IOC_WRITE | IOC_READ, 1, 24);
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = ioc(IOC_WRITE, 2, 8);

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct SeccompData {
    nr: libc::c_int,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
#[derive(Debug)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// 이 빌드가 도는 아키텍처의 `AUDIT_ARCH_*` 값.
///
/// `__AUDIT_ARCH_64BIT`(0x8000_0000)과 `__AUDIT_ARCH_LE`(0x4000_0000)에 ELF 머신 번호를
/// 더한 값입니다. 모르는 아키텍처에서 컴파일이 깨지지 않도록 `None`으로 두고, 중계를
/// 켜려는 시점에 런타임 오류로 알립니다. 아키텍처 검사 없는 필터를 거는 것보다 낫습니다
#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: Option<u32> = Some(0xc000_003e);
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: Option<u32> = Some(0xc000_00b7);
#[cfg(target_arch = "riscv64")]
const NATIVE_ARCH: Option<u32> = Some(0xc000_00f3);
#[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
const NATIVE_ARCH: Option<u32> = Some(0xc000_0015);
#[cfg(target_arch = "s390x")]
const NATIVE_ARCH: Option<u32> = Some(0x8000_0016);
#[cfg(target_arch = "loongarch64")]
const NATIVE_ARCH: Option<u32> = Some(0xc000_0102);
#[cfg(target_arch = "x86")]
const NATIVE_ARCH: Option<u32> = Some(0x4000_0003);
#[cfg(all(target_arch = "arm", target_endian = "little"))]
const NATIVE_ARCH: Option<u32> = Some(0x4000_0028);
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64",
    all(target_arch = "powerpc64", target_endian = "little"),
    target_arch = "s390x",
    target_arch = "loongarch64",
    target_arch = "x86",
    all(target_arch = "arm", target_endian = "little"),
)))]
const NATIVE_ARCH: Option<u32> = None;

/// 이 아키텍처에 남아 있는 `open` syscall 번호.
///
/// `openat`만 있는 아키텍처에서는 `None`입니다. 빠뜨리면 `open`으로 파일을 여는
/// 프로그램이 관측되지 않습니다
#[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "arm"))]
const LEGACY_OPEN: Option<i32> = Some(libc::SYS_open as i32);
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "arm")))]
const LEGACY_OPEN: Option<i32> = None;

/// 어디까지 중계할지.
///
/// `openat`은 보통 프로그램 하나가 초당 수천 번 부르고, 감사 엔트리는 규격상
/// 항목마다 `fsync` 합니다(`docs/audit-format.md` 4절). 파일까지 중계하면 그 비용이
/// 그대로 실행 시간이 되므로 기본값은 드물게 일어나는 exec과 연결만 중계합니다.
/// 파일 접근의 실제 강제는 Landlock이 하며 이 층은 기록과 승인 채널입니다
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Level {
    /// 중계하지 않습니다. 세션 단위 기록만 남습니다
    Off,
    /// exec과 아웃바운드 연결만 중계합니다
    #[default]
    ExecNet,
    /// 파일 열기까지 중계합니다. 느리지만 모든 접근이 기록됩니다
    Full,
}

impl Level {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "exec-net" => Some(Self::ExecNet),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::ExecNet => "exec-net",
            Self::Full => "full",
        }
    }
}

/// 중계할 syscall 번호.
///
/// `openat2`는 두 아키텍처에서 번호가 같아 리터럴로 적습니다. 빠뜨리면 그 경로로
/// 파일을 여는 프로그램이 관측되지 않습니다
fn mediated_syscalls(level: Level) -> Vec<u32> {
    let mut v: Vec<u32> = vec![
        libc::SYS_connect as u32,
        libc::SYS_execve as u32,
        libc::SYS_execveat as u32,
    ];
    if level == Level::Full {
        v.push(libc::SYS_openat as u32);
        v.push(437); // openat2
        if let Some(nr) = LEGACY_OPEN {
            v.push(nr as u32);
        }
    }
    v
}

/// 중계 필터를 조립합니다.
///
/// # Errors
/// 이 아키텍처의 `AUDIT_ARCH_*` 값을 모르면 `None`입니다. 아키텍처 검사를 뺀 필터는
/// 다른 ABI의 syscall 번호를 자기 것으로 착각하므로 만들지 않습니다
fn build_filter(level: Level) -> Option<Vec<SockFilter>> {
    const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JMP_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const RET_K: u16 = 0x06; // BPF_RET | BPF_K

    let native = NATIVE_ARCH?;
    let nrs = mediated_syscalls(level);
    let mut prog = Vec::with_capacity(nrs.len().saturating_add(8));

    // 아키텍처가 다르면 죽입니다. 32비트 바이너리를 실행하면 syscall 번호 체계가 달라
    // 비교가 전부 빗나가는데, 통과시키면 exec·connect 중계를 통째로 우회합니다.
    // exec ask 는 이 층에만 있으므로 그 우회는 곧 승인 우회입니다
    prog.push(stmt(LD_W_ABS, 4)); // seccomp_data.arch
    prog.push(jump(JMP_JEQ_K, native, 1, 0));
    prog.push(stmt(RET_K, SECCOMP_RET_KILL_PROCESS));

    prog.push(stmt(LD_W_ABS, 0)); // seccomp_data.nr

    // x32 는 arch 가 같으므로 번호로만 걸러 냅니다
    #[cfg(target_arch = "x86_64")]
    {
        const JMP_JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
        prog.push(jump(JMP_JGE_K, X32_SYSCALL_BIT, 0, 1));
        prog.push(stmt(RET_K, SECCOMP_RET_KILL_PROCESS));
    }

    // 마지막 두 명령이 ALLOW, USER_NOTIF이므로 매칭되면 그 지점으로 점프합니다
    let total_after = nrs.len();
    for (i, nr) in nrs.iter().enumerate() {
        let remaining = total_after.saturating_sub(i).saturating_sub(1);
        // 매칭이면 ALLOW를 건너뛰어 USER_NOTIF로, 아니면 다음 비교로
        let jt = u8::try_from(remaining.saturating_add(1)).unwrap_or(u8::MAX);
        prog.push(jump(JMP_JEQ_K, *nr, jt, 0));
    }
    prog.push(stmt(RET_K, SECCOMP_RET_ALLOW));
    prog.push(stmt(RET_K, SECCOMP_RET_USER_NOTIF));
    Some(prog)
}

/// 자식에서 seccomp 필터를 걸고 listener fd를 돌려줍니다.
///
/// # Safety
/// `pre_exec` 문맥에서 호출합니다. 새로 할당하지 않도록 필터는 호출 전에 만들어 둡니다.
/// `no_new_privs`를 먼저 세워야 권한 없는 프로세스가 필터를 걸 수 있습니다
unsafe fn install_filter(prog: &[SockFilter]) -> std::io::Result<RawFd> {
    // # Safety
    // prctl은 호출 프로세스의 플래그만 바꿉니다
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fprog = SockFprog {
        len: u16::try_from(prog.len()).unwrap_or(u16::MAX),
        filter: prog.as_ptr(),
    };
    // # Safety
    // fprog는 이 스코프 동안 유효하고 len은 filter 배열 길이와 일치합니다
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &raw const fprog,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    RawFd::try_from(fd).map_err(|_| std::io::Error::other("listener fd가 범위를 벗어남"))
}

/// SCM_RIGHTS로 fd 하나를 보냅니다.
///
/// # Safety
/// `sock`은 열린 유닉스 도메인 소켓이어야 하고 `fd`는 유효해야 합니다
unsafe fn send_fd(sock: RawFd, fd: RawFd) -> std::io::Result<()> {
    let mut byte: [u8; 1] = [0];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;

    // # Safety
    // msg_control 버퍼가 CMSG_SPACE(4) 이상이며 헤더를 규격대로 채웁니다
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        if cmsg.is_null() {
            return Err(std::io::Error::other("cmsg 헤더를 만들 수 없음"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::copy_nonoverlapping(&raw const fd, libc::CMSG_DATA(cmsg).cast::<RawFd>(), 1);
        if libc::sendmsg(sock, &raw const msg, 0) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// SCM_RIGHTS로 fd 하나를 받습니다.
///
/// # Safety
/// `sock`은 열린 유닉스 도메인 소켓이어야 합니다
unsafe fn recv_fd(sock: RawFd) -> std::io::Result<OwnedFd> {
    let mut byte: [u8; 1] = [0];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;

    // # Safety
    // 커널이 채운 cmsg 헤더를 규격대로 읽습니다
    unsafe {
        let n = libc::recvmsg(sock, &raw mut msg, 0);
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(std::io::Error::other("listener fd를 받지 못함"));
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg).cast::<RawFd>(), &raw mut fd, 1);
        if fd < 0 {
            return Err(std::io::Error::other("받은 fd가 유효하지 않음"));
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// 읽을 문자열의 최대 길이. 리눅스 `PATH_MAX`와 같습니다.
///
/// 상한을 넘기면 잘린 값을 돌려주지 않고 실패로 처리합니다. 부분 경로로 정책을 평가하면
/// 실제로 열리는 대상과 다른 것을 판정하게 됩니다
const MAX_CSTR: usize = 4096;

/// 대상 프로세스의 메모리에서 널 종료 문자열을 읽습니다.
///
/// # Errors
/// 대상이 이미 죽었거나 주소가 유효하지 않거나 [`MAX_CSTR`]를 넘으면 실패합니다.
/// 실패는 곧 판단 불가이며 호출자는 제한 방향으로 처리합니다
fn read_cstr(pid: u32, addr: u64) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    if addr == 0 {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(256);
    let mut buf = [0u8; 256];
    let mut offset: u64 = 0;

    loop {
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: (addr.saturating_add(offset)) as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // # Safety
        // 두 iovec는 유효하며 커널이 읽을 수 있는 만큼만 복사하고 길이를 돌려줍니다
        let n = unsafe { libc::process_vm_readv(pid as libc::pid_t, &local, 1, &remote, 1, 0) };
        if n <= 0 {
            return None;
        }
        let n = usize::try_from(n).ok()?;
        if let Some(pos) = buf[..n].iter().position(|b| *b == 0) {
            out.extend_from_slice(&buf[..pos]);
            return Some(PathBuf::from(std::ffi::OsString::from_vec(out)));
        }
        out.extend_from_slice(&buf[..n]);
        if out.len() > MAX_CSTR {
            return None;
        }
        offset = offset.saturating_add(n as u64);
    }
}

/// dirfd 기준 상대 경로를 절대 경로로 만듭니다 (`docs/policy-dsl.md` 4.2절).
fn resolve_at(pid: u32, dirfd: i64, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    let base = if dirfd == libc::AT_FDCWD as i64 {
        std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
    } else if dirfd >= 0 {
        std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).ok()
    } else {
        None
    };
    match base {
        Some(b) => b.join(path),
        None => path,
    }
}

/// `connect`의 대상 주소를 읽은 결과.
///
/// "정책 대상이 아님"과 "판단할 수 없음"을 반드시 구분합니다. 둘을 같은 값으로 뭉개면
/// 유닉스 소켓을 통과시키려던 경로가 주소를 읽지 못한 경우까지 통과시킵니다
#[derive(Debug, Clone, PartialEq, Eq)]
enum Peer {
    Inet {
        host: String,
        port: u16,
        protocol: Protocol,
    },
    /// 유닉스 소켓 등 egress 정책의 대상이 아닌 주소 계열
    NotInet,
    /// 읽지 못했거나 길이·형태가 규격에 맞지 않음
    Unreadable,
}

fn sockaddr_of(pid: u32, addr: u64, len: u64) -> Peer {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let Ok(len) = usize::try_from(len) else {
        return Peer::Unreadable;
    };
    // sockaddr_storage 보다 큰 길이나 sa_family 도 담기지 못하는 길이는 커널도 거부합니다
    if !(2..=128).contains(&len) {
        return Peer::Unreadable;
    }
    let mut buf = vec![0u8; len];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    // # Safety
    // 두 iovec는 유효하고 len 바이트만 복사합니다
    let n = unsafe { libc::process_vm_readv(pid as libc::pid_t, &local, 1, &remote, 1, 0) };
    // 짧게 읽힌 버퍼의 나머지는 0으로 남아 있어 엉뚱한 주소로 해석됩니다
    if n < 0 || usize::try_from(n).map(|got| got != len).unwrap_or(true) {
        return Peer::Unreadable;
    }

    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    match i32::from(family) {
        libc::AF_INET => {
            if len < 8 {
                return Peer::Unreadable;
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            Peer::Inet {
                host: ip.to_string(),
                port,
                protocol: Protocol::Tcp,
            }
        }
        libc::AF_INET6 => {
            if len < 24 {
                return Peer::Unreadable;
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[8..24]);
            let ip = Ipv6Addr::from(octets);
            Peer::Inet {
                host: ip.to_canonical().to_string(),
                port,
                protocol: Protocol::Tcp,
            }
        }
        _ => Peer::NotInet,
    }
}

/// 이 알림이 아직 유효한지 확인합니다.
///
/// 대상이 죽었거나 시그널로 syscall이 취소되면 응답이 엉뚱한 요청에 붙을 수 있습니다.
/// `docs/policy-dsl.md` 4.2절이 요구하는 liveness 확인입니다
fn id_valid(fd: RawFd, id: u64) -> bool {
    // # Safety
    // id는 커널이 방금 준 값이고 ioctl은 유효성만 확인합니다
    unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &raw const id) == 0 }
}

fn respond(fd: RawFd, id: u64, allow: bool) {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: if allow { 0 } else { -libc::EACCES },
        flags: if allow {
            SECCOMP_USER_NOTIF_FLAG_CONTINUE
        } else {
            0
        },
    };
    // # Safety
    // resp는 커널이 기대하는 레이아웃이며 id는 방금 받은 알림의 것입니다
    unsafe {
        libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &raw const resp);
    }
}

fn file_mode_for(flags: u64) -> FileMode {
    let acc = (flags as libc::c_int) & libc::O_ACCMODE;
    if acc == libc::O_RDONLY && (flags as libc::c_int) & libc::O_CREAT == 0 {
        FileMode::Read
    } else if (flags as libc::c_int) & libc::O_CREAT != 0 {
        FileMode::Create
    } else {
        FileMode::Write
    }
}

/// 감독 스레드가 들고 갈 부모 쪽 소켓
#[derive(Debug)]
pub struct ParentEnd {
    sock: OwnedFd,
}

impl ParentEnd {
    /// 자식이 보낸 listener fd를 받습니다.
    ///
    /// `Command::spawn`은 자식이 exec을 마칠 때까지 돌아오지 않는데 그 exec 자체가
    /// 알림으로 멈춰 있으므로, 이 호출은 반드시 spawn을 부르는 스레드와 다른
    /// 스레드에서 먼저 대기하고 있어야 합니다
    pub fn receive(&self) -> std::io::Result<OwnedFd> {
        // # Safety
        // sock은 열린 유닉스 도메인 소켓입니다
        unsafe { recv_fd(self.sock.as_raw_fd()) }
    }
}

/// 감독 루프. 알림을 하나씩 받아 정책을 평가하고 응답합니다
pub fn supervise(listener: OwnedFd, session: Arc<Mutex<Session>>, stop: Arc<AtomicBool>) {
    let fd = listener.as_raw_fd();
    let openat_nr = libc::SYS_openat as i32;
    let connect_nr = libc::SYS_connect as i32;
    let execve_nr = libc::SYS_execve as i32;
    let execveat_nr = libc::SYS_execveat as i32;

    // 첫 알림은 반드시 직속 자식이 자기 자신을 exec 하는 것입니다. 그 결정은 spawn 전에
    // 이미 내려 감사에 기록했으므로 여기서 다시 묻지 않습니다. 두 번 물으면 사용자가
    // 같은 exec에 대해 승인 프롬프트를 두 번 보게 됩니다
    let mut first_exec_seen = false;

    while !stop.load(Ordering::Relaxed) {
        let mut notif = SeccompNotif::default();
        // # Safety
        // notif는 커널이 기대하는 레이아웃이고 매 회 새로 0으로 채웁니다
        let rc = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &raw mut notif) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // 자식이 모두 끝나면 listener가 닫히고 ENOENT/ENOTTY로 빠져나옵니다
            break;
        }

        let pid = notif.pid;
        let nr = notif.data.nr;
        let args = notif.data.args;

        let allow = if nr == connect_nr {
            match sockaddr_of(pid, args[1], args[2]) {
                Peer::Inet {
                    host,
                    port,
                    protocol,
                } => {
                    let mut s = match session.lock() {
                        Ok(s) => s,
                        Err(_) => break,
                    };
                    s.check_egress(&host, port, protocol)
                        .map(|o| o.permitted())
                        .unwrap_or(false)
                }
                // 유닉스 소켓 등은 egress 정책의 대상이 아니므로 통과시킵니다
                Peer::NotInet => true,
                // 주소를 읽지 못한 것은 판단 불가입니다. exec 과 open 이 그렇게 하듯 거부합니다
                Peer::Unreadable => false,
            }
        } else if nr == execve_nr || nr == execveat_nr {
            if !first_exec_seen {
                first_exec_seen = true;
                if id_valid(fd, notif.id) {
                    respond(fd, notif.id, true);
                }
                continue;
            }
            let (dirfd, path_arg, argv_arg) = if nr == execveat_nr {
                (args[0] as i64, args[1], args[2])
            } else {
                (libc::AT_FDCWD as i64, args[0], args[1])
            };
            match read_cstr(pid, path_arg) {
                Some(p) => {
                    let program = resolve_at(pid, dirfd, p);
                    let argv = read_argv(pid, argv_arg);
                    let mut s = match session.lock() {
                        Ok(s) => s,
                        Err(_) => break,
                    };
                    s.check_exec(&program, &argv)
                        .map(|o| o.permitted())
                        .unwrap_or(false)
                }
                None => false,
            }
        } else {
            // openat / openat2 / open
            let (dirfd, path_arg, mode) = if nr == openat_nr {
                (args[0] as i64, args[1], file_mode_for(args[2]))
            } else if LEGACY_OPEN == Some(nr) {
                (libc::AT_FDCWD as i64, args[0], file_mode_for(args[1]))
            } else {
                // openat2 는 세 번째 인자가 open_how 구조체 포인터입니다. 플래그를 따로
                // 읽지 않고 읽기로 보수적으로 잡아 정책 평가만 받습니다
                (args[0] as i64, args[1], FileMode::Read)
            };
            match read_cstr(pid, path_arg) {
                Some(p) => {
                    let path = resolve_at(pid, dirfd, p);
                    let mut s = match session.lock() {
                        Ok(s) => s,
                        Err(_) => break,
                    };
                    s.check_file(&path, mode)
                        .map(|o| o.permitted())
                        .unwrap_or(false)
                }
                None => false,
            }
        };

        // 응답 직전에 다시 확인합니다. 사이에 대상이 죽었으면 이 id는 무효입니다
        if !id_valid(fd, notif.id) {
            continue;
        }
        respond(fd, notif.id, allow);
    }
}

/// 읽을 argv 원소 수 상한.
///
/// 상한 자체는 필요합니다. 대상 프로세스의 포인터 배열이 널로 끝난다는 보장이 없으므로
/// 무한히 따라갈 수 없습니다
const MAX_ARGV: usize = 256;

/// 잘렸다는 사실을 엔트리에 남기는 표시.
///
/// 감사 로그는 "관측된 사실"을 주장하므로, 부분값을 전부인 것처럼 남길 수 없습니다.
/// 정책 평가도 이 잘린 목록으로 이루어졌음을 사후에 알 수 있어야 합니다
const ARGV_TRUNCATED: &str = "…airlock: argv가 상한에서 잘림";
const ARGV_UNREADABLE: &str = "…airlock: argv 원소를 읽지 못해 여기서 멈춤";

fn read_argv(pid: u32, addr: u64) -> Vec<String> {
    let mut out = Vec::new();
    if addr == 0 {
        return out;
    }
    for i in 0..MAX_ARGV as u64 {
        let mut slot: u64 = 0;
        let local = libc::iovec {
            iov_base: (&raw mut slot).cast(),
            iov_len: 8,
        };
        let remote = libc::iovec {
            iov_base: (addr.saturating_add(i.saturating_mul(8))) as *mut libc::c_void,
            iov_len: 8,
        };
        // # Safety
        // 포인터 배열을 한 칸씩 읽습니다. 실패하면 거기서 멈춥니다
        let n = unsafe { libc::process_vm_readv(pid as libc::pid_t, &local, 1, &remote, 1, 0) };
        if n != 8 {
            out.push(ARGV_UNREADABLE.to_string());
            break;
        }
        if slot == 0 {
            return out;
        }
        match read_cstr(pid, slot) {
            Some(s) => out.push(s.to_string_lossy().into_owned()),
            None => {
                out.push(ARGV_UNREADABLE.to_string());
                break;
            }
        }
    }
    if out.len() >= MAX_ARGV {
        out.push(ARGV_TRUNCATED.to_string());
    }
    out
}

/// 자식에 필터를 걸고 부모가 listener fd를 받을 수 있게 socketpair를 준비합니다
#[derive(Debug)]
pub struct NotifyChannel {
    parent: OwnedFd,
    child: OwnedFd,
    prog: Vec<SockFilter>,
}

impl NotifyChannel {
    pub fn new(level: Level) -> std::io::Result<Self> {
        if level == Level::Off {
            return Err(std::io::Error::other("중계가 꺼져 있음"));
        }
        // 필터를 fork 전에 만들어 둡니다. 자식의 pre_exec 문맥에서는 새로 할당하지 않습니다
        let prog = build_filter(level).ok_or_else(|| {
            std::io::Error::other("이 아키텍처의 seccomp arch 값을 모름. 중계 필터를 만들 수 없음")
        })?;
        let mut fds = [0 as RawFd; 2];
        // # Safety
        // fds는 두 칸짜리 배열이며 커널이 두 fd를 채웁니다
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // # Safety
        // 방금 만든 두 fd의 소유권을 가져옵니다
        unsafe {
            Ok(Self {
                parent: OwnedFd::from_raw_fd(fds[0]),
                child: OwnedFd::from_raw_fd(fds[1]),
                prog,
            })
        }
    }

    /// 자식에서 실행할 클로저를 만듭니다. `pre_exec` 안에서 호출됩니다
    pub fn child_hook(&self) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
        let prog = self.prog.clone();
        let child_fd = self.child.as_raw_fd();
        move || {
            // # Safety
            // pre_exec 문맥이며 프로그램은 fork 전에 만들어 두었습니다
            let listener = unsafe { install_filter(&prog)? };
            // # Safety
            // child_fd는 fork로 상속된 socketpair의 자식 쪽입니다
            unsafe { send_fd(child_fd, listener)? };
            // # Safety
            // 부모가 fd를 복제해 갔으므로 자식 쪽 원본은 닫습니다
            unsafe { libc::close(listener) };
            Ok(())
        }
    }

    /// 부모 쪽과 자식 쪽 소켓을 분리합니다.
    ///
    /// 부모 쪽은 감독 스레드로 옮기고 자식 쪽은 `spawn` 직후 닫아야 합니다. 자식 쪽이
    /// 부모 프로세스에 열려 있으면 자식이 죽어도 `recvmsg`가 EOF를 보지 못해
    /// 감독 스레드가 영원히 막힙니다
    pub fn split(self) -> (ParentEnd, OwnedFd) {
        (ParentEnd { sock: self.parent }, self.child)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(level: Level) -> Vec<SockFilter> {
        build_filter(level).expect("이 아키텍처의 필터를 만들 수 없음")
    }

    #[test]
    fn filter_program_is_well_formed() {
        let prog = filter(Level::Full);
        assert!(prog.len() >= 6, "필터가 너무 짧음");
        let last = prog.last().copied().expect("빈 필터");
        assert_eq!(last.k, SECCOMP_RET_USER_NOTIF, "마지막은 USER_NOTIF여야 함");
        let allow = prog
            .get(prog.len().saturating_sub(2))
            .copied()
            .expect("짧음");
        assert_eq!(allow.k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn every_mediated_syscall_has_a_comparison() {
        let nrs = mediated_syscalls(Level::Full);
        let prog = filter(Level::Full);
        for nr in nrs {
            assert!(
                prog.iter().any(|i| i.k == nr && i.code == 0x15),
                "syscall {nr} 비교가 필터에 없음"
            );
        }
    }

    #[test]
    fn foreign_architecture_is_killed_not_allowed() {
        let prog = filter(Level::ExecNet);
        // 첫 세 명령이 arch 적재, 비교, 불일치 처리입니다
        assert_eq!(
            prog.first().map(|i| i.k),
            Some(4),
            "arch 적재가 먼저여야 함"
        );
        assert_eq!(
            prog.get(1).map(|i| i.k),
            NATIVE_ARCH,
            "네이티브 arch 비교가 없음"
        );
        assert_eq!(
            prog.get(2).map(|i| i.k),
            Some(SECCOMP_RET_KILL_PROCESS),
            "아키텍처 불일치를 통과시키면 중계가 통째로 우회됨"
        );
        assert!(
            !prog
                .iter()
                .take(3)
                .any(|i| i.k == SECCOMP_RET_ALLOW && i.code == 0x06),
            "아키텍처 검사 구간에 ALLOW가 있으면 안 됨"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_syscall_numbers_are_killed() {
        let prog = filter(Level::ExecNet);
        let idx = prog
            .iter()
            .position(|i| i.k == X32_SYSCALL_BIT)
            .expect("x32 비트 검사가 없음. arch 검사를 통과하면서 번호가 어긋나 우회됨");
        assert_eq!(
            prog.get(idx.saturating_add(1)).map(|i| i.k),
            Some(SECCOMP_RET_KILL_PROCESS)
        );
    }

    #[test]
    fn ioctl_numbers_match_the_kernel_abi() {
        // 커널 uapi의 _IOWR('!', 0, struct seccomp_notif) 등과 같아야 합니다
        assert_eq!(SECCOMP_IOCTL_NOTIF_RECV, 0xc050_2100);
        assert_eq!(SECCOMP_IOCTL_NOTIF_SEND, 0xc018_2101);
        assert_eq!(SECCOMP_IOCTL_NOTIF_ID_VALID, 0x4008_2102);
    }

    #[test]
    fn struct_layouts_match_the_kernel() {
        assert_eq!(std::mem::size_of::<SeccompData>(), 64);
        assert_eq!(std::mem::size_of::<SeccompNotif>(), 80);
        assert_eq!(std::mem::size_of::<SeccompNotifResp>(), 24);
    }

    #[test]
    fn open_flags_map_to_modes() {
        assert_eq!(file_mode_for(libc::O_RDONLY as u64), FileMode::Read);
        assert_eq!(file_mode_for(libc::O_WRONLY as u64), FileMode::Write);
        assert_eq!(
            file_mode_for((libc::O_WRONLY | libc::O_CREAT) as u64),
            FileMode::Create
        );
    }
}
