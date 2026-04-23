//! Raw syscall wrappers for x86_64, will addd aarch64 soon

use core::net::SocketAddr;
use std::arch::asm;
use std::io;
use std::mem;

/// Linux x86_64: SYS_geteuid = 107
/// Linux aarch64: SYS_geteuid = 175
/// always successful, no errno, returns current effective UID in rax.
/// todo: add to detection (low confidence), process checking euid within x time after starting if it returns 0?
/// todo: add to detection (low confidence), process check uid after euid and/or comparing uid != euid or uid = 0
#[inline]
pub fn geteuid() -> u32 {
    let ret: u64; // syscall returns 64bits
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") 107_u64 => ret, // rax is used for input and return value is written to rax
            lateout("rcx") _, // clobbered by syscall (RIP)
            lateout("r11") _, // clobbered by syscall (RFLAGS)
            options(nostack, preserves_flags), // no push/pop and no stack alignment needed, we wont be using the flags later setting this even though syscall clobbers flags for optimization
        );
    }
    ret as u32 // return 32 low bits
}

/// Linux x86_64: SYS_getpid = 39
/// Linux aarch64: SYS_getpid = 172
/// always successful no errno, returns caller's PID in rax.
/// //todo: (test) add to detection (high confidence), process checks getpid() and return value = 1 (init) and is not /sbin/init. used in some container escapes
#[inline]
pub fn getpid() -> u32 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") 39_u64 => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret as u32
}


/// Linux x86_64: SYS_socket = 41
/// Linux aarch64: SYS_socket = 198
/// Returns fd on success, or -errno in the [-4095, -1] range.
#[inline]
pub fn socket_tcp() -> io::Result<i32> {
    // AF_INET = 2, SOCK_STREAM = 1, IPPROTO_TCP = 6
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") 41_i64 => ret,
            in("rdi") 2_i64, // AF_INET
            in("rsi") 1_i64, // SOCK_STREAM
            in("rdx") 6_i64, // IPPROTO_TCP
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }

    if (-4095..0).contains(&ret) {
        Err(io::Error::from_raw_os_error(-ret as i32))
    } else {
        Ok(ret as i32)
    }
}

/// Linux x86_64: SYS_socket = 41
/// Linux aarch64: SYS_socket = 198
/// Returns fd on success, or -errno in the [-4095, -1] range.
#[inline]
pub fn socket_udp() -> io::Result<i32> {
    // AF_INET = 2, SOCK_DGRAM = 2, IPPROTO_UDP = 17
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") 41_i64 => ret,
            in("rdi") 2_i64, // AF_INET
            in("rsi") 2_i64, // SOCK_DGRAM
            in("rdx") 17_i64, // IPPROTO_UDP
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }

    if (-4095..0).contains(&ret) {
        Err(io::Error::from_raw_os_error(-ret as i32))
    } else {
        Ok(ret as i32)
    }
}

/// Linux x86_64: SYS_openat = 257
/// Linux aarch64: SYS_openat = 56
/// returns fd in rax, or negative errno on failure.
/// arg4 (mode) in r10 not rcx; unused here since O_CREAT/O_TMPFILE not in flags.
/// todo: (test) add to detection (medium confidence), openat with path containing /proc/*/mem outside of debugger processes (gdb, lldb, strace)
/// todo: (test) add to detection (medium confidence), openat to /dev/mem or /dev/kmem from any process (extremely rare legitimate use)
pub fn open(path: &str, flags: i32) -> Result<i32, io::Error> {
    let path_bytes = std::ffi::CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "null byte in path"))?;

    const SYS_OPENAT: u64 = 257;
    const AT_FDCWD: i64 = -100;

    let ret: i64;
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") SYS_OPENAT => ret,
            in("rdi") AT_FDCWD,
            in("rsi") path_bytes.as_ptr(),
            in("rdx") flags as i64,
            in("r10") 0i64,            // mode, unused unless O_CREAT/O_TMPFILE
            lateout("rcx") _,          // clobbered by syscall (RIP)
            lateout("r11") _,          // clobbered by syscall (RFLAGS)
            options(nostack, preserves_flags)
        );
    }

    if ret < 0 {
        Err(io::Error::from_raw_os_error(-ret as i32))
    } else {
        Ok(ret as i32)
    }
}

/// Linux x86_64: SYS_read = 0
/// Linux aarch64: SYS_read = 63
/// returns bytes read (non-negative) in rax, or negative errno on failure.
/// short reads are normal on pipes/sockets/terminals, not errors. caller must loop.
/// //todo: (test) add to detection (high confidence), read on fd resolving to /etc/shadow, /etc/sudoers, SSH private keys (argfilter on fd->path in tetragon)
/// //todo: (test) add to detection (medium confidence), read from /proc/*/maps, /proc/*/mem, /proc/kallsyms by non-root or non-debugger
/// //todo: (test) add to detection (low confidence, high volume), anomalous read volume per-pid baseline (needs process profiling, defer)
pub fn read(fd: i32, buf: &mut [u8]) -> Result<usize, io::Error> {
    const SYS_READ: u64 = 0;

    let ret: i64;
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") SYS_READ => ret,
            in("rdi") fd as i64,
            in("rsi") buf.as_mut_ptr(),
            in("rdx") buf.len(),
            lateout("rcx") _,          // clobbered by syscall (RIP)
            lateout("r11") _,          // clobbered by syscall (RFLAGS)
            options(nostack, preserves_flags)
        );
    }

    if ret < 0 {
        Err(io::Error::from_raw_os_error(-ret as i32))
    } else {
        Ok(ret as usize)
    }
}

/// read_file
/// RAII guard ensures fd closed on all paths (success, error, panic).
/// 4096-byte buffer matches page size; 8x fewer syscalls than 512 for the same data.
/// //todo: (test) add to detection (medium confidence), sequential read_file of many /proc/*/environ, /proc/*/cmdline, /proc/*/status - process enumeration, classic recon
/// //todo: (test) add to detection (medium confidence), read_file on /proc/self/maps, /proc/self/status - self-introspection often precedes process injection or sandbox evasion
pub fn read_file(path: &str) -> Result<Vec<u8>, io::Error> {
    let fd = open(path, 0i32)?;

    // RAII guard: close fd even on panic or early return.
    struct FdGuard(i32);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            let _ = close(self.0);
        }
    }
    let _guard = FdGuard(fd);

    let mut result = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        let n = match read(fd, &mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };

        if n == 0 {
            break;
        }

        result.extend_from_slice(&buf[..n]);
    }

    Ok(result)
}

// read_file_string
/// wraps read_file with UTF-8 validation + trim.
/// Common for config files, /proc/*/cmdline, /proc/version, etc.
/// todo: (test) add to detection (low confidence), high-volume read_file_string on /proc/version, /proc/cpuinfo, /etc/os-release - OS fingerprinting pre-payload
pub fn read_file_string(path: &str) -> Result<String, io::Error> {
    let bytes = read_file(path)?;
    String::from_utf8(bytes)
        .map(|s| s.trim().to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}


// close
/// Linux x86_64: SYS_close = 3
/// Linux aarch64: SYS_close = 57
/// returns 0 in rax on success, negative errno on failure.
/// never retry close on EINTR - fd is gone regardless; retry risks closing another thread's fd.
/// //todo: (test) add to detection (medium confidence), close(0/1/2) followed by dup2 - stdio redirection for reverse shells
/// //todo: (test) add to detection (low confidence), sequential close() of fds 3..N right before exec - post-exploitation fd sanitization, but also legitimate daemonizer behavior - sequence context matters
pub fn close(fd: i32) -> Result<(), io::Error> {
    const SYS_CLOSE: u64 = 3;

    let ret: i64;
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") SYS_CLOSE => ret,
            in("rdi") fd as i64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags)
        );
    }

    if ret < 0 {
        Err(io::Error::from_raw_os_error(-ret as i32))
    } else {
        Ok(())
    }
}

/// Write to a file descriptor using a direct write(2) syscall.
///
/// Bypasses libc::syscall() entirely - no PLT/GOT lookup, no libc frame.
/// Linux x86_64: SYS_write = 1
/// returns number of bytes written in rax on success, -errno on failure.
/// partial writes are legal (ret < count) - caller must loop on short writes.
/// //todo: (test) add to detection (low confidence alone, high in correlation), direct syscall write to fd bypasses libc uprobes but hits tracepoint/syscalls/sys_enter_write identically. noisy on its own - every process writes. pivot signals: writes to /dev/tcp/*, /proc/*/mem, /proc/*/maps, /sys/kernel/*, or fds resolving to sockets from unexpected binaries. writes from processes with no libc mapping (readlink /proc/self/maps lacking libc.so) are a stronger signal.
pub fn write(fd: i32, buf: &[u8]) -> Result<usize, io::Error> {
    // write(2): rax=1, rdi=fd, rsi=buf, rdx=count
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 1_i64 => ret,
            in("rdi") fd as i64,
            in("rsi") buf.as_ptr(),
            in("rdx") buf.len(),
            out("rcx") _,   // clobbered by syscall (return address)
            out("r11") _,   // clobbered by syscall (rflags)
            options(nostack, preserves_flags),
        );
    }

    if ret < 0 {
        // Kernel returns -errno in rax on failure
        Err(io::Error::from_raw_os_error(-ret as i32))
    } else {
        Ok(ret as usize)
    }
}

pub fn write_all(fd: i32, mut buf: &[u8]) -> Result<(), io::Error> {
    while !buf.is_empty() {
        match write(fd, buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ));
            }
            Ok(n) => {
                buf = &buf[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                // EINTR: syscall interrupted by signal, retry
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

/// Linux x86_64: SYS_SETSOCKOPT = 54
pub fn set_read_timeout(fd: i32, secs: u64) -> Result<(), io::Error> {

    let tv = Timeval {
        tv_sec: secs as i64,
        tv_usec: 0,
    };

    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 54_i64 => ret, // 54 = SYS_SETSOCKOPT on x86_64
            in("rdi") fd as i64,
            in("rsi") 1_i64, // 1 = SOL_SOCKET on x86_64
            in("rdx") 20_i64, // 20 = SO_RCVTIMEO on x86_64
            in("r10") (&tv as *const Timeval),
            in("r8") mem::size_of::<Timeval>(),
            out("rcx") _, // clobbered by syscall
            out("r11") _, // clobbered by syscall
            options(nostack, preserves_flags),
        );
    }

    if ret < 0 {
        Err(io::Error::from_raw_os_error(-ret as i32))
    } else {
        Ok(())
    }
}

/// //todo: (test) add to detection (medium confidence), direct connect() to raw IPv4 sockaddr bytes without libc wrapper - uncommon in normal apps, interesting for custom implants/loaders
/// //todo: (test) add to detection (high confidence when correlated), socket() -> connect() -> dup2()/execve() chain - classic reverse shell sequence
///
/// connect(2):
///   rax = SYS_connect
///   rdi = fd
///   rsi = uservaddr
///   rdx = addrlen
///
/// Here we pass a manually built 16-byte sockaddr_in:
///   family = AF_INET
///   port   = network byte order
///   addr   = 4-byte IPv4 address
///   zero   = 8 bytes padding
pub fn connect_tcp(fd: i32, addr: &SocketAddr) -> Result<(), io::Error> {
    match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip().octets();
            let port = v4.port();

            // struct sockaddr_in layout:
            //   sa_family_t    sin_family   = 2 bytes
            //   in_port_t      sin_port     = 2 bytes (big-endian / network order)
            //   struct in_addr sin_addr     = 4 bytes
            //   unsigned char  sin_zero[8]  = 8 bytes
            let mut sockaddr = [0u8; 16];

            sockaddr[0] = 2; // AF_INET low byte on little-endian Linux
            sockaddr[1] = 0; // AF_INET high byte

            sockaddr[2] = (port >> 8) as u8;   // port high byte (network byte order)
            sockaddr[3] = (port & 0xff) as u8; // port low byte

            sockaddr[4] = ip[0]; // IPv4 octet 1
            sockaddr[5] = ip[1]; // IPv4 octet 2
            sockaddr[6] = ip[2]; // IPv4 octet 3
            sockaddr[7] = ip[3]; // IPv4 octet 4

            // sockaddr[8..16] remains zero-filled padding

            let ret: isize;
            unsafe {
                core::arch::asm!(
                    "syscall",
                    inlateout("rax") 42_i64 => ret,
                    in("rdi") fd as i64,
                    in("rsi") sockaddr.as_ptr(), // pointer to sockaddr_in bytes
                    in("rdx") 16_usize, // sizeof(sockaddr_in)
                    out("rcx") _,  // clobbered by syscall
                    out("r11") _,  // clobbered by syscall
                    options(nostack, preserves_flags),
                );
            }

            if ret < 0 {
                Err(io::Error::from_raw_os_error(-ret as i32))
            } else {
                Ok(())
            }
        }
        SocketAddr::V6(_) => Err(io::Error::new(io::ErrorKind::Unsupported, "v6")),
    }
}

pub fn connect_udp(fd: i32, addr: &SocketAddr) -> io::Result<()> {
    match addr {
        SocketAddr::V4(v4) => {

            let ip = v4.ip().octets();
            let port = v4.port();

            // struct sockaddr_in layout:
            //   sa_family_t    sin_family   = 2 bytes
            //   in_port_t      sin_port     = 2 bytes (big-endian / network order)
            //   struct in_addr sin_addr     = 4 bytes
            //   unsigned char  sin_zero[8]  = 8 bytes
            let mut sockaddr = [0u8; 16];

            sockaddr[0] = 2; // AF_INET low byte on little-endian Linux
            sockaddr[1] = 0; // AF_INET high byte

            sockaddr[2] = (port >> 8) as u8;   // port high byte (network byte order)
            sockaddr[3] = (port & 0xff) as u8; // port low byte

            sockaddr[4] = ip[0]; // IPv4 octet 1
            sockaddr[5] = ip[1]; // IPv4 octet 2
            sockaddr[6] = ip[2]; // IPv4 octet 3
            sockaddr[7] = ip[3]; // IPv4 octet 4

            // sockaddr[8..16] remains zero-filled padding

            let ret: isize;
            unsafe {
                core::arch::asm!(
                    "syscall",
                    inlateout("rax") 42_i64 => ret,
                    in("rdi") fd as i64,
                    in("rsi") sockaddr.as_ptr(), // pointer to sockaddr_in bytes
                    in("rdx") 16_usize, // sizeof(sockaddr_in)
                    out("rcx") _,  // clobbered by syscall
                    out("r11") _,  // clobbered by syscall
                    options(nostack, preserves_flags),
                );
            }

            if ret < 0 {
                Err(io::Error::from_raw_os_error(-ret as i32))
            } else {
                Ok(())
            }

        }
        SocketAddr::V6(_) => Err(io::Error::new(io::ErrorKind::Unsupported, "v6")),
    }
}

// Get 64-bits of random data from cpu RDRAND without syscalls
#[inline]
pub fn rand_rdrand64() -> Option<u64> {
    let mut val: u64;
    let mut ok: u8;
    unsafe {
        asm!(
            "rdrand {v}",
            "setc  {o}",
            v = out(reg) val,
            o = out(reg_byte) ok,
            options(nomem, nostack)
        );
    }
    if ok == 1 { Some(val) } else { None }
}

// use RDTSC+splitmix64 to derive a pseudorandom number
// good enough for simple purposes like picking a source port
pub fn rand_rdtsc() -> u64 {
    let t = unsafe { std::arch::x86_64::_rdtsc() };
    // splitmix64 finalizer
    let mut x = t;
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9); // Stafford mix13
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb); // Stafford mix13
    x ^ (x >> 31)
}

pub fn rand_u64() -> u64 {
    rand_rdrand64().unwrap_or_else(rand_rdtsc)
}
