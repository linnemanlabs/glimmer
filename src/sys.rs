use std::io;
use std::net::{SocketAddr, ToSocketAddrs};


/// Open a file using the openat syscall directly.
/// Returns a raw file descriptor.
pub fn open(path: &str, flags: i32) -> Result<i32, io::Error> {
    let path_bytes = std::ffi::CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "null byte in path"))?;

    // AT_FDCWD (-100) means relative to current working directory
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat,
            -100i32,          // AT_FDCWD
            path_bytes.as_ptr(),
            flags,
        )
    } as i32;

    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

/// Read from a file descriptor using the read syscall directly.
pub fn read(fd: i32, buf: &mut [u8]) -> Result<usize, io::Error> {
    let n = unsafe {
        libc::syscall(
            libc::SYS_read,
            fd,
            buf.as_mut_ptr(),
            buf.len(),
        )
    } as isize;

    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Close a file descriptor using the close syscall directly.
pub fn close(fd: i32) -> Result<(), io::Error> {
    let ret = unsafe {
        libc::syscall(libc::SYS_close, fd)
    } as i32;

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Read an entire file into a Vec<u8> using direct syscalls.
pub fn read_file(path: &str) -> Result<Vec<u8>, io::Error> {
    let fd = open(path, libc::O_RDONLY)?;

    let mut result = Vec::new();
    let mut buf = [0u8; 512];

    loop {
        let n = match read(fd, &mut buf) {
            Ok(n) => n,
            Err(e) => {
                let _ = close(fd);
                return Err(e);
            }
        };

        if n == 0 {
            break;
        }

        result.extend_from_slice(&buf[..n]);
    }

    close(fd)?;
    Ok(result)
}

/// Read a file and return it as a trimmed String.
pub fn read_file_string(path: &str) -> Result<String, io::Error> {
    let bytes = read_file(path)?;
    String::from_utf8(bytes)
        .map(|s| s.trim().to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Get the current effective user ID using direct syscall.
pub fn geteuid() -> u32 {
    unsafe { libc::syscall(libc::SYS_geteuid) as u32 }
}

/// Get the current process ID using direct syscall.
pub fn getpid() -> u32 {
    unsafe { libc::syscall(libc::SYS_getpid) as u32 }
}

/// Create a TCP socket using direct syscall.
/// Returns a raw file descriptor.
pub fn socket_tcp() -> Result<i32, io::Error> {
    // AF_INET = 2, SOCK_STREAM = 1, IPPROTO_TCP = 6
    let fd = unsafe {
        libc::syscall(
            libc::SYS_socket,
            2i64,  // AF_INET
            1i64,  // SOCK_STREAM
            6i64,  // IPPROTO_TCP
        )
    } as i32;

    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

/// Connect a socket to an address using direct syscall.
pub fn connect_tcp(fd: i32, addr: &SocketAddr) -> Result<(), io::Error> {
    match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip().octets();
            let port = v4.port();

            // struct sockaddr_in layout: family(2) + port(2) + addr(4) + zero(8)
            let mut sockaddr = [0u8; 16];
            sockaddr[0] = 2; // AF_INET (little-endian, low byte)
            sockaddr[1] = 0;
            sockaddr[2] = (port >> 8) as u8;   // port in network byte order
            sockaddr[3] = (port & 0xff) as u8;
            sockaddr[4] = ip[0];
            sockaddr[5] = ip[1];
            sockaddr[6] = ip[2];
            sockaddr[7] = ip[3];

            let ret = unsafe {
                libc::syscall(
                    libc::SYS_connect,
                    fd as i64,
                    sockaddr.as_ptr() as i64,
                    16i64, // sizeof(sockaddr_in)
                )
            } as i32;

            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
        SocketAddr::V6(_) => {
            Err(io::Error::new(io::ErrorKind::Unsupported, "v6"))
        }
    }
}

/// Write to a file descriptor using direct syscall.
pub fn write(fd: i32, buf: &[u8]) -> Result<usize, io::Error> {
    let n = unsafe {
        libc::syscall(
            libc::SYS_write,
            fd as i64,
            buf.as_ptr() as i64,
            buf.len() as i64,
        )
    } as isize;

    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Write all bytes to a file descriptor, looping until complete.
pub fn write_all(fd: i32, mut buf: &[u8]) -> Result<(), io::Error> {
    while !buf.is_empty() {
        let n = write(fd, buf)?;
        buf = &buf[n..];
    }
    Ok(())
}

/// Set a socket timeout using setsockopt via direct syscall.
pub fn set_read_timeout(fd: i32, secs: u64) -> Result<(), io::Error> {
    // struct timeval: tv_sec(8 bytes) + tv_usec(8 bytes)
    let mut timeval = [0u8; 16];
    timeval[..8].copy_from_slice(&secs.to_ne_bytes());
    // tv_usec stays 0

    // SOL_SOCKET = 1, SO_RCVTIMEO = 20
    let ret = unsafe {
        libc::syscall(
            libc::SYS_setsockopt,
            fd as i64,
            1i64,   // SOL_SOCKET
            20i64,  // SO_RCVTIMEO
            timeval.as_ptr() as i64,
            16i64,  // sizeof(timeval)
        )
    } as i32;

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// This still uses libc's getaddrinfo, only libc dependency left. Will
/// write a custom handler for this soon. 
/// Resolve a hostname to a SocketAddr.
pub fn resolve(host: &str, port: u16) -> Result<SocketAddr, io::Error> {
    let addr_str = format!("{}:{}", host, port);
    addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addr"))
}