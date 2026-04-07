use std::io;

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