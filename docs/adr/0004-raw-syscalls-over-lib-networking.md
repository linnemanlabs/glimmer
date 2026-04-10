**Date:** 2026-04-08
**Status:** Accepted
**Context:** Standard Rust networking (`TcpStream`) imports `socket`, `connect`, `send`, `recv` from libc. These appear in the binary's dynamic symbol table (`.dynstr`), clearly indicating network capability to any analyst examining imports. We want the import table to reveal as little as possible about the binary's actual capabilities. Also, security tools (EDR, eBPF uprobes, LD_PRELOAD hooks) commonly instrument libc network functions to monitor application behavior. Using libc means every connection is visible to userspace monitoring hooks.
 
**Decision:** Implement all networking operations through the generic `libc::syscall()` entry point using raw syscall numbers (`SYS_socket`, `SYS_connect`, `SYS_write`, `SYS_read`, `SYS_close`, `SYS_setsockopt`). DNS resolution still uses libc's `getaddrinfo` until a custom resolver is built.
 
**Consequences:**
- `socket`, `connect`, `send`, `recv` no longer appear in the import table
- Only the generic `syscall` entry point is imported, which thousands of binaries use for various purposes
- Bypasses any userspace hooking of libc network functions (LD_PRELOAD, uprobes on libc connect/send/recv). Monitoring tools that instrument libc see no network activity from the beacon
- Does NOT bypass kernel-level monitoring things like auditd, tracepoints, and kprobes on sys_enter_connect still capture the syscalls regardless of invocation method
- An analyst examining `.dynstr` sees no network-specific imports
- Creates a detectable pattern in itself of a binary with `syscall` but without standard network imports (this becomes YARA rule `glimmer_syscall_pattern`). Not significant on it's own but powerful combined with auditd/ebpf connection monitoring.
- `getaddrinfo` remains as the one network-related import until custom DNS is implemented
- Direct syscalls are architecture-specific, current implementation is x86_64 only
- Auditd still captures the connect syscalls regardless of invocation method, kernel-level monitoring is unevadable from userspace