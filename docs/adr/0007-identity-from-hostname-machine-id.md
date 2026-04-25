**Date:** 2026-04-08

**Status:** Accepted

**Context:** The beacon needs a stable node identifier that persists across reboots. The original implementation read `/proc/cpuinfo`, `/proc/version`, `/sys/block/dm-0/dm/uuid`, and `/proc/self/mountinfo` but these are files that very few normal applications access. This created a distinctive behavioral fingerprint in strace and auditd.
 
**Decision:** Generate node identity from `SHA-256(/etc/hostname || /etc/machine-id || arch)`, using only files that hundreds of normal applications read. `/etc/hostname` is read by virtually every application through `gethostname()`. `/etc/machine-id` is read by systemd, dbus, journald, flatpak, snap, Firefox, Chrome, and dozens of other applications.
 
**Consequences:**
- strace shows only common file accesses indistinguishable from normal application startup
- Identity is stable across reboots (machine-id is generated at install time and persists)
- Identity changes if hostname or machine-id changes, which is acceptable
- Unique per installation, the combination of hostname + machine-id + architecture is sufficient for node deduplication
- No unusual file access patterns for behavioral detection to flag
- Hostname is read once and cached to avoid duplicate file accesses in strace
- The beacon reads these files via raw syscall (SYS_open/SYS_read) rather than libc's gethostname() or standard file I/O. Legitimate applications almost universally use libc wrappers. A process reading /etc/hostname via direct syscall is itself a behavioral anomaly - the same detection gap that ADR-004 exploits for networking applies here in reverse as a detection surface
- **Planned improvement:** Use libc's gethostname() for hostname and standard file I/O for machine-id to blend with normal application behavior, or read these values from environment variables or other sources that don't generate file access syscalls at all