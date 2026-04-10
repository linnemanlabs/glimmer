**Date:** 2026-04-09
**Status:** Accepted
**Context:** YARA provides static analysis detection, identifying suspicious binaries on disk. But a binary flagged by YARA might never execute, or might execute but not make network connections. Runtime confirmation of network activity from a YARA-flagged binary provides high-confidence detection that the suspicious code is actively communicating.
 
**Decision:** Deploy an auditd rule logging all `connect()` syscalls with the `network_connect` key. A custom Wazuh rule (100200) elevates these from the default level 0 audit grouping to level 6 alerts, making them searchable in OpenSearch. Cross-source correlation via OpenSearch aggregation identifies binaries appearing in both YARA alerts and auditd connect events.
 
**Consequences:**
- Every TCP connection from every process is logged with full context: PID, PPID, executable path, UID, destination
- Auditd operates at the kernel boundary - unevadable from userspace regardless of whether connections use libc or raw syscalls
- Combined with YARA rule 100102 (binary with syscall but no socket/connect imports), provides a two-source detection: "binary is statically suspicious AND actively making network connections"
- Noisy on busy systems since every process's connect calls are logged. Production deployment needs filtering or tiered alerting
- Fedora default auditd config includes `-a never,task` which must be removed or overridden for the connect rule to work
- Backlog limit must be increased from Fedora's default of 64 to prevent silent event drops under load
- The `never,task` discovery was itself a valuable finding, my servers have hardened auditd configs but my workstation default config silently disabled auditing on tasks launched after auditd