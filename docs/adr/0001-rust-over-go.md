**Date:** 2026-04-06
**Status:** Accepted
**Context:** The initial Glimmer prototype was written in Go. While functional for basic checkin/beacon/encryption, Go binaries carry the full runtime and garbage collector (~3-4MB minimum even stripped), embed identifiable strings from the runtime, and produce GC memory access patterns that are fingerprintable. Binary analysis resistance is a core requirement for a C2 beacon.
 
**Decision:** Rewrite the beacon in Rust. Rust compiles to native code with no runtime, no garbage collector, and provides direct access to syscalls. Memory management happens at compile time through the ownership model, leaving no runtime GC patterns to fingerprint.
 
**Consequences:**
- Binary size starts at ~400KB with crypto dependencies vs ~3-4MB minimum in Go
- No GC pause patterns detectable through memory analysis or timing
- Direct syscall access without FFI overhead
- Steeper learning curve, already proficient in Go, Rust is newer to me
- Nightly compiler features needed for optimal binary hardening (`-Zbuild-std`, `-Zlocation-detail=none`)
- Ownership model prevents entire classes of memory bugs but requires understanding lifetimes and borrowing