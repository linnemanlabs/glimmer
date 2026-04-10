**Date:** 2026-04-08
**Status:** Accepted
**Context:** Sensitive strings in the binary like HTTP headers (`POST`, `Cookie`, `Content-Type`), file paths (`/etc/hostname`, `/etc/machine-id`), protocol elements, etc are trivially discoverable with `strings` and form the basis of YARA signatures. These strings need to be present at runtime but should not be readable in the static binary.
 
**Decision:** A `build.rs` script generates a random 16-byte XOR key per build and encodes all sensitive strings at compile time. The encoded bytes and key are written to a generated Rust source file that gets compiled into the binary. At runtime, strings are decoded on demand using rolling XOR with the per-build key.
 
**Consequences:**
- `strings` finds nothing recognizable from the HTTP layer or file access patterns
- Each build produces different encoded bytes due to the random key, defeating static signatures
- The XOR key itself is in the binary but indistinguishable from other constant data
- Rolling multi-byte XOR resists single-byte XOR brute-force analysis tools
- Decoded strings exist in heap memory for the duration of use, not yet zeroized after use (future improvement)
- The encoding/decoding adds negligible runtime overhead
- New strings are added by editing the string list in `build.rs` for centralized management