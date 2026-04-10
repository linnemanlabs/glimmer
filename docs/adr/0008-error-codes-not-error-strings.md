**Date:** 2026-04-07
**Status:** Accepted
**Context:** Rust's `thiserror` derive macro generates descriptive error messages like `"encryption failed"`, `"invalid public key"`, `"key derivation failed"` that appear in the binary and describe exactly what the tool does. Error variant names like `EncryptionFailed`, `InvalidPublicKey` also survive in the binary through the derived `Debug` implementation.
 
**Decision:** Replace descriptive error messages with single-byte error codes in production builds. Manual `Debug` implementation outputs hex codes (`E01`, `E02`) instead of variant names. Descriptive messages are gated behind `--features debug` using `cfg_attr`. A dedicated `errlog` module stores errors as `(timestamp, code)` tuples in memory for optional exfiltration.
 
**Consequences:**
- Zero descriptive error strings in the production binary
- Error variant names eliminated from binary through manual Debug impl
- Debug builds retain full error messages for development
- Silent error logging, no stderr output in production, errors stored as 9-byte records (8-byte timestamp + 1-byte code)
- Error log can be exfiltrated as a diagnostic payload if the server requests it
- Requires maintaining a mapping document between error codes and their meanings
- `cfg_attr` conditional compilation means the same source produces different binaries for debug vs production
 