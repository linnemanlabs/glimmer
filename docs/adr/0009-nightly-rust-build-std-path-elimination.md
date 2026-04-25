**Date:** 2026-04-08

**Status:** Accepted

**Context:** The Rust compiler embeds source file paths in panic messages. A standard release build contains the developer's home directory, cargo registry paths, rustup toolchain paths, and the rustc version with git commit hash. These leak the build environment and identify the binary as Rust.
 
**Decision:** Use nightly Rust with:
- `-Zlocation-detail=none` to strip file/line/column from panic messages
- `-Zbuild-std=std,panic_abort` to rebuild the standard library from source with the same flags
- Post-build `objcopy` to remove `.comment`, `.gnu.build.attributes`, `.note.gnu.build-id`, and `.annobin.notes` ELF sections
 
**Consequences:**
- Zero `/home/` paths, zero `/rustc/` paths, zero cargo registry paths in the binary
- Compiler version strings removed from ELF sections
- Build ID removed, no unique build fingerprint
- Binary size reduced from ~450KB to ~388KB due to stdlib rebuild optimizations
- Requires nightly toolchain, stable Rust cannot do this
- `rust-src` component must be installed for build-std
- Build output goes to `target/x86_64-unknown-linux-gnu/release/` instead of `target/release/`
- Must specify `--target` explicitly even when building for the host architecture