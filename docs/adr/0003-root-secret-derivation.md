**Date:** 2026-04-07

**Status:** Accepted

**Context:** The time-based outer encryption layer needs a root secret that both the beacon and server can derive independently from the ECDH bootstrap exchange. The original implementation used a static string `"glimmer-time-root"` as domain separation for the root secret derivation. This string appeared in the binary and was fingerprintable.
 
**Decision:** Derive the root secret as `SHA-256(server_pub_bytes || ECDH_shared_secret)`. The server's public key bytes serve as domain separation, replacing the static string. Both sides have the server public key, the beacon has it baked in at build time, the server has its own keypair.
 
**Consequences:**
- No static domain separation string in the binary. One less fingerprintable artifact
- Different server keys produce different domain separation automatically
- Cryptographically distinct from the encryption key derivation path which uses only the shared secret
- Both sides compute identically since both have the server public key
- Key ID (first 4 bytes of SHA-256 of server public key) sent with every message for server-side keypair lookup
 