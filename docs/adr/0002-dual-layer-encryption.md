# ADR 0002: Dual-Layer Encryption Architecture

**Date:** 2026-04-06
**Status:** Accepted

**Context:** A single encryption layer creates a tradeoff, ECIES provides forward secrecy but leaves identifiable EC point structures (33-byte compressed P-256 points) in every message. Simple obfuscation (XOR) could hide these but is trivially reversible. We want protocol-level opacity, cryptographic forward secrecy, and zero per-message key exchange overhead on the wire.

**Decision:** Implement dual-layer encryption:
- **Outer layer:** Time-based key derivation from a shared root secret. Both sides independently derive the same AES-256-GCM key from `HKDF(root_secret, time_bucket)`. No key material exchanged on the wire for routine beacons.
- **Inner layer:** Per-message ECIES with fresh ephemeral ECDH keypair. Ephemeral private key consumed and zeroized immediately after use. Only the server's private key can decrypt.
- **Bootstrap:** Full ephemeral ECDH exchange during initial checkin establishes the root secret. This is the only message that exposes EC points on the wire.

**Consequences:**
- Wire traffic shows only time-encrypted blobs - no EC points, no identifiable crypto parameters for routine beacons
- Inner ECIES ephemeral public key (33 bytes) is hidden inside the outer encryption, not visible on the wire
- Each message has unique inner encryption even within the same time bucket, compromising one message doesn't compromise others
- Breaking the outer time-based key only reveals ECIES-encrypted data, not plaintext
- Both layers must stay synchronized on time, clock skew tolerance handled by checking adjacent time buckets
- Time bucket size (300 seconds) balances key rotation frequency against clock tolerance
- Each deployment generates a unique server keypair baked into the beacon at build time
- Server maintains a keystore supporting multiple active keypairs for concurrent deployments
- Currently, key ID (8 hex characters) and node ID are sent in cleartext with every message for server-side lookup. Both are static fingerprints across messages from the same node
- **Planned improvement:** Replace static identifiers with first 4 bytes of the current time-derived key. Server maintains a small lookup table mapping rotating prefixes to nodes. Eliminates all static identifiers from the wire. Check-in remains the only message requiring a static key ID since no time-based key exists yet