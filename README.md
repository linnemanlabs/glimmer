# Glimmer

Adversary emulation framework for offensive security research and purple team operations.

Glimmer is a custom C2 framework built from scratch to explore persistence, evasion, and detection engineering across workstation, cloud, and embedded environments.

This is a research and portfolio project. All testing is conducted against infrastructure I own and operate, with appropriate authorization.

## Status

Early development. Architecture and ADRs will be documented as the project evolves.

Currently has:
 - beacon, server, and utility for generating per-build EC keypairs for server communication
 - http POST channel for development (very fingerprintable)
 - channel encoding beacon data and tasking data in ISNs
 - DNF mirror tasking channel
 - Direct asm syscalls (no libc)
 - Raw tcp connections and packets for http using syscalls
 - Raw udp sockets/connections and packet crafting for dns and response handling for A records (lots more to come) using syscalls
 - keyring collection (wifi passwords, browser database keys)
 - browser collection (saved passwords) using keys from keyring

## Structure

```
src/bin/beacon.rs        - Implant entrypoint
src/bin/server.rs        - C2 server entrypoint
src/bin/dump_browser.rs  - Standalone test binary for browser collection
src/bin/dump_keyring.rs  - Standalone test binary for keyring collection
src/                     - Core modules (agent, c2, crypto, collectors, syscalls)
docs/adr/                - Architecture decision records
```

## Legal

This tool is intended for authorized security testing and research only.

Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.

## License

MIT. Copy it, steal it, modify it, learn from it, share your improvements with me. Or don't. It's code, do what you want with it.