# Glimmer

Adversary emulation framework for offensive security research and purple team operations.

Glimmer is a custom C2 framework built from scratch to explore persistence, evasion, and detection engineering across workstation and cloud environments.

This is a research and portfolio project. All testing is conducted against infrastructure I own and operate, with appropriate authorization.

## Status

Early development. Architecture and ADRs will be documented as the project evolves.

## Structure

```
src/bin/beacon/     - Implant entrypoint
src/bin/server/     - C2 server entrypoint
src/                - Core modules (agent, c2, crypto, collectors, syscalls)
docs/adr/           - Architecture decision records
```

## Legal

This tool is intended for authorized security testing and research only.

Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.

## License

MIT. Copy it, steal it, modify it, learn from it, share your improvements with me. Or don't. It's code, do what you want with it.