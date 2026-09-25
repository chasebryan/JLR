# JLR Documentation Index

This directory is the normative design record for JLR.

## Reading order

1. [ARCHITECTURE.md](ARCHITECTURE.md) — component boundaries and data flow
2. [TRUST_MODEL.md](TRUST_MODEL.md) — what JLR trusts, and why
3. [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) — properties the implementation must preserve
4. [INTEGRITY_PROTOCOL.md](INTEGRITY_PROTOCOL.md) — Encryption Protocol Numbers and verification records
5. [SOFTWARE_ADMISSION.md](SOFTWARE_ADMISSION.md) — how software moves from unknown to admitted
6. [JAIL_MODEL.md](JAIL_MODEL.md) — confinement and capability control
7. [BOOT_INSTALLATION.md](BOOT_INSTALLATION.md) — JLR-first installation and host boot chain
8. [RECOVERY.md](RECOVERY.md) — redundant, host-independent recovery
9. [THREAT_MODEL.md](THREAT_MODEL.md) — adversaries, assumptions, and non-goals
10. [CONFIGURATION_CLONING.md](CONFIGURATION_CLONING.md) — cloneable profiles without cloning secrets
11. [SECURITY_BOUNDARIES.md](SECURITY_BOUNDARIES.md) — limits on what JLR may claim
12. [DECISIONS.md](DECISIONS.md) — durable architecture decisions
13. [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md) — staged engineering plan
14. [GLOSSARY.md](GLOSSARY.md) — terminology

## Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are used in their ordinary standards-document sense:

- MUST / MUST NOT: required for conformance.
- SHOULD / SHOULD NOT: strong recommendation; deviation requires a documented reason.
- MAY: optional behavior.

## Scope

These documents specify architecture and security behavior. They are not a claim of completed security verification. Any implementation claiming conformance should publish:

- source revision
- build recipe
- toolchain versions
- binary hashes
- signed manifest
- test results
- known limitations
- audit status
