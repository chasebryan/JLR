# JLR Documentation

This directory is the normative design record. Status of each statement is marked **Implemented**, **Prototype**, or
**Designed**; a property is claimed only where a reproducible test demonstrates it
([SECURITY_BOUNDARIES.md](SECURITY_BOUNDARIES.md)).

## Reading order

**To understand it**

1. [OVERVIEW.md](OVERVIEW.md) - the whole idea on one page
2. [ARCHITECTURE.md](ARCHITECTURE.md) - components, flows, state, failure behaviour
3. [TRUST_MODEL.md](TRUST_MODEL.md) - what is trusted, and why
4. [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) - properties the code must keep, and what enforces each
5. [INTEGRITY_PROTOCOL.md](INTEGRITY_PROTOCOL.md) - EPN, encodings, envelopes, the ledger; with
   [generated record tables](generated/RECORDS.md) and [test vectors](vectors/protocol-v1.json)
6. [SOFTWARE_ADMISSION.md](SOFTWARE_ADMISSION.md) - from unknown to admitted, policy, evidence, what a person is asked
7. [JAIL_MODEL.md](JAIL_MODEL.md) - cells, controls, the enforcement report
8. [BOOT_INSTALLATION.md](BOOT_INSTALLATION.md) - verified boot, A/B, RAM residency, Secure Boot and TPM plans
9. [RECOVERY.md](RECOVERY.md) - redundancy, key survival, drills
10. [THREAT_MODEL.md](THREAT_MODEL.md) - adversaries, assumptions, abuse cases and their tests
11. [SECURITY_BOUNDARIES.md](SECURITY_BOUNDARIES.md) - what may and may not be claimed, and the known limits
12. [CONFIGURATION_CLONING.md](CONFIGURATION_CLONING.md) - profiles without secrets

**To use it**

13. [OPERATIONS.md](OPERATIONS.md) - the runbook
14. [CLI_REFERENCE.md](CLI_REFERENCE.md) - every command

**To change it**

15. [DEVELOPMENT.md](DEVELOPMENT.md) - repository map, testing, rules
16. [DECISIONS.md](DECISIONS.md) - durable decisions and the reconciliation of the two earlier design sets
17. [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md) - status and what is next
18. [GLOSSARY.md](GLOSSARY.md), [REFERENCES.md](REFERENCES.md)
19. [REVIEW_2026-09.md](REVIEW_2026-09.md) - the adversarial review of the first implementation: every finding and what was done

## Normative language

**MUST / MUST NOT**: required for conformance. **SHOULD / SHOULD NOT**: strong recommendation; deviation needs a documented
reason. **MAY**: optional.

## Conformance statement

An implementation claiming conformance should publish its source revision, build recipe, toolchain versions, binary
hashes, signed manifest, test results, known limitations and audit status. This repository publishes them as
follows: the source is here; `boot/build.sh` is the recipe; `rust-toolchain.toml` and `Cargo.lock` pin the toolchain and
dependencies; `boot/build.sh` prints artifact hashes; CI runs the tests; the limits are in
[SECURITY_BOUNDARIES.md](SECURITY_BOUNDARIES.md); **audit status: none**.

## Generated files

`docs/generated/RECORDS.md` is produced by `tools/gen_records.py` from the Rust declarations, and
`docs/vectors/protocol-v1.json` by `crates/jlr/tests/vectors.rs`. CI fails if either is stale.
