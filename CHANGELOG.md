# Changelog

All notable changes are recorded here. The project follows the pre-1.0 rule that any change to a signed wire format is
a deliberate, reviewed event; see `docs/INTEGRITY_PROTOCOL.md`.

## [Unreleased]

### Added
- Rust workspace of 11 crates implementing the design: deterministic CBOR (JLR-DCBOR/1), COSE_Sign1-style signed
  envelopes with domain separation, a content-addressed EPN record model, an RFC 9162 Merkle evidence ledger with signed
  checkpoints, a deterministic trust engine with validated policies, revocations, approvals and baselines, descriptor-
  based measurement with a dpkg adapter, a jail fabric (namespaces, private root, seccomp, Landlock, dropped capabilities)
  that executes a sealed copy of the measured bytes and reports what was enforced, and the `jlr` command-line tool.
- Verified boot chain: signed release manifests, A/B slots with a monotonic rollback floor, an initramfs that verifies
  and loads the base image into RAM before mounting it, and reproducible image builds.
- `jlrd`: fanotify exec gate with audit and enforce modes, state watcher and background rescan.
- Protocol test vectors (`docs/vectors/protocol-v1.json`) and generated record reference (`docs/generated/RECORDS.md`).
- QEMU/KVM integration tests that boot the real initramfs and exercise the exec gate under a real kernel.

### Changed
- Reconciled the two divergent design sets into one vocabulary; see `docs/DECISIONS.md`.

### Security
- The measured bytes are the executed bytes: launches run a sealed memfd copy that was hashed while it was copied.
- Missing enforcement is reported, never silently downgraded; missing mandatory controls refuse the launch.
- Fixed before release, found by testing: an EPN identity that changed on every observation; a ledger torn-tail heuristic
  that could have discarded valid events after a single corrupted length field; a slot installer that could not outrank
  the slot it replaced.
