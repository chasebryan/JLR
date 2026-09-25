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
- Follow-up to the adversarial review of the first implementation (`docs/REVIEW_2026-09.md`, 35 findings): the exec gate
  treats unmeasurable files as decisions, marks file systems mounted later, and bounds each user's slow-path cost; boot
  applies the highest rollback floor on any attached medium, can be pinned to one medium, boots from write-protected
  media, and retires a slot only on proof its image is bad; cells get their own session, sweep inherited descriptors, and
  refuse `syslog` and terminal-injection `ioctl`s; approvals and baselines are bound to the ledger; the ledger repairs a
  torn checkpoint log; `jlr ledger verify` is read-only; `jlr run` releases the ledger lock while the program runs.
- **State compatibility:** baselines enrolled before this change carry no ledger subject and are ignored until they are
  enrolled again (`jlr baseline enroll`); on an enforcing machine that denies everything a baseline admitted, including `jlr`,
  so turn enforcement off first (docs/OPERATIONS.md section 5a). Approval and baseline files are now named by digest. The path
  index gained two fields, so the first start rebuilds it from the ledger. Policies whose name uses spaces or punctuation
  still load; new policies must use `A-Za-z0-9._-`. `jlr scan` exits 3 when it could not measure everything.
- A second independent review of these fixes (66 agents, 61 findings reported, 57 confirmed) led to further changes recorded
  in `docs/REVIEW_2026-09.md`: the mount watcher, the gate budget, verify-before-spend in boot, ledger rollback and
  concurrent verification, evidence objects, and several tests that had passed without the fix they cited.

### Security
- The measured bytes are the executed bytes: launches run a sealed memfd copy that was hashed while it was copied.
- Missing enforcement is reported, never silently downgraded; missing mandatory controls refuse the launch.
- Fixed before release, found by testing: an EPN identity that changed on every observation; a ledger torn-tail heuristic
  that could have discarded valid events after a single corrupted length field; a slot installer that could not outrank
  the slot it replaced.
