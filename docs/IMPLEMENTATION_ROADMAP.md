# Implementation Roadmap

The roadmap builds the smallest verifiable core first and adds automation only on top of things that have been shown to
work. **Engineering priorities, in order:** correctness, clear failure state, minimal trusted code, recoverability,
explainability, performance, convenience.

## 1. Where things stand

| Phase | Deliverable | Status | Evidence |
|---|---|---|---|
| 0 Reproducible baseline | Toolchain pinned, SBOM path, EPN/event/policy schemas, deterministic fixtures, reproducible image recipe | **Done**, SBOM pending | `rust-toolchain.toml`, [protocol vectors](vectors/protocol-v1.json), `boot/build.sh` builds identical artifacts twice |
| 1 Bootable governance core | Immutable base, RAM boot, A/B slots, manifest verification, offline key workflow, CLI status | **Done (prototype anchor)** | 19 QEMU tests: refusals for every failure class, fallback, upgrade, rollback, several and pinned media, write-protected media, unreadable state |
| 2 Measurement | Descriptor hashing, classification, package inventory, EPN assignment, evidence store, chained events | **Done for files** | Mutation of a protected executable is detected and recorded; ledger replay validates. Processes, modules, listeners: designed |
| 3 Admission and quarantine | State machine, deterministic policy engine, capability model, approvals, baselines, revocation | **Done** | Property tests; mutation-checked; approvals distinguishable from cryptographic verification |
| 4 Jail fabric | Namespaces, private root, seccomp, Landlock, caps, cgroup, rlimits, enforcement report | **Done for CELL-0/1/2** | Real-cell tests for filesystem, network, syscalls, privileges, PID visibility, sealed exec, inherited descriptors, terminals, kernel log, allow-listed ports |
| 4b Continuous enforcement | Exec gate with audit and enforce modes, rescan, state watcher | **Done** | QEMU guest: audit, enforce, tamper, unmeasurable file, later mount, confined run, daemon stop |
| 5 JLR-first installation | Installer, partition planner, host handoff, measured host launch, protected JLR partitions | **Designed** | Boot chain exists; installer does not |
| 6 Recovery maturity | Read-only inspect, export, restore, boot repair, key rotation, evidence bundle | **Designed** | A/B fallback and ledger verification exist |
| 7 Advanced | Behaviour baselining, remote attestation, reproducible package rebuilds, VM cells, fleet policy | **Designed** | n/a |

## 2. Next, in order

Each item has an exit test that must exist before the item is called done.

1. **Managed-installer hook (apt).** Record the file digests of an apt-verified transaction and emit `PACKAGE_SIGNATURE`, so
   `managed-package` admits silently without a baseline and enforcement can coexist with unattended upgrades.
   *Exit:* an upgrade under enforcement runs its maintainer scripts; a package tampered after download is not admitted.
2. **Authenticated boot.** A unified kernel image signed with the operator's key, enrolled in firmware; the rollback floor in a
   TPM NV counter; PCR measurements; checkpoints with `anchor = Tpm`.
   *Exit:* under OVMF with Secure Boot and `swtpm`, an initramfs signed by another key does not start, and the floor cannot be
   lowered by rewriting the media.
3. **Recovery tools.** Read-only enumeration and mount, safe export with receipts, snapshot comparison, ledger verification
   against an off-machine checkpoint, from a recovery image.
   *Exit:* the disk-loss and host-unbootable drills in [RECOVERY.md](RECOVERY.md) pass.
4. **Observation telemetry and an allow-list profile for CELL-0.** Record what an unknown program opens, executes, connects to
   and asks for, in normalised form; derive a seccomp allow list from it; add `FORBIDDEN_BEHAVIOR`.
   *Exit:* a fixture that attempts a forbidden action is moved to `POLICY_BLOCKED` with the observation as evidence.
5. **Notification and portals.** The green/yellow/red contract, a Wayland-only display path and portal-style prompts so a
   user's ordinary action grants a capability.
   *Exit:* a graphical application runs in a cell and its file access is granted by a file-chooser action.
6. **Host installer and supervisor deployment.** Partition planner, host handoff, measured host launch, IPE and fs-verity where
   the kernel provides them, a shell-less production base.
   *Exit:* a host installs after JLR without overwriting it; a modified host boot set yields a degraded posture.
7. **VM-backed cell and cross-view comparison.** A KVM cell for hostile code; a rule that compares a guest's report with the
   supervisor's view of the same fact.
8. **Ledger scale and witnesses.** Persisted tree state so opening does not hash the whole log; tiled storage; a witness that
   cosigns checkpoints.
9. **Hybrid post-quantum signatures** for the root, release and recovery roles.
10. **Fleet policy.** Enrolment against an organisation's policy key; signed role manifests; duplicate-identity detection.

## 3. Hardening work that is independent of features

- **Fuzzing** of every untrusted parser: the CBOR decoder, the envelope, the manifest and boot state, the dpkg parser and the
  ledger frame reader. Property tests exist; coverage-guided fuzzing does not.
- **Reproducible Rust builds** verified across machines (the boot artifacts are reproducible today; the compiled binaries
  inside them are not yet compared across hosts).
- **SBOM and licence inventory** for every binary in the base image.
- **`cargo-vet` or equivalent** for the dependencies in the trusted computing base.
- **External review** of the boot chain, the cell setup and the envelope.
- **A real power-cut matrix** for the update path, not only the logic.
- **Usability testing** of the wording of the red screen with people who are not engineers.

## 4. Minimum viable security release

A release should not call itself security-ready until it has:

| Requirement | Status |
|---|---|
| Threat-model tests for the abuse cases in [THREAT_MODEL.md](THREAT_MODEL.md) | Mostly; see the coverage table there |
| Update rollback tests | Done (QEMU) |
| Recovery tests | Partly (fallback and refusal); the tools are not built |
| A documented key-compromise procedure | Drafted in [RECOVERY.md](RECOVERY.md); not rehearsed |
| External code review | Not done |
| Documented unsupported platforms | Anything other than x86_64 Linux with a recent kernel; Ubuntu 24.04 needs the userns setting or root |
| Fuzzing for untrusted parsers | Not done |
| Reproducible build analysis | Boot artifacts yes; cross-machine Rust no |

No security adjective outruns the test suite.
