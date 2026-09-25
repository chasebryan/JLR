# Architecture Decisions

Decisions are numbered and never edited away: a superseded decision stays, with a pointer to what replaced it.

## Original decisions (pull request #2)

**ADR-001 - JLR installs before host Linux.** JLR owns an independent boot and recovery substrate before provisioning or handing off to the governed host.
*Status: adopted; boot chain implemented, installer designed.*

**ADR-002 - Puppy Linux is a construction substrate.** A stripped Puppy-derived build may supply the recovery base; Puppy is not the security boundary.
*Status: **amended by ADR-024**. The trusted base no longer uses Puppy at all.*

**ADR-003 - Runtime is RAM-resident, not persistence-free.** Verified core code runs from RAM; policies, keys, manifests, evidence and redundant recovery assets use explicit persistent storage.
*Status: adopted; implemented.*

**ADR-004 - Unknown is not malicious.** New artifacts begin `UNKNOWN`/`QUARANTINED`/`OBSERVED` because missing evidence does not establish intent. *Adopted.*

**ADR-005 - EPN is public identity, not secret key material.** Safe to log. *Adopted; **refined by ADR-016**: the identifier is content-addressed, not random.*

**ADR-006 - Approval grants scoped capability.** Authorisation binds an EPN, a policy epoch and a cell and capability set, not permanent unrestricted trust. *Adopted; implemented with expiry and node scope.*

**ADR-007 - Self-verification requires external anchors.** Internal self-check loops are evidence, not proof. *Adopted.*

**ADR-008 - Recovery is read-only by default.** Suspect host storage stays read-only until an explicit repair action authorises writes. *Adopted; designed.*

**ADR-009 - Linux is the first governed host.** Guarantees map to concrete Linux enforcement primitives. *Adopted.*

**ADR-010 - Explain evidence, not opaque scores.** Alerts point to measurements, events, rules or attributed external classifications. *Adopted; `jlr explain`.*

**ADR-011 - No mandatory cloud dependency.** Boot, recovery, EPN verification, policy, isolation and evidence work offline. *Adopted; nothing in the code touches a network.*

**ADR-012 - Security claims follow tests.** Planned properties remain design targets until demonstrated by reproducible evidence. *Adopted; see [SECURITY_BOUNDARIES.md](SECURITY_BOUNDARIES.md).*

## Reconciliation and implementation decisions

**ADR-013 - One design, two sources.** The merged set (pull request #2) is the backbone for artifact governance: EPN, admission states, jail classes, invariants. The draft (pull request #1) contributes assurance labels, scoped evidence, the no-automatic-destruction rule and milestone gates. Where they disagreed, the choice is in the table below. *Adopted.*

**ADR-014 - Assurance is a label; supervisor deployment is staged.** `prototype`, `companion`, `supervisor`, `recovery`. Companion mode is built first because it is testable on any machine; the same protocols serve the supervisor. Whether the host runs directly on JLR's kernel or as a KVM guest is a deployment property, deferred until a guest can be tested, because a guest boundary changes what can be *observed* but not what is *recorded*. *Adopted.*

**ADR-015 - Two state machines, never conflated.** Artifact admission state (per EPN) and posture (per named scope). The draft's `PROVEN / DEGRADED / ISOLATED / RECOVERY` are postures; the merged set's eight states are admission states. *Adopted.*

**ADR-016 - An EPN is content-addressed and time-free.** `EPN-1-<CLASS>-<sha256 of the canonical record>`. Anyone can recompute it. No timestamp, counter or state is in the record; first sight is a ledger event. *Supersedes the "random record identifier" reading of ADR-005.* A first implementation put a discovery time in the record, so unchanged files got a new identity on every scan; a live run found it and a regression test now pins it. *Adopted.*

**ADR-017 - One encoding: JLR-DCBOR/1 inside COSE_Sign1.** Deterministic CBOR (RFC 8949 section 4.2.1, narrowed), integer-keyed maps, strict decode, and a re-encode check so exactly one byte string means each record. Signed objects use a strict COSE_Sign1 profile with the record type and node scope in the signed context. JSON is never signed. *Adopted; vectors and an independent checker pin it.*

**ADR-018 - Ed25519 with strict verification; SHA-256 only on the wire.** Weak public keys are rejected at enrolment. Hybrid post-quantum signatures for the root, release and recovery roles are planned, not claimed. *Adopted.*

**ADR-019 - The ledger is an RFC 9162 Merkle tree with signed checkpoints.** A plain hash chain cannot prove append-only growth to a third party and can be replaced wholesale; checkpoints let an external holder detect truncation and rewriting. Events are still hash-linked for streaming verification. Opening verifies events after the newest checkpoint, hashes the rest, and relies on the signed root for the prefix; `jlr ledger verify` verifies everything. Checkpoint counters are software counters and say so. *Adopted.*

**ADR-020 - Measure the descriptor; execute a sealed copy.** Files are hashed through the descriptor that will be used; launches copy the bytes into a sealed memfd, re-hash while copying, and execute that. This closes path-swap and in-place-edit races between measurement and use. *Adopted.*

**ADR-021 - A cell is a function of a decision, and it reports what it enforced.** Missing mandatory controls refuse the launch; missing optional controls make the report `Partial`. *Adopted; makes I-21 testable.*

**ADR-022 - A seccomp deny list first, an allow list from observation later.** An allow list needs to know what workloads require; observation cells will tell it. *Adopted; allow-list profile planned.*

**ADR-023 - Landlock confines writes and TCP ports; the mount namespace decides visibility.** Landlock rules are recursive and cannot allow listing `/` without allowing beneath it, and `EXECUTE` cannot name a sealed memfd. *Adopted.*

**ADR-024 - The trusted base is static binaries and BusyBox, not a Puppy distribution.** About 4 MB and 15,000 lines of first-party Rust, bit-reproducible, no package mutation channel, headless. Puppy's concepts (compressed read-only image in RAM behind a small initramfs) are kept; Woof-CE remains the candidate for a graphical recovery image, decided separately with a pinned-source and licence inventory. *Amends ADR-002. Adopted.*

**ADR-025 - Boot state follows the ChromeOS slot triple with a monotonic floor.** Tries are spent durably **before** a slot is used; the floor rises only **after** the health check; installing a release demotes the previous slot. *Adopted; tested as properties and under QEMU.*

**ADR-026 - Hash the whole image into RAM; do not use dm-verity for the RAM-resident base.** Every byte is verified before use and the media is released; per-read verification is for large on-disk bases. *Adopted for the RAM base; dm-verity remains right for large on-disk roots.*

**ADR-027 - The exec gate is audit-first, with enforcement a signed policy flag, and fails open on its own errors.** Enforcement changes only through a policy epoch, which is logged. An internal daemon error records DEGRADED and allows, unless `--fail-closed`, because a governance daemon that can brick the machine will be turned off. Policy denials are never fail-open. *Adopted.*

**ADR-028 - No long-lived engine and no IPC.** The CLI and the daemon each open the engine briefly; a file lock serialises writers; the CLI waits for it. Long scans run in slices so no operation holds the ledger long. *Adopted; revisit if latency demands a shared in-memory cache.*

**ADR-029 - Operator authority is recorded as operator authority.** Baselines and approvals grant `ADMITTED` with basis `MANUAL_OVERRIDE`; the evidence that was missing stays on the record. The dpkg adapter never emits `PACKAGE_SIGNATURE`, because dpkg's manifests are unauthenticated. The managed-installer hook is the route to honest silent admission. *Adopted.*

**ADR-030 - Documentation and vectors come from the code.** Record and enumeration tables are generated from the Rust declarations; protocol vectors are pinned in a checked-in file that fails a test on drift; an independent implementation checks the vectors. *Adopted.*

**ADR-031 - Rootful workloads run as `nobody`; unprivileged launches use a user namespace.** *Adopted; the rootful path is tested inside the QEMU guest.*

**ADR-032 - Rust workspace; `unsafe` confined to two `sys.rs` modules and two call sites; static musl builds; pinned toolchain.** Everything else is `forbid(unsafe_code)`. *Adopted.*

## How the two design sets were reconciled

| Topic | Merged set (PR #2) | Draft (PR #1) | Decision |
|---|---|---|---|
| Boundary | Governance beside/under a host, jail fabric | Supervisor kernel with the host as a KVM cell | Staged (ADR-014): companion now, supervisor next; KVM as a later cell backend |
| Vocabulary | Trust Engine, Measurement, Admission Controller, Jail fabric, Host adapter | S0, G, RIME, CELL, EPN, SIR, JIP, XVD, PURIFY, R | Merged names for what exists; draft concepts kept where they add rigor ([ARCHITECTURE.md](ARCHITECTURE.md) section 3) |
| State | Eight admission states | PROVEN / DEGRADED / ISOLATED / RECOVERY | Both, as different machines (ADR-015) |
| EPN | Random record identifier | Digest of versioned content; expansion undecided | Content-addressed; **"Encryption Protocol Number" retained** (ADR-016, O-10) |
| Keys | root/release/policy/recovery/device | image signer, administrative signer, node identity, data-recovery authority | Merged: five roles, plus the data-recovery authority in [RECOVERY.md](RECOVERY.md) |
| Storage | IMMUTABLE/TRUSTED_MUTABLE/EVIDENCE/CACHE/HOST/QUARANTINE | Ephemeral RAM / read-only core / persistent evidence | The classes in [ARCHITECTURE.md](ARCHITECTURE.md) section 6 |
| Roadmap | Phases 0 to 7 | Milestones M0 to M7 | Interleaved in [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md) |
| File naming | `CAPS_UNDERSCORE` | `CAPS-HYPHEN` | Underscore |
| Typo | `jpn` for `epn` in two files | n/a | Corrected |

The draft's fixed decisions and open questions, resolved:

| Draft | Resolution |
|---|---|
| D-01 x86_64 UEFI/QEMU, one Linux workload first | Adopted; the test target |
| D-02 pinned, modified Woof-CE | Superseded by ADR-024 |
| D-03 headless, non-interactive supervisor | Adopted. The **test** base carries BusyBox and a shell for guest scripts; a shell-less production flavour is on the roadmap |
| D-04 recovery read-only, separate media | Adopted; designed |
| D-05 A/B is reboot failover | Adopted; implemented |
| D-06 signed role manifests, per-node identity | Partly: node identity is generated at `init`; role manifests designed |
| D-07 receipts name scope and missing observations | Posture names its scope; signed receipts designed |
| D-08 no destructive automatic purification | Adopted |
| D-09 off-machine encrypted backup, non-TPM factor | Adopted; designed |
| O-01 Woof-CE revision | Moot (ADR-024) |
| O-02 whole-image vs dm-verity | Decided (ADR-026) |
| O-03 encoding, hashes, signatures, rotation | Decided (ADR-017, ADR-018); rotation designed |
| O-04 where authorities live | [RECOVERY.md](RECOVERY.md) section 6 |
| O-05 guest agent | Deferred with the VM cell |
| O-06 passthrough and DMA | Deferred |
| O-07 guest disk filesystem and snapshots | Deferred |
| O-08 external witness | Checkpoints follow the transparency-log model; witness designed |
| O-09 offline emergency and quorum | Designed |
| O-10 what EPN stands for | **Encryption Protocol Number** |
