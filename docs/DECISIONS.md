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

## Decisions taken after the first adversarial review

**ADR-033 - A file the gate cannot measure is a decision, not an error.** The user who runs a file controls its size,
whether it changes while it is read, and whether it is a regular file, so treating those conditions as internal errors
(which fail open) let anyone pad or touch a file to run it unchecked. They now yield a verdict: quarantined, `CELL-0`, no
network, `EVIDENCE_MISSING`, denied when enforcing and recorded as "would deny" when auditing, cached for seconds only.
`--fail-closed` remains for genuine internal errors. *Adopted; amends ADR-027.*

**ADR-034 - The rollback floor is the highest one on any attached medium, and media can be pinned.** The floor lives on the
medium (until the TPM counter exists), so "the first disk that answers" let anyone who could attach a disk choose which
floor applied. All media that enumerate in time are examined and the maximum applies to every slot; an initramfs pinned to
one file system identifier never mounts another disk. Media are mounted read-only and remounted only to write state. *Adopted;
amends ADR-025. A pin is an identifier, not authentication: a cloned identifier with the real medium absent, or a writer of
the pinned medium, defeats it. Unpinned boots still depend on the real medium being attached, and say so at every boot.*

**ADR-035 - Only a proven-bad image retires a slot; only a missing file is a fresh medium.** A read error, an unreadable
state file, memory exhaustion or reads that disagree with each other are not evidence about a slot's content, and guessing
"fresh" resets the floor to zero. Those stop the boot or skip the slot for one boot and change nothing on disk; a
mismatch is confirmed by a second read, and the same wrong answer twice is the proof. The image is verified **before** a
try is spent, because a try exists to make a crash while the slot is in use fall back, and reading is not use. *Adopted;
refines ADR-025.*

**ADR-036 - The ledger, not a directory, says which approval and baseline are current.** A signed file counts only if its
envelope digest is the evidence of the latest `OVERRIDE` event for its subject (`baseline:<name>` for baselines). A
superseded file that is copied back verifies again on its signature alone; binding to the ledger closes that, and reports
the ignored file once. Files are stored under names that carry their digest and are written before the event that makes them
current, so an interrupted update leaves the old authority in force. *Adopted; baselines enrolled before this change must be
re-enrolled (docs/OPERATIONS.md 5a).*

**ADR-037 - Caches may lose data but not the memory of what was trusted.** The path index and object store are
unauthenticated caches. A lost index is rebuilt from recorded discoveries and content-addressed records, a truncated
object is rewritten, an unloadable record still degrades or revokes by identifier, and the index is written only after the
ledger events it summarises are durable. *Adopted.*

**ADR-038 - A cell owns its session and its descriptors.** The workload gets a new session (no controlling terminal), only
descriptors 0 to 2 and its own sealed image, no kernel log and no terminal-injection `ioctl`s. A grant that could not be
applied is reported and makes the status `Partial`. *Adopted; amends ADR-021 and ADR-022.*

**ADR-039 - The lock is held to decide, not to run.** `jlr run` measures, decides and records the start under the ledger
lock, releases it for the life of the workload, and takes it again to record the end. A long-lived confined program
therefore cannot stall the exec gate, revocations or a policy change. If the end cannot be recorded, the program's result is
still returned with a note. *Adopted; refines ADR-028.*

**ADR-040 - Sanitising is idempotent.** Text passes through several layers (an operator's reason, the event that records it,
the command that prints it), and escaping backslashes doubled them at each layer and made a legitimate identifier such as
`CN=Doe\, John` "unprintable". Control, separator and invisible characters are escaped and a backslash is left alone; text
that is already safe and short enough is returned as it is, which makes applying the function again change nothing, even
when a limit falls inside an escape. Every attacker-influenced part (a path, a file name) of a composed event is bounded on
its own before the message is assembled, so truncation cannot remove the state, reasons or step that follow it. *Adopted.*

**ADR-041 - The gate's budget is charged for work and capped overall.** A user is charged for opening the engine and
deciding, not for waiting on a lock they did not hold; all unprivileged users together may spend at most 30 seconds of that
work a minute, so many uids (subordinate ids, user namespaces) cannot multiply the allowance; a file already allowed,
unchanged and inside its real validity is not made to pay for its user's other executions; throttling is recorded as a
bounded number of events written with one flush, never one per user or file. The price: a few accounts can use the shared
cap up and cause other users' *unknown* executions to be answered by policy for the rest of the minute (cached and known-good
files are unaffected). *Adopted; refines ADR-027.*

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
