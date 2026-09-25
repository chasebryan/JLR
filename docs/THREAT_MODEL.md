# JLR Threat Model

## 1. Protected assets

- integrity of JLR's own boot, policy and trust-anchor artifacts;
- integrity evidence for host software and the admission decisions made from it;
- the recovery capability;
- signing keys;
- operator intent (nothing is authorised without a person or a signed policy behind it);
- historical security events;
- confidentiality of protected JLR state;
- host data during recovery.

## 2. Adversaries

For each: what the adversary can do, what JLR does about it **today**, and what remains.

### A1 - Malicious user-space program

*Can:* run as a normal user, try to persist, modify files it can reach, open connections, inspect peers.
*JLR today:* identity, the exec gate, cells, mutation detection. An unknown program runs only in CELL-0 (no network, no home, no
devices, read-only system tree); if enforcement is on it cannot be executed natively at all.
*Remains:* the kernel it shares; code loaded without exec ([SECURITY_BOUNDARIES.md](SECURITY_BOUNDARIES.md) 2).

### A2 - Privileged host compromise

*Can:* host root; modify services, the package database and boot artifacts.
*JLR today:* **supervisor:** the base is read-only in RAM, verified before use; a modified host boot set is designed to be
detected. **Companion:** host root is above JLR's protection: it can stop the daemon and rewrite the state directory. Signed
objects cannot be forged without keys, and the ledger plus an off-machine checkpoint reveal what JLR saw and any rollback.
*Remains:* the whole of companion mode's residual; the supervisor's handoff to a host is designed, not built.

### A3 - Supply-chain compromise

*Can:* a malicious upstream package, stolen publisher key, compromised mirror, poisoned update.
*JLR today:* provenance ranks; revocation by digest, signer or EPN; policy that never admits on weak provenance; observation-first
for the unknown; reproducible boot images. **Gap:** package-managed software is admitted by an operator baseline, so a
compromised package present at enrolment is enrolled; the managed-installer hook and reproducible package rebuilds are the fix.

### A4 - JLR mutable-state tampering

*Can:* modify the policy, approvals, baselines or evidence store offline.
*JLR today:* every trust-bearing object is signed and verified at load and refused on failure; policy and revocation epochs never
go backwards; the ledger is signed, linked and Merkle-committed; single-bit changes are detected; torn tails are quarantined.
*Remains:* an attacker who also holds the device and policy keys (companion mode), or who replaces the whole directory
with an older consistent copy and holds no off-machine checkpoint.

### A5 - Physical attacker

*Can:* vary from swapping a disk to removing it.
*JLR today:* nothing at rest is encrypted yet (**designed**: authenticated encryption of `JLR-STATE`, TPM sealing, Secure
Boot). A boot-media writer can replace the initramfs and lower the floor until the unified kernel image and TPM counter exist.
*Remains:* unrestricted physical access to an unprotected machine is not defended.

### A6 - Firmware or hardware compromise

JLR does not claim to defeat a malicious CPU, firmware or DMA device, or an already compromised root of trust. Measured boot
provides evidence, not repair.

### A7 - Boot-media attacker (added)

*Can:* write the boot medium (a removable stick, a shared disk) but does not hold the release key.
*JLR today:* cannot boot a chosen image (manifest signature, role and image digest are checked before use), cannot make the
machine run a validly signed **older** release once the floor has risen while any medium that recorded the raised floor is
attached and seen in time (the highest floor on any attached medium applies), and cannot cause anything from the media to
run after a refusal. Pinning the initramfs to the real medium's identifier keeps other disks from being considered at all,
but the identifier is copyable, so a cloned identifier with the real medium absent is the same residual risk as unpinned. A read error or a damaged state file stops the boot; it never
reads as "fresh" and never resets the floor, and only proof that an image is bad (digest or size) retires a slot.
*Remains:* replace the initramfs (and with it the anchors), lower the floor and the boot state on every attached medium at
once (or on the pinned one), offer an older release when the real medium is absent and either the initramfs is unpinned or
the pinned identifier is cloned, or deny service (a state file with a very high floor, or a damaged one). The first three need the authenticated-boot milestone or the TPM counter.

### A8 - Local co-tenant and workload in a cell (added)

*Can:* another local user, or code inside a cell, trying to reach JLR's state or another cell.
*JLR today:* the state directory is mode 0700 and never mounted into cells; key files are refused if group or world accessible;
a cell has a private root, PID, IPC and (usually) network namespace; the sealed executable is per launch.
*Remains:* the shared kernel.

## 3. Attack surfaces

The parsers and boundaries that take untrusted input, and how each is hardened:

| Surface | Hardening |
|---|---|
| CBOR decoder, envelope, records | Strict, canonical, bounded depth, no allocation from declared lengths, re-encode check; property tests and mutation fuzz tests; **not** coverage-guided fuzzed |
| Ledger frames | Length check field; torn tails quarantined, never deleted; every flip is an error |
| Release manifest, boot state | Signature and role first, then strict parse; image size and digest checked while copying |
| dpkg database and manifests | Treated as unauthenticated hints; index cache validated by a fingerprint and structural checks; a damaged cache is a miss |
| TOML policy source | Compiled and validated; only the signed canonical form is loaded; unknown fields rejected |
| Kernel command line, media discovery | Read only for named flags; a partition needs a `/jlr` directory and a verifying manifest |
| Cell specification (helper argument) | CBOR, strict, produced by the launcher; the helper trusts nothing from the environment |
| The state directory | Mode 0700; every trust-bearing file verified at load |
| fanotify events | The daemon measures the delivered descriptor, not a path |
| Filesystem parsers (ext4, squashfs, vfat) | The kernel's. For the RAM base the image is verified **before** the kernel parses it |

## 4. Assumptions

- Cryptographic primitives are correctly implemented by the libraries used.
- At least one boot or recovery artifact remains trustworthy (an unmodified release key and its signed images).
- The operator can protect the offline keys, and takes an off-machine checkpoint.
- The CPU and memory subsystem are not actively malicious.
- The kernel enforcing a cell is trusted enough for that cell's threat level.
- The clock may be wrong; nothing relies on wall time for authority (it is advisory, and used only to expire approvals and
  age evidence).

## 5. Non-goals

JLR is not a guarantee that admitted software is benign; a malware oracle; a substitute for backups; a hypervisor by default; a
defence against every hardware implant; a replacement for secure software development; or a system that can prove itself
trustworthy from a compromised runtime alone.

## 6. Abuse cases and their tests

Every case must have a test or an explicit gap.

| # | Abuse case | Coverage |
|---:|---|---|
| 1 | Modified admitted executable | Engine tamper test; QEMU `tampered known: BLOCKED` |
| 2 | Symlink or path replacement between measurement and use | Symlink refusal; descriptor-measurement tests; sealed-exec tests |
| 3 | The package database lies about file identity | Manifest mismatch is evidence; a *consistent* lie yields only `SOURCE_KNOWN`, which policy cannot admit. **Gap:** an operator baseline enrols what the database vouches for |
| 4 | Stolen or revoked signing key | Revocation by digest and EPN, in every accepted spelling, with malformed targets refused (`revocation_targets_are_validated_and_put_in_the_form_the_matcher_compares`). **Gap:** revocation by signer is accepted, but no source adapter records a signer identity yet, so it matches nothing today; the command says so |
| 5 | Jail attempts host namespace entry | Cell tests: no `unshare`, no `chroot`, no host paths, PID isolation |
| 6 | Hostile process writes an executable into a trusted path | `WRITABLE_PATH` evidence caps the cell; the gate denies the new file when enforcing |
| 7 | Host root tries to change JLR policy | Tampered, wrong-role and rolled-back policy are refused. **Gap:** in companion mode root holds the policy key |
| 8 | Event log truncation | Truncation, reordering, deletion and rollback tests |
| 9 | Rollback to a vulnerable signed release | QEMU rollback scenarios |
| 10 | Malicious recovery image | Unknown signer and wrong-role scenarios cover the boot path; recovery images are designed |
| 11 | Partial update or power loss | Tries spent before boot; property tests. **Gap:** a real power-cut matrix |
| 12 | Dependency substitution | **Not covered:** dependencies are not populated yet |
| 13 | Writable loader or EFI compromise | **Not covered:** needs Secure Boot |
| 14 | Kernel module introduced after admission | **Not covered:** modules are governed by scan, and `finit_module` is not gated |
| 15 | Operator override without an audit trail | Every override is a ledger event with `MANUAL_OVERRIDE` |
| 16 | A damaged length field causing valid events to be treated as a torn tail and deleted | Fixed and tested: length check field, quarantine, and `a_corrupt_length_in_the_middle_never_causes_deletion_on_open` |
| 17 | An approval or baseline replayed on another node | Signature scope test |
| 18 | A signed policy replayed as a release, or the reverse | Envelope type-confusion tests, including in QEMU |
| 19 | A stale cached verdict outliving a policy change | The daemon clears its cache on signed-state changes and expires verdicts by age; the QEMU audit-to-enforce flip |
| 20 | An unverified image reaching the mount | Image hashed while copied into RAM; refusal scenarios; nothing runs after a refusal |
| 21 | A user makes measurement fail (pad a file past the limit, touch it in a loop, use a FIFO) to slip past the gate | Unmeasurable files are decisions and are denied when enforcing (`a_file_that_cannot_be_measured_is_a_denial_not_an_internal_error`); QEMU `enforce unmeasurable: BLOCKED` |
| 22 | A file system mounted after the gate started, including one that reuses a device number or has an unusual mount-point name | QEMU: `late mount stranger`, `remounted stranger`, `odd name stranger` all `BLOCKED`. **Gap:** mounts in another mount namespace (limitation 5 in SECURITY_BOUNDARIES) |
| 23 | An unprivileged user floods the gate with new executables to stall everyone or grow governance state | Per-user slow-path budget plus a cap on all unprivileged users together (so subordinate ids do not multiply it), charged only for work and not for lock waits; a throttled user leaves a summary event; bounded caches; a repeat exec of an unchanged file writes neither events, index nor evidence objects (`a_repeat_exec_decision_for_an_unchanged_file_writes_nothing`); O(1) prefix roots in the ledger. **Gaps:** the gate is one thread, root is not throttled, and each *unique* unknown executable still costs an engine open (on the order of 100 ms at 6,000 events (a one-off measurement, not a benchmark)) and adds an evidence object and events; growth is rate-bounded per user, not capped |
| 24 | Hostile file, policy or revocation text forges terminal or ledger lines, or moves the policy epoch floor | `sanitize` on every printed and logged attacker-influenced string; policy and tier names are a plain alphabet; the epoch floor is parsed from fixed fields (`the_policy_epoch_floor_ignores_prose_an_author_controls`, `attacker_chosen_names_cannot_inject_control_characters_into_the_ledger`) |
| 25 | A cell workload types into the operator's terminal, uses a leaked descriptor, or reads the host kernel log | Cell tests for each, mutation-checked |
| 26 | A second attached disk offers an older release or shadows the real medium | QEMU: `a_second_disk_with_an_older_release_cannot_downgrade_the_machine`, `a_pinned_boot_never_uses_or_mounts_another_disk` |
| 27 | A transient I/O error or a damaged state file retires a good slot or resets the floor | Boot unit tests and the QEMU unreadable-state and write-protected-medium scenarios |
| 28 | A crash or full disk leaves a torn checkpoint and the next checkpoint corrupts the log | `a_torn_checkpoint_tail_is_quarantined_and_does_not_brick_the_ledger`, `a_failed_append_leaves_no_bytes_behind` |
| 29 | An edit that restores the modification time, or a file that keeps changing, is measured as if stable | `an_edit_that_restores_mtime_is_still_detected_because_ctime_cannot_be_restored`, `a_file_that_keeps_changing_is_reported_not_measured` |
| 30 | A withdrawn or superseded approval or baseline is restored from a copy, or a copy under another name shadows the current one | `a_withdrawn_approval_cannot_be_put_back_from_a_copy`, `a_superseded_baseline_cannot_be_restored_from_a_copy` |
| 31 | The path index or an object is deleted or truncated to hide a replaced file | `losing_the_path_index_does_not_hide_that_a_trusted_file_was_replaced`, `losing_the_object_store_still_degrades_a_trusted_file_that_changes`, `a_truncated_object_is_rewritten_the_next_time_the_artifact_is_seen` |

## 7. Response principle

JLR prefers an explicit degraded state to pretending certainty. Unknown remains unknown.
