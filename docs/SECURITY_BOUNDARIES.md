# Security Boundaries and Claims

JLR is a **pre-release prototype**. This document says what it may claim, what it may not, and where each boundary is.
Documentation describes intended properties unless it says a test demonstrates them; it does not imply that a property is
audited, or safe for production.

## 1. Claim discipline

A release MAY claim a security property only when a reproducible test or procedure demonstrates it on a documented platform.
**No security adjective outruns the test suite.**

### Claims the project makes today, and what backs each

| Claim | Backed by |
|---|---|
| A modified, truncated or mis-signed base image or manifest is refused before anything from it runs | QEMU boots: tampered image, truncated image, tampered manifest, unknown signer, wrong record type |
| A validly signed older release is refused once the rollback floor has risen | QEMU: rollback, and the upgrade-then-old-slot scenario |
| A failed update falls back to the proven slot and the failed slot is never retried | QEMU: broken update; boot-state property tests |
| Every single-bit change to the evidence log, a manifest or a signed envelope is detected | Exhaustive flip tests |
| A ledger truncated behind a checkpoint, or rewritten, is detected; a whole-directory rollback is detected against an off-machine checkpoint | Ledger and engine tests |
| The bytes that execute are the bytes that were measured, despite path replacement or in-place edits | Cell, measure and engine tests |
| A cell workload cannot see host files, reach the network in a no-network cell, create namespaces, gain capabilities or see host processes | Real-cell tests, mutation-checked |
| A cell launch whose mandatory controls are missing runs nothing, and every launch reports what was enforced | Cell tests; `jlr doctor` |
| The trust decision is deterministic, revocation always wins, and nothing is promoted without matching evidence | Property tests, mutation-checked |
| Unknown or tampered executables are denied by the kernel when enforcement is on, and only then | QEMU exec-gate test |
| An executable the gate cannot measure (oversized, changing, not a regular file) is denied when enforcing, never waved through, and a repeat exec of an unchanged file writes nothing | Engine tests; QEMU `enforce unmeasurable: BLOCKED` |
| A file system mounted after the daemon started is gated too | QEMU `late mount stranger: BLOCKED` |
| An extra attached disk cannot lower the rollback floor, and a pinned initramfs never mounts another disk | QEMU two-disk and pinned-medium tests |
| A transient read error or a damaged state file cannot retire a good slot or reset the floor | Boot unit tests; QEMU unreadable-state test |
| A cell workload has no controlling terminal, inherits no descriptor beyond its own image, cannot type into the operator's terminal or read the host kernel log | Cell tests, mutation-checked |
| A hostile file name, policy name or revocation text cannot forge ledger or terminal lines or move the policy epoch floor | Model, policy and engine tests |
| A superseded or withdrawn approval or baseline cannot be put back from a copy: only the file whose digest the ledger records as the latest override counts | Engine tests, mutation-checked |
| Losing the path index cannot hide that a trusted file was replaced | Engine test, mutation-checked |
| Wire formats are deterministic, strictly decoded, and reproduced by an independent implementation | Pinned vectors and `tools/check_vectors.py` |
| The boot image and initramfs are bit-for-bit reproducible from identical inputs | `boot/build.sh` builds twice and compares |

### Language to avoid

Documentation and releases SHOULD NOT call JLR unhackable, malware-proof, a proof that software is safe, able to prove its
own integrity solely from inside itself, able to determine hostile intent with certainty, or impossible to bypass. Prefer
concrete statements about measurements, policy, enforcement and recovery.

## 2. Known limitations

Every item below is a boundary a reader must know about. None is hidden elsewhere.

**Deployment**

1. **Companion mode does not resist host root.** Root can stop `jlrd`, read the policy key and rewrite the state directory.
   What remains: signed objects cannot be forged without the key, and an off-machine checkpoint exposes a rollback.
2. **The exec gate sees `exec`, not `mmap`.** `ld.so /path/to/binary` runs a file without an exec event. Closing this needs the
   supervisor deployment (verified base with IPE or fs-verity), not a smarter daemon.
3. **If the daemon dies, the gate opens.** The kernel releases held events when the fanotify descriptor closes. The ledger
   records when the daemon last ran and when it stopped.
4. **Internal gate errors fail open** unless `--fail-closed`. A file the gate cannot measure is *not* an internal error: it
   is denied when enforcing, because the user who runs a file controls its size and how it changes.
5. **The gate cannot see every file system.** One mounted in another mount namespace (for example a tmpfs an unprivileged
   user mounts inside their own user namespace) is not marked, so executables there are not gated. Where that matters,
   restrict unprivileged user namespaces (`kernel.unprivileged_userns_clone=0`, or the AppArmor restriction on recent
   Ubuntu). A file system mounted in the host's namespace is marked when the kernel reports the mount-table change;
   an exec in the few milliseconds before that is not gated.

**Boot**

6. **The initramfs is not authenticated by firmware.** A boot-media attacker who can replace it can replace the trust anchors.
   Fix: signed unified kernel image (designed).
7. **The rollback floor is on the boot media.** The same attacker can lower it. Fix: TPM NV counter (designed).
8. **The boot state file is unauthenticated** for the same reason.
9. **Which disk supplies the rollback floor.** Every attached disk with a `/jlr` tree is examined, and the highest floor on
   any of them applies to all of them, so a stale or foreign disk cannot lower it. That holds only for media that are
   attached: with the real medium absent nothing records what the floor should have been, and an older, validly signed
   release on another disk will boot. An initramfs pinned to one medium (`jlr.media=` or `/etc/jlr/media-id`) never
   mounts any other disk and refuses when the pinned one is missing. Unpinned, an attached disk can still deny service (a
   state file with a very high floor, or a damaged one) because the boot stops rather than guess a floor. The fix that
   removes the dependence on media is the TPM counter (designed).
10. **Write-protected media boot only a proven slot.** An unproven update needs its "try spent" record written first, so
    on a medium that cannot be written it is skipped and the proven slot boots. Success cannot be recorded there either.

**Evidence and provenance**

11. **dpkg's manifests are unauthenticated.** Package-managed software is therefore admitted by an operator-signed baseline, not
   by evidence; the adapter records `SOURCE_KNOWN` and never `PACKAGE_SIGNATURE`.
12. **Checkpoint counters are software counters.** They detect nothing against an attacker who rewrites both the ledger and its
    checkpoints. A checkpoint held off the machine does.
13. **`PROVEN` is scoped.** It never means free of malware.
14. **Path facts and metadata are hints.** Incremental scans reuse a measurement while size, mtime, ctime, inode and device are
    unchanged and the evidence is younger than the policy's limit; an attacker with root can move the clock or edit the inode.
    Evidence is re-collected on the age limit and by the daemon's rescan.

**Confinement**

15. **Cells share the host kernel.** A kernel bug reachable through the allowed syscalls defeats them. A VM is the stronger
    boundary (designed).
16. **The seccomp filter is a deny list.** It also refuses `syslog` and the terminal-injection `ioctl` requests.
17. **`NET_CONNECT` host names are not enforced**; Landlock matches ports.
18. **cgroup limits need a delegated cgroup**; without one, memory and process ceilings are unavailable and reported so.
19. **A `FULL_USER_NETWORK` cell shares the host network namespace.**
20. **No display, audio or input is forwarded**, so graphical programs cannot yet run in cells.
21. **Companion-mode cells created by an unprivileged user depend on user namespaces**, which some distributions restrict.
22. **A cell started from a terminal keeps that terminal as standard input** (in a session with no controlling terminal). It
    can read what is typed and write to it.
23. **The object store and the path index are unauthenticated caches.** Their loss is detected and repaired from the ledger
    where that is possible (a lost index is rebuilt from recorded discoveries; a truncated record is rewritten), but an
    attacker who can write the state directory can still make JLR forget cache-only facts such as evidence details. What
    the ledger records, signed and checkpointed, is not affected.

**Cryptography and process**

24. Signatures are Ed25519 only; post-quantum hybrids are planned, not present.
25. **No external audit; no coverage-guided fuzzing** of the untrusted parsers (property and malformed-input tests only).
26. Compiled binaries are not yet compared bit-for-bit across build machines; the boot artifacts are.

## 3. The self-integrity boundary

JLR can verify signatures, re-measure immutable assets, compare A/B images, validate policy and inspect selected runtime state.
These are **evidence**. A mutable runtime cannot create absolute assurance by repeatedly hashing itself. Stronger assurance
comes from immutable anchors, an independent recovery context, measured boot, external checkpoints and reproducible builds.

## 4. The jail boundary

Namespaces, cgroups, seccomp, Landlock and capability controls share the host kernel. The launcher records the kernel
release, the controls requested, the controls actually active, the mandatory controls unavailable and the resulting status.
Missing mandatory controls MUST NOT be silently treated as full enforcement.

## 5. The cryptographic boundary

Hashes detect change relative to known values. Signatures authenticate relative to trusted keys. Encryption protects data
relative to key control. TPM sealing conditions key release on measured state. None determines whether software logic is
benevolent.

## 6. Human authority

Human approval is authorisation, not verification. Overrides record actor, time, subject EPN, prior state, new scope,
policy version and expiry. An override never becomes "verified".

## 7. Evidence privacy

Evidence may reveal file names, endpoints, process relationships and user activity. The base design provides local-only
operation, no automatic telemetry, explicit export, and encryption for sensitive persistent evidence (**designed**; the
ledger is currently plaintext under a mode-0700 directory). Ledger events contain paths and package names; treat an exported
evidence bundle as sensitive.

## 8. Release rule

**No security adjective outruns the test suite.**
