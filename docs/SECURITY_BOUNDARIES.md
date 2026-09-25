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
4. **Internal gate errors fail open** unless `--fail-closed`.

**Boot**

5. **The initramfs is not authenticated by firmware.** A boot-media attacker who can replace it can replace the trust anchors.
   Fix: signed unified kernel image (designed).
6. **The rollback floor is on the boot media.** The same attacker can lower it. Fix: TPM NV counter (designed).
7. **The boot state file is unauthenticated** for the same reason.
8. **Media discovery mounts the first partition that has a `/jlr` directory.** A second attached disk carrying a `/jlr` tree
   signed by an untrusted key is still refused (its manifest will not verify), and one signed by a trusted key is, by
   definition, trusted; but a *denial of service* by an attached disk that shadows the real one is possible.

**Evidence and provenance**

9. **dpkg's manifests are unauthenticated.** Package-managed software is therefore admitted by an operator-signed baseline, not
   by evidence; the adapter records `SOURCE_KNOWN` and never `PACKAGE_SIGNATURE`.
10. **Checkpoint counters are software counters.** They detect nothing against an attacker who rewrites both the ledger and its
    checkpoints. A checkpoint held off the machine does.
11. **`PROVEN` is scoped.** It never means free of malware.
12. **Path facts and metadata are hints.** Incremental scans reuse a measurement while size, mtime, ctime, inode and device are
    unchanged and the evidence is younger than the policy's limit; an attacker with root can move the clock or edit the inode.
    Evidence is re-collected on the age limit and by the daemon's rescan.

**Confinement**

13. **Cells share the host kernel.** A kernel bug reachable through the allowed syscalls defeats them. A VM is the stronger
    boundary (designed).
14. **The seccomp filter is a deny list.**
15. **`NET_CONNECT` host names are not enforced**; Landlock matches ports.
16. **cgroup limits need a delegated cgroup**; without one, memory and process ceilings are unavailable and reported so.
17. **A `FULL_USER_NETWORK` cell shares the host network namespace.**
18. **No display, audio or input is forwarded**, so graphical programs cannot yet run in cells.
19. **Companion-mode cells created by an unprivileged user depend on user namespaces**, which some distributions restrict.

**Cryptography and process**

20. Signatures are Ed25519 only; post-quantum hybrids are planned, not present.
21. **No external audit; no coverage-guided fuzzing** of the untrusted parsers (property and malformed-input tests only).
22. Compiled binaries are not yet compared bit-for-bit across build machines; the boot artifacts are.

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
