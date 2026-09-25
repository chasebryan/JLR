# JLR Security Boundaries and Claims

JLR is presently a **design specification**. Documentation describes intended properties; it does not imply those properties are implemented, audited, or safe for production use.

## Claim discipline

A release MAY claim a security property only when a reproducible test or procedure demonstrates it on a documented platform.

Examples include rejection of a modified image or invalid signature, read-only forensic mounts, enforced no-network cells on supported kernels, deterministic EPN measurement, event-chain corruption detection relative to a trusted checkpoint, and verified-slot rollback.

## Language to avoid

JLR documentation SHOULD NOT call the system unhackable, malware-proof, a proof that software is safe, able to prove its own integrity solely from inside itself, able to determine hostile intent with certainty, or impossible to bypass.

Prefer concrete statements about measurements, policy, enforcement, and recovery.

## Self-integrity boundary

JLR can verify signatures, remeasure immutable assets, compare A/B images, validate policy, and inspect selected runtime state. These are evidence.

A mutable runtime cannot create absolute assurance merely by repeatedly hashing itself. Stronger assurance comes from immutable anchors, independent recovery context, measured boot, external checkpoints, and reproducible builds.

## Jail boundary

Linux namespaces, cgroups, seccomp, Landlock, and capability controls share the host kernel.

JLR MUST record the kernel/build identity, requested controls, controls actually activated, mandatory controls unavailable, and resulting enforcement status. Missing mandatory controls MUST NOT be silently treated as full enforcement.

## Cryptographic boundary

Hashes detect change relative to known values. Signatures authenticate relative to trusted keys. Encryption protects data relative to key control. TPM sealing conditions key release on measured state. None determines whether software logic is benevolent.

## Human authority

Human approval is authorization, not verification. Overrides SHOULD record actor, time, subject EPN, prior state, new scope, policy version, and expiration where applicable.

## Evidence privacy

Evidence may reveal filenames, endpoints, process relationships, and user activity. The base design SHOULD provide local-only operation, no automatic telemetry, explicit export, documented retention, redaction support, and encryption for sensitive persistent evidence.

## Release rule

**No security adjective outruns the test suite.**
