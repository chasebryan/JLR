# JLR Threat Model

## 1. Protected assets

JLR protects:

- integrity of its own boot and policy artifacts
- integrity evidence for host software
- admission decisions
- recovery capability
- trusted keys
- operator intent
- historical security events
- confidentiality of protected JLR state
- host data during recovery

## 2. Adversaries

### A1 — Malicious user-space program

Capabilities:

- runs as normal user
- attempts persistence
- modifies accessible files
- opens network connections
- tries to inspect peers

JLR defense: identity, jail fabric, least capability, mutation detection.

### A2 — Privileged host compromise

Capabilities:

- host root
- service modification
- package database modification
- boot artifact modification

JLR defense: separate trust plane, immutable base, host remeasurement, independent recovery.

### A3 — Supply-chain compromise

Capabilities:

- malicious upstream package
- stolen publisher key
- compromised mirror
- poisoned update

JLR defense: provenance policy, multiple evidence types, revocation, reproducible builds where available, observation cell.

### A4 — JLR mutable-state tampering

Capabilities:

- modifies policy database or evidence store offline

JLR defense: signatures/MACs, hash chaining, encrypted state, checkpoint verification.

### A5 — Physical attacker

Capabilities vary.

JLR can mitigate some physical attacks with full-disk encryption, Secure Boot, TPM sealing, and protected recovery media, but cannot guarantee security against unrestricted physical access to an unprotected machine.

### A6 — Firmware or hardware compromise

JLR does not claim to defeat malicious CPU, firmware, DMA hardware, or an already compromised root of trust.

Measured boot can provide evidence but not magically repair a hostile platform.

## 3. Primary attack surfaces

- bootloader
- update channel
- policy parser
- manifest parser
- jail creation
- privileged helper interface
- host adapter
- event store
- recovery UI
- key storage
- filesystem parsers
- kernel attack surface

## 4. Security assumptions

Initial implementation assumes:

- cryptographic primitives are correctly implemented by audited libraries
- at least one boot/recovery artifact remains trustworthy
- the operator can protect root credentials or hardware token
- the CPU and memory subsystem are not actively malicious
- the kernel enforcing a jail is trusted enough for that jail's threat level

## 5. Non-goals

JLR is not:

- a guarantee that all admitted software is benign
- a malware oracle
- a substitute for backups
- a hypervisor by default
- a defense against every hardware implant
- a replacement for secure software development
- a system that can prove itself trustworthy from a compromised runtime alone

## 6. High-value abuse cases

The implementation must test at least:

1. modified admitted executable
2. symlink/path replacement
3. package database lies about file identity
4. stolen or revoked signing key
5. jail attempts host namespace entry
6. hostile process writes executable into trusted path
7. host root tries to change JLR policy
8. event log truncation
9. rollback to vulnerable signed release
10. malicious recovery image
11. partial update/power loss
12. dependency substitution
13. writable loader or EFI compromise
14. kernel module introduced after admission
15. operator override without audit trail

## 7. Response principle

JLR should prefer an explicit degraded state over pretending certainty.

Unknown must remain unknown.
