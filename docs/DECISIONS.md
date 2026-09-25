# JLR Architecture Decisions

## ADR-001 — JLR installs before host Linux
JLR owns an independent boot/recovery substrate before provisioning or handing off to the governed host.

## ADR-002 — Puppy Linux is a construction substrate
A heavily stripped Puppy-derived build may supply the recovery base, but Puppy is not itself the security boundary.

## ADR-003 — Runtime is RAM-resident, not persistence-free
Verified core code runs from RAM; policies, keys, manifests, evidence, and redundant recovery assets use explicit persistent storage.

## ADR-004 — Unknown is not malicious
New artifacts begin UNKNOWN/QUARANTINED because missing evidence does not establish intent.

## ADR-005 — EPN is public identity, not secret key material
The Encryption Protocol Number identifies a signed integrity/protection record and is safe to log.

## ADR-006 — Approval grants scoped capability
Authorization binds an EPN, policy version, and jail/capability set rather than permanent unrestricted trust.

## ADR-007 — Self-verification requires external anchors
Internal self-check loops are evidence, not proof. Immutable references, signatures, measured boot, recovery context, and independent checkpoints provide stronger anchors.

## ADR-008 — Recovery is read-only by default
Suspect host storage stays read-only until an explicit repair action authorizes writes.

## ADR-009 — Linux is the first governed host
Initial guarantees map to concrete Linux enforcement primitives.

## ADR-010 — Explain evidence, not opaque scores
UI alerts point to measurements, events, rules, or attributed external classifications.

## ADR-011 — No mandatory cloud dependency
Core boot, recovery, EPN verification, policy, isolation, and evidence functions work offline.

## ADR-012 — Security claims follow tests
Planned properties remain design targets until demonstrated by reproducible implementation evidence.
