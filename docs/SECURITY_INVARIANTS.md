# JLR Security Invariants

These invariants are intended to be testable implementation requirements.

## I-01 — No implicit trust promotion

An artifact MUST NOT move from UNKNOWN, QUARANTINED, or OBSERVED to VERIFIED or ADMITTED without a recorded policy decision and supporting evidence.

## I-02 — Identity before policy

Policy decisions about an artifact MUST be bound to a cryptographic identity, not only a pathname or package name.

## I-03 — Immutable expected state

A component being measured MUST NOT be able to silently rewrite its own expected measurement and then satisfy verification.

## I-04 — Separation of evidence and decision

Raw measurements MUST be retained independently from the conclusion produced from them.

## I-05 — Host cannot authorize JLR

The host OS MUST NOT be able to promote JLR core components, rewrite root policy, or erase historical security events through ordinary host privileges.

## I-06 — Least capability

Admission MUST grant an explicit capability set. Absence of a capability means denial.

## I-07 — State transitions are auditable

Every trust-state transition MUST record old state, new state, evidence, policy version, actor, and time.

## I-08 — Degradation on mismatch

A verified artifact whose protected identity changes MUST leave VERIFIED/ADMITTED state until re-evaluated.

## I-09 — Recovery independence

At least one supported recovery path MUST remain bootable without executing the host OS.

## I-10 — Signed base

A production JLR base image MUST have authenticated release metadata.

## I-11 — No silent policy fallback

If trusted policy cannot be loaded or validated, JLR MUST NOT silently substitute permissive defaults.

## I-12 — Monotonic evidence

Security event history MUST be append-only during normal operation and hash chained or equivalently tamper evident.

## I-13 — Explicit override

An operator override MUST be represented as an override, never rewritten as automatic verification.

## I-14 — Revocation wins

A valid revocation applicable to an artifact MUST take precedence over stale admission evidence.

## I-15 — Minimal mutable core

Runtime-writable state in the trusted computing base MUST be minimized and separately mounted from immutable code.

## I-16 — Jail escape is trust failure

Evidence of jail escape, unauthorized namespace crossing, policy-bypass, or forbidden device access MUST immediately degrade or revoke the responsible workload.

## I-17 — Deterministic decision replay

Given the same policy version and same normalized evidence set, the Trust Engine SHOULD reproduce the same decision.

## I-18 — Explicit recovery writes

Recovery mode MUST mount host storage read-only by default. Any write operation requires an explicit recovery action.
