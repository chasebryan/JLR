# Glossary

**Admission** - authorisation for an identified artifact to execute with a defined capability set. Never "unrestricted".

**Approval** - a signed, scoped, expiring operator authorisation for one EPN. Authority, not proof.

**Artifact** - a file, image, package, service definition, configuration object, firmware object or other governed object.

**Assurance label** - what a report may honestly claim given the boundary it runs behind: `prototype`, `companion`, `supervisor`, `recovery`.

**Audit mode** - the exec gate records what it would deny and blocks nothing. The default.

**Baseline** - an operator-signed set of EPN record digests standing for a machine's initial state. Members are admitted as manual overrides.

**Base image** - the immutable, signed JLR operating image loaded into RAM.

**Basis** - why a state was reached: `CRYPTOGRAPHIC`, `POLICY`, `MANUAL_OVERRIDE`, or `NONE`.

**Capability** - one specific permission in a semantic vocabulary (`FS_READ:/path`, `NET_CONNECT:host:port`, ...). Absence is denial.

**Cell** - an isolated execution environment produced by the jail fabric; CELL-0 (analysis) to CELL-3, and CELL-R for recovery.

**Checkpoint** - a signed commitment to the ledger's size and Merkle root.

**Companion** - the deployment where JLR runs beside the host on the host kernel; host root can subvert it.

**Degraded** - previously valid trust evidence no longer fully matches reality (an artifact state), or evidence is missing or stale (a posture).

**Device key** - the per-machine key that signs ledger events and checkpoints.

**Enforcement report** - what a cell launch actually established: controls requested, active and unavailable, mandatory controls missing, and an overall `Full`, `Partial` or `Refused`.

**Envelope** - the COSE_Sign1 structure that carries every signed record, bound to its record type and node.

**EPN (Encryption Protocol Number)** - the public, content-addressed identifier of an artifact identity record: `EPN-1-<CLASS>-<sha256>`. Not a secret and not itself encryption.

**Evidence** - an observed or externally authenticated fact used by policy, with source and time.

**Exec gate** - the fanotify permission mark that holds each `exec` until the daemon answers.

**Floor (rollback floor)** - the lowest release epoch that may boot; it only rises, and only after a successful health check.

**Governance plane** - the JLR components that measure, decide, record, enforce and recover.

**Host** - the general-purpose operating system JLR governs.

**Immutable** - not writable during ordinary runtime; changed only by authenticated replacement.

**Jail fabric** - the composition of kernel isolation and resource controls that enforces a decision.

**JLR-DCBOR/1** - the deterministic CBOR profile all signed objects use.

**Ledger** - the signed, hash-linked, Merkle-committed record of security-relevant events.

**Manifest** - a signed statement binding a release to the exact digest and size of its image.

**Manual override** - a state reached by human authority despite incomplete evidence; always recorded as such.

**Measurement** - a cryptographic or structural observation of state.

**Observation cell** - a restrictive cell in which unknown software runs while its behaviour is recorded.

**Policy** - signed rules mapping normalised evidence to state, cell, network and capabilities.

**Posture** - the trust state of a named scope (`DEGRADED`, `PROVEN`, `ISOLATED`, `RECOVERY`). Always scoped, never "clean".

**Provenance rank** - how strongly an artifact's origin is authenticated, from `REPRODUCED` (1) to `UNKNOWN` (6).

**Quarantine** - a state in which an artifact is denied ordinary execution.

**Recovery plane** - the independently bootable environment used when the host's trust is unavailable.

**Revocation** - explicit, signed, terminal-until-superseded invalidation of prior trust, by EPN, content digest or signer.

**Root of trust** - a component or key accepted as an initial anchor rather than derived from the mutable system being evaluated.

**Sealed memfd** - an in-memory file whose contents can no longer be changed; what a cell executes.

**Slot** - one of the A/B boot images with its priority, remaining tries and success flag.

**Supervisor** - the deployment where JLR boots first from verified media and governs the host as a workload.

**Torn tail** - an incomplete final ledger record left by a crash during append; quarantined, never deleted.

**Trust anchor** - a key or artifact the verifier accepts without deriving it from anything else.

**Trust engine** - the deterministic decision function over evidence and a policy version.
