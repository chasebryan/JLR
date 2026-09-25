# JLR Integrity Protocol

## 1. Encryption Protocol Number

Every governed artifact is represented by an **Encryption Protocol Number (EPN)**.

An EPN is a public, versioned identifier for a signed JLR integrity-and-policy record. The name reflects the protection protocol bound to the artifact; the EPN itself is **not** a secret, password, cipher key, or proof that the software is benevolent.

Recommended EPN v1 textual form:

~~~text
EPN-1-<class>-<record-id>
~~~

Example:

~~~text
EPN-1-EXE-7f3c64d2c6244a889fe64dc8a95e3132
~~~

The full record binds the random record identity to exact cryptographic measurements and policy. Security MUST NOT depend on secrecy of the EPN.

## 2. Artifact classes

Initial classes:

- BOOT
- KERNEL
- INITRD
- MODULE
- EXE
- LIB
- SCRIPT
- SERVICE
- CONFIG
- PACKAGE
- CONTAINER
- IMAGE
- POLICY
- KEY
- FIRMWARE
- DATASET
- RECOVERY
- OTHER

## 3. Required record fields

~~~text
schema_version
epn
artifact_class
canonical_name
version
created_at
discovered_at
content_digests
normalized_metadata_digest
size
source
provenance
signatures
build_identity
dependencies
requested_capabilities
allowed_capabilities
filesystem_profile
network_profile
device_profile
sandbox_profile
protection_profile
state
state_reason
policy_version
evidence_refs
approval_refs
revocation_refs
supersedes
superseded_by
record_signature
~~~

The immutable artifact identity and the mutable local admission state SHOULD be separable in storage so a state transition never rewrites the historical artifact measurement.

## 4. Cryptographic baseline

EPN v1 production baseline:

- SHA-256 MUST be supported for artifact and manifest digests.
- SHA-512 MAY be recorded as an additional digest.
- JLR-owned protocol records SHOULD use Ed25519 signatures.
- Signed machine records SHOULD use a deterministic canonical representation such as canonical CBOR.
- Human-readable JSON MAY mirror a signed record but MUST NOT create a second ambiguous signing format.
- Random record identifiers MUST come from a cryptographically secure operating-system RNG.

Every digest field includes its algorithm name. Bare unlabeled digests are forbidden.

## 5. Protection profile

The word **Encryption** in EPN binds an artifact to an explicit storage/protection policy. It does not mean every executable is necessarily encrypted at rest.

Initial profile classes may include:

- NONE — no JLR-managed at-rest encryption
- HOST — protection delegated to host disk encryption
- JLR-SEALED — protected by a JLR-managed encrypted object store
- TPM-SEALED — key release additionally bound to measured platform state

Cipher suites and key-derivation parameters belong to versioned protection profiles and MUST NOT be encoded as undocumented defaults.

## 6. Identity separation

JLR distinguishes:

- **content identity** — digest of exact bytes
- **record identity** — EPN
- **installation instance identity** — one filesystem/package occurrence
- **execution instance identity** — one launched process tree

This permits identical bytes to have different local permissions without confusing artifact identity with execution context.

## 7. Evidence

Evidence may include content hash matches, release/package signatures, reproducible-build matches, dependency closure, measured-boot values, static-analysis results, observation-cell results, operator authorization, and attributed external classifications.

Evidence records MUST identify source and timestamp. Operator authorization is authority, not cryptographic verification.

## 8. Admission state

~~~text
UNKNOWN
  |
  v
QUARANTINED ----> REVOKED
  |
  v
OBSERVED
  |
  +----> POLICY_BLOCKED
  |
  v
VERIFIED
  |
  v
ADMITTED
  |
  +----> DEGRADED ----> QUARANTINED / REVOKED
~~~

POLICY_BLOCKED means evidence satisfies a prohibition in the active policy. It does not claim JLR has independently proven a developer's or process's intent.

Transitions are policy-driven and auditable.

## 9. Release manifest

A JLR release manifest SHOULD bind release version, source commit, build-environment identity, SBOM digest, base-image digest, loader digest, policy-bundle digest, recovery-image digest, supported migrations, and minimum allowed version when rollback protection is enabled.

The manifest is signed separately from the image.

## 10. Evidence ledger

Security-relevant records SHOULD form a tamper-evident chain containing at least:

~~~text
sequence
boot_id
actor
subject_epn
event_type
policy_version
decision
evidence_digest
previous_event_digest
record_digest
signature_or_mac
~~~

A hash chain detects rewriting only relative to a trusted checkpoint. Higher-assurance deployments SHOULD periodically checkpoint ledger heads outside mutable host state.

## 11. Revocation

Revocation entries MUST support exact EPN, exact content digest, signing key, package coordinate/version range, policy capability, and whole release.

Revocation wins over stale admission evidence unless an explicit later signed record supersedes it.

## 12. Protocol principle

**Hashes identify. Signatures authenticate provenance. Encryption protects data under key control. Policy constrains authority. Observations provide evidence. None of these alone proves software intent.**
