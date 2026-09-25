# JLR Integrity Protocol

## 1. JLR Protocol Number

Every governed artifact is represented by a **JLR Protocol Number (JPN)**.

A JPN is a stable identifier for a versioned security record.

Recommended textual form:

~~~text
JPN-1-<class>-<128-bit-id>
~~~

Example:

~~~text
JPN-1-EXE-7f3c64d2c6244a889fe64dc8a95e3132
~~~

The random identifier prevents path- or name-based ambiguity. The record itself contains cryptographic digests.

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
jpn
artifact_class
canonical_name
version
created_at
discovered_at
content_digests
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

## 4. Digest policy

At minimum, production records should support SHA-256 and SHA-512.

The schema must permit future algorithms without reinterpreting old records.

A digest field includes the algorithm name:

~~~text
sha256:...
sha512:...
~~~

JLR must never use a bare unlabeled digest in a protocol record.

## 5. Content identity versus instance identity

Two files with the same bytes may have the same content digest but exist in different security contexts.

Therefore JLR distinguishes:

- **content identity** — cryptographic hash of bytes
- **record identity** — JPN
- **instance identity** — a particular filesystem/process occurrence

This permits one binary to be admitted in one context and denied in another.

## 6. Verification evidence

Evidence may include:

- hash match
- release signature
- package signature
- reproducible-build match
- known-good snapshot match
- dependency closure match
- measured boot value
- user approval
- static analysis result
- sandbox observation result
- policy exception

Evidence records must include source and timestamp.

## 7. State machine

~~~text
UNKNOWN
  |
  v
QUARANTINED ----> REVOKED
  |
  v
OBSERVED
  |
  +----> HOSTILE
  |
  v
VERIFIED
  |
  v
ADMITTED
  |
  +----> DEGRADED ----> QUARANTINED / REVOKED
~~~

Transitions are policy-driven and auditable.

## 8. Protocol numbers are not secrets

A JPN may appear in logs, UI, and reports.

Security must not depend on keeping JPN values secret.

## 9. Manifest format

A JLR release manifest should bind:

- release version
- build commit
- build environment identifier
- base image digest
- loader digest
- policy bundle digest
- recovery image digest
- supported migration paths
- minimum allowed version when rollback protection is enabled

The manifest is signed separately from the image.

## 10. Revocation

Revocation entries must support:

- exact JPN
- exact content digest
- signing key
- package coordinate
- version range
- policy capability
- whole release

Revocation must be monotonic unless an explicit superseding revocation record restores eligibility.
