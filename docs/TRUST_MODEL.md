# JLR Trust Model

## 1. Principle

JLR does not equate "currently running" with "trusted."

Trust must be derived from evidence anchored outside the mutable component being evaluated.

## 2. Trust anchors

A deployment may use one or more of these anchors:

1. read-only installation media
2. immutable EFI system partition content
3. signed release manifest
4. offline root signing key
5. TPM-backed measured boot
6. hardware security token for operator approval
7. independently stored recovery image
8. reproducible build evidence

JLR should support a hierarchy in which compromise of one online key does not automatically authorize a new trusted base image.

## 3. Root and release keys

Recommended key separation:

- **Root key** — offline, long-lived, used to authorize release keys
- **Release key** — signs JLR releases and manifests
- **Policy key** — signs administrative policy
- **Recovery key** — authorizes recovery artifacts
- **Device key** — per-machine identity and event checkpointing

No single runtime process should possess all of these private keys.

## 4. Self-verification

JLR continuously measures its own files and runtime state.

However, self-measurement is only evidence when compared against an external trust anchor.

Therefore:

- the running system MUST NOT rewrite the expected hash of the component currently being measured and then declare the result trusted
- manifest updates MUST require an authenticated update path
- a self-measurement failure MUST be externally visible in state and logs
- recovery verification SHOULD occur from a separate boot context

## 5. Host trust

The host OS is not inherently trusted.

A host may be:

- verified and admitted
- verified but locally modified
- degraded
- quarantined
- unknown
- compromised

JLR may still allow a degraded host to boot under a restrictive profile for data recovery or forensic inspection.

## 6. Human approval

Human approval is authorization, not proof.

An operator may approve execution of software despite incomplete evidence, but JLR must preserve the distinction between:

- cryptographically verified
- policy-compliant
- manually permitted

The event record must show which basis was used.

## 7. Trust decay

Trust can expire.

JLR should support:

- signature expiry
- policy expiry
- revocation
- vulnerability-triggered degradation
- dependency changes
- host configuration drift
- elapsed-time revalidation

A previously admitted artifact is not permanently trusted.

## 8. Provenance

Evidence quality is ranked.

Example hierarchy:

1. locally rebuilt and reproducibly matched artifact
2. signature from a pinned trusted vendor key
3. distribution package signature from an approved repository
4. verified upstream checksum transported through a trusted channel
5. source-known but unsigned artifact
6. unknown origin

Policy can require stronger provenance for higher privileges.
