# JLR Architecture

## 1. Purpose

JLR is a security-governance layer whose primary job is to mediate trust between machine state, software artifacts, and the host operating system.

JLR is intentionally separated into a **governance plane** and a **host plane**.

The governance plane makes trust decisions. The host plane performs general-purpose work.

A host compromise must not automatically imply compromise of JLR's immutable boot artifacts, trusted manifests, recovery environment, or historical evidence.

## 2. Architectural layers

### Layer 0 — Platform anchors

Optional platform mechanisms:

- UEFI Secure Boot
- TPM 2.0 PCR measurements
- firmware write protection
- IOMMU
- hardware-backed keys
- read-only or physically removable recovery media

JLR must remain usable without every feature above, but it should use available hardware roots of trust when they are correctly configured.

### Layer 1 — Immutable loader

Responsibilities:

- locate and authenticate the JLR base image
- verify release manifest signatures
- measure the image before execution
- reject unauthorized downgrade when rollback protection is enabled
- select primary or recovery image
- emit boot measurements

The loader must be smaller and simpler than the environment it loads.

### Layer 2 — RAM-resident JLR base

A minimized read-only image is expanded into RAM.

The base contains only software required for:

- storage discovery
- cryptography
- integrity measurement
- policy evaluation
- sandbox orchestration
- event logging
- recovery
- essential operator interface

Package installation into the immutable base during normal operation is prohibited.

Mutable state is mounted separately.

### Layer 3 — Trust and policy engine

The Trust Engine consumes evidence and returns policy decisions.

Inputs include:

- artifact digests
- signed metadata
- provenance
- prior JPN record
- dependency identity
- runtime observations
- policy version
- user approval
- revocation information
- boot measurements

Outputs include:

- state classification
- allowed capabilities
- required isolation profile
- required user action
- revocation or degradation event
- evidence record

The Trust Engine must be deterministic for the same evidence set and policy version.

### Layer 4 — Measurement engine

The Measurement Engine continuously observes security-relevant state.

Required measurement targets include:

- JLR base image
- loader
- policy files
- trusted manifest database
- host kernel
- initramfs
- bootloader configuration
- executable files
- shared libraries
- service units
- privileged scripts
- package database
- critical configuration
- loaded kernel modules
- active processes
- network listeners

Measurement frequency may vary by target, but security-critical mutations should trigger event-driven remeasurement where the platform permits.

### Layer 5 — Admission controller

No newly discovered executable should silently become trusted.

The Admission Controller:

1. creates or resolves a JPN
2. validates identity and provenance
3. determines initial state
4. assigns an isolation profile
5. requests user approval when policy requires it
6. starts the workload through the jail fabric
7. collects execution evidence
8. promotes, degrades, or revokes state

### Layer 6 — Jail fabric

The jail fabric is a set of enforceable Linux isolation mechanisms, not a single container technology.

Preferred primitives:

- mount namespaces
- user namespaces
- PID namespaces
- network namespaces
- cgroup v2
- seccomp
- Linux capabilities
- Landlock where available
- read-only bind mounts
- tmpfs scratch space
- per-workload network policy
- device allowlists
- resource ceilings

A jail profile is attached to the JPN and policy decision.

### Layer 7 — Host adapter

The host adapter integrates JLR with the installed Linux distribution.

Responsibilities:

- identify host boot artifacts
- collect package metadata
- supervise host launch
- mediate admission hooks
- map host users and services to JLR policy identities
- expose status without permitting host-side policy forgery

The host adapter is considered less trusted than the core governance plane.

### Layer 8 — Recovery plane

Recovery is deliberately independent from normal host operation.

Recovery capabilities include:

- boot without mounting host filesystems read-write
- inspect JLR and host measurements
- validate manifests
- unlock encrypted storage with authorized credentials
- export files
- compare known-good snapshots
- restore selected artifacts
- reinstall boot components
- roll back a compromised host
- rebuild the JLR base from trusted media

## 3. Mutable state separation

JLR uses explicit storage classes:

- **IMMUTABLE** — base image, loader, release manifests
- **TRUSTED_MUTABLE** — policy database, approved JPN records, revocations
- **EVIDENCE** — append-only event and measurement log
- **CACHE** — reproducible derived data that can be discarded
- **HOST** — host operating system state
- **QUARANTINE** — untrusted artifacts awaiting decision

Cross-class writes must be explicit and policy checked.

## 4. Event model

Every security-relevant action emits an event:

~~~text
event_id
timestamp_monotonic
timestamp_wall
boot_id
actor
subject_jpn
event_type
old_state
new_state
policy_version
evidence_refs[]
decision
operator_identity
signature_or_mac
previous_event_digest
~~~

Event chaining detects deletion and reordering. Periodic checkpoints should be signed and, when available, sealed to TPM state or exported to independent storage.

## 5. Operator interface

The operator UI is not the root of trust.

It displays:

- current boot trust
- degraded components
- pending admissions
- quarantined software
- revoked software
- host integrity summary
- event timeline
- recovery actions

Sensitive actions must require explicit confirmation and must produce an event.

## 6. Failure behavior

JLR follows fail-closed behavior for privilege escalation and trust promotion.

Examples:

- missing signature -> no promotion
- unknown dependency -> remain restricted
- changed executable hash -> degrade or quarantine
- invalid policy signature -> refuse privileged host launch
- broken event chain -> mark evidence store degraded
- failed self-measurement -> enter recovery-oriented degraded mode

Availability decisions may be policy configurable, but the system must never convert missing evidence into positive trust.
