# JLR Implementation Roadmap

The roadmap intentionally builds the smallest verifiable core before advanced automation.

## Phase 0 — Reproducible design baseline

Deliverables:

- documented build environment
- pinned dependency list
- minimal Puppy-derived image recipe
- software bill of materials
- signed release manifest format
- EPN schema
- event schema
- policy schema
- deterministic test fixtures

Exit criteria:

- two clean builds produce an explainable artifact difference report
- base image contents are enumerated
- no undocumented startup services

## Phase 1 — Bootable governance core

Deliverables:

- immutable JLR base image
- RAM boot
- A/B base slots
- recovery boot
- manifest verification
- offline root/release key workflow
- initial CLI status interface

Exit criteria:

- corrupted image is rejected
- invalid manifest is rejected
- fallback slot boots
- host is not required for JLR startup

## Phase 2 — Measurement engine

Deliverables:

- host boot measurement
- file/directory watchers
- package inventory
- process inventory
- EPN assignment
- evidence store
- hash-chained events

Exit criteria:

- mutation of a protected executable is detected and recorded
- event replay validates the chain
- evidence can be exported from recovery

## Phase 3 — Admission and quarantine

Deliverables:

- UNKNOWN/QUARANTINED/OBSERVED/VERIFIED/ADMITTED state machine
- quarantine storage
- explicit user approval flow
- deterministic policy engine
- capability model

Exit criteria:

- unknown executable cannot obtain normal host privileges without policy decision
- approvals are distinguishable from cryptographic verification

## Phase 4 — Jail fabric

Deliverables:

- namespace orchestration
- cgroup v2
- seccomp profiles
- filesystem isolation
- network isolation
- device policy
- observation telemetry

Exit criteria:

- test workloads cannot escape declared filesystem/network/process boundaries under supported kernel assumptions
- jail policy is reproducible from EPN record

## Phase 5 — JLR-first host installation

Deliverables:

- installer
- partition planner
- host installer handoff
- host boot registration
- measured host launch
- protected JLR partitions

Exit criteria:

- supported Linux host can be installed after JLR without overwriting JLR
- modified host boot set produces degraded state

## Phase 6 — Recovery maturity

Deliverables:

- snapshot comparison
- safe export
- known-good restore
- boot repair
- key rotation
- policy rollback
- evidence bundle generation

Exit criteria:

- recovery works with host unbootable
- recovery mounts host read-only by default
- destructive actions are explicit and logged

## Phase 7 — Advanced analysis

Possible later features:

- richer static analysis
- behavioral baselining
- anomaly scoring
- remote attestation
- reproducible package rebuilds
- VM-backed hostile analysis
- fleet policy distribution

These features must not weaken deterministic identity and policy fundamentals.

## Engineering priorities

1. correctness
2. clear failure state
3. minimal trusted code
4. recoverability
5. explainability
6. performance
7. convenience

## Minimum viable security release

A release should not call itself security-ready until it has:

- threat-model tests
- update rollback tests
- recovery tests
- key compromise procedure
- external code review
- documented unsupported platforms
- fuzzing for untrusted parsers
- reproducible build analysis
