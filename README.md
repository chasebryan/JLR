# JLR

**JLR is a proposed, Puppy-derived security governance operating system with an independently bootable recovery path.** Its long-term design places a small supervisory Linux environment between the machine's boot chain and a user-facing operating system. JLR measures admitted software, governs authority, records evidence, preserves recoverable snapshots, and can start its own rescue environment when the user-facing OS cannot boot.

> **Status: documentation and architecture only.** This repository currently contains no JLR boot image, enforcement agent, recovery program, or validated security implementation. The specifications below describe intended behavior and explicit test gates, not a claim that a machine is already protected.

## The essential promise

The user-facing OS may be damaged, encrypted by an attacker, or unable to boot. JLR must still have an independently bootable, verified route to inspect its storage, authenticate backups, and recover accessible files. Recovery from a failed physical disk additionally requires a copy on another device and a recovery key path that survives loss of that machine.

JLR is built from a **heavily reduced Puppy Linux/Woof-CE lineage**: a reproducible build, a small RAM-oriented Linux userland, verified read-only system images, and an ephemeral writable runtime. It has no normal desktop, login shell, or persistent Puppy savefile in production. The actual source and license inventory must be recorded before an image is released.

## Deployment modes

| Mode | Placement | What it can honestly claim |
| --- | --- | --- |
| Development companion | Agent running in an ordinary Linux host | Telemetry, prototype policy decisions, backup coordination; host root can subvert it. |
| JLR-S0 supervisor (target) | Boots first as the Linux supervisor; the user-facing OS runs as a managed workload, initially a KVM guest | Controls exposed virtual disks, network, and boot admission under the JLR-S0 kernel. A compromised supervisor kernel still defeats its in-kernel protection. |
| JLR-R recovery | Signed boot image on an independent medium, with optional local A/B copies | Can run without the user-facing OS or its bootloader and inspect host storage read-only. Local copies alone do not survive loss of the disk. |

S0 is a small supervisory **OS**, not an ordinary subprocess of the workload. A Linux guest is the first target; other guest OSes require separate integration work. An external witness or separately isolated Guardian is a future trust boundary, not a property of two processes sharing one kernel.

## Components

| Name | Responsibility |
| --- | --- |
| **JLR-S0** | Minimal Puppy-derived boot substrate and supervisor. |
| **JLR-G** | Verification and policy decision service; independence is qualified by its actual isolation. |
| **JLR-RIME** | Event intake, measurement, and reconciliation of guest and supervisor observations. |
| **JLR-CELL** | Managed workload boundary, initially a virtual machine. |
| **JLR-EPN** | Versioned admission record linking an artifact digest to provenance, dependencies, and policy. The expansion of “EPN” remains undecided. |
| **JLR-SIR** | Scoped system integrity receipt and digest for one observed state and epoch. |
| **JLR-XVD** | Cross-view comparison of in-guest reports with supervisor observations. |
| **JLR-PURIFY** | Controlled isolation, reinstallation, and data restoration workflow. |
| **JLR-R** | Standalone recovery boot image. |

## Documentation

1. [Architecture](docs/ARCHITECTURE.md) — placement, boundaries, components, and invariants.
2. [Threat model](docs/THREAT-MODEL.md) — attackers, assumptions, and honest limits.
3. [Boot and recovery](docs/BOOT-AND-RECOVERY.md) — A/B images, independent rescue, backup, and restoration.
4. [State and protocols](docs/STATE-AND-PROTOCOLS.md) — manifests, EPN, SIR, pulse receipts, and state transitions.
5. [Configurations](docs/CONFIGURATIONS.md) — cloneable roles and separate machine identities.
6. [Keys and data](docs/KEYS-AND-DATA.md) — encryption, key separation, and disaster recovery.
7. [Implementation plan](docs/IMPLEMENTATION-PLAN.md) — development phases and observable exit criteria.
8. [References and decisions](docs/REFERENCES-AND-DECISIONS.md) — upstream mechanisms, settled choices, and questions requiring experiments.

## First engineering target

Build a reproducible, headless, Puppy-derived image that boots under QEMU, verifies a signed manifest before mounting its read-only core, writes runtime data only to a disposable area, and enters a bounded recovery state when verification fails. The same image family must also boot directly as a rescue image with the guest powered off and mount a test guest disk read-only. **No host installation or automatic disk repair belongs in this first target.**

For concrete tests and sequencing, see [Implementation plan](docs/IMPLEMENTATION-PLAN.md).

## Security language

An artifact hash proves equality to a chosen digest, not that the artifact is safe. A signed boot image establishes a chain to a trusted signer, not that firmware or runtime memory is uncompromised. A snapshot is recoverable only when its contents, keys, and independent copy have been checked by a restore drill. JLR reports the scope and freshness of evidence instead of claiming absolute machine integrity.

## License

The JLR repository is licensed under [AGPL-3.0](LICENSE). A Puppy-derived distribution will need its own complete attribution, corresponding source, and per-component license review before release.
