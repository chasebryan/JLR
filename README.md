# JLR

**JLR is a security-governance operating layer designed to sit beneath or beside a conventional Linux installation and continuously decide what the host is allowed to trust.**

JLR is not intended to be another general-purpose Linux distribution. Its purpose is narrower and more demanding: establish a small, auditable root of trust; measure software and configuration; isolate unverified workloads; record security-relevant state transitions; and remain independently bootable when the host system is damaged or compromised.

The current design uses a heavily reduced, remastered Puppy Linux lineage as the recovery and governance substrate because its RAM-oriented execution model, compact userspace, and remasterability are useful for building a small trusted environment. Puppy itself is not the security boundary. JLR's verification, policy, isolation, measurement, and recovery architecture is.

> **Design principle:** the host may fail. JLR must remain understandable, verifiable, and recoverable.

## What JLR is

JLR is designed around five roles:

1. **Pre-host trust layer** — JLR may be installed before the primary Linux distribution and retain control of the trusted boot and recovery path.
2. **RAM-resident governance environment** — critical policy, measurement, and decision components operate from a minimized read-only image expanded into RAM.
3. **Continuous integrity engine** — JLR measures files, packages, executables, services, policy, boot state, and its own immutable artifacts against signed manifests and known-good state.
4. **Software admission authority** — software begins untrusted, is analyzed and identified, then may be admitted into progressively less restrictive execution classes only after explicit policy and, where required, user approval.
5. **Independent recovery system** — if the host becomes unusable, JLR remains bootable and can inspect, export, repair, roll back, or restore host state without trusting the host runtime.

## The trust boundary

JLR does **not** claim that software can prove its own integrity from inside the same potentially compromised execution context. That would create circular trust.

Instead, JLR separates trust into independently verifiable anchors:

- read-only boot media or immutable boot partition
- signed manifests and release metadata
- reproducible or independently rebuildable artifacts where practical
- measured boot records
- optional TPM-backed measurements and key sealing
- immutable recovery images
- append-only security event records
- redundant known-good configurations

The running JLR instance continuously verifies itself against these anchors. A mismatch is a security event, not something the runtime is allowed to silently explain away.

## Core object: the JLR Protocol Record

Every governed artifact is assigned a **JLR Protocol Number (JPN)**.

A JPN identifies a versioned protocol record containing:

- cryptographic digests
- artifact type and provenance
- signer or source identity
- package/build metadata
- expected capabilities
- requested privileges
- dependency set
- filesystem access profile
- network policy
- executable ancestry
- sandbox profile
- verification evidence
- admission state
- policy version
- user approvals
- revocations and superseding records

The JPN is an identifier for a security protocol record; it is **not** itself encryption and must never be treated as a substitute for cryptographic verification.

## Security states

JLR uses explicit states instead of a binary trusted/untrusted flag:

| State | Meaning |
|---|---|
| UNKNOWN | Not yet classified or insufficient evidence |
| QUARANTINED | Present but denied normal execution |
| OBSERVED | May execute only inside a high-restriction observation cell |
| VERIFIED | Identity and required evidence match policy |
| ADMITTED | Explicitly permitted for a defined capability set |
| DEGRADED | Previously admitted, but one or more measurements no longer match |
| REVOKED | Explicitly denied by current policy |
| HOSTILE | Strong evidence indicates malicious or prohibited behavior |

A state transition is recorded with the evidence that caused it.

## High-level architecture

~~~text
Firmware / Secure Boot / TPM (optional)
                |
        JLR immutable loader
                |
       signed JLR base image
                |
      +---------+---------+
      |                   |
 Trust + Policy       Recovery Plane
 Engine               (independent)
      |
 Measurement Engine
      |
 Admission Controller
      |
 Isolation / Jail Fabric
      |
 Host Linux + Applications
~~~

The detailed architecture is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Documentation

- [Documentation index](docs/README.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Trust model](docs/TRUST_MODEL.md)
- [Integrity protocol and JPN format](docs/INTEGRITY_PROTOCOL.md)
- [Software admission lifecycle](docs/SOFTWARE_ADMISSION.md)
- [Isolation and jail model](docs/JAIL_MODEL.md)
- [Boot and installation model](docs/BOOT_INSTALLATION.md)
- [Recovery and redundancy](docs/RECOVERY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security invariants](docs/SECURITY_INVARIANTS.md)
- [Implementation roadmap](docs/IMPLEMENTATION_ROADMAP.md)
- [Glossary](docs/GLOSSARY.md)

## Status

JLR is currently a **design and documentation project**. The documents in this repository define intended properties and implementation requirements; they do not imply that those properties have already been implemented or independently audited.

The first implementation milestone is intentionally conservative: bootable minimal image, signed manifests, deterministic measurement, append-only event log, quarantine execution, and independent recovery. Advanced behavioral classification comes later.

## License

JLR is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
