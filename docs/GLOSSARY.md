# JLR Glossary

**Admission** — authorization for an identified artifact to execute with a defined capability set.

**Artifact** — a file, image, package, service definition, configuration object, firmware object, or other governed software/data object.

**Base image** — the immutable JLR operating image loaded into RAM.

**Capability** — a specific permission granted by JLR policy.

**Cell** — an isolated execution environment produced by the JLR jail fabric.

**Degraded** — a state indicating that previously valid trust evidence no longer fully matches current reality.

**Evidence** — an observed or externally authenticated fact used by policy.

**Governance plane** — JLR components that measure, classify, authorize, isolate, and recover.

**Host** — the general-purpose operating system governed by JLR.

**Immutable** — not writable during ordinary runtime; updates occur by authenticated replacement.

**Encryption Protocol Number (EPN)** — stable identifier for a versioned JLR security record.

**Jail fabric** — composition of kernel isolation and resource-control mechanisms used to enforce JLR capability policy.

**Manifest** — signed metadata binding a release to exact expected artifacts.

**Measurement** — cryptographic or structural observation of system state.

**Observation cell** — restrictive jail used to execute software while collecting behavior evidence.

**Policy** — signed rules mapping normalized evidence to state and allowed capabilities.

**Quarantine** — storage/execution state in which an artifact is prevented from ordinary host execution.

**Recovery plane** — independently bootable JLR environment used when normal host trust is unavailable.

**Revocation** — explicit invalidation of prior trust or admission.

**Root of trust** — a component or key accepted as an initial trust anchor rather than deriving trust from the mutable system being evaluated.

**Trust Engine** — deterministic JLR component that evaluates evidence under a specific policy version.
