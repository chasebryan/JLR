# Upstream references and design decisions

**Status:** researched architecture choices, not evidence of a working build. Upstream mechanisms provide ingredients; JLR-specific assurance requires its own configuration and tests.

## Primary references

| Mechanism | Primary documentation | Why it matters to JLR |
| --- | --- | --- |
| Puppy build lineage | [Woof-CE source](https://github.com/puppylinux-woof-CE/woof-CE), [initrd notes](https://github.com/puppylinux-woof-CE/woof-CE/blob/testing/initrd-progs/0initrd/README.txt) | Construction inputs and RAM-oriented boot/SFS layering to adapt and substantially reduce. |
| Read-only block verification | [Linux dm-verity](https://docs.kernel.org/admin-guide/device-mapper/verity.html) | Merkle-verified block reads if the root digest is authenticated by JLR's boot chain. |
| Read-only file verification | [Linux fs-verity](https://docs.kernel.org/filesystems/fsverity.html) | Per-file Merkle verification for supported filesystems; not a substitute for boot verification. |
| Device mapper measurement | [Linux dm-ima](https://docs.kernel.org/admin-guide/device-mapper/dm-ima.html) | Candidate measurement input; policy and actual enforcement must be specified separately. |
| Virtualization boundary | [Linux KVM API](https://docs.kernel.org/virt/kvm/api.html), [QEMU system emulation](https://www.qemu.org/docs/master/system/index.html) | Initial workload cell and reproducible fault-test harness. |
| QEMU disk snapshots | [QEMU disk images](https://www.qemu.org/docs/master/system/images) | Development fixtures; a VM snapshot is not an off-machine backup. |

Upstream revisions, exact code paths, licenses, kernel configurations, and tested combinations belong in a future pinned build manifest. External links here do not assert that JLR has adopted or correctly configured any particular feature.

## Decisions fixed for the first implementation

| ID | Decision | Reason / consequence |
| --- | --- | --- |
| D-01 | x86_64 UEFI/QEMU and one Linux workload first | Makes boot and recovery falsifiable on a controlled target. |
| D-02 | Use a pinned, modified Woof-CE build lineage | Keeps the proposed Puppy-derived construction traceable. |
| D-03 | Headless, non-interactive S0; separate bounded recovery interface | Reduces routine privileged interaction while retaining a viable rescue path. |
| D-04 | Recovery starts read-only and boots from separate media | Does not rely on the compromised workload or shared disk. |
| D-05 | A/B boot slots are reboot failover, not independent concurrent Guardians | Same-kernel and same-disk clones share failure modes. |
| D-06 | Role manifests are signed; node identities are created on enrollment | Prevents cloned instances from sharing private keys by default. |
| D-07 | SIR and JIP explicitly report scope and missing observations | Prevents a partial hash from being described as universal machine proof. |
| D-08 | No destructive automatic purification from anomaly scores | Preserves user data and demands auditable authority. |
| D-09 | Off-machine encrypted backup and non-TPM-only recovery factor | Permits recovery after shared disk or TPM loss. |

## Decisions requiring experiments or operator policy

| ID | Question | Required evidence before fixing it |
| --- | --- | --- |
| O-01 | Which Woof-CE revision, base packages, and kernel config? | Reproducible boot and per-package source/license inventory. |
| O-02 | Signed whole-image verification, dm-verity, or both? | Chain from trusted boot key to root digest, tamper tests, boot-time and size measurements. |
| O-03 | What exact canonical encoding, hashes, signatures, and key rotation? | Public schema, test vectors, parser fuzzing, and algorithm migration design. |
| O-04 | Where do backup, boot, checkpoint, and recovery authorities live? | Lost-key, compromised-key, and replacement-machine restore drills. |
| O-05 | Which guest agent or kernel hooks are worth their attack surface? | Event completeness and missed-event measurements under adversarial load. |
| O-06 | How will device passthrough and DMA be bounded? | Platform IOMMU/device mapping audit and negative tests. |
| O-07 | Which filesystem and snapshot mechanism backs guest disks? | Consistent backup, corruption, rollback, and restore tests. |
| O-08 | How is an external Guardian or witness isolated? | Demonstrated separation from the S0 kernel and authenticated checkpoint exchange. |
| O-09 | How are emergency recovery and quorum authorized offline? | An operator exercise on an offline and replacement machine. |
| O-10 | What does EPN stand for? | Adopt one expansion when the admission schema is stable; keep the identifier semantics consistent. |

Any claim of “Puppy-derived,” “verified,” “self-protecting,” or “recoverable” in a release must name the relevant build provenance, trust boundary, and passed test. Changing a decision requires updating the affected docs and recording the rationale alongside the implementation.
