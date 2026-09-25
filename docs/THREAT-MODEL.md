# Threat model and assurance claims

**Status:** design target. Every guarantee below requires an implemented control and a passing adversarial test before release.

## Assets and adversaries

Protected assets are user files, viable backups, recovery keys, boot images, software admission policy, audit evidence, and the ability to boot a clean workload. Potential adversaries include a malicious user process, a compromised workload administrator or kernel, a hostile package/update, ransomware with workload-level authority, and a person who can write the shared internal disk. We also model accidental disk failure, corrupted updates, interrupted power, and a lost TPM. A malicious firmware/CPU or a physical attacker able to replace trusted boot keys is **outside initial prevention claims**; such events may still be investigated through independent backups or an external witness.

| Scenario | Required defense | What it cannot prove |
| --- | --- | --- |
| Workload user process encrypts files | VM-level disk/network controls where possible, versioned snapshots, and separate immutable backups | A broad authorized workload write grant may still permit damage before detection. |
| Workload kernel lies about processes | Treat guest-agent data as untrusted; compare only independently observable facts at the VM boundary | Block or network observations do not reveal all guest memory or kernel semantics. |
| Workload root writes JLR partition | Prevent direct assignment of JLR storage to guest; verify boot images; separate rescue media | A compromised JLR-S0 kernel, firmware, or hardware access can still modify local storage. |
| Bad JLR update | Signed A/B images with boot health gate and independently bootable rescue | A bad signed update can still be harmful; rollback needs an allowed version policy. |
| Shared SSD dies | Encrypted off-machine backup, tested recovery key path, independent boot medium | No local partition or second image on the same SSD can recover missing bits. |
| JLR-G userspace process is compromised | Isolation, minimal privileges, and evidence checkpointing; stop new key releases on failure | Other processes on the same kernel are not an independent root of trust. |
| TPM is replaced or inaccessible | Offline recovery factor plus separately held encrypted backup | TPM-only sealed keys cannot unlock on a different machine. |
| Backup repository or ledger is rolled back | Independently stored signed checkpoints and a monotonic version policy | A local hash chain without an external anchor can be replaced wholesale. |

## Explicit trust dependencies

1. The platform starts an expected boot artifact under an administratively controlled firmware trust policy. Secure Boot authenticates the boot chain as configured; it does not imply that runtime code, firmware, or data is safe.
2. The JLR-S0 kernel and VMM correctly enforce VM device boundaries. All in-kernel Guardian claims inherit this dependency.
3. Image signing keys are protected outside the workload, and their compromise has a documented revocation and recovery path.
4. The recovery image is copied to an independent boot medium and boot-tested on supported hardware. Its integrity and read-only handling of source volumes are tested.
5. Backups have a separate failure domain and do not depend solely on the compromised workload's credentials or on a single TPM.
6. Clocks may be untrustworthy. Replay prevention uses version/epoch checks and externally checkpointed evidence where possible; timestamps alone are not authority.

## What a measurement actually says

A matching hash proves that bytes match a committed digest; it does not establish benign behavior, complete observation, or correct policy. A Merkle root authenticates only objects under that root and only if the root itself is authenticated. JLR-SIR is a **scoped receipt** for an explicit inventory, not a universal proof of the whole machine. A gap in coverage is recorded as a gap, and absence of a report is not evidence that an event did not happen.

The state labels mean:

| State | Meaning | Allowed default action |
| --- | --- | --- |
| `PROVEN` | Required evidence for a **named operation and scope** is fresh and consistent with current policy | Grant a short-lived, scoped authority lease. |
| `DEGRADED` | Evidence is missing, stale, contradictory, or the observation plane is unhealthy | Deny new sensitive operations; collect evidence and preserve recoverability. |
| `ISOLATED` | Policy has deliberately fenced a cell or source volume | No normal execution or egress from the isolated scope; authorized export or recovery may proceed. |
| `RECOVERY` | Independent rescue image is active and workload is stopped | Inspection starts read-only; explicit authority is needed for writes. |

`PROVEN` never means “free of malware.” An `INTEGRITY_FRACTURE` is an event with evidence of an unauthorized transition or a failed required integrity check; a transient disagreement between sensors is `DEGRADED` until it is resolved. The event record contains the affected scope and the reason for the decision.

## Failure response

- **Single sensor fails:** mark only dependent claims stale; deny grants that require it; maintain a usable recovery channel.
- **Guest report and VM observation disagree:** preserve both reports and their observation windows; restrict the affected cell while reconciling ordering and instrumentation gaps.
- **JLR-S0 boot verification fails:** do not launch the workload; try an allowed, independently verified slot or enter recovery.
- **Runtime compromise of the JLR-S0 kernel is suspected:** local Guardian responses are no longer reliable. Stop issuing new keys, preserve externally anchored checkpoints, and require reboot into independent rescue or a separate trusted verifier.
- **Suspected ransomware:** fence affected write paths and egress if that control exists, preserve evidence and earlier snapshots, and restore only after reviewing the candidate point and affected objects.

No behavioral score alone destroys keys, deletes snapshots, or wipes the workload. Escalation requires named authority and an auditable action. Even a positive signature match must be interpreted in the context of what it covered.

## Assurance labels

Every build and status report must identify its assurance mode: `prototype` (QEMU evidence only), `companion` (workload-level), `supervisor` (JLR-S0 VM boundary), or `independent-recovery` (separately booted rescue). An implementation must not claim the next tier until the corresponding exit tests in [Implementation plan](IMPLEMENTATION-PLAN.md) pass. There is no “unhackable,” “always verified,” or “guaranteed recovery” tier.
