# Cloneable images and role configurations

**Status:** design target. No installable images or enrollments exist yet.

## One build lineage, several roles

JLR is cloned through reproducible image artifacts and **signed role manifests**, not by copying a configured installation. A common build can contain only the capabilities required by a given role; role manifests control policy and service admission but cannot create capabilities that are absent from or forbidden by the image. Boot policy binds the image digest, allowed role, node identity, and a version floor.

| Role | Allowed main action | Persistent storage authority | Human interface |
| --- | --- | --- | --- |
| `S0` supervisor | Start/stop guest, govern virtual devices, record evidence, make backups | Dedicated ledger and snapshot interfaces | Status and signed administrative requests. |
| `S1` standby | Serve as next verified local boot candidate | Inactive image slot only through updater | None. |
| `R` recovery | Read damaged source and export files; restore only after authorization | Separate export target; write access gated | Minimal local recovery workflow, or pre-signed headless policy. |
| `F` forensic | Acquire and verify an image without source writes | Evidence destination only | Limited acquisition workflow. |
| `V` backup vault | Receive encrypted snapshots/checkpoints, enforce retention | Vault store only | Separate authenticated administration. |
| `DEV` experimental | Exercise instrumentation and fault cases | Disposable test volumes | Developer logs and console. |

`S1` is a standby **image role**, not a concurrently trusted clone of `S0`. `V` on the same SSD is not off-machine redundancy. The role name describes intent; actual isolation and media location determine the security property.

## Enrollment

1. Build an image from pinned sources and publish its content digest, SBOM/license inventory, build recipe, and signature. The same signed build may be staged to many machines.
2. On first boot, verify the image and authorize enrollment using an operator-controlled bootstrap method. Generate a **new node identity** inside the intended key boundary; do not embed node private keys in a golden image.
3. Bind the node identifier, hardware reference where available, selected role, minimum image version, policy digest, device assignments, and backup destination to a signed manifest.
4. Prove possession of the node key to the enrollment authority and save a verifiable receipt. Establish independent data-recovery authorization before real files are entrusted to JLR.
5. Reject reused node identities, unknown role versions, missing signers, replayed enrollments, and downgrade attempts.

An installation copied byte-for-byte after enrollment is a **duplicate identity incident**. On detecting one, quarantine both identities until rotated and re-enrolled. Storage, policy, and ledger encryption contexts are per node and per role where appropriate. No clone receives another node's plaintext keys simply because it has the same core image.

## Illustrative role intent

```json
{
  "format_version": 1,
  "role": "S0",
  "node_id": "example-node",
  "image_digest": "sha256:...",
  "policy_digest": "sha256:...",
  "min_image_epoch": 12,
  "cell_ids": ["cell.alpha"],
  "devices": ["virtual-disk.alpha", "virtual-nic.alpha"],
  "backup_destination_id": "vault.beta",
  "recovery_authority_id": "offline-group.gamma"
}
```

This is a field sketch, not a valid signed manifest. Final encoding, validation, signer chains, and policy schema are specified and tested at M1. Profiles are *not* mutable plaintext configuration files on the workload disk.

## Operator changes

Administration sends a signed intent with requested operation, target node/role, expected current policy digest, expiration, nonce, and authority proof. JLR rejects intents for a different role, stale version, reused nonce, or policy conflict. Emergency access is a separate recovery state with a physical or offline factor and a bounded operation. The production S0 image has no routinely exposed login shell or SSH daemon.

Role and node revocation must invalidate subsequent key release and future image admission without destroying stored encrypted backups. Revocation instructions and recovery-key escrow cannot depend on the damaged workload being able to boot.
