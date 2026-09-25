# Recovery and Redundancy

## 1. Objective

JLR must remain useful when the host is broken, compromised or unbootable. Recovery is not a menu inside the host; it is an
**independently bootable security context** that does not execute the host's software.

Recovery has two jobs that must not be confused: getting **files** back, which works even when restoring a whole system is
inappropriate, and rebuilding a **system**, which needs a known-good base, fresh admission of anything executable, and
rotation of exposed secrets. Recovered data is untrusted input until validated for its use; a restored executable needs fresh
admission; being able to decrypt data proves nothing about whether it is authentic or clean.

## 2. Status

| Capability | Status |
|---|---|
| Independent boot path that runs nothing from the host (RAM-resident, signed base) | Implemented |
| A/B slots; fallback when the active slot is corrupt; refusal when none verifies | Implemented, tested under QEMU |
| Ledger verification from any JLR environment, against an off-machine checkpoint | Implemented (`jlr ledger verify --checkpoint`) |
| Signed policy, revocation and boot-state handling that refuses rollback | Implemented |
| Read-only inspection of host storage; safe export with receipts | **Designed** |
| Snapshot comparison, known-good restore, boot repair | **Designed** |
| Encrypted, versioned backups with an independent recovery key | **Designed** |
| Recovery-context key rotation; recovery authorizations | **Designed** (the `recovery` role and record type exist) |
| A recovery image for graphical use | **Designed**; a separate decision, see [BOOT_INSTALLATION.md](BOOT_INSTALLATION.md) section 8 |

No document should claim recovery works for a scenario that is not in the drill table below with a passing result.

## 3. Roles and failure domains

| Role | Location | Failure domain |
|---|---|---|
| `JLR-A` / `JLR-B` | Two signed local boot slots | Same disk and firmware path |
| Recovery media | A separate, removable, signed image | Survives loss of the internal disk |
| Backup vault | Encrypted, versioned store on another device or off-machine | Needs credentials and retention the ordinary workload does not have |

A/B failover is an authenticated **reboot into a different slot**, never a live handoff of compromised RAM state. A second
copy on the same disk shares the disk's failure domain, and a second process on the same kernel shares the kernel's; neither is an
independent verifier.

## 4. Recovery startup (designed, on the implemented boot chain)

1. Verify the environment's own signed manifest (**implemented**).
2. Start without trusting any host executable (**implemented**: the base is RAM-resident and the media is released).
3. Enumerate storage without executing anything from a damaged volume; mount host storage **read-only**, at the block layer
   as well where supported, and do not replay a journal or run a repair tool against the source merely to inspect it (I-18).
4. Verify the JLR evidence history and any off-machine checkpoint.
5. Show the last known host trust state, then offer explicit operations.

## 5. Operations

Required: inspect file hashes; inspect EPN records; verify package signatures; compare snapshots; copy user data to external
media; restore known-good files; restore bootloader configuration; roll back a JLR slot; rebuild host boot metadata;
quarantine suspicious files; export an evidence bundle.

Optional: reinstall host packages from trusted media; verify a file system offline; rotate device keys; revoke compromised
policy keys; reseal to a TPM.

**Before any destructive step:** identify the target, show the expected effects, offer a backup or export, record the
operator's action in the ledger, and verify the write. No silent repair, and no automatic destructive action from an
anomaly score.

## 6. Keys and data survival

The design requirement is that **the backup and the unlock path must survive the same failure being claimed**.

| Authority | Purpose | Where its secret belongs |
|---|---|---|
| Image signer | Release and boot artifacts | Offline; never inside a distributable image |
| Administrative (policy) signer | Policy, approvals, recovery writes | An operator device or quorum, separate from routine credentials |
| Node identity | One installation's events and checkpoints | Created per node; hardware-bound where supported |
| Data-recovery authority | Unwrap backups after machine loss | An offline factor or quorum, tested on replacement hardware |

A single node identity must not be able to decrypt every archived snapshot forever. A TPM-sealed key is fine for unattended
boot but cannot be the only route to data stored off the machine.

**Backup envelope (designed).** Each backup set has a fresh data-encryption key from a vetted library; chunks use a standard
authenticated-encryption construction with enforced nonce rules; chunk order, sizes, version, dataset identity and manifest
metadata are authenticated (encryption alone does not detect replay or rollback); the key is wrapped once for the node's
policy and once for the offline recovery policy; the signed manifest carries chunk digests and the dataset epoch; and the
whole thing is written to an independent destination together with an off-machine ledger checkpoint. No plain key ever
touches the vault, the repository or an image.

| Event | Required procedure |
|---|---|
| Local TPM state lost | Recover an off-machine backup with the independent factor on replacement hardware, generate new node keys, re-wrap active data |
| Node key suspected stolen | Revoke the node identity, stop future key grants, re-enrol, rotate wrapping keys and access credentials |
| Recovery factor lost | Use an already-enrolled alternate factor; otherwise the data may be permanently unavailable, which must be reported **before** a deployment is accepted |
| Recovery factor compromised | Suspend grants, re-encrypt affected envelopes, revoke the old recipient, audit prior use |
| Signing key compromised | Stop accepting its releases and policies; distribute an authenticated replacement over a separately established path; inspect existing deployments |

No design can promise both recoverability and zero external key custody. Choose and test the recovery authority before
protecting irreplaceable data.

## 7. Recovery-context rules

- Never copy a file from a compromised host into JLR's immutable base to make recovery convenient.
- Host tools run only under explicit quarantine or recovery policy, in a cell.
- Recovery mounts host storage read-only by default; any write is an explicit, logged recovery action authorised by a
  recovery-role signature or a deliberate local action with an independent factor.
- A headless machine may use a pre-signed, narrowly scoped recovery policy that includes a preview, a receipt and an escape
  path.

## 8. Drills

Each drill is run against disposable disks first. Only drills with a passing result may appear as achieved recovery claims.

| Fault injected | Expected outcome | Result today |
|---|---|---|
| Corrupt the active slot's image | Verified alternate slot boots; corrupt slot marked bad | **Passes** (QEMU: `a_broken_update_falls_back_to_the_proven_slot`) |
| Corrupt every local slot | Boot refuses; nothing from the media runs; recovery media is the fallback | **Passes** (QEMU: tampered/truncated image, no bootable slot) |
| Power cut during boot of an unproven slot | A try was already spent; at least one signed path remains | Logic covered by property tests; a real power-cut matrix is **not yet run** |
| Delete the host's kernel and bootloader | Recovery boots, identifies and exports a known file | Designed |
| Erase the internal disk | Recovery media + separate backup + recovery factor rebuild a file on a new disk | Designed |
| Lose TPM state | An offline factor unlocks the backup on replacement hardware, or the inability is documented | Designed |
| Tamper with a backup or replay an older checkpoint | Verification fails or reports a rollback gap; no silent restore | Ledger half **passes** (`checkpoints_detect_rollback_of_the_whole_state_directory`); backup half designed |
| Restore a snapshot that contains a malicious executable | The executable is quarantined pending fresh admission, not run | Designed |
| Installed slot's release is older than the floor | Refused as a rollback | **Passes** (QEMU) |
