# JLR Recovery and Redundancy

## 1. Objective

JLR must remain useful when the host is broken, compromised, or unbootable.

Recovery is not a menu option inside the host. It is an independently bootable security context.

## 2. Recovery sources

A deployment should maintain at least two of:

- local immutable recovery partition
- removable recovery media
- second internal JLR base slot
- offline image stored on another machine
- network recovery image with authenticated boot

## 3. Recovery startup

Recovery should:

1. verify its own signed manifest
2. start without trusting host executables
3. mount host storage read-only
4. verify JLR evidence history
5. display last known host trust state
6. offer explicit recovery operations

## 4. Recovery operations

Required operations:

- inspect file hashes
- inspect EPN records
- verify package signatures
- compare snapshots
- copy user data to external media
- restore known-good files
- restore bootloader configuration
- roll back JLR base slot
- rebuild host boot metadata
- quarantine suspicious files
- export evidence bundle

Optional operations:

- reinstall host packages from trusted media
- verify filesystem offline
- rotate device keys
- revoke compromised policy keys
- perform TPM resealing

## 5. File preservation

Recovery should prioritize data preservation.

Before destructive repair:

- identify target
- show expected effects
- offer backup/export
- record operator action
- verify write result

## 6. Snapshot strategy

JLR may maintain:

- base image snapshots
- policy snapshots
- host boot snapshots
- critical configuration snapshots
- optional host filesystem snapshots

Snapshot metadata must include content hashes and parent relationship.

## 7. Catastrophic host failure

If the host fails completely, JLR should still be able to:

- boot
- identify disks
- unlock authorized storage
- mount data read-only
- export user files
- wipe/reinstall host partitions
- preserve JLR evidence and keys

## 8. Catastrophic JLR failure

If the active JLR slot fails:

- boot alternate slot
- verify manifest
- compare failed slot
- preserve failure evidence
- repair or replace failed slot

If all internal JLR slots fail, external recovery media is the final root.

## 9. Recovery trust rule

Never copy a file from a compromised host into JLR's immutable base merely because it is required to make recovery convenient.

Host tools may be executed only under explicit quarantine/recovery policy.
