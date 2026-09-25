# JLR Configuration and Cloning

JLR installations SHOULD be cloneable without cloning secrets or historical machine identity. A portable JLR configuration is a **signed profile bundle**; device identity, private keys, boot identity, and evidence history remain local unless explicitly migrated.

## Profile bundle

A bundle MAY contain schema version, profile name, policy epoch, admission defaults, jail profiles, capability rules, measurement targets, network defaults, recovery behavior, retention rules, update channels, minimum required enforcement features, and signer identity.

A portable bundle MUST NOT contain device-unique private keys by default.

## Conceptual profile

~~~text
profile:
  name: workstation-strict
  schema: 1
  policy_epoch: 17
admission:
  unknown: quarantine
  require_user_approval: true
  default_cell: CELL-0
runtime:
  supervisor_mode: ram
  fail_on_missing_enforcement: true
network:
  unknown_default: none
recovery:
  readonly_host_mount_default: true
~~~

Parsing and effective-policy calculation MUST be deterministic.

## Clone workflow

1. export signed non-secret profile bundle
2. install and verify JLR on target
3. generate new device identity and local keys
4. import profile
5. resolve hardware-specific grants
6. install/register host Linux
7. create fresh host baseline and evidence chain
8. optionally enroll independent checkpoints

## Never cloned automatically

Private signing keys, disk-encryption keys, TPM-sealed secrets, credentials, device identity, boot IDs, execution-instance IDs, ledger MAC/checkpoint secrets, and network credentials require explicit migration.

## Hardware adaptation

A cloned profile MUST NOT silently authorize a new machine's cameras, microphones, GPUs, SDRs, raw USB devices, removable storage, TPM, or other hardware.

## Effective policy

JLR SHOULD display the resolved policy digest, source bundle(s), local overrides, policy epoch, signer, required enforcement features, and missing enforcement features.

Import MUST fail or enter a clearly degraded mode when a mandatory control cannot be enforced.

A profile bundle plus a JLR release SHOULD produce the same effective-policy digest across compatible machines, excluding explicitly declared local fields.
