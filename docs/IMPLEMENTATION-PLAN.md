# Implementation plan and verification gates

**Status:** build plan. The repository contains documentation only; milestone results are not claimed.

## Order of work

Start with the simplest testable survival claim: an independently bootable, read-only rescue that can retrieve a file after the workload fails. Add supervision and runtime telemetry only after that boot and backup route works. All destructive tests use disposable QEMU disks until physical-hardware recovery has its own reviewed procedure.

| Milestone | Build artifact | Exit evidence |
| --- | --- | --- |
| **M0: design baseline** | Versioned architecture, threat model, explicit decisions | Documentation links resolve; all claims identify scope; a reviewer can trace each proposed assurance to a planned fault test. |
| **M1: bootable minimal substrate** | Pinned Woof-CE-derived recipe, stripped initrd/root, boot manifest, headless QEMU image | Clean reproducible build; signed-image acceptance and tampered-image rejection; runtime writes confined to specified ephemeral/persistent paths; bad boot does not start a workload. |
| **M2: standalone rescue** | External JLR-R image and read-only disk inspection/export tool | Boots with a broken workload bootloader and no network; copies known files to a separate destination with verified receipts; never writes source media in inspection mode. |
| **M3: redundancy and backups** | A/B selector/updater, encrypted vault, independent recovery-key path | Power-cut matrix leaves an allowed boot path; corrupted A/B forces external recovery; replacement VM restores test files from a secondary device without original TPM. |
| **M4: supervisor cell** | JLR-S0 runs one Linux workload guest under KVM with assigned virtual disk/network | Guest root cannot directly see/write JLR image, rescue, or vault; supervisor can fence the VM and its virtual NIC; failed S0 boot admission prevents guest startup. |
| **M5: evidence and authority** | EPN, scoped SIR/JIP receipts, ledger checkpoints, guest/supervisor telemetry and policy leases | Signed records verify, replay fails, missing sensors cause degraded state, mismatched guest claims produce auditable restrictions; missed-event rates and performance are measured. |
| **M6: recovery transaction** | Known-good workload rebuild and selective data restoration | An induced ransomware-like fixture cannot erase protected backups; clean base + reviewed data restore works; executable re-admission and rollback from a failed restore are demonstrated. |
| **M7: platform hardening** | Hardware-specific enrollment, secure boot policy, independent witness options | Repeat tests on each supported hardware profile; publish remaining assumptions and unsupported configurations. |

An optional companion agent can be built to prototype guest semantics, but it must retain the `companion` assurance label until protected by the supervisor boundary. Windows guests, hardware-passthrough devices, and live failover are separate future projects; none blocks the Linux/QEMU rescue proof.

## Proposed repository organization

```text
docs/             contracts, decisions, test reports
build/            pinned Woof-CE inputs, patch set, image recipes
boot/             selector, manifests, initrd configuration
supervisor/       Guardian, policy, VM and key broker services
guest/            untrusted semantic sensors and transport
recovery/         offline inspection, export and rebuild tools
protocol/         canonical schemas and signed test vectors
tests/            QEMU integration, property and fault tests
```

Directories other than `docs/` are a proposed shape, not existing implementations. Do not vendor a full Puppy tree without source provenance and a license inventory. Build automation records upstream commits, package hashes, compiler versions, image hashes, signing procedure, and reproducibility deltas. Release artifacts include a corresponding source offer and a tested rescue medium.

## M1 engineering checklist

1. Choose one upstream Woof-CE revision and one supported x86_64 UEFI/QEMU target. Record pinned fetches and patches; strip packages/services in the recipe, not by manual deletion of an opaque ISO.
2. Produce a boot image that authenticates the kernel, initrd, manifest, and read-only root. Decide signed whole-image digest versus dm-verity for the first iteration and document where the trusted root digest comes from.
3. Implement a minimal init state machine: verify → mount read-only → create ephemeral runtime → start only required services → either `READY` or `RECOVERY-RESTRICTED`.
4. Design the manifest's deterministic encoding and sign/verify vectors. Reject tampering, wrong role, unsupported version, missing pieces, malformed input, and a stale minimum epoch.
5. Test with QEMU boot logs and image digests; archive exact commands and results. Production assertions wait until the tests exist.

## M2 engineering checklist

1. Boot the rescue image with the internal guest disk omitted, then with a corrupt partition table or broken guest boot entry. There must be no dependency on normal host userspace.
2. Locate a test disk without trusting labels supplied by the workload. Expose source read-only at the block layer as well as the filesystem layer when supported.
3. Export selected files to a different writable target; verify content digests and report metadata that cannot be preserved.
4. Test locked-volume handling using an offline recovery factor. If keys are unavailable, explain exactly which files cannot be recovered instead of silently formatting or attempting repair.
5. Demonstrate the failure case of a dead shared disk and the success case with a secondary backup plus replacement disk.

## Security and usability gates for later milestones

- Every error path returns a typed denial/degraded outcome; parser crashes and sensor loss never grant access.
- State receipts identify coverage, missing observations, boot identity, and the key used to sign them.
- A/B tests simulate interruption before, during, and after writing inactive image and boot intent.
- Restore tests preserve evidence before replacing a workload and use disposable disks until explicitly authorized for real systems.
- Recovery UI gives an inventory and a precise destination before any operation that changes a source disk.
- Build reports quantify boot time, pulse cost, storage overhead, and false positive behavior; marketing claims use the measured configuration only.

## What is intentionally deferred

JLR will not initially attempt to decrypt and remap its own executing code on demand, assert complete guest-memory observation, infer malware from statistical behavior alone, or silently rewrite physical host disks. These features either expand the trusted computing base or require guarantees that a minimal supervisor cannot yet demonstrate. Reconsider them only with a threat analysis and an experiment that produces a stronger measurable outcome.
