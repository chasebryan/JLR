# Key authority and protected data

**Status:** design requirements. Exact cryptographic algorithms, provider APIs, and test vectors remain M1 decisions; no key-management implementation exists.

## Separation of keys

JLR has at least four distinct authorities:

| Authority | Purpose | Where its secret belongs |
| --- | --- | --- |
| Image signer | Authorize JLR boot and release artifacts | Offline or separately controlled signing system; never inside a distributable image. |
| Administrative signer | Approve profiles, policy changes, and recovery writes | Operator-controlled device or quorum, separate from routine workload credentials. |
| Node identity | Authenticate one enrolled JLR instance and its evidence | Created per node in an appropriate hardware/protected key boundary when supported. |
| Data recovery authority | Unwrap encrypted backups after machine loss | Independent offline factor or quorum, tested on replacement hardware. |

A single node identity must not be enough to decrypt every archived snapshot forever. Compromise or loss of one authority must have a documented response: revoke, rotate, re-enroll, or recover. A TPM-sealed local key can be useful for unattended normal boot but cannot be the sole route to data stored off-machine.

## Backup envelope

For each protected backup set, generate a fresh high-entropy data encryption key (DEK) through a vetted cryptographic library. Encrypt chunks using a standard authenticated-encryption construction with nonce rules enforced by the chosen format. Authenticate chunk order, sizes, version, dataset identity, and manifest metadata; do not rely on encryption alone for replay or rollback detection. Wrap the DEK for authorized local use **and** for the separately governed recovery path. No plain DEK is written to the vault or source repository.

```text
Protected snapshot
  → authenticated encrypted chunks
  → signed manifest with chunk digests and dataset/epoch identity
  → wrapped DEK for node policy + wrapped DEK for offline recovery policy
  → independent backup destination and external ledger checkpoint
```

The manifest defines an exact snapshot boundary. A filesystem snapshot may be crash-consistent rather than application-consistent; guest quiescing and database-aware hooks require their own test. A successful decryption proves authenticity only under the encryption keys and metadata rules in force; it does not establish that the files are malware-free or that the snapshot captured a healthy application state.

## Key broker and policy

Key requests are bound to a node, role, cell, object, operation, policy digest, epoch, and expiry. JLR-G decides whether an action is authorized; the broker checks the decision at the point of key use and records a result. Ordinary workload code never receives image-signing keys, backup-wide master secrets, or raw recovery factors. Revoke a lease when a required integrity input becomes stale; do not assume that revocation erases copies of data already given to the guest.

Short lifetimes and memory clearing reduce exposure but do not make active keys invisible to a compromised supervisor kernel, DMA-capable device, swap, or dump path. Disable or protect swap and core dumps for key services, restrict debug access, and test crash behavior. Encrypting dormant modules in RAM is a research option, not a substitute for kernel isolation or a requirement of the initial design.

## Rotation and disaster cases

| Event | Required procedure |
| --- | --- |
| Local TPM state lost | Recover an off-machine backup with an independent factor on replacement hardware, generate new node keys, rewrap active data. |
| Node key suspected stolen | Revoke node identity, stop future key grants, re-enroll, rotate affected wrapping keys and access credentials. |
| Recovery factor lost | Use an already authorized alternate quorum/factor if enrolled; otherwise data may be permanently unavailable. Report this before allowing a deployment. |
| Recovery factor compromised | Suspend recovery grants, rotate/re-encrypt affected backup envelopes, revoke old recipient access and audit prior recovery use. |
| Signing key compromised | Stop accepting its new images/policies, distribute authenticated revocation or replacement through a separately established trust path, inspect existing deployments. |

No design can promise both recoverability and zero external key custody. Each deployment must select and test its recovery authority before protecting irreplaceable data. The first cryptographic implementation must publish format versions, algorithm choices, domain separation, nonce handling, signature test vectors, key import/export rules, and a restore drill; it must not invent new ciphers.
