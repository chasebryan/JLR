# JLR Trust Model

## 1. Principle

JLR does not equate "currently running" with "trusted". Trust is derived from evidence anchored **outside the mutable
component being evaluated**, and it is scoped, dated and revocable.

A hash is identity evidence, not intent. A signature is provenance evidence, not proof of safety. A sandbox constrains
authority; it does not prove harmlessness. A human approval is authority, not verification.

## 2. What is trusted, and why

Everything JLR trusts is listed here. Anything not listed is not trusted.

| Anchor | Why it is trusted | Where it lives | Status |
|---|---|---|---|
| **Trust anchors in the initramfs** (release public key) | They are the root of the boot decision; in the supervisor deployment they are inside the Secure-Boot-signed image | Initramfs | Implemented; not yet authenticated by firmware (prototype) |
| **Release key** | Signs release manifests; offline | Build machine | Implemented |
| **Policy key** | Signs policy, revocations, approvals, baselines | Ideally a separate device | Implemented; companion mode keeps it in the state directory |
| **Device key** | Signs ledger events and checkpoints; must be online | State directory | Implemented |
| **Root and recovery keys** | Authorise the others; used from recovery | Offline | Role defined; ceremony designed |
| **The kernel and its enforcement** | Namespaces, seccomp, Landlock and fanotify are only as sound as the kernel | Host or base | Assumed, with the tier of the claim reduced accordingly |
| **Cryptographic libraries** | `sha2`, `ed25519-dalek`, `getrandom` | Compiled in | Assumed correct; verified against RFC and Wycheproof-style vectors where practical |
| **An off-machine checkpoint** | Turns a self-consistent ledger into one known not to be rolled back | Operator's choice | Manual today |

**Not trusted:** the host's package database as proof of origin, mtimes as proof of no change, any path name, any file
the host can rewrite, the running system's report of its own integrity, and a person's wish for software to be safe.

## 3. Key roles

No single runtime process should hold all of these.

| Role | Signs | Compromise of it lets an attacker |
|---|---|---|
| Root | Authorisations of the other keys | Enrol any other key. Offline |
| Release | Boot manifests | Boot any image they build, but not below the rollback floor already raised on a machine |
| Policy | Policy, revocations, approvals, baselines | Admit software and change the rules. The highest-value online key |
| Recovery | Recovery authorisations | Authorise writes from the recovery context |
| Device | Events and checkpoints | Forge history from now on, but not rewrite what an off-machine checkpoint already commits to |

An envelope names its signer by key identifier, and the verifier accepts it only if that key is a trusted anchor **with a
role that record type permits** (`allowed_signers`). A device key cannot sign a release; a release key cannot sign
policy.

## 4. Self-verification

JLR measures its own files and state, but a mutable component that re-hashes itself is not an anchor. Therefore:

- the running system must not rewrite the expected value of the thing being measured and then declare it good;
- manifests change only through a path that authenticates the change (a signature under a permitted role, and an epoch
  that does not go backwards);
- a self-measurement failure must be visible in state and in the ledger;
- the verification that matters most (of the ledger, of the base) should be repeatable from a separate boot context.

The boot chain is the concrete form of this: the base image is checked against a signed manifest **before** it is used,
and stage 2 does not decide whether the image is trustworthy, only whether it is healthy.

## 5. The host

The host is not inherently trusted. An artifact on it is, at any moment, in one of eight states
(`UNKNOWN`, `QUARANTINED`, `OBSERVED`, `VERIFIED`, `ADMITTED`, `DEGRADED`, `REVOKED`, `POLICY_BLOCKED`), and the reasons for its
state are recorded with the evidence that caused it. JLR can let a degraded host boot under restrictive policy for data
recovery.

## 6. Provenance, ranked

Evidence quality is ranked, and policy can require more for more privilege. Smaller is stronger.

| Rank | Name | Meaning | What produces it today |
|---:|---|---|---|
| 1 | `REPRODUCED` | Locally rebuilt and reproducibly matched | Not yet |
| 2 | `PINNED_VENDOR` | Signature from a pinned trusted vendor key | Not yet (no vendor key store) |
| 3 | `DISTRO_SIGNED` | Signature from an approved repository, verified | Not yet (needs the managed-installer hook) |
| 4 | `VERIFIED_CHECKSUM` | Upstream checksum received over a trusted channel | Not yet |
| 5 | `SOURCE_KNOWN` | Source is known, nothing authenticates the bytes | dpkg ownership |
| 6 | `UNKNOWN` | Nothing is known | Everything else |

The built-in policies **cannot** admit on rank 5 or 6 by evidence alone, and the validator refuses any policy that
would. What admits package-managed software on a real machine today is an operator-signed **baseline**, which is an
explicit human statement recorded as such. That gap is honest, visible, and on the roadmap.

## 7. Human approval and baselines

Human authority is used and recorded as authority. The ledger distinguishes three bases for a state:

- `CRYPTOGRAPHIC`: a signature or a reproducible build satisfied policy;
- `POLICY`: rules were satisfied without a cryptographic anchor (for example an owned, matching, installer-verified file);
- `MANUAL_OVERRIDE`: a person authorised it despite incomplete evidence.

An approval is scoped (one EPN, a cell, a network mode, exact capabilities), signed under a role that may approve, bound
to this node, and expires. A baseline is the same idea for a set. Neither can lift a revocation or a policy prohibition,
and neither converts weak provenance into strong provenance: the weakness stays on the record beside the override.

## 8. Trust decays

Nothing is admitted forever.

- **Content change:** the old identity is degraded and the new bytes are unknown.
- **Revocation:** by EPN, content digest or signer; it wins over stale admission; it is terminal until a later signed record.
- **Expiry:** approvals and baselines carry an expiry and grant nothing after it.
- **Policy change:** a new policy epoch re-evaluates known artifacts on the next scan or exec.
- **Rollback:** an older validly signed policy, revocation list or release is refused once a newer epoch is recorded.

## 9. Ledger trust

The ledger is evidence, not authority. A signature chain shows the events were written by the device key in order. A
Merkle checkpoint commits to a prefix, so a verifier holding one can detect truncation and rewriting behind it. What no
on-machine mechanism can show is that the *whole directory* was not replaced by an older self-consistent copy; that needs a
checkpoint held elsewhere, or a hardware counter (designed). The software counter in a checkpoint says `Software`
because that is what it is.

## 10. Where the trust argument is weakest today

Stated so nobody has to discover it:

1. The initramfs is not yet authenticated by firmware, so a boot-media attacker who can replace it can replace the anchors.
2. The rollback floor lives on the boot media, so the same attacker can lower it.
3. In companion mode the policy key sits beside the engine.
4. dpkg's manifests are unauthenticated, which is why package-managed software is admitted by baseline, not by evidence.
5. Cells share the host kernel.

Each has a designed fix and a place in [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md).
