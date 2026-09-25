# Configuration and Cloning

JLR installations should be cloneable **without cloning secrets or historical machine identity**. What is portable is a
*profile*: the rules. What is never portable is anything that identifies one machine or lets someone act as it.

## 1. What is a profile

A profile is a **policy**: the ordered tiers, the guards (setuid, writable-path and manual-grant ceilings), the
evidence age limit, the blocked classes and the exec-gate mode. It is authored as TOML, compiled to canonical CBOR,
validated, and signed under the **policy** role with scope `*`, meaning valid on any node that trusts the signing key.

```sh
jlr policy show > profile.toml         # on the source machine
$EDITOR profile.toml                   # optional; bump `epoch`
jlr policy set profile.toml            # on the target: compile, validate, sign with the target's policy key, install
```

Parsing and effective-policy calculation are deterministic. **The same TOML gives the same compiled policy and the same
digest on every machine and every build**; `jlr status` prints the digest, so two machines can be compared at a glance,
and a round trip through TOML is tested to be byte-identical.

## 2. What is node-scoped, and therefore not cloned

| Object | Scope | Why it stays local |
|---|---|---|
| Device key, policy key (companion mode) | This machine | Signing authority |
| Node identifier, boot ids, execution ids | This machine | Identity |
| Ledger and checkpoints | This machine | History cannot be inherited |
| Baselines | This node | They vouch for *this* machine's files |
| Approvals | This node | A grant for one artifact on one machine |
| Object store, index, caches | This machine | Derived from local measurement |
| Trust anchors | This machine | They decide whose signatures count here |

Approvals, baselines, events, checkpoints and EPN envelopes carry the node identifier in the signed context, so a valid one
copied to another machine **does not verify there**. A cloned machine must not silently authorise its new hardware's
devices, storage or network, and it does not: nothing device-specific is in a profile.

## 3. Clone workflow

1. Export the profile as TOML (above). It contains no key, no identity and no history.
2. Install and verify JLR on the target; run `jlr init`. This generates a **new** device identity and new keys.
3. Import the profile with `jlr policy set`. It must have a higher `epoch` than the fresh install's (1). It is compiled
   and validated; a profile the target cannot enforce, or one that breaks the safety rules, is **refused**, never
   partially applied.
4. Install or register the host; take a fresh inventory; enrol a fresh baseline; take a first checkpoint off the machine.

## 4. Effective policy and missing enforcement

`jlr status` shows the policy name, epoch and digest. `jlr doctor` shows which enforcement features this machine actually
has. A profile whose tiers assume a control the machine lacks is not silently weakened: cells built from it report the
unavailable controls, and mandatory controls refuse the launch.

## 5. Duplicate identities

Copying a state directory byte for byte after initialisation duplicates the node identifier, keys and ledger. Two machines
would then sign as one. This is a **duplicate identity incident**; both identities should be treated as untrusted until
re-enrolled. Detection is **designed, not built**: comparing checkpoints from the two machines shows a fork (two different
roots at the same size). Until an enrolment authority exists, do not clone state directories; clone profiles.

## 6. Fleet use (designed)

An organisation-wide policy signed by a key held centrally needs the machines to *trust that key as their policy
anchor*. `jlr init` currently generates a local policy key and does not accept an external one, so a portable, centrally
signed profile is not available yet. Roles with signed manifests (`S0`, `S1`, `R`, `F`, `V`, `DEV`) from the earlier draft
remain the model for what such an enrolment would bind: image digest, role, node identifier, minimum epoch, policy digest,
device assignments and backup destination, with revocation of a node or role that does not destroy encrypted backups.
