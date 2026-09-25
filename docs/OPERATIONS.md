# Operating JLR

This is the runbook for the **companion** deployment: JLR running beside an ordinary Linux host. The verified-boot
deployment is described in [BOOT_INSTALLATION.md](BOOT_INSTALLATION.md).

Everything below has been exercised on a real machine (Linux Mint 22.3, kernel 7.0) and, for the parts that need
root, inside a QEMU/KVM guest. Where a step is a manual workaround for a feature that is not built yet, it says so.

## 1. Before you start

```sh
jlr doctor
```

`doctor` launches a real test cell and prints every kernel control as `active`, `UNAVAILABLE (reason)` or
`not requested`. Read it. A control shown as unavailable is a control you do not have. Typical findings:

| Finding | Meaning | What to do |
|---|---|---|
| `cgroup UNAVAILABLE (memory.max: Permission denied)` | The session has no delegated cgroup, so memory and process ceilings cannot be set | Run the daemon as a system service, or accept `Partial` enforcement. Reports say so. |
| `mount-ns` or `user-ns` unavailable | Unprivileged user namespaces are blocked | On Ubuntu 24.04 set `kernel.apparmor_restrict_unprivileged_userns=0`, or run jlr as root |
| `landlock NOT present` | Kernel lacks Landlock | Cells run without the write-confinement layer; the mount namespace still applies |
| `TPM 2.0 no device`, `Secure Boot disabled` | No hardware anchor | Ledger checkpoints are software counters only; say so in your own risk notes |

## 2. Initialise

```sh
jlr init                 # workstation policy: silent for managed software, observation for the rest
jlr init --strict        # quarantine anything without strong evidence and ask
```

This creates the state directory (`$JLR_STATE`, `/var/lib/jlr` as root, else `~/.local/state/jlr`) with mode 0700:
a **device key**, a **policy key**, the trust anchors, a signed policy, an empty signed revocation list and the
ledger. `init` prints two reminders that matter:

1. **The policy key can approve software and replace policy.** In companion mode it sits beside the engine, so anything
   that can read the state directory can use it. Move `keys/policy.jlrkey` to a separate device and load it only when
   you change policy or approve something.
2. **Store a ledger checkpoint off this machine.** Without one, an attacker who can rewrite the whole state directory can
   roll it back and nothing will notice.

```sh
jlr ledger checkpoint --out /media/usb/jlr-checkpoint-$(date +%F).cose
```

## 3. Take the first inventory

```sh
jlr scan /usr /opt                         # measures governed files; idempotent and incremental
jlr status
```

On a Debian-family host every file owned by an installed package is recorded with provenance `SOURCE_KNOWN` and the
evidence `MANAGED_INSTALLER` plus `PACKAGE_MANIFEST_MATCH` when its bytes match dpkg's manifest. That manifest lives on
the host disk and is not authenticated, so this is *evidence of consistency*, not proof of origin. Until
verification against an apt-signed transaction exists ([roadmap](IMPLEMENTATION_ROADMAP.md), managed-installer hook),
package-managed software becomes trusted by an **operator statement**, not by JLR:

```sh
jlr baseline enroll /usr /opt              # only files dpkg vouches for AND that match its manifest
jlr baseline enroll /usr --include-unmanaged   # installer mode: trust what is on disk now
```

Baseline members are recorded in the ledger as **manual overrides**. That is the honest label: the operator is
vouching for the initial state. Do this immediately after a clean installation, ideally before the machine touches
untrusted networks, and keep the resulting checkpoint.

Setuid binaries (`sudo`, `passwd`, `mount`, ...) are quarantined by default because their origin evidence is too weak
for the privilege they carry; enrolling them in a baseline is the operator accepting that.

## 4. Audit first, then enforce

The exec gate has two modes, chosen by the signed policy:

| Mode | Behaviour |
|---|---|
| **audit** (default) | Records what it *would* deny. Nothing is blocked. |
| **enforce** | Denies `exec` of anything whose decision is not `VERIFIED` or `ADMITTED`. |

```sh
sudo jlrd --state /var/lib/jlr &           # or install contrib/jlrd.service
jlr ledger log -n 100 | grep 'exec gate'   # what would have been blocked?
```

Run in audit mode for as long as it takes to be confident. Then:

```sh
jlr policy enforce on                      # a new signed policy epoch, logged; jlrd notices immediately
jlr policy enforce off                     # the way back
```

Programs that are blocked are not gone. Run them confined:

```sh
jlr run ~/Downloads/tool --flag            # measured, sealed, run in CELL-0: no network, no home, no devices
jlr explain ~/Downloads/tool               # why, with the evidence
jlr approve EPN-1-EXE-... --cell CELL-1 --cap FS_READ:/home/me/data --ttl-hours 24
```

`approve` produces a signed, expiring, scoped approval, and the ledger records it as a manual override. It cannot lift a
revocation or a policy prohibition.

## 5. Day to day

Nothing. `jlrd` re-measures governed files in the background (default hourly, in small slices) and the gate answers
known files from a cache. `jlr status` shows the posture:

```text
assurance   companion   (what this report can honestly claim)
posture     PROVEN   scope: ledger, policy, keys and 2271 known artifacts
exec gate   audit (records what it would deny; nothing is blocked)
```

`PROVEN` is always scoped to the named things; it never means "free of malware". It turns `DEGRADED` when an artifact that
was trusted changes, or when the ledger had to quarantine an incomplete record at start.

## 6. Software updates

Until the package-manager hook exists, an update makes the new files unknown to JLR. The safe routine is:

```sh
sudo apt upgrade                           # with the gate in audit mode, or `jlr policy enforce off` first
jlr scan /usr                              # new files become OBSERVED; changed files degrade their old identity
jlr baseline enroll /usr --name after-upgrade   # your statement that the upgrade was yours
```

Do not enable enforcement on a machine that updates unattended until the hook lands; a maintainer script that runs a
new binary would be denied.

## 7. Revocation

```sh
jlr revoke --digest sha256:<hex> --reason "CVE-..."      # every artifact with these bytes, everywhere
jlr revoke --signer vendor-a --reason "key compromised"
jlr revoke --epn EPN-1-EXE-... --reason "..."
```

A revocation list is signed and has an epoch that may never go backwards. Revocation wins over stale admission,
baselines and approvals. Revoked is terminal until a later signed record supersedes it.

## 8. Policy

```sh
jlr policy show > policy.toml              # the active policy as TOML
$EDITOR policy.toml                        # bump `epoch`, change tiers
jlr policy set policy.toml                 # compile, validate, sign, install
```

TOML is only an authoring format. It is compiled to canonical CBOR, validated against structural safety rules and
signed; the engine loads only the signed form. Policies that would silently admit unknown software, admit on weak
provenance, or grant privileged cells without strong evidence are **refused at compile time**. A policy whose
signature does not verify at start stops the engine; it is never replaced by a default.

## 9. The ledger

```sh
jlr ledger verify                          # every signature, link and checkpoint
jlr ledger verify --checkpoint FILE        # also against a checkpoint you kept elsewhere
jlr ledger log -n 50
jlr ledger checkpoint --out FILE
```

What each check proves:

| Check | Detects | Does not detect |
|---|---|---|
| Signatures and links | Edited, reordered, forged or spliced events | Truncation, or a whole-ledger rollback |
| Local checkpoints | Truncation or rewrite behind a checkpoint | An attacker who also deletes the checkpoints |
| Off-machine checkpoint | Rollback and truncation of everything up to it | Events added after it, until you take a new one |

Checkpoints are written automatically every 256 events. Copy the newest one somewhere the host cannot write.

## 10. Keys

| Role | Signs | Where it should live |
|---|---|---|
| root | Authorises the others | Offline, never on the machine |
| release | Releases and boot manifests | Build machine, offline |
| policy | Policy, revocations, approvals, baselines | A separate device; needed only when you change policy |
| recovery | Recovery authorisations | Offline |
| device | Ledger events and checkpoints | On the machine (it must sign continuously) |

Companion mode generates the device and policy keys locally; the rest belong to the boot deployment. Key rotation is
not automated yet: to rotate the policy key, generate a new one, replace the trust anchors and re-sign the policy, then
record the change with a checkpoint. Do this from recovery media, not from the running system.

## 11. Boot images

```sh
boot/build.sh                              # reproducible base image, initramfs, keys (test keys!) in out/boot/
```

The build produces bit-identical artifacts for identical inputs. `out/boot/release.key` is a **test key**; a real
release is signed with a release key that never touches the build host's network. See
[BOOT_INSTALLATION.md](BOOT_INSTALLATION.md).

## 12. When something is wrong

| Symptom | Cause | Action |
|---|---|---|
| `ledger is locked by another process` | Another `jlr` or the daemon holds it briefly | The CLI already waits up to 20 s; if it persists, find the holder |
| `verification failed: policy: ...` | The signed policy no longer verifies | Do not "fix" by deleting it. Restore the last good policy file or re-sign from the policy key. The engine will not start without a valid one |
| `rollback refused: policy epoch N is older than ...` | An older validly signed policy was put back | Treat as tampering. Investigate before restoring the newer policy |
| `posture DEGRADED` after a scan | A trusted binary changed | `jlr scan` lists the paths. Was it an update? If not, isolate the machine |
| Boot prints `REFUSED reason=...` and `RECOVERY-RESTRICTED` | The base image, manifest, signer or rollback floor failed | Nothing from the media was run. Boot independent recovery media. The reason line names the check |
| `jlr run` says `denied` | The decision does not allow it to run | `jlr explain PATH`; approve, or leave it |
| Everything is slow after months | Very large ledger | Opening verifies events after the last checkpoint and hashes the rest; see the roadmap for persisted tree state |

## 13. If you think the machine is compromised

1. Do not trust `jlr status` from the running system for the answer; **boot independent media** and run
   `jlr ledger verify --checkpoint` with an off-machine checkpoint.
2. Preserve `ledger/` and the quarantined `events.log.torn.N` files.
3. Revoke what you can name; rotate the policy key from the recovery context.
4. Assume host root could have edited the state directory. The ledger and checkpoints tell you what *JLR* saw and when;
   they cannot vouch for the host after root was lost.
