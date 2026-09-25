# Command reference

`jlr` is the operator's tool. `jlrd` is the daemon. `jlr-release` is the build-time signing tool. `jlr-init` and
`jlr-cell-init` are helpers that are started by other components and are not run by hand.

Global option for `jlr` and `jlrd`: `--state DIR`, default `$JLR_STATE`, else `/var/lib/jlr` for root, else
`$XDG_STATE_HOME/jlr` or `~/.local/state/jlr`.

Environment: `JLR_STATE` (state directory), `JLR_CELL_INIT` (path of the `jlr-cell-init` helper; default: next to the
`jlr` binary).

## Exit status of `jlr`

| Code | Meaning |
|---:|---|
| 0 | Success |
| 1 | Error, or `scan` found artifacts that degraded because their content changed |
| 2 | `doctor`: this machine cannot host JLR cells as this user |
| 3 | `scan`: nothing degraded, but some files could not be measured (unreadable, too large, changing), so the scan did not look at everything |
| 126 | `run`: execution denied by the trust decision |
| other | `run`: the exit code of the program, clamped to 0..255 |

## `jlr init [--strict]`

Creates the state directory, the device and policy keys, trust anchors, the first signed policy, an empty revocation
list and the ledger with its first checkpoint. Refuses to run twice. `--strict` installs the policy that quarantines
everything without strong evidence and asks the operator.

## `jlr status`

Shows the assurance label, posture and its scope, policy name/epoch/digest, exec-gate mode, revocations, trust keys,
artifact counts per state, baselines, approvals, and the ledger's size, checkpoints and Merkle root. A warning line
appears if an incomplete ledger record was quarantined at start.

## `jlr doctor`

Prints kernel facts (LSMs, cgroup v2, TPM device, Secure Boot, IMA, user-namespace restriction) and then launches a
sealed `/bin/true` in a CELL-0, printing every control as `active`, `UNAVAILABLE (reason)` or `not requested`.

## `jlr scan [PATH...] [--full] [--exclude DIR]...`

Default path `/usr`. Walks below each path without following symlinks, measures governed files (executables, libraries,
scripts, modules, service units, boot files), records new artifacts and applies policy. Without `--full`, a file is
skipped only while its size, mtime, ctime, inode and device are unchanged, its evidence is younger than the policy's
limit, the policy epoch is the one it was decided under, and no approval or baseline it relied on has expired. Prints
counts, any path whose previously trusted content changed (exit status 1), and any file that could not be measured
(exit status 3). File names are printed with control and bidirectional-override characters escaped.

## `jlr explain PATH`

Read-only. Prints the EPN, class, size, digest, source, provenance, the state recorded in the ledger, the decision the
policy would make now with its reasons, and the evidence with its source. If a person must answer something, prints
the question.

## `jlr run [--cap CAP]... PROGRAM [ARG...]`

Measures `PROGRAM`, evaluates policy, and if the decision permits execution, seals the measured bytes into a memfd and
runs them in the prescribed cell. Prints the decision and the enforcement report to standard error. If the program ran but its end could not be recorded in
the ledger (it stayed locked for 20 seconds, or the disk is full), the program's exit status is still returned, with a
warning that the record is incomplete. `--cap` names a
capability the program requests; high-risk capabilities are withheld unless an approval grants them.

The ledger lock is held only while the program is measured and its start and end are recorded, not while it runs,
so a long-running confined program does not block the exec gate, `jlr revoke` or a policy change. The workload gets a
new session with no controlling terminal, and only descriptors 0 to 2 (the sealed program is 3) cross into the cell.

Capability syntax: `FS_READ:/abs/path`, `FS_WRITE:/abs/path`, `NET_CONNECT:host:port`, `NET_LISTEN:addr:port`,
`DEV_AUDIO`, `DEV_GPU`, `DEV_USB:class`, `PROC_SPAWN:epn`, `IPC_DBUS:name`, `HOST_SERVICE_CONTROL:service`,
`KERNEL_MODULE_LOAD`, `RAW_NETWORK`, `RAW_BLOCK_WRITE`. Paths must be absolute and normalised.

## `jlr baseline enroll [PATH...] [--name N] [--cell C] [--network M] [--ttl-days D] [--by WHO] [--exclude DIR]... [--include-unmanaged]`

Signs a baseline: an operator statement that the artifacts below the paths are the machine's initial state. Members are
files the package database vouches for whose bytes match its manifest; `--include-unmanaged` also enrols everything
else that is not known-bad (installer mode). Defaults: name `initial-host`, cell `CELL-2`, network
`FULL_USER_NETWORK`, 365 days. Members are recorded as manual overrides, one legal state step at a time.

## `jlr approve EPN [--cell C] [--network M] [--cap CAP]... [--ttl-hours H] [--by WHO]`

Signs an approval for one known artifact and re-evaluates it. The cell is capped by the policy's `max_manual_cell`.
An approval never lifts a revocation or a policy prohibition. Default: `CELL-1`, no network, 24 hours.

## `jlr revoke (--digest sha256:HEX | --signer ID | --epn EPN) --reason TEXT`

Adds an entry to the signed revocation list (epoch + 1) and moves matching known artifacts to `REVOKED`. The target
is validated and stored in the one form the matcher compares: a digest is 64 hex digits with or without a `sha256:`
prefix in any case, an EPN is accepted in any case, and anything else is refused without consuming an epoch. An EPN
revocation takes effect even for an artifact whose record has been lost from the object store; a digest or signer
revocation needs the record, so the command reports how many known artifacts it could not check and does not claim that
"nothing matched". A signer
revocation is accepted but matches nothing today, because no source adapter records a signer identity yet; the command
says so. Revoke the digests or EPNs you know are affected as well.

## `jlr policy show | set FILE | enforce on|off`

`show` prints the active policy as TOML. `set` compiles a TOML file, refuses it if validation fails, signs it with the
policy key and installs it; the epoch must exceed the current one. `enforce on|off` installs a new epoch with the
exec-gate enforcement flag changed.

## `jlr ledger verify [--checkpoint FILE] | log [-n N] | checkpoint [--out FILE]`

`verify` checks every signature, link and checkpoint, and optionally an external checkpoint. It is read-only: it loads
no signing key, takes no lock and writes nothing, so it works on read-only storage, while `jlrd` runs, and from a
recovery environment. `log` prints the last N events with control characters escaped. `checkpoint` writes a signed
checkpoint; store it off the machine.

## `jlrd [--state DIR] [--mark PATH]... [--scan-root PATH]... [--scan-every SECS] [--audit] [--fail-closed] [--lock-wait-ms N] [--slow-budget-secs N]`

The exec gate, state watcher and background rescan. Needs root. Marks every real file system (or only `--mark` paths)
and watches the mount table, so a file system mounted later is marked as soon as the kernel reports the change.
`--audit` forces audit mode whatever the policy says. `--fail-closed` denies an exec when the daemon itself errs;
the default is to allow and record a DEGRADED event. `--scan-every 0` disables the rescan.

A file the gate cannot measure (over the size limit, changing while it is read, not a regular file, a FIFO) is a
**decision**, not an internal error: it is denied when enforcing and recorded as "would deny" when auditing, whatever
`--fail-closed` says, because the user who runs a file controls those conditions. `--slow-budget-secs` (default 10)
bounds how much work each non-root user may cost per minute (opening the engine and deciding, **not** time spent waiting for
the ledger lock), and all non-root users together may use 30 seconds of it a minute; beyond that their unknown executions are
answered at once by policy without being measured (denied when enforcing, allowed and counted when auditing), so one user,
or one person with many uids, cannot stall everyone's `exec`. A file the daemon already allowed and that has not changed
is still allowed. Each throttled user leaves a summary event. `--lock-wait-ms` (default 3000) bounds how long the gate
waits for the ledger lock; a timeout follows `--fail-closed`, and is recorded as a DEGRADED event as soon as the ledger
can be opened (it is kept in memory and written at the next opportunity, not lost).

## `jlr-release`

```text
keygen   --role <root|release|policy|recovery|device> --out KEYFILE
pubkey   KEYFILE --out PUBFILE
anchors  --out ANCHORS PUBFILE...
manifest --key KEYFILE --image IMG --name N --version V --epoch E [--min-epoch M] [--component NAME=FILE]... --out MANIFEST
verify   --anchors ANCHORS --manifest MANIFEST [--image IMG] [--floor N]
state    --out FILE [--install SLOT]... [--floor N]
```

Key files are created exclusively with mode 0600 and refused on load if group- or world-accessible.

## Kernel command line for the initramfs

| Parameter | Effect |
|---|---|
| `jlr.onfail=poweroff\|reboot` | What stage 1 does after a refusal (default: wait) |
| `jlr.test=poweroff` | Stage 2 powers off after the payload; for automated tests |
| `jlr.exec=/path` | Stage 2 runs this program as a child after proving the slot, then continues |
| `jlr.media=uuid=ID` | Use only the boot medium whose ext4 UUID or FAT volume serial is `ID`; other disks are never mounted. A pin baked into the initramfs (`/etc/jlr/media-id`, `JLR_MEDIA_ID` at build time) takes precedence |

## Console protocol

Boot writes machine-checkable lines to the console. `JLR-BOOT:` lines come from stage 1 (`anchors loaded`,
`media found`, `slot=… manifest=verified`, `trying slot=…`, `image verified …`, `selected slot=…` (after the try was
spent), `base mounted read-only from RAM`,
`boot media released`, `switching root`, or `REFUSED reason=…` followed by `state=RECOVERY-RESTRICTED`). Also
`boot media is pinned to id=…` or `boot media is not pinned`, `media=N rollback floor=F`, `ignoring /dev/…: not the pinned
boot medium`, and `slot=… skipped: …` when a slot cannot be used on this boot without being retired.
`JLR-STAGE2:` lines come from the verified base (`check … ok`, `slot … marked successful; rollback floor is now N`,
`ready`).
