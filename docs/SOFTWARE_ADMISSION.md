# Software Admission

## 1. The default rule

New software is not trusted because it was downloaded, installed by a package manager, or launched by an administrator.
The lifecycle is:

```text
discover -> identify (EPN) -> gather evidence -> decide -> [observe] -> admit or restrict
```

Every arrow is a ledger event. Nothing moves from `UNKNOWN`, `QUARANTINED` or `OBSERVED` to `VERIFIED` or `ADMITTED`
without a recorded decision, the evidence behind it, and the policy version that made it (I-01).

## 2. Discovery

JLR examines a file when:

| Trigger | Component | Status |
|---|---|---|
| The operator scans a tree | `jlr scan`, `jlr baseline enroll` | Implemented |
| The daemon's rescan reaches it | `jlrd` (default hourly, in slices of 100 files) | Implemented |
| It is about to be executed | `jlrd` exec gate (`FAN_OPEN_EXEC_PERM`) | Implemented |
| The operator runs it | `jlr run` | Implemented |
| A package transaction installs it | A package-manager hook | Designed (section 9) |
| It is written or modified | `FAN_CLOSE_WRITE` event-driven re-measurement | Designed; exec-time and periodic checks cover it today |

**Governed classes** are things the machine can execute, load or boot from: executables, libraries, scripts (including any
executable file of unknown format), kernel modules, service units, kernel and initrd images, boot files, packages and
application bundles. Ordinary data, configuration and key files are not governed.

Measurement never follows a final symlink, never reads more than the size limit, and refuses a file that changed while
it was being read. A symlink is not an artifact; the file it points to is measured under its own path.

## 3. Evidence

Evidence is normalised into items with a kind, source, time, detail and an optional digest of the raw measurement. Raw
measurements are kept apart from the conclusion drawn from them (I-04): the engine stores each observation's evidence as
a content-addressed object and the ledger event names it by digest.

| Kind | Meaning | Produced today by |
|---|---|---|
| `CONTENT_DIGEST_MATCH` | The bytes hash to the recorded digest | every measurement |
| `CONTENT_DIGEST_MISMATCH` | The bytes differ from what was recorded or what the package manifest says | the dpkg adapter; the engine when content at a path changes |
| `MANAGED_INSTALLER` | A package transaction owns the file | dpkg ownership |
| `PACKAGE_MANIFEST_MATCH` | The bytes match the local package manifest. **The manifest is unauthenticated** | dpkg manifests |
| `SETUID_BIT` | Setuid or setgid | measurement |
| `WRITABLE_PATH` | The file, a parent directory or a symlink on the route can be changed by an untrusted actor | measurement |
| `MISSING` | Expected evidence could not be obtained | measurement, dpkg adapter |
| `SIGNATURE_VALID`, `SIGNATURE_INVALID` | A signature verified or did not | Not yet (needs a vendor key store) |
| `PACKAGE_SIGNATURE` | A repository or package signature verified | Not yet (needs the managed-installer hook) |
| `REPRODUCIBLE_MATCH` | A local rebuild reproduced the bytes | Not yet |
| `STATIC_FINDING`, `OBSERVATION`, `FORBIDDEN_BEHAVIOR` | Analysis and behaviour in an observation cell | Not yet |
| `REVOCATION_HIT` | A revocation matched | Sensors may supply it; the engine also consults its own list |
| `OPERATOR_APPROVAL`, `BASELINE_MEMBER` | Human authority | Reserved; approvals and baselines act through their signed objects, not as evidence items |

Static analysis is evidence, not proof of benign behaviour. **A dpkg manifest is a consistency check, not a provenance
claim**: the adapter therefore records provenance `SOURCE_KNOWN` and never emits `PACKAGE_SIGNATURE`.

## 4. Policy

A policy is an ordered list of **tiers**, a few **guards**, and a set of limits. It is authored as TOML, compiled to
canonical CBOR, validated, signed by the policy key, and loaded only in that form.

**Tier.** `name`, `classes` (empty = any), `max_provenance` (the artifact's provenance must be at least this strong),
`require_evidence` (every listed kind must be present), the resulting `state`, `cell` and `network`, whether a person
must answer (`needs_user`), and a `reason`. The **first matching tier decides**; missing evidence makes a tier not match,
never match.

**Guards** applied after tier selection: `setuid_min_provenance`, `writable_path_max_cell`, `max_manual_cell`,
`block_classes`, `evidence_max_age_secs`, and `enforce_exec`.

### Built-in policies

`workstation` (silent for managed software, observation for the rest):

| # | Tier | Applies to | Needs | Result |
|---|---|---|---|---|
| 1 | `managed-boot` | BOOT, KERNEL, INITRD, MODULE, FIRMWARE | DISTRO_SIGNED or stronger; MANAGED_INSTALLER and PACKAGE_SIGNATURE | ADMITTED, CELL-3, no network |
| 2 | `managed-package` | any | DISTRO_SIGNED or stronger; MANAGED_INSTALLER and PACKAGE_SIGNATURE | ADMITTED, CELL-2, full user network |
| 3 | `pinned-vendor` | any | PINNED_VENDOR or stronger; SIGNATURE_VALID | ADMITTED, CELL-2 |
| 4 | `reproduced` | any | REPRODUCED; REPRODUCIBLE_MATCH | ADMITTED, CELL-2 |
| 5 | `checksum-verified` | any | VERIFIED_CHECKSUM or stronger; CONTENT_DIGEST_MATCH | VERIFIED, CELL-1, loopback only |
| 6 | `observe-unknown` | any | nothing | OBSERVED, CELL-0, no network |

`strict` keeps tiers 1 to 4 and ends with `quarantine-unknown`: QUARANTINED, CELL-0, and a question for a person.

| Guard | workstation | strict |
|---|---|---|
| `setuid_min_provenance` | DISTRO_SIGNED | PINNED_VENDOR |
| `writable_path_max_cell` | CELL-1 | CELL-0 |
| `max_manual_cell` | CELL-2 | CELL-1 |
| `evidence_max_age_secs` | 7 days | 1 day |
| `enforce_exec` | off (audit) | off (audit) |

### Validation

A policy that breaks any of these is **refused at compile time and again at load**; it is never partially applied and
never replaced by a default (I-11):

1. schema 1, a name, a positive epoch, between 1 and 64 tiers with unique names; the policy name and every tier name are 1 to
   128 characters from `A-Z a-z 0-9 . _ -`, so a name can never carry a control character, a line break or text that reads
   like another field (`epoch=9`) into the ledger or a terminal;
2. the final tier matches everything (all classes, provenance `UNKNOWN`, no required evidence);
3. a tier that lets software run (`VERIFIED` or `ADMITTED`) requires at least `VERIFIED_CHECKSUM` provenance and at least one
   piece of required evidence, so **unknown software cannot be admitted by policy alone**;
4. no tier assigns `UNKNOWN`, `DEGRADED` or `REVOKED`;
5. states that do not run (`OBSERVED`, `QUARANTINED`, `POLICY_BLOCKED`) stay in CELL-0 and may not have network access;
6. CELL-R is never in a tier; CELL-3 needs a person or a verified package transaction; `PRIVILEGED_NETWORK` needs a person;
7. `max_manual_cell` may not be CELL-R.

## 5. The decision function

`evaluate(policy, artifact, evidence, requested capabilities, prior state, revocations, approval, now)` is **pure**. The
same inputs give the same decision, whatever order the evidence arrives in (I-17). Precedence, highest first:

1. **Revocation** by EPN, content digest or signer, or a previous `REVOKED` state. Nothing overrides it (I-14).
2. **Changed content** of something previously `VERIFIED` or `ADMITTED` degrades it; of anything else quarantines it (I-08).
3. **Prohibitions:** forbidden behaviour or a blocked class gives `POLICY_BLOCKED`. Approvals cannot lift it.
4. **Invalid signature** quarantines, even with a valid package transaction.
5. **The first matching tier.** Then the guards: a setuid file whose provenance is weaker than the guard is quarantined
   with a question; a file in a path an untrusted actor can write is capped to a smaller cell and a narrower network.
6. **Capabilities.** Only artifacts that run normally, and only outside CELL-0, receive any. **High-risk capabilities are
   never granted by the engine**; they are withheld and raise a question.
7. **An operator approval** raises the artifact within the policy's manual ceiling and is recorded as a manual override.

Properties tested over thousands of generated inputs: determinism and order-independence; revocation dominance; no
`VERIFIED`/`ADMITTED` result without a tier whose conditions the evidence satisfies; no high-risk capability without an
approval; a non-running state carries no capability, no cell above CELL-0 and no network.

## 6. Capabilities

Policy uses semantic capabilities, not user ids: `FS_READ:/path`, `FS_WRITE:/path`, `NET_CONNECT:host:port`,
`NET_LISTEN:addr:port`, `DEV_AUDIO`, `DEV_GPU`, `DEV_USB:class`, `PROC_SPAWN:epn`, `IPC_DBUS:name`,
`HOST_SERVICE_CONTROL:service`, `KERNEL_MODULE_LOAD`, `RAW_NETWORK`, `RAW_BLOCK_WRITE`. Paths must be absolute, normalised
and free of `..`. **Absence of a capability is denial** (I-06). The high-risk set is `KERNEL_MODULE_LOAD`, `RAW_NETWORK`,
`RAW_BLOCK_WRITE`, `HOST_SERVICE_CONTROL` and `DEV_USB`.

## 7. Approvals and baselines

An **approval** is a signed record for one EPN: a cell, a network mode, exact capabilities, an expiry and the operator's
name. It is verified against the trust anchors, scoped to this node, and honoured only while unexpired. It raises an
artifact to `ADMITTED` (via `VERIFIED`, as two recorded transitions) with basis `MANUAL_OVERRIDE`. The reasons that made
it unadmittable stay on the record beside `OPERATOR_AUTHORIZED`.

A **baseline** is the same authority over a *set*: an operator's signed statement that these artifacts are the machine's
initial state. The operator chooses whether it covers only package-managed files that match their manifests (the default)
or everything on disk (`--include-unmanaged`, for an installer whose verified base image is itself the trust root).

Neither can lift a revocation or a prohibition. Neither survives a content change: the new bytes are a new EPN.

**The ledger says which one is current.** A file in `approvals/` or `baselines/` counts only if its envelope digest is the
evidence of the latest `OVERRIDE` event for its subject (the EPN, or `baseline:<name>`). A superseded or withdrawn file that
is copied back still verifies on its signature, and is ignored and reported once. A copy stored under another name cannot
shadow the current one for the same reason. Approving again with a shorter time or a smaller cell is how an approval is
narrowed or withdrawn. The signed files are stored as `<subject>.<first 16 hex of their digest>.cose`, so writing a new one
never overwrites the one the ledger currently records; the ledger event that makes it current comes next, and older files
are removed only after that. A crash or a full disk in between leaves the old authority in force and the new file ignored
(and reported once) until the operator repeats the command.

## 8. Revocation

Signed lists with an epoch that never goes backwards. Entries name an EPN, a content digest (`sha256:...`) or a signer, and
are validated and stored in one canonical form before they are signed, so a target that could never match is refused
instead of being recorded as done. Signer entries are accepted but match nothing until an adapter records signers.
Adding one moves every known matching artifact to `REVOKED` immediately and every future observation with it. It is
terminal until a later signed record supersedes it (a supersession record is designed).

## 9. Managed installers: what is built and what is not

**Today.** The dpkg adapter reports ownership and consistency with dpkg's unauthenticated manifests. It cannot vouch for
origin, so package-managed software becomes trusted through an operator-signed **baseline**. That is honest, recorded as
a manual override, and requires the operator to enrol at a moment they trust.

**Designed.** An apt hook (`DPkg::Pre-Install-Pkgs`) receives the `.deb` files of a transaction *after apt has verified
them against the signed repository indexes*. JLR would extract each package's file digests, record them as the expected
digests of a hook-attested transaction (a signed, ledgered object), and after installation emit `PACKAGE_SIGNATURE` for
files whose bytes match. That gives `DISTRO_SIGNED` provenance an authenticated chain from the repository key to the
file, lets `managed-package` admit silently with no baseline, and lets enforcement coexist with unattended upgrades. Until it
exists, do not enable enforcement on a machine that updates itself unattended.

## 10. Re-evaluation

| Trigger | Status |
|---|---|
| Content changed | Implemented (exec-time and scan) |
| Signer or digest revoked | Implemented |
| Policy epoch changed | Implemented (next scan, or immediately for the gate's cache) |
| Approval or baseline expired | Implemented |
| Evidence older than `evidence_max_age_secs` | Implemented (scan re-hashes; gate verdicts expire) |
| Dependency changed | Designed (EPNs list dependencies; nothing populates them yet) |
| Host trust changed, path became writable to a less-trusted actor | Designed for the running set; path facts are re-evaluated at every scan |
| New forbidden behaviour observed | Designed (needs observation telemetry) |

## 11. What a person is asked

The autonomy contract. Everything else is silent.

| A person must decide | Because |
|---|---|
| A high-risk capability | It raises authority beyond what evidence supports |
| Anything in CELL-3, and any persistent autostart or service install | Same |
| A boot-set change that did not come from a verified package transaction | Same |
| Running something `REVOKED` or `POLICY_BLOCKED` | These are decisions already taken; overriding one is a policy change |
| Recovery writes | Destructive, and recovery is read-only by default (I-18) |
| Enrolling or rotating a key, or lowering the enforcement tier | Changes the rules |

**Notification design (designed, not built).** Green is silent. Yellow (`DEGRADED`, non-blocking) is a single rate-limited
note with a link to the evidence, never repeated on every boot. Red (boot chain, policy signature or ledger failure) is a
blocking screen whose primary action is recovery. Overrides live in a settings surface with deliberate friction, not on
the alert. Today the equivalent is the CLI's messages, `jlr explain`, and the ledger.

## 12. Emergency execution

Recovery sometimes needs a tool JLR has never seen. `jlr run` already gives the safe form: an unknown program runs in an
isolated cell with no promotion. A separate `EMERGENCY OVERRIDE` (explicit confirmation, forced isolation, no promotion,
prominent logging, automatic expiry) is designed for the recovery context and does not exist yet.
