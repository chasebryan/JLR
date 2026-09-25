# JLR Integrity Protocol

This document specifies the wire formats and the rules for producing and checking them. It is written so that an
implementation can be built from it and checked against [`vectors/protocol-v1.json`](vectors/protocol-v1.json).
`tools/check_vectors.py` does exactly that, with an implementation that shares no code with the Rust one: it decodes the
CBOR, rebuilds the COSE `Sig_structure`, verifies the Ed25519 signature, and recomputes identifiers and Merkle roots.
Field-level tables are generated from the source in [generated/RECORDS.md](generated/RECORDS.md).

> **Protocol principle.** Hashes identify. Signatures authenticate provenance. Encryption protects data under key
> control. Policy constrains authority. Observations provide evidence. None of these alone proves that software is
> benevolent.

## 1. The Encryption Protocol Number (EPN)

An **EPN** identifies a signed-or-signable *artifact identity record*. It is a public identifier, safe to log and share. It
is **not** a secret, a key, or a cipher, and security never depends on its secrecy.

```text
EPN-1-<CLASS>-<64 lowercase hex digits>
```

The hex digits are the SHA-256 of the record's canonical CBOR encoding. Consequences, all of which are tested:

- **Anyone can recompute and check it.** There is no registry and no random component.
- **It is time-free.** The record holds only facts about the artifact and its provenance. When an artifact was first seen
  is a ledger event. (An earlier draft embedded a discovery time, which gave the same file a new EPN on every scan.)
- **It binds the installation path.** The same bytes at two paths have two EPNs and may have different permissions, but
  the same content digest, so revocation by digest reaches both.
- **Mutable facts are not in it.** State, approvals and revocations are ledger events and signed lists that *refer* to
  the EPN; a transition never rewrites the historical measurement.

**The name.** "Encryption Protocol Number" is retained because the record is the anchor to which a protection policy is
meant to bind. Format version 1 records do **not** yet carry a protection profile (at-rest encryption, sealing); adding
one is a schema change and follows the version rules in section 8. Nothing in v1 claims that any artifact is encrypted.

## 2. Deterministic encoding: JLR-DCBOR/1

Every signed or hashed object is CBOR (RFC 8949) restricted to the **core deterministic encoding of section 4.2.1**,
narrowed so that exactly one byte string represents each value.

| Rule | Detail |
|---|---|
| Types | unsigned and negative integers, byte strings, UTF-8 text, arrays, maps, tags, `true`, `false`, `null` |
| Forbidden | floating point, `undefined`, other simple values, indefinite lengths, reserved additional information |
| Integers and lengths | shortest possible argument; a longer form is an error |
| Maps | keys sorted by the bytewise order of their **encodings**; a duplicate or out-of-order key is an error |
| Text | must be valid UTF-8 |
| Framing | exactly one top-level item; trailing bytes are an error; nesting depth is bounded (32) |
| Records | integer keys; `Option` fields are **omitted** when absent and never written as `null`; unknown, missing or mistyped keys are errors |

The decoder enforces these while parsing, and records are additionally decoded, re-encoded, and rejected unless the bytes
are identical. The invariant, property-tested: **any input that decodes re-encodes to exactly the same bytes**, so two
different byte strings can never mean the same record, and a signature can never be transplanted onto a second encoding.

**Digests** are never bare. On the wire a digest is the array `[-16, <32 bytes>]`, where `-16` is the COSE algorithm
identifier for SHA-256. Text form is `sha256:<64 hex>`.

**Enumerations** are unsigned integers; the codes are in [generated/RECORDS.md](generated/RECORDS.md) and never change
meaning once released.

## 3. The signed envelope

Signed objects are COSE_Sign1 (RFC 9052) under a strict profile:

```text
18([ protected   : bstr .cbor { 1: -19, 4: kid, 16: typ },
     unprotected : {},
     payload     : bstr,                  ; canonical JLR-DCBOR/1 record
     signature   : bstr .size 64 ])

Sig_structure = ["Signature1", protected, external_aad, payload]
external_aad  = "JLR/1/" || record_type || "/" || scope        ; ASCII
typ           = "application/vnd.jlr." || record_type || "+cbor;v=1"
kid           = SHA-256(raw 32-byte Ed25519 public key)
alg -19       = Ed25519, fully specified (RFC 9864). The deprecated -8 is rejected.
```

Verification, in order; any failure refuses the object:

1. Decode the envelope strictly (section 2). It must be tag 18 with four elements and an **empty** unprotected header.
2. The protected header must contain exactly labels 1, 4 and 16. `alg` must be -19. `typ` must equal the value for the
   record type the verifier **expected**, so an envelope cannot be reinterpreted as another type.
3. The `kid` must name a key in the verifier's trust anchors, and that key's **role** must be one this record type permits.
4. Verify the Ed25519 signature over the `Sig_structure` **built from the received protected bytes**, with the expected
   `external_aad`. Verification is *strict*: non-canonical `s`, small-order points and weak public keys are rejected.
5. Only then parse the payload, strictly.

**Domain separation.** The `external_aad` binds record type and scope into the signature. A signature made for
`epn` on `node-a` does not verify as `policy`, nor on `node-b`. Scope is the node identifier for node-local records
(events, checkpoints, approvals, baselines, EPNs) and `*` for portable records (policy, revocations, release manifests).

**Identities.** *Record identity* is SHA-256 of the payload. *Envelope identity* is SHA-256 of the whole envelope and is
the ledger leaf. Re-signing a record (for a key rotation) changes the envelope identity and leaves the record identity,
and therefore the EPN, unchanged.

### Record types and who may sign them

| Record type | Scope | Roles permitted to sign |
|---|---|---|
| `epn` | node | device, release |
| `event` | node | device |
| `checkpoint` | node | device |
| `policy` | `*` | policy |
| `revocations` | `*` | root, policy, release |
| `release-manifest` | `*` | release |
| `approval` (also baselines) | node | policy, recovery |
| `recovery-authorization` | node | recovery |

## 4. Records

Field tables for `EpnRecord`, `Event`, `Checkpoint`, `Decision`, `Policy`, `Tier`, `Approval`, `Baseline`,
`Revocations`, `ReleaseManifest`, `BootState`, `CellSpec`, `EnforcementReport` and the rest are in
[generated/RECORDS.md](generated/RECORDS.md). Semantic rules that a table cannot carry:

- **`Event.prev`** is the *envelope digest* of the previous event (all zeroes for the first). `seq` starts at 0 and must
  be consecutive. The first event is `GENESIS` and `GENESIS` may appear once.
- **`Event.basis`** is one of `CRYPTOGRAPHIC`, `POLICY`, `MANUAL_OVERRIDE`, `NONE`. An override is never recorded as anything else.
- **`Decision.capabilities`** and `reasons` are sorted and de-duplicated, so equal decisions have equal bytes.
- **`Capability`** is text with a grammar (`FS_READ:/abs/path`, `NET_CONNECT:host:port`, ...). Parsing then re-printing must
  give the same text, or the record is not canonical.
- **`Policy`** must pass validation (section 4 of [SOFTWARE_ADMISSION.md](SOFTWARE_ADMISSION.md)) before it is signed and
  again when loaded; its identity is the digest of its canonical form.
- **`Baseline.members`** are EPN record digests, sorted ascending and unique.
- **`ReleaseManifest.epoch`** is the rollback counter; `min_epoch` may not exceed `epoch`.

## 5. The evidence ledger

**Log files.** `events.log` and `checkpoints.log` are sequences of frames:

```text
u32 big-endian length || u32 check || envelope
check = first 4 bytes of SHA-256( be64(9) || "JLR-frame" || be64(4) || be32(length) )
```

(`be64(n)` is an 8-byte big-endian length prefix; each part of the hashed message is length-framed so parts cannot be
shifted into one another.)

The check is an *integrity* check on the length field, not a security control. It exists so that a damaged length is an
**error**, never mistaken for a torn write. A trailing frame that is incomplete, whose header is valid, is a *torn tail*
(a crash during append): its bytes are copied to `events.log.torn.N`, the file is truncated to the last whole frame, and
the repair is logged. Torn bytes are never deleted. `checkpoints.log` follows the same rules (`checkpoints.log.torn.N`) and
is repaired when the ledger is opened, so a later checkpoint is never appended behind garbage. An append that fails part
way removes what it wrote, so a full disk cannot leave a torn frame in the middle of the log, and the counter advances
only after the frame is durable.

**Merkle tree.** The tree is RFC 9162: leaf hash `SHA-256(0x00 || envelope)`, node hash `SHA-256(0x01 || left || right)`.
Inclusion and consistency proofs are as specified there, and are tested for every size and index up to 40, against the
Certificate Transparency reference roots. A root does not commit to its own size, so a verifier takes `(size, root)`
together from a signed checkpoint.

**Checkpoints** are signed `Checkpoint` records: `origin` (`jlr/<node>/evidence`), `size`, `root`, `boot_id`, a strictly
increasing `counter`, and an `anchor` label. A verifier must state which anchors were present. A `Software` anchor is a
counter stored beside the ledger and detects nothing against an attacker who rewrites both.

**Replay and the fast path.** Opening a ledger hashes every frame into the tree and verifies every checkpoint signature
and that each checkpoint's root equals the tree's root at its size. Events at positions below the newest checkpoint's
`size` are then covered by that signed root: any byte change alters the root and is an error, so per-event signatures are
verified only after the checkpoint. This is the documented trade: a checkpoint is the device key vouching for exactly
those bytes. `jlr ledger verify` skips the shortcut and verifies every signature.

**What each mechanism detects** is tabulated in [OPERATIONS.md](OPERATIONS.md) section 9 and in
[SECURITY_BOUNDARIES.md](SECURITY_BOUNDARIES.md).

## 6. Release and boot records

A `ReleaseManifest` binds a release to the SHA-256 and exact size of its base image. It is signed with scope `*`
under the release role. **Boot verification** (see [BOOT_INSTALLATION.md](BOOT_INSTALLATION.md)):

1. verify the manifest (signature, role, `epoch >= floor`, `min_epoch <= epoch`);
2. copy the image into RAM, hashing while copying, refusing more bytes than `image_size`, and require both size and digest
   to match;
3. only then mount that RAM copy.

`BootState` is `{floor, slots[{name, priority, tries, successful}]}`. Selection, the durable spending of a try before
booting, and the rule that the floor rises only after a successful health check are specified in `state.rs` and tested
as properties.

## 7. Cryptographic baseline

| Purpose | Algorithm | Notes |
|---|---|---|
| Digests | SHA-256 | Mandatory and the only wire digest |
| Signatures | Ed25519 (RFC 8032) | Strict verification; weak public keys rejected at enrolment |
| Randomness | Operating-system RNG | Failure is fatal; there is no fallback |
| Key files | CBOR, mode 0600, created exclusively | Refused on load if group or world accessible; seeds wiped on drop |
| Legacy comparison | MD5 | Only to compare with dpkg's own manifests; never in a signed record and never a trust decision on its own |

**Not yet implemented, and planned rather than claimed:** hybrid post-quantum signatures (an ML-DSA-65 signature carried
beside Ed25519 for the root, release and recovery roles, both required) and TPM-anchored counters. Neither exists in the
code; the envelope's `alg` label and the checkpoint's `anchor` field are where they will appear.

## 8. Versioning

- Every record has a `schema` (or the envelope a `typ` `;v=1`). A verifier rejects a version it does not know; it does not
  guess.
- A change to canonicalisation, digest or signature algorithms, key roles, evidence chaining, loader verification or
  recovery-image verification is a **protocol change**. It needs an explicit version decision, an update to this
  document, and regenerated vectors, in one reviewed change ([DEVELOPMENT.md](DEVELOPMENT.md)).
- Enumeration codes are append-only.

## 9. Test vectors

`vectors/protocol-v1.json` contains, from fixed seeds: ten CBOR cases; the device key, its public key and key id; an EPN
record with its digest and identifier; the same record in a signed envelope with its digests; an event; a decision; the
workstation policy's digest; a five-leaf Merkle tree with its roots, an inclusion proof and a consistency proof; a signed
release manifest; and a boot state. `crates/jlr/tests/vectors.rs` fails on any drift; `tools/check_vectors.py` verifies
the file with an independent implementation.
