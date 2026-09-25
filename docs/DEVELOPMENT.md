# Developing JLR

## Repository map

| Path | What it is | Unsafe |
|---|---|---|
| `crates/jlr-cbor` | JLR-DCBOR/1: strict deterministic CBOR, the `record!` schema macro | forbidden |
| `crates/jlr-crypto` | SHA-256, strict Ed25519, key roles and files, COSE_Sign1 envelope | forbidden |
| `crates/jlr-model` | EPN records, admission states, capabilities, cells, evidence, decisions, events | forbidden |
| `crates/jlr-ledger` | RFC 9162 Merkle tree, signed append-only log, checkpoints | forbidden |
| `crates/jlr-policy` | Trust engine, policy validation, revocations, approvals, baselines | forbidden |
| `crates/jlr-measure` | Descriptor hashing, classification, path facts, dpkg adapter and index cache | forbidden |
| `crates/jlr-cell` | Jail fabric and the `jlr-cell-init` helper | `sys.rs` and two call sites, each commented |
| `crates/jlr-engine` | State directory, key ceremony, loading, scan, admission, run, revoke | forbidden |
| `crates/jlr` | The `jlr` CLI and TOML policy authoring | forbidden |
| `crates/jlr-boot` | Release manifests, A/B state, `jlr-init`, `jlr-release` | `sys.rs` only |
| `crates/jlrd` | fanotify exec gate, state watcher, rescan | forbidden |
| `boot/` | Reproducible base image and initramfs build, guest scripts | n/a |
| `tools/` | Documentation generators | n/a |
| `docs/` | The design record; `docs/generated` and `docs/vectors` are produced from code | n/a |
| `contrib/` | Service units and packaging files | n/a |

About 15,000 lines of Rust, of which about a quarter are tests. Every `unsafe` block sits under a `SAFETY:` comment.

Dependencies inside the trusted computing base are deliberately few: `sha2`, `ed25519-dalek`, `getrandom`, `zeroize`,
`subtle` for cryptography; `nix`, `libc`, `landlock`, `seccompiler`, `caps` for the kernel; `md-5` only to compare with
dpkg's manifests. TOML, JSON and `clap` are confined to the CLI and to authoring.

## Environment without root

Everything below was developed on a machine where automation has no `sudo`.

```sh
# Rust (a recent stable; the workspace pins the toolchain in rust-toolchain.toml)
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
rustup target add x86_64-unknown-linux-musl

# QEMU, OVMF, swtpm, erofs tools without root: download the .debs and extract them
mkdir -p ~/.local/jlr-tools/debs && cd ~/.local/jlr-tools/debs
apt-get download qemu-system-x86 ovmf swtpm seabios ipxe-qemu    # plus their dependencies
for d in *.deb; do dpkg -x "$d" ~/.local/jlr-tools/root; done

# A kernel for boot tests (root-only in /boot, so extract the package's copy)
apt-get download linux-image-$(uname -r) && dpkg-deb -x linux-image-*.deb ~/.local/jlr-tools/kernel/ex
```

The boot tests need a kernel with virtio, loop, ext4 and squashfs built in (Ubuntu's generic kernel qualifies), a
static `busybox`, `mksquashfs`, `mke2fs` and `debugfs`. They look for `JLR_QEMU`, `JLR_QEMU_DATA`, `JLR_KERNEL`,
`JLR_BUSYBOX` and `JLR_BOOT_OUT`, then for the paths above, and **skip loudly** when something is missing.

## Everyday commands

```sh
cargo build --workspace
cargo test  --workspace                     # ~190 tests; the QEMU boots take about 15 s
cargo clippy --workspace --all-targets
cargo fmt --all
./boot/build.sh                             # boot artifacts into out/boot/
JLR_BOOT_SHOW=1 cargo test -p jlr-boot --test qemu -- --nocapture   # see the guest console
python3 tools/gen_records.py                # regenerate docs/generated/RECORDS.md
JLR_UPDATE_VECTORS=1 cargo test -p jlr --test vectors   # only when deliberately changing a wire format
```

## How the code is tested

- **Unit and property tests.** The codec has an RFC 8949 vector set and the property that any accepted input re-encodes
  to identical bytes. The trust engine has properties for determinism, order-independence, revocation dominance, no
  promotion without matching evidence, and no high-risk capability without an approval. Merkle proofs are checked for
  every size and index up to 40 and against the Certificate Transparency reference roots.
- **Real-kernel tests.** `jlr-cell` launches real cells and asserts what a workload can and cannot do. `jlr-boot`
  boots the actual initramfs under QEMU/KVM and asserts each refusal and each success from the console. The exec gate
  is tested as root inside the guest.
- **Mutation checks.** A security test is only worth having if it fails when the check it guards is removed. For each
  control, temporarily disable it, run the tests, and confirm the matching test fails. This has been done for the trust
  engine, the cell controls, the engine's drift, revocation and ledger-derived state, and the three boot checks. It
  found real gaps: a test that iterated over an empty listing, an installer that could not outrank the old slot, and a
  detection that reported the wrong artifact. When you add a control, do the same.
- **Protocol vectors.** `docs/vectors/protocol-v1.json` pins bytes, digests, signatures and Merkle roots. Any change to
  a wire format fails `crates/jlr/tests/vectors.rs` until the file is regenerated on purpose.

## Rules for changes

1. Record what threat or failure the change addresses, what trust boundary moves, what evidence is produced, how it
   fails, how it is tested and how it is recovered from. Put it in the pull request; put durable decisions in
   [DECISIONS.md](DECISIONS.md).
2. **Decode strictly.** Anything that parses untrusted bytes must reject non-canonical, unknown and truncated input, and
   must be covered by a malformed-input test.
3. **Fail closed for trust; be explicit about availability.** Missing evidence never becomes positive trust. A control
   that could not be established is reported and, if mandatory, refuses the operation.
4. **No new `unsafe` outside the two `sys.rs` files** without a design note. Prefer a safe wrapper from `nix`.
5. **Do not put time, counters or other volatile data in an identity.** An earlier version put a discovery timestamp in
   the EPN record and every observation produced a new identity. The regression test is
   `the_same_file_has_the_same_identity_at_different_times`.
6. **Never claim more than a test demonstrates.** Update [SECURITY_BOUNDARIES.md](SECURITY_BOUNDARIES.md) in the same change.
7. **Wire-format changes** bump a format version, update [INTEGRITY_PROTOCOL.md](INTEGRITY_PROTOCOL.md) and regenerate
   the vectors, in one reviewed change.

## Adding things

- **An evidence kind:** add a variant to `EvidenceKind` (`jlr-model/src/decision.rs`) with the next code, produce it in
  `jlr-measure` or the engine, consume it in a policy tier or guard in `jlr-policy`, add tests for present, absent and
  forged, regenerate `docs/generated/RECORDS.md`.
- **A jail control:** add a `Control` variant, establish it in `jlr-cell/src/init.rs` stage 2, add it to the requested and
  (if it must hold) mandatory sets in `CellSpec`, report it, and add a test that a workload cannot do what the control
  forbids, plus the mutation check.
- **A record:** declare it with `record!`. The macro gives you canonical encoding, strict decoding, and the re-encode
  check for free; add it to the vectors.

## Reproducible builds

`boot/build.sh` uses `SOURCE_DATE_EPOCH`, a deterministic squashfs (`-reproducible`, no xattrs, all-root) and a
deterministic newc writer (`boot/mkcpio.py`, sorted, sequential inodes, fixed times). Two builds from the same inputs
give identical `base.sqfs` and `initramfs.cpio.gz`; the build compares them in CI. Rust binaries are built with
`--locked` from a pinned toolchain; bit-for-bit Rust reproducibility across machines is not yet verified.

## Continuous integration

`.github/workflows/ci.yml` runs formatting, clippy, the unit suites, the generated-docs check, the static musl builds and
the QEMU boot tests (with KVM where the runner offers it, otherwise TCG, which is slower). See the file for the exact
steps; it uses only actions and packages pinned by version or digest.
