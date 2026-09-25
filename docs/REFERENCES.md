# References

Sources that shaped the design or that the implementation relies on. Researched 2026-09-25 against live documentation;
**verify a claim against the source before relying on it**, because several of these projects change quickly.

## Verified boot, immutable systems, update safety

- ChromeOS verified boot (per-read dm-verity, why not whole-image hashing): <https://www.chromium.org/chromium-os/chromiumos-design-docs/verified-boot/>
- ChromeOS A/B kernel slots (priority, tries remaining, successful): <https://www.chromium.org/chromium-os/developer-library/reference/device/disk-format/>
- Android Verified Boot states and rollback ordering: <https://source.android.com/docs/security/features/verifiedboot/boot-flow>
- Apple Signed System Volume: <https://support.apple.com/guide/security/signed-system-volume-security-secd698747c9/web>
- Talos Linux (no shell, API-only, signed read-only SquashFS): <https://docs.siderolabs.com/talos/latest/learn-more/philosophy>
- Bottlerocket security features (dm-verity root, no shell, restart on corruption): <https://github.com/bottlerocket-os/bottlerocket/blob/develop/SECURITY_FEATURES.md>
- Tails memory erasure (RAM-resident, amnesic): <https://tails.net/contribute/design/memory_erasure/>
- Woof-CE, the Puppy Linux build system: <https://github.com/puppylinux-woof-CE/woof-CE>
- Linux dm-verity: <https://docs.kernel.org/admin-guide/device-mapper/verity.html>; fs-verity: <https://docs.kernel.org/filesystems/fsverity.html>

## Confinement and enforcement

- Landlock: <https://docs.kernel.org/userspace-api/landlock.html>
- seccomp filters: <https://docs.kernel.org/userspace-api/seccomp_filter.html>
- fanotify(7) (`FAN_OPEN_EXEC_PERM`): <https://man7.org/linux/man-pages/man7/fanotify.7.html>
- memfd_create(2) and file sealing: <https://man7.org/linux/man-pages/man2/memfd_create.2.html>
- user_namespaces(7): <https://man7.org/linux/man-pages/man7/user_namespaces.7.html>
- IPE, the Integrity Policy Enforcement LSM (Linux 6.12): <https://docs.kernel.org/admin-guide/LSM/ipe.html>
- Qubes qrexec policy, disposables and the dom0 rule: <https://doc.qubes-os.org/en/latest/developer/services/qrexec.html>
- Flatpak sandbox permissions and portals: <https://docs.flatpak.org/en/latest/sandbox-permissions.html>

## Formats, signatures and logs

- CBOR, deterministic encoding (section 4.2): <https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2>
- COSE structures: <https://www.rfc-editor.org/rfc/rfc9052.html>
- Fully specified COSE algorithm identifiers (Ed25519 = -19): <https://datatracker.ietf.org/doc/rfc9864/>
- Certificate Transparency v2 (Merkle tree hashing, inclusion and consistency proofs): <https://www.rfc-editor.org/rfc/rfc9162>
- Transparency-log checkpoints (the model for JLR checkpoints): <https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md>
- The Update Framework specification (role separation, rollback protection): <https://theupdateframework.github.io/specification/latest/>

## Evidence and provenance

- Debian package management and maintainer scripts: the dpkg database format (`/var/lib/dpkg/info/*.list`, `*.md5sums`).
  This metadata is unauthenticated; see [SOFTWARE_ADMISSION.md](SOFTWARE_ADMISSION.md).
- Smart App Control's evaluation mode, and Gatekeeper's quarantine attribute, as models for audit-first enforcement and
  provenance tagging.

## What the two earlier design sets contributed

The merged design (pull request #2) supplied the artifact model (EPN records, admission states, jail classes,
invariants I-01 to I-18). The draft (pull request #1) supplied the assurance labels, scoped evidence, authority scoping,
the "no destructive automatic repair" rule and the milestone gates. [DECISIONS.md](DECISIONS.md) records how the two were
reconciled.
