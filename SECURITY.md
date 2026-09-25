# Security Policy

JLR is a pre-release prototype. It has not been externally audited and **does not yet provide a production security
boundary**. Read [docs/SECURITY_BOUNDARIES.md](docs/SECURITY_BOUNDARIES.md) before relying on any property.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository. If it is not enabled, open a minimal public issue asking
for a private contact **without** exploit details, secrets, private logs or proof-of-concept payloads.

A useful report includes: the affected commit or release; the environment and kernel; the component; preconditions;
expected and observed behaviour; the security impact; a minimal reproduction; and **which trust boundary was crossed**.

What is especially valuable: a way to make a modified file, image or manifest pass verification; to make the engine load
an unsigned or older policy; to run something other than what was measured; to escape a cell or regain a dropped
capability; to make the ledger accept a truncated, reordered or forged history; to boot an image that was not signed for
the target; or to make the exec gate allow what policy denies.

## Protocol changes

Changes to EPN canonicalisation, digest or signature algorithms, key roles, evidence chaining, loader verification or
recovery-image verification require an explicit version decision, an update to
[docs/INTEGRITY_PROTOCOL.md](docs/INTEGRITY_PROTOCOL.md), and regenerated, reviewed test vectors
(`docs/vectors/protocol-v1.json`).

## Sensitive material

Do not publish private keys, recovery keys, disk-unlock material, credential databases, unredacted user evidence logs, or
other secrets in issues or pull requests. The build produces **test keys**; they are not release keys and must never be
used to sign anything real.

## Scope notes

Known limitations that are documented and therefore not vulnerabilities by themselves are listed in
[docs/SECURITY_BOUNDARIES.md](docs/SECURITY_BOUNDARIES.md). A report that shows one of them is *worse* than documented is welcome.
