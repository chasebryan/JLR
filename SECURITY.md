# Security Policy

JLR is currently in the specification/design phase. This repository does not yet provide a production security boundary.

## Reporting a vulnerability

Use GitHub private vulnerability reporting if enabled. If no private channel is available, open a minimal public issue requesting private contact **without exploit details, secrets, private logs, or proof-of-concept payloads**.

A useful report includes affected commit/release, environment/kernel, component, preconditions, expected behavior, observed behavior, security impact, minimal reproduction, and trust boundary crossed.

## Protocol changes

Changes to EPN canonicalization, digest/signature algorithms, key roles, evidence chaining, loader verification, or recovery-image verification require explicit version review and deterministic test vectors.

## Sensitive material

Do not publish private keys, recovery keys, disk-unlock material, credential databases, unredacted user evidence logs, or other secrets in public issues or pull requests.
