# Contributing to JLR

JLR welcomes contributions that make the system smaller, more measurable, more recoverable and easier to audit.

## Before adding a security feature

Write down, in the pull request: the threat or failure addressed; the trust boundary changed; any privileged code added;
the evidence produced; the failure behaviour; the tests; and the rollback or recovery path.

## Design rules

- Unknown is not malicious.
- A hash is identity evidence, not intent. A signature is provenance evidence, not proof of safety.
- A sandbox constrains authority; it does not prove harmlessness.
- Missing enforcement must be visible. Missing evidence is never positive trust.
- Recovery defaults to read-only. Human overrides are explicit and auditable.
- Anything that parses untrusted bytes decodes strictly and is tested with malformed input.
- Identities contain nothing volatile (no timestamps, counters or state).
- Security claims require reproducible tests, and a test is only worth having if it fails when the check it guards is removed.

## Workflow

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 tools/gen_records.py          # if you changed a record or enumeration
python3 tools/check_vectors.py        # independent check of the protocol vectors
```

Boot and gate tests need QEMU and a suitable kernel; they skip loudly when those are missing. See
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the environment, for how to mutation-check a control, and for the rules on
`unsafe` (only in the two `sys.rs` modules, each block commented).

Architecture changes update the relevant document. Durable design changes add or supersede an entry in
[docs/DECISIONS.md](docs/DECISIONS.md). Wire-format changes follow the version rules in
[docs/INTEGRITY_PROTOCOL.md](docs/INTEGRITY_PROTOCOL.md) and regenerate the vectors in the same change.

Security-relevant tests should cover allow, deny, malformed input, state transition, failure mode, evidence output and
recovery where applicable.

## Scope

The first target is x86_64 Linux. Portability work must preserve concrete enforcement guarantees.

Contributions are provided under the GNU Affero General Public License v3.0.
