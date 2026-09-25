# Contributing to JLR

JLR welcomes contributions that make the system smaller, more measurable, more recoverable, and easier to audit.

## Before adding a security feature

Document the threat/failure addressed, trust boundary changed, privileged code added, evidence produced, failure behavior, tests, and rollback/recovery path.

## Design rules

- Unknown is not malicious.
- A hash is identity evidence, not intent.
- A signature is provenance evidence, not proof of safety.
- A sandbox constrains authority; it does not prove harmlessness.
- Missing enforcement must be visible.
- Recovery defaults to read-only.
- Human overrides are explicit and auditable.
- Complex untrusted parsers should be isolated.
- Security claims require reproducible tests.

Architecture changes SHOULD update the relevant docs file. Durable design changes SHOULD add or supersede an entry in docs/DECISIONS.md.

Security-relevant tests SHOULD cover allow, deny, malformed input, state transition, failure mode, evidence output, and recovery where applicable.

The first implementation target is Linux. Portability work should preserve concrete enforcement guarantees.

Contributions are provided under the GNU Affero General Public License v3.0.
