# JLR Security Invariants

These are testable implementation requirements. Each carries a status, stated honestly:

- **Upheld**: the code enforces it and a test fails if the enforcement is removed.
- **Partly**: enforced for part of the surface; the gap is stated.
- **Designed**: specified, not built.

Where an invariant holds only in a particular deployment, the deployment is named.

## I-01 - No implicit trust promotion

An artifact MUST NOT move from UNKNOWN, QUARANTINED, or OBSERVED to VERIFIED or ADMITTED without a recorded policy decision and supporting evidence.

**Upheld.** `jlr-policy` returns `VERIFIED`/`ADMITTED` only from a tier whose evidence is present or from a signed approval; the engine records each transition with its evidence digest. *Tests:* `no_promotion_without_matching_evidence` (property), `missing_evidence_never_promotes`, `state_machine_matches_specification`; the policy validator refuses a policy that would admit on nothing.

## I-02 - Identity before policy

Policy decisions about an artifact MUST be bound to a cryptographic identity, not only a pathname or package name.

**Upheld.** Decisions are per EPN, the SHA-256 of a record containing the content digest. *Tests:* `epn_id_is_content_addressed_and_stable`, `identical_bytes_at_different_paths_have_different_epns_but_equal_digests`.

## I-03 - Immutable expected state

A component being measured MUST NOT be able to silently rewrite its own expected measurement and then satisfy verification.

**Partly.** In the engine, state is rebuilt from the signed ledger and never from a cache (`state_is_rebuilt_from_the_ledger_not_from_caches`); a changed file gets a new identity and its old one is degraded. In the boot chain the manifest is verified before the image is used. **Gap:** the rollback floor lives on the boot media, so a media writer can lower it until it moves to a TPM counter; in companion mode a process that can write the state directory and read the policy key can re-sign policy.

## I-04 - Separation of evidence and decision

Raw measurements MUST be retained independently from the conclusion produced from them.

**Upheld.** Each observation's evidence is stored as a content-addressed object; the decision is a separate record; the ledger event names the evidence by digest, and objects are made durable before the events that name them.

## I-05 - Host cannot authorize JLR

The host OS MUST NOT be able to promote JLR core components, rewrite root policy, or erase historical security events through ordinary host privileges.

**Partly, by deployment.** *Supervisor:* the base is RAM-resident, read-only and verified before use, so the host cannot alter it; the ledger and policy live in state the host does not mount. *Companion:* **does not hold against host root**, which can read the policy key and rewrite the state directory. Companion reports say so (`assurance: companion`). Signed objects still cannot be forged by a process without the key, and a rollback of the whole directory is detectable against an off-machine checkpoint.

## I-06 - Least capability

Admission MUST grant an explicit capability set. Absence of a capability means denial.

**Upheld.** Only artifacts that run normally, and only outside CELL-0, receive requested capabilities; high-risk ones are never granted without an approval; capability strings are canonical and paths normalised. *Tests:* `decisions_are_always_internally_consistent`, `high_risk_capabilities_are_withheld_and_ask_a_human`, `capability_rejects_malformed_and_traversal`.

## I-07 - State transitions are auditable

Every trust-state transition MUST record old state, new state, evidence, policy version, actor, and time.

**Upheld.** Every `TRANSITION` event carries `old_state`, `new_state`, the evidence digest, the policy digest, the actor and time; a promotion that skips a state is recorded as each legal step. *Test:* `baseline_admits_managed_software_and_tampering_degrades_it`, `approval_promotes_step_by_step_with_a_manual_basis`.

## I-08 - Degradation on mismatch

A verified artifact whose protected identity changes MUST leave VERIFIED/ADMITTED state until re-evaluated.

**Upheld.** A change of content at a path creates a new EPN and degrades the old one; the exec gate re-measures when size, mtime or ctime change and expires verdicts by age. *Tests:* the tamper test in the engine; QEMU `tampered known: BLOCKED`; `unchanged_files_are_rehashed_once_their_evidence_is_older_than_the_policy_allows`.

## I-09 - Recovery independence

At least one supported recovery path MUST remain bootable without executing the host OS.

**Partly.** The boot chain runs nothing from the host (`base mounted read-only from RAM`, media released) and falls back across slots or refuses. **Gap:** the recovery *tools* (read-only inspection, export) are designed; the independent medium is not yet a shipped image.

## I-10 - Signed base

A production JLR base image MUST have authenticated release metadata.

**Upheld for the image, not yet for the loader.** A manifest signed by a trusted key with the release role is required, and the image must match its digest and size (QEMU: tampered image, tampered manifest, unknown signer, wrong role). **Gap:** the initramfs that holds the anchors is not authenticated by firmware until the unified-kernel-image milestone.

## I-11 - No silent policy fallback

If trusted policy cannot be loaded or validated, JLR MUST NOT silently substitute permissive defaults.

**Upheld.** The engine refuses to open on a policy, revocation list or anchor set that fails verification or validation; a stale epoch is refused as a rollback; unverifiable baselines and approvals are ignored and logged. *Tests:* `a_tampered_policy_is_refused_and_no_default_is_substituted`, `a_policy_signed_by_the_wrong_role_is_refused`, `policy_epoch_cannot_go_backwards`, `unverifiable_approvals_grant_nothing_and_are_logged`, `validation_rejects_unsafe_policies`.

## I-12 - Monotonic evidence

Security event history MUST be append-only during normal operation and hash chained or equivalently tamper evident.

**Upheld for tampering within the directory; rollback of the whole directory needs an external checkpoint.** Signed, hash-linked, Merkle-committed events; every single-bit change to the log is an error; a torn tail is quarantined, never deleted. A whole-directory rollback to an older self-consistent state is detected only against a checkpoint held elsewhere (`truncation_is_caught_only_with_a_checkpoint`, `checkpoints_detect_rollback_of_the_whole_state_directory`).

## I-13 - Explicit override

An operator override MUST be represented as an override, never rewritten as automatic verification.

**Upheld.** Approvals and baselines produce `basis = MANUAL_OVERRIDE`, the weakness that was overridden stays in the reasons, and the enrolment is its own `OVERRIDE` event. *Test:* `approval_raises_unknown_software_and_is_recorded_as_override`.

## I-14 - Revocation wins

A valid revocation applicable to an artifact MUST take precedence over stale admission evidence.

**Upheld.** First in the decision function, over approvals and baselines, and terminal. *Tests:* `revocation_dominates_everything` (property), `approval_never_lifts_revocation_or_prohibition`.

## I-15 - Minimal mutable core

Runtime-writable state in the trusted computing base MUST be minimized and separately mounted from immutable code.

**Upheld in the boot chain** (read-only RAM base, tmpfs for `/run` and `/tmp`), **Partly in companion mode** (the binaries live wherever they were installed).

## I-16 - Jail escape is trust failure

Evidence of jail escape, unauthorized namespace crossing, policy-bypass, or forbidden device access MUST immediately degrade or revoke the responsible workload.

**Designed.** The controls that prevent the crossings are implemented and tested, but there is no telemetry loop that turns a denied syscall into a state change. See [JAIL_MODEL.md](JAIL_MODEL.md) section 11.

## I-17 - Deterministic decision replay

Given the same policy version and same normalized evidence set, the Trust Engine SHOULD reproduce the same decision.

**Upheld.** `evaluate` is pure; decisions are canonically ordered; the evidence order does not matter. *Test:* `evaluation_is_deterministic_and_order_independent` (property, 2000 cases).

## I-18 - Explicit recovery writes

Recovery mode MUST mount host storage read-only by default. Any write operation requires an explicit recovery action.

**Designed.** No recovery mount code exists yet.

## Added by the implementation

## I-19 - The measured bytes are the executed bytes

What is executed MUST be the exact byte sequence that was measured, whatever happens to the path or the original file afterwards.

**Upheld for launches and the gate.** Files are hashed through the descriptor that will be used; `jlr run` copies that descriptor into a sealed memfd, re-hashes while copying, refuses a mismatch, and executes the sealed copy; the gate measures the descriptor the kernel delivers. *Tests:* `executed_bytes_are_the_measured_bytes_even_if_the_file_is_replaced_or_edited`, `sealing_refuses_content_that_changed_after_measurement`, `exec_verdict_measures_the_descriptor_not_the_path`, `measured_descriptor_is_the_file_that_was_hashed_even_if_the_path_is_swapped`. **Gap:** the gate does not see code loaded by `mmap` (for example `ld.so /path`).

## I-20 - Identity is content-addressed and time-free

An EPN MUST be a function of the artifact's identity record alone and MUST NOT change when the same bytes are observed again.

**Upheld.** *Tests:* `identity_is_stable_across_observations`, `the_same_file_has_the_same_identity_at_different_times`, and the pinned vectors. A first implementation broke this; see [DECISIONS.md](DECISIONS.md) ADR-016.

## I-21 - Missing enforcement is never reported as full enforcement

Every cell launch MUST report which requested controls are active and which are unavailable; a missing mandatory control MUST refuse the launch and run nothing.

**Upheld.** *Tests:* `missing_mandatory_control_refuses_and_runs_nothing`, `report_accounts_for_every_requested_control`; `jlr doctor` prints the same report on a live cell.

## I-22 - A checkpoint vouches for exactly what it commits to

A signed ledger checkpoint MUST commit to a size and Merkle root; a verifier MUST treat events below it as authenticated by that root, and MUST verify every signature after it.

**Upheld.** *Tests:* `checkpointed_prefix_is_covered_by_the_signed_root_not_by_per_event_signatures`, `events_after_the_newest_checkpoint_are_always_verified_in_full`, `any_single_bit_flip_is_still_detected_on_the_fast_path`. `jlr ledger verify` verifies every signature.

## I-23 - Boot authenticates before use, spends a try before boot, and raises the floor only after health

The boot chain MUST verify a slot's manifest and image before mounting it, record the boot attempt durably before using an unproven slot, and raise the rollback floor only after the booted system passes its health check.

**Upheld** (prototype anchor). *Tests:* the QEMU boot scenarios plus `a_crashing_update_falls_back_to_the_old_slot_after_its_tries`, `success_raises_the_floor_and_strands_older_releases`, and `choose_never_violates_its_invariants` (property).

## I-24 - Signatures are bound to record type and node

A signature MUST verify only for the record type, node scope, algorithm and key role it was made for.

**Upheld.** *Tests:* `signature_is_bound_to_record_type_and_scope`, `record_type_confusion_is_rejected_even_with_forged_header`, `wrong_role_and_unknown_key_are_rejected`, `any_single_bit_flip_is_rejected`, `signature_malleability_is_rejected`, `a_release_signed_by_a_key_with_the_wrong_role_is_refused` (QEMU), and the independent checker.

## I-25 - Epochs never go backwards

A policy epoch, a revocation epoch and a release epoch MUST NOT be replaced by a lower one once a higher one has been recorded.

**Partly.** Policy and revocation epochs: **upheld** against the ledger. Release epochs: upheld against the floor on the media, which is itself unanchored until a TPM counter exists.

## I-26 - Decoding is strict

Every accepted byte string MUST re-encode to itself; unknown, missing, mistyped, duplicate, out-of-order, oversized or trailing input MUST be an error.

**Upheld.** *Tests:* `accepted_input_is_canonical` (property), the rejection suites, `capability_cbor_rejects_non_canonical_text`, and the independent decoder in `tools/check_vectors.py`.

## I-27 - The exec gate's failure modes are explicit

Enforcement MUST change only through a signed policy epoch; a policy denial MUST NOT be fail-open; an internal gate error MUST be recorded and MUST fail open unless configured otherwise.

**Upheld.** *Tests (QEMU):* audit records without blocking; `policy enforce on` makes the kernel deny unknown and tampered binaries with `EPERM`; stopping the daemon releases the gate. Fail-closed-on-error is a flag; its test is **not yet written**.
