# UpgradeRail

UpgradeRail is a contract-only GenLayer primitive for controlled in-place upgrades of Intelligent Contracts. A target names UpgradeRail as its only native code upgrader. UpgradeRail reviews exact candidate source against fixed owner-declared invariants through GenLayer consensus, enforces a delay, and sends the approved bytes to the target in a finalized internal message.

The repository contains the controller, a guarded target example, an example v2 release, direct behavioral tests, an end-to-end simulator scenario, and a threat model. There is no frontend or fake deployment flow.

The [Studio verification record](docs/live-studio-verification.md) links the deployed controller, managed target, successful upgrade, and two finalized rollback tests. The checked-in v2 example is byte-identical to the reviewed and installed source.

## Why this uses GenLayer

Upgrade authorization and timing are enforced with deterministic contract checks. The review asks validators to interpret whether a code change preserves a human-readable invariant set, including authorization and behavior that are difficult to compare with a byte-level hash alone. Validators must agree on the exact candidate hash, decision, full invariant partition, severity, and confidence band before a proposal can be approved.

The hash and the delay do not prove the candidate is safe. They make the reviewed bytes and the enforced approval path auditable. See [the threat model](docs/threat-model.md).

## Upgrade lifecycle

1. Deploy an immutable UpgradeRail controller with a minimum delay and fixed invariant set.
2. Deploy the target with the controller address. The target adds only that address to GenLayer's native `Root.upgraders` list and reports the list in its upgrade context.
3. Link the target to the controller once with `set_target`. It checks the target-reported native upgrader list and rejects any target reporting another upgrader. This report must be backed by review of the target source; a malicious target can lie about its own view.
4. The owner proposes a new version, the unchanged storage-layout hash, release notes, and exact UTF-8 Python source bytes.
5. The non-deterministic review fetches the current target source and independently evaluates current and candidate code against every invariant. Malformed, incomplete, conflicting, or unsafe outcomes cannot authorize an upgrade.
6. After an approved proposal's delay, anyone can call `queue_upgrade`. The controller emits the exact reviewed bytes to the target only after the queue transaction finalizes.
7. The target checks the sender, proposal state, version, hash, and bytes before replacing its code slot. After the target transaction finalizes, it acknowledges completion to UpgradeRail.

V1 rejects declared storage-layout changes. An exact layout hash match is a deterministic gate; the source review also checks the actual field declarations. The hash itself is owner-supplied metadata, not a compiler-derived proof.

## Deploy and configure

Use the same network for both contracts. The controller must be deployed first so its address is available to the target.

1. Deploy `contracts/upgrade_rail.py` with:
   - `minimum_delay`: seconds, from 3,600 through 2,592,000.
   - `invariants_json`: a JSON list of 1–8 `{ "id", "rule" }` objects. Keep IDs stable and rules specific. For example:

   ```json
   [
     {"id":"storage_layout","rule":"Keep every persistent field name, type, and order unchanged."},
     {"id":"upgrade_authority","rule":"Keep this controller as the only Root code upgrader."},
     {"id":"value_rules","rule":"Preserve the target's authorization and value-handling rules."}
   ]
   ```

2. Deploy `examples/guarded_target.py` with:
   - the controller address;
   - version `1`;
   - a non-empty storage-layout identifier, such as `storage-v1-controller-version-layout-value-last-proposal`;
   - the initial target value.

   In Studio, the `Address` constructor field may be decoded as an integer
   even when the value was entered as a hex address. The example normalizes
   both representations before installing the controller in `Root.upgraders`.
   Use the deployed `UpgradeRail` contract address here—not the deployer
   wallet address.
3. Call `set_target(target_address)` from the controller owner. The controller verifies that the target names this exact controller.
4. Call `propose_upgrade(proposal_id, next_version, candidate_layout_hash, release_notes, candidate_code_bytes)` from the controller owner. The version must increase by one and the layout hash must match the target.
   In Studio's generic `bytes` input, encode the exact UTF-8 source as `b#` followed by hex bytes. Do not use base64 or normalize line endings: the example source files retain the CRLF bytes used in the live review.
5. Read `get_proposal(proposal_id)` until its status is `approved` or `rejected`. If approved, wait until `apply_after`, then call `queue_upgrade(proposal_id)`.
6. Follow both GenLayer transactions to `Finalized`: the controller queue and the target's child upgrade. The target's finality-gated acknowledgement updates the proposal status to `applied`. If that acknowledgement is delayed, `retry_upgrade` can re-dispatch the same bytes after another hour; the target handles a repeated application idempotently.

The target integration must retain the storage fields and the `apply_upgrade` entry point in later releases. Review the target source and its deployment permissions: the controller can check the target's reported upgrader list, but cannot independently read another contract's native Root slots. Existing deployed ICs cannot gain this protection retroactively unless their current code and Root upgrader permissions already permit the guarded integration.

## Contract surface

### UpgradeRail

- `set_target(address)` — one-time link to a target configured for this controller.
- `propose_upgrade(id, version, layout_hash, notes, code)` — owner-only consensus review.
- `queue_upgrade(id)` — permissionless dispatch after the enforced delay.
- `retry_upgrade(id)` — permissionless same-byte retry after the retry delay.
- `get_proposal(id)`, `get_policy()` — public review and lifecycle state.
- `get_dispatchable_upgrade(id)` — target-facing view, available only while queued.
- `confirm_applied(id, hash)` — target-only completion acknowledgement.

### Guarded target example

- `get_upgrade_context()` — exposes version, layout identifier, configured controller, and current code bytes to the reviewer.
- `apply_upgrade(...)` — accepts only the configured controller and exact queued proposal.
- `get_state()` — demonstrates that application data survives a compatible code replacement.

## Run checks

```powershell
python -m pip install -r requirements.txt
python -m pytest -p no:cacheprovider tests -q
python -m genvm_linter.cli check --json contracts/upgrade_rail.py
python -m genvm_linter.cli check --json examples/guarded_target.py
python -m genvm_linter.cli check --json examples/guarded_target_v2.py
```

The direct suite covers owner authority, exact code-hash binding, complete and disjoint invariant classification, rejection of failed/unclear/high-severity/low-confidence reviews, layout and version gates, timelock enforcement, and retry behavior. The simulator scenario deploys both contracts, runs the review, advances the delay, dispatches the real internal message, checks target state and installed code bytes, and rejects a direct attacker call.

`tests/test_release_artifact.py` also checks that the v2 file hashes to the approved Studio candidate and differs from the v1 file only by the new read-only `release()` method. The simulator supplies a controlled review response; the separate Studio record documents the live consensus path.

## Limits

- Consensus review is not a formal security proof or a substitute for human code review.
- A proposer can submit false release notes or a misleading declared layout hash; validators inspect source, but their judgment can be wrong.
- The controller is intentionally frozen after deployment. If it has a defect, a new controller and target integration may be required.
- V1 does not support storage migrations, multi-controller governance, cancellation after dispatch, or recovery from a target that permanently rejects valid controller messages.
- The Studio deployment is a public test-network demonstration, not a production security audit. A finalized transaction can still have a GenVM rollback; check its execution result and contract state.
