# UpgradeRail threat model

## Assets and authority

- Target contract code and its persistent state.
- The controller's fixed invariant policy and approved proposal records.
- The target's native `Root.upgraders` authority.

The example target stores the controller address and adds only that address to its native upgrader list. Its upgrade context reports the native list, and UpgradeRail refuses to bind unless the controller is the sole reported upgrader. UpgradeRail does not add its owner as a target upgrader. The controller is deployed without an upgrader, so its code is locked by GenLayer's default Root-slot locking behavior.

## Threats and controls

| Threat | Control | Remaining limit |
| --- | --- | --- |
| Unauthorized caller invokes target upgrade method | Target checks `msg.sender` against its configured controller; GenLayer Root permissions restrict writes to the controller address; binding rejects a reported extra upgrader | The target controls its own view and could lie; stewards must inspect the deployed target source and Root permissions. Existing targets may not be retrofit-able |
| Candidate bytes change after review | SHA-256 is computed from exact bytes; the controller stores those bytes; target checks hash and full byte equality against the queued proposal | Hashing does not establish that source is correct or safe |
| Owner bypasses consensus or delay | Controller has no direct target code-write privilege; target accepts only its finalized internal message; controller enforces status and minimum delay | A controller implementation bug can invalidate this guarantee |
| Model omits or duplicates a declared invariant | Contract requires an exact, disjoint partition of the complete declared ID set | Validators can still agree on an incorrect interpretation |
| Validators accept materially different reviews | Equivalence compares code hash, decision, each invariant partition, severity, and confidence band | The review can be consistently wrong; agreement is not proof |
| Candidate changes target storage incompatibly | V1 requires the declared layout hash to match and asks validators to inspect field names, types, and order | The layout hash is proposer-supplied; no source compiler proves it matches the code |
| Internal message or acknowledgement is delayed | Proposal remains queued; the exact same bytes can be retried after one hour; target handles an already-applied proposal idempotently | A target that permanently rejects the message can leave the proposal queued; no unsafe cancellation is offered after dispatch |
| Source or release notes contain prompt injection | Prompt marks both source blocks and release notes as untrusted data and requests bounded structured fields | Prompt instructions are not a formal sandbox for model reasoning |

## Deliberate exclusions

UpgradeRail does not certify that a release is vulnerability-free, prove authorship of the candidate, enforce a source repository or build pipeline, or support storage migration. It provides a narrow authority path: only a specific controller can apply a specific reviewed code payload after consensus and a delay.
