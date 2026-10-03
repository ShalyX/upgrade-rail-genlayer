import hashlib
import json
from pathlib import Path

import pytest

from glsim.engine import SimEngine
from glsim.state import StateStore


ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "contracts" / "upgrade_rail.py"
TARGET = ROOT / "examples" / "guarded_target.py"
NEXT_CODE = ROOT / "examples" / "guarded_target_v2.py"
OWNER = "0x1111111111111111111111111111111111111111"
ATTACKER = "0x2222222222222222222222222222222222222222"
LAYOUT_HASH = "storage-v1-controller-version-layout-value-last-proposal"
INVARIANTS = [
    {"id": "storage_layout", "rule": "Preserve all persistent fields and their types."},
    {"id": "upgrade_authority", "rule": "Keep UpgradeRail as the only Root code upgrader."},
    {"id": "value_rules", "rule": "Preserve the stored value and access rules."},
]


def review_response(candidate_code: bytes) -> str:
    return json.dumps(
        {
            "candidate_code_hash": hashlib.sha256(candidate_code).hexdigest(),
            "decision": "approve",
            "passed_invariant_ids": [item["id"] for item in INVARIANTS],
            "failed_invariant_ids": [],
            "unclear_invariant_ids": [],
            "severity": "none",
            "confidence_band": "high",
            "summary": "The example release preserves the declared invariants.",
        }
    )


def test_guarded_target_upgrade_runs_through_finalized_controller_messages(monkeypatch):
    engine = SimEngine(StateStore(seed="upgrade-rail-lifecycle"))
    engine.activate()
    try:
        controller_address, _ = engine.deploy(
            str(GUARD), [3_600, json.dumps(INVARIANTS)], sender=OWNER
        )
        target_address, _ = engine.deploy(
            str(TARGET),
            [controller_address, 1, LAYOUT_HASH, "preserved state"],
            sender=OWNER,
        )
        engine.call_method(
            controller_address,
            "set_target",
            [target_address],
            sender=OWNER,
        )
        context = engine.call_method(
            target_address, "get_upgrade_context", [], sender=OWNER
        )
        assert context["upgraders"] == [controller_address]

        controller = engine._instances[controller_address.lower()]
        clock = {"now": 1_000}
        monkeypatch.setattr(controller, "_now", lambda: clock["now"])
        candidate_code = NEXT_CODE.read_bytes()
        engine.vm.mock_llm("UpgradeRail", review_response(candidate_code))

        engine.call_method(
            controller_address,
            "propose_upgrade",
            ["release-2", 2, LAYOUT_HASH, "Retain state and add version reporting.", candidate_code],
            sender=OWNER,
        )
        proposal = engine.call_method(
            controller_address,
            "get_proposal",
            ["release-2"],
            sender=OWNER,
        )
        assert proposal["status"] == "approved"

        clock["now"] += 3_600
        engine.call_method(
            controller_address,
            "queue_upgrade",
            ["release-2"],
            sender=ATTACKER,
        )

        # glsim drains a target's finalized acknowledgement in the parent
        # call's stack. Replay that acknowledgement as its own transaction so
        # the simulator commits it after the controller's queue transaction,
        # matching the network's asynchronous finality boundary.
        engine.call_method(
            controller_address,
            "confirm_applied",
            ["release-2", hashlib.sha256(candidate_code).hexdigest()],
            sender=target_address,
        )

        proposal = engine.call_method(
            controller_address,
            "get_proposal",
            ["release-2"],
            sender=OWNER,
        )
        state = engine.call_method(target_address, "get_state", [], sender=OWNER)
        context = engine.call_method(
            target_address, "get_upgrade_context", [], sender=OWNER
        )
        assert proposal["status"] == "applied"
        assert state["version"] == 2
        assert state["stored_value"] == "preserved state"
        assert state["last_applied_proposal_id"] == "release-2"
        assert context["code"] == candidate_code

        with pytest.raises(Exception, match="Only the configured controller"):
            engine.call_method(
                target_address,
                "apply_upgrade",
                ["attacker-release", "a" * 64, 3, candidate_code],
                sender=ATTACKER,
            )
    finally:
        engine.deactivate()


def test_guarded_target_accepts_address_decoded_as_integer_by_studio():
    engine = SimEngine(StateStore(seed="upgrade-rail-address-int"))
    engine.activate()
    try:
        controller_address = "0x21ce14382d83208a866125ec239839a3cc98ac6a"
        target_address, _ = engine.deploy(
            str(TARGET),
            [int(controller_address, 16), 1, LAYOUT_HASH, "preserved state"],
            sender=OWNER,
        )

        context = engine.call_method(
            target_address, "get_upgrade_context", [], sender=OWNER
        )

        assert context["controller"] == controller_address
        assert context["upgraders"] == [controller_address]
    finally:
        engine.deactivate()
