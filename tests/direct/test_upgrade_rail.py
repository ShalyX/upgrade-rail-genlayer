import json
import sys

import pytest


GUARD_CONTRACT = "contracts/upgrade_rail.py"
INVARIANTS = [
    {"id": "storage_layout", "rule": "Preserve the declared persistent storage layout."},
    {"id": "upgrade_authority", "rule": "Keep the controller as the sole code upgrader."},
    {"id": "business_rules", "rule": "Preserve the target's stated authorization and value rules."},
]
OLD_CODE = b"class TargetV1: pass"
NEW_CODE = b"class TargetV2: pass"
LAYOUT_HASH = "layout-v1"
TARGET_ADDRESS = "0x3333333333333333333333333333333333333333"


class FakeTarget:
    def __init__(self, controller):
        self.controller = controller
        self.code = OLD_CODE
        self.version = 1
        self.layout_hash = LAYOUT_HASH
        self.dispatched = []

    def view(self):
        return self

    def get_upgrade_context(self):
        return {
            "controller": self.controller,
            "upgraders": [self.controller],
            "code": self.code,
            "version": self.version,
            "layout_hash": self.layout_hash,
        }

    def emit(self, on):
        assert on == "finalized"
        return self

    def apply_upgrade(self, proposal_id, code_hash, version, candidate_code):
        self.dispatched.append((proposal_id, code_hash, version, candidate_code))


def approval(*, passed=None, failed=None, unclear=None, severity="none", confidence="high"):
    passed = passed if passed is not None else [item["id"] for item in INVARIANTS]
    return json.dumps(
        {
            "candidate_code_hash": __import__("hashlib").sha256(NEW_CODE).hexdigest(),
            "decision": "approve" if not failed and not unclear else "reject",
            "passed_invariant_ids": passed,
            "failed_invariant_ids": failed or [],
            "unclear_invariant_ids": unclear or [],
            "severity": severity,
            "confidence_band": confidence,
            "summary": "The declared requirements were reviewed.",
        }
    )


def setup_guard(direct_deploy, direct_vm, direct_alice, monkeypatch):
    direct_vm.sender = direct_alice
    guard = direct_deploy(
        GUARD_CONTRACT,
        3_600,
        json.dumps(INVARIANTS),
        sdk_version="v0.2.16",
    )
    module = sys.modules[guard._instance.__class__.__module__]
    guard_address = "0x" + direct_vm._contract_address.hex()
    target = FakeTarget(guard_address)
    monkeypatch.setattr(module.gl, "get_contract_at", lambda _address: target)
    guard.set_target(TARGET_ADDRESS)
    return guard, target, module


def test_target_with_an_additional_native_code_upgrader_is_rejected(
    direct_deploy, direct_vm, direct_alice, monkeypatch
):
    direct_vm.sender = direct_alice
    fresh_guard = direct_deploy(
        GUARD_CONTRACT, 3_600, json.dumps(INVARIANTS), sdk_version="v0.2.16"
    )
    module = sys.modules[fresh_guard._instance.__class__.__module__]
    controller_address = "0x" + direct_vm._contract_address.hex()
    target = FakeTarget(controller_address)
    target.get_upgrade_context = lambda: {
        "controller": controller_address,
        "upgraders": [controller_address, "0x" + "4" * 40],
        "code": OLD_CODE,
        "version": 1,
        "layout_hash": LAYOUT_HASH,
    }
    monkeypatch.setattr(module.gl, "get_contract_at", lambda _address: target)

    with direct_vm.expect_revert("Target must have this controller as its sole code upgrader"):
        fresh_guard.set_target(TARGET_ADDRESS)


def test_only_policy_owner_can_propose_an_upgrade(
    direct_deploy, direct_vm, direct_alice, direct_bob, monkeypatch
):
    guard, _target, module = setup_guard(
        direct_deploy, direct_vm, direct_alice, monkeypatch
    )
    direct_vm.sender = direct_bob

    with direct_vm.expect_revert("Only the upgrade owner may propose code"):
        guard.propose_upgrade("release-2", 2, LAYOUT_HASH, "Routine release", NEW_CODE)


def test_proposal_requires_a_complete_consensus_review_and_binds_exact_code(
    direct_deploy, direct_vm, direct_alice, monkeypatch
):
    guard, _target, _module = setup_guard(
        direct_deploy, direct_vm, direct_alice, monkeypatch
    )
    direct_vm.mock_llm(r"(?s).*UpgradeRail.*", approval())

    guard.propose_upgrade("release-2", 2, LAYOUT_HASH, "Routine release", NEW_CODE)

    proposal = guard.get_proposal("release-2")
    assert proposal["status"] == "approved"
    assert proposal["candidate_code_hash"] == __import__("hashlib").sha256(NEW_CODE).hexdigest()
    assert json.loads(proposal["passed_invariant_ids_json"]) == sorted(
        item["id"] for item in INVARIANTS
    )
    assert proposal["failed_invariant_ids_json"] == "[]"
    assert proposal["unclear_invariant_ids_json"] == "[]"


def test_incomplete_review_partition_reverts(
    direct_deploy, direct_vm, direct_alice, monkeypatch
):
    guard, _target, _module = setup_guard(
        direct_deploy, direct_vm, direct_alice, monkeypatch
    )
    incomplete = json.dumps(
        {
            "candidate_code_hash": __import__("hashlib").sha256(NEW_CODE).hexdigest(),
            "decision": "approve",
            "passed_invariant_ids": ["storage_layout"],
            "failed_invariant_ids": [],
            "unclear_invariant_ids": [],
            "severity": "none",
            "confidence_band": "high",
            "summary": "Incomplete partition.",
        }
    )
    direct_vm.mock_llm(r"(?s).*UpgradeRail.*", incomplete)

    with direct_vm.expect_revert("Review must classify each declared invariant exactly once"):
        guard.propose_upgrade("release-2", 2, LAYOUT_HASH, "Routine release", NEW_CODE)


@pytest.mark.parametrize(
    "response",
    [
        approval(
            passed=["storage_layout", "upgrade_authority"],
            failed=["business_rules"],
            severity="high",
        ),
        approval(severity="critical"),
        approval(severity="none", confidence="low"),
    ],
)
def test_unsafe_consensus_review_is_recorded_as_rejected(
    direct_deploy, direct_vm, direct_alice, monkeypatch, response
):
    guard, _target, _module = setup_guard(
        direct_deploy, direct_vm, direct_alice, monkeypatch
    )
    direct_vm.mock_llm(r"(?s).*UpgradeRail.*", response)

    guard.propose_upgrade("release-2", 2, LAYOUT_HASH, "Routine release", NEW_CODE)
    assert guard.get_proposal("release-2")["status"] == "rejected"


def test_storage_layout_hash_must_match_before_consensus(
    direct_deploy, direct_vm, direct_alice, monkeypatch
):
    guard, _target, _module = setup_guard(
        direct_deploy, direct_vm, direct_alice, monkeypatch
    )

    with direct_vm.expect_revert("Storage layout changes are not supported in v1"):
        guard.propose_upgrade("release-2", 2, "layout-v2", "Migration", NEW_CODE)


def test_approved_upgrade_cannot_be_queued_before_delay_and_dispatches_only_afterward(
    direct_deploy, direct_vm, direct_alice, monkeypatch
):
    guard, target, module = setup_guard(
        direct_deploy, direct_vm, direct_alice, monkeypatch
    )
    direct_vm.mock_llm(r"(?s).*UpgradeRail.*", approval())
    clock = {"now": 1_000}
    monkeypatch.setattr(module.UpgradeRail, "_now", lambda _self: clock["now"])
    guard.propose_upgrade("release-2", 2, LAYOUT_HASH, "Routine release", NEW_CODE)
    with direct_vm.expect_revert("Upgrade delay has not elapsed"):
        guard.queue_upgrade("release-2")

    clock["now"] += 3_600
    guard.queue_upgrade("release-2")

    proposal = guard.get_proposal("release-2")
    assert proposal["status"] == "queued"
    assert target.dispatched == [
        (
            "release-2",
            __import__("hashlib").sha256(NEW_CODE).hexdigest(),
            2,
            NEW_CODE,
        )
    ]


def test_queued_upgrade_can_be_retried_after_a_separate_retry_delay(
    direct_deploy, direct_vm, direct_alice, monkeypatch
):
    guard, target, module = setup_guard(
        direct_deploy, direct_vm, direct_alice, monkeypatch
    )
    direct_vm.mock_llm(r"(?s).*UpgradeRail.*", approval())
    clock = {"now": 10_000}
    monkeypatch.setattr(module.UpgradeRail, "_now", lambda _self: clock["now"])
    guard.propose_upgrade("release-2", 2, LAYOUT_HASH, "Routine release", NEW_CODE)

    clock["now"] += 3_600
    guard.queue_upgrade("release-2")
    with direct_vm.expect_revert("Retry delay has not elapsed"):
        guard.retry_upgrade("release-2")

    clock["now"] += 3_600
    guard.retry_upgrade("release-2")
    assert guard.get_proposal("release-2")["status"] == "queued"
    assert len(target.dispatched) == 2
    assert target.dispatched[0] == target.dispatched[1]


def test_equivalence_compares_every_criterion_and_material_review_field(
    direct_deploy, direct_vm, direct_alice, monkeypatch
):
    guard, _target, module = setup_guard(
        direct_deploy, direct_vm, direct_alice, monkeypatch
    )
    baseline = {
        "candidate_code_hash": "a" * 64,
        "decision": "approve",
        "passed_invariant_ids_json": '["business_rules","storage_layout","upgrade_authority"]',
        "failed_invariant_ids_json": "[]",
        "unclear_invariant_ids_json": "[]",
        "severity": "none",
        "confidence_band": "high",
    }
    changed = dict(baseline, passed_invariant_ids_json='["business_rules","storage_layout"]', unclear_invariant_ids_json='["upgrade_authority"]')

    assert module._reviews_equivalent(baseline, baseline)
    assert not module._reviews_equivalent(baseline, changed)
