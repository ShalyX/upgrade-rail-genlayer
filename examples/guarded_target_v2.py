# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""Example target configured to accept code changes only from UpgradeRail."""

import hashlib

from genlayer import *


ERROR_EXPECTED = "[EXPECTED]"


class GuardedTarget(gl.Contract):
    controller_address: str
    version: u256
    layout_hash: str
    stored_value: str
    last_applied_proposal_id: str

    def __init__(self, controller_address: Address, version: u256, layout_hash: str, initial_value: str):
        self.controller_address = self._address_text(controller_address)
        self.version = u256(version)
        self.layout_hash = layout_hash
        self.stored_value = initial_value
        self.last_applied_proposal_id = ""
        gl.storage.Root.get().upgraders.get().append(Address(self.controller_address))

    def _address_text(self, value) -> str:
        if isinstance(value, bytes):
            return "0x" + value.hex()
        if isinstance(value, int):
            return "0x" + format(value, "040x")
        try:
            return value.as_hex.lower()
        except AttributeError:
            return str(value).strip().lower()

    @gl.public.view
    def get_upgrade_context(self) -> dict:
        root = gl.storage.Root.get()
        return {
            "controller": self.controller_address,
            "upgraders": [self._address_text(address) for address in root.upgraders.get()],
            "version": self.version,
            "layout_hash": self.layout_hash,
            "code": bytes(root.code.get()),
        }

    @gl.public.view
    def get_state(self) -> dict:
        return {
            "version": self.version,
            "layout_hash": self.layout_hash,
            "stored_value": self.stored_value,
            "last_applied_proposal_id": self.last_applied_proposal_id,
        }

    @gl.public.view
    def release(self) -> str:
        return "upgrade-rail-example-v2"

    @gl.public.write
    def apply_upgrade(self, proposal_id: str, code_hash: str, version: u256, candidate_code: bytes) -> None:
        if self._address_text(gl.message.sender_address) != self.controller_address:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Only the configured controller may upgrade code")
        if not proposal_id or len(proposal_id) > 80:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Invalid proposal ID")
        if len(candidate_code) == 0 or hashlib.sha256(candidate_code).hexdigest() != code_hash:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Candidate code hash does not match")

        controller = gl.get_contract_at(Address(self.controller_address))
        approved = controller.view().get_dispatchable_upgrade(proposal_id)
        if (
            approved["status"] != "queued"
            or approved["candidate_code_hash"] != code_hash
            or approved["candidate_code"] != candidate_code
            or int(approved["version"]) != int(version)
            or approved["layout_hash"] != self.layout_hash
        ):
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Upgrade does not match the queued proposal")

        if self.last_applied_proposal_id == proposal_id:
            installed_code_hash = hashlib.sha256(bytes(gl.storage.Root.get().code.get())).hexdigest()
            if int(version) == int(self.version) and installed_code_hash == code_hash:
                controller.emit(on="finalized").confirm_applied(proposal_id, code_hash)
                return
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Proposal was already applied")
        if int(version) != int(self.version) + 1:
            raise gl.vm.UserError(f"{ERROR_EXPECTED} Upgrade version is stale")

        self.version = u256(version)
        self.last_applied_proposal_id = proposal_id
        code = gl.storage.Root.get().code.get()
        code.truncate()
        code.extend(candidate_code)
        controller.emit(on="finalized").confirm_applied(proposal_id, code_hash)

    @gl.public.view
    def is_upgrade_applied(self, proposal_id: str) -> bool:
        return self.last_applied_proposal_id == proposal_id
