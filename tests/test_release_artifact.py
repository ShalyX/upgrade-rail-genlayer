"""Keep the published v2 example identical to the reviewed Studio release."""

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
V2_SOURCE = ROOT / "examples" / "guarded_target_v2.py"
V1_SOURCE = ROOT / "examples" / "guarded_target.py"
APPROVED_CODE_HASH = "0ef466430f79f322d60c7239c7d15a98b0f621d922fe1c9cd374b20ca221f7b0"


def test_v2_example_matches_approved_onchain_code() -> None:
    assert hashlib.sha256(V2_SOURCE.read_bytes()).hexdigest() == APPROVED_CODE_HASH


def test_v2_changes_only_the_release_view() -> None:
    v1 = V1_SOURCE.read_bytes()
    anchor = b"    @gl.public.write\r\n    def apply_upgrade"
    release_view = (
        b"    @gl.public.view\r\n"
        b"    def release(self) -> str:\r\n"
        b'        return "upgrade-rail-example-v2"\r\n\r\n'
    )
    assert v1.count(anchor) == 1
    assert V2_SOURCE.read_bytes() == v1.replace(anchor, release_view + anchor)
