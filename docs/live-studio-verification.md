# Live Studio verification — 3 October 2026

UpgradeRail was exercised on the GenLayer Studio network with normal, five-validator consensus. The controller, target, and transaction receipts below are public evidence. Studio is a test network; this is a runtime demonstration, not a production security audit.

| Item | Verified value |
| --- | --- |
| Controller | [`0xFA73EAfa27b44b79eA35a0902422CC4Ef373734d`](https://explorer-studio.genlayer.com/address/0xFA73EAfa27b44b79eA35a0902422CC4Ef373734d) |
| Managed target | [`0x43154eEa11365F395337fF022e59A15Be16dBEaE`](https://explorer-studio.genlayer.com/address/0x43154eEa11365F395337fF022e59A15Be16dBEaE) |
| Proposal ID | `v2-release-20261003-hex` |
| Approved candidate SHA-256 | `0ef466430f79f322d60c7239c7d15a98b0f621d922fe1c9cd374b20ca221f7b0` |
| Minimum delay | 3,600 seconds |

The owner proposed the exact bytes of [`examples/guarded_target_v2.py`](../examples/guarded_target_v2.py) in [this transaction](https://explorer-studio.genlayer.com/tx/0x1a37102e2938ed230a83560dffbd101a80559bb928bdb13fb2c8cae903cbd22d). The finalized proposal read showed `decision: approve`, all three invariant IDs (`storage_layout`, `upgrade_authority`, `value_rules`) passed, no failed or unclear IDs, `severity: none`, and `confidence_band: high`. After the delay, [the queue transaction](https://explorer-studio.genlayer.com/tx/0x1aa8cba24cd8eebfa07caa26c577dd0874739fadd0009bd0267d37f262f8fb55) finalized. A subsequent finalized controller read showed `status: applied`.

The target's finalized `get_state()` read showed `version: 2`, `last_applied_proposal_id: v2-release-20261003-hex`, and the unchanged `stored_value: preserved state`. The new `release()` view returned `upgrade-rail-example-v2`. Reading the target's installed source from `get_upgrade_context()` produced the candidate SHA-256 above. The checked-in v1 and v2 files are exact source-byte artifacts: v2 adds only the read-only `release()` method to v1. Their CRLF line endings are intentionally preserved by `.gitattributes`.

Two further live calls checked failure paths after application:

- [Re-queueing the applied proposal](https://explorer-studio.genlayer.com/tx/0x3d3bd29d88e8c5e4d1a60f0fb4f04dbbf85a8b7e6d96ea11447b36e54fa36d98) finalized with a GenVM `Rollback`: `[EXPECTED] Proposal is not approved`.
- [Calling `apply_upgrade` directly from the owner wallet](https://explorer-studio.genlayer.com/tx/0x5c9a47c5c690b6d520088cbae97613aee540a7217b5c1cfb18426e56d6a5ab73), with the approved hash and exact candidate bytes, finalized with a GenVM `Rollback`: `[EXPECTED] Only the configured controller may upgrade code`.

A finalized target read after both rejected calls still showed version 2 and `preserved state`. `FINALIZED` and consensus `Accepted` describe transaction processing, not necessarily successful GenVM execution; the two negative transactions rolled back as intended.

To reproduce from a fresh deployment, follow the [README deployment steps](../README.md#deploy-and-configure). Use the v1 example for the initial target, and pass the v2 file's exact bytes to Studio's `bytes` field as `b#` plus hexadecimal UTF-8 bytes. Do not paste the source as a string or use base64. Wait at least the configured hour before queueing.
