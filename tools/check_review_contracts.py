#!/usr/bin/env python3
"""Structural and selected semantic consistency checks, NOT firmware/RF qualification."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import sync_reference_tables

EXPECTED_IDF_COMMIT = "76f5dedd9950a3012fee8fb7d5586df21fc67802"


def validate(root: Path) -> dict:
    checks = []

    def test(name, ok, detail=""):
        checks.append({"name": name, "passed": bool(ok), "detail": detail})

    def load(path):
        return json.loads((root / path).read_text(encoding="utf-8"))

    try:
        radio = load("docs/reference/radio-defaults.json")
        boards = load("docs/reference/boards.json")
        resources = load("docs/reference/resource-profiles.json")
        features = load("docs/reference/feature-profiles.json")
        semantic = load("protocol/semantics.json")
        test(
            "idf_exact_pin",
            radio["esp_idf"]
            == {"tag": "v6.0.3", "commit": EXPECTED_IDF_COMMIT},
        )
        test(
            "fixed_baseline",
            radio["radio"]["mode"] == "LR250_FIXED"
            and radio["migration"]["auto_policy"] is False,
        )
        feature_map = features["features"]
        prototype_features = {
            "portable_core",
            "c_api",
            "espnow_lr250_adapter",
            "reference_firmware_builds",
            "development_psk_aead",
            "multi_hop_repair",
            "host_cli",
        }
        test(
            "prototype_status",
            features["implementation_status"] == "core-fixed-250-prototype"
            and features["schema_version"] == 2,
        )
        test(
            "prototype_features_implemented",
            all(
                feature_map[name]["implemented"] is True
                and feature_map[name]["qualified"] is False
                and feature_map[name]["default_enabled"] is False
                and bool(feature_map[name]["evidence"])
                for name in prototype_features
            ),
        )
        test(
            "nothing_falsely_qualified",
            all(
                item["qualified"] is False
                and item["default_enabled"] is False
                for item in feature_map.values()
            ),
        )
        test(
            "production_security_not_claimed",
            feature_map["development_psk_aead"]["implemented"] is True
            and feature_map["development_psk_aead"]["design_target"] is False
            and feature_map["secure_unicast"]["implemented"] is False,
        )
        test(
            "advanced_features_not_claimed",
            all(
                feature_map[name]["implemented"] is False
                for name in {
                    "adaptive_lr500",
                    "automatic_channel_migration",
                    "quorum_authority",
                    "mesh_ota",
                    "service_provider_failover",
                    "tui",
                    "lora_tx",
                    "deep_sleep_resume",
                }
            ),
        )
        test(
            "wire_not_falsely_frozen",
            features["wire_frozen"] is False
            and semantic["wire_frozen"] is False
            and semantic["crypto_suite"] is None
            and semantic["frame_numeric_ids"] is None,
        )
        test(
            "initial_jitter_separate",
            radio["retry"]["initial_data_jitter_ms"] == [0, 0]
            and radio["retry"]["normal_jitter_scope"]
            == "link-retry-only",
        )
        test(
            "semantic_security",
            semantic["counter_independent_of_message_id"] is True
            and semantic["applied_provider_failover_default"] is False
            and semantic["member_traffic_requires_roles_and_crypto"] is True,
        )
        test(
            "usb_credit_kind",
            semantic["usb_credit"] == "session-direction-cumulative-grants",
        )
        test(
            "crc_profile",
            semantic["usb_crc"] == "CRC-32/ISO-HDLC"
            and semantic["usb_crc_check_hex"] == "CBF43926",
        )
        test(
            "frame_size_contract",
            semantic["max_normal_payload_bytes"]
            == radio["buffers"]["normal_payload_max"]
            == 128
            and semantic["max_espnow_body_bytes"]
            == radio["buffers"]["espnow_body_max"]
            == 250,
        )
        allow = semantic["membership_allowlist"]
        member_only = set(semantic["member_only"])
        test(
            "no_nonmember_data",
            all(
                not (member_only & set(types))
                for state, types in allow.items()
                if state != "MEMBER"
            ),
        )
        test(
            "join_bootstrap_allowed",
            {"BOOTSTRAP_AUTH", "BOOTSTRAP_CHUNK", "BOOTSTRAP_REPLY"}
            <= set(allow["AUTHENTICATING"]),
        )
        test(
            "pending_result_fragment",
            {"MEMBERSHIP_RESULT", "BOOTSTRAP_CHUNK"}
            <= set(allow["AUTHORIZED_PENDING_COMMIT"]),
        )
        test("revoked_default_deny", allow["REVOKED"] == [])
        test(
            "aad_disjoint",
            not (set(semantic["end_immutable"]) & set(semantic["hop_mutable"])),
        )
        test(
            "board_runtime_separate",
            boards["schema_version"] == 2
            and all(
                board["published_facts_only"] is True
                and board["qualified_runtime_profile"] is None
                and board["runtime_generation_allowed"] is False
                for board in boards["boards"]
            ),
        )
        for board in boards["boards"]:
            if "gpio_d0_to_d10" not in board:
                test(
                    "wio_conflict_defined",
                    board["exclusive_functions"]
                    == [["base_user_led_gpio21", "wio_button_gpio21"]]
                    and board["tcxo_voltage_v"] is None
                    and board["rf_switch_polarity"] is None,
                )
                continue
            text = (root / board["doc"]).read_text(encoding="utf-8")
            rows = re.findall(
                r"^\|\s*D(\d+)\b[^|]*\|\s*(\d+)\s*\|", text, re.M
            )
            actual = {int(key): int(value) for key, value in rows}
            test(
                "pin_table:" + board["id"],
                actual == dict(enumerate(board["gpio_d0_to_d10"])),
            )
        for name, profile in resources["profiles"].items():
            budget = profile["budget_bytes"]
            test(
                "typed_budget:" + name,
                all(type(value) is int and value >= 0 for value in budget.values()),
            )
            test(
                "budget_total:" + name,
                sum(budget.values()) <= profile["sdk_budget_ceiling_bytes"],
            )
            test(
                "dedup_allocation:" + name,
                budget["dedup_and_compact_receipt_records"]
                >= profile["dedup_entries"] * 64,
            )
            test(
                "bounded_lifetime:" + name,
                profile["max_message_lifetime_ms"] == 30000
                and profile["late_result_ttl_ms"] == 30000,
            )
            test(
                "unmeasured:" + name,
                profile["qualified"] is False
                and profile["measured_peak_bytes"] is None
                and profile["voter_enabled"] is False,
            )
        preauth = resources["preauth"]
        test(
            "preauth_bounded",
            preauth["global_handshakes"] == 1
            and preauth["max_object_bytes"] <= preauth["global_assembly_bytes"]
            and preauth["max_object_bytes"]
            < preauth["authenticated_control_object_max_bytes"],
        )
        test(
            "preauth_cpu_budget",
            preauth["asymmetric_operations_per_second"]
            * preauth["expensive_operation_max_ms"]
            <= preauth["cpu_budget_ms"]
            <= preauth["cpu_window_ms"],
        )
        admission = resources["admission"]
        test(
            "atomic_reservation",
            admission["reservation_order"]
            == ["frame", "dedup", "transaction", "reply_peer", "ack_slot"]
            and admission["partial_reservation_side_effects"] is False,
        )
        test(
            "reply_peer_capacity",
            admission["reply_peer_leases_max"] <= radio["peers"]["transient"]
            and admission["protected_peers_including_regular_pin_max"]
            <= radio["peers"]["total"] - radio["peers"]["broadcast"],
        )
        generated_errors = sync_reference_tables.check(root)
        for error in generated_errors:
            test("generated_table", False, error)
        test("generated_tables_match", not generated_errors)
        disposition = load("docs/reference/review-disposition.json")
        test(
            "all_findings_tracked",
            sorted(finding["id"] for finding in disposition["findings"])
            == list(range(1, 31)),
        )
        test(
            "findings_not_falsely_closed",
            all(
                finding["implementation_verified"] is False
                and finding["remaining_gate"]
                and finding["docs"]
                for finding in disposition["findings"]
            ),
        )
        for finding in disposition["findings"]:
            test(
                f"finding_paths:{finding['id']}",
                all((root / path).is_file() for path in finding["docs"]),
            )
    except (ValueError, KeyError, TypeError, OSError) as error:
        test("schema_read", False, str(error))
    return {
        "scope": "selected-design-contracts-and-document-consistency",
        "checks": len(checks),
        "passed": sum(check["passed"] for check in checks),
        "failed": [check for check in checks if not check["passed"]],
        "firmware_tested": False,
        "rf_tested": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = validate(args.root)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.report:
        args.report.write_text(text + "\n", encoding="utf-8")
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
