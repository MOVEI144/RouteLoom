#!/usr/bin/env python3
"""Structural and selected semantic consistency checks, NOT firmware/RF qualification."""
from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path

import sync_reference_tables

EXPECTED_IDF_COMMIT = "76f5dedd9950a3012fee8fb7d5586df21fc67802"

# sizeof(MeshNode::DedupEntry) measured on the host toolchain (sdk-completion
# 02 §2.4): the phase + first_seen_ms fields grew the record 144 B -> 152 B.
# The profile dedup budget must cover this real record — reconcile the
# budget, never shrink the record (static_assert ceiling in node.hpp: 176 B).
DEDUP_ENTRY_BYTES = 152

# ESP-NOW link overhead per transmitted frame (preamble-independent fixed
# header/trailer cost) — a radio-physical constant of the LR250 profile,
# not a tuneable contract (issue #47 premises).
ESPNOW_MAC_OVERHEAD_BYTES = 43

# Acceptance IDs with no host test by construction (P3-10): hardware-in-
# the-loop measurements. The trace check below requires every other
# design-table ID to be tagged in tests/ or host/.
ACCEPTANCE_HIL_ONLY = {
    "V1-J15": "02 §14: join/ECC timing on C3/S3 hardware",
    "V1-N08": "05 §8: nvs_get_stats() budget cross-check on C3",
    "V1-F06": "06 §9: 6+ node power-on recovery timing",
}

# Acceptance IDs with no host test yet (P3-10): explicitly triaged so
# the trace check stays a closed loop; each needs a future test.
ACCEPTANCE_NO_HOST_TEST = {
    "V1-F04": "relay-stop route-switch handshake count (needs routing+session integration)",
}

ACCEPTANCE_ID_RE = re.compile(r"\bV1-[A-Z]\d+\b")
# The six design acceptance tables currently define 62 stable IDs. Keep
# their roster independent of the table scan so deleting a table row
# cannot silently shrink the set being checked.
ACCEPTANCE_SERIES_END = {"J": 15, "K": 12, "R": 10, "N": 8, "F": 8, "H": 9}
EXPECTED_ACCEPTANCE_IDS = {
    f"V1-{series}{number:02d}"
    for series, end in ACCEPTANCE_SERIES_END.items()
    for number in range(1, end + 1)
}


def acceptance_test_sources(root: Path):
    """Only executable test sources can establish an acceptance trace."""
    for path in (root / "tests").rglob("test_*"):
        if path.is_file() and path.suffix in {".cpp", ".py"}:
            # Checker mutation tests mention IDs as decoys; they are not
            # evidence for the protocol acceptance cases themselves.
            if path.suffix == ".py" and "from check_review_contracts import" in path.read_text(
                encoding="utf-8"
            ):
                continue
            yield path
    for path in (root / "host").rglob("*.rs"):
        if "target" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        if re.search(r"#\[(?:tokio::)?test\]", source):
            yield path

# Frozen Wire v1 frame type IDs (CORE_FIXED_250 profile). Mirrors
# FrameType in components/routeloom/include/routeloom/types.hpp.
EXPECTED_FRAME_IDS = {
    "DISCOVER": 1,
    "OFFER": 2,
    "BOOTSTRAP_AUTH": 3,
    "MEMBERSHIP_RESULT": 4,
    "BOOTSTRAP_CHUNK": 5,
    "BOOTSTRAP_REPLY": 6,
    "MEMBERSHIP_QUERY": 7,
    "DATA": 16,
    "HOP_ACCEPT": 17,
    "END_RECEIPT": 18,
    "APP_RESULT": 19,
    "BUSY": 20,
    "SERVICE": 21,
    "CONTROL": 22,
    "TIME_SYNC": 23,
    "CHANNEL_NOTICE": 24,
    "GROUP_DATA": 25,
    "GROUP_REPORT": 26,
    "ROUTE_UPDATE": 32,
    "ROUTE_WITHDRAW": 33,
    "SEQNO_REQUEST": 34,
    "ROUTE_REQUEST": 35,
    "NEIGHBOR_PROBE": 40,
    "NEIGHBOR_RESULT": 41,
    "DIAGNOSTIC": 48,
    "CONTROL_OBJECT": 49,
    "OBJECT_CHUNK": 50,
    "OBJECT_ACK": 51,
}


# make_end_aad() write expression -> semantics.json end_aad_fields name.
END_AAD_SOURCE_NAMES = {
    "kMajor": "version_major",
    "kMinor": "version_minor",
    "header.type": "type",
    "header.flags": "flags",
    "header.delivery": "delivery_contract",
    "header.network": "network",
    "header.origin": "origin_identity",
    "header.destination": "bound_destination",
    "header.message.session": "origin_message_session",
    "header.message.sequence": "message_sequence",
    "header.original_lifetime_ms": "original_lifetime",
    "header.end_epoch": "end_epoch",
    "header.end_counter": "end_counter",
    "header.payload_length": "payload_length",
}


def end_aad_layout(wire_source: str) -> list:
    """Ordered (field, bytes) written by make_end_aad() in wire.cpp."""
    body = wire_source.split("Status make_end_aad(", 1)[1].split("#undef RL_WRITE", 1)[0]
    layout = []
    for width, expr in re.findall(r"writer\.write_u(\d+)\((.*)\)\);", body):
        name = re.search(r"kMajor|kMinor|header\.[a-z_.]+", expr).group(0)
        layout.append((END_AAD_SOURCE_NAMES.get(name, name), int(width) // 8))
    return layout


def maintenance_rx_covers_bundle(header: str, glue: str) -> bool:
    bundle_match = re.search(r"kMaintenanceBundleMax = (\d+);", header)
    line_match = re.search(
        r"kMaintenanceLineMax = (\d+) \+ (\d+) \* kMaintenanceBundleMax;",
        header,
    )
    rx_match = re.search(r"config\.rx_buffer_size = ([^;]+);", glue)
    if not bundle_match or not line_match or not rx_match:
        return False
    line_max = int(line_match[1]) + int(line_match[2]) * int(bundle_match[1])
    expression = rx_match[1].strip()
    if expression.isdecimal():
        rx_bytes = int(expression)
    else:
        offset = re.fullmatch(r"sdkv1::kMaintenanceLineMax \+ (\d+)", expression)
        if not offset:
            return False
        rx_bytes = line_max + int(offset[1])
    return rx_bytes >= line_max + 1  # the newline follows the longest line


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
        # Issue #47: acceptance targets must not undercut the LR250 serial
        # airtime floor. Airtime is derived from the physical premises
        # (wire bytes + ESP-NOW MAC overhead) x bit time + LR preamble, and
        # the displayed floor_ms must equal ceil() of the derived serial
        # model — floor(n) = n x DATA + (2n-1) x HOP_ACCEPT +
        # n x END_RECEIPT + (4n-1) x turnaround. Every hop relays DATA once,
        # every hop receiver (relays and destination on the forward path,
        # relays on the receipt's return path) emits HOP_ACCEPT, and every
        # frame reception costs a turnaround tick; the issue #47 cross-check
        # (5hop ~= forward 84ms + return 87ms) reproduces this model.
        floor_model = radio["latency_floor"]
        turn = floor_model["relay_turnaround_ms"]
        preamble_range = floor_model["lr_preamble_ms"]
        preamble = floor_model["lr_preamble_model_ms"]
        wire = floor_model["frame_wire_bytes"]
        # The premises are pinned to independent sources so a coordinated
        # edit that keeps the JSON internally consistent still fails:
        # bit time derives from the 250kbps contract (8e6 us/Mbit / rate),
        # the ESP-NOW MAC overhead is a fixed radio-physical constant, and
        # the wire byte lengths must match the Wire v1 layouts in code.
        test(
            "latency_bit_time_from_250kbps_contract",
            floor_model["us_per_byte"] * radio["radio"]["control_rate_kbps"]
            == 8000,
        )
        test(
            "latency_mac_overhead_is_espnow_constant",
            floor_model["espnow_mac_overhead_bytes"]
            == ESPNOW_MAC_OVERHEAD_BYTES,
        )
        wire_hpp = (
            root / "components/routeloom/include/routeloom/wire.hpp"
        ).read_text(encoding="utf-8")
        types_hpp = (
            root / "components/routeloom/include/routeloom/types.hpp"
        ).read_text(encoding="utf-8")
        node_cpp = (
            root / "components/routeloom/src/node.cpp"
        ).read_text(encoding="utf-8")

        def payload_bytes(function_name):
            body = node_cpp.split(
                f"Status MeshNode::{function_name}(", 1
            )[1].split("#undef RL_WRITE", 1)[0]
            return sum(
                int(width) // 8
                for width in re.findall(r"writer\.write_u(\d+)\(", body)
            )

        header_bytes = int(
            re.search(r"kHeaderSize = (\d+);", wire_hpp).group(1)
        )
        tag_bytes = int(
            re.search(r"kAeadTagSize = (\d+);", types_hpp).group(1)
        )
        # End-to-end frames carry link + end AAD tags (2); the one-hop
        # HOP_ACCEPT is link-only (1). Plaintext sizes come from the actual
        # payload encoders in node.cpp.
        expected_wire = {
            "data_64b_payload": header_bytes + 64 + 2 * tag_bytes,
            "hop_accept": header_bytes + payload_bytes("encode_ack_payload")
            + tag_bytes,
            "end_receipt": header_bytes
            + payload_bytes("encode_receipt_payload") + 2 * tag_bytes,
        }
        test(
            "latency_wire_lengths_match_wire_layout",
            wire == expected_wire,
            f"wire layout derives {expected_wire}",
        )

        def airtime_ms(wire_bytes):
            return preamble + (
                (wire_bytes + floor_model["espnow_mac_overhead_bytes"])
                * floor_model["us_per_byte"] / 1000.0
            )

        derived_airtime = {
            "data": airtime_ms(wire["data_64b_payload"]),
            "hop_accept": airtime_ms(wire["hop_accept"]),
            "end_receipt": airtime_ms(wire["end_receipt"]),
        }
        test(
            "latency_preamble_model_within_range",
            preamble_range[0] <= preamble <= preamble_range[1],
        )
        test(
            "latency_airtime_matches_physical_premises",
            all(
                abs(floor_model["frame_airtime_ms"][key] - value) <= 0.05
                for key, value in derived_airtime.items()
            ),
        )
        hop_floors = {
            "reliable_1hop_p95": 1,
            "reliable_5hop_p95": 5,
            "reliable_10hop_p95": 10,
        }
        targets = radio["performance_targets_ms"]
        floors = floor_model["floor_ms"]

        def serial_floor_ms(hops):
            return (
                hops * derived_airtime["data"]
                + (2 * hops - 1) * derived_airtime["hop_accept"]
                + hops * derived_airtime["end_receipt"]
                + (4 * hops - 1) * turn
            )

        test(
            "latency_floor_displayed_is_derived",
            all(
                floors[key] == math.ceil(serial_floor_ms(hops) - 1e-9)
                for key, hops in hop_floors.items()
            ),
        )
        test(
            "latency_targets_above_airtime_floor",
            all(
                targets[key] >= floors[key]
                for key in hop_floors
            ),
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
            and features["schema_version"] == 3,
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
            "maturity_fields_honest",
            all(
                type(item["host_tested"]) is bool
                and type(item["build_tested"]) is bool
                and item["hardware_tested"] is False
                and (item["implemented"] or not (
                    item["host_tested"] or item["build_tested"]))
                and (not item["implemented"] or bool(item["evidence"]))
                for item in feature_map.values()
            ),
        )
        host_tested_features = {
            "portable_core",
            "wire_v1_codec",
            "c_api",
            "security_hardening",
            "multi_hop_repair",
            "authority_ledger",
            "usb_device_bridge",
            "power_coordinator",
            "host_cli",
            "tui",
            "deep_sleep_resume",
            "discovery_scope",
            "explicit_gateway",
            "small_remote_config",
        }
        build_only_features = {
            "espnow_lr250_adapter",
            "reference_firmware_builds",
            "development_psk_aead",
            "nvs_replay_store",
            "nvs_ledger_store",
            "espnow_power_port",
        }
        test(
            "host_tested_features",
            all(
                feature_map[name]["implemented"] is True
                and feature_map[name]["host_tested"] is True
                for name in host_tested_features
            ),
        )
        test(
            "build_only_adapters_not_host_tested",
            all(
                feature_map[name]["implemented"] is True
                and feature_map[name]["build_tested"] is True
                and feature_map[name]["host_tested"] is False
                for name in build_only_features
            ),
        )
        test(
            "nothing_falsely_qualified",
            all(
                item["qualified"] is False
                and item["hardware_tested"] is False
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
                    "lora_tx",
                    "secure_unicast",
                }
            ),
        )
        test(
            "scope_gateway_config_implemented_experimental",
            all(
                feature_map[name]["implemented"] is True
                and feature_map[name]["host_tested"] is True
                and feature_map[name]["build_tested"] is True
                and feature_map[name]["hardware_tested"] is False
                and feature_map[name]["qualified"] is False
                and feature_map[name]["default_enabled"] is False
                for name in {
                    "discovery_scope",
                    "explicit_gateway",
                    "small_remote_config",
                }
            ),
        )
        test(
            "wire_v1_frozen_crypto_pending",
            features["wire_frozen"] is True
            and semantic["wire_frozen"] is True
            and semantic["crypto_suite"] is None
            and semantic["frame_numeric_ids"] == EXPECTED_FRAME_IDS
            and "wire_byte_layout" not in semantic["open_gates"]
            and "mandatory_security_profile_and_vectors" in semantic["open_gates"],
        )
        all_semantic_names = {
            name
            for names in semantic["membership_allowlist"].values()
            for name in names
        } | set(semantic["member_only"]) | set(
            semantic["bootstrap_requires_transaction"]
        )
        test(
            "wire_ids_cover_all_semantic_names",
            set(semantic["frame_numeric_ids"]) == all_semantic_names,
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
        # Route refresh vs. lease (issue #41, docs/design/sdk-v1/routing-scale.md
        # §5): a lease shorter than the refresh cycle makes routes expire
        # before their refresh lands, i.e. chronic flapping.
        routing = radio["routing"]
        flat = routing["flat"]
        scoped = routing["gateway_scoped"]
        records = (radio["buffers"]["normal_payload_max"] - 1) // flat["record_bytes"]
        test(
            "route_update_records_per_frame",
            records == flat["records_per_frame"] == 7,
        )

        def flat_pages(destinations):
            return max(1, -(-destinations // (records - 1)))

        def flat_sustains(period, lifetime, destinations):
            return lifetime > (flat_pages(destinations) + 1) * period

        flat_max = max(
            (
                d
                for d in range(1, 4096)
                if flat_sustains(
                    flat["default_period_ms"], flat["default_lifetime_ms"], d
                )
            ),
            default=0,
        )
        test(
            "flat_refresh_bound_documented",
            flat_max == flat["max_destinations_at_default"],
            f"flat default sustains {flat_max} destinations",
        )
        test(
            "scoped_lease_covers_two_refresh_cycles",
            scoped["lifetime_ms"]
            >= (2 * scoped["refresh_ticks"] + scoped["lease_margin_ticks"])
            * scoped["period_ms"],
        )
        routing_hpp = (
            root / "components/routeloom/include/routeloom/routing.hpp"
        ).read_text(encoding="utf-8")
        route_constants = {
            name: int(value)
            for name, value in re.findall(
                r"constexpr std::\w+ (k\w+) = (\d+);", routing_hpp
            )
        }
        test(
            "scoped_constants_match_manifest",
            route_constants.get("kScopedDefaultRefreshTicks") == scoped["refresh_ticks"]
            and route_constants.get("kScopedLeaseMarginTicks")
            == scoped["lease_margin_ticks"]
            and route_constants.get("kScopedProductPeriodMs") == scoped["period_ms"]
            and route_constants.get("kScopedProductLifetimeMs") == scoped["lifetime_ms"]
            and route_constants.get("kMaxRouteGateways") == scoped["max_gateways"]
            and route_constants.get("kRouteTombstoneDwellMs")
            == scoped["tombstone_dwell_min_ms"]
            and route_constants.get("kRouteUpdateRecordBytes") == flat["record_bytes"],
            "routing.hpp constants vs radio-defaults.json routing.gateway_scoped",
        )
        test(
            "scoped_lease_rule_in_code",
            "(2ULL * refresh_ticks + kScopedLeaseMarginTicks) * period_ms" in routing_hpp
            and "scoped_lifetime_sufficient(config_.route_advertisement_period_ms"
            in (root / "components/routeloom/src/node.cpp").read_text(encoding="utf-8"),
            "validate_config must enforce the same lease rule",
        )
        routing_cpp = (root / "components/routeloom/src/routing.cpp").read_text(
            encoding="utf-8"
        )
        test(
            # Feasibility state must outlive every lease (RFC 8966 §3.7.3).
            "tombstone_dwell_follows_lease",
            "now_ms + tombstone_dwell_ms_" in routing_cpp
            and "routes_.set_tombstone_dwell(config.route_lifetime_ms)"
            in (root / "components/routeloom/src/node.cpp").read_text(encoding="utf-8"),
        )
        route_request_hpp = (
            root / "components/routeloom/include/routeloom/route_request.hpp"
        ).read_text(encoding="utf-8")
        record_bytes = sum(f["bytes"] for f in semantic["route_record_fields"])
        request = semantic["route_request_payload"]
        test(
            "route_request_payload_contract",
            f"kRouteRequestPayloadBytes == {scoped['route_request_payload_bytes']}"
            in route_request_hpp
            and sum(f["bytes"] for f in request["fields"])
            == scoped["route_request_payload_bytes"]
            and record_bytes == flat["record_bytes"]
            and semantic["route_update_payload"]["max_records"] == records
            and request["ttl_max"] == scoped["route_request_max_ttl"]
            == radio["network"]["hop_max"],
            "semantics.json route payloads vs route_request.hpp and radio-defaults",
        )
        # Group delivery (docs/design/sdk-v1/group-delivery.md): the
        # semantics.json payload contract, group.hpp constants, the FrameType
        # ids and the radio-defaults group budget must agree.
        group_hpp = (
            root / "components/routeloom/include/routeloom/group.hpp"
        ).read_text(encoding="utf-8")
        types_hpp = (
            root / "components/routeloom/include/routeloom/types.hpp"
        ).read_text(encoding="utf-8")
        group_data = semantic["group_data"]
        group_report = semantic["group_report_payload"]
        group_radio = radio["group_delivery"]
        report_head = sum(f["bytes"] for f in group_report["fields"])
        test(
            "group_payload_contract",
            f"kGroupReportFixedBytes == {report_head}" in group_hpp
            and f"kGroupPayloadMax == {group_data['application_payload_max']}" in group_hpp
            and f"kGroupReportMissingMax = {group_report['missing_max']};" in group_hpp
            and report_head + group_report["missing_max"] * group_report["missing_id_bytes"]
            <= semantic["max_normal_payload_bytes"]
            and group_data["application_payload_max"] + 1
            == semantic["max_normal_payload_bytes"]
            and "kGroupAddressBase = 0xFFFFFFFFFFFF0000ULL" in group_hpp
            and group_data["group_address_base"] == "0xFFFFFFFFFFFF0000"
            and "GroupData = 25," in types_hpp
            and "GroupReport = 26," in types_hpp
            and "Group = 2," in types_hpp,
            "semantics.json group payloads vs group.hpp / types.hpp",
        )
        group_node_hpp = (
            root / "components/routeloom/include/routeloom/node.hpp"
        ).read_text(encoding="utf-8")
        node_constants = {
            name: int(value)
            for name, value in re.findall(
                r"constexpr std::(?:u?int\d+_t|size_t) (kGroup\w+) = (\d+);",
                group_node_hpp,
            )
        }
        estimate_group = group_radio["estimate_d100"]
        per_node = estimate_group["copy_us"] + estimate_group["report_us"]
        test(
            "group_budget_manifest",
            node_constants.get("kGroupMaxRounds") == group_radio["max_rounds"]
            and node_constants.get("kGroupLevelWaitMs") == group_radio["level_wait_ms"]
            and node_constants.get("kGroupRepairGapMs") == group_radio["repair_gap_ms"]
            and node_constants.get("kGroupOrderMaxHoldMs")
            == group_radio["order_max_hold_ms"]
            and node_constants.get("kGroupBudgetCapacityUs")
            == group_radio["source_bucket_capacity_us"]
            and f"group_airtime_us_per_s{{{group_radio['source_budget_us_per_second']}}}"
            in group_node_hpp
            # One 100-node message (a copy + a report per board) fits the
            # bucket, and the §14 model reproduces the manifest's numbers.
            and estimate_group["network_us_per_message"] == 99 * per_node
            and estimate_group["network_us_per_message"]
            <= group_radio["source_bucket_capacity_us"]
            and (group_radio["max_rounds"] - 1) * group_radio["repair_gap_ms"]
            <= resources["profiles"]["relay-c3"]["max_message_lifetime_ms"],
            "node.hpp group constants vs radio-defaults.json group_delivery",
        )
        # Zero-touch join transport (docs/design/sdk-v1/02 §5.4/§7.4, P3-1/
        # P3-2, plus the #116 v2 in 02 §7.5): the semantics.json contract,
        # the C++ constants, the Rust USB mirror, the FrameType ids and the
        # membership allowlist must agree. The v1 entries stay as history;
        # the code constants are v2 now.
        zt = semantic["zero_touch_join"]
        zt2 = zt["relay_v2"]
        zt_hpp = (
            root / "components/routeloom/include/routeloom/sdkv1_join_transport.hpp"
        ).read_text(encoding="utf-8")
        relay_hpp = (
            root / "components/routeloom/include/routeloom/sdkv1_join_relay.hpp"
        ).read_text(encoding="utf-8")
        usb_hpp = (
            root / "components/routeloom/include/routeloom/usb_host_ops.hpp"
        ).read_text(encoding="utf-8")
        ead_hpp = (
            root / "components/routeloom/include/routeloom/sdkv1_ead.hpp"
        ).read_text(encoding="utf-8")
        jr_rs = (root / "host/routeloom-protocol/src/join_relay.rs").read_text(encoding="utf-8")
        zt_chunk = zt["chunk"]
        subs = zt["usb"]["subcommands"]
        ids = semantic["frame_numeric_ids"]
        test(
            "zero_touch_join_contract",
            f"kZtDiscoverBodySize = {zt['rld1_body_v3']['discover_body_bytes']};" in zt_hpp
            and f"kZtOfferBodySize = {zt['rld1_body_v3']['offer_body_bytes']};" in zt_hpp
            and f"kZtBodyVersion = {zt['rld1_body_v3']['body_version']};" in zt_hpp
            and f"kZtClass = {zt['rld1_body_v3']['scope_class']};" in zt_hpp
            and f"kJoinMessageMax = {zt['join_message_max_bytes']};" in zt_hpp
            and f"kRelayHeaderSize = {zt2['relay_header_bytes']};" in zt_hpp
            and f"RELAY_HEADER_SIZE: usize = {zt2['relay_header_bytes']};" in jr_rs
            and zt2["relay_header_bytes"] + zt["join_message_max_bytes"]
            == zt2["relay_object_max_bytes"]
            and f"kJoinChunkHeaderSize = {zt_chunk['header_bytes']};" in zt_hpp
            and f"kJoinReplySize = {zt_chunk['reply_bytes']};" in zt_hpp
            and f"kWireRelayChunkHeaderSize = {zt2['wire_chunk_header_bytes']};" in zt_hpp
            and f"kWireRelayReplySize = {zt2['wire_reply_bytes']};" in zt_hpp
            and f"kEpochQuerySize = {zt2['epoch_query_bytes']};" in zt_hpp
            and f"kEpochReplySize = {zt2['epoch_reply_bytes']};" in zt_hpp
            and f"EPOCH_QUERY_SIZE: usize = {zt2['epoch_query_bytes']};" in jr_rs
            and f"EPOCH_REPLY_SIZE: usize = {zt2['epoch_reply_bytes']};" in jr_rs
            and f"kProxyFloors = {zt2['relay_book']['floors']};" in relay_hpp
            and f"kActiveRelays = {zt2['relay_book']['active']};" in relay_hpp
            and f"kCapJoinRelayV2 = 1u << {zt2['usb']['capability_bit']};" in usb_hpp
            and f"CAP_JOIN_RELAY_V2: u32 = 1 << {zt2['usb']['capability_bit']};" in jr_rs
            and f"kJoinRelaySchema = {zt2['usb']['inner_schema']};" in usb_hpp
            and f"JOIN_RELAY_SCHEMA: u8 = {zt2['usb']['inner_schema']};" in jr_rs
            and zt_chunk["rld1_data_max"] + zt_chunk["header_bytes"]
            == zt_chunk["chunked_only_above"]["RLD1"]
            and zt_chunk["wire_data_max"] + zt_chunk["header_bytes"]
            == zt_chunk["chunked_only_above"]["WIRE"]
            == semantic["max_normal_payload_bytes"]
            and zt["join_object_max_bytes"] == 1024
            and all(
                f"{name} = {value}," in zt_hpp
                for name, value in (
                    ("EdhocMessage", zt["bootstrap_auth_phases"]["EDHOC_MESSAGE"]),
                    ("Resume", zt["bootstrap_auth_phases"]["RESUME"]),
                    ("RelayStatus", zt["bootstrap_auth_phases"]["RELAY_STATUS"]),
                )
            )
            and all(name in ids for name in zt["relay_frame_types"])
            and ids[zt["relay_final_single_frame_type"]] == 4
            and f"kCapJoinRelayV1 = 1u << {zt['usb']['capability_bit']};" in usb_hpp
            and f"CAP_JOIN_RELAY_V1: u32 = 1 << {zt['usb']['capability_bit']};" in jr_rs
            and all(
                f"{cxx} = 0x{subs[key]:02x}," in usb_hpp
                and f"{rs}: u8 = 0x{subs[key]:02x};" in jr_rs
                for key, cxx, rs in (
                    ("JOIN_RELAY_UP", "JoinRelayUp", "SUB_JOIN_RELAY_UP"),
                    ("JOIN_RELAY_DOWN", "JoinRelayDown", "SUB_JOIN_RELAY_DOWN"),
                    ("JOIN_RELAY_ABORT", "JoinRelayAbort", "SUB_JOIN_RELAY_ABORT"),
                    ("JOIN_RELAY_RESULT", "JoinRelayResult", "SUB_JOIN_RELAY_RESULT"),
                )
            )
            # The family never reuses node_status_v1 (0x40-0x42) or
            # group_delivery_v1 (0x50-0x52), nor their capability bits.
            and not {0x40, 0x41, 0x42, 0x50, 0x51, 0x52} & set(subs.values())
            and zt["usb"]["capability_bit"] not in (6, 7)
            and f"Credential = {zt['ead_credential_label']}," in ead_hpp
            # The lane only uses what the membership allowlist already grants.
            and {"DISCOVER", "OFFER"} <= set(semantic["membership_allowlist"]["DISCOVERING"])
            and {"BOOTSTRAP_AUTH", "BOOTSTRAP_CHUNK", "BOOTSTRAP_REPLY"}
            <= set(semantic["membership_allowlist"]["AUTHENTICATING"])
            and set(zt["relay_frame_types"]) <= set(semantic["membership_allowlist"]["MEMBER"]),
            "semantics.json zero_touch_join vs sdkv1_join_transport.hpp / usb_host_ops.hpp / join_relay.rs",
        )
        estimate = scoped["airtime_estimate_d100"]
        management = radio["scheduling"]["management_network_estimated_us_per_second"]
        per_node_share = management // radio["network"]["qualification_nodes"]
        test(
            "scoped_airtime_estimate_within_envelope",
            estimate["network_us_per_second"] <= management
            and estimate["mean_node_us_per_second"] <= per_node_share
            and estimate["leaf_node_us_per_second"] <= per_node_share,
            "radio.md §14 envelope and per-node share",
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
        end_aad = [(f["field"], f["bytes"]) for f in semantic["end_aad_fields"]]
        end_aad_names = {name for name, _ in end_aad}
        test(
            "end_aad_matches_wire",
            end_aad
            == end_aad_layout(
                (root / "components/routeloom/src/wire.cpp").read_text(
                    encoding="utf-8"
                )
            ),
            "protocol/semantics.json end_aad_fields vs make_end_aad()",
        )
        test(
            "end_aad_no_hop_mutable",
            not (end_aad_names & set(semantic["hop_mutable"])),
        )
        test(
            # The payload itself is the AEAD plaintext; its length is in the AAD.
            "end_aad_covers_end_immutable",
            set(semantic["end_immutable"]) - {"payload"} <= end_aad_names,
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
        for app in ("reference_node", "bridge_node"):
            firmware = (
                root / f"firmware/{app}/main/main.cpp"
            ).read_text(encoding="utf-8")
            partition = firmware.index("nvs_flash_init_partition(")
            console = firmware.index("run_maintenance_console(sdkv1_stores)")
            peer_capacity = firmware.index("nvs_partition_peer_capacity(")
            security = firmware.index("security.initialize(")
            test(
                f"{app}_maintenance_before_mesh_security",
                partition < console < peer_capacity < security,
                "factory console needs rlsec, not the development mesh security state",
            )
        workflow = (root / ".github/workflows/sdk.yml").read_text(encoding="utf-8")
        test(
            "maintenance_usb_rx_covers_identity_bundle",
            maintenance_rx_covers_bundle(
                (root / "components/routeloom/include/routeloom/sdkv1_maintenance.hpp")
                .read_text(encoding="utf-8"),
                (root / "components/routeloom_espnow/src/espnow_sdkv1.cpp")
                .read_text(encoding="utf-8"),
            ),
            "USB RX must hold the largest hex-encoded identity bundle and newline",
        )
        for app in ("reference_node", "bridge_node"):
            test(
                f"{app}_maintenance_build_cell",
                re.search(
                    rf"- app: {app}\s+target: esp32c3\s+profile: normal"
                    rf"\s+autonomy: off\s+features: maintenance_on",
                    workflow,
                ) is not None,
                "each factory console branch must compile in the fixed-IDF matrix",
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
                >= profile["dedup_entries"] * DEDUP_ENTRY_BYTES,
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
        # The compile-time dedup profiles (node.hpp, issue #39) are the
        # resource-profile values, and the ESP-IDF Kconfig / host CMake
        # selectors offer exactly those capacities.
        profile_entries = {
            "Leaf": resources["profiles"]["leaf-small"]["dedup_entries"],
            "Relay": resources["profiles"]["relay-c3"]["dedup_entries"],
            "Gateway": resources["profiles"]["gateway-s3"]["dedup_entries"],
        }
        node_hpp = (
            root / "components/routeloom/include/routeloom/node.hpp"
        ).read_text(encoding="utf-8")
        header_caps = {
            name: int(value)
            for name, value in re.findall(
                r"constexpr std::size_t kDedupCapacity(Leaf|Relay|Gateway) = (\d+);",
                node_hpp,
            )
        }
        test("dedup_profile_capacities", header_caps == profile_entries,
             "node.hpp kDedupCapacity{Leaf,Relay,Gateway} vs dedup_entries")
        default_cap = re.search(
            r"#define ROUTELOOM_DEDUP_CAPACITY (\d+)", node_hpp
        )
        test(
            "dedup_default_relay",
            default_cap is not None
            and int(default_cap.group(1)) == profile_entries["Relay"],
        )
        kconfig = (root / "components/routeloom/Kconfig").read_text(encoding="utf-8")
        # Only the ROUTELOOM_DEDUP_CAPACITY block carries dedup capacities;
        # other integer options (e.g. ROUTELOOM_BOOT_HEAP_FLOOR_BYTES) have
        # their own defaults.
        dedup_block = re.search(
            r"^\s*config ROUTELOOM_DEDUP_CAPACITY\b(.*?)(?=^\s*(?:config|choice|menu|endmenu)\b)",
            kconfig, re.M | re.S,
        )
        kconfig_caps = sorted(
            int(value)
            for value in re.findall(
                r"^\s*default (\d+)\b", dedup_block.group(1) if dedup_block else "", re.M
            )
        )
        test(
            "dedup_kconfig_capacities",
            kconfig_caps == sorted(profile_entries.values()),
            "components/routeloom/Kconfig ROUTELOOM_DEDUP_CAPACITY defaults vs dedup_entries",
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
        # Acceptance-ID traceability (final-review P3-10): every V1-*
        # acceptance ID named by the sdk-v1 design tables must be
        # traceable to a host test (an exact "V1-Xnn" tag in tests/ or
        # host/) or explicitly triaged above (HIL-only, or no host
        # test yet). A design ID in neither state fails, so silently
        # dropped coverage cannot pass.
        design_ids: set[str] = set()
        for doc in (
            "docs/design/sdk-v1/02-zero-touch-join.md",
            "docs/design/sdk-v1/03-key-hierarchy.md",
            "docs/design/sdk-v1/04-removal-revocation.md",
            "docs/design/sdk-v1/05-nvs-state-37.md",
            "docs/design/sdk-v1/06-fast-rejoin.md",
            "docs/design/sdk-v1/07-host-api-tooling.md",
        ):
            design_ids.update(
                ACCEPTANCE_ID_RE.findall((root / doc).read_text(encoding="utf-8"))
            )
        test("acceptance_design_ids", design_ids == EXPECTED_ACCEPTANCE_IDS,
             f"missing={sorted(EXPECTED_ACCEPTANCE_IDS - design_ids)} "
             f"unexpected={sorted(design_ids - EXPECTED_ACCEPTANCE_IDS)}")
        evidence: dict[str, list[str]] = {i: [] for i in design_ids}
        for path in acceptance_test_sources(root):
            source_ids = set(ACCEPTANCE_ID_RE.findall(path.read_text(encoding="utf-8")))
            for i in source_ids & design_ids:
                evidence[i].append(str(path.relative_to(root)))
        for i in sorted(design_ids):
            if evidence[i]:
                test(f"acceptance_trace:{i}", True, ",".join(evidence[i][:4]))
            elif i in ACCEPTANCE_HIL_ONLY:
                test(f"acceptance_trace:{i}", True, f"HIL-only: {ACCEPTANCE_HIL_ONLY[i]}")
            elif i in ACCEPTANCE_NO_HOST_TEST:
                test(
                    f"acceptance_trace:{i}",
                    True,
                    f"NO_HOST_TEST: {ACCEPTANCE_NO_HOST_TEST[i]}",
                )
            else:
                test(f"acceptance_trace:{i}", False, "no host test tags this ID")
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
