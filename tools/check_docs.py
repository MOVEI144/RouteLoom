#!/usr/bin/env python3
"""RouteLoom documentation checks. Does not test firmware or RF behavior."""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit


def run(root: Path) -> dict:
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "passed": bool(ok), "detail": detail})

    markdown = sorted([root / "README.md", *(root / "docs").rglob("*.md")])
    check("documentation_exists", len(markdown) >= 25)
    texts = {}
    for file in markdown:
        relative = file.relative_to(root).as_posix()
        try:
            text = file.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            check(f"read:{relative}", False, type(error).__name__)
            continue
        texts[relative] = text
        check(f"heading:{relative}", text.startswith("# "))
        check(f"line_endings:{relative}", text.endswith("\n") and "\x00" not in text)
        fences = [line for line in text.splitlines() if line.startswith("```")]
        check(f"fences:{relative}", len(fences) % 2 == 0)
        clean = re.sub(r"```.*?```", "", text, flags=re.S)
        for index, target in enumerate(re.findall(r"\]\(([^\s)]+)\)", clean)):
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            destination = (file.parent / unquote(parsed.path)).resolve()
            inside = destination.is_relative_to(root.resolve())
            check(f"link:{relative}:{index}", inside and destination.exists(), target)

    data = {}
    for file in sorted((root / "docs/reference").glob("*.json")):
        try:
            data[file.name] = json.loads(file.read_text(encoding="utf-8"))
            check(f"json:{file.name}", True)
        except (OSError, ValueError) as error:
            check(f"json:{file.name}", False, type(error).__name__)

    try:
        p = data["radio-defaults.json"]
        check("toolchain_pin", p["esp_idf"]["tag"] == "v6.0.3" and bool(re.fullmatch(r"[0-9a-f]{40}", p["esp_idf"]["commit"])))
        check("target_set", set(p["targets"]) == {"esp32c3", "esp32s3", "esp32c5"})
        radio = p["radio"]
        check("lr_only", radio["tx_rates_kbps"] == [250, 500] and radio["bootstrap_rate_kbps"] == radio["control_rate_kbps"] == 250)
        check("fixed_profile_present", "LR250_FIXED" in radio["supported_profiles"])
        check("rf_approval_required", radio["tx_requires_approved_profile"] and radio["tx_power_qdbm"] is None)
        check("unsupported_radios_disabled", not any(radio[k] for k in ["ap_connection", "ble", "lora_tx", "auto_tx_power"]))
        net = p["network"]
        check("network_scope", net["membership_per_node"] == net["steady_channels_per_network"] == 1)
        check("qualification_scale", net["qualification_nodes"] == 100 and net["node_records"] >= 100 and net["gateway_max"] == 4 and net["hop_max"] == 10)
        check("candidate_channels", net["default_candidates"] == [1, 6, 11])
        buffers = p["buffers"]
        check("frame_budget", buffers["normal_payload_max"] + buffers["envelope_budget"] <= buffers["espnow_body_max"] == 250)
        check("bounded_queues", 0 < buffers["reserved_control_frames"] < min(buffers["rx_frames"], buffers["tx_frames"]))
        check("control_objects", buffers["control_object_max"] == 2048 and buffers["control_reassembly_slots"] == 4)
        peers = p["peers"]
        check("peer_partition", peers["broadcast"] + peers["regular"] + peers["transient"] == peers["total"] == 20)
        check("peer_pins", peers["pinned_regular_max"] <= peers["regular"])
        check("security_not_driver_only", peers["sdk_aead_required"] and not peers["driver_encrypt_default"])
        retry = p["retry"]
        check("rto_order", 0 < retry["link_rto_min_ms"] <= retry["link_rto_initial_ms"] <= retry["link_rto_max_ms"] < retry["callback_watchdog_ms"])
        check("retry_bounds", retry["link_attempts_including_initial"] == 2 and retry["origin_rounds_including_initial"] == 3)
        discovery = p["discovery"]
        check("offer_window", discovery["offer_slots"] * discovery["offer_slot_ms"] < discovery["channel_dwell_max_ms"])
        check("wake_stop_reserve", discovery["sleepy_awake_budget_ms"] > discovery["stop_reserve_ms"] + retry["callback_watchdog_ms"] + discovery["channel_dwell_max_ms"])
        check("scan_not_unbounded", discovery["sleepy_scan_cycles_max"] == 2)
        rate = p["rate"]
        check("rate_probation", 0 < rate["success_required"] <= rate["probe_samples"] and not rate["sleepy_extra_probe"])
        check("data_not_flooded", not p["routing"]["data_flood"])
        scheduler = p["scheduling"]
        check("queue_thresholds", 0 < scheduler["background_reduce_queue_fraction"] < scheduler["bulk_stop_queue_fraction"] < 1)
        check("airtime_budget_scope", 0 < scheduler["optimization_network_estimated_us_per_second"] < scheduler["management_network_estimated_us_per_second"] <= 1000000)
        survey = p["survey"]
        check("survey_samples", survey["exchanges_per_direction_per_visit"] * survey["minimum_visits"] >= survey["samples_per_direction"] >= survey["success_required"])
        check("survey_finite", survey["visit_max_ms"] == 200 and survey["visit_gap_min_ms"] >= 30000)
        migration = p["migration"]
        check("migration_commit_active_split", migration["committed_and_active_separate"] and not migration["unilateral_rollback"])
        check("migration_guard_base", migration["cutover_guard_min_ms"] >= migration["guard_uncertainty_multiplier"] * migration["clock_uncertainty_max_ms"])
        check("migration_times", migration["commit_lead_min_ms"] < migration["prepare_timeout_ms"] < migration["cooldown_ms"])
        check("sleep_relay_not_claimed", not p["power"]["synchronized_sleep_relay"])
        load = p["reference_load"]
        per_hour = load["nodes"] * (load["data_per_node_per_hour"] + 3600 / load["heartbeat_period_seconds"])
        check("reference_load_2100_per_hour", per_hour == 2100)
        check("radio_doc_budget_mentions", all(s in texts["docs/spec/radio.md"] for s in ["2000ms", "200ms", "1000ms", "128", "250"]))
    except (KeyError, TypeError, ValueError) as error:
        check("parameter_schema", False, type(error).__name__)

    try:
        boards = data["boards.json"]["boards"]
        check("four_board_profiles", len(boards) == 4 and len({b["id"] for b in boards}) == 4)
        for board in boards:
            check(f"board_doc:{board['id']}", (root / board["doc"]).is_file())
            check(f"board_not_rf_claim:{board['id']}", board["rf_qualified"] is False)
            if "gpio_d0_to_d10" in board:
                pins = board["gpio_d0_to_d10"]
                check(f"gpio_map:{board['id']}", len(pins) == len(set(pins)) == 11 and all(isinstance(x, int) and x >= 0 for x in pins))
                check(f"usb_reserved:{board['id']}", board["usb_dm"] not in pins and board["usb_dp"] not in pins)
        c5 = next(b for b in boards if b["chip"] == "esp32c5")
        check("c5_memory_qualification", c5["psram_requires_bom_and_runtime_verification"])
        extension = next(b for b in boards if "extra_radio" in b)
        check("lora_not_implemented", extension["lora_tx_v1"] is False and extension["requires_revision_and_continuity_test"])
        tests = set(re.findall(r"\|\s*(T\d{2})\s*\|", texts["docs/spec/acceptance.md"]))
        requirements = data["requirements.json"]["requirements"]
        check("requirements_unique", len({r["id"] for r in requirements}) == len(requirements))
        covered = set()
        for requirement in requirements:
            docs_exist = bool(requirement["docs"]) and all((root / d).is_file() for d in requirement["docs"])
            cases = set(requirement["tests"])
            covered |= cases
            check(f"traceability:{requirement['id']}", docs_exist and bool(cases) and cases <= tests)
        check("all_acceptance_gates_mapped", tests == covered and len(tests) == 20)
    except (KeyError, StopIteration, TypeError) as error:
        check("manifest_schema", False, type(error).__name__)

    pattern = os.environ.get("FORBIDDEN_PATTERN", "")
    if pattern:
        matcher = re.compile(pattern, re.I)
        for relative, text in texts.items():
            check(f"content_policy:{relative}", matcher.search(text) is None)
        for name, value in data.items():
            check(f"content_policy:{name}", matcher.search(json.dumps(value, ensure_ascii=False)) is None)

    failed = [item for item in checks if not item["passed"]]
    return {"scope": "documentation-and-parameters-only", "markdown_files": len(markdown), "json_files": len(data), "checks": len(checks), "passed": len(checks) - len(failed), "failed": failed, "rf_tested": False, "firmware_tested": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = run(args.root.resolve())
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    print(rendered)
    if args.report:
        args.report.write_text(rendered + "\n", encoding="utf-8")
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
