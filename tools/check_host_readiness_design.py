#!/usr/bin/env python3
"""Validate a draft's budgets/examples, not SDK code, crypto, storage or HIL."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import re
import struct
from urllib.parse import unquote, urlsplit

REL = Path("docs/design/host-security-readiness")
BASE = "31b3eb0ae7080d713e7acd7ee3b7f31b43423465"
PR6 = "be21fbb41e8bb7fbf4de76e1f946436915dea741"
LIB = "c8857b62d66be3664d1694bbe4eea37c56c05d9e"
GROUPS = {"RX": (7, 8), "TX": (8, 10), "CAP": (9, 10),
          "SEC": (10, 12), "HIL": (11, 12), "AP": (12, 10)}
CANONICAL = struct.Struct(">BIBQBBBBIBBH")


def strict_json(text: str):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key] = value
        return out

    def invalid_constant(_):
        raise ValueError("non-finite JSON constant")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)


def integer(value, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError("INVALID_ARGUMENT")
    return value


def hex_value(value, digits: int) -> int:
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-fA-F]{{{digits}}}", value):
        raise ValueError("INVALID_ARGUMENT")
    return int(value, 16)


def canonical_send(request: dict) -> bytes:
    """Executable design example only; production validators need full ACL/state."""
    required = {"network", "admission_epoch", "key", "destination", "payload_hex", "payload_len"}
    if not isinstance(request, dict) or not required <= request.keys() or request.keys() - required - {"options"}:
        raise ValueError("INVALID_ARGUMENT")
    network = integer(hex_value(request["network"], 16), 1, 0xffffffff)
    integer(hex_value(request["admission_epoch"], 16), 1, (1 << 64) - 1)
    hex_value(request["key"], 32)
    dst = request["destination"]
    if not isinstance(dst, dict) or set(dst) != {"kind", "id"}:
        raise ValueError("INVALID_ARGUMENT")
    if dst["kind"] not in ("node", "gateway"):
        raise ValueError("UNSUPPORTED")
    node = integer(hex_value(dst["id"], 16), 1, (1 << 64) - 2)
    length = integer(request["payload_len"], 0, 65535)
    value = request["payload_hex"]
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value) or len(value) != 2 * length:
        raise ValueError("INVALID_ARGUMENT")
    if length > 128:
        raise ValueError("PAYLOAD_TOO_LARGE")
    opts = request.get("options", {})
    defaults = {"delivery": "RELIABLE", "priority": "NORMAL", "ttl_ms": 5000,
                "deadline_policy": "WALL_ELAPSED_VALIDITY", "storage": "HOST_DURABLE",
                "hop_limit": 10, "persist_across_sleep": False}
    if not isinstance(opts, dict) or opts.keys() - defaults.keys():
        raise ValueError("INVALID_ARGUMENT")
    opts = {**defaults, **opts}
    ttl = integer(opts["ttl_ms"], 1, 30000)
    hop = integer(opts["hop_limit"], 1, 10)
    if type(opts["persist_across_sleep"]) is not bool:
        raise ValueError("INVALID_ARGUMENT")
    if opts["delivery"] not in ("BEST_EFFORT", "RELIABLE") or opts["priority"] != "NORMAL" or opts["deadline_policy"] != "WALL_ELAPSED_VALIDITY" or opts["storage"] not in ("RAM_ONLY", "HOST_DURABLE") or opts["persist_across_sleep"]:
        raise ValueError("UNSUPPORTED")
    payload = bytes.fromhex(value)
    return CANONICAL.pack(1, network, int(dst["kind"] == "gateway"), node,
                          int(opts["delivery"] == "RELIABLE"), 1, 0,
                          int(opts["storage"] == "HOST_DURABLE"), ttl, hop, 0, length) + payload


def validate(c: dict) -> tuple[list[str], dict]:
    errors = []
    def require(name, ok):
        if not ok:
            errors.append(name)
    try:
        require("design-status", c["status"] == "design_only_pending_review")
        require("issues", c["issues"] == [7, 8, 9, 10, 11, 12])
        for key in ("runtime_changed", "implemented_by_this_pr", "hardware_tested_by_this_pr", "qualified_by_this_pr"):
            require(key, c[key] is False)
        require("base-pin", c["snapshots"]["main"] == BASE and c["snapshots"]["pr6"] == PR6)
        require("independent-review-pending", c["review_gates"]["production_crypto"] == "pending_independent_review")
        require("principal-authentication", c["ipc"]["principal_from_client_input"] is False)
        r, s, cap, w, sec, app, hil = (c[k] for k in ("receive", "send", "capacity", "wire", "security", "applied", "hil"))
        require("receive-poll", r["mode"] == "cursor_poll")
        require("receive-gap", r["gap_is_explicit"] and r["daemon_restart_changes_cursor_epoch"])
        require("receive-boundary", not r["durable_receive"] and not r["pc_service_destination"])
        require("receive-bytes", r["entries_per_network"] * r["record_charge_bytes"] <= r["bytes_per_network"] and r["max_networks"] * r["bytes_per_network"] <= r["global_log_bytes"])
        require("deadline", s["ttl_min_ms"] == 1 and s["ttl_default_ms"] == 5000 and s["ttl_max_ms"] == 30000 and not s["time_unknown_auto_dispatch"] and not s["same_key_changes_deadline"])
        require("send-capability", s["initial_priority"] == "NORMAL" and not s["provider_failover"])
        horizon = cap["retention_seconds"] + cap["admission_epoch_seconds"] + cap["late_seconds"] + cap["message_lifetime_seconds"]
        needed = math.ceil(cap["host_rate_per_minute"] * horizon / 60) + cap["burst"] + cap["host_active"]
        gateway_needed = math.ceil(cap["host_rate_per_minute"] * cap["gateway_retire_assumption_seconds"] / 60) + cap["burst"] + cap["gateway_active"]
        require("host-capacity", needed <= cap["host_records"])
        require("gateway-capacity", gateway_needed <= cap["gateway_records_per_lane"])
        storage = cap["host_records"] * cap["host_record_reservation_bytes"] + cap["host_journal_budget_bytes"] + cap["host_metadata_budget_bytes"] + cap["host_reserve_bytes"]
        require("host-storage-budget", storage <= cap["host_storage_bytes"])
        require("atomic-retirement", cap["retire_floor_before_delete"] and cap["retire_only_contiguous_prefix"])
        require("protected-records", not cap["lookup_extends_retention"] and not cap["evict_protected"] and not cap["new_boot_auto_resubmit"])
        require("unmeasured-budget", cap["measured_ram_bytes"] is None and cap["measured_disk_bytes"] is None)
        require("wire-size", w["normal_payload_max"] == 128 and w["header_bytes"] + w["normal_payload_max"] + w["tag_count"] * w["aead_tag_bytes"] <= w["espnow_body_max"])
        require("canonical-size", w["canonical_send_fixed_bytes"] == CANONICAL.size == 26)
        require("usb-size", w["usb_submit_fixed_bytes"] == struct.calcsize(">BB16s16sQ24s32sQH") == 108)
        require("rx-size", w["rx_event_fixed_bytes"] == struct.calcsize(">B16sQQIQH") == 47)
        require("applied-size", w["app_result_type"] == 19 and w["applied_result_fixed_bytes"] == struct.calcsize(">BBBBIQIQQ32sIH") == 74 and w["applied_result_fixed_bytes"] + w["applied_result_max_bytes"] <= 128)
        require("applied-request-size", w["applied_request_lease_bytes"] + w["applied_request_user_max_bytes"] == 128)
        require("applied-safety", not app["enabled_by_this_pr"] and not app["provider_failover_default"] and not app["auto_redispatch_after_unknown"] and not app["ack_of_result_ack"])
        require("applied-retention", app["result_retention_min_seconds"] >= cap["message_lifetime_seconds"] + app["late_result_seconds"])
        require("edhoc-profile", sec["edhoc_method"] == 0 and sec["edhoc_suite"] == 2 and sec["message_4_required"] and sec["context_confirmation_required"])
        require("security-pin", sec["libedhoc_commit"] == LIB and sec["libedhoc_version"] == "v2.3.2" and sec["libedhoc_license"] == "MIT")
        require("security-scope", sec["production_implemented_evidence"] is None and not sec["hardware_qualified"] and not sec["dev_fallback"])
        require("p0-bootstrap-limit", sec["bootstrap_object_max_bytes"] <= 1024 and sec["handshake_max_global"] == 1 and sec["authenticated_object_max_bytes"] <= 2048)
        require("exporter-private-use", 32768 <= sec["exporter_key_label"] <= 65535 and 32768 <= sec["exporter_iv_label"] <= 65535 and sec["exporter_key_label"] != sec["exporter_iv_label"])
        require("hil-not-run", hil["new_cases_executed"] == 0 and hil["new_measurements"] is None)
        require("preserve-smoke", hil["existing_c3_manual_smoke"] == "preserved_as_reported_not_reexecuted")
        require("soak-counts", cap["host_rate_per_minute"] * 60 * 24 == hil["host_24h_operations"] and cap["host_rate_per_minute"] * 60 * 72 == hil["host_72h_operations"])
        require("legacy-targets", hil["legacy_latency_target_ms"] == {"1hop_p95": 20, "5hop_p95": 100, "10hop_p95": 250, "warm_resume_p95": 500})
        metrics = {"host_record_requirement": needed, "gateway_window_requirement": gateway_needed, "host_storage_budget_bytes": storage,
                   "wire_normal_max": w["header_bytes"] + 128 + 32, "wire_app_result_max": w["header_bytes"] + w["applied_result_fixed_bytes"] + app["result_max_bytes"] + 32,
                   "usb_submit_max": w["usb_submit_fixed_bytes"] + CANONICAL.size + 128}
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        errors.append("schema:" + str(exc))
        metrics = {}
    return errors, metrics


def run(root: Path) -> dict:
    directory = root / REL
    c = strict_json((directory / "contracts.json").read_text())
    fixtures = strict_json((directory / "fixtures.json").read_text())
    cases = strict_json((directory / "scenarios.json").read_text())["cases"]
    errors, metrics = validate(c)
    def require(name, ok):
        if not ok:
            errors.append(name)
    expected = {f"{prefix}{i:02}": issue for prefix, (issue, n) in GROUPS.items() for i in range(1, n+1)}
    require("scenario-identity", len(cases) == len(expected) and {x["id"]: x["issue"] for x in cases} == expected)
    require("scenario-not-executed", all(x["status"] == "planned_not_run" and x["test"] and x["expect"] for x in cases))
    require("fixture-scope", fixtures["scope"] == "design_serialization_examples_not_runtime_or_crypto_vectors")
    for case in fixtures["valid_send"]:
        try:
            encoded = canonical_send(case["request"])
            require("fixture:" + case["id"], encoded.hex() == case["canonical_hex"] and hashlib.sha256(encoded).hexdigest() == case["sha256"])
            altered = copy.deepcopy(case["request"])
            altered["payload_hex"] = altered["payload_hex"].lower()
            require("normalization:" + case["id"], canonical_send(altered) == encoded)
        except ValueError as exc:
            errors.append("valid-fixture:" + case["id"] + ":" + str(exc))
    for case in fixtures["invalid_send"]:
        try:
            canonical_send(case["request"])
            errors.append("invalid-accepted:" + case["id"])
        except ValueError as exc:
            require("error:" + case["id"], str(exc) == case["error"])
    require("hil-template", fixtures["hil_record_template"]["status"] == "planned_not_run" and fixtures["hil_record_template"]["qualification"] is False)
    require("zero-new-measurements", all(v is None for v in fixtures["hil_record_template"]["counts"].values()))
    links = 0
    docs = sorted(directory.glob("*.md"))
    require("document-inventory", len(docs) == 10)
    for path in docs:
        text = path.read_text(encoding="utf-8")
        require("markdown:" + path.name, text.startswith("# ") and text.endswith("\n") and len(re.findall(r"^```", text, re.M)) % 2 == 0)
        clean = re.sub(r"```.*?```", "", text, flags=re.S)
        for target in re.findall(r"\]\(([^\s)]+)\)", clean):
            url = urlsplit(target)
            if url.scheme or url.netloc or not url.path:
                continue
            resolved = (path.parent / unquote(url.path)).resolve()
            require("link:" + target, resolved.is_relative_to(root.resolve()) and resolved.is_file())
            links += 1
    prose_examples = 0
    for path in docs:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("API1 "):
                continue
            try:
                example = strict_json(line[5:])
                require("api-example-version:" + path.name, example["v"] == 1)
                if example["method"] == "messages.submit":
                    canonical_send(example["params"])
                prose_examples += 1
            except (ValueError, KeyError, TypeError) as exc:
                errors.append("api-example:" + path.name + ":" + str(exc))
    require("api-examples-present", prose_examples >= 3)
    security_text = (directory / "05-production-security.md").read_text(encoding="utf-8")
    require("security-prose-budget", "認証前bootstrap object最大1024B" in security_text and "全体1handshake枠" in security_text)
    require("epoch-prose-prefix", "連続したprefixだけ" in (directory / "04-capacity-storage.md").read_text(encoding="utf-8"))
    combined = "\n".join(x.read_text() for x in docs)
    require("capacity-prose", "3050" in combined and "26" in combined)
    mutation_values = [
        (("runtime_changed",), True), (("receive", "gap_is_explicit"), False),
        (("send", "time_unknown_auto_dispatch"), True), (("send", "same_key_changes_deadline"), True),
        (("capacity", "evict_protected"), True), (("capacity", "retire_floor_before_delete"), False),
        (("capacity", "retire_only_contiguous_prefix"), False), (("capacity", "host_records"), 3000),
        (("ipc", "principal_from_client_input"), True), (("security", "libedhoc_commit"), "0"*40),
        (("security", "bootstrap_object_max_bytes"), 2048), (("applied", "ack_of_result_ack"), True),
        (("qualified_by_this_pr",), True), (("hil", "legacy_latency_target_ms", "1hop_p95"), 2),
    ]
    detected = []
    for keys, value in mutation_values:
        changed = copy.deepcopy(c)
        at = changed
        for key in keys[:-1]:
            at = at[key]
        at[keys[-1]] = value
        failed, _ = validate(changed)
        require("mutation:" + ".".join(keys), bool(failed))
        if failed:
            detected.append(".".join(keys))
    return {"scope": "draft-design-and-example-validation-only", "passed": not errors, "errors": errors,
            "design_documents": len(docs), "local_links": links, "serialization_valid_examples": len(fixtures["valid_send"]), "prose_api_examples": prose_examples,
            "invalid_examples_rejected": len(fixtures["invalid_send"]), "mutations_detected": detected,
            "capacity_and_size_calculations": metrics, "planned_scenarios": len(cases), "planned_scenarios_executed": 0,
            "runtime_tested": False, "crypto_tested": False, "hardware_tested": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        result = run(args.root.resolve())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {"scope": "draft-design-only", "passed": False, "errors": [str(exc)]}
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    print(output, end="")
    if args.report:
        args.report.write_text(output, encoding="utf-8")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
