#!/usr/bin/env python3
"""Validate design artifacts, not runtime behavior or RF qualification."""
from __future__ import annotations

import argparse
import copy
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit

DESIGN = Path("docs/design/autonomous-mesh")
PREFIXES = {"D3": {3}, "D4": {4}, "D5": {5}, "X": {3, 4, 5}}


def validate_admission(a: dict) -> list[str]:
    """Check the draft integration contract; this does not execute SDK admission."""
    errors: list[str] = []

    def require(condition: bool, name: str) -> None:
        if not condition:
            errors.append(f"admission:{name}")

    try:
        require(a["membership_enum"] == {
            "Unprovisioned": 0, "Discovering": 1, "Authenticating": 2,
            "AuthorizedPendingCommit": 3, "Member": 4, "Revoked": 5,
        }, "preserve six membership values")
        require(a["membership_scope"] == "node-network" and
                a["membership_writer"] == "MembershipController", "membership owner")
        require(a["neighbor_state_type"] == "NeighborPhase" and
                a["neighbor_scope"] == "peer-radio-exchange", "independent neighbor state")
        require(a["coarse_policy_source"] == "protocol/semantics.json#membership_allowlist",
                "one coarse semantic source")
        require(a["frame_allowed_role"] == "refactor-coarse-whitelist-and-context-gate",
                "legacy helper is not final authorization")
        require(a["frame_type_ids"] == {
            "Discover": 1, "Offer": 2, "BootstrapAuth": 3, "MembershipResult": 4,
            "BootstrapChunk": 5, "BootstrapReply": 6, "MembershipQuery": 7,
        }, "reuse reserved type IDs")
        require(a["rld1_type_ids"] == [1, 2, 3, 5, 6], "RLD1 type allowlist")
        require(a["rl_bootstrap_type_ids"] == [3, 4, 5, 6, 7], "Wire bootstrap types")
        require(a["logical_auth_phases"] == {"PROVE": 3, "CONFIRM": 3, "FINISH": 3},
                "auth phases are not new top-level types")
        require(a["cookie_type_id"] == 2, "cookie belongs to OFFER")
        require(a["rld1_fragment_inner_types"] == [3] and
                a["rl_fragment_inner_types"] == [3, 4], "bounded fragment types")
        require(a["authenticator_output"] == "AuthenticatedPeerProof" and
                a["membership_result_carrier"] == "RL", "proof is not membership")
        for name in ("local_member_preserved_during_discovery",
                     "verified_binding_requires_membership", "unknown_types_rejected",
                     "context_required_on_tx_rx_proxy_reassembly", "recheck_before_state_promotion"):
            require(a[name] is True, name)
        for name in ("restricted_bootstrap_context_is_normal_binding",
                     "member_state_alone_allows_candidate_data", "revoked_wire_join_allowed",
                     "rld1_multihop_forwarding", "parser_failure_fallback",
                     "recursive_bootstrap_fragments"):
            require(a[name] is False, name)
        gate = a["ci_adoption_gate"]
        require(gate["status"] == "pending_pr2_adoption" and
                gate["executed_by_this_design_pr"] is False, "CI adoption is not execution evidence")
        require(gate["targets"] == ["esp32c3", "esp32s3", "esp32c5"] and
                gate["app_profiles"] == {
                    "reference_node": ["normal", "deep_sleep"], "bridge_node": ["normal"],
                }, "preserve PR2 firmware profiles")
        require(gate["expected_jobs"] == len(gate["targets"]) *
                sum(len(v) for v in gate["app_profiles"].values()) == 9, "nine firmware builds")
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        errors.append(f"admission:invalid manifest shape: {type(error).__name__}: {error}")
    return errors


def validate_contract(c: dict, scenarios: dict) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, name: str) -> None:
        if not condition:
            errors.append(name)

    try:
        require(c["schema_version"] == 1, "schema version")
        require(c["status"] == "design-only", "design-only status")
        require(c["issues"] == [3, 4, 5], "issue scope")
        require(c["runtime_changes_in_this_pr"] is False, "no runtime claim")
        require(c["existing_core_default_changes"] is False, "CORE defaults unchanged")
        require(len(c["features"]) == 3, "three feature records")
        require({v["issue"] for v in c["features"].values()} == {3, 4, 5}, "feature coverage")
        for feature in c["features"].values():
            require(feature["implemented_by_this_pr"] is False and feature["qualified"] is False,
                    "feature remains unimplemented/unqualified")
        for name in ("main", "pr2", "esp_idf_commit"):
            value = c["snapshots"][name]
            require(bool(re.fullmatch(r"[0-9a-f]{40}", value)) and value != "0" * 40,
                    f"snapshot:{name}")
        require(bool(re.fullmatch(r"[0-9a-f]{64}", c["snapshots"]["pr2_artifact_sha256"])),
                "artifact digest")
        w = c["wire"]
        require((w["preserve_major"], w["preserve_minor"]) == (1, 0), "preserve Wire v1")
        require(w["header_bytes"] + w["normal_payload_bytes"] +
                w["aead_tag_bytes"] * w["end_and_link_tags"] <= w["espnow_body_limit"] == 250,
                "normal frame size")
        require(w["discovery_magic"] == "RLD1", "separate discovery magic")
        require(w["discovery_header_budget"] == 4+1+1+2+2+2+4+8+16+4,
                "discovery header field widths")
        require(w["discovery_header_budget"] + w["discovery_body_budget"] ==
                w["discovery_total_limit"] <= 250, "discovery size budget")
        require(w["header_bytes"] + w["busy_payload_limit"] + 2*w["aead_tag_bytes"] <= 250,
                "BUSY envelope budget")
        require(w["new_control_payloads_require_vectors"] is True, "new payload vectors required")
        d = c["discovery"]
        p = d["peer_partition"]
        require(p["broadcast"] + p["regular"] + p["transient"] == p["total"] == 20,
                "Peer partition")
        require(0 < d["regular_pins_max"] <= p["regular"], "Peer pin bounds")
        require(d["logical_neighbors_max"] >= p["total"], "logical vs driver peers")
        require(d["rate_kbps"] == 250, "bootstrap LR250")
        require(d["offer_slots"] * d["offer_slot_ms"] < d["channel_visit_max_ms"],
                "discovery window margin")
        require(d["sleep_awake_budget_ms"] > d["stop_reserve_ms"] +
                d["callback_watchdog_ms"] + d["channel_visit_max_ms"], "awake budget guard")
        require(0 < d["idle_refresh_ms"] < d["awake_neighbor_lease_ms"], "neighbor lease")
        require(d["global_handshakes"] == 1 and d["bootstrap_rx_slots"] == 4,
                "bounded preauth resources")
        for name in ("unauthenticated_data_allowed", "unapproved_member_data_allowed",
                     "automatic_identity_reassignment"):
            require(d[name] is False, name)
        errors.extend(validate_admission(c["admission"]))
        q = c["congestion"]
        require(0 < q["background_reduce_fraction"] < q["bulk_stop_fraction"] < 1,
                "queue thresholds")
        require(0 < q["window_min"] <= q["window_initial"] <= q["window_max"] <=
                q["global_hop_wait_slots"], "window limits")
        require(q["rf_attempts_max"] + q["busy_readmissions_max"] <=
                q["combined_physical_attempts_max"], "combined attempts")
        require(0 < q["busy_retry_after_ms"][0] <= q["busy_retry_after_ms"][1], "BUSY interval")
        require(q["observation_window_ms"] < q["feedback_ttl_ms"], "feedback lifetime")
        require(q["queue_penalty_step_ms"] > 0 and q["queue_penalty_max_multiple"] > 0,
                "queue penalty bounds")
        require(q["recheck_current_feasibility"] is True, "current feasibility required")
        for name in ("metric_changes_refresh_advertisement_lease", "data_replication_multipath", "data_flood"):
            require(q[name] is False, name)
        m = c["migration"]
        require(m["design_initial_mode"] == "Observe", "initial design mode")
        require(set(m["modes"]) == {"Disabled", "Observe", "Manual", "AutoGuarded"}, "mode set")
        require(m["single_authority_supported"] is True and
                m["raft_required_for_initial_implementation"] is False, "SingleAuthority baseline")
        require(m["candidate_channels"] == [1, 6, 11] and m["normal_rates_kbps"] == [250],
                "initial radio scope")
        require(0 < m["screening_successes"] <= m["survey_samples_per_direction"], "screening samples")
        require(m["guard_floor_ms"] >= m["guard_uncertainty_multiplier"] *
                m["clock_uncertainty_max_ms"], "guard lower bound; measured switch time still required")
        require(0 < m["commit_lead_floor_ms"] < m["prepare_timeout_ms"], "plan timing")
        require(0 < m["survey_visit_max_ms"] < m["helper_old_channel_dwell_ms"] <
                m["helper_visit_period_ms"] < m["helper_total_budget_ms"] < m["cooldown_ms"],
                "separate survey/recovery budgets")
        for name in ("requires_verified_commit", "requires_recovery_plan", "legacy_required_node_blocks_auto",
                     "liveness_requires_explicit_loss_clock_coverage_transfer_bounds"):
            require(m[name] is True, name)
        for name in ("unilateral_rollback", "atomic_all_node_cutover_claimed", "unknown_time_is_zero"):
            require(m[name] is False, name)
        require(m["driver_peer_channel_policy"] == "current-channel-zero", "driver channel policy")
        r = c["resources"]
        require(r["values_are_design_budgets_not_measurements"] is True, "budget is not measured")
        require(r["per_radio_owner_count"] == 1, "single owner")
        require(r["unbounded_raw_statistics"] is False and
                r["global_graph_required_on_every_c3"] is False, "bounded distributed footprint")
        require(0 < r["relay_incremental_resident_budget_bytes"] < r["planner_incremental_budget_bytes"],
                "resource budget order")
        require(r["planner_sparse_edges_max"] > 0, "bounded planner edges")
        require(scenarios["schema_version"] == 1 and scenarios["runtime_tested"] is False,
                "scenario evidence level")
        cases = scenarios["scenarios"]
        ids = [case["id"] for case in cases]
        require(len(ids) == len(set(ids)), "unique scenario IDs")
        require(Counter(i.split("-")[0] for i in ids) == Counter(c["expected_scenarios"]),
                "scenario counts")
        for case in cases:
            prefix = case["id"].split("-")[0]
            require(bool(re.fullmatch(r"(?:D3|D4|D5|X)-\d{2}", case["id"])), "scenario ID format")
            require(bool(case["issues"]) and set(case["issues"]) <= PREFIXES.get(prefix, set()),
                    f"issue mapping:{case['id']}")
            require(case["status"] == "planned_not_run", f"not claimed executed:{case['id']}")
            require(case["level"] in {"model", "integration", "build", "hil", "contract"},
                    f"scenario level:{case['id']}")
            require(bool(case["preconditions"]) and bool(case["action"]) and
                    bool(case["oracles"]) and all(isinstance(s, str) and s for s in case["oracles"]),
                    f"scenario oracle:{case['id']}")
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        errors.append(f"invalid manifest shape: {type(error).__name__}: {error}")
    return errors


def run(root: Path) -> dict:
    errors: list[str] = []
    folder = root / DESIGN
    try:
        c = json.loads((folder / "contracts.json").read_text(encoding="utf-8"))
        s = json.loads((folder / "scenarios.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return {"scope": "design-lint-only", "passed": False, "errors": [str(error)]}
    errors.extend(validate_contract(c, s))
    # This is a comparison with the checked-in semantic contract, not with
    # runtime frame_allowed(), which the implementation backlog must reconcile.
    try:
        semantics = json.loads((root / "protocol/semantics.json").read_text(encoding="utf-8"))
        bootstrap = {"DISCOVER", "OFFER", "BOOTSTRAP_AUTH", "MEMBERSHIP_RESULT",
                     "BOOTSTRAP_CHUNK", "BOOTSTRAP_REPLY", "MEMBERSHIP_QUERY"}
        expected = {
            "UNPROVISIONED": {"DISCOVER", "OFFER"},
            "DISCOVERING": {"DISCOVER", "OFFER"},
            "AUTHENTICATING": {"DISCOVER", "OFFER", "BOOTSTRAP_AUTH", "BOOTSTRAP_CHUNK", "BOOTSTRAP_REPLY"},
            "AUTHORIZED_PENDING_COMMIT": {"MEMBERSHIP_QUERY", "MEMBERSHIP_RESULT", "BOOTSTRAP_CHUNK", "BOOTSTRAP_REPLY"},
            "MEMBER": bootstrap,
            "REVOKED": set(),
        }
        allowed = semantics["membership_allowlist"]
        if set(allowed) != set(expected):
            errors.append("admission:semantic membership state drift")
        for state, wanted in expected.items():
            actual = set(allowed[state])
            if actual & bootstrap != wanted:
                errors.append(f"admission:semantic bootstrap allowlist drift:{state}")
            if state != "MEMBER" and actual - bootstrap:
                errors.append(f"admission:member traffic admitted before membership:{state}")
        if allowed["REVOKED"]:
            errors.append("admission:revoked semantic allowlist must be empty")
        registry = semantics.get("frame_numeric_ids")
        # The design branch still predates PR2. Missing frozen type IDs are
        # explicitly a dependency, never silently reported as source-verified.
        type_source_status = "pending_pr2_adoption" if registry is None else "checked_against_semantics"
        if registry is not None:
            for name, value in zip(("DISCOVER", "OFFER", "BOOTSTRAP_AUTH", "MEMBERSHIP_RESULT",
                                    "BOOTSTRAP_CHUNK", "BOOTSTRAP_REPLY", "MEMBERSHIP_QUERY"), range(1, 8)):
                if registry.get(name) != value:
                    errors.append(f"admission:semantic type ID drift:{name}")
    except (OSError, KeyError, TypeError, ValueError) as error:
        errors.append(f"admission:semantic source invalid: {type(error).__name__}: {error}")
        type_source_status = "invalid"
    links = 0
    for name in c.get("documents", []):
        file = (folder / name).resolve()
        if not file.is_relative_to(folder.resolve()) or not file.is_file():
            errors.append(f"missing design document: {name}")
            continue
        text = file.read_text(encoding="utf-8")
        if not text.startswith("# ") or not text.endswith("\n"):
            errors.append(f"document structure: {name}")
        fences = [line for line in text.splitlines() if line.startswith("```")]
        if len(fences) % 2:
            errors.append(f"unclosed fence: {name}")
        clean = re.sub(r"```.*?```", "", text, flags=re.S)
        for target in re.findall(r"\]\(([^\s)]+)\)", clean):
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            links += 1
            destination = (file.parent / unquote(parsed.path)).resolve()
            if not destination.is_relative_to(root) or not destination.exists():
                errors.append(f"broken local link: {name}: {target}")
    mutations = [
        ("wire", "header_bytes", 150),
        ("discovery", "unauthenticated_data_allowed", True),
        ("congestion", "recheck_current_feasibility", False),
        ("migration", "unilateral_rollback", True),
        ("migration", "atomic_all_node_cutover_claimed", True),
        ("resources", "values_are_design_budgets_not_measurements", False),
        ("admission", "membership_enum", {"Member": 0}),
        ("admission", "membership_scope", "peer-radio-exchange"),
        ("admission", "rld1_type_ids", [1, 2, 3, 4, 5, 6, 7]),
        ("admission", "logical_auth_phases", {"PROVE": 3, "CONFIRM": 4, "FINISH": 7}),
        ("admission", "rld1_fragment_inner_types", [3, 16]),
        ("admission", "restricted_bootstrap_context_is_normal_binding", True),
        ("admission", "member_state_alone_allows_candidate_data", True),
        ("admission", "local_member_preserved_during_discovery", False),
        ("admission", "unknown_types_rejected", False),
        ("admission", "revoked_wire_join_allowed", True),
        ("admission", "context_required_on_tx_rx_proxy_reassembly", False),
        ("admission", "parser_failure_fallback", True),
        ("admission", "recheck_before_state_promotion", False),
        ("admission", "ci_adoption_gate", {"status": "completed"}),
    ]
    for section, key, value in mutations:
        mutated = copy.deepcopy(c)
        mutated[section][key] = value
        if not validate_contract(mutated, s):
            errors.append(f"negative check not detected: {section}.{key}")
    return {"scope": "design-lint-only", "passed": not errors, "errors": errors,
            "documents": len(c.get("documents", [])), "local_links_checked": links,
            "planned_scenarios": len(s.get("scenarios", [])),
            "negative_manifest_checks": len(mutations),
            "semantic_type_source": type_source_status,
            "runtime_admission_tested": False,
            "scenario_executions": 0, "firmware_tested": False, "rf_tested": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = run(args.root.resolve())
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    print(output, end="")
    if args.report:
        args.report.write_text(output, encoding="utf-8")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
