#!/usr/bin/env python3
"""NVS entry budget model for per-peer security state (issue #37).

docs/design/sdk-v1/05-nvs-state-37.md §5.3 / plan P0-1 (V1-N07). Reads the
record sizes and budget constants straight from the C++ headers and the
partition tables of every firmware app, then checks that the capped
worst-case peer state fits 80% of the usable entries of the "rlsec" NVS
partition, that the table fits the flash size the build assumes, and that
the firmware selects the table. Arithmetic only: it does not measure a
device (V1-N08 is the HIL counterpart).
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PAGE_BYTES = 4096
# ESP-IDF's default CONFIG_ESPTOOLPY_FLASHSIZE (2 MB) applies when an app's
# sdkconfig.defaults does not choose one; every supported board has >= 4 MB.
DEFAULT_FLASH_BYTES = 0x200000
# Factory size of the previous CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE table
# (1500 KiB): the custom table must not shrink the app partition.
PREVIOUS_FACTORY_BYTES = 1500 * 1024
SECURITY_PARTITION = "rlsec"

# Every firmware app that mounts rlsec (directory with main/main.cpp).
APPS = (
    "firmware/reference_node",
    "firmware/bridge_node",
    "firmware/bench_node",
    "examples/espnow_node",
)

# Apps on the shared components/routeloom_node_boot bring-up no longer keep
# the peer-capacity constant in their own main.cpp — it lives in the shared
# source, which is what these builds actually compile.
BOOT_SOURCE = {
    "firmware/reference_node": "components/routeloom_node_boot/src/node_boot.cpp",
    "firmware/bench_node": "components/routeloom_node_boot/src/node_boot.cpp",
}

HEADERS = {
    "counter": "components/routeloom/include/routeloom/counter_store.hpp",
    "replay": "components/routeloom/include/routeloom/replay.hpp",
    "peer_state": "components/routeloom/include/routeloom/peer_state.hpp",
    "provider": "components/routeloom_espnow/include/routeloom/psk_security.hpp",
    "records": "components/routeloom/include/routeloom/sdkv1_records.hpp",
    "store": "components/routeloom/include/routeloom/sdkv1_store.hpp",
}


class BudgetError(ValueError):
    """A source the model depends on is missing or malformed."""


@dataclass(frozen=True)
class Partition:
    name: str
    type: str
    subtype: str
    offset: int
    size: int


def _int(text: str) -> int:
    text = text.strip()
    multiplier = 1
    if text[-1:] in ("K", "k"):
        multiplier, text = 1024, text[:-1]
    elif text[-1:] in ("M", "m"):
        multiplier, text = 1024 * 1024, text[:-1]
    return int(text, 0) * multiplier


def _constant(text: str, name: str) -> int:
    match = re.search(rf"\b{name}\s*=\s*(0x[0-9A-Fa-f]+|\d+)", text)
    if match is None:
        raise BudgetError(f"constant {name} not found")
    return int(match.group(1), 0)


def _sizeof(text: str, record: str) -> int:
    match = re.search(rf"static_assert\(sizeof\({record}\)\s*==\s*(\d+)", text)
    if match is None:
        raise BudgetError(f"sizeof({record}) static_assert not found")
    return int(match.group(1))


def parse_partitions(text: str) -> list[Partition]:
    partitions = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = [field.strip() for field in line.split(",")]
        if len(fields) < 5 or not fields[3] or not fields[4]:
            raise BudgetError(f"partition row needs explicit offset and size: {raw!r}")
        partitions.append(Partition(fields[0], fields[1], fields[2],
                                    _int(fields[3]), _int(fields[4])))
    return partitions


def blob_entries(size: int, entry_bytes: int) -> int:
    """NVS v2 blob: index entry + chunk header + 32-byte data spans."""
    return 2 + (size + entry_bytes - 1) // entry_bytes


def load_constants(sources: dict[str, str]) -> dict[str, int]:
    counter, replay = sources["counter"], sources["replay"]
    peer, provider = sources["peer_state"], sources["provider"]
    records, store = sources["records"], sources["store"]
    constants = {
        "counter_record": _sizeof(counter, "CounterRecord"),
        "floor_record": _sizeof(replay, "ReplayFloorRecord"),
        "window_record": _sizeof(replay, "ReplayWindowRecord"),
        "entry_bytes": _constant(peer, "kNvsEntryBytes"),
        "entries_per_page": _constant(peer, "kNvsEntriesPerPage"),
        "fixed_entries": _constant(peer, "kPeerStateFixedEntries"),
        "budget_percent": _constant(peer, "kPeerStateBudgetPercent"),
        "kNodeMaxPersistedPeers": _constant(provider, "kNodeMaxPersistedPeers"),
        "kGatewayMaxPersistedPeers": _constant(provider, "kGatewayMaxPersistedPeers"),
        # P4 session/membership stores (RLP2 quotas + RLV1 twin pair).
        "rlp2_slot": _constant(records, "kResume2SlotBytes"),
        "rlv1_slot": _constant(records, "kLocalRevocationSlotBytes"),
        "rlp2_node_link": _constant(store, "kResume2NodeLinkQuota"),
        "rlp2_node_end": _constant(store, "kResume2NodeEndQuota"),
        "rlp2_gateway_link": _constant(store, "kResume2GatewayLinkQuota"),
        "rlp2_gateway_end": _constant(store, "kResume2GatewayEndQuota"),
    }
    match = re.search(r"static_assert\(kPeerStateEntriesPerPeer\s*==\s*(\d+)", peer)
    if match is None:
        raise BudgetError("kPeerStateEntriesPerPeer static_assert not found")
    constants["declared_entries_per_peer"] = int(match.group(1))
    return constants


def entries_per_peer(constants: dict[str, int]) -> int:
    entry = constants["entry_bytes"]
    return 2 * (blob_entries(constants["counter_record"], entry)
                + blob_entries(constants["floor_record"], entry)
                + blob_entries(constants["window_record"], entry))


def max_peers_for_entries(total_entries: int, constants: dict[str, int]) -> int:
    """Mirror of routeloom::max_persisted_peers_for_entries."""
    usable = max(total_entries - constants["entries_per_page"], 0)
    budget = usable * constants["budget_percent"] // 100
    if budget <= constants["fixed_entries"]:
        return 0
    return (budget - constants["fixed_entries"]) // entries_per_peer(constants)


def session_fixed_entries(constants: dict[str, int], gateway: bool) -> int:
    """P4 RLP2 + RLV1 worst case: every resume slot written plus the RLV1
    twin pair (fixed key counts, never peer-churn dependent)."""
    entry = constants["entry_bytes"]
    if gateway:
        slots = constants["rlp2_gateway_link"] + constants["rlp2_gateway_end"]
    else:
        slots = constants["rlp2_node_link"] + constants["rlp2_node_end"]
    return slots * blob_entries(constants["rlp2_slot"], entry) + 2 * blob_entries(
        constants["rlv1_slot"], entry
    )


def check_app(app: str, sources: dict[str, str], constants: dict[str, int]) -> dict:
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": f"{app}:{name}", "passed": bool(ok), "detail": detail})

    defaults = sources[f"{app}/sdkconfig.defaults"]
    main = sources[BOOT_SOURCE.get(app, f"{app}/main/main.cpp")]
    check("custom_table_selected",
          re.search(r"^CONFIG_PARTITION_TABLE_CUSTOM=y$", defaults, re.M) is not None
          and re.search(r'^CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"$',
                        defaults, re.M) is not None
          and "CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y" not in defaults)
    flash = DEFAULT_FLASH_BYTES
    size_match = re.search(r"^CONFIG_ESPTOOLPY_FLASHSIZE_(\d+)MB=y$", defaults, re.M)
    if size_match:
        flash = int(size_match.group(1)) * 1024 * 1024

    try:
        partitions = parse_partitions(sources[f"{app}/partitions.csv"])
    except (BudgetError, ValueError) as error:
        check("partition_table_parses", False, str(error))
        return {"app": app, "checks": checks}
    if not partitions:
        check("partition_table_parses", False, "no partitions")
        return {"app": app, "checks": checks}
    by_name = {p.name: p for p in partitions}
    check("names_unique", len(by_name) == len(partitions))
    ordered = sorted(partitions, key=lambda p: p.offset)
    overlaps = [f"{a.name}/{b.name}" for a, b in zip(ordered, ordered[1:])
                if a.offset + a.size > b.offset]
    check("no_overlap", not overlaps, ",".join(overlaps))
    end = max(p.offset + p.size for p in partitions)
    check("fits_flash", end <= flash, f"end=0x{end:x} flash=0x{flash:x}")
    for p in partitions:
        alignment = 0x10000 if p.type == "app" else PAGE_BYTES
        check(f"aligned:{p.name}", p.offset % alignment == 0 and p.size % PAGE_BYTES == 0)
    factory = by_name.get("factory")
    check("factory_not_shrunk", factory is not None and factory.type == "app"
          and factory.size >= PREVIOUS_FACTORY_BYTES)
    system = by_name.get("nvs")
    check("system_nvs_present", system is not None and system.type == "data"
          and system.subtype == "nvs")
    security = by_name.get(SECURITY_PARTITION)
    check("security_nvs_present", security is not None and security.type == "data"
          and security.subtype == "nvs")
    if security is None:
        return {"app": app, "checks": checks}

    pages = security.size // PAGE_BYTES
    check("security_nvs_min_pages", pages >= 3, f"pages={pages}")
    uses_gateway = "kGatewayMaxPersistedPeers" in main
    uses_node = "kNodeMaxPersistedPeers" in main
    check("cap_selected", uses_gateway != uses_node)
    cap_name = "kGatewayMaxPersistedPeers" if uses_gateway else "kNodeMaxPersistedPeers"
    cap = constants[cap_name]
    total = pages * constants["entries_per_page"]
    usable = (pages - 1) * constants["entries_per_page"]
    budget = usable * constants["budget_percent"] // 100
    # Profile-split (P4 §12.2): the legacy per-peer worst case and the RAM
    # session worst case are gated separately — a RAM-profile firmware
    # never writes legacy c/f/r records, so their maxima are not added.
    # Stale legacy records during migration are purge's problem (P6/PR6),
    # reported below, not gated here.
    legacy = cap * entries_per_peer(constants) + constants["fixed_entries"]
    check("worst_case_within_budget", legacy <= budget,
          f"worst={legacy} budget={budget} usable={usable}")
    session = session_fixed_entries(constants, uses_gateway)
    ram = constants["fixed_entries"] + session
    check("worst_case_ram_within_budget", ram <= budget,
          f"worst={ram} budget={budget} usable={usable} session_fixed={session}")
    worst = legacy
    # The firmware clamps the cap to what the mounted partition holds; the
    # configured cap must survive that clamp unchanged.
    fits = max_peers_for_entries(total, constants)
    check("cap_not_clamped", cap <= fits, f"cap={cap} fits={fits}")
    return {
        "app": app,
        "partition_bytes": security.size,
        "pages": pages,
        "usable_entries": usable,
        "budget_entries": budget,
        "cap_constant": cap_name,
        "max_persisted_peers": cap,
        "worst_case_entries": worst,
        "ram_worst_case_entries": ram,
        "session_fixed_entries": session,
        "table_end": f"0x{end:x}",
        "checks": checks,
    }


def run(sources: dict[str, str], apps: tuple[str, ...] = APPS) -> dict:
    checks: list[dict] = []
    results = []
    try:
        constants = load_constants(sources)
    except BudgetError as error:
        return {"scope": "arithmetic-only", "failed": [{"name": "constants",
                "passed": False, "detail": str(error)}], "apps": []}
    per_peer = entries_per_peer(constants)
    checks.append({"name": "entries_per_peer_matches_codecs",
                   "passed": per_peer == constants["declared_entries_per_peer"],
                   "detail": f"model={per_peer} header={constants['declared_entries_per_peer']}"})
    for app in apps:
        result = check_app(app, sources, constants)
        checks.extend(result["checks"])
        results.append(result)
    failed = [item for item in checks if not item["passed"]]
    return {"scope": "arithmetic-only", "hardware_measured": False,
            "entries_per_peer": per_peer, "checks": len(checks),
            "failed": failed, "apps": results}


def load_sources(root: Path, apps: tuple[str, ...] = APPS) -> dict[str, str]:
    sources = {key: (root / path).read_text(encoding="utf-8")
               for key, path in HEADERS.items()}
    for app in apps:
        for name in ("sdkconfig.defaults", "partitions.csv", "main/main.cpp"):
            path = root / app / name
            sources[f"{app}/{name}"] = path.read_text(encoding="utf-8") if path.exists() else ""
    for extra in {BOOT_SOURCE[app] for app in apps if app in BOOT_SOURCE}:
        sources[extra] = (root / extra).read_text(encoding="utf-8")
    return sources


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true",
                        help="exit non-zero when any budget check fails")
    args = parser.parse_args()
    result = run(load_sources(args.root.resolve()))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if args.check and result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
