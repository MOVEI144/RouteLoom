#!/usr/bin/env python3
"""Regenerate protocol/sdkv1-golden/dams/ — SDK v1 join DAMS context vectors
(plan P3-4 PR 1).

Independent reference encoder for the EDHOC_Exporter context both join ends
build for the DAMS derivation (docs/design/sdk-v1/02-zero-touch-join.md
§10.3, 03-key-hierarchy.md §2.1): the deterministic CBOR array

    ["RouteLoom", 1, 4, network, node_id, site_id, device_kid, sak_kid]

with version 1, purpose 4 (authority) and each kid a 32-byte bstr; every
integer is shortest-form. The join profile pins this context instead of the
generic 03 §2 exporter context; the Site Authority has emitted these bytes
since P3-3 (host/routeloom-join's dams_exporter_context) and the device's
sdkv1_ead.cpp twin must agree byte for byte. Only the exporter CONTEXT is
pinned — the output depends on the session PRK_exporter (the
protocol/edhoc-interop transcripts pin a whole exporter output for fixed
keys, and both ends' agreement on an authenticated session is EDHOC's own
property).

Keys are the shared test material; the context encoder below is written
from the design text and shares no code with C++ or Rust (only the key and
kid helpers of tools/gen_sdkv1_vectors.py, which are test material, not the
format under test).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "protocol" / "sdkv1-golden" / "dams"
FMT = "routeloom-sdkv1-dams-golden-v1"

_spec = importlib.util.spec_from_file_location(
    "gen_sdkv1_vectors", Path(__file__).resolve().parent / "gen_sdkv1_vectors.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)  # type: ignore[union-attr]

PURPOSE_AUTHORITY = 4
CONTEXT_MAX = 108


def cbor_uint(value: int) -> bytes:
    """CBOR unsigned integer, shortest form."""
    if value < 0:
        raise ValueError("unsigned only")
    if value < 24:
        return bytes((value,))
    if value <= 0xFF:
        return b"\x18" + value.to_bytes(1, "big")
    if value <= 0xFFFF:
        return b"\x19" + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return b"\x1a" + value.to_bytes(4, "big")
    return b"\x1b" + value.to_bytes(8, "big")


def dams_context(network: int, node_id: int, site_id: int,
                 device_kid: bytes, sak_kid: bytes) -> bytes:
    """["RouteLoom", 1, 4, network, node_id, site_id, device_kid, sak_kid]."""
    if network == 0 or network & 0xFFFFFFFF == 0:
        raise ValueError("network")
    if node_id in (0, 0xFFFFFFFFFFFFFFFF) or site_id in (0, 0xFFFFFFFFFFFFFFFF):
        raise ValueError("id")
    if len(device_kid) != 32 or len(sak_kid) != 32:
        raise ValueError("kid")
    context = (b"\x88\x69" + b"RouteLoom" +
               cbor_uint(1) + cbor_uint(PURPOSE_AUTHORITY) +
               cbor_uint(network) + cbor_uint(node_id) + cbor_uint(site_id) +
               b"\x58\x20" + device_kid + b"\x58\x20" + sak_kid)
    if len(context) > CONTEXT_MAX:
        raise AssertionError("context bound")
    return context


def emit(folder: str, name: str, record: dict) -> None:
    record = dict(record, format=FMT, name=name)
    path = OUT / folder / f"{name}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def good(name: str, network: int, node_id: int, site_id: int,
         device_kid: bytes, sak_kid: bytes, note: str) -> None:
    context = dams_context(network, node_id, site_id, device_kid, sak_kid)
    emit("valid", name,
         dict(codec="dams_context", expect="ok", network=network,
              node_id=node_id, site_id=site_id, device_kid_hex=device_kid.hex(),
              sak_kid_hex=sak_kid.hex(), context_hex=context.hex(),
              context_sha256=hashlib.sha256(context).hexdigest(), note=note))


def main() -> None:
    base.self_test()
    for sub in ("valid", "invalid"):
        shutil.rmtree(OUT / sub, ignore_errors=True)
        (OUT / sub).mkdir(parents=True)

    sak, device = base.seed(0x53), base.seed(0x54)
    site_id = 0x5173000000000042
    site_epoch, network_low32 = 3, 0x0A1B2C3D
    network = (site_epoch << 32) | network_low32
    node = 0x00A1000000001234
    device_kid = base.kid(base.pubkey(device))
    sak_kid = base.kid(base.pubkey(sak))

    good("dams_typical", network, node, site_id, device_kid, sak_kid,
         "the join test identities; full-width ids take the 8-byte form")
    good("dams_min", 1, 1, 1, bytes(32), b"\xff" * 32,
         "one-byte integer forms; all-zero/all-ones kids stay opaque bstrs")
    good("dams_wide", 0x1122334455, 0x0102030405060708, 0x0BADF00D,
         bytes(range(32)), bytes(range(32, 0, -1)),
         "5-byte and 4-byte integer forms inside the same context")

    emit("invalid", "dams_network_zero",
         dict(codec="dams_context", expect="error", network=0, node_id=node,
              site_id=site_id, device_kid_hex=device_kid.hex(),
              sak_kid_hex=sak_kid.hex(),
              note="network 0 is never a membership id"))
    emit("invalid", "dams_node_all_ones",
         dict(codec="dams_context", expect="error", network=network,
              node_id=0xFFFFFFFFFFFFFFFF, site_id=site_id,
              device_kid_hex=device_kid.hex(), sak_kid_hex=sak_kid.hex(),
              note="0xFF..FF is not a node id"))


if __name__ == "__main__":
    main()
