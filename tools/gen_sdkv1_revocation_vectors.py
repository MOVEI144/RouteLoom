#!/usr/bin/env python3
"""Regenerate protocol/sdkv1-golden/revocation/ — P6-1 (PR A) revocation
wire vectors.

Independent reference encoder for the new PR-A wire, written from the
layout text in the codec doc comments (no shared code with C++ or Rust
beyond the P-256/RFC 6979 signer and CBOR/Sign1 helpers of
tools/gen_sdkv1_vectors.py, the shared test material):

* link-only 1-hop Control (22) gossip bodies — StateEpochs (14 B) and
  RrsRequest (10 B) (`sdkv1_revocation.{hpp,cpp}` /
  `host/routeloom-wire/src/revocation.rs`);
* authority type-5 device→Host bodies — RrsApplied (40 B), RrsGet (8 B),
  RrsNoticeAccepted (40 B) (same twins; Host→device is the RRS1 COSE
  object itself);
* the kind-6 (RevocationSet) autonomy object envelope — manifest (38 B)
  and chunks (`autonomy_wire.{hpp,cpp}` / `routeloom-wire/src/autonomy.rs`)
  carrying a real SAK-signed RRS1 object end to end.

The RRS1 objects below are built by this file's own payload encoder plus
the shared test SAK (seed 0x53, same test site as the existing rrs1_*
vectors); consumers decode and verify them, so a layout mistake here fails
both harnesses instead of silently pinning a wrong shape.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "protocol" / "sdkv1-golden" / "revocation"
FMT = "routeloom-sdkv1-revocation-golden-v1"

_spec = importlib.util.spec_from_file_location(
    "gen_sdkv1_vectors", Path(__file__).resolve().parent / "gen_sdkv1_vectors.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)  # type: ignore[union-attr]

SITE_ID = 0x5173000000000042
SITE_EPOCH = 3
NETWORK = (SITE_EPOCH << 32) | 0x0A1B2C3D
SAK = base.seed(0x53)
REVOCATION_DOMAIN = b"RouteLoom/revocation-set/v1\x00"

RRS_CONTROL_VERSION = 1
SUB_STATE_EPOCHS = 0x61
SUB_REQUEST = 0x62
TYPE5_APPLIED = 1
TYPE5_GET = 2
TYPE5_NOTICE_ACCEPTED = 3
KIND_REVOCATION_SET = 6
OBJECT_MAX = 2048
CHUNK_DATA_MAX = 128 - 38


def u16(value: int) -> bytes:
    return struct.pack(">H", value)


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def rrs1_payload(site_id: int, network: int, rs_epoch: int, floor: int,
                 entries: list) -> bytes:
    """RRS1 payload: ver=1 | flags=0 | count u16 | site u64 | network u64 |
    rs_epoch u32 | floor u32 | entries × (node u64 | min_gen u32 | reason u8
    | 3 reserved), ascending node."""
    out = b"\x01\x00" + u16(len(entries)) + u64(site_id) + u64(network)
    out += u32(rs_epoch) + u32(floor)
    for node, generation, reason in entries:
        out += u64(node) + u32(generation) + bytes((reason,)) + b"\x00" * 3
    return out


def rrs1_object(site_id: int, network: int, rs_epoch: int, floor: int,
                entries: list) -> dict:
    """A real SAK-signed RRS1 object plus its intermediate encodings."""
    payload = rrs1_payload(site_id, network, rs_epoch, floor, entries)
    aad = REVOCATION_DOMAIN + u64(network)
    structure = base.sig_structure(payload, aad)
    signature = base.sign(SAK, structure)
    return dict(payload_hex=payload.hex(), aad_hex=aad.hex(),
                sig_structure_hex=structure.hex(),
                signature_hex=signature.hex(),
                object_hex=base.sign1(payload, signature).hex(),
                signer_pubkey_hex=base.pubkey(SAK).hex())


def state_epochs(site_epoch: int, applied_rs: int, gk_epoch: int) -> bytes:
    return (bytes((RRS_CONTROL_VERSION, SUB_STATE_EPOCHS)) +
            u32(site_epoch) + u32(applied_rs) + u32(gk_epoch))


def rrs_request(site_epoch: int, have_rs: int) -> bytes:
    return (bytes((RRS_CONTROL_VERSION, SUB_REQUEST)) +
            u32(site_epoch) + u32(have_rs))


def type5(sub: int, rs_epoch: int, digest: bytes = b"") -> bytes:
    return (bytes((RRS_CONTROL_VERSION, sub, 0, 0)) +
            u32(rs_epoch) + digest)


def manifest(kind: int, total_len: int, digest: bytes) -> bytes:
    return (b"\x01\x01" + bytes((kind, 0)) + u16(total_len) + digest)


def chunk(digest: bytes, offset: int, data: bytes) -> bytes:
    return (b"\x01\x01" + digest + u16(offset) + u16(len(data)) + data)


def emit(folder: str, name: str, record: dict) -> None:
    record = dict(record, format=FMT, name=name)
    path = OUT / folder / f"{name}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def good(name: str, codec: str, record: dict) -> None:
    emit("valid", name, dict(record, codec=codec, expect="ok"))


def bad(name: str, codec: str, encoded: bytes, note: str) -> None:
    emit("invalid", name, dict(codec=codec, expect="error",
                              encoded_hex=encoded.hex(), note=note))


def main() -> None:
    base.self_test()
    for sub in ("valid", "invalid"):
        shutil.rmtree(OUT / sub, ignore_errors=True)
        (OUT / sub).mkdir(parents=True)

    # ---- gossip bodies -------------------------------------------------
    body = state_epochs(SITE_EPOCH, 14, 7)
    assert len(body) == 14
    good("epochs_typical", "rrs_state_epochs",
         dict(site_epoch=SITE_EPOCH, applied_rs_epoch=14, gk_epoch=7,
              body_hex=body.hex(),
              note="a member at site epoch 3 with rs 14 and gk 7 applied"))
    body = state_epochs(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
    good("epochs_max", "rrs_state_epochs",
         dict(site_epoch=0xFFFFFFFF, applied_rs_epoch=0xFFFFFFFF,
              gk_epoch=0xFFFFFFFF, body_hex=body.hex(),
              note="hints carry no range check; epochs compare circularly"))
    body = rrs_request(SITE_EPOCH, 13)
    assert len(body) == 10
    good("request_typical", "rrs_request",
         dict(site_epoch=SITE_EPOCH, have_rs_epoch=13, body_hex=body.hex(),
              note="pull our rs 13 against the peer's newer advertisement"))
    body = rrs_request(SITE_EPOCH, 0)
    good("request_none", "rrs_request",
         dict(site_epoch=SITE_EPOCH, have_rs_epoch=0, body_hex=body.hex(),
              note="have 0: the requester holds no set for this site epoch"))

    # ---- authority type-5 bodies ---------------------------------------
    small_entries = [(0x00A1000000000100, 2, 1), (0x00A1000000000777, 4, 2)]
    small = rrs1_object(SITE_ID, NETWORK, 16, 2, small_entries)
    small_bytes = bytes.fromhex(small["object_hex"])
    small_digest = hashlib.sha256(small_bytes).digest()
    full_entries = [(0x00A1000000010000 + i * 3, i + 1, (i % 4) + 1)
                    for i in range(32)]
    full = rrs1_object(SITE_ID, NETWORK, 17, 2, full_entries)
    full_bytes = bytes.fromhex(full["object_hex"])
    assert len(full_bytes) == 616, len(full_bytes)
    full_digest = hashlib.sha256(full_bytes).digest()

    body = type5(TYPE5_APPLIED, 16, small_digest)
    assert len(body) == 40
    good("applied_typical", "rrs_applied",
         dict(rs_epoch=16, object_sha256_hex=small_digest.hex(),
              body_hex=body.hex(),
              note="applied evidence for the small object below (its sha256)"))
    body = type5(TYPE5_APPLIED, 0xFFFFFFFF, full_digest)
    good("applied_max_epoch", "rrs_applied",
         dict(rs_epoch=0xFFFFFFFF, object_sha256_hex=full_digest.hex(),
              body_hex=body.hex(), note="epoch bound, full-set digest"))
    body = type5(TYPE5_GET, 0)
    assert len(body) == 8
    good("get_latest", "rrs_get",
         dict(wanted_rs_epoch=0, body_hex=body.hex(),
              note="wanted 0 asks for the latest set"))
    body = type5(TYPE5_GET, 14)
    good("get_epoch", "rrs_get",
         dict(wanted_rs_epoch=14, body_hex=body.hex(),
              note="wanted names one rs epoch"))
    notice_digest = hashlib.sha256(b"RouteLoom revocation notice test v1").digest()
    body = type5(TYPE5_NOTICE_ACCEPTED, 16, notice_digest)
    assert len(body) == 40
    good("notice_accepted_typical", "rrs_notice_accepted",
         dict(rs_epoch=16, notice_sha256_hex=notice_digest.hex(),
              body_hex=body.hex(),
              note="PR B consumes the notice; PR A only pins these bytes"))

    # ---- RRS1 objects (kind-6 content, verified end to end) ------------
    good("rrs1_object_small", "rrs1_object",
         dict(small, site_id=SITE_ID, network=NETWORK, rs_epoch=16,
              site_epoch_floor=2, count=2,
              entry00_node=small_entries[0][0],
              entry00_min_generation=small_entries[0][1],
              entry00_reason=small_entries[0][2],
              entry01_node=small_entries[1][0],
              entry01_min_generation=small_entries[1][1],
              entry01_reason=small_entries[1][2],
              note="2-entry set; also the kind-6 small content"))
    good("rrs1_object_full32", "rrs1_object",
         dict(full, site_id=SITE_ID, network=NETWORK, rs_epoch=17,
              site_epoch_floor=2, count=32,
              entry00_node=full_entries[0][0],
              entry00_min_generation=1, entry00_reason=1,
              entry31_node=full_entries[31][0],
              entry31_min_generation=32, entry31_reason=4,
              note="32-entry set; the object is exactly 616 B"))

    # ---- kind-6 envelope ------------------------------------------------
    assert len(small_bytes) <= OBJECT_MAX
    wire = manifest(KIND_REVOCATION_SET, len(small_bytes), small_digest)
    assert len(wire) == 38
    good("kind6_manifest_small", "rrs_kind6_manifest",
         dict(kind=KIND_REVOCATION_SET, total_len=len(small_bytes),
              object_sha256_hex=small_digest.hex(), manifest_hex=wire.hex(),
              object_hex=small_bytes.hex(),
              signer_pubkey_hex=base.pubkey(SAK).hex(),
              site_id=SITE_ID, network=NETWORK, rs_epoch=16, count=2,
              note="manifest for the small object; content rides the chunks"))
    offset = 0
    index = 0
    while offset < len(small_bytes):
        data = small_bytes[offset:offset + CHUNK_DATA_MAX]
        wire = chunk(small_digest, offset, data)
        assert len(wire) <= 128
        good(f"kind6_chunk_small_{index}", "rrs_kind6_chunk",
             dict(object_sha256_hex=small_digest.hex(), offset=offset,
                  length=len(data), data_hex=data.hex(), chunk_hex=wire.hex(),
                  note=f"slice {index} of the small object"))
        offset += len(data)
        index += 1
    assert index == 2, index
    wire = manifest(KIND_REVOCATION_SET, len(full_bytes), full_digest)
    good("kind6_manifest_full32", "rrs_kind6_manifest",
         dict(kind=KIND_REVOCATION_SET, total_len=len(full_bytes),
              object_sha256_hex=full_digest.hex(), manifest_hex=wire.hex(),
              object_hex=full_bytes.hex(),
              signer_pubkey_hex=base.pubkey(SAK).hex(),
              site_id=SITE_ID, network=NETWORK, rs_epoch=17, count=32,
              note="manifest for the 616 B full set (no chunk plan pinned)"))

    # ---- invalid --------------------------------------------------------
    good_body = state_epochs(SITE_EPOCH, 14, 7)
    bad("epochs_bad_version", "rrs_state_epochs",
        b"\x02" + good_body[1:], "version is 1")
    bad("epochs_bad_sub", "rrs_state_epochs",
        good_body[:1] + b"\x63" + good_body[2:], "sub 0x63 is unassigned")
    bad("epochs_short_13", "rrs_state_epochs", good_body[:13],
        "14 B exact; a short body is not epochs")
    bad("epochs_long_15", "rrs_state_epochs", good_body + b"\x00",
        "14 B exact; a trailing byte is not epochs")
    good_body = rrs_request(SITE_EPOCH, 13)
    bad("request_bad_version", "rrs_request", b"\x02" + good_body[1:],
        "version is 1")
    bad("request_bad_sub", "rrs_request",
        good_body[:1] + b"\x61" + good_body[2:],
        "an epochs body is not a request")
    bad("request_short_9", "rrs_request", good_body[:9], "10 B exact")
    bad("request_long_11", "rrs_request", good_body + b"\x00", "10 B exact")
    good_body = type5(TYPE5_APPLIED, 16, small_digest)
    bad("applied_bad_sub", "rrs_applied",
        good_body[:1] + b"\x09" + good_body[2:], "sub 9 is unassigned")
    bad("applied_reserved_nonzero", "rrs_applied",
        good_body[:2] + b"\x01\x00" + good_body[4:],
        "reserved bytes stay zero")
    bad("applied_short_39", "rrs_applied", good_body[:39], "40 B exact")
    bad("applied_long_41", "rrs_applied", good_body + b"\x00", "40 B exact")
    good_body = type5(TYPE5_GET, 14)
    bad("get_bad_sub", "rrs_get", good_body[:1] + b"\x01" + good_body[2:],
        "an applied body is not a get")
    bad("get_reserved_nonzero", "rrs_get",
        good_body[:3] + b"\x01" + good_body[4:], "reserved bytes stay zero")
    bad("get_short_7", "rrs_get", good_body[:7], "8 B exact")
    bad("get_long_9", "rrs_get", good_body + b"\x00", "8 B exact")
    good_body = type5(TYPE5_NOTICE_ACCEPTED, 16, notice_digest)
    bad("notice_bad_sub", "rrs_notice_accepted",
        good_body[:1] + b"\x02" + good_body[2:], "a get body is not evidence")
    bad("notice_reserved_nonzero", "rrs_notice_accepted",
        good_body[:2] + b"\x00\x01" + good_body[4:],
        "reserved bytes stay zero")
    bad("notice_short_39", "rrs_notice_accepted", good_body[:39], "40 B exact")
    good_manifest = manifest(KIND_REVOCATION_SET, len(small_bytes), small_digest)
    bad("kind6_manifest_bad_version", "rrs_kind6_manifest",
        b"\x02" + good_manifest[1:], "version is 1")
    bad("kind6_manifest_bad_subtype", "rrs_kind6_manifest",
        good_manifest[:1] + b"\x02" + good_manifest[2:],
        "manifest subtype is 1")
    bad("kind6_manifest_kind5", "rrs_kind6_manifest",
        good_manifest[:2] + b"\x05" + good_manifest[3:],
        "kind 5 is the reserved P5 envelope, never a manifest here")
    bad("kind6_manifest_kind4", "rrs_kind6_manifest",
        good_manifest[:2] + b"\x04" + good_manifest[3:], "kind 4 unassigned")
    bad("kind6_manifest_flags_nonzero", "rrs_kind6_manifest",
        good_manifest[:3] + b"\x01" + good_manifest[4:], "flags stay zero")
    bad("kind6_manifest_total_len_zero", "rrs_kind6_manifest",
        good_manifest[:4] + b"\x00\x00" + good_manifest[6:],
        "an empty object has no manifest")
    bad("kind6_manifest_total_len_over_max", "rrs_kind6_manifest",
        good_manifest[:4] + u16(OBJECT_MAX + 1) + good_manifest[6:],
        "total_len stays within 2048")
    bad("kind6_manifest_short_37", "rrs_kind6_manifest",
        good_manifest[:37], "38 B exact")
    good_chunk = chunk(small_digest, 0, small_bytes[:CHUNK_DATA_MAX])
    bad("kind6_chunk_bad_version", "rrs_kind6_chunk",
        b"\x02" + good_chunk[1:], "version is 1")
    bad("kind6_chunk_bad_subtype", "rrs_kind6_chunk",
        good_chunk[:1] + b"\x02" + good_chunk[2:], "chunk subtype is 1")
    bad("kind6_chunk_length_mismatch", "rrs_kind6_chunk",
        good_chunk[:36] + u16(CHUNK_DATA_MAX - 1) + good_chunk[38:],
        "declared length must equal the trailing bytes")
    over = chunk(small_digest, OBJECT_MAX - 10, b"\x00" * 11)
    bad("kind6_chunk_overrun", "rrs_kind6_chunk", over,
        "offset + length stays within 2048")
    bad("kind6_chunk_short_37", "rrs_kind6_chunk", good_chunk[:37],
        "at least the 38 B header")
    bad("kind6_chunk_over_payload", "rrs_kind6_chunk",
        chunk(small_digest, 0, b"\x00" * (CHUNK_DATA_MAX + 1)),
        "a chunk fits the 128 B application payload")


if __name__ == "__main__":
    main()
