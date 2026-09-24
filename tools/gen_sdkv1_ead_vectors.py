#!/usr/bin/env python3
"""Regenerate protocol/sdkv1-golden/ead/ — SDK v1 join EAD vectors (plan P2-3).

Independent reference encoder for the zero-touch join EDHOC External
Authorization Data items of docs/design/sdk-v1/02-zero-touch-join.md
§6.1/§6.2 (JoinIntent, SiteOffer, JoinRequest, JoinResult, SitePackage)
and the RemovalNotice of 04-removal-revocation.md §6.1, as resolved in
02 "Resolved in implementation (P2-3)" and protocol/sdkv1-golden/ead/README.md,
plus the Credential item (label 65541, P3-1: the RLCW1 certificate of a
kid-referenced ID_CRED_x, after SiteOffer in EAD_2 / JoinRequest in EAD_3).
It shares no code with the C++ codec (components/routeloom/src/sdkv1_ead.cpp)
or the Rust mirror (host/routeloom-join); all three must agree on every byte.

The P-256 / RFC 6979 signer, the COSE helpers and the RLCW1 certificate
encoder are the ones of the sibling generator tools/gen_sdkv1_vectors.py
(the same independent Python reference; it self-tests against the RFC 6979
known answer before anything is emitted). Every key is TEST MATERIAL.

The generator also writes the fuzz seed corpus tests/fuzz/corpus/sdkv1_ead/
(the raw value / item / field / object bytes of every valid vector), so the
seeds never drift from the pinned layouts.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "protocol" / "sdkv1-golden" / "ead"
CORPUS = ROOT / "tests" / "fuzz" / "corpus" / "sdkv1_ead"
FMT = "routeloom-sdkv1-ead-golden-v1"

_spec = importlib.util.spec_from_file_location(
    "gen_sdkv1_vectors", Path(__file__).resolve().parent / "gen_sdkv1_vectors.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)  # type: ignore[union-attr]

u8, u16, u32, u64 = base.u8, base.u16, base.u32, base.u64
cbor_bstr, sig_structure, sign1, sign = base.cbor_bstr, base.sig_structure, base.sign1, base.sign
pubkey, seed = base.pubkey, base.seed

# --- EAD labels (absolute values; the wire carries -label, i.e. critical) ------
LABELS = {"intent": 65537, "offer": 65538, "request": 65539, "result": 65540,
          "credential": 65541}
VALUE_SIZE = {"intent": 12, "offer": 22, "request": 26}
RESULT_HEAD, RESULT_MAX = 12, 520
SITE_PACKAGE_SIZE = 120
PENDING_TICKET_MAX, ASSIGNMENT_TICKET_MAX = 48, 128

ALLOW, PENDING, DENY_NOT_HERE, DENY_BLOCKED, REMOVED, BUSY = 1, 2, 3, 4, 5, 6
REMOVAL_DOMAIN = b"RouteLoom/removal-notice/v1\x00"


def cbor_int(value: int) -> bytes:
    """Shortest-form CBOR integer (major 0 or 1)."""
    major, arg = (0, value) if value >= 0 else (0x20, -1 - value)
    if arg < 24:
        return u8(major | arg)
    if arg <= 0xFF:
        return u8(major | 24) + u8(arg)
    if arg <= 0xFFFF:
        return u8(major | 25) + u16(arg)
    if arg <= 0xFFFFFFFF:
        return u8(major | 26) + u32(arg)
    return u8(major | 27) + u64(arg)


def ead_item(kind: str, value: bytes) -> bytes:
    return cbor_int(-LABELS[kind]) + cbor_bstr(value)


def first4(data: bytes) -> int:
    return struct.unpack(">I", hashlib.sha256(data).digest()[:4])[0]


def org_hint(site_ca_pub: bytes) -> int:
    return first4(b"RouteLoom/org-hint/v1\x00" + site_ca_pub)


def site_hint(site_id: int) -> int:
    return first4(b"RouteLoom/site-hint/v1\x00" + u64(site_id))


# --- value encoders (02 §6.1/§6.2) -------------------------------------------------
def join_intent(r: dict, ver: int = 1, flags: int = 0, reserved: int = 0) -> bytes:
    return u8(ver) + u8(flags) + u32(r["org_hint"]) + u32(r["profile_bits"]) + u16(reserved)


def site_offer(r: dict, ver: int = 1, flags: int = 0, reserved: int = 0) -> bytes:
    return (u8(ver) + u8(flags) + u64(r["site_id"]) + u32(r["network_low32"]) +
            u32(r["site_epoch"]) + u16(r["decision_timeout_ms"]) + u16(reserved))


def join_request(r: dict, ver: int = 1, flags: int = 0, reserved: int = 0) -> bytes:
    return (u8(ver) + u8(flags) + u16(r["model"]) + u32(r["fw_version"]) +
            u32(r["capability"]) + u8(r["requested_role"]) + u8(reserved) +
            u64(r["last_site_id"]) + u32(r["last_generation"]))


def site_package(r: dict, ver: int = 1, flags: int = 0, reserved: tuple = (0, 0, 0)) -> bytes:
    out = (u8(ver) + u8(flags) + u16(reserved[0]) + u64(r["site_id"]) + u64(r["network"]) +
           u32(r["rs_epoch"]) + u32(r["gk_epoch"]) + bytes.fromhex(r["gk_hex"]) +
           u8(r["channel"]) + u8(r["role"]) + u8(r["gateway_count"]) + u8(reserved[1]) +
           u32(r["channel_epoch"]))
    for i in range(4):
        out += u64(r[f"gateway{i}"])
    out += (u64(r["authority_time_s"]) + u32(r["time_uncertainty_ms"]) +
            u32(r["membership_revision"]) + u32(reserved[2]))
    assert len(out) == SITE_PACKAGE_SIZE
    return out


def removal_payload(r: dict, ver: int = 1, reserved: int = 0) -> bytes:
    return (u8(ver) + u8(r["reason"]) + u16(reserved) + u64(r["site_id"]) + u64(r["node_id"]) +
            u32(r["generation"]) + u32(r["rs_epoch"]))


def removal_aad(network: int) -> bytes:
    return REMOVAL_DOMAIN + u64(network)


def join_result(verdict: int, retry: int, body: bytes, ver: int = 1, reason: int = 0,
                reserved: int = 0, body_len: int | None = None) -> bytes:
    n = len(body) if body_len is None else body_len
    return (u8(ver) + u8(verdict) + u16(reason) + u32(retry) + u16(n) + u16(reserved) + body)


def allow_body(member_cert: bytes, package: bytes, ticket: bytes = b"") -> bytes:
    return u16(len(member_cert)) + member_cert + package + u16(len(ticket)) + ticket


# --- emit ----------------------------------------------------------------------------
seeds: list[tuple[str, bytes]] = []


def emit(folder: str, name: str, record: dict) -> None:
    record = dict(record, format=FMT, name=name)
    path = OUT / folder / f"{name}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def good(name: str, codec: str, record: dict, **corpus: bytes) -> None:
    emit("valid", name, dict(record, codec=codec, expect="ok"))
    for kind, data in corpus.items():
        seeds.append((f"{name}.{kind}", data))


def bad(name: str, codec: str, encoded: bytes, note: str, expect: str = "error",
        **extra) -> None:
    record = dict(codec=codec, encoded_hex=encoded.hex(), expect=expect, note=note)
    record.update(extra)
    emit("invalid", name, record)


def main() -> None:
    base.self_test()
    for sub in ("valid", "invalid"):
        shutil.rmtree(OUT / sub, ignore_errors=True)
        (OUT / sub).mkdir(parents=True)
    shutil.rmtree(CORPUS, ignore_errors=True)
    CORPUS.mkdir(parents=True)

    # Test identities — the same seeds as tools/gen_sdkv1_vectors.py.
    device_ca, device_ca_id = seed(0x51), 0x0DCA000000000001
    site_ca, site_ca_id = seed(0x52), 0x05CA000000000001
    sak = seed(0x53)
    device, node = seed(0x54), 0x00A1000000001234
    peer, peer_node = seed(0x56), 0x00A1000000000777
    site_id = 0x5173000000000042
    site_epoch, network_low32 = 3, 0x0A1B2C3D
    network = (site_epoch << 32) | network_low32
    site_ca_pub, sak_pub = pubkey(site_ca), pubkey(sak)
    device_pub, peer_pub = pubkey(device), pubkey(peer)

    def cert(cert_type, issuer, subject, pub, serial, signer, **kw) -> bytes:
        fields = base.cert_fields(cert_type, issuer, subject, pub, serial, **kw)
        return bytes.fromhex(base.make_cert(fields, signer)["cert_hex"])

    devcert = cert(base.DEVICE, device_ca_id, node, device_pub, 90211, device_ca,
                   model=17, hw_rev=2)
    sitecert = cert(base.SITE, site_ca_id, site_id, sak_pub, 7, site_ca,
                    network_low32=network_low32, site_epoch=site_epoch, usage=1)

    def member(subject=node, pub=device_pub, issuer=site_id, net=network, role=0b001,
               generation=3, epoch=site_epoch, signer=sak, serial=4412) -> bytes:
        return cert(base.MEMBER, issuer, subject, pub, serial, signer, network=net, role=role,
                    assignment_generation=generation, site_epoch=epoch)

    membercert = member()
    # Allow-verification context shared by the join_result vectors.
    allow_ctx = dict(site_cert_hex=sitecert.hex(), node=node, device_pubkey_hex=device_pub.hex(),
                     strict_assignment=0, sak_secret_hex=sak.to_bytes(32, "big").hex())

    # ---- hints (02 §5.1/§5.2) --------------------------------------------------------
    good("hint_test_site", "hint", dict(site_ca_pubkey_hex=site_ca_pub.hex(),
                                        org_hint=org_hint(site_ca_pub), site_id=site_id,
                                        site_hint=site_hint(site_id)))

    # ---- JoinIntent (EAD_1) ----------------------------------------------------------
    intent = dict(org_hint=org_hint(site_ca_pub), profile_bits=0b11)
    for name, r in (("join_intent_rljoin_rlres", intent),
                    ("join_intent_rljoin_only", dict(intent, profile_bits=0b01)),
                    ("join_intent_hint_extremes", dict(org_hint=0xFFFFFFFF, profile_bits=1))):
        value = join_intent(r)
        item = ead_item("intent", value)
        assert len(value) == VALUE_SIZE["intent"] and len(item) == 18
        good(name, "join_intent", dict(r, value_hex=value.hex(), item_hex=item.hex(),
                                       label=LABELS["intent"], site_ca_pubkey_hex=site_ca_pub.hex()),
             value=value, item=item)
    iv = join_intent(intent)
    bad("join_intent_short", "join_intent", iv[:-1], "JoinIntent is exactly 12 bytes")
    bad("join_intent_long", "join_intent", iv + b"\x00", "JoinIntent is exactly 12 bytes")
    bad("join_intent_version_2", "join_intent", join_intent(intent, ver=2), "unknown version")
    bad("join_intent_flags_set", "join_intent", join_intent(intent, flags=1),
        "no JoinIntent flag is defined")
    bad("join_intent_reserved_set", "join_intent", join_intent(intent, reserved=1),
        "reserved must be zero")
    bad("join_intent_without_rljoin1", "join_intent",
        join_intent(dict(intent, profile_bits=0b10)), "profile bit0 (RLJOIN1) is required")
    bad("join_intent_unknown_profile", "join_intent",
        join_intent(dict(intent, profile_bits=0b1001)), "only profile bits 0..2 are defined")
    bad("join_intent_other_org", "join_intent",
        join_intent(dict(intent, org_hint=org_hint(sak_pub))),
        "org_hint of another Site CA (the authority does not answer it)", expect="deny",
        site_ca_pubkey_hex=site_ca_pub.hex())

    # ---- SiteOffer (EAD_2) -----------------------------------------------------------
    offer = dict(site_id=site_id, network_low32=network_low32, site_epoch=site_epoch,
                 decision_timeout_ms=2000)
    for name, r in (("site_offer_default", offer),
                    ("site_offer_min_timeout", dict(offer, decision_timeout_ms=500)),
                    ("site_offer_max_timeout", dict(offer, decision_timeout_ms=5000))):
        value = site_offer(r)
        item = ead_item("offer", value)
        assert len(value) == VALUE_SIZE["offer"]
        good(name, "site_offer", dict(r, value_hex=value.hex(), item_hex=item.hex(),
                                      label=LABELS["offer"], site_cert_hex=sitecert.hex()),
             value=value, item=item)
    ov = site_offer(offer)
    bad("site_offer_design_24_bytes", "site_offer", ov + b"\x00\x00",
        "02 §6.1 states 24 B but the listed fields sum to 22 B; the fields win")
    bad("site_offer_short", "site_offer", ov[:-1], "SiteOffer is exactly 22 bytes")
    bad("site_offer_version_2", "site_offer", site_offer(offer, ver=2), "unknown version")
    bad("site_offer_flags_set", "site_offer", site_offer(offer, flags=0x80),
        "no SiteOffer flag is defined")
    bad("site_offer_reserved_set", "site_offer", site_offer(offer, reserved=1),
        "reserved must be zero")
    bad("site_offer_site_zero", "site_offer", site_offer(dict(offer, site_id=0)),
        "site_id 0 is invalid")
    bad("site_offer_site_all_ones", "site_offer",
        site_offer(dict(offer, site_id=0xFFFFFFFFFFFFFFFF)), "site_id all-ones is invalid")
    bad("site_offer_network_zero", "site_offer", site_offer(dict(offer, network_low32=0)),
        "network_low32 0 is invalid")
    bad("site_offer_timeout_499", "site_offer", site_offer(dict(offer, decision_timeout_ms=499)),
        "decision_timeout_ms below 500")
    bad("site_offer_timeout_5001", "site_offer",
        site_offer(dict(offer, decision_timeout_ms=5001)), "decision_timeout_ms above 5000")
    for name, r, note in (
            ("site_offer_other_site", dict(offer, site_id=site_id + 1), "site_id != SiteCert sub"),
            ("site_offer_other_network", dict(offer, network_low32=network_low32 + 1),
             "network_low32 != SiteCert"),
            ("site_offer_other_epoch", dict(offer, site_epoch=site_epoch + 1),
             "site_epoch != SiteCert")):
        bad(name, "site_offer", site_offer(r), note, expect="deny", site_cert_hex=sitecert.hex())

    # ---- JoinRequest (EAD_3) ---------------------------------------------------------
    request = dict(model=17, fw_version=0x01040000, capability=0b010, requested_role=0b001,
                   last_site_id=0, last_generation=0)
    for name, r in (("join_request_first_join", request),
                    ("join_request_rejoin_relay",
                     dict(request, requested_role=0b011, last_site_id=site_id,
                          last_generation=3)),
                    ("join_request_gateway_max",
                     dict(request, capability=0b111, requested_role=0b111, fw_version=0xFFFFFFFF,
                          last_site_id=0xFFFFFFFFFFFFFFFE, last_generation=0xFFFFFFFF))):
        value = join_request(r)
        item = ead_item("request", value)
        assert len(value) == VALUE_SIZE["request"]
        good(name, "join_request", dict(r, value_hex=value.hex(), item_hex=item.hex(),
                                        label=LABELS["request"], dev_cert_hex=devcert.hex()),
             value=value, item=item)
    rv = join_request(request)
    bad("join_request_design_30_bytes", "join_request", rv + b"\x00" * 4,
        "02 §6.1 states 30 B but the listed fields sum to 26 B; the fields win")
    bad("join_request_short", "join_request", rv[:-1], "JoinRequest is exactly 26 bytes")
    bad("join_request_version_2", "join_request", join_request(request, ver=2), "unknown version")
    bad("join_request_flags_set", "join_request", join_request(request, flags=1),
        "no JoinRequest flag is defined")
    bad("join_request_reserved_set", "join_request", join_request(request, reserved=1),
        "reserved must be zero")
    bad("join_request_unknown_capability", "join_request",
        join_request(dict(request, capability=0b100000)), "capability bits 0..4 only")
    bad("join_request_role_zero", "join_request", join_request(dict(request, requested_role=0)),
        "a role is required")
    bad("join_request_role_unknown", "join_request",
        join_request(dict(request, requested_role=0b1001)), "role bits 0..2 only")
    bad("join_request_gateway_without_capability", "join_request",
        join_request(dict(request, requested_role=0b101)),
        "gateway role needs the gateway capability")
    bad("join_request_relay_without_capability", "join_request",
        join_request(dict(request, capability=0, requested_role=0b010)),
        "relay role needs the relay capability")
    bad("join_request_generation_without_site", "join_request",
        join_request(dict(request, last_generation=1)), "last_generation needs a last_site_id")
    bad("join_request_site_without_generation", "join_request",
        join_request(dict(request, last_site_id=site_id)), "a last site has generation >= 1")
    bad("join_request_last_site_all_ones", "join_request",
        join_request(dict(request, last_site_id=0xFFFFFFFFFFFFFFFF, last_generation=1)),
        "last_site_id all-ones is invalid")
    bad("join_request_other_model", "join_request", join_request(dict(request, model=18)),
        "model differs from the verified DevCert", expect="deny", dev_cert_hex=devcert.hex())

    # ---- SitePackage (Allow body) ----------------------------------------------------
    package = dict(site_id=site_id, network=network, rs_epoch=14, gk_epoch=203,
                   gk_hex=bytes(range(0x30, 0x50)).hex(), channel=6, role=0b001,
                   gateway_count=2, channel_epoch=9, gateway0=0x00A1000000000001,
                   gateway1=0x00A1000000000002, gateway2=0, gateway3=0,
                   authority_time_s=1790000000, time_uncertainty_ms=1500,
                   membership_revision=41)
    package_max = dict(package, rs_epoch=0xFFFFFFFF, gk_epoch=0xFFFFFFFF, channel=14,
                       role=0b111, gateway_count=4, channel_epoch=0xFFFFFFFF,
                       gateway2=0x00A1000000000003, gateway3=0xFFFFFFFFFFFFFFFE,
                       authority_time_s=0xFFFFFFFFFFFFFFFF, time_uncertainty_ms=0xFFFFFFFF,
                       membership_revision=0xFFFFFFFF, gk_hex="ff" * 32)
    package_first = dict(package, rs_epoch=0, channel=1, gateway_count=1, gateway1=0,
                         authority_time_s=0, time_uncertainty_ms=0, membership_revision=0)
    for name, r in (("site_package_two_gateways", package), ("site_package_max", package_max),
                    ("site_package_first_boot", package_first)):
        value = site_package(r)
        good(name, "site_package", dict(r, value_hex=value.hex()), value=value)
    pv = site_package(package)
    bad("site_package_short", "site_package", pv[:-1], "SitePackage is exactly 120 bytes")
    bad("site_package_version_2", "site_package", site_package(package, ver=2), "unknown version")
    bad("site_package_flags_set", "site_package", site_package(package, flags=1),
        "no SitePackage flag is defined")
    for i, note in ((0, "reserved u16 at 2"), (1, "reserved u8 at 63"), (2, "reserved u32 at 116")):
        res = [0, 0, 0]
        res[i] = 1
        bad(f"site_package_reserved_{i}", "site_package", site_package(package, reserved=tuple(res)),
            f"{note} must be zero")
    for name, patch, note in (
            ("site_package_site_zero", dict(site_id=0), "site_id 0"),
            ("site_package_network_low_zero", dict(network=site_epoch << 32), "network low32 0"),
            ("site_package_gk_epoch_zero", dict(gk_epoch=0), "gk_epoch starts at 1"),
            ("site_package_gk_zero", dict(gk_hex="00" * 32), "an all-zero GK"),
            ("site_package_channel_zero", dict(channel=0), "channel 1..14"),
            ("site_package_channel_15", dict(channel=15), "channel 1..14"),
            ("site_package_role_zero", dict(role=0), "role nonzero"),
            ("site_package_role_unknown", dict(role=0b1000), "role bits 0..2"),
            ("site_package_gateway_count_zero", dict(gateway_count=0, gateway0=0, gateway1=0),
             "gateway_count 1..4"),
            ("site_package_gateway_count_5", dict(gateway_count=5), "gateway_count 1..4"),
            ("site_package_gateway_tail", dict(gateway2=0x00A1000000000009),
             "unused gateway slots are zero"),
            ("site_package_gateway_duplicate", dict(gateway1=0x00A1000000000001),
             "gateway ids are unique"),
            ("site_package_gateway_zero", dict(gateway1=0), "listed gateway ids are valid")):
        bad(name, "site_package", site_package(dict(package, **patch)), note)

    # ---- RemovalNotice (04 §6.1) ---------------------------------------------------------
    removal = dict(reason=1, site_id=site_id, node_id=node, generation=3, rs_epoch=15)

    def removal_doc(r: dict, net: int = network, signer: int = sak) -> dict:
        payload = removal_payload(r)
        aad = removal_aad(net)
        structure = sig_structure(payload, aad)
        signature = sign(signer, structure)
        obj = sign1(payload, signature)
        assert len(obj) == 103
        return dict(r, payload_hex=payload.hex(), aad_hex=aad.hex(),
                    sig_structure_hex=structure.hex(), signature_hex=signature.hex(),
                    object_hex=obj.hex(), network=net,
                    signer_secret_hex=signer.to_bytes(32, "big").hex(),
                    signer_pubkey_hex=pubkey(signer).hex())

    notice_ctx = dict(signer_pubkey_hex=sak_pub.hex(), own_site_id=site_id,
                      own_network=network, own_node=node, own_generation=3)
    for name, r in (("removal_notice_removed", removal),
                    ("removal_notice_lost_newer_generation",
                     dict(removal, reason=2, generation=4, rs_epoch=0xFFFFFFFF))):
        doc = removal_doc(r)
        good(name, "removal_notice", dict(doc, **notice_ctx),
             object=bytes.fromhex(doc["object_hex"]))
    good_notice = bytes.fromhex(removal_doc(removal)["object_hex"])

    def notice_signed(payload: bytes, net: int = network, signer: int = sak) -> bytes:
        return sign1(payload, sign(signer, sig_structure(payload, removal_aad(net))))

    for name, patch, note in (("removal_notice_reason_zero", dict(reason=0), "reason 1..4"),
                              ("removal_notice_reason_5", dict(reason=5), "reason 1..4"),
                              ("removal_notice_generation_zero", dict(generation=0),
                               "generation >= 1"),
                              ("removal_notice_rs_epoch_zero", dict(rs_epoch=0), "rs_epoch >= 1"),
                              ("removal_notice_node_zero", dict(node_id=0), "node_id 0"),
                              ("removal_notice_site_all_ones",
                               dict(site_id=0xFFFFFFFFFFFFFFFF), "site_id all-ones")):
        bad(name, "removal_notice", notice_signed(removal_payload(dict(removal, **patch))), note,
            **notice_ctx)
    bad("removal_notice_version_2", "removal_notice",
        notice_signed(removal_payload(removal, ver=2)), "unknown version", **notice_ctx)
    bad("removal_notice_reserved_set", "removal_notice",
        notice_signed(removal_payload(removal, reserved=1)), "reserved must be zero",
        **notice_ctx)
    bad("removal_notice_payload_29", "removal_notice",
        notice_signed(removal_payload(removal) + b"\x00"), "payload is exactly 28 bytes",
        **notice_ctx)
    bad("removal_notice_trailing_byte", "removal_notice", good_notice + b"\x00",
        "nothing may follow the Sign1", **notice_ctx)
    flipped = bytearray(good_notice)
    flipped[-3] ^= 0x01
    bad("removal_notice_bad_signature", "removal_notice", bytes(flipped),
        "signature does not verify", expect="deny", **notice_ctx)
    bad("removal_notice_other_network_aad", "removal_notice",
        notice_signed(removal_payload(removal), net=network + 1),
        "signed under another network's external AAD", expect="deny", **notice_ctx)
    bad("removal_notice_wrong_sak", "removal_notice", good_notice,
        "checked against a different SAK", expect="deny",
        **dict(notice_ctx, signer_pubkey_hex=peer_pub.hex()))
    bad("removal_notice_other_node", "removal_notice", good_notice,
        "addressed to another node", expect="deny", **dict(notice_ctx, own_node=peer_node))
    bad("removal_notice_other_site", "removal_notice", good_notice,
        "another site's notice", expect="deny", **dict(notice_ctx, own_site_id=site_id + 1))
    bad("removal_notice_older_generation", "removal_notice", good_notice,
        "generation below the device's own MemberCert generation", expect="deny",
        **dict(notice_ctx, own_generation=4))

    # ---- JoinResult (EAD_4) --------------------------------------------------------------
    pkg = site_package(package)

    def result_doc(verdict: int, retry: int, body: bytes, **fields) -> tuple[dict, bytes, bytes]:
        value = join_result(verdict, retry, body)
        item = ead_item("result", value)
        doc = dict(verdict=verdict, retry_after_s=retry, body_len=len(body), value_hex=value.hex(),
                   item_hex=item.hex(), label=LABELS["result"], **fields)
        return doc, value, item

    ticket = bytes(range(0x60, 0x60 + 64))
    pending_ticket = bytes(range(0x90, 0x90 + 48))
    member_max = member(generation=0xFFFFFFFF, role=0b111, serial=0xFFFFFFFF)
    pkg_max_role = site_package(dict(package, role=0b111))
    cases = [
        ("join_result_allow", ALLOW, 0, allow_body(membercert, pkg),
         dict(member_cert_hex=membercert.hex(), site_package_hex=pkg.hex(),
              assignment_ticket_hex="", verified=1, **allow_ctx)),
        ("join_result_allow_max_cert", ALLOW, 0, allow_body(member_max, pkg_max_role),
         dict(member_cert_hex=member_max.hex(), site_package_hex=pkg_max_role.hex(),
              assignment_ticket_hex="", verified=1, **allow_ctx)),
        ("join_result_allow_with_ticket", ALLOW, 0, allow_body(membercert, pkg, ticket),
         dict(member_cert_hex=membercert.hex(), site_package_hex=pkg.hex(),
              assignment_ticket_hex=ticket.hex(), verified=1, **allow_ctx)),
        ("join_result_pending", PENDING, 300, pending_ticket,
         dict(pending_ticket_hex=pending_ticket.hex())),
        ("join_result_pending_bounds", PENDING, 30, b"\x01", dict(pending_ticket_hex="01")),
        ("join_result_pending_max_retry", PENDING, 3600, pending_ticket[:17],
         dict(pending_ticket_hex=pending_ticket[:17].hex())),
        ("join_result_deny_not_here", DENY_NOT_HERE, 0, b"", {}),
        ("join_result_deny_blocked", DENY_BLOCKED, 0, b"", {}),
        ("join_result_removed", REMOVED, 0, good_notice,
         dict(removal_notice_hex=good_notice.hex(), **notice_ctx)),
        ("join_result_busy", BUSY, 1, b"", {}),
        ("join_result_busy_max", BUSY, 3600, b"", {}),
    ]
    for name, verdict, retry, body, fields in cases:
        doc, value, item = result_doc(verdict, retry, body, **fields)
        good(name, "join_result", doc, value=value, item=item)
    allow_value = join_result(ALLOW, 0, allow_body(membercert, pkg))
    # 02 §6: m4 allow ≈355 B — the EAD_4 item here is well inside it.
    assert len(ead_item("result", allow_value)) == 5 + 3 + len(allow_value) < 355

    # Largest JoinResult: 256-byte certificate slot is never reached by a real
    # MemberCert (<= 208 B), so the bound is exercised with the ticket.
    big_ticket = bytes([0xA5]) * ASSIGNMENT_TICKET_MAX
    big = join_result(ALLOW, 0, allow_body(member_max, pkg_max_role, big_ticket))
    doc, value, item = result_doc(ALLOW, 0, allow_body(member_max, pkg_max_role, big_ticket),
                                  member_cert_hex=member_max.hex(),
                                  site_package_hex=pkg_max_role.hex(),
                                  assignment_ticket_hex=big_ticket.hex(), verified=1,
                                  **allow_ctx)
    assert value == big
    good("join_result_allow_max_ticket", "join_result", doc, value=value, item=item)

    def rbad(name: str, encoded: bytes, note: str, expect: str = "error", **extra) -> None:
        bad(name, "join_result", encoded, note, expect=expect, **extra)

    rbad("join_result_head_only_short", allow_value[:11], "the head is 12 bytes")
    rbad("join_result_version_2", join_result(DENY_NOT_HERE, 0, b"", ver=2), "unknown version")
    rbad("join_result_verdict_zero", join_result(0, 0, b""), "verdict 1..6")
    rbad("join_result_verdict_7", join_result(7, 0, b""), "verdict 1..6")
    rbad("join_result_reason_set", join_result(DENY_BLOCKED, 0, b"", reason=1),
         "no reason code is defined in v1")
    rbad("join_result_reserved_set", join_result(DENY_BLOCKED, 0, b"", reserved=1),
         "reserved must be zero")
    rbad("join_result_body_len_short", join_result(PENDING, 300, pending_ticket, body_len=47),
         "body_len must equal the remaining bytes")
    rbad("join_result_body_len_long", join_result(PENDING, 300, pending_ticket, body_len=49),
         "body_len must equal the remaining bytes")
    rbad("join_result_deny_with_body", join_result(DENY_NOT_HERE, 0, b"\x00"),
         "deny verdicts carry no body")
    rbad("join_result_busy_with_body", join_result(BUSY, 5, b"\x00"),
         "AuthorityBusy carries no body")
    rbad("join_result_deny_retry", join_result(DENY_NOT_HERE, 60, b""),
         "deny avoid times are fixed by the device (retry 0)")
    rbad("join_result_allow_retry", join_result(ALLOW, 1, allow_body(membercert, pkg)),
         "Allow has retry_after_s 0")
    rbad("join_result_busy_retry_zero", join_result(BUSY, 0, b""), "AuthorityBusy retry >= 1")
    rbad("join_result_busy_retry_3601", join_result(BUSY, 3601, b""), "retry <= 3600")
    rbad("join_result_pending_retry_29", join_result(PENDING, 29, pending_ticket),
         "pending retry 30..3600")
    rbad("join_result_pending_retry_3601", join_result(PENDING, 3601, pending_ticket),
         "pending retry 30..3600")
    rbad("join_result_pending_no_ticket", join_result(PENDING, 300, b""),
         "pending carries a 1..48 byte ticket")
    rbad("join_result_pending_ticket_49", join_result(PENDING, 300, pending_ticket + b"\x00"),
         "pending ticket <= 48 bytes")
    rbad("join_result_removed_empty", join_result(REMOVED, 0, b""),
         "Removed carries a RemovalNotice")
    rbad("join_result_removed_garbage", join_result(REMOVED, 0, b"\x00" * 103),
         "Removed body must parse as a RemovalNotice Sign1")
    rbad("join_result_allow_devcert", join_result(ALLOW, 0, allow_body(devcert, pkg)),
         "the Allow certificate must be a MemberCert")
    rbad("join_result_allow_cert_len_zero", join_result(ALLOW, 0, allow_body(b"", pkg)),
         "MemberCert length 1..256")
    body = allow_body(membercert, pkg)
    rbad("join_result_allow_cert_len_overrun",
         join_result(ALLOW, 0, u16(len(membercert) + 1) + body[2:]),
         "MemberCert length inconsistent with the body")
    rbad("join_result_allow_ticket_len_overrun", join_result(ALLOW, 0, body[:-2] + u16(1)),
         "ticket length runs past the body")
    rbad("join_result_allow_trailing", join_result(ALLOW, 0, body + b"\x00"),
         "nothing may follow the ticket")
    rbad("join_result_allow_ticket_129",
         join_result(ALLOW, 0, allow_body(membercert, pkg, b"\x01" * 129)),
         "AssignmentTicket <= 128 bytes")
    rbad("join_result_allow_bad_package",
         join_result(ALLOW, 0, allow_body(membercert, site_package(dict(package, channel=0)))),
         "the SitePackage must validate")
    rbad("join_result_allow_cert_trailing_inside",
         join_result(ALLOW, 0, allow_body(membercert + b"\x00", pkg)),
         "the MemberCert slot holds exactly one canonical certificate")
    oversize = join_result(PENDING, 300, b"\x00" * (RESULT_MAX + 1 - RESULT_HEAD))
    assert len(oversize) == RESULT_MAX + 1
    rbad("join_result_oversize", oversize, "JoinResult <= 520 bytes")
    rbad("join_result_allow_trailing_max", big + b"\x00", "nothing may follow the largest Allow")

    # V1-J12: well-formed Allow whose MemberCert/SitePackage disagree — the
    # device stores nothing (verified = false).
    def allow_deny(name: str, cert_bytes: bytes, package_bytes: bytes, note: str,
                   **ctx_patch) -> None:
        ctx = dict(allow_ctx, **ctx_patch)
        rbad(name, join_result(ALLOW, 0, allow_body(cert_bytes, package_bytes)), note,
             expect="deny", **ctx)

    allow_deny("join_allow_other_node", member(subject=peer_node), pkg, "MemberCert sub != node")
    allow_deny("join_allow_other_key", member(pub=peer_pub), pkg, "MemberCert cnf != device key")
    allow_deny("join_allow_peer_cert", member(subject=peer_node, pub=peer_pub, generation=1,
                                              role=0b010), pkg, "another member's certificate")
    allow_deny("join_allow_other_issuer", member(issuer=site_id + 1), pkg,
               "MemberCert iss != SiteCert sub")
    other_low = (site_epoch << 32) | (network_low32 + 1)
    allow_deny("join_allow_other_network_low32", member(net=other_low),
               site_package(dict(package, network=other_low)),
               "MemberCert network low32 != SiteCert network_low32")
    allow_deny("join_allow_other_site_epoch", member(net=(4 << 32) | network_low32, epoch=4),
               site_package(dict(package, network=(4 << 32) | network_low32)),
               "MemberCert site_epoch != SiteCert site_epoch")
    allow_deny("join_allow_package_network_mismatch", membercert,
               site_package(dict(package, network=other_low)),
               "SitePackage network != MemberCert network")
    allow_deny("join_allow_package_site_mismatch", membercert,
               site_package(dict(package, site_id=site_id + 1)),
               "SitePackage site_id != SiteCert sub")
    allow_deny("join_allow_package_role_mismatch", membercert,
               site_package(dict(package, role=0b011)), "SitePackage role != MemberCert role")
    allow_deny("join_allow_not_signed_by_sak", member(signer=peer), pkg,
               "MemberCert not signed by the SAK of the m2 SiteCert")
    allow_deny("join_allow_strict_without_ticket", membercert, pkg,
               "A2 (strict_assignment) requires an AssignmentTicket", strict_assignment=1)

    # ---- EAD field (CBOR sequence) --------------------------------------------------------
    intent_value = join_intent(intent)
    intent_item = ead_item("intent", intent_value)
    for name, ead, note in (
            ("ead_intent_only", intent_item, "the single critical item"),
            ("ead_intent_padding_before", cbor_int(0) + cbor_bstr(b"\x00" * 4) + intent_item,
             "padding (label 0) before the item is ignored"),
            ("ead_intent_padding_after_no_value", intent_item + cbor_int(0),
             "padding without a value is ignored"),
            ("ead_intent_padding_both", cbor_int(0) + intent_item + cbor_int(0) +
             cbor_bstr(b"\xaa" * 30), "padding on both sides")):
        good(name, "ead_field", dict(ead_hex=ead.hex(), expected="intent",
                                     value_hex=intent_value.hex(), note=note), field=ead)
    result_value = join_result(DENY_BLOCKED, 0, b"")
    result_item = ead_item("result", result_value)
    good("ead_result_only", "ead_field", dict(ead_hex=result_item.hex(), expected="result",
                                              value_hex=result_value.hex(),
                                              note="EAD_4 with an empty-body JoinResult"),
         field=result_item)

    def ebad(name: str, ead: bytes, note: str, expected: str = "intent") -> None:
        bad(name, "ead_field", ead, note, expected=expected)

    ebad("ead_empty", b"", "an EAD field with no item")
    ebad("ead_padding_only", cbor_int(0) + cbor_bstr(b"\x00"), "the join item is required")
    ebad("ead_non_critical", cbor_int(LABELS["intent"]) + cbor_bstr(intent_value),
         "join items must be critical (negative label)")
    ebad("ead_unknown_critical", cbor_int(-65542) + cbor_bstr(intent_value),
         "unknown critical label")
    ebad("ead_credential_in_m1", ead_item("credential", devcert) + intent_item,
         "the Credential item rides EAD_2/EAD_3 only")
    ebad("ead_unknown_noncritical", intent_item + cbor_int(1) + cbor_bstr(b"\x00"),
         "no other item is accepted (strict)")
    ebad("ead_wrong_message", ead_item("offer", site_offer(offer)),
         "a SiteOffer where EAD_1 expects a JoinIntent")
    ebad("ead_duplicated", intent_item + intent_item, "the item appears exactly once")
    ebad("ead_trailing_bstr", intent_item + cbor_bstr(b"\x00"),
         "a bstr without a label after the item")
    ebad("ead_trailing_garbage", intent_item + b"\xff", "trailing non-integer byte")
    ebad("ead_label_nonminimal", b"\x3b" + u64(65536) + cbor_bstr(intent_value),
         "label must use the shortest form")
    ebad("ead_value_nonminimal", cbor_int(-LABELS["intent"]) + b"\x58\x0c" + intent_value,
         "bstr length must use the shortest form")
    ebad("ead_value_indefinite", cbor_int(-LABELS["intent"]) + b"\x5f" + cbor_bstr(intent_value) +
         b"\xff", "indefinite-length bstr")
    ebad("ead_value_text", cbor_int(-LABELS["intent"]) + b"\x6c" + intent_value,
         "the value must be a bstr")
    ebad("ead_missing_value", cbor_int(-LABELS["intent"]), "the join item carries a value")
    ebad("ead_value_size", cbor_int(-LABELS["intent"]) + cbor_bstr(intent_value + b"\x00"),
         "JoinIntent value must be 12 bytes")
    ebad("ead_value_truncated", intent_item[:-1], "the bstr runs past the field")
    ebad("ead_result_oversize", cbor_int(-LABELS["result"]) + cbor_bstr(oversize),
         "JoinResult value above 520 bytes", expected="result")
    ebad("ead_padding_text_value", cbor_int(0) + b"\x61\x00" + intent_item,
         "padding values are bstr")

    # ---- Credential item (label 65541, P3-1): kid-referenced ID_CRED_x plus the
    # full RLCW1 certificate in EAD — SiteCert in EAD_2, DevCert in EAD_3 -------------
    offer_item = ead_item("offer", site_offer(offer))
    request_item = ead_item("request", join_request(request))
    site_kid, dev_kid = base.kid(sak_pub), base.kid(device_pub)
    for name, cert, cert_type, kid_value, item, expected, pad, note in (
            ("ead2_sitecert_offer", sitecert, "site", site_kid, offer_item, "offer", False,
             "EAD_2: SiteOffer then Credential(SiteCert)"),
            ("ead3_devcert_request", devcert, "device", dev_kid, request_item, "request", False,
             "EAD_3: JoinRequest then Credential(DevCert)"),
            ("ead3_devcert_request_padding", devcert, "device", dev_kid, request_item, "request",
             True, "padding between and after the two items is ignored")):
        cred_item = ead_item("credential", cert)
        ead = (item + cbor_int(0) + cbor_bstr(b"\x00" * 3) + cred_item + cbor_int(0)) if pad \
            else item + cred_item
        value = site_offer(offer) if expected == "offer" else join_request(request)
        good(name, "ead_field_credential",
             dict(ead_hex=ead.hex(), expected=expected, credential_hex=cert.hex(),
                  value_hex=value.hex(), cert_type=cert_type, kid_hex=kid_value.hex(),
                  credential_item_hex=cred_item.hex(), label=LABELS["credential"], note=note),
             field=ead, item=cred_item)

    def cbad(name: str, ead: bytes, note: str, expected: str = "offer") -> None:
        bad(name, "ead_field_credential", ead, note, expected=expected)

    site_item = ead_item("credential", sitecert)
    cbad("ead2_missing_credential", offer_item, "EAD_2 needs the SiteCert credential")
    cbad("ead2_credential_first", site_item + offer_item, "the SiteOffer item comes first")
    cbad("ead2_credential_only", site_item, "the SiteOffer item is required")
    cbad("ead2_credential_twice", offer_item + site_item + site_item, "one Credential")
    cbad("ead2_offer_twice", offer_item + offer_item + site_item, "one SiteOffer")
    cbad("ead2_extra_intent", offer_item + site_item + intent_item, "no other item")
    cbad("ead2_request_instead", request_item + site_item, "EAD_2 carries a SiteOffer")
    cbad("ead2_credential_non_critical",
         offer_item + cbor_int(LABELS["credential"]) + cbor_bstr(sitecert),
         "the Credential item is critical")
    cbad("ead2_credential_empty", offer_item + cbor_int(-LABELS["credential"]) + cbor_bstr(b""),
         "a certificate is 1..256 B")
    cbad("ead2_credential_oversize",
         offer_item + cbor_int(-LABELS["credential"]) + cbor_bstr(b"\x00" * 257),
         "a certificate is at most 256 B")
    cbad("ead2_credential_no_value", offer_item + cbor_int(-LABELS["credential"]),
         "the Credential item carries a value")
    cbad("ead3_trailing_byte", request_item + ead_item("credential", devcert) + b"\xff",
         "trailing byte", expected="request")

    # join_credential_check: the certificate decodes as the right type and its
    # cnf key hashes to the kid of the same message's ID_CRED_x.
    def cred_bad(name: str, cert: bytes, cert_type: str, kid_value: bytes, expect: str,
                 note: str) -> None:
        bad(name, "credential", cert, note, expect=expect, cert_type=cert_type,
            kid_hex=kid_value.hex())

    cred_bad("credential_kid_mismatch", sitecert, "site", dev_kid, "deny",
             "the SiteCert cnf does not hash to this kid")
    cred_bad("credential_wrong_type", devcert, "site", dev_kid, "deny",
             "a DevCert where the SiteCert is expected")
    cred_bad("credential_kid_short", devcert, "device", dev_kid[:31], "deny",
             "kid = SHA-256, 32 B")
    cred_bad("credential_trailing", devcert + b"\x00", "device", dev_kid, "error",
             "one canonical certificate, no trailing byte")
    cred_bad("credential_garbage", b"\xa0" * 20, "device", dev_kid, "error", "not a COSE_Sign1")

    for name, data in seeds:
        (CORPUS / name).write_bytes(data)


if __name__ == "__main__":
    main()
