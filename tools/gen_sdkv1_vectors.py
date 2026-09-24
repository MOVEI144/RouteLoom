#!/usr/bin/env python3
"""Regenerate protocol/sdkv1-golden/*.json — SDK v1 (G-SEC) shared vectors.

Independent reference encoder for the byte layouts in
docs/design/sdk-v1/02-zero-touch-join.md (§2 RLI1, §3 RLCW1, §10.3 RLS1),
04-removal-revocation.md (§2 RRS1), 05-nvs-state-37.md (§3.2 RLP1) and
07-host-api-tooling.md (§6 steps 2-3, the device-key proof of possession),
as resolved in protocol/sdkv1-golden/README.md. It shares no code with the
C++ codecs (components/routeloom/src/{rlcw1,sdkv1_records,sdkv1_pop}.cpp)
or the Rust mirror (host/routeloom-provision/src/sdkv1/); all three must
agree on every byte.

Signatures: ECDSA P-256 / SHA-256 with the RFC 6979 deterministic nonce,
normalized to low-S. Python's standard library has no ECDSA and the
`cryptography` package offers deterministic signing only in recent
versions, so this generator carries a small pure-Python P-256 used ONLY to
produce test vectors. It is pinned at start-up by the RFC 6979 A.2.5
known-answer test (P-256, SHA-256, message "sample") and must reproduce
the provisioning-golden test_keypair public keys. The Rust harness re-signs
with RustCrypto `p256` and must match these signatures byte-for-byte; the
C++ harness verifies them with the vendored micro-ecc (its deterministic
signer is not RFC 6979, so the C++ side is verify-only). Every key here is
TEST MATERIAL (a repeated seed byte) and never a real key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "protocol" / "sdkv1-golden"
FMT = "routeloom-sdkv1-golden-v1"

# --- P-256 (test-vector use only) --------------------------------------------
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _mul(k, point=G):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def on_curve(xy: bytes) -> bool:
    x, y = int.from_bytes(xy[:32], "big"), int.from_bytes(xy[32:], "big")
    return x < P and y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def pubkey(secret: int) -> bytes:
    x, y = _mul(secret)
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def rfc6979_k(secret: int, h1: bytes) -> int:
    x = secret.to_bytes(32, "big")
    h = (int.from_bytes(h1, "big") % N).to_bytes(32, "big")  # bits2octets
    v, k = b"\x01" * 32, b"\x00" * 32
    k = _hmac(k, v + b"\x00" + x + h)
    v = _hmac(k, v)
    k = _hmac(k, v + b"\x01" + x + h)
    v = _hmac(k, v)
    while True:
        v = _hmac(k, v)
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = _hmac(k, v + b"\x00")
        v = _hmac(k, v)


def sign_raw(secret: int, message: bytes, low_s: bool = True):
    h1 = hashlib.sha256(message).digest()
    e = int.from_bytes(h1, "big")
    k = rfc6979_k(secret, h1)
    r = _mul(k)[0] % N
    s = pow(k, N - 2, N) * (e + r * secret) % N
    assert r and s
    if low_s and s > N // 2:
        s = N - s
    return r, s


def sign(secret: int, message: bytes) -> bytes:
    r, s = sign_raw(secret, message)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def self_test() -> None:
    # RFC 6979 A.2.5: P-256, SHA-256, message "sample" (raw s, no low-S).
    x = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    assert pubkey(x).hex().upper() == (
        "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
        "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")
    assert rfc6979_k(x, hashlib.sha256(b"sample").digest()) == \
        0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
    r, s = sign_raw(x, b"sample", low_s=False)
    assert r == 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
    assert s == 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
    # Same test_keypair(0x11) public key the provisioning golden pins.
    assert pubkey(int.from_bytes(b"\x11" * 32, "big")).hex() == (
        "0217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed"
        "194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794")


# --- byte helpers -------------------------------------------------------------
def u8(v): return struct.pack(">B", v)
def u16(v): return struct.pack(">H", v)
def u32(v): return struct.pack(">I", v)
def u64(v): return struct.pack(">Q", v)
def crc32(data: bytes) -> int: return zlib.crc32(data) & 0xFFFFFFFF  # ISO-HDLC


def cbor_uint(v: int) -> bytes:
    if v < 24:
        return u8(v)
    if v <= 0xFF:
        return b"\x18" + u8(v)
    if v <= 0xFFFF:
        return b"\x19" + u16(v)
    if v <= 0xFFFFFFFF:
        return b"\x1a" + u32(v)
    return b"\x1b" + u64(v)


def cbor_bstr(data: bytes) -> bytes:
    n = len(data)
    if n < 24:
        return u8(0x40 + n) + data
    if n <= 0xFF:
        return b"\x58" + u8(n) + data
    return b"\x59" + u16(n) + data


# --- COSE ES256 restricted profile --------------------------------------------
PROTECTED = bytes.fromhex("a10126")  # {1: -7}


def cose_key(pub: bytes) -> bytes:
    # {1:2 kty EC2, 3:-7 alg ES256, -1:1 crv P-256, -2:x, -3:y}
    return (bytes.fromhex("a5010203262001") + b"\x21" + cbor_bstr(pub[:32]) +
            b"\x22" + cbor_bstr(pub[32:]))


def kid(pub: bytes) -> bytes:
    return hashlib.sha256(cose_key(pub)).digest()


def sig_structure(payload: bytes, aad: bytes = b"") -> bytes:
    return (b"\x84" + b"\x6a" + b"Signature1" + cbor_bstr(PROTECTED) +
            cbor_bstr(aad) + cbor_bstr(payload))


def sign1(payload: bytes, signature: bytes) -> bytes:
    return b"\xd2\x84" + cbor_bstr(PROTECTED) + b"\xa0" + cbor_bstr(payload) + \
        cbor_bstr(signature)


# --- RLCW1 --------------------------------------------------------------------
DEVICE, SITE, MEMBER = 1, 2, 3
PRIVATE_LABEL = bytes.fromhex("3a00010000")  # -65537


def cert_payload(c: dict) -> bytes:
    t = c["cert_type"]
    if t == DEVICE:
        private = [DEVICE, c["model"], c["hw_rev"], c["serial"]]
    elif t == SITE:
        private = [SITE, c["network_low32"], c["site_epoch"], c["usage"], c["serial"]]
    else:
        private = [MEMBER, c["network"], c["role"], c["assignment_generation"],
                   c["site_epoch"], c["serial"]]
    return (b"\xa4" + b"\x01" + cbor_uint(c["issuer"]) + b"\x02" + cbor_uint(c["subject"]) +
            b"\x08" + b"\xa1\x01" + cose_key(bytes.fromhex(c["pubkey_hex"])) +
            PRIVATE_LABEL + u8(0x80 + len(private)) +
            b"".join(cbor_uint(v) for v in private))


def cert_fields(cert_type, issuer, subject, pub, serial, **kw):
    fields = dict(cert_type=cert_type, issuer=issuer, subject=subject,
                  pubkey_hex=pub.hex(), serial=serial, model=0, hw_rev=0,
                  network_low32=0, usage=0, network=0, role=0,
                  assignment_generation=0, site_epoch=0)
    fields.update(kw)
    return fields


def make_cert(fields: dict, signer_secret: int) -> dict:
    payload = cert_payload(fields)
    structure = sig_structure(payload)
    signature = sign(signer_secret, structure)
    record = dict(fields)
    record.update(payload_hex=payload.hex(), sig_structure_hex=structure.hex(),
                  signature_hex=signature.hex(), cert_hex=sign1(payload, signature).hex(),
                  signer_secret_hex=signer_secret.to_bytes(32, "big").hex(),
                  signer_pubkey_hex=pubkey(signer_secret).hex(),
                  subject_kid_hex=kid(bytes.fromhex(fields["pubkey_hex"])).hex())
    return record


# --- sealed records -----------------------------------------------------------
SEAL = {"RLI1": 0x1DE71771, "RLS1": 0x5173AB1E, "RRS1": 0x2E5E7C0D}


def sealed(magic: bytes, body: bytes, seal: int, seq: int | None = None,
           fmt: int = 1, schema: int = 1) -> bytes:
    head_len = 16 if seq is None else 20
    used = head_len + len(body) + 4
    head = magic + u16(fmt) + u16(used) + u32(schema) + u32(seal)
    if seq is not None:
        head += u32(seq)
    data = head + body
    return data + u32(crc32(data))


def recrc(record: bytes) -> bytes:
    return record[:-4] + u32(crc32(record[:-4]))


def rli1_body(r: dict) -> bytes:
    body = (u64(r["node_id"]) + u8(r["key_location"]) + u8(r["flags"]) +
            u8(len(r["anchors"])) + b"\x00" + u32(0) + bytes.fromhex(r["kid_hex"]) +
            bytes.fromhex(r["pubkey_hex"]) + bytes.fromhex(r["key_material_hex"]))
    for anchor_id, kind, status, pub in r["anchors"]:
        body += u64(anchor_id) + u8(kind) + u8(status) + b"\x00" * 6 + pub
    devcert = bytes.fromhex(r["devcert_hex"])
    return body + u16(len(devcert)) + u16(0) + devcert


def rls1_body(r: dict) -> bytes:
    body = (u64(r["site_id"]) + u64(r["network"]) + u32(r["assignment_generation"]) +
            u32(r["rs_epoch_floor"]) + u32(r["gk_epoch_current"]) + u32(r["gk_epoch_next"]) +
            bytes.fromhex(r["gk_current_hex"]) + bytes.fromhex(r["gk_next_hex"]) +
            bytes.fromhex(r["dams_hex"]) + u8(r["state"]) + u8(r["role"]) +
            u8(r["gateway_count"]) + u8(r["channel"]) + u32(r["channel_epoch"]) +
            u32(r["boot_witness"]))
    for i in range(4):
        body += u64(r[f"gateway{i}"])
    site = bytes.fromhex(r["site_cert_hex"])
    member = bytes.fromhex(r["member_cert_hex"])
    return body + u16(len(site)) + u16(len(member)) + site + member


REVOCATION_DOMAIN = b"RouteLoom/revocation-set/v1\x00"
POP_DOMAIN = b"RouteLoom/device-key-pop/v1\x00"


def rrs1_payload(r: dict, count_override=None, version=1, flags=0) -> bytes:
    entries = r["entries"]
    count = len(entries) if count_override is None else count_override
    out = (u8(version) + u8(flags) + u16(count) + u64(r["site_id"]) + u64(r["network"]) +
           u32(r["rs_epoch"]) + u32(r["site_epoch_floor"]))
    for node, generation, reason in entries:
        out += u64(node) + u32(generation) + u8(reason) + b"\x00" * 3
    return out


def rrs1_aad(network: int) -> bytes:
    return REVOCATION_DOMAIN + u64(network)


def rlp1(r: dict) -> bytes:
    data = (b"RLP1" + u8(1) + u8(r["purpose"]) + u8(r["state"]) + u8(r["flags"]) +
            u64(r["peer"]) + u64(r["network"]) + bytes.fromhex(r["peer_cert_id_hex"]) +
            u32(r["peer_generation"]) + u32(r["created_gk_epoch"]) +
            u32(r["last_used_boot"]) + u32(0) + bytes.fromhex(r["rms_hex"]))
    return data + u32(crc32(data))


def rlx1(r: dict, payload: bytes, seal: int = 0x4C583101,
         seq: int = 7) -> bytes:
    body = (u32(seq) + u8(r["mode"]) + b"\x00" + u16(len(payload)) +
            u64(r["self_node"]) + u64(r["site_id"]) +
            u64(r["old_network"]) + u64(0) + u32(r["generation"]) +
            u32(r["rs_floor"]) + u32(r["gk_floor"]) +
            u32(r["boot_witness"]) + u64(0) + u32(0) + payload)
    head = b"RLX1" + u16(1) + u16(16 + len(body) + 4) + u32(1) + u32(seal)
    data = head + body
    return data + u32(crc32(data))


def rlp2(r: dict) -> bytes:
    data = (b"RLP2" + u8(1) + u8(r["purpose"]) + u8(r["state"]) + u8(r["flags"]) +
            u64(r["peer"]) + u64(r["network"]) + bytes.fromhex(r["peer_cert_id_hex"]) +
            bytes.fromhex(r["local_cert_id_hex"]) + u32(r["peer_generation"]) +
            u32(r["peer_role"]) + u32(r["created_gk_epoch"]) + u32(r["last_used_boot"]) +
            u32(r["reserved_uses"]) + bytes.fromhex(r["rms_hex"]))
    return data + u32(crc32(data))


def rlv1(r: dict, seal: int, commit_seq: int) -> bytes:
    data = (b"RLV1" + u16(1) + u16(108) + u32(1) + u32(seal) + u32(commit_seq) +
            u64(r["local_node"]) + u64(r["site_id"]) + u64(r["network"]) +
            u32(r["removed_generation"]) + u32(r["rs_epoch_floor"]) +
            u32(r["site_epoch_floor"]) + u8(r["state"]) + u8(r["cause"]) + u16(0) +
            bytes.fromhex(r["evidence_digest_hex"]) + u32(r["rls_commit_seq"]) +
            u32(r["boot_witness"]) + u32(r["holdoff_ms"]))
    return data + u32(crc32(data))


# --- emit ---------------------------------------------------------------------
def emit(folder: str, name: str, record: dict) -> None:
    record = dict(record, format=FMT, name=name)
    path = OUT / folder / f"{name}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def bad(name: str, codec: str, encoded: bytes, note: str, expect: str = "error",
        **extra) -> None:
    record = dict(codec=codec, encoded_hex=encoded.hex(), expect=expect, note=note)
    record.update(extra)
    emit("invalid", name, record)


def seed(byte: int) -> int:
    return int.from_bytes(bytes([byte]) * 32, "big")


def main() -> None:
    self_test()
    for sub in ("valid", "invalid"):
        shutil.rmtree(OUT / sub, ignore_errors=True)
        (OUT / sub).mkdir(parents=True)

    # Test identities (seed byte x32 scalars — TEST MATERIAL ONLY).
    device_ca, device_ca_id = seed(0x51), 0x0DCA000000000001
    site_ca, site_ca_id = seed(0x52), 0x05CA000000000001
    sak = seed(0x53)
    device, node = seed(0x54), 0x00A1000000001234
    verifier_key, verifier_id = seed(0x55), 0x0A55000000000001
    peer, peer_node = seed(0x56), 0x00A1000000000777
    old_site_ca, old_site_ca_id = seed(0x57), 0x05CA000000000002
    site_id = 0x5173000000000042
    site_epoch, network_low32 = 3, 0x0A1B2C3D
    network = (site_epoch << 32) | network_low32
    device_pub, sak_pub, peer_pub = pubkey(device), pubkey(sak), pubkey(peer)

    # ---- RLCW1 -------------------------------------------------------------
    devcert = make_cert(cert_fields(DEVICE, device_ca_id, node, device_pub, 90211,
                                    model=17, hw_rev=2), device_ca)
    sitecert = make_cert(cert_fields(SITE, site_ca_id, site_id, sak_pub, 7,
                                     network_low32=network_low32, site_epoch=site_epoch,
                                     usage=1), site_ca)
    membercert = make_cert(cert_fields(MEMBER, site_id, node, device_pub, 4412,
                                       network=network, role=0b001,
                                       assignment_generation=3, site_epoch=site_epoch), sak)
    peercert = make_cert(cert_fields(MEMBER, site_id, peer_node, peer_pub, 4413,
                                     network=network, role=0b010,
                                     assignment_generation=1, site_epoch=site_epoch), sak)
    big = 0xFFFFFFFE
    member_max = make_cert(cert_fields(MEMBER, 0xFEDCBA9876543210, 0xFEDCBA9876543211,
                                       device_pub, 0xFFFFFFFF,
                                       network=(big << 32) | 0xFFFFFFFF, role=0b111,
                                       assignment_generation=0xFFFFFFFF, site_epoch=big), sak)
    devcert_small = make_cert(cert_fields(DEVICE, 1, 2, device_pub, 0, model=0, hw_rev=0),
                              device_ca)
    assert len(bytes.fromhex(member_max["cert_hex"])) == 208  # largest v1 certificate
    for name, cert in (("cert_devcert", devcert), ("cert_sitecert", sitecert),
                       ("cert_membercert", membercert), ("cert_membercert_peer", peercert),
                       ("cert_membercert_max", member_max),
                       ("cert_devcert_small_ints", devcert_small)):
        emit("valid", name, dict(cert, codec="rlcw1", expect="ok"))

    good = bytes.fromhex(membercert["cert_hex"])
    good_payload = bytes.fromhex(membercert["payload_hex"])
    signer = dict(signer_pubkey_hex=sak_pub.hex())

    def cert_with_payload(payload: bytes) -> bytes:
        return sign1(payload, sign(sak, sig_structure(payload)))

    bad("cert_trailing_byte", "rlcw1", good + b"\x00", "nothing may follow the Sign1", **signer)
    bad("cert_untagged", "rlcw1", good[1:], "the COSE_Sign1 must carry tag 18", **signer)
    bad("cert_cwt_tag61", "rlcw1", b"\xd8\x3d" + good, "CWT tag 61 is not part of the profile",
        **signer)
    bad("cert_protected_esp256", "rlcw1",
        good.replace(bytes.fromhex("43a10126"), bytes.fromhex("43a10128"), 1),
        "protected header must be exactly {1:-7} (ES256)", **signer)
    bad("cert_unprotected_not_empty", "rlcw1",
        b"\xd2\x84\x43\xa1\x01\x26\xa1\x04\x41\x00" + good[7:],
        "unprotected header must be the empty map", **signer)
    bad("cert_indefinite_payload", "rlcw1",
        good[:7] + b"\x5f" + cbor_bstr(good_payload) + b"\xff" + cbor_bstr(bytes(64)),
        "indefinite-length byte strings are not canonical", **signer)
    bad("cert_payload_length_nonminimal", "rlcw1",
        good[:7] + b"\x59" + u16(len(good_payload)) + good_payload + good[9 + len(good_payload):],
        "payload bstr length must use the shortest form", **signer)
    bad("cert_oversize", "rlcw1", good + b"\x00" * (257 - len(good)),
        "certificate above the 256-byte bound", **signer)
    # Claim-level defects, each re-signed so only the named defect fails.
    small = bytes.fromhex(devcert_small["payload_hex"])
    bad("cert_uint_nonminimal", "rlcw1",
        cert_with_payload(small.replace(b"\x01\x01\x02\x02", b"\x01\x18\x01\x02\x02", 1)),
        "integers must use the shortest encoding (iss 1 as 0x18 0x01)", **signer)
    bad("cert_unknown_claim_exp", "rlcw1",
        cert_with_payload(b"\xa5" + good_payload[1:] + b"\x04\x1a\x00\x01\x00\x00"),
        "unknown claims (exp) are rejected", **signer)
    split = good_payload.index(b"\x08\xa1\x01")
    iss_sub = good_payload[1:split]
    sub_at = iss_sub.index(b"\x02" + cbor_uint(node))
    bad("cert_claims_out_of_order", "rlcw1",
        cert_with_payload(b"\xa4" + iss_sub[sub_at:] + iss_sub[:sub_at] + good_payload[split:]),
        "claim keys must appear in canonical order 1, 2, 8, -65537", **signer)
    bad("cert_private_array_mismatch", "rlcw1",
        cert_with_payload(good_payload.replace(PRIVATE_LABEL + b"\x86\x03",
                                               PRIVATE_LABEL + b"\x85\x03", 1)),
        "private-claim array length must match its type", **signer)
    bad("cert_unknown_type", "rlcw1",
        cert_with_payload(good_payload.replace(PRIVATE_LABEL + b"\x86\x03",
                                               PRIVATE_LABEL + b"\x86\x04", 1)),
        "certificate type 4 is not defined", **signer)
    bad("cert_member_epoch_mismatch", "rlcw1",
        cert_with_payload(cert_payload(dict(membercert, site_epoch=site_epoch + 1))),
        "MemberCert network>>32 must equal site_epoch", **signer)
    bad("cert_member_generation_zero", "rlcw1",
        cert_with_payload(cert_payload(dict(membercert, assignment_generation=0))),
        "MemberCert assignment_generation must be >= 1", **signer)
    bad("cert_member_unknown_role", "rlcw1",
        cert_with_payload(cert_payload(dict(membercert, role=0b1000))),
        "MemberCert role bits must be known", **signer)
    bad("cert_subject_zero", "rlcw1",
        cert_with_payload(cert_payload(dict(membercert, subject=0))),
        "subject 0 is not a node id", **signer)
    bad("cert_subject_all_ones", "rlcw1",
        cert_with_payload(cert_payload(dict(membercert, subject=(1 << 64) - 1))),
        "subject all-ones is the broadcast id", **signer)
    off = bytearray(device_pub)
    off[63] ^= 0x01
    assert not on_curve(bytes(off))
    bad("cert_key_off_curve", "rlcw1",
        cert_with_payload(cert_payload(dict(membercert, pubkey_hex=bytes(off).hex()))),
        "cnf key must be a P-256 point", **signer)
    bad("cert_cnf_alg_es384", "rlcw1",
        cert_with_payload(good_payload.replace(bytes.fromhex("a501020326"),
                                               bytes.fromhex("a50102033822"), 1)),
        "cnf COSE_Key must be the canonical EC2/ES256/P-256 key", **signer)
    bad("cert_site_usage_zero", "rlcw1",
        sign1(cert_payload(dict(sitecert, usage=0)),
              sign(site_ca, sig_structure(cert_payload(dict(sitecert, usage=0))))),
        "SiteCert usage must be nonzero known bits",
        signer_pubkey_hex=pubkey(site_ca).hex())
    flipped = bytearray(good)
    flipped[-1] ^= 0x01
    bad("cert_bad_signature", "rlcw1", bytes(flipped),
        "well-formed but the signature does not verify", expect="deny", **signer)
    r_s = good[-64:]
    high_s = r_s[:32] + (N - int.from_bytes(r_s[32:], "big")).to_bytes(32, "big")
    bad("cert_high_s", "rlcw1", good[:-64] + high_s,
        "the high-S twin of a valid signature is rejected (low-S only)", expect="deny", **signer)
    bad("cert_wrong_signer", "rlcw1", good,
        "a valid certificate checked against another key", expect="deny",
        signer_pubkey_hex=pubkey(site_ca).hex())

    # ---- RLI1 --------------------------------------------------------------
    anchors = [(site_ca_id, 1, 1, pubkey(site_ca)),
               (old_site_ca_id, 1, 2, pubkey(old_site_ca)),
               (verifier_id, 2, 1, pubkey(verifier_key))]
    rli1 = dict(node_id=node, key_location=1, flags=0x03, kid_hex=kid(device_pub).hex(),
                pubkey_hex=device_pub.hex(), key_material_hex=device.to_bytes(32, "big").hex(),
                anchors=anchors, devcert_hex=devcert["cert_hex"])

    def rli1_doc(r: dict) -> dict:
        doc = {k: v for k, v in r.items() if k != "anchors"}
        doc["anchor_count"] = len(r["anchors"])
        for i, (anchor_id, kind, status, pub) in enumerate(r["anchors"]):
            doc[f"anchor{i}_id"] = anchor_id
            doc[f"anchor{i}_kind"] = kind
            doc[f"anchor{i}_status"] = status
            doc[f"anchor{i}_pubkey_hex"] = pub.hex()
        return doc

    rli1_record = sealed(b"RLI1", rli1_body(rli1), SEAL["RLI1"])
    assert len(rli1_record) == 160 + 3 * 80 + 4 + len(bytes.fromhex(devcert["cert_hex"])) + 4
    emit("valid", "rli1_strict_three_anchors",
         dict(rli1_doc(rli1), codec="rli1", expect="ok", record_hex=rli1_record.hex()))
    rli1_min = dict(rli1, key_location=0, flags=0, key_material_hex="00" * 32,
                    anchors=[anchors[0]])
    rli1_min_record = sealed(b"RLI1", rli1_body(rli1_min), SEAL["RLI1"])
    emit("valid", "rli1_minimal",
         dict(rli1_doc(rli1_min), codec="rli1", expect="ok", record_hex=rli1_min_record.hex()))

    def rli1_bad(name, r=None, record=None, note=""):
        if record is None:
            record = sealed(b"RLI1", rli1_body(r), SEAL["RLI1"])
        bad(name, "rli1", record, note)

    rli1_bad("rli1_bad_crc", record=rli1_record[:-1] + bytes([rli1_record[-1] ^ 1]),
             note="CRC-32/ISO-HDLC mismatch")
    rli1_bad("rli1_pending_seal", record=sealed(b"RLI1", rli1_body(rli1), 0),
             note="a pending (uncommitted) record is not a committed identity")
    rli1_bad("rli1_format_2", record=sealed(b"RLI1", rli1_body(rli1), SEAL["RLI1"], fmt=2),
             note="unknown format version")
    rli1_bad("rli1_schema_2", record=sealed(b"RLI1", rli1_body(rli1), SEAL["RLI1"], schema=2),
             note="unknown schema version (Unsupported)")
    rli1_bad("rli1_trailing_byte", record=rli1_record + b"\x00",
             note="bytes beyond used_len")
    rli1_bad("rli1_kid_mismatch", dict(rli1, kid_hex="00" * 31 + "01"),
             note="kid must be SHA-256 of the canonical COSE_Key")
    rli1_bad("rli1_keypair_mismatch", dict(rli1, key_material_hex=(seed(0x60)).to_bytes(32, "big").hex()),
             note="location 1 scalar must reproduce the public key")
    rli1_bad("rli1_no_active_site_ca", dict(rli1_min, anchors=[(site_ca_id, 1, 2, pubkey(site_ca))]),
             note="at least one ACTIVE SiteCA anchor is required")
    rli1_bad("rli1_strict_without_verifier", dict(rli1_min, flags=0x02),
             note="strict_assignment requires an active AssignmentVerifier anchor")
    rli1_bad("rli1_anchor_duplicated", dict(rli1_min, anchors=[anchors[0], anchors[0]]),
             note="anchor ids must be unique")
    rli1_bad("rli1_unknown_flag", dict(rli1_min, flags=0x04), note="flags beyond bits 0-1")
    other_devcert = make_cert(cert_fields(DEVICE, device_ca_id, node + 1, device_pub, 1,
                                          model=17, hw_rev=2), device_ca)
    rli1_bad("rli1_devcert_subject_mismatch", dict(rli1, devcert_hex=other_devcert["cert_hex"]),
             note="DevCert sub must equal node_id")
    body = bytearray(rli1_body(rli1_min))
    body[11] = 1  # reserved byte after anchor_count
    rli1_bad("rli1_reserved_nonzero", record=sealed(b"RLI1", bytes(body), SEAL["RLI1"]),
             note="reserved bytes must be zero")

    # ---- RLS1 --------------------------------------------------------------
    rls1 = dict(state=1, site_id=site_id, network=network, assignment_generation=3,
                rs_epoch_floor=14, gk_epoch_current=203, gk_epoch_next=204,
                gk_current_hex=bytes(range(0x20, 0x40)).hex(),
                gk_next_hex=bytes(range(0x40, 0x60)).hex(),
                dams_hex=bytes(range(0x60, 0x80)).hex(), role=1, gateway_count=2, channel=6,
                channel_epoch=9, boot_witness=1234, gateway0=0x00A1000000000001,
                gateway1=0x00A1000000000002, gateway2=0, gateway3=0,
                site_cert_hex=sitecert["cert_hex"], member_cert_hex=membercert["cert_hex"])
    rls1_record = sealed(b"RLS1", rls1_body(rls1), SEAL["RLS1"], seq=41)
    emit("valid", "rls1_member", dict(rls1, codec="rls1", expect="ok", commit_seq=41,
                                      record_hex=rls1_record.hex()))
    cleared = dict(rls1, state=0, site_id=0, network=0, assignment_generation=0,
                   rs_epoch_floor=0, gk_epoch_current=0, gk_epoch_next=0,
                   gk_current_hex="00" * 32, gk_next_hex="00" * 32, dams_hex="00" * 32,
                   role=0, gateway_count=0, channel=0, channel_epoch=0, boot_witness=0,
                   gateway0=0, gateway1=0, site_cert_hex="", member_cert_hex="")
    cleared_record = sealed(b"RLS1", rls1_body(cleared), SEAL["RLS1"], seq=42)
    assert len(cleared_record) == 200
    emit("valid", "rls1_cleared", dict(cleared, codec="rls1", expect="ok", commit_seq=42,
                                       record_hex=cleared_record.hex()))

    def rls1_bad(name, r, note):
        bad(name, "rls1", sealed(b"RLS1", rls1_body(r), SEAL["RLS1"], seq=41), note)

    bad("rls1_bad_crc", "rls1", rls1_record[:-1] + bytes([rls1_record[-1] ^ 1]), "CRC mismatch")
    rls1_bad("rls1_gateway_count_5", dict(rls1, gateway_count=5), "gateway_count is 1..4")
    rls1_bad("rls1_gateway_tail_nonzero", dict(rls1, gateway2=5),
             "gateways beyond gateway_count must be zero")
    rls1_bad("rls1_channel_zero", dict(rls1, channel=0), "channel is 1..14")
    rls1_bad("rls1_gk_next_without_epoch", dict(rls1, gk_epoch_next=0),
             "gk_next bytes require gk_epoch_next")
    rls1_bad("rls1_generation_mismatch", dict(rls1, assignment_generation=4),
             "MemberCert generation must equal the record")
    rls1_bad("rls1_network_mismatch", dict(rls1, network=network + 1),
             "MemberCert/SiteCert network must equal the record")
    rls1_bad("rls1_certs_swapped", dict(rls1, site_cert_hex=membercert["cert_hex"],
                                        member_cert_hex=sitecert["cert_hex"]),
             "SiteCert then MemberCert, each of its own type")
    rls1_bad("rls1_tombstone_residue", dict(cleared, boot_witness=1),
             "a cleared (state 0) record carries no data")
    rls1_bad("rls1_state_2", dict(rls1, state=2), "state is 0 (cleared) or 1 (member)")

    # ---- RRS1 --------------------------------------------------------------
    rrs1 = dict(site_id=site_id, network=network, rs_epoch=14, site_epoch_floor=2,
                entries=[(0x00A1000000000100, 2, 1), (0x00A1000000000777, 4, 2),
                         (0x00A10000000009AB, 1, 4)])

    def rrs1_doc(r: dict, object_seq: int, sak_secret: int = sak) -> dict:
        payload = rrs1_payload(r)
        aad = rrs1_aad(r["network"])
        structure = sig_structure(payload, aad)
        signature = sign(sak_secret, structure)
        obj = sign1(payload, signature)
        record = sealed(b"RRS1", obj, SEAL["RRS1"], seq=object_seq)
        doc = {k: v for k, v in r.items() if k != "entries"}
        doc.update(count=len(r["entries"]), payload_hex=payload.hex(), aad_hex=aad.hex(),
                   sig_structure_hex=structure.hex(), signature_hex=signature.hex(),
                   object_hex=obj.hex(), commit_seq=object_seq, record_hex=record.hex(),
                   signer_secret_hex=sak_secret.to_bytes(32, "big").hex(),
                   signer_pubkey_hex=pubkey(sak_secret).hex())
        for i, (node_id, generation, reason) in enumerate(r["entries"]):
            doc[f"entry{i:02d}_node"] = node_id
            doc[f"entry{i:02d}_min_generation"] = generation
            doc[f"entry{i:02d}_reason"] = reason
        return doc

    emit("valid", "rrs1_three_entries", dict(rrs1_doc(rrs1, 5), codec="rrs1", expect="ok"))
    cutover = dict(rrs1, rs_epoch=15, site_epoch_floor=site_epoch, entries=[])
    emit("valid", "rrs1_cutover_empty", dict(rrs1_doc(cutover, 6), codec="rrs1", expect="ok"))
    full = dict(rrs1, rs_epoch=0xFFFFFFFF,
                entries=[(0x00A1000000010000 + i * 3, i + 1, (i % 4) + 1) for i in range(32)])
    full_doc = rrs1_doc(full, 0xFFFFFFF0)
    assert len(bytes.fromhex(full_doc["object_hex"])) == 616
    assert len(bytes.fromhex(full_doc["record_hex"])) == 640
    emit("valid", "rrs1_full_32", dict(full_doc, codec="rrs1", expect="ok"))
    tomb = sealed(b"RRS1", b"", SEAL["RRS1"], seq=7)
    emit("valid", "rrs1_record_cleared", dict(codec="rrs1_record", expect="ok", commit_seq=7,
                                              count=0, record_hex=tomb.hex()))

    good_obj = bytes.fromhex(rrs1_doc(rrs1, 5)["object_hex"])
    verify_ctx = dict(signer_pubkey_hex=sak_pub.hex(), expected_site_id=site_id,
                      expected_network=network)

    def rrs1_signed(payload: bytes, aad_network: int = network) -> bytes:
        return sign1(payload, sign(sak, sig_structure(payload, rrs1_aad(aad_network))))

    unsorted = dict(rrs1, entries=[rrs1["entries"][1], rrs1["entries"][0]])
    bad("rrs1_entries_unsorted", "rrs1", rrs1_signed(rrs1_payload(unsorted)),
        "entries strictly ascending by node_id", **verify_ctx)
    dup = dict(rrs1, entries=[rrs1["entries"][0], rrs1["entries"][0]])
    bad("rrs1_entries_duplicated", "rrs1", rrs1_signed(rrs1_payload(dup)),
        "duplicate node_id entries", **verify_ctx)
    over = dict(rrs1, entries=[(0x00A1000000010000 + i, 1, 1) for i in range(33)])
    bad("rrs1_count_33", "rrs1", rrs1_signed(rrs1_payload(over)), "more than 32 entries",
        **verify_ctx)
    bad("rrs1_count_mismatch", "rrs1", rrs1_signed(rrs1_payload(rrs1, count_override=2)),
        "count disagrees with the payload length", **verify_ctx)
    bad("rrs1_flags_set", "rrs1", rrs1_signed(rrs1_payload(rrs1, flags=1)),
        "flags are reserved zero", **verify_ctx)
    bad("rrs1_version_2", "rrs1", rrs1_signed(rrs1_payload(rrs1, version=2)),
        "unknown payload version", **verify_ctx)
    bad("rrs1_floor_above_network_epoch", "rrs1",
        rrs1_signed(rrs1_payload(dict(rrs1, site_epoch_floor=site_epoch + 1))),
        "site_epoch_floor may not exceed network>>32", **verify_ctx)
    bad("rrs1_epoch_zero", "rrs1", rrs1_signed(rrs1_payload(dict(rrs1, rs_epoch=0))),
        "rs_epoch starts at 1", **verify_ctx)
    bad("rrs1_bad_reason", "rrs1",
        rrs1_signed(rrs1_payload(dict(rrs1, entries=[(0x00A1000000000100, 2, 5)]))),
        "reason is 1..4", **verify_ctx)
    bad("rrs1_generation_zero", "rrs1",
        rrs1_signed(rrs1_payload(dict(rrs1, entries=[(0x00A1000000000100, 0, 1)]))),
        "min_generation must be >= 1", **verify_ctx)
    bad("rrs1_trailing_byte", "rrs1", good_obj + b"\x00", "nothing may follow the Sign1",
        **verify_ctx)
    flipped = bytearray(good_obj)
    flipped[-2] ^= 0x10
    bad("rrs1_bad_signature", "rrs1", bytes(flipped), "signature does not verify",
        expect="deny", **verify_ctx)
    bad("rrs1_aad_other_network", "rrs1",
        rrs1_signed(rrs1_payload(rrs1), aad_network=network + 1),
        "signed under another network's external AAD", expect="deny", **verify_ctx)
    bad("rrs1_other_site", "rrs1", good_obj, "authentic set of another site",
        expect="deny", signer_pubkey_hex=sak_pub.hex(), expected_site_id=site_id + 1,
        expected_network=network)
    bad("rrs1_wrong_sak", "rrs1", good_obj, "checked against a different SAK",
        expect="deny", signer_pubkey_hex=peer_pub.hex(), expected_site_id=site_id,
        expected_network=network)
    good_record = bytes.fromhex(rrs1_doc(rrs1, 5)["record_hex"])
    bad("rrs1_record_bad_crc", "rrs1_record", good_record[:-1] + bytes([good_record[-1] ^ 1]),
        "storage record CRC mismatch")
    bad("rrs1_record_pending", "rrs1_record", sealed(b"RRS1", good_obj, 0, seq=5),
        "pending storage record")
    bad("rrs1_record_garbage_object", "rrs1_record",
        sealed(b"RRS1", b"\x00" * 40, SEAL["RRS1"], seq=5),
        "stored object must parse as an RRS1 Sign1")

    # ---- PoP ---------------------------------------------------------------
    # 07 §6 steps 2-3: the device answers the office challenge with a
    # restricted ES256 COSE_Sign1 over version | key_location | 0x0000 |
    # node_id | challenge | pubkey (108 B), external AAD POP_DOMAIN (28 B),
    # signed by the key being certified. The challenges below are fixed
    # test values; the office uses a fresh CSPRNG challenge per device.
    assert len(POP_DOMAIN) == 28

    def pop_payload(node_id: int, location: int, challenge: bytes, pub: bytes,
                    version: int = 1) -> bytes:
        return u8(version) + u8(location) + b"\x00\x00" + u64(node_id) + challenge + pub

    def pop_doc(node_id: int, location: int, challenge: bytes, secret: int) -> dict:
        pub = pubkey(secret)
        payload = pop_payload(node_id, location, challenge, pub)
        structure = sig_structure(payload, POP_DOMAIN)
        signature = sign(secret, structure)
        return dict(node_id=node_id, key_location=location,
                    challenge_hex=challenge.hex(), pubkey_hex=pub.hex(),
                    payload_hex=payload.hex(), aad_hex=POP_DOMAIN.hex(),
                    sig_structure_hex=structure.hex(),
                    signature_hex=signature.hex(),
                    object_hex=sign1(payload, signature).hex(),
                    signer_secret_hex=secret.to_bytes(32, "big").hex())

    pop_challenge = bytes(range(32))
    pop = pop_doc(node, 1, pop_challenge, device)
    assert len(bytes.fromhex(pop["object_hex"])) == 183
    emit("valid", "pop_device_nvs", dict(pop, codec="pop", expect="ok"))
    emit("valid", "pop_device_se",
         dict(pop_doc(peer_node, 3, bytes([0xC3]) * 32, peer), codec="pop", expect="ok"))

    pop_good = bytes.fromhex(pop["object_hex"])
    pop_ctx = dict(expected_node_id=node, expected_challenge_hex=pop_challenge.hex())

    def pop_signed(payload: bytes) -> bytes:
        return sign1(payload, sign(device, sig_structure(payload, POP_DOMAIN)))

    bad("pop_version_2", "pop",
        pop_signed(pop_payload(node, 1, pop_challenge, device_pub, version=2)),
        "PoP payload version must be 1", **pop_ctx)
    bad("pop_location_none", "pop",
        pop_signed(pop_payload(node, 0, pop_challenge, device_pub)),
        "key location 0 proves nothing", **pop_ctx)
    bad("pop_location_unknown", "pop",
        pop_signed(pop_payload(node, 9, pop_challenge, device_pub)),
        "key location must be 1..3", **pop_ctx)
    pop_reserved = bytearray(pop_payload(node, 1, pop_challenge, device_pub))
    pop_reserved[2] = 1
    bad("pop_reserved_nonzero", "pop", pop_signed(bytes(pop_reserved)),
        "reserved bytes must be zero", **pop_ctx)
    bad("pop_truncated", "pop", pop_good[:-1], "truncated object", **pop_ctx)
    bad("pop_trailing_byte", "pop", pop_good + b"\x00",
        "nothing may follow the Sign1", **pop_ctx)
    bad("pop_key_off_curve", "pop",
        pop_signed(pop_payload(node, 1, pop_challenge, bytes(off))),
        "the carried key must be a P-256 point", **pop_ctx)
    pop_flipped = bytearray(pop_good)
    pop_flipped[-1] ^= 0x01
    bad("pop_bad_signature", "pop", bytes(pop_flipped),
        "well-formed but the signature does not verify", expect="deny", **pop_ctx)
    pop_rs = pop_good[-64:]
    pop_high = pop_rs[:32] + (N - int.from_bytes(pop_rs[32:], "big")).to_bytes(32, "big")
    bad("pop_high_s", "pop", pop_good[:-64] + pop_high,
        "the high-S twin of a valid signature is rejected (low-S only)",
        expect="deny", **pop_ctx)
    bad("pop_wrong_node", "pop", pop_good,
        "a valid PoP presented for another node", expect="deny",
        expected_node_id=node + 1, expected_challenge_hex=pop_challenge.hex())
    bad("pop_wrong_challenge", "pop", pop_good,
        "a PoP replayed against another challenge", expect="deny",
        expected_node_id=node, expected_challenge_hex=("34" * 32))

    # ---- RLX1 removal journal ---------------------------------------------
    notice_payload = (u8(1) + u8(1) + u16(0) + u64(site_id) + u64(node) +
                      u32(3) + u32(14))
    notice_aad = b"RouteLoom/removal-notice/v1\x00" + u64(network)
    signed_notice = sign1(notice_payload, sign(sak, sig_structure(notice_payload, notice_aad)))
    assert len(signed_notice) == 103
    cert_bytes = bytes.fromhex(sitecert["cert_hex"])
    proof = u16(len(cert_bytes)) + u16(len(signed_notice)) + cert_bytes + signed_notice
    removal = dict(self_node=node, site_id=site_id, old_network=network,
                   generation=3, rs_floor=14, gk_floor=203, boot_witness=512)
    for mode, name, payload in ((1, "rlx1_removing", proof),
                                (2, "rlx1_holdoff", proof),
                                (3, "rlx1_unassigned_ready", b"")):
        fields = dict(removal, mode=mode, payload_hex=payload.hex(), commit_seq=7,
                      signer_pubkey_hex=sak_pub.hex())
        emit("valid", name, dict(fields, codec="rlx1_record", expect="ok",
                                 record_hex=rlx1(fields, payload).hex()))
    good_rlx = rlx1(dict(removal, mode=1), proof)
    bad("rlx1_bad_crc", "rlx1_record", good_rlx[:-1] + bytes([good_rlx[-1] ^ 1]),
        "CRC mismatch")
    bad("rlx1_pending", "rlx1_record", rlx1(dict(removal, mode=1), proof, seal=0),
        "pending seal is not durable")
    bad("rlx1_zero_seq", "rlx1_record", rlx1(dict(removal, mode=1), proof, seq=0),
        "sequence zero is invalid")
    bad("rlx1_reserved_mode", "rlx1_record", rlx1(dict(removal, mode=4), proof),
        "Prepared is reserved until cutover")
    bad("rlx1_wrong_notice_generation", "rlx1_record",
        rlx1(dict(removal, mode=1, generation=4), proof),
        "journal generation must match signed Notice")
    bad("rlx1_floor_below_notice", "rlx1_record",
        rlx1(dict(removal, mode=1, rs_floor=13), proof),
        "journal floor cannot be below signed Notice")
    bad("rlx1_ready_with_proof", "rlx1_record", rlx1(dict(removal, mode=3), proof),
        "UnassignedReady contains no proof")

    # ---- RLP1 --------------------------------------------------------------
    peer_cert_id = hashlib.sha256(bytes.fromhex(peercert["cert_hex"])).digest()[:8]
    rlp = dict(purpose=1, state=1, flags=1, peer=peer_node, network=network,
               peer_cert_id_hex=peer_cert_id.hex(), peer_generation=1,
               created_gk_epoch=203, last_used_boot=512,
               rms_hex=bytes(range(0xA0, 0xC0)).hex(), peer_cert_hex=peercert["cert_hex"])
    emit("valid", "rlp1_link_pinned", dict(rlp, codec="rlp1", expect="ok",
                                           record_hex=rlp1(rlp).hex()))
    rlp_end = dict(rlp, purpose=2, flags=0, last_used_boot=0)
    emit("valid", "rlp1_end", dict(rlp_end, codec="rlp1", expect="ok",
                                   record_hex=rlp1(rlp_end).hex()))
    empty = dict(purpose=0, state=0, flags=0, peer=0, network=0, peer_cert_id_hex="00" * 8,
                 peer_generation=0, created_gk_epoch=0, last_used_boot=0, rms_hex="00" * 32)
    emit("valid", "rlp1_empty", dict(empty, codec="rlp1", expect="ok",
                                     record_hex=rlp1(empty).hex()))
    good_slot = rlp1(rlp)
    bad("rlp1_bad_crc", "rlp1", good_slot[:-1] + bytes([good_slot[-1] ^ 1]), "CRC mismatch")
    bad("rlp1_bad_magic", "rlp1", recrc(b"RLP2" + good_slot[4:]), "magic must be RLP1")
    bad("rlp1_format_2", "rlp1", recrc(good_slot[:4] + b"\x02" + good_slot[5:]),
        "format must be 1")
    bad("rlp1_bad_purpose", "rlp1", rlp1(dict(rlp, purpose=3)), "purpose is 1 or 2")
    bad("rlp1_unknown_flag", "rlp1", rlp1(dict(rlp, flags=2)), "only the pinned flag is defined")
    bad("rlp1_state_2", "rlp1", rlp1(dict(rlp, state=2)), "state is 0 or 1")
    bad("rlp1_empty_residue", "rlp1", rlp1(dict(empty, rms_hex="01" + "00" * 31)),
        "an empty slot carries no secret")
    bad("rlp1_empty_with_purpose", "rlp1", rlp1(dict(empty, purpose=1)),
        "an empty slot has purpose 0")
    bad("rlp1_reserved_nonzero", "rlp1",
        recrc(good_slot[:44] + b"\x00\x00\x00\x01" + good_slot[48:]),
        "reserved word must be zero")
    bad("rlp1_zero_rms", "rlp1", rlp1(dict(rlp, rms_hex="00" * 32)),
        "a valid slot has a nonzero RMS")
    bad("rlp1_truncated", "rlp1", good_slot[:83], "slots are exactly 84 bytes")

    # ---- RLP2 --------------------------------------------------------------
    local_cert_id = hashlib.sha256(bytes.fromhex(membercert["cert_hex"])).digest()[:8]
    rlp2_link = dict(purpose=1, state=1, flags=1, peer=peer_node, network=network,
                     peer_cert_id_hex=peer_cert_id.hex(), local_cert_id_hex=local_cert_id.hex(),
                     peer_generation=1, peer_role=0b010, created_gk_epoch=203,
                     last_used_boot=512, reserved_uses=9,
                     rms_hex=bytes(range(0xC0, 0xE0)).hex(),
                     peer_cert_hex=peercert["cert_hex"])
    emit("valid", "rlp2_link_pinned", dict(rlp2_link, codec="rlp2", expect="ok",
                                           record_hex=rlp2(rlp2_link).hex()))
    rlp2_end = dict(rlp2_link, purpose=2, flags=0, reserved_uses=64)
    emit("valid", "rlp2_end_capped", dict(rlp2_end, codec="rlp2", expect="ok",
                                          record_hex=rlp2(rlp2_end).hex()))
    empty2 = dict(purpose=0, state=0, flags=0, peer=0, network=0,
                  peer_cert_id_hex="00" * 8, local_cert_id_hex="00" * 8,
                  peer_generation=0, peer_role=0, created_gk_epoch=0, last_used_boot=0,
                  reserved_uses=0, rms_hex="00" * 32)
    emit("valid", "rlp2_empty", dict(empty2, codec="rlp2", expect="ok",
                                     record_hex=rlp2(empty2).hex()))
    good2 = rlp2(rlp2_link)
    bad("rlp2_bad_crc", "rlp2", good2[:-1] + bytes([good2[-1] ^ 1]), "CRC mismatch")
    bad("rlp2_bad_magic", "rlp2", recrc(b"RLP1" + good2[4:]), "magic must be RLP2")
    bad("rlp2_bad_purpose", "rlp2", rlp2(dict(rlp2_link, purpose=3)), "purpose is 1 or 2")
    bad("rlp2_role_zero", "rlp2", rlp2(dict(rlp2_link, peer_role=0)),
        "a valid slot names the peer role")
    bad("rlp2_uses_over_cap", "rlp2", rlp2(dict(rlp2_link, reserved_uses=65)),
        "reserved_uses never exceeds 64")
    bad("rlp2_empty_residue", "rlp2", rlp2(dict(empty2, reserved_uses=8)),
        "an empty slot carries no use count")
    bad("rlp2_truncated", "rlp2", good2[:95], "slots are exactly 96 bytes")

    # ---- RLV1 --------------------------------------------------------------
    RLV1_SEAL = 0x72564B31
    removal = dict(local_node=node, site_id=site_id, network=network,
                   removed_generation=3, rs_epoch_floor=11, site_epoch_floor=site_epoch,
                   state=1, cause=1,
                   evidence_digest_hex=hashlib.sha256(b"removal-evidence").digest().hex(),
                   rls_commit_seq=41, boot_witness=9000, holdoff_ms=600000)
    emit("valid", "rlv1_blocked", dict(removal, codec="rlv1", expect="ok", commit_seq=7,
                                       record_hex=rlv1(removal, RLV1_SEAL, 7).hex()))
    cleaned = dict(removal, state=2, cause=2)
    emit("valid", "rlv1_cleaned", dict(cleaned, codec="rlv1", expect="ok", commit_seq=8,
                                       record_hex=rlv1(cleaned, RLV1_SEAL, 8).hex()))
    good_rlv = rlv1(removal, RLV1_SEAL, 7)
    bad("rlv1_bad_crc", "rlv1", good_rlv[:-1] + bytes([good_rlv[-1] ^ 1]), "CRC mismatch")
    bad("rlv1_pending_seal", "rlv1", rlv1(removal, 0, 7), "a readable record is committed")
    bad("rlv1_bad_state", "rlv1", rlv1(dict(removal, state=0), RLV1_SEAL, 7),
        "state is Blocked(1) or Cleaned(2)")
    bad("rlv1_bad_cause", "rlv1", rlv1(dict(removal, cause=0), RLV1_SEAL, 7),
        "cause is 1..3")
    bad("rlv1_zero_generation", "rlv1", rlv1(dict(removal, removed_generation=0), RLV1_SEAL, 7),
        "a removal names a nonzero generation")
    bad("rlv1_zero_evidence", "rlv1",
        rlv1(dict(removal, evidence_digest_hex="00" * 32), RLV1_SEAL, 7),
        "evidence is the digest of a verified object")
    bad("rlv1_holdoff_changed", "rlv1", rlv1(dict(removal, holdoff_ms=599999), RLV1_SEAL, 7),
        "holdoff is the fixed 600000 ms")
    bad("rlv1_reserved_nonzero", "rlv1",
        recrc(good_rlv[:58] + b"\x00\x01" + good_rlv[60:]), "reserved bytes must be zero")
    bad("rlv1_truncated", "rlv1", good_rlv[:107], "records are exactly 108 bytes")


if __name__ == "__main__":
    main()
