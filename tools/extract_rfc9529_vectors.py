#!/usr/bin/env python3
"""Extract the RFC 9529 §3 EDHOC trace into protocol/edhoc-rfc9529/.

RFC 9529 ("Traces of Ephemeral Diffie-Hellman Over COSE (EDHOC)") §3 is the
method 3 / cipher suite 2 trace (P-256, SHA-256, AES-CCM-16-64-128, kid-
referenced CCS credentials) — the only RFC trace that runs on RouteLoom's
suite-2 backend (§2 is suite 0: X25519/EdDSA). §4 lists invalid messages
that a compliant implementation must or may reject; all of them are copied
too (`invalid_4_x_y`). The C++ test tests/cpp/test_edhoc.cpp replays §3 byte
for byte through the vendored libedhoc and routeloom::edhoc and feeds it
every §4 message.

The RFC text is not vendored. Fetch it and run:

    curl -sSO https://www.rfc-editor.org/rfc/rfc9529.txt
    python3 tools/extract_rfc9529_vectors.py rfc9529.txt

The script refuses any input whose SHA-256 differs from RFC_SHA256 (the
published text), so the committed file can only come from the RFC. Each
value keeps its RFC section and label as a comment. Values are only copied,
never computed here.
"""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "protocol" / "edhoc-rfc9529" / "chapter3.txt"
RFC_SHA256 = "e220e864adba55278e976e2e1824037a5c51adbe3b359b3519730af7166a7489"

# (section, label as printed, occurrence within the section) -> vector name.
# A label printed without a name ("(Raw Value) (32 bytes)" under a prose
# line) is matched by that prose line.
WANTED = [
    ("3.1", "message_1", 0, "message_1_first"),
    ("3.2", "error", 0, "error"),
    ("3.3", "X", 0, "X"),
    ("3.3", "G_X", 0, "G_X"),
    ("3.3", "C_I", 0, "C_I"),
    ("3.3", "message_1", 0, "message_1"),
    ("3.4", "Y", 0, "Y"),
    ("3.4", "G_Y", 0, "G_Y"),
    ("3.4", "C_R", 0, "C_R"),
    ("3.4", "H(message_1)", 0, "H_message_1"),
    ("3.4", "TH_2", 0, "TH_2"),
    ("3.4", "G_XY (Raw Value)", 0, "G_XY"),
    ("3.4", "PRK_2e", 0, "PRK_2e"),
    ("3.4", "SK_R", 0, "SK_R"),
    ("3.4", "Responder's public authentication key, 'x'-coordinate", 0, "PK_R_x"),
    ("3.4", "Responder's public authentication key, 'y'-coordinate", 0, "PK_R_y"),
    ("3.4", "SALT_3e2m", 0, "SALT_3e2m"),
    ("3.4", "G_RX (Raw Value)", 0, "G_RX"),
    ("3.4", "PRK_3e2m", 0, "PRK_3e2m"),
    ("3.4", "ID_CRED_R", 0, "ID_CRED_R"),
    ("3.4", "CRED_R", 0, "CRED_R"),
    ("3.4", "MAC_2", 0, "MAC_2"),
    ("3.4", "PLAINTEXT_2", 0, "PLAINTEXT_2"),
    ("3.4", "KEYSTREAM_2", 0, "KEYSTREAM_2"),
    ("3.4", "message_2", 0, "message_2"),
    ("3.5", "TH_3", 0, "TH_3"),
    ("3.5", "SK_I", 0, "SK_I"),
    ("3.5", "Initiator's public authentication key, 'x'-coordinate", 0, "PK_I_x"),
    ("3.5", "Initiator's public authentication key, 'y'-coordinate", 0, "PK_I_y"),
    ("3.5", "SALT_4e3m", 0, "SALT_4e3m"),
    ("3.5", "G_IY (Raw Value)", 0, "G_IY"),
    ("3.5", "PRK_4e3m", 0, "PRK_4e3m"),
    ("3.5", "ID_CRED_I", 0, "ID_CRED_I"),
    ("3.5", "CRED_I", 0, "CRED_I"),
    ("3.5", "MAC_3", 0, "MAC_3"),
    ("3.5", "K_3", 0, "K_3"),
    ("3.5", "IV_3", 0, "IV_3"),
    ("3.5", "CIPHERTEXT_3", 0, "CIPHERTEXT_3"),
    ("3.5", "message_3", 0, "message_3"),
    ("3.5", "TH_4", 0, "TH_4"),
    ("3.6", "K_4", 0, "K_4"),
    ("3.6", "IV_4", 0, "IV_4"),
    ("3.6", "message_4", 0, "message_4"),
    ("3.7", "PRK_out", 0, "PRK_out"),
    ("3.7", "PRK_exporter", 0, "PRK_exporter"),
    ("3.8", "Client's OSCORE Sender ID", 0, "OSCORE_client_sender_id"),
    ("3.8", "Server's OSCORE Sender ID", 0, "OSCORE_server_sender_id"),
    ("3.8", "OSCORE Master Secret", 0, "OSCORE_master_secret"),
    ("3.8", "OSCORE Master Salt", 0, "OSCORE_master_salt"),
    ("3.9", "context for KeyUpdate", 0, "key_update_context"),
    ("3.9", "PRK_out after KeyUpdate", 0, "key_update_PRK_out"),
    ("3.9", "PRK_exporter after KeyUpdate", 0, "key_update_PRK_exporter"),
    ("3.9", "OSCORE Master Secret after KeyUpdate", 0, "key_update_OSCORE_master_secret"),
    ("3.9", "OSCORE Master Salt after KeyUpdate", 0, "key_update_OSCORE_master_salt"),
]

INVALID_HEADER = re.compile(r"^   Invalid (\S+) \((\d+) bytes?\)$")
INVALID_HEX = re.compile(r"^   [0-9a-fA-F]{2}( [0-9a-fA-F]{2})*$")
SUBSECTION = re.compile(r"^(4\.\d+\.\d+)\.  ")

HEADER = re.compile(r"^   (.*?) ?\(([^()]+)\) \((\d+) bytes?\)$")
HEX_LINE = re.compile(r"^   [0-9a-f]{2}( [0-9a-f]{2})*$")
SECTION = re.compile(r"^(3\.\d+)\.  ")


def parse(lines: list[str]) -> dict[tuple[str, str, int], tuple[str, str]]:
    start = next(i for i, l in enumerate(lines) if l.startswith("3.  Authentication with Static DH"))
    end = next(i for i, l in enumerate(lines) if l.startswith("4.  Invalid Traces"))
    found: dict[tuple[str, str, int], tuple[str, str]] = {}
    seen: dict[tuple[str, str], int] = {}
    section = "3"
    i = start
    while i < end:
        line = lines[i]
        m = SECTION.match(line)
        if m:
            section = m.group(1)
        m = HEADER.match(line)
        if m:
            label, kind, size = m.group(1), m.group(2), int(m.group(3))
            if not label:  # "(Raw Value) (32 bytes)" under a prose line
                label = lines[i - 1].strip()
            data: list[str] = []
            j = i + 1
            while j < end and HEX_LINE.match(lines[j]):
                data += lines[j].split()
                j += 1
            if len(data) != size:
                raise SystemExit(f"§{section} {label}: {len(data)} bytes, header says {size}")
            if kind in ("Raw Value", "raw value", "CBOR Data Item", "CBOR Sequence",
                        "ECDH shared secret"):
                # Raw values are preferred; CBOR forms only when no raw form exists.
                n = seen.get((section, label, kind), 0)
                seen[(section, label, kind)] = n + 1
                key = (section, label, n)
                if key not in found or kind.lower() == "raw value":
                    found[key] = ("".join(data), f"{kind}, {size} bytes")
            i = j
            continue
        i += 1
    return found


def parse_invalid(lines: list[str]) -> list[tuple[str, str, str]]:
    """§4: (subsection, what is invalid, hex) in document order."""
    start = next(i for i, l in enumerate(lines) if l.startswith("4.  Invalid Traces"))
    end = next(i for i, l in enumerate(lines) if l.startswith("5.  Security Considerations"))
    out: list[tuple[str, str, str]] = []
    subsection = ""
    i = start
    while i < end:
        m = SUBSECTION.match(lines[i])
        if m:
            subsection = m.group(1)
        m = INVALID_HEADER.match(lines[i])
        if m:
            what, size = m.group(1), int(m.group(2))
            data: list[str] = []
            j = i + 1
            while j < end and INVALID_HEX.match(lines[j]):
                data += lines[j].split()
                j += 1
            if len(data) != size:
                raise SystemExit(f"§{subsection}: {len(data)} bytes, header says {size}")
            out.append((subsection, what, "".join(data).lower()))
            i = j
            continue
        i += 1
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    raw = Path(sys.argv[1]).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != RFC_SHA256:
        print(f"input sha256 {digest} is not the RFC 9529 text ({RFC_SHA256})")
        return 1
    lines = raw.decode("utf-8-sig").split("\n")
    found = parse(lines)
    invalid = parse_invalid(lines)
    out = [
        "# RFC 9529 §3 (EDHOC method 3, cipher suite 2) — values copied verbatim",
        "# by tools/extract_rfc9529_vectors.py from",
        "# https://www.rfc-editor.org/rfc/rfc9529.txt (sha256 " + RFC_SHA256 + ").",
        "# Public test keys only. Copyright (c) 2024 IETF Trust and the persons",
        "# identified as the document authors; Revised BSD License, see README.md.",
        "# Format: one `name = hex` per line; `#` comments.",
    ]
    for section, label, occurrence, name in WANTED:
        key = (section, label, occurrence)
        if key not in found:
            print(f"missing §{section} {label!r}")
            return 1
        value, kind = found[key]
        out.append("")
        out.append(f"# §{section} {label} ({kind})")
        out.append(f"{name} = {value}")
    for subsection, what, value in invalid:
        out.append("")
        out.append(f"# §{subsection} invalid {what} ({len(value) // 2} bytes)")
        out.append(f"invalid_{subsection.replace('.', '_')}_{what} = {value}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(WANTED)} values, {len(invalid)} invalid)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
