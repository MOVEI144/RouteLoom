#!/usr/bin/env python3
"""RouteLoom HIL rig description and port discovery.

A *rig* is a named bench: a set of boards, each mapped to a serial-port
glob, chip, firmware app, baud, and console type. Rigs live in
``tools/hil/rigs.yaml`` — see ``docs/hil.md``.

Discovery is deliberately non-fatal: a bench whose ports are absent is
reported OFFLINE (with per-board reasons) so scenario runners can emit
SKIP-OFFLINE instead of crashing. This module never opens a port for
logging; ``--probe`` optionally asks esptool to identify the chip on a
resolved port, which is the only operation that touches hardware.

No third-party dependencies. The rigs file is a strict YAML subset
(nested maps, lists of scalars/maps, plain/quoted scalars, comments) —
no anchors, no flow collections, no block scalars. ``parse_yaml_subset``
implements just that subset; JSON input is also accepted because JSON is
a subset of the same grammar in spirit.

NOTE: none of the discovery paths here have been exercised against real
hardware yet (issue #18 bootstrap — hardware verification pending).
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import json
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

# --------------------------------------------------------------------------
# Minimal YAML-subset loader
# --------------------------------------------------------------------------


class YamlSubsetError(ValueError):
    """Raised when the rigs file uses YAML features we do not support."""


def _strip_comment(line: str) -> str:
    """Remove a ``#`` comment that is not inside quotes."""
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if in_single:
            if ch == "'":
                in_single = False
        elif in_double:
            if ch == "\\":
                continue
            if ch == '"':
                in_double = False
        elif ch == "'":
            in_single = True
        elif ch == '"':
            in_double = True
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


def _parse_scalar(text: str) -> Any:
    text = text.strip()
    if text == "":
        return ""
    if text[0] == '"':
        if len(text) < 2 or text[-1] != '"':
            raise YamlSubsetError(f"unterminated double-quoted scalar: {text!r}")
        body = text[1:-1]
        # Minimal escape handling for the escapes we emit/consume.
        return re.sub(
            r"\\(.)",
            lambda m: {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(
                m.group(1), m.group(1)
            ),
            body,
        )
    if text[0] == "'":
        if len(text) < 2 or text[-1] != "'":
            raise YamlSubsetError(f"unterminated single-quoted scalar: {text!r}")
        return text[1:-1].replace("''", "'")
    lowered = text.lower()
    if lowered in ("null", "~"):
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        return int(text, 0) if re.match(r"^-?0x", text) else int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    if text[0] in "[{|":
        raise YamlSubsetError(
            f"flow collections and block scalars are not supported: {text!r}"
        )
    return text


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Return (indent, content) pairs with comments/blank lines removed."""
    out = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise YamlSubsetError(f"line {lineno}: tab indentation is not allowed")
        stripped = _strip_comment(raw).rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        out.append((indent, stripped.lstrip(" ")))
    return out


def _parse_block(lines: list[tuple[int, str]], pos: int, indent: int):
    """Parse one block (map or list) at the given indent. Returns (obj, pos)."""
    if pos >= len(lines):
        return None, pos
    is_list = lines[pos][1].startswith("- ") or lines[pos][1] == "-"
    result: Any = [] if is_list else {}
    while pos < len(lines):
        ind, content = lines[pos]
        if ind < indent:
            break
        if ind > indent:
            raise YamlSubsetError(f"unexpected indentation at {content!r}")
        if is_list:
            if not (content == "-" or content.startswith("- ")):
                break
            item_text = content[1:].lstrip(" ")
            pos += 1
            if item_text == "":
                # Nested block on following lines.
                if pos < len(lines) and lines[pos][0] > indent:
                    item, pos = _parse_block(lines, pos, lines[pos][0])
                    result.append(item)
                else:
                    result.append(None)
            elif ":" in item_text and not item_text.startswith(("'", '"')):
                # Inline map start: "- key: value" possibly followed by more
                # keys at a deeper indent aligned under the key.
                key, _, value = item_text.partition(":")
                item = {key.strip(): _parse_scalar(value)}
                if pos < len(lines) and lines[pos][0] > indent:
                    sub_ind = lines[pos][0]
                    more, pos = _parse_block(lines, pos, sub_ind)
                    if isinstance(more, dict):
                        item.update(more)
                    else:
                        raise YamlSubsetError(
                            f"list item map expected mapping continuation, got {more!r}"
                        )
                result.append(item)
            else:
                result.append(_parse_scalar(item_text))
        else:
            if content.startswith("- ") or content == "-":
                break
            key, sep, value = content.partition(":")
            if not sep:
                raise YamlSubsetError(f"expected 'key: value', got {content!r}")
            key = key.strip()
            value = value.strip()
            pos += 1
            if value == "":
                if pos < len(lines) and lines[pos][0] > indent:
                    child, pos = _parse_block(lines, pos, lines[pos][0])
                    result[key] = child
                else:
                    result[key] = None
            else:
                result[key] = _parse_scalar(value)
    return result, pos


def parse_yaml_subset(text: str) -> Any:
    """Parse the restricted YAML dialect used by rigs.yaml.

    JSON is accepted as well (a JSON document parses via json.loads first).
    """
    stripped = text.strip()
    if stripped.startswith("{"):
        return json.loads(stripped)
    lines = _logical_lines(text)
    if not lines:
        return {}
    obj, pos = _parse_block(lines, 0, lines[0][0])
    if pos != len(lines):
        raise YamlSubsetError(f"trailing unparsed content at line {pos + 1}")
    return obj


# --------------------------------------------------------------------------
# Rig model
# --------------------------------------------------------------------------

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

CONSOLE_TYPES = ("usb-serial-jtag", "uart0", "none")
RESET_TYPES = ("esptool", "dtr-rts", "command", "none")


@dataclass
class Board:
    """One board on the bench."""

    name: str
    role: str = "reference"          # "bridge" | "reference" | free-form
    app: str = ""                  # firmware/<app>
    chip: str = ""                 # esp32c3 / esp32s3 / esp32c5
    baud: int = 115200
    flash_baud: int = 460800
    console: str = "usb-serial-jtag"
    port_globs: list[str] = field(default_factory=list)
    serial_hint: Optional[str] = None  # substring to disambiguate matches
    node_id: Optional[int] = None
    reset: str = "esptool"         # how reset_boards drives a reboot
    reset_command: Optional[str] = None  # for reset == "command"; {port} expands
    dtr: bool = True               # assert DTR on the console port
    rts: bool = False              # assert RTS on the console port

    def build_dir(self, repo: str = REPO_ROOT) -> str:
        return os.path.join(repo, "firmware", self.app, "build")


@dataclass
class HostSide:
    """Host daemon endpoints used by scenario steps."""

    daemon_bin: str = os.path.join("host", "target", "debug", "routeloom-host")
    ctl_bin: str = os.path.join("host", "target", "debug", "routeloomctl")
    socket: str = "/tmp/routeloom-hil.sock"
    poll_interval_s: float = 0.5
    command_timeout_s: float = 10.0
    # "auto" = scenarios.py writes a per-run ACL granting the runner's uid
    # READ_PAYLOAD/SEND/READ_OPERATION on "*". A path = use that file
    # (repo-relative or absolute). "none"/"" = start the daemon without
    # --api-acl-file (default-deny: SEND will be refused — honest).
    acl_file: str = "auto"


@dataclass
class Rig:
    name: str
    boards: dict[str, Board]
    host: HostSide
    description: str = ""


class RigConfigError(ValueError):
    pass


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise RigConfigError(msg)


def load_rigs(path: str) -> dict[str, Rig]:
    with open(path, "r", encoding="utf-8") as fh:
        doc = parse_yaml_subset(fh.read())
    _require(isinstance(doc, dict), f"{path}: top level must be a mapping")
    rigs_doc = doc.get("rigs")
    _require(isinstance(rigs_doc, dict), f"{path}: missing 'rigs' mapping")
    rigs: dict[str, Rig] = {}
    for rig_name, body in rigs_doc.items():
        _require(isinstance(body, dict), f"rigs.{rig_name}: must be a mapping")
        host_doc = body.get("host") or {}
        host = HostSide()
        for key, value in host_doc.items():
            _require(
                hasattr(host, key), f"rigs.{rig_name}.host: unknown key {key!r}"
            )
            setattr(host, key, value)
        boards_doc = body.get("boards")
        _require(
            isinstance(boards_doc, dict) and boards_doc,
            f"rigs.{rig_name}: 'boards' must be a non-empty mapping",
        )
        boards: dict[str, Board] = {}
        for board_name, bdoc in boards_doc.items():
            _require(
                isinstance(bdoc, dict),
                f"rigs.{rig_name}.boards.{board_name}: must be a mapping",
            )
            known = {f for f in Board.__dataclass_fields__ if f != "name"}
            board = Board(name=board_name)
            for key, value in bdoc.items():
                _require(
                    key in known,
                    f"rigs.{rig_name}.boards.{board_name}: unknown key {key!r}",
                )
                setattr(board, key, value)
            globs = bdoc.get("port_globs")
            if globs is None and bdoc.get("port_glob"):
                globs = [bdoc["port_glob"]]
            if globs is not None:
                _require(
                    isinstance(globs, list) and all(isinstance(g, str) for g in globs),
                    f"boards.{board_name}.port_globs must be a list of strings",
                )
                board.port_globs = list(globs)
            _require(board.app, f"boards.{board_name}: 'app' is required")
            _require(
                board.console in CONSOLE_TYPES,
                f"boards.{board_name}.console must be one of {CONSOLE_TYPES}",
            )
            _require(
                board.reset in RESET_TYPES,
                f"boards.{board_name}.reset must be one of {RESET_TYPES}",
            )
            if board.reset == "command":
                _require(
                    bool(board.reset_command),
                    f"boards.{board_name}: reset=command requires reset_command",
                )
            boards[board_name] = board
        rigs[rig_name] = Rig(
            name=rig_name,
            boards=boards,
            host=host,
            description=str(body.get("description") or ""),
        )
    return rigs


# --------------------------------------------------------------------------
# Port discovery
# --------------------------------------------------------------------------

#: Default glob set per platform. On macOS only /dev/cu.* devices should be
#: opened for output (/dev/tty.* blocks on carrier). On Linux the stable
#: names live under /dev/serial/by-id.
DEFAULT_PORT_GLOBS = {
    "Darwin": [
        "/dev/cu.usbmodem*",
        "/dev/cu.usbserial*",
        "/dev/cu.wchusbserial*",
        "/dev/cu.SLAB_USBtoUART*",
        "/dev/cu.ESP_*",
    ],
    "Linux": [
        "/dev/serial/by-id/*",
        "/dev/ttyUSB*",
        "/dev/ttyACM*",
    ],
}


def default_port_globs(system: Optional[str] = None) -> list[str]:
    system = system or platform.system()
    return list(DEFAULT_PORT_GLOBS.get(system, ["/dev/ttyUSB*", "/dev/ttyACM*"]))


def list_candidate_ports(system: Optional[str] = None) -> list[str]:
    """All currently-present serial-ish device paths for this platform."""
    seen: list[str] = []
    for pattern in default_port_globs(system):
        for path in sorted(glob.glob(pattern)):
            if path not in seen:
                seen.append(path)
    return seen


def usb_inventory(timeout_s: float = 15.0) -> str:
    """Best-effort USB device inventory for the report's evidence trail.

    macOS uses ``system_profiler SPUSBDataType``; Linux uses ``lsusb`` if
    present. Output is raw text — it is evidence, not a parse contract.
    Never fails: returns a diagnostic string on error.
    """
    system = platform.system()
    try:
        if system == "Darwin":
            out = subprocess.run(
                ["system_profiler", "SPUSBDataType"],
                capture_output=True, text=True, timeout=timeout_s,
            )
            return out.stdout or out.stderr or "(empty system_profiler output)"
        if system == "Linux":
            try:
                out = subprocess.run(
                    ["lsusb"], capture_output=True, text=True, timeout=timeout_s
                )
                return out.stdout or "(empty lsusb output)"
            except FileNotFoundError:
                return "(lsusb not installed)"
        return f"(no USB inventory tool configured for {system})"
    except subprocess.TimeoutExpired:
        return f"(usb inventory timed out after {timeout_s}s)"
    except OSError as exc:  # tool missing etc.
        return f"(usb inventory failed: {exc})"


def resolve_board_port(
    board: Board, candidates: Optional[list[str]] = None
) -> tuple[Optional[str], list[str], str]:
    """Resolve one board's serial port.

    Returns (port_or_None, all_matches, status) where status is one of:
      - ``ONLINE``      — exactly one usable port
      - ``OFFLINE``     — no candidates matched
      - ``AMBIGUOUS``   — several matches and no serial_hint to disambiguate
    """
    patterns = board.port_globs or default_port_globs()
    pool = candidates if candidates is not None else list_candidate_ports()
    matches = [p for p in pool if any(fnmatch.fnmatch(p, g) for g in patterns)]
    if board.serial_hint:
        narrowed = [p for p in matches if board.serial_hint in p]
        if narrowed:
            matches = narrowed
    if not matches:
        return None, [], "OFFLINE"
    if len(matches) > 1:
        return None, matches, "AMBIGUOUS"
    return matches[0], matches, "ONLINE"


def probe_chip(port: str, esptool: str, timeout_s: float = 20.0) -> Optional[str]:
    """Ask esptool to identify the chip on a port (opens the port!).

    Returns the detected chip name (e.g. ``esp32c3``) or None on failure.
    This resets the board into the ROM bootloader — only call it when the
    bench is quiescent (discovery phase), never mid-scenario.
    """
    try:
        out = subprocess.run(
            [esptool, "--port", port, "--connect-attempts", "1", "chip-id"],
            capture_output=True, text=True, timeout=timeout_s,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"(esp32[a-z0-9]+)", out.stdout + out.stderr, re.IGNORECASE)
    return match.group(1).lower() if match else None


@dataclass
class BoardStatus:
    board: Board
    port: Optional[str]
    matches: list[str]
    status: str          # ONLINE | OFFLINE | AMBIGUOUS | MISMATCH
    detail: str = ""


def resolve_rig(
    rig: Rig,
    probe: bool = False,
    esptool: Optional[str] = None,
    candidates: Optional[list[str]] = None,
) -> dict[str, BoardStatus]:
    """Resolve every board on the bench. Never raises for missing hardware."""
    statuses: dict[str, BoardStatus] = {}
    claimed: set[str] = set()
    for name, board in rig.boards.items():
        port, matches, status = resolve_board_port(board, candidates)
        detail = ""
        if port is not None and port in claimed:
            # Two roles resolving to the same device is a bench wiring or
            # glob error — never let two boards share one port silently.
            port, status = None, "AMBIGUOUS"
            matches = matches
            detail = "port already claimed by another board role"
        if port is not None:
            claimed.add(port)
        if status == "ONLINE" and probe and esptool:
            detected = probe_chip(port, esptool)
            if detected is None:
                status, detail = "MISMATCH", "esptool could not identify chip"
            elif board.chip and detected != board.chip:
                status, detail = (
                    "MISMATCH",
                    f"rig expects {board.chip}, probe saw {detected}",
                )
        statuses[name] = BoardStatus(board, port, matches, status, detail)
    return statuses


def rig_online(statuses: dict[str, BoardStatus]) -> list[str]:
    """Human-readable reasons the rig is not fully online; [] when online."""
    reasons = []
    for name, st in statuses.items():
        if st.status == "ONLINE":
            continue
        if st.status == "OFFLINE":
            globs = st.board.port_globs or default_port_globs()
            reasons.append(f"board {name!r}: no port matched {globs}")
        elif st.status == "AMBIGUOUS":
            reasons.append(
                f"board {name!r}: ambiguous ports {st.matches} {st.detail}".strip()
            )
        else:
            reasons.append(f"board {name!r}: {st.status} {st.detail}".strip())
    return reasons


# --------------------------------------------------------------------------
# CLI + self test
# --------------------------------------------------------------------------

def _selftest() -> int:
    """Unit tests for the subset parser and resolution logic (no hardware)."""
    doc = parse_yaml_subset(
        """
        # comment
        rigs:
          bench-a:                      # inline comment
            description: "two node #withhash"
            host:
              socket: /tmp/x.sock
              poll_interval_s: 0.5
            boards:
              bridge:
                app: bridge_node
                chip: esp32c3
                node_id: 0x1
                console: none
                port_globs:
                  - /dev/cu.usbmodem*
                  - /dev/ttyACM*
              ref-a:
                app: reference_node
                chip: esp32c3
                node_id: 2
                dtr: true
                reset: dtr-rts
        """
    )
    assert doc["rigs"]["bench-a"]["description"] == "two node #withhash"
    assert doc["rigs"]["bench-a"]["host"]["poll_interval_s"] == 0.5
    boards = doc["rigs"]["bench-a"]["boards"]
    assert boards["bridge"]["node_id"] == 0x1
    assert boards["ref-a"]["node_id"] == 2
    assert boards["ref-a"]["dtr"] is True

    # Round-trip through load_rigs using a temp file.
    import tempfile

    with tempfile.NamedTemporaryFile(
        "w", suffix=".yaml", delete=False
    ) as fh:
        fh.write(
            "rigs:\n  bench-x:\n    boards:\n      b1:\n        app: reference_node\n"
            "        chip: esp32c3\n        port_globs:\n          - /dev/fake*A\n"
        )
        path = fh.name
    try:
        rigs = load_rigs(path)
    finally:
        os.unlink(path)
    rig = rigs["bench-x"]
    pool = ["/dev/fake1A", "/dev/fake2B", "/dev/ttyUSB0"]
    port, matches, status = resolve_board_port(rig.boards["b1"], pool)
    assert status == "ONLINE" and port == "/dev/fake1A", (port, matches, status)

    rig.boards["b1"].port_globs = ["/dev/nothing*"]
    port, matches, status = resolve_board_port(rig.boards["b1"], pool)
    assert status == "OFFLINE" and port is None

    rig.boards["b1"].port_globs = ["/dev/fake*"]
    port, matches, status = resolve_board_port(rig.boards["b1"], pool)
    assert status == "AMBIGUOUS" and len(matches) == 2
    rig.boards["b1"].serial_hint = "2B"
    port, matches, status = resolve_board_port(rig.boards["b1"], pool)
    assert status == "ONLINE" and port == "/dev/fake2B"

    # Two roles claiming the same port -> AMBIGUOUS for the second.
    rig.boards["b2"] = Board(name="b2", app="reference_node",
                             port_globs=["/dev/fake*"])
    rig.boards["b1"].serial_hint = None
    rig.boards["b1"].port_globs = ["/dev/fake1A"]
    rig.boards["b2"].port_globs = ["/dev/fake1A"]
    statuses = resolve_rig(rig, candidates=pool)
    assert statuses["b1"].status == "ONLINE"
    assert statuses["b2"].status == "AMBIGUOUS"
    reasons = rig_online(statuses)
    assert reasons and "b2" in reasons[0]

    # Bad config is rejected with a clear error.
    try:
        parse_yaml_subset("a: [1, 2]")
    except YamlSubsetError:
        pass
    else:
        raise AssertionError("flow collection should be rejected")

    print("rig.py selftest OK")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Describe a RouteLoom HIL rig and resolve its serial ports."
    )
    parser.add_argument("--rig", help="path to rigs.yaml")
    parser.add_argument("--bench", help="bench name inside the rigs file")
    parser.add_argument(
        "--probe",
        action="store_true",
        help="probe resolved ports with esptool chip-id (resets the board)",
    )
    parser.add_argument("--esptool", default=os.path.expanduser(
        "~/.local/bin/esptool.py"), help="esptool path")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--inventory",
        action="store_true",
        help="include a USB device inventory in the output",
    )
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    if args.selftest:
        return _selftest()
    if not args.rig:
        parser.error("--rig is required (or use --selftest)")

    rigs = load_rigs(args.rig)
    if args.bench:
        if args.bench not in rigs:
            print(f"error: bench {args.bench!r} not in {args.rig} "
                  f"(have: {', '.join(sorted(rigs))})", file=sys.stderr)
            return 2
        rigs = {args.bench: rigs[args.bench]}

    report = {"benches": {}}
    for name, rig in rigs.items():
        statuses = resolve_rig(rig, probe=args.probe, esptool=args.esptool)
        offline = rig_online(statuses)
        bench = {
            "description": rig.description,
            "status": "OFFLINE" if offline else "ONLINE",
            "offline_reasons": offline,
            "boards": {
                bname: {
                    "app": st.board.app,
                    "chip": st.board.chip,
                    "role": st.board.role,
                    "node_id": st.board.node_id,
                    "console": st.board.console,
                    "port": st.port,
                    "matches": st.matches,
                    "status": st.status,
                    "detail": st.detail,
                }
                for bname, st in statuses.items()
            },
        }
        report["benches"][name] = bench
        if args.inventory:
            bench["usb_inventory"] = usb_inventory()

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for name, bench in report["benches"].items():
            print(f"bench {name}: {bench['status']}")
            for reason in bench["offline_reasons"]:
                print(f"  offline: {reason}")
            for bname, board in bench["boards"].items():
                print(
                    f"  {bname}: {board['status']}"
                    f" port={board['port'] or '-'} app={board['app']}"
                    f" chip={board['chip']} console={board['console']}"
                )
    # Discovery is a report, not a gate: exit 0 even when benches are OFFLINE.
    return 0


if __name__ == "__main__":
    sys.exit(main())
