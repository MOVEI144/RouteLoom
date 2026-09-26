#!/usr/bin/env python3
"""RouteLoom HIL scenario runner (issue #18).

Runs named scenarios — ordered lists of steps — against a rig described in
``rigs.yaml``. Every step that can block takes an explicit timeout; all
evidence lands in ``artifacts/hil/<run>/scenarios/<name>/``.

Step vocabulary (a scenario is a list of dicts, each with ``step``):

  start_daemon                     spawn routeloom-host --device <bridge port>
                                   --socket <rig socket> --api-acl-file <gen>,
                                   then poll `adapter` until the device
                                   session reports authenticated (bounded)
  stop_daemon                      terminate the managed daemon
  reset_boards {boards: [...]}     reboot boards via their rig `reset` method;
                                   if the bridge board is reset while the
                                   daemon owns its port, the daemon is
                                   stopped and restarted around the reset
  mark {name: M}                   remember the current position in every
                                   open capture; `since`/`window` may then
                                   say "mark:M" (e.g. re-BOUND must be a
                                   NEW event, not the pre-restart one)
  wait_for {capture, pattern, timeout, [since]}
                                   first matching line; FAIL + tail dump on
                                   timeout
  send_host_command {args: [...]}  run `routeloomctl --socket <s> <args...>`,
                                   log command+output to host-commands.log
  sleep {seconds}
  assert_log {capture, pattern, [window]}
                                   FAIL unless pattern appears in window
  assert_absent {capture, pattern, [window]}
                                   FAIL if pattern appears in window

``capture`` names: a board name (its serial console log),
``daemon:<verb>`` (a PollCapture running `routeloomctl <verb>` — the ONLY
way bridge state is observed), ``daemon`` (daemon stdout), or
``host-commands`` (routeloomctl request/response log).

``since``/``window``: ``run`` (whole capture, default), ``mark:NAME``
(lines after the named mark), ``last:N`` (last N lines).

Template substitution in args/patterns: ``{node:BOARD}`` → the board's
node_id, ``{socket}`` → daemon socket path.

Verdicts: PASS (all steps ok AND evidence files exist), FAIL (a step
failed), SKIP-OFFLINE (rig/board/daemon unavailable before the scenario
ran — never a verdict about firmware).

The first partial C3 run is recorded in docs/hil/2026-09-26-bench-5node.md.
Full scenario regexes still await a working gateway bench.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from typing import Optional

try:
    from . import rig as rig_mod
    from . import capture as cap_mod
    from . import report as report_mod
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import rig as rig_mod  # type: ignore
    import capture as cap_mod  # type: ignore
    import report as report_mod  # type: ignore

DEFAULT_ESPTOOL = os.path.expanduser("~/.local/bin/esptool")
TAIL_LINES = 40
DAEMON_AUTH_TIMEOUT_S = 45.0
RESET_SETTLE_S = 0.5

# Firmware-side log contracts (see firmware/reference_node/main/main.cpp and
# components/routeloom/src/discovery.cpp):
#   ref console: "discovery event=BOUND peer=<dec>" / "...REACHABLE peer=<dec>"
#                "message origin=<dec> session=..." (received payload)
#                "delivery session=... state=7 reason=END_RECEIVED"
#   daemon socket: EVENTS -> {"kind":"diagnostic","peer":N,"reason":"BOUND"}
#                  DELIVERIES -> {"destination":N,"state":"delivered",
#                                 "reason":"END_RECEIVED"}
#                  ADAPTER -> "session":{"authenticated":true,...}

SCENARIOS: dict[str, dict] = {
    "bind_2node": {
        "description": "reset bridge + reference; both must reach "
                       "BOUND + REACHABLE within 60s",
        "boards": ["bridge", "ref-a"],
        "daemon": True,
        "steps": [
            {"step": "start_daemon"},
            {"step": "reset_boards", "boards": ["ref-a", "bridge"]},
            {"step": "wait_for", "capture": "ref-a", "timeout": 60,
             "pattern": r"discovery event=BOUND peer=1\b"},
            {"step": "wait_for", "capture": "ref-a", "timeout": 60,
             "pattern": r"discovery event=REACHABLE peer=1\b"},
            {"step": "wait_for", "capture": "daemon:events", "timeout": 60,
             "pattern": r'"kind":"diagnostic","peer":2,"reason":"BOUND"'},
            {"step": "wait_for", "capture": "daemon:events", "timeout": 60,
             "pattern": r'"kind":"diagnostic","peer":2,"reason":"REACHABLE"'},
            {"step": "assert_absent", "capture": "ref-a", "window": "run",
             "pattern": r"Guru Meditation|assert failed|Brownout|panic"},
        ],
    },
    "deliver_2node": {
        "description": "bound pair; host `send` must end delivered/"
                       "END_RECEIVED on the daemon and appear in the ref log",
        "boards": ["bridge", "ref-a"],
        "daemon": True,
        "steps": [
            {"step": "start_daemon"},
            {"step": "reset_boards", "boards": ["ref-a", "bridge"]},
            {"step": "wait_for", "capture": "ref-a", "timeout": 60,
             "pattern": r"discovery event=REACHABLE peer=1\b"},
            {"step": "wait_for", "capture": "daemon:events", "timeout": 60,
             "pattern": r'"kind":"diagnostic","peer":2,"reason":"REACHABLE"'},
            {"step": "mark", "name": "pre-send"},
            {"step": "send_host_command",
             "args": ["send", "{node:ref-a}", "524c48494c31"]},  # "RLHIL1"
            {"step": "wait_for", "capture": "host-commands", "timeout": 15,
             "since": "mark:pre-send",
             "pattern": r'"accepted":true'},
            {"step": "wait_for", "capture": "daemon:deliveries", "timeout": 90,
             "since": "mark:pre-send",
             "pattern": r'"destination":{node:ref-a},"state":"delivered",'
                        r'"reason":"END_RECEIVED"'},
            {"step": "wait_for", "capture": "ref-a", "timeout": 90,
             "since": "mark:pre-send",
             "pattern": r"message origin=1 session="},
        ],
    },
    "restart_resume": {
        "description": "deliver once, restart the reference node "
                       "mid-session; it must re-BIND and deliver again",
        "boards": ["bridge", "ref-a"],
        "daemon": True,
        "steps": [
            {"step": "start_daemon"},
            {"step": "reset_boards", "boards": ["ref-a", "bridge"]},
            {"step": "wait_for", "capture": "ref-a", "timeout": 60,
             "pattern": r"discovery event=REACHABLE peer=1\b"},
            {"step": "send_host_command",
             "args": ["send", "{node:ref-a}", "524c48494c32"]},
            {"step": "wait_for", "capture": "daemon:deliveries", "timeout": 90,
             "pattern": r'"destination":{node:ref-a},"state":"delivered",'
                        r'"reason":"END_RECEIVED"'},
            {"step": "mark", "name": "pre-restart"},
            {"step": "reset_boards", "boards": ["ref-a"]},
            {"step": "wait_for", "capture": "ref-a", "timeout": 90,
             "since": "mark:pre-restart",
             "pattern": r"discovery event=BOUND peer=1\b"},
            {"step": "wait_for", "capture": "ref-a", "timeout": 90,
             "since": "mark:pre-restart",
             "pattern": r"discovery event=REACHABLE peer=1\b"},
            {"step": "send_host_command",
             "args": ["send", "{node:ref-a}", "524c48494c33"]},
            {"step": "wait_for", "capture": "daemon:deliveries", "timeout": 90,
             "since": "mark:pre-restart",
             "pattern": r'"destination":{node:ref-a},"state":"delivered",'
                        r'"reason":"END_RECEIVED"'},
        ],
    },
}


class StepFailure(RuntimeError):
    """A scenario step failed — the scenario verdict becomes FAIL."""


class ScenarioConfigError(RuntimeError):
    """Bad step definition — caught at validation, counts as runner error."""


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

class Runner:
    """Executes one scenario: owns captures, marks and the managed daemon."""

    def __init__(
        self,
        rig: rig_mod.Rig,
        statuses: dict[str, rig_mod.BoardStatus],
        scenario_dir: str,
        esptool: str = DEFAULT_ESPTOOL,
    ):
        self.rig = rig
        self.statuses = statuses
        self.dir = scenario_dir
        self.esptool = esptool
        self.captures: dict[str, cap_mod.Capture] = {}
        self.marks: dict[str, dict[str, int]] = {}
        self.daemon_proc: Optional[subprocess.Popen] = None
        self._daemon_reader: Optional[threading.Thread] = None
        self.acl_path: Optional[str] = None
        # Relativisation root for evidence paths; run_scenario overrides it
        # with the real run dir. Defaulting to the scenario dir keeps
        # self-contained unit tests working.
        self.run_dir = scenario_dir

    # -- capture management ------------------------------------------------

    def open_board_captures(self, boards: list[str]) -> None:
        for name in boards:
            board = self.rig.boards[name]
            if board.console == "none":
                continue  # bridge: USB is protocol-only, never captured
            status = self.statuses[name]
            cap = cap_mod.SerialCapture(
                name, status.port, board.baud,
                os.path.join(self.dir, f"{name}.log"),
                dtr=board.dtr, rts=board.rts,
            )
            cap.start()
            self._register_capture(name, cap)

    def capture(self, name: str) -> cap_mod.Capture:
        cap = self.captures.get(name)
        if cap is not None:
            return cap
        if name.startswith("daemon:"):
            verb = name.split(":", 1)[1]
            if not re.fullmatch(r"[a-z-]+", verb):
                raise ScenarioConfigError(
                    f"daemon capture {name!r}: bad verb {verb!r}")
            cap = cap_mod.PollCapture(
                name,
                self.ctl_argv([verb]),
                os.path.join(self.dir, f"daemon-{verb}.log"),
                interval_s=self.rig.host.poll_interval_s,
                timeout_s=self.rig.host.command_timeout_s,
            )
            cap.start()
            return self._register_capture(name, cap)
        if name == "host-commands":
            cap = cap_mod.Capture(
                name, os.path.join(self.dir, "host-commands.log"))
            return self._register_capture(name, cap)
        if name == "daemon":
            cap = cap_mod.Capture(
                name, os.path.join(self.dir, "daemon.log"))
            return self._register_capture(name, cap)
        raise ScenarioConfigError(
            f"unknown capture {name!r} (board without a console? "
            f"bridge has console=none by design)")

    def _register_capture(self, name: str, cap: cap_mod.Capture) -> cap_mod.Capture:
        """Track a capture and give existing marks a position in it.

        A capture created after `mark` ran still needs a value for that
        mark — position 0 is correct ("everything here is post-mark").
        """
        self.captures[name] = cap
        for mark_name, marks in self.marks.items():
            marks[name] = cap.mark()
        return cap

    def ctl_argv(self, args: list[str]) -> list[str]:
        return [os.path.join(rig_mod.REPO_ROOT, self.rig.host.ctl_bin),
                "--socket", self.rig.host.socket, *args]

    def evidence_paths(self) -> list[str]:
        return [
            cap.log_path for cap in self.captures.values()
            if os.path.isfile(cap.log_path)
        ]

    # -- daemon management --------------------------------------------------

    def _write_acl(self) -> str:
        """Per-run ACL granting the invoking uid send/read on all networks.

        The daemon is default-deny without --api-acl-file; HIL runs act as
        the bench operator, so we mint a file naming *this* uid. Recorded in
        the run dir — it is evidence, not a hidden privilege.
        """
        path = os.path.join(self.dir, "hil-acl.json")
        doc = {
            "principals": {
                str(os.getuid()): {
                    "networks": {
                        "*": ["READ_PAYLOAD", "SEND", "READ_OPERATION"]
                    }
                }
            },
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        os.chmod(path, 0o600)
        return path

    def start_daemon(self, timeout_s: float = DAEMON_AUTH_TIMEOUT_S) -> str:
        if self.daemon_proc is not None and self.daemon_proc.poll() is None:
            return "already running"
        socket_path = self.rig.host.socket
        if os.path.exists(socket_path):
            # A live foreign daemon on our socket would let SENDs run with
            # an unknown device/ACL — refuse rather than inherit it.
            probe = subprocess.run(
                self.ctl_argv(["status"]),
                capture_output=True, text=True, timeout=5,
            )
            if probe.returncode == 0 and probe.stdout.strip():
                raise StepFailure(
                    f"{socket_path} is served by an unmanaged daemon — "
                    f"stop it or set a different host.socket in rigs.yaml")
            os.unlink(socket_path)  # stale socket file
        bridge = self._bridge_board()
        if bridge is None:
            raise StepFailure("scenario needs a daemon but the bench has no "
                              "board with role 'bridge'")
        port = self.statuses[bridge.name].port
        daemon_bin = os.path.join(
            rig_mod.REPO_ROOT, self.rig.host.daemon_bin)
        acl_cfg = self.rig.host.acl_file
        argv = [daemon_bin, "--socket", socket_path, "--device", port]
        if acl_cfg == "auto":
            self.acl_path = self._write_acl()
            argv += ["--api-acl-file", self.acl_path]
        elif acl_cfg and acl_cfg != "none":
            self.acl_path = acl_cfg if os.path.isabs(acl_cfg) else os.path.join(
                rig_mod.REPO_ROOT, acl_cfg)
            argv += ["--api-acl-file", self.acl_path]
        # else: no ACL file — daemon runs default-deny; SEND will be refused
        # and the scenario will FAIL with the daemon's own error. Honest.
        daemon_cap = self.capture("daemon")
        daemon_cap.feed_line(f"$ {shlex.join(argv)}")
        self.daemon_proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd=rig_mod.REPO_ROOT,
        )
        self._daemon_reader = threading.Thread(
            target=self._drain_daemon, daemon=True, name="daemon-stdout")
        self._daemon_reader.start()
        # Wait until the device session is authenticated — SEND is refused
        # before that point, so polling `adapter` is the honest gate.
        adapter = self.capture("daemon:adapter")
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.daemon_proc.poll() is not None:
                raise StepFailure(
                    f"daemon exited rc={self.daemon_proc.returncode} "
                    f"during startup — see daemon.log")
            if adapter.find(r'"authenticated":true'):
                return "authenticated"
            time.sleep(0.5)
        self._dump_tail(adapter, "adapter")
        raise StepFailure(
            f"daemon did not reach an authenticated session within "
            f"{timeout_s}s")

    def _drain_daemon(self) -> None:
        cap = self.captures.get("daemon")
        if cap is None or self.daemon_proc is None or self.daemon_proc.stdout is None:
            return
        try:
            for line in self.daemon_proc.stdout:
                cap.feed_line(line.rstrip("\n"))
        except (ValueError, OSError):
            pass

    def stop_daemon(self) -> None:
        if self.daemon_proc is None:
            return
        proc = self.daemon_proc
        self.daemon_proc = None
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        if self._daemon_reader is not None:
            self._daemon_reader.join(timeout=3)
            self._daemon_reader = None

    def _bridge_board(self) -> Optional[rig_mod.Board]:
        for board in self.rig.boards.values():
            if board.role == "bridge":
                return board
        return None

    def daemon_owns(self, board_name: str) -> bool:
        bridge = self._bridge_board()
        return (
            bridge is not None
            and board_name == bridge.name
            and self.daemon_proc is not None
            and self.daemon_proc.poll() is None
        )

    # -- steps ---------------------------------------------------------------

    def _subst(self, text: str) -> str:
        def repl(match: "re.Match[str]") -> str:
            kind, _, arg = match.group(1).partition(":")
            if kind == "node":
                board = self.rig.boards.get(arg)
                if board is None or board.node_id is None:
                    raise ScenarioConfigError(
                        f"template {match.group(0)}: board {arg!r} has no node_id")
                return str(board.node_id)
            if kind == "socket":
                return self.rig.host.socket
            raise ScenarioConfigError(f"unknown template {match.group(0)}")
        return re.sub(r"\{([a-z]+:[^}]+|socket)\}", repl, text)

    def _resolve_since(self, capture_name: str, spec: Optional[str]) -> int:
        if spec in (None, "run"):
            return 0
        if isinstance(spec, str) and spec.startswith("mark:"):
            name = spec[5:]
            mark = self.marks.get(name, {}).get(capture_name)
            if mark is None:
                raise ScenarioConfigError(
                    f"no mark {name!r} recorded for capture {capture_name!r}")
            return mark
        raise ScenarioConfigError(f"bad since/window {spec!r}")

    def _window_lines(self, capture_name: str, window: Optional[str]) -> list[str]:
        cap = self.capture(capture_name)
        if window in (None, "run"):
            return cap.all_lines()
        if isinstance(window, str) and window.startswith("mark:"):
            return cap.lines_since(self._resolve_since(capture_name, window))
        if isinstance(window, str) and window.startswith("last:"):
            try:
                n = int(window[5:])
            except ValueError:
                raise ScenarioConfigError(f"bad window {window!r}")
            return cap.tail(n)
        raise ScenarioConfigError(f"bad window {window!r}")

    def _dump_tail(self, cap: cap_mod.Capture, tag: str) -> Optional[str]:
        tail = cap.tail(TAIL_LINES)
        if not tail:
            return None
        path = os.path.join(self.dir, f"timeout-tail-{tag}.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"# tail({TAIL_LINES}) of {cap.log_path}\n")
            fh.write("\n".join(tail) + "\n")
        return path

    def step_reset_boards(self, boards: list[str]) -> str:
        restart_daemon = any(self.daemon_owns(b) for b in boards)
        if restart_daemon:
            self.stop_daemon()
        try:
            for name in boards:
                board = self.rig.boards.get(name)
                if board is None:
                    raise ScenarioConfigError(f"unknown board {name!r}")
                status = self.statuses.get(name)
                if status is None or status.status != "ONLINE":
                    raise StepFailure(
                        f"board {name!r} went {status.status if status else 'MISSING'} "
                        "mid-run")
                self._reset_one(board, status.port)
            time.sleep(RESET_SETTLE_S)
        finally:
            if restart_daemon:
                self.start_daemon()
        return f"reset: {', '.join(boards)}"

    def _reset_one(self, board: rig_mod.Board, port: str) -> None:
        cap = self.captures.get(board.name)
        if board.reset == "none":
            if cap:
                cap.feed_line("!! reset skipped (reset=none)")
            return
        if board.reset == "dtr-rts" and isinstance(cap, cap_mod.SerialCapture):
            cap.pulse_reset()          # keep the fd; toggles EN via RTS
            return
        if cap is not None:
            cap.suspend()
        try:
            if board.reset == "dtr-rts":
                cap_mod.pulse_reset_port(port, board.baud)
            elif board.reset == "esptool":
                ok, out = cap_mod.esptool_reset(
                    port, self.esptool, chip=board.chip or None)
                log = self.capture("host-commands")
                log.feed_line(f"$ esptool reset {board.name} on {port}")
                for line in out.splitlines()[-20:]:
                    log.feed_line(f"  {line}")
                if not ok:
                    raise StepFailure(
                        f"esptool reset of {board.name} failed — "
                        f"see host-commands.log tail")
            elif board.reset == "command":
                cmd = board.reset_command.replace("{port}", port)
                out = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True,
                    timeout=self.rig.host.command_timeout_s)
                if out.returncode != 0:
                    raise StepFailure(
                        f"reset_command for {board.name} exit "
                        f"{out.returncode}: {out.stderr.strip()}")
        finally:
            if cap is not None:
                try:
                    cap.resume()
                except cap_mod.CaptureError as exc:
                    raise StepFailure(
                        f"capture resume on {board.name} failed: {exc}")

    def step_wait_for(self, capture: str, pattern: str,
                      timeout: float, since: Optional[str] = None) -> str:
        cap = self.capture(capture)
        mark = self._resolve_since(capture, since)
        rx = self._subst(pattern)
        line = cap.wait_for(rx, timeout, since=mark)
        if line is None:
            tail = self._dump_tail(cap, capture.replace(":", "_"))
            raise StepFailure(
                f"timeout {timeout}s waiting for /{rx}/ on {capture}"
                + (f" (tail dumped to {os.path.basename(tail)})" if tail else ""))
        return f"matched: {line[:160]}"

    def step_send_host_command(self, args: list[str]) -> str:
        argv = self.ctl_argv([self._subst(a) for a in args])
        log = self.capture("host-commands")
        log.feed_line(f"$ {shlex.join(argv)}")
        try:
            out = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=self.rig.host.command_timeout_s)
        except subprocess.TimeoutExpired:
            raise StepFailure(
                f"routeloomctl timed out after "
                f"{self.rig.host.command_timeout_s}s")
        except OSError as exc:
            raise StepFailure(f"routeloomctl exec failed: {exc}")
        for line in out.stdout.splitlines():
            log.feed_line(line)
        for line in out.stderr.splitlines():
            log.feed_line(f"!stderr! {line}")
        log.feed_line(f"!exit={out.returncode}!")
        if out.returncode != 0:
            raise StepFailure(
                f"routeloomctl exit {out.returncode}: "
                f"{(out.stderr or out.stdout).strip()[:200]}")
        return out.stdout.strip()[:160]

    def step_assert_log(self, capture: str, pattern: str,
                        window: Optional[str] = None) -> str:
        rx = re.compile(self._subst(pattern))
        for line in self._window_lines(capture, window):
            if rx.search(line):
                return f"found: {line[:160]}"
        raise StepFailure(
            f"/{pattern}/ not found in {capture} window={window or 'run'}")

    def step_assert_absent(self, capture: str, pattern: str,
                           window: Optional[str] = None) -> str:
        rx = re.compile(self._subst(pattern))
        for line in self._window_lines(capture, window):
            if rx.search(line):
                raise StepFailure(
                    f"unexpected /{pattern}/ in {capture}: {line[:160]}")
        return f"absent in {capture} (window={window or 'run'})"

    def step_mark(self, name: str) -> str:
        marks = self.marks.setdefault(name, {})
        for cap_name, cap in self.captures.items():
            marks[cap_name] = cap.mark()
        return f"mark {name!r} on {len(marks)} captures"

    def run(self, name: str, spec: dict) -> report_mod.ScenarioResult:
        result = report_mod.ScenarioResult(name=name)
        started = time.monotonic()
        boards = spec.get("boards", [])
        try:
            self.open_board_captures(boards)
            for index, step in enumerate(spec["steps"]):
                kind = step.get("step")
                t0 = time.monotonic()
                detail, ok = "", True
                try:
                    detail = self._dispatch(kind, step)
                except StepFailure as exc:
                    ok, detail = False, str(exc)
                except ScenarioConfigError:
                    raise
                except Exception as exc:  # runner bug, not firmware evidence
                    ok, detail = False, f"runner-error: {exc!r}"
                result.steps.append(report_mod.StepResult(
                    step=f"{index}:{kind}", ok=ok, detail=detail,
                    duration_s=time.monotonic() - t0))
                if not ok:
                    result.verdict = "FAIL"
                    result.detail = f"step {index} ({kind}): {detail}"
                    break
            else:
                result.verdict = "PASS"
                result.detail = spec.get("description", "")
        except ScenarioConfigError as exc:
            result.verdict = "FAIL"
            result.detail = f"bad scenario definition: {exc}"
        except Exception as exc:
            # e.g. a board capture failed to open — a runner/environment
            # problem, reported as FAIL with the error, never as PASS.
            result.verdict = "FAIL"
            result.detail = f"runner-error: {exc!r}"
        finally:
            self.stop_daemon()
            for cap in self.captures.values():
                try:
                    cap.stop()
                except Exception:
                    pass
            result.duration_s = time.monotonic() - started
            # Evidence = every artifact this scenario produced.
            for path in self.evidence_paths():
                rel = os.path.relpath(path, self.run_dir)
                if rel not in result.evidence:
                    result.evidence.append(rel)
        return result

    def _dispatch(self, kind: str, step: dict) -> str:
        if kind == "start_daemon":
            return self.start_daemon(
                float(step.get("timeout", DAEMON_AUTH_TIMEOUT_S)))
        if kind == "stop_daemon":
            self.stop_daemon()
            return "stopped"
        if kind == "reset_boards":
            return self.step_reset_boards(list(step.get("boards", [])))
        if kind == "wait_for":
            return self.step_wait_for(
                step["capture"], step["pattern"],
                float(step["timeout"]), step.get("since"))
        if kind == "send_host_command":
            return self.step_send_host_command(list(step["args"]))
        if kind == "assert_log":
            return self.step_assert_log(
                step["capture"], step["pattern"], step.get("window"))
        if kind == "assert_absent":
            return self.step_assert_absent(
                step["capture"], step["pattern"], step.get("window"))
        if kind == "mark":
            return self.step_mark(step["name"])
        if kind == "sleep":
            seconds = float(step["seconds"])
            time.sleep(seconds)
            return f"slept {seconds}s"
        raise ScenarioConfigError(f"unknown step kind {kind!r}")


# --------------------------------------------------------------------------
# Scenario-level driver
# --------------------------------------------------------------------------

def precheck(
    spec: dict,
    rig: rig_mod.Rig,
    statuses: dict[str, rig_mod.BoardStatus],
) -> list[str]:
    """Reasons this scenario cannot run; empty means GO."""
    reasons = []
    required = list(spec.get("boards", []))
    if spec.get("daemon"):
        # The daemon owns the bridge's USB port — a daemon scenario
        # implicitly requires a bridge board that resolved ONLINE.
        for name, board in rig.boards.items():
            if board.role == "bridge" and name not in required:
                required.append(name)
    for name in required:
        if name not in rig.boards:
            reasons.append(f"board {name!r} not defined in rig")
            continue
        st = statuses.get(name)
        if st is None or st.status != "ONLINE":
            reasons.append(
                f"board {name!r} not ONLINE "
                f"({st.status if st else 'unresolved'}"
                + (f": {st.detail}" if st and st.detail else "")
                + (f" matches={st.matches}" if st and st.matches else "")
                + ")")
    if spec.get("daemon"):
        host = rig.host
        for label, rel in (("daemon", host.daemon_bin), ("ctl", host.ctl_bin)):
            path = os.path.join(rig_mod.REPO_ROOT, rel)
            if not (os.path.isfile(path) and os.access(path, os.X_OK)):
                reasons.append(
                    f"host {label} binary missing/not executable: {rel} "
                    f"(build with `cargo build` in host/)")
    return reasons


def run_scenario(
    name: str,
    rig: rig_mod.Rig,
    statuses: dict[str, rig_mod.BoardStatus],
    run: report_mod.RunReport,
    esptool: str = DEFAULT_ESPTOOL,
) -> report_mod.ScenarioResult:
    spec = SCENARIOS.get(name)
    if spec is None:
        raise ScenarioConfigError(
            f"unknown scenario {name!r} (have: {', '.join(sorted(SCENARIOS))})")
    reasons = precheck(spec, rig, statuses)
    if reasons:
        result = report_mod.ScenarioResult(
            name=name, verdict="SKIP-OFFLINE", detail="; ".join(reasons))
        run.add(result)
        return result
    scenario_dir = run.scenario_dir(name)
    runner = Runner(rig, statuses, scenario_dir, esptool=esptool)
    runner.run_dir = run.dir  # for evidence relativisation
    result = runner.run(name, spec)
    run.add(result)
    return result


def validate_scenarios() -> list[str]:
    """Static sanity checks on the scenario table (used by --selftest)."""
    problems = []
    known_kinds = {
        "start_daemon", "stop_daemon", "reset_boards", "wait_for",
        "send_host_command", "assert_log", "assert_absent", "mark", "sleep",
    }
    for name, spec in SCENARIOS.items():
        if not spec.get("steps"):
            problems.append(f"{name}: no steps")
        for i, step in enumerate(spec.get("steps", [])):
            kind = step.get("step")
            if kind not in known_kinds:
                problems.append(f"{name}[{i}]: unknown step {kind!r}")
            if kind == "wait_for" and "timeout" not in step:
                problems.append(f"{name}[{i}]: wait_for needs a timeout")
            if kind in ("wait_for", "assert_log", "assert_absent") \
                    and "capture" not in step:
                problems.append(f"{name}[{i}]: {kind} needs a capture")
            if kind in ("wait_for", "assert_log", "assert_absent") \
                    and "pattern" not in step:
                problems.append(f"{name}[{i}]: {kind} needs a pattern")
            if kind == "send_host_command" and "args" not in step:
                problems.append(f"{name}[{i}]: send_host_command needs args")
    return problems


def _selftest() -> int:
    """Unit-test the step engine against a synthetic capture (no hardware)."""
    import tempfile

    problems = validate_scenarios()
    assert not problems, problems

    with tempfile.TemporaryDirectory() as tmp:
        rig = rig_mod.Rig(
            name="fake",
            boards={
                "ref-a": rig_mod.Board(
                    name="ref-a", app="reference_node", chip="esp32c3",
                    node_id=2, console="usb-serial-jtag"),
                "bridge": rig_mod.Board(
                    name="bridge", app="bridge_node", chip="esp32c3",
                    node_id=1, role="bridge", console="none"),
            },
            host=rig_mod.HostSide(),
        )
        runner = Runner(rig, {}, tmp)
        cap = cap_mod.Capture("ref-a", os.path.join(tmp, "ref-a.log"))
        runner.captures["ref-a"] = cap
        runner.run_dir = tmp

        cap.feed_line("discovery event=BOUND peer=1")
        assert runner.step_wait_for("ref-a", r"event=BOUND", 1.0)
        cap.feed_line("discovery event=REACHABLE peer=1")
        runner.step_mark("m1")
        cap.feed_line("some noise")
        # wait_for with since=mark must not see the pre-mark BOUND.
        cap.feed_line("discovery event=BOUND peer=1")  # new event post-mark
        line = runner.step_wait_for(
            "ref-a", r"event=BOUND", 1.0, since="mark:m1")
        assert "BOUND" in line
        # assert_absent over the pre-mark window only.
        runner.step_assert_absent("ref-a", r"REACHABLE", window="mark:m1")
        try:
            runner.step_assert_absent("ref-a", r"REACHABLE", window="run")
        except StepFailure:
            pass
        else:
            raise AssertionError("assert_absent should have fired on run window")
        try:
            runner.step_wait_for("ref-a", r"never-appears", 0.3)
        except StepFailure as exc:
            assert "timeout" in str(exc)
        else:
            raise AssertionError("wait_for should have timed out")
        # Templates.
        assert runner._subst("send {node:ref-a}") == "send 2"
        # daemon capture creation needs ctl binary — expect config error
        # path only when used; here just check bad verb rejected.
        try:
            runner.capture("daemon:bad verb!")
        except ScenarioConfigError:
            pass
        else:
            raise AssertionError("bad daemon verb should be rejected")
    print("scenarios.py selftest OK")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run RouteLoom HIL scenarios against a rig.")
    parser.add_argument("--rig", help="path to rigs.yaml (required for a run)")
    parser.add_argument("--bench", help="bench name (default: first in file)")
    parser.add_argument("--scenario", action="append",
                        help="scenario name (repeatable); default: all")
    parser.add_argument("--list", action="store_true",
                        help="list scenarios and exit")
    parser.add_argument("--out", default=report_mod.ARTIFACTS_ROOT,
                        help="artifacts root (default: artifacts/hil)")
    parser.add_argument("--esptool", default=DEFAULT_ESPTOOL)
    parser.add_argument("--label", default="",
                        help="extra label appended to the run dir name")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    if args.selftest:
        return _selftest()

    if args.list:
        for name, spec in SCENARIOS.items():
            print(f"{name}: {spec['description']}")
        return 0

    if not args.rig:
        parser.error("--rig is required for a run")

    rigs = rig_mod.load_rigs(args.rig)
    if not rigs:
        print("error: no benches in", args.rig, file=sys.stderr)
        return 2
    bench_name = args.bench or next(iter(rigs))
    if bench_name not in rigs:
        print(f"error: bench {bench_name!r} not in {args.rig} "
              f"(have: {', '.join(sorted(rigs))})", file=sys.stderr)
        return 2
    rig = rigs[bench_name]

    selected = args.scenario or list(SCENARIOS)
    for name in selected:
        if name not in SCENARIOS:
            print(f"error: unknown scenario {name!r} "
                  f"(have: {', '.join(sorted(SCENARIOS))})", file=sys.stderr)
            return 2

    run = report_mod.RunReport(bench_name, args.out, label=args.label)
    run.meta["environment"] = report_mod.environment(
        cap_mod.serial_backend(), args.esptool)
    run.meta["repo"] = report_mod.repo_evidence()
    run.meta["firmware"] = {
        b.app: report_mod.firmware_evidence(b.app)
        for b in {b.app: b for b in rig.boards.values()}.values()
    }
    run.write_text("usb-inventory.txt", rig_mod.usb_inventory())

    statuses = rig_mod.resolve_rig(rig)
    offline = rig_mod.rig_online(statuses)
    run.meta["boards"] = {
        name: {"status": st.status, "port": st.port, "detail": st.detail}
        for name, st in statuses.items()
    }
    if offline:
        print(f"bench {bench_name}: OFFLINE")
        for reason in offline:
            print(f"  {reason}")

    for name in selected:
        run_scenario(name, rig, statuses, run, esptool=args.esptool)

    report = run.finalize()
    print(f"report: {run.dir}/report.json")
    return 1 if report["totals"]["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
