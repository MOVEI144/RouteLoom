#!/usr/bin/env python3
"""Timestamped serial capture for RouteLoom HIL runs.

Two serial backends, chosen automatically:

* ``serial`` (pyserial) when it is importable;
* raw ``termios``+``fcntl`` via the Python standard library otherwise
  (the previous HIL session ran in an environment without pyserial — this
  path exists so capture works with zero pip installs).

Both backends assert DTR on the reference node's USB-Serial-JTAG console:
that console emits nothing while DTR is deasserted. RTS is left
deasserted by default (RTS drives EN on classic auto-reset wiring).

A ``Capture`` is a sink: timestamped lines appended to a log file plus a
bounded ring buffer and a ``wait_for(regex, timeout)`` condition.
Producers feed it: ``SerialCapture`` (a reader thread on a serial port)
and ``PollCapture`` (a subprocess re-run on an interval, e.g. polling
``routeloomctl`` against the daemon socket — this is how bridge-side
state is observed, since the bridge's USB port carries COBS protocol
frames and MUST NOT be read as logs).

All blocking is bounded; callers pass explicit timeouts. On timeout the
scenario runner dumps ``tail()`` into the report.

NOTE: not yet exercised against real hardware (issue #18 bootstrap).
"""

from __future__ import annotations

import argparse
import datetime
import errno
import fcntl
import os
import re
import select
import shlex
import struct
import subprocess
import sys
import termios
import threading
import time
from collections import deque
from typing import Optional, Pattern

try:
    import serial  # type: ignore  # pyserial, optional

    HAVE_PYSERIAL = True
except ImportError:
    serial = None  # type: ignore
    HAVE_PYSERIAL = False


def serial_backend() -> str:
    return "pyserial" if HAVE_PYSERIAL else "termios"


#: Baud rates termios knows by name on both Linux and macOS.
_BAUD_MAP = {
    0: "B0", 50: "B50", 75: "B75", 110: "B110", 134: "B134", 150: "B150",
    200: "B200", 300: "B300", 600: "B600", 1200: "B1200", 1800: "B1800",
    2400: "B2400", 4800: "B4800", 9600: "B9600", 19200: "B19200",
    38400: "B38400", 57600: "B57600", 115200: "B115200", 230400: "B230400",
    460800: "B460800", 500000: "B500000", 921600: "B921600",
    1000000: "B1000000", 2000000: "B2000000",
}

# Darwin ioctl to set an arbitrary baud on a tty (from <sys/ioctl.h>).
_IOSSIOSPEED = 0x80045402


def utc_stamp(ts: Optional[float] = None) -> str:
    """ISO-8601 UTC timestamp with milliseconds — the capture log prefix."""
    dt = datetime.datetime.fromtimestamp(
        time.time() if ts is None else ts, tz=datetime.timezone.utc
    )
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class CaptureError(RuntimeError):
    pass


class Capture:
    """A timestamped line log + ring buffer + wait_for condition.

    Producers call ``feed_line``/``feed_bytes``; consumers call
    ``wait_for``/``lines_since``/``tail``. Thread-safe.
    """

    RING_LINES = 4000

    def __init__(self, name: str, log_path: str):
        self.name = name
        self.log_path = log_path
        os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
        # Line-buffered so a crashed producer still leaves complete lines.
        self._fh = open(log_path, "a", encoding="utf-8", buffering=1)
        self._ring: deque[tuple[float, str]] = deque(maxlen=self.RING_LINES)
        self._line_count = 0  # absolute counter so marks survive ring eviction
        self._cond = threading.Condition()
        self._closed = False
        self.started_at = time.time()

    # -- producer side ----------------------------------------------------

    def feed_line(self, text: str, ts: Optional[float] = None) -> None:
        stamp = utc_stamp(ts)
        with self._cond:
            if self._closed:
                return
            self._fh.write(f"[{stamp}] {text}\n")
            self._ring.append((time.time() if ts is None else ts, text))
            self._line_count += 1
            self._cond.notify_all()

    def feed_bytes(self, data: bytes, ts: Optional[float] = None) -> None:
        for line in data.decode("utf-8", errors="replace").splitlines():
            self.feed_line(line, ts)

    # -- consumer side ----------------------------------------------------

    def mark(self) -> int:
        """Opaque offset: ``lines_since`` returns lines logged after it."""
        with self._cond:
            return self._line_count

    def lines_since(self, mark: int) -> list[str]:
        """All lines recorded after ``mark`` (which came from ``mark()``)."""
        with self._cond:
            skip = max(0, mark - (self._line_count - len(self._ring)))
            return [t for _, t in list(self._ring)[skip:]]

    def all_lines(self) -> list[str]:
        with self._cond:
            return [t for _, t in self._ring]

    def tail(self, n: int = 40) -> list[str]:
        with self._cond:
            return [t for _, t in list(self._ring)[-n:]]

    def find(self, pattern: "str | Pattern[str]", since: int = 0):
        rx = re.compile(pattern) if isinstance(pattern, str) else pattern
        for line in self.lines_since(since):
            if rx.search(line):
                return line
        return None

    def wait_for(
        self, pattern: "str | Pattern[str]", timeout_s: float, since: int = 0
    ) -> Optional[str]:
        """First line matching ``pattern`` recorded after ``since``.

        Returns the matched line, or None on timeout. Bounded — always
        returns within ``timeout_s``.
        """
        rx = re.compile(pattern) if isinstance(pattern, str) else pattern
        deadline = time.monotonic() + timeout_s
        with self._cond:
            while True:
                skip = max(0, since - (self._line_count - len(self._ring)))
                for _, line in list(self._ring)[skip:]:
                    if rx.search(line):
                        return line
                if self._closed:
                    return None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(min(remaining, 0.5))

    def close(self) -> None:
        with self._cond:
            if self._closed:
                return
            self._closed = True
            self._cond.notify_all()
        try:
            self._fh.close()
        except OSError:
            pass

    def __repr__(self) -> str:
        return f"<Capture {self.name} -> {self.log_path}>"


# --------------------------------------------------------------------------
# Serial backend: raw termios
# --------------------------------------------------------------------------

def _set_baud_termios(attrs: list, baud: int) -> None:
    name = _BAUD_MAP.get(baud)
    if name is not None and hasattr(termios, name):
        attrs[4] = attrs[5] = getattr(termios, name)
        return
    raise CaptureError(
        f"baud {baud} not in the standard termios table; use the pyserial "
        f"backend or extend _BAUD_MAP"
    )


class _TermiosSerial:
    """Minimal read/write serial port via stdlib termios+fcntl.

    Used when pyserial is not installed. Configures 8N1 raw mode, asserts
    modem lines via TIOCMBIS/TIOCMBIC ioctls, and supports non-blocking
    reads via select.
    """

    def __init__(self, port: str, baud: int, dtr: bool, rts: bool):
        self.port = port
        self.fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            attrs = termios.tcgetattr(self.fd)
            # Raw 8N1, no flow control, no echo — equivalent to cfmakeraw
            # plus CLOCAL|CREAD.
            attrs[0] = 0  # iflag
            attrs[1] = 0  # oflag
            attrs[2] = termios.CS8 | termios.CLOCAL | termios.CREAD  # cflag
            attrs[3] = 0  # lflag
            attrs[6][termios.VMIN] = 0
            attrs[6][termios.VTIME] = 0
            _set_baud_termios(attrs, baud)
            termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
        except Exception:
            os.close(self.fd)
            raise
        # Non-standard baud on macOS needs IOSSIOSPEED after tcsetattr.
        if _BAUD_MAP.get(baud) is None or not hasattr(termios, _BAUD_MAP[baud]):
            try:
                fcntl.ioctl(self.fd, _IOSSIOSPEED, struct.pack("I", baud))
            except OSError:
                pass
        self.set_modem(dtr=dtr, rts=rts)
        self.flush_input()

    def set_modem(self, dtr: Optional[bool] = None, rts: Optional[bool] = None) -> None:
        bits = 0
        if dtr:
            bits |= termios.TIOCM_DTR
        if rts:
            bits |= termios.TIOCM_RTS
        if bits:
            fcntl.ioctl(self.fd, termios.TIOCMBIS, struct.pack("I", bits))
        clear = 0
        if dtr is False:
            clear |= termios.TIOCM_DTR
        if rts is False:
            clear |= termios.TIOCM_RTS
        if clear:
            fcntl.ioctl(self.fd, termios.TIOCMBIC, struct.pack("I", clear))

    def read(self, size: int, timeout_s: float) -> bytes:
        ready, _, _ = select.select([self.fd], [], [], timeout_s)
        if not ready:
            return b""
        try:
            return os.read(self.fd, size)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return b""
            raise

    def flush_input(self) -> None:
        termios.tcflush(self.fd, termios.TCIFLUSH)

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass


class _PyserialSerial:
    """Thin adapter so both backends share one reader interface."""

    def __init__(self, port: str, baud: int, dtr: bool, rts: bool):
        self._ser = serial.Serial()  # type: ignore[union-attr]
        self._ser.port = port
        self._ser.baudrate = baud
        self._ser.bytesize = 8
        self._ser.parity = "N"
        self._ser.stopbits = 1
        self._ser.timeout = 0
        self._ser.open()
        # DTR first: on the reference node's USB-Serial-JTAG console output
        # is suppressed while DTR is low.
        self._ser.dtr = bool(dtr)
        self._ser.rts = bool(rts)
        self._ser.reset_input_buffer()

    def set_modem(self, dtr: Optional[bool] = None, rts: Optional[bool] = None) -> None:
        if dtr is not None:
            self._ser.dtr = bool(dtr)
        if rts is not None:
            self._ser.rts = bool(rts)

    def read(self, size: int, timeout_s: float) -> bytes:
        ready, _, _ = select.select([self._ser.fd], [], [], timeout_s)
        if not ready:
            return b""
        try:
            return self._ser.read(size)
        except Exception as exc:
            raise CaptureError(f"pyserial read failed: {exc}") from exc

    def flush_input(self) -> None:
        self._ser.reset_input_buffer()

    def close(self) -> None:
        try:
            self._ser.close()
        except Exception:
            pass


def open_serial(port: str, baud: int, dtr: bool = True, rts: bool = False):
    """Open ``port`` with the best available backend."""
    if HAVE_PYSERIAL:
        return _PyserialSerial(port, baud, dtr, rts)
    return _TermiosSerial(port, baud, dtr, rts)


# --------------------------------------------------------------------------
# SerialCapture
# --------------------------------------------------------------------------

class SerialCapture(Capture):
    """Background serial reader feeding a Capture sink.

    The port is opened with DTR asserted (constructor arg) — required for
    the reference node's USB-Serial-JTAG console to emit anything.
    """

    def __init__(
        self,
        name: str,
        port: str,
        baud: int,
        log_path: str,
        dtr: bool = True,
        rts: bool = False,
    ):
        super().__init__(name, log_path)
        self.port = port
        self.baud = baud
        self._want_dtr = dtr
        self._want_rts = rts
        self._serial = None
        self._reader: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._open_error: Optional[str] = None

    def start(self) -> "SerialCapture":
        try:
            self._serial = open_serial(
                self.port, self.baud, dtr=self._want_dtr, rts=self._want_rts
            )
        except (OSError, CaptureError) as exc:
            self._open_error = str(exc)
            self.feed_line(f"!! capture open failed on {self.port}: {exc}")
            raise CaptureError(
                f"open {self.port} for capture {self.name!r}: {exc}"
            ) from exc
        self._stop.clear()
        self._reader = threading.Thread(
            target=self._read_loop, name=f"cap-{self.name}", daemon=True
        )
        self._reader.start()
        self.feed_line(
            f"!! capture open {self.port} @ {self.baud} backend={serial_backend()}"
            f" dtr={int(self._want_dtr)} rts={int(self._want_rts)}"
        )
        return self

    def _read_loop(self) -> None:
        partial = b""
        while not self._stop.is_set():
            try:
                data = self._serial.read(4096, 0.2)
            except (OSError, CaptureError) as exc:
                # Device unplugged mid-run: record it in the log — the
                # scenario sees it as a timeout, which is honest.
                self.feed_line(f"!! serial read error on {self.port}: {exc}")
                break
            if not data:
                continue
            chunk = partial + data
            lines = chunk.split(b"\n")
            partial = lines.pop()
            for raw in lines:
                self.feed_line(raw.decode("utf-8", errors="replace").rstrip("\r"))
        if partial:
            self.feed_line(
                partial.decode("utf-8", errors="replace") + "  (unterminated)")

    def suspend(self) -> None:
        """Close the port but keep the sink (used while esptool owns it)."""
        self._stop.set()
        if self._reader is not None:
            self._reader.join(timeout=3)
            self._reader = None
        if self._serial is not None:
            self._serial.close()
            self._serial = None
        self.feed_line(f"!! capture suspended on {self.port}")

    def resume(self) -> None:
        if self._serial is not None:
            return
        self._serial = open_serial(
            self.port, self.baud, dtr=self._want_dtr, rts=self._want_rts
        )
        self._stop.clear()
        self._reader = threading.Thread(
            target=self._read_loop, name=f"cap-{self.name}", daemon=True
        )
        self._reader.start()
        self.feed_line(f"!! capture resumed on {self.port}")

    def pulse_reset(self, hold_s: float = 0.1) -> None:
        """Reset via DTR/RTS on the *open* port (reset=dtr-rts).

        Classic wiring: RTS->EN, DTR->IO9. We assert RTS (EN low) while
        holding DTR low (IO9 high -> normal boot, not download mode), wait,
        release RTS, then restore the requested DTR level so console output
        resumes.

        Only valid on boards where the USB-Serial-JTAG block or an external
        UART bridge drives EN/IO9 from these lines. Not yet hardware-verified.
        """
        if self._serial is None:
            raise CaptureError("pulse_reset needs an open port")
        self.feed_line("!! reset pulse (dtr-rts)")
        self._serial.set_modem(dtr=False, rts=True)
        time.sleep(hold_s)
        self._serial.set_modem(rts=False)
        self._serial.set_modem(dtr=self._want_dtr)
        self._serial.flush_input()

    def stop(self) -> None:
        self._stop.set()
        if self._reader is not None:
            self._reader.join(timeout=3)
            self._reader = None
        if self._serial is not None:
            self._serial.close()
            self._serial = None
        self.feed_line("!! capture closed")
        self.close()


# --------------------------------------------------------------------------
# PollCapture — bridge/daemon observation without touching the bridge port
# --------------------------------------------------------------------------

class PollCapture(Capture):
    """Re-run a command on an interval and log its output.

    Used for ``routeloomctl <verb>`` polls against the host daemon socket —
    this is the ONLY supported way to observe bridge-side state in a
    scenario, because the bridge's own USB port carries protocol frames,
    not logs.
    """

    def __init__(
        self,
        name: str,
        argv: list[str],
        log_path: str,
        interval_s: float = 0.5,
        timeout_s: float = 10.0,
    ):
        super().__init__(name, log_path)
        self.argv = list(argv)
        self.interval_s = interval_s
        self.timeout_s = timeout_s
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> "PollCapture":
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._poll_loop, name=f"poll-{self.name}", daemon=True
        )
        self._thread.start()
        self.feed_line(f"!! poll start: {shlex.join(self.argv)} "
                       f"every {self.interval_s}s")
        return self

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self._proc = subprocess.run(
                    self.argv,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_s,
                )
                for line in self._proc.stdout.splitlines():
                    self.feed_line(line)
                for line in self._proc.stderr.splitlines():
                    self.feed_line(f"!stderr! {line}")
                if self._proc.returncode != 0:
                    self.feed_line(f"!exit={self._proc.returncode}!")
            except subprocess.TimeoutExpired:
                self.feed_line(f"!! poll timeout after {self.timeout_s}s")
            except OSError as exc:
                self.feed_line(f"!! poll exec failed: {exc}")
            finally:
                self._proc = None
            # Stop-responsive sleep.
            self._stop.wait(max(0.05, self.interval_s - (time.monotonic() - started)))

    def stop(self) -> None:
        self._stop.set()
        if self._proc is not None:
            try:
                self._proc.kill()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=self.timeout_s + 2)
            self._thread = None
        self.feed_line("!! poll stopped")
        self.close()


# --------------------------------------------------------------------------
# Reset helpers (module level for boards without a live capture)
# --------------------------------------------------------------------------

def pulse_reset_port(port: str, baud: int = 115200, hold_s: float = 0.1) -> None:
    """DTR/RTS reset on a port we do not hold open (opens it briefly)."""
    ser = open_serial(port, baud, dtr=False, rts=True)
    try:
        time.sleep(hold_s)
        ser.set_modem(rts=False, dtr=True)
        time.sleep(0.05)
    finally:
        ser.close()


def esptool_reset(
    port: str, esptool: str, chip: Optional[str] = None, timeout_s: float = 30.0
) -> tuple[bool, str]:
    """Reset a board by making esptool connect and let it boot the app.

    ``esptool <port> read-mac`` performs the configured before-reset
    sequence (default-reset for UART/USB-Serial-JTAG targets), then a hard
    reset on exit. Bounded by ``timeout_s``. Returns (ok, output).
    """
    argv = [esptool]
    if chip:
        argv += ["--chip", chip]
    argv += ["--port", port, "--connect-attempts", "2", "read-mac"]
    try:
        out = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout_s
        )
        return out.returncode == 0, (out.stdout or "") + (out.stderr or "")
    except subprocess.TimeoutExpired:
        return False, f"esptool reset timed out after {timeout_s}s"
    except OSError as exc:
        return False, f"esptool reset failed to exec: {exc}"


# --------------------------------------------------------------------------
# CLI: standalone capture for debugging a bench
# --------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Capture a serial port to a timestamped log."
    )
    parser.add_argument("--port", required=True)
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--out", required=True, help="log file path")
    parser.add_argument("--seconds", type=float, default=0,
                        help="stop after N seconds (0 = until ^C)")
    parser.add_argument("--no-dtr", action="store_true",
                        help="do not assert DTR (default asserts it — "
                             "required for the USB-Serial-JTAG console)")
    parser.add_argument("--rts", action="store_true")
    args = parser.parse_args(argv)

    cap = SerialCapture(
        "cli", args.port, args.baud, args.out,
        dtr=not args.no_dtr, rts=args.rts,
    )
    cap.start()
    print(f"capturing {args.port} -> {args.out} (backend={serial_backend()})")
    try:
        if args.seconds:
            time.sleep(args.seconds)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        cap.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
