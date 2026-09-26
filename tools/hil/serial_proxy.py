#!/usr/bin/env python3
"""Expose a serial board as a PTY and retain the device-to-host byte stream."""

import argparse
import errno
import os
import pty
import select
import sys
import tty

import serial


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--baud", type=int, default=115200)
    args = p.parse_args()
    physical = serial.Serial(port=None, baudrate=args.baud, timeout=0, write_timeout=1)
    physical.rts = False
    physical.dtr = True
    physical.port = args.port
    physical.open()
    master, slave = pty.openpty()
    tty.setraw(slave)
    print(os.ttyname(slave), flush=True)
    with open(args.out, "wb", buffering=0) as log:
        try:
            while True:
                ready, _, _ = select.select([physical.fileno(), master], [], [], 0.2)
                if physical.fileno() in ready:
                    data = physical.read(4096)
                    if data:
                        log.write(data)
                        os.write(master, data)
                if master in ready:
                    try:
                        data = os.read(master, 4096)
                    except OSError as exc:
                        if exc.errno == errno.EIO:  # no host has opened the PTY yet
                            continue
                        raise
                    if data:
                        physical.write(data)
        except KeyboardInterrupt:
            pass
    os.close(master)
    os.close(slave)
    physical.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
