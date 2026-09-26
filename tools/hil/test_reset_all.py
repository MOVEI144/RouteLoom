"""USB Serial/JTAG can disappear briefly after identity preflight."""

import unittest
from unittest.mock import patch

import reset_all


class SerialAfterReenumeration:
    attempts = 0
    closed = 0

    def __init__(self, **_kwargs):
        self.port = None
        self.dtr = False
        self.rts = False

    def open(self):
        type(self).attempts += 1
        if type(self).attempts == 1:
            raise BrokenPipeError("USB tty re-enumerating")

    def close(self):
        type(self).closed += 1


class ResetAllTest(unittest.TestCase):
    def test_retries_transient_usb_open_on_same_pinned_port(self):
        SerialAfterReenumeration.attempts = 0
        SerialAfterReenumeration.closed = 0
        with patch.object(reset_all.serial, "Serial", SerialAfterReenumeration), \
             patch.object(reset_all.time, "sleep"):
            device, attempts = reset_all.open_stable_port("/dev/serial/by-id/pinned")
        self.assertEqual(attempts, 2)
        self.assertEqual(device.port, "/dev/serial/by-id/pinned")
        self.assertEqual(SerialAfterReenumeration.closed, 1)


if __name__ == "__main__":
    unittest.main()
