#!/usr/bin/env python3
"""Regression checks for reset-cycle evidence accounting."""

import unittest

import reset_cycles


class ResetCycleAccountingTest(unittest.TestCase):
    def test_idempotency_full_after_host_admission_is_counted(self):
        sends = [
            {"response": {"accepted": True, "request": 7},
             "delivery": {"state": "failed", "reason": "IDEMPOTENCY_FULL"}},
            {"response": {"accepted": False, "error": "IDEMPOTENCY_FULL"}},
            {"response": {"accepted": True, "request": 8},
             "delivery": {"state": "delivered"}},
        ]
        self.assertEqual(reset_cycles.count_idempotency_full(sends), 2)


if __name__ == "__main__":
    unittest.main()
