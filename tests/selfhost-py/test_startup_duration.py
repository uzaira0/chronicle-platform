"""Caddy's duration range is Go's signed 64-bit nanosecond range."""

import unittest

from chronicle_ops.startup import valid_caddy_duration


class StartupDurationTests(unittest.TestCase):
    def test_positive_caddy_duration_boundaries_and_units(self):
        for value in ("1ns", "+1s", "1.5h", ".5s", "1.s", "1m30s", "1us", "1µs", "1μs",
                      "2562047h47m16.854775807s", "9999999ns", "1d", "1.5d"):
            with self.subTest(value=value):
                self.assertTrue(valid_caddy_duration(value))

    def test_malformed_zero_underflow_and_overflow_are_rejected(self):
        for value in ("", "0", "0s", "-1s", " 1s", "1s ", "1w", "1e3s", "1s!",
                      "0.0000000001ns", "2562047h47m16.854775808s", "999999h999999h999999h",
                      "1" * 129 + "ns"):
            with self.subTest(value=value):
                self.assertFalse(valid_caddy_duration(value))


if __name__ == "__main__":
    unittest.main()
