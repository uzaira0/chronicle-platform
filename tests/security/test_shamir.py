#!/usr/bin/env python3
"""The Shamir split and recovery in docker/shamir.py; uses only synthetic keys.

Found by `unittest discover -s tests/security -p 'test_*.py'` (scripts/local-ci.sh job_engineering)."""

import itertools
from pathlib import Path
import secrets
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "docker"))
import shamir

SHAMIR_COMMAND = [sys.executable, "-B", str(ROOT / "docker/shamir.py")]

# Captured before refactoring docker/key-ceremony.sh's embedded python_split.
# Embedded source SHA-256: 704188f26543347cecf0f3c35a30726fcb82945b6c96f9eced9ed7d5263a4d72
LEGACY_SHARES = (
    "1-4e0c08fee41387d5634e7b73d958f69d2935bb3df4d1740f1de83a416cf2e8f1",
    "2-322e3faeaa4684bfffb9fd7acd64c8411722e32d6fbec6057d0e00f69a6364b5",
    "3-7c2335534a50056d94fe8c02183130d32e064a038f7aa41d78ff20acea8c925b",
    "4-ea8bdc698c244370798aabdb4efe2d4cd1803dfc54b8fdbb75a25da5883be8ff",
    "5-a486d6946c32c2a212cddaa39babd5dee8a494d2b47c9fa370537dfff8d41e11",
)


def encoded_shares(secret, threshold, count=5):
    result = subprocess.run([*SHAMIR_COMMAND, "split", secret.hex(), str(threshold), str(count)],
                            check=True, capture_output=True, text=True)
    return result.stdout.splitlines()


class ShamirTests(unittest.TestCase):
    def test_every_threshold_and_subset_roundtrips_random_secrets(self):
        for threshold in range(2, 6):
            for length in (16, 32, 33, 65):
                secret = secrets.token_bytes(length)
                shares = encoded_shares(secret, threshold)
                for subset in itertools.combinations(shares, threshold):
                    with self.subTest(threshold=threshold, length=length, subset=subset):
                        self.assertEqual(shamir.combine(subset, threshold), secret)
                        self.assertEqual(shamir.combine(subset[::-1], threshold), secret)
                self.assertEqual(shamir.combine(shares, threshold), secret)
                for insufficient in itertools.combinations(shares, threshold - 1):
                    with self.assertRaises(ValueError):
                        shamir.combine(insufficient, threshold)

    def test_legacy_embedded_splitter_shares_still_combine(self):
        for subset in itertools.combinations(LEGACY_SHARES, 3):
            self.assertEqual(shamir.combine(subset, 3), bytes(range(32)))

    def test_malformed_duplicate_and_unequal_shares_are_rejected(self):
        good = list(LEGACY_SHARES[:3])
        for bad in ("", "0-00", "256-00", "1000-00", "-1-00", "1-", "1-f",
                    "1-zz", "1-00 11", "1-00\n", "1-00;print('injected')",
                    "１-00", "1-00"):
            for position in (0, len(good)):
                values = good.copy()
                values.insert(position, bad)
                with self.subTest(bad=bad, position=position), self.assertRaises(ValueError):
                    shamir.combine(values, 3)
        for duplicate in (good[0], "001-" + good[0].split("-", 1)[1]):
            with self.assertRaises(ValueError):
                shamir.combine([*good, duplicate], 3)
        with self.assertRaises(ValueError):
            shamir.combine([], 3)

    def test_maximum_share_index_and_invalid_split_inputs(self):
        secret = secrets.token_bytes(32)
        shares = encoded_shares(secret, 2, 255)
        self.assertEqual(shamir.combine(shares[-2:], 2), secret)
        for threshold, count in ((0, 5), (1, 5), (3, 2), (2, 256)):
            with self.assertRaises(ValueError):
                shamir.make_shares(secret, threshold, count)
        with self.assertRaises(ValueError):
            shamir.make_shares(b"", 3, 5)

    def test_cli_split_combine_and_insufficient_shares(self):
        secret = secrets.token_bytes(32)
        shares = encoded_shares(secret, 3)
        self.assertEqual(len(shares), 5)
        recovered = subprocess.run([*SHAMIR_COMMAND, "combine", "3", *shares], capture_output=True, text=True)
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(recovered.stdout.strip(), secret.hex())
        refused = subprocess.run([*SHAMIR_COMMAND, "combine", "3", *shares[:2]], capture_output=True, text=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(refused.stdout, "")


if __name__ == "__main__":
    unittest.main()
