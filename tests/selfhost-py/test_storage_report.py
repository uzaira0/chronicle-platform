"""Storage reserve decisions are identical for host and daemon measurements."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from chronicle_ops import common


class StorageReportTests(unittest.TestCase):
    def test_local_and_daemon_inode_and_byte_boundaries_agree(self):
        cases = (
            dict(total=0, available=0, free_gib=6, enough=True),
            dict(total=100_000, available=0, free_gib=6, enough=False),
            dict(total=100_000, available=9_999, free_gib=6, enough=False),
            dict(total=100_000, available=10_000, free_gib=6, enough=True),
            dict(total=0, available=0, free_gib=4, enough=False),
            dict(total=0, available=0, free_gib=5, enough=True),
        )
        for case in cases:
            disk = SimpleNamespace(f_bavail=case['free_gib'], f_frsize=common.GIB,
                                   f_files=case['total'], f_favail=case['available'])
            measured = SimpleNamespace(stdout=(
                'Filesystem 1024-blocks Used Available Capacity Mounted\n'
                f"disk 20000000 0 {case['free_gib'] * common.GIB // 1024} 0% /storage\n"
                'Filesystem Inodes IUsed IFree IUse% Mounted\n'
                f"disk {case['total']} 0 {case['available']} 0% /storage\n"))
            for remote in (False, True):
                with self.subTest(case=case, remote=remote), \
                     patch.object(common, 'database_volume_path', return_value=None), \
                     patch.object(common, 'run', side_effect=[SimpleNamespace(stdout='/docker'), measured]), \
                     patch.object(common.os, 'statvfs', side_effect=[disk, FileNotFoundError() if remote else disk]), \
                     patch.dict(common.os.environ, POSTGRES_IMAGE='fixture-image'):
                    rows = common.storage_report('/state', 'fixture')
                    self.assertEqual(case['enough'], rows[1][1])

    def test_malformed_daemon_capacity_is_rejected(self):
        disk = SimpleNamespace(f_bavail=6, f_frsize=common.GIB, f_files=100_000, f_favail=10_000)
        for output in ('truncated',
                       'header\ndisk 20000000 0 invalid 0% /storage\nheader\ndisk 100000 0 10000 0% /storage\n',
                       'header\ndisk 20000000 0 10000000 0% /storage\nheader\ndisk invalid 0 10000 0% /storage\n'):
            with self.subTest(output=output), \
                 patch.object(common, 'database_volume_path', return_value=None), \
                 patch.object(common, 'run', side_effect=[SimpleNamespace(stdout='/docker'), SimpleNamespace(stdout=output)]), \
                 patch.object(common.os, 'statvfs', side_effect=[disk, FileNotFoundError()]), \
                 patch.dict(common.os.environ, POSTGRES_IMAGE='fixture-image'), \
                 self.assertRaises((IndexError, ValueError)):
                common.storage_report('/state', 'fixture')
