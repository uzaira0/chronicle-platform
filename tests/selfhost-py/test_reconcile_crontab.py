"""The operator crontab edit leaves cronie a place for its backup of the previous crontab.

cronie 1.7 (Alpine, Fedora) saves the previous crontab to $XDG_CACHE_HOME/crontab/crontab.bak,
default ~/.cache/crontab, creating only the last directory. An operator account made with
`adduser` has no ~/.cache, so every rewrite printed
`$HOME/.cache/crontab: mkdir: No such file or directory` (the operator's home) and kept no backup. The fake
crontab here does what cronie does.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from chronicle_ops import reconcile

CRONIE = '''#!/bin/sh
# cronie's crontab, reduced to its backup step: one mkdir of the backup directory, not recursive.
table="$CRONTAB_FIXTURE"
if [ "$1" = -l ]; then
  [ -f "$table" ] || { echo "no crontab for $(id -un)" >&2; exit 1; }
  cat "$table"; exit 0
fi
if [ -f "$table" ]; then
  backup="${XDG_CACHE_HOME:-$HOME/.cache}/crontab"
  if [ ! -d "$backup" ] && ! mkdir "$backup" 2>/dev/null; then
    echo "$backup: mkdir: No such file or directory" >&2
  else
    cp "$table" "$backup/crontab.bak"
    echo "Backup of $(id -un)'s previous crontab saved to $backup/crontab.bak"
  fi
fi
cat >"$table"
'''


class CrontabBackupTests(unittest.TestCase):
    def setUp(self):
        folder = Path(tempfile.mkdtemp(prefix='crontab-'))
        self.addCleanup(subprocess.run, ['chmod', '-R', 'u+w', str(folder)], check=False)
        self.home, self.bin = folder / 'home', folder / 'bin'
        self.home.mkdir()
        self.bin.mkdir()
        (self.bin / 'crontab').write_text(CRONIE)
        (self.bin / 'crontab').chmod(0o755)
        self.table = folder / 'table'
        self.table.write_text('# an earlier schedule\n')
        environment = {key: value for key, value in os.environ.items() if key != 'XDG_CACHE_HOME'}
        environment.update(HOME=str(self.home), CRONTAB_FIXTURE=str(self.table),
                           PATH=str(self.bin) + os.pathsep + os.environ['PATH'])
        patcher = patch.dict(os.environ, environment, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self):
        result = subprocess.run(['python3', '-s', '-c', 'from chronicle_ops.reconcile import write_crontab; '
                                 'write_crontab(["# chronicle"])'], capture_output=True, text=True, timeout=30,
                                env=dict(os.environ, PYTHONPATH=str(Path(reconcile.__file__).resolve().parents[1])))
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout + result.stderr

    def test_a_rewrite_on_an_account_without_a_cache_directory_keeps_cronies_backup(self):
        self.assertEqual('', self.write())
        self.assertEqual('# chronicle\n', self.table.read_text())
        self.assertEqual('# an earlier schedule\n', (self.home / '.cache/crontab/crontab.bak').read_text())
        self.assertEqual(0o700, (self.home / '.cache').stat().st_mode & 0o777)

    def test_an_xdg_cache_home_is_the_directory_prepared(self):
        cache = self.home / 'elsewhere'
        os.environ['XDG_CACHE_HOME'] = str(cache)
        self.assertEqual('', self.write())
        self.assertTrue((cache / 'crontab/crontab.bak').is_file())
        self.assertFalse((self.home / '.cache').exists())

    def test_a_failed_write_still_names_crontabs_own_message(self):
        (self.bin / 'crontab').write_text('#!/bin/sh\ncat >/dev/null\necho "crontab: permission denied" >&2\nexit 1\n')
        with self.assertRaisesRegex(ValueError, 'permission denied'):
            reconcile.write_crontab(['# chronicle'])


if __name__ == '__main__':
    unittest.main()
