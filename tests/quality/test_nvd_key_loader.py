#!/usr/bin/env python3
"""The NVD key loader never opens a passphrase prompt.

scripts/chronicle-load-nvd-api-key.sh falls back to `pass show` when the Keychain has no key; `pass`
runs `gpg --decrypt`, and on 2026-11-06 a gradle-depcheck run from an agent session opened a
pinentry-mac dialog on the user's screen that way. Every `pass` call now carries
PASSWORD_STORE_GPG_OPTS with --batch and --pinentry-mode error, so gpg uses a cached passphrase or
fails; it never prompts, with or without a TTY.

The fakes on PATH stand in for macOS `security` (no Keychain item), `pass` (calls gpg as pass does,
with $PASSWORD_STORE_GPG_OPTS) and `gpg` (records its arguments and refuses to decrypt unless it was
told never to prompt).
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
LOADER = ROOT / 'scripts/chronicle-load-nvd-api-key.sh'
FAKES = {
    'security': '#!/bin/sh\nexit 44\n',
    'pass': '#!/bin/sh\n# pass show NAME -> gpg -d ... $PASSWORD_STORE_GPG_OPTS FILE\n'
            'exec gpg -d --quiet --yes --compress-algo=none --no-encrypt-to $PASSWORD_STORE_GPG_OPTS "$HOME/$2.gpg"\n',
    'gpg': '#!/bin/sh\nprintf "%s\\n" "$*" >> "$FAKE_GPG_LOG"\n'
           'for needed in " --batch " " --pinentry-mode error "; do\n'
           '  case " $* " in *"$needed"*) ;; *) echo "fake gpg: this call would open pinentry" >&2; exit 2 ;; esac\n'
           'done\n'
           'echo placeholder-not-a-key\n',
}


class NvdKeyLoaderTests(unittest.TestCase):
    def run_loader(self, **extra):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            bin_dir = work / 'bin'
            bin_dir.mkdir()
            for name, text in FAKES.items():
                (bin_dir / name).write_text(text)
                (bin_dir / name).chmod(0o755)
            log = work / 'gpg.log'
            env = {k: v for k, v in os.environ.items()
                   if k not in ('NVD_API_KEY', 'CHRONICLE_NVD_API_KEY_FILE', 'PASSWORD_STORE_GPG_OPTS', 'CI')}
            env.update(PATH=f'{bin_dir}:{env["PATH"]}', HOME=str(work), FAKE_GPG_LOG=str(log), **extra)
            result = subprocess.run(['bash', str(LOADER)], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                    timeout=60, check=False, env=env)
            return result, log.read_text() if log.exists() else ''

    def test_pass_never_lets_gpg_prompt_without_a_tty(self):
        result, calls = self.run_loader()
        self.assertTrue(calls, 'the pass fallback did not run')
        for line in calls.splitlines():
            self.assertIn('--batch', line.split())
            self.assertIn('--pinentry-mode error', line)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('NVD_API_KEY=present\n', result.stdout)
        self.assertNotIn('placeholder-not-a-key', result.stdout + result.stderr)

    def test_ci_runs_never_let_gpg_prompt(self):
        result, calls = self.run_loader(CI='1')
        self.assertTrue(calls, 'the pass fallback did not run')
        self.assertTrue(all('--pinentry-mode error' in line for line in calls.splitlines()), calls)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_existing_gpg_options_are_kept(self):
        _result, calls = self.run_loader(PASSWORD_STORE_GPG_OPTS='--trust-model always')
        self.assertIn('--trust-model always', calls)
        self.assertIn('--pinentry-mode error', calls)


if __name__ == '__main__':
    unittest.main()
