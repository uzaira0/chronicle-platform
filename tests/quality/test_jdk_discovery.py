#!/usr/bin/env python3
"""The gate finds the manifest's JDK where Homebrew installs it, not only where JAVA_HOME points.

On a Mac, Homebrew JDKs (/opt/homebrew/opt/openjdk@25) are not registered with /usr/libexec/java_home
and /usr/bin/java may be older. With JAVA_HOME unset, scripts/local-ci.sh require_jdk21 and
scripts/verify-toolchain.sh must still find the manifest's JDK; both resolve the same list.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FAKE_JAVA = '#!/bin/sh\necho \'openjdk version "{version}" 2026-10-21\' >&2\n'


def fake_jdk(home: Path, version: str) -> Path:
    (home / 'bin').mkdir(parents=True)
    java = home / 'bin/java'
    java.write_text(FAKE_JAVA.format(version=version))
    java.chmod(0o755)
    return home


class JdkDiscoveryTests(unittest.TestCase):
    def environment(self, work: Path) -> dict:
        prefix = work / 'homebrew'
        fake_jdk(prefix / 'opt/openjdk@25/libexec/openjdk.jdk/Contents/Home', '25.0.5')
        old = fake_jdk(work / 'jdk17', '17.0.17')
        env = {k: v for k, v in os.environ.items() if k != 'JAVA_HOME'}
        env.update(HOME=str(work / 'home'), HOMEBREW_PREFIX=str(prefix), PATH=f'{old / "bin"}:{env["PATH"]}')
        return env

    def test_local_ci_require_jdk21_uses_the_homebrew_jdk(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            result = subprocess.run(['bash', '-s', str(ROOT / 'scripts/local-ci.sh')],
                                    input='source "$1"\nrequire_jdk21\nprintf "%s" "$JAVA_HOME"\n',
                                    capture_output=True, text=True, timeout=60, check=False, env=self.environment(work))
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(str(work / 'homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home'), result.stdout)

    def test_verify_toolchain_checks_the_homebrew_jdk(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            result = subprocess.run(['bash', str(ROOT / 'scripts/verify-toolchain.sh')], capture_output=True, text=True,
                                    timeout=300, check=False, env=self.environment(work))
            self.assertIn('[ok] active JDK -> 25 (' + str(work / 'homebrew'), result.stdout)


if __name__ == '__main__':
    unittest.main()
