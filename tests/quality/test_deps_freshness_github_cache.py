#!/usr/bin/env python3
"""scripts/deps-freshness.sh --fetch-github: the dependency gate's sandbox has no gh login, so the runner
fetches the GitHub release lookups with this checkout's script and the sandbox reads them from a directory.

Every GitHub lookup the report makes must come from that directory (gh is never called), and the fetch
must cover every lookup the report makes."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/deps-freshness.sh'

# A stand-in gh: `gh api PATH` answers like the GitHub API and logs PATH; FlywayDB has no releases.
FAKE_GH = '''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ['GH_LOG'], 'a') as log:
    log.write(' '.join(args) + '\\n')
if os.environ.get('GH_FORBIDDEN'):
    sys.exit(99)
path = args[1]
if path.endswith('/releases/latest'):
    if 'flyway/flyway' in path:
        print('{"message": "Not Found"}'); sys.exit(1)
    tag = 'jdk-25.0.9+10' if 'temurin25' in path else 'v77.1.0'
    print(json.dumps({'tag_name': tag}))
elif '/tags' in path:
    names = ['v3.15.2', 'v3.14.9'] if 'cpython' in path else ['v77.0.1', 'v76.9.9']
    print(json.dumps([{'name': name} for name in names]))
else:
    sys.exit(2)
'''
FAKE_CURL = '#!/bin/sh\nexit 7\n'


class GithubCacheTests(unittest.TestCase):
    def run_script(self, bin_dir: Path, *args: str, **env: str) -> subprocess.CompletedProcess:
        return subprocess.run(['bash', str(SCRIPT), *args], capture_output=True, text=True, timeout=120, check=False,
                              env=dict(os.environ, PATH=f'{bin_dir}{os.pathsep}{os.environ["PATH"]}', **env))

    def test_the_report_reads_every_github_lookup_from_the_fetched_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bin_dir = base / 'bin'
            bin_dir.mkdir()
            for name, text in (('gh', FAKE_GH), ('curl', FAKE_CURL)):
                (bin_dir / name).write_text(text)
                (bin_dir / name).chmod(0o755)
            cache = base / 'github-api'
            cache.mkdir()
            fetched_log = base / 'fetch.log'
            fetch = self.run_script(bin_dir, '--fetch-github', str(cache), GH_LOG=str(fetched_log))
            self.assertEqual(0, fetch.returncode, fetch.stderr)
            fetched = {line.split()[1] for line in fetched_log.read_text().splitlines()}
            self.assertTrue(any(name.endswith('.json') for name in os.listdir(cache)))

            report_log = base / 'report.log'
            report = self.run_script(bin_dir, '--json', GH_LOG=str(report_log), GH_FORBIDDEN='1',
                                     CHRONICLE_GITHUB_API_CACHE=str(cache))
            self.assertFalse(report_log.exists(), 'the report called gh although the lookups were fetched')
            rows = {row['name']: row for row in json.JSONDecoder().raw_decode(report.stdout)[0]}
            self.assertEqual('v77.1.0', rows['kotlin']['latest'])
            self.assertEqual('v77.0.1', rows['flyway']['latest'])  # no release: the newest matching tag
            self.assertEqual('25', rows['jdk']['latest'])
            self.assertEqual('v77.1.0', rows['victoria-logs']['latest'])
            self.assertEqual('v3.15.2', rows['python']['latest'])

            # Without the directory the report asks gh for exactly what --fetch-github fetched.
            direct_log = base / 'direct.log'
            self.run_script(bin_dir, '--json', GH_LOG=str(direct_log))
            asked = {line.split()[1] for line in direct_log.read_text().splitlines()}
            self.assertLessEqual(asked, fetched)

    def test_a_missing_lookup_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bin_dir = base / 'bin'
            bin_dir.mkdir()
            for name, text in (('gh', FAKE_GH), ('curl', FAKE_CURL)):
                (bin_dir / name).write_text(text)
                (bin_dir / name).chmod(0o755)
            empty = base / 'empty'
            empty.mkdir()
            report = self.run_script(bin_dir, '--json', GH_LOG=str(base / 'log'), GH_FORBIDDEN='1',
                                     CHRONICLE_GITHUB_API_CACHE=str(empty))
            self.assertNotEqual(0, report.returncode)
            rows = {row['name']: row for row in json.JSONDecoder().raw_decode(report.stdout)[0]}
            self.assertEqual('unknown', rows['kotlin']['status'])


if __name__ == '__main__':
    unittest.main()
