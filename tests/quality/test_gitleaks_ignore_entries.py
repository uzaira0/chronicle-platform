"""Every root gitleaks ignore fingerprint names a commit this repository has.

The root ignore file (tests/security/gitleaks-ignore/chronicle-platform-root.gitleaksignore, named
methodic-root.gitleaksignore until the repository was renamed) held 13 fingerprints for commits that were gone
from the repository and from GitHub after a history rewrite (launch audit AF-T6, 2026-11-06). An exact
fingerprint for a commit that cannot be scanned admits nothing today, but it is unreviewable: nobody can read
what it hid. A full clone fails this test on such an entry; a shallow clone cannot tell, so it skips.

This test once read the file's old name while the secrets job (job_gitleaks in scripts/local-ci.sh) read
the new one. GitleaksIgnoreFileNameTests holds the name here equal to the name that job and the two
security scripts give the root's file. The job scans with no ignore entries when the file is absent, and
the public mirror does not carry the ignore directory: a checkout without the directory skips the test of
the file, a checkout that has the directory and lacks the root's file fails it.
"""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IGNORE_DIR = ROOT / 'tests/security/gitleaks-ignore'
IGNORE = IGNORE_DIR / 'chronicle-platform-root.gitleaksignore'
ROOT_NAME = IGNORE.name.removesuffix('.gitleaksignore')
# The secrets job derives each repository's file from a name; the root's is set on this line.
JOB_ROOT_NAME = re.compile(r'\[\[ "\$repo" == "\." \]\] && name="([^"]+)"')
JOB_IGNORE_PATH = 'ignore="$ROOT_DIR/tests/security/gitleaks-ignore/$name.gitleaksignore"'
# These name the root's file outright.
LITERAL_READERS = ('tests/security/gitleaks-history-regression.sh', 'tests/security/run-all-security.sh')
LITERAL_ROOT_FILE = re.compile(r'gitleaks-ignore/([A-Za-z0-9-]+-root)\.gitleaksignore')


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(['git', '-C', str(ROOT), *args], capture_output=True, text=True, check=False)


def entries(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]


def missing_commits(lines: list[str]) -> list[str]:
    return [line for line in lines if git('cat-file', '-e', line.split(':', 1)[0] + '^{commit}').returncode != 0]


class GitleaksIgnoreEntryTests(unittest.TestCase):
    def setUp(self):
        if git('rev-parse', '--is-shallow-repository').stdout.strip() != 'false':
            self.skipTest('shallow clone: absent commits cannot be told apart from unfetched ones')

    def test_every_root_entry_names_a_commit_in_this_repository(self):
        if not IGNORE_DIR.is_dir():
            self.skipTest('this checkout has no tests/security/gitleaks-ignore; the secrets job scans it with '
                          'no ignore entries')
        self.assertEqual([], missing_commits(entries(IGNORE.read_text())))

    def test_an_entry_for_a_missing_commit_is_caught(self):
        absent = '13f9a203e92e1c34b2f124ba20e7b3b6b184f4d5:docker/x.yml:generic-api-key:13'
        present = git('rev-parse', 'HEAD').stdout.strip() + ':README.md:generic-api-key:1'
        self.assertEqual([absent], missing_commits(entries(f'# note\n{present}\n{absent}\n')))


class GitleaksIgnoreFileNameTests(unittest.TestCase):
    def test_the_file_checked_is_the_one_the_secrets_job_reads(self):
        job = (ROOT / 'scripts/local-ci.sh').read_text()
        self.assertEqual([ROOT_NAME], JOB_ROOT_NAME.findall(job))
        self.assertIn(JOB_IGNORE_PATH, job)

    def test_the_security_scripts_name_the_same_file(self):
        for reader in LITERAL_READERS:
            with self.subTest(reader=reader):
                self.assertEqual([ROOT_NAME], sorted(set(LITERAL_ROOT_FILE.findall((ROOT / reader).read_text()))))


if __name__ == '__main__':
    unittest.main()
