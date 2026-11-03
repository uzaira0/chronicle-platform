#!/usr/bin/env python3
"""scripts/publish.sh push must refuse when gitleaks leaves no readable report."""

import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

GITLEAKS_STUB = textwrap.dedent('''\
    #!/usr/bin/env bash
    # Writes the fixture for this scan to --report-path ("none" writes nothing): the commit-range
    # scan (--log-opts) gets $FIXTURE_COMMIT_REPORT, the filtered-tree scan $FIXTURE_TREE_REPORT.
    fixture="$FIXTURE_TREE_REPORT"
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == --report-path ]]; then report="$2"; fi
      if [[ "$1" == --log-opts=* ]]; then fixture="$FIXTURE_COMMIT_REPORT"; fi
      shift
    done
    [[ "$fixture" == none ]] || printf '%s' "$fixture" > "$report"
''')


class PublishGitleaksGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        repo, bin_dir = self.tmp / 'repo', self.tmp / 'bin'
        (repo / 'scripts').mkdir(parents=True)
        bin_dir.mkdir()
        for name in ('publish.sh', 'check-commit-msg.sh'):
            shutil.copy2(ROOT / 'scripts' / name, repo / 'scripts' / name)
        (repo / '.gitmodules').write_text('')
        (bin_dir / 'gitleaks').write_text(GITLEAKS_STUB)
        (bin_dir / 'gh').write_text('#!/usr/bin/env bash\necho main\n')
        for stub in bin_dir.iterdir():
            stub.chmod(0o755)
        self.env = {**os.environ, 'PATH': f'{bin_dir}:{os.environ["PATH"]}', 'GIT_TERMINAL_PROMPT': '0',
                    'CHRONICLE_PUBLISH_WORK': str(self.tmp / 'work'), 'GIT_CONFIG_GLOBAL': '/dev/null',
                    'GIT_AUTHOR_NAME': 'Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                    'GIT_COMMITTER_NAME': 'Fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}
        git = lambda *args: subprocess.run(['git', '-C', str(repo), *args], env=self.env, check=True,
                                           capture_output=True)
        git('init', '-q', '-b', 'main')
        git('add', '.')
        git('commit', '-q', '-m', 'chore: seed fixture')
        git('remote', 'add', 'public', f'file://{self.tmp}/absent/github.com/example/fixture.git')
        git('worktree', 'add', '-q', '-b', 'curate', str(self.tmp / 'work' / 'root'), 'HEAD')
        self.repo = repo

    def push(self, tree='[]', commits='[]'):
        return subprocess.run(['bash', str(self.repo / 'scripts/publish.sh'), 'push', 'root', '--dry-run'],
                              env={**self.env, 'FIXTURE_TREE_REPORT': tree, 'FIXTURE_COMMIT_REPORT': commits},
                              capture_output=True, text=True)

    def test_clean_reports_pass(self):
        result = self.push()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('would push 1 commit(s)', result.stderr)

    def test_unreadable_or_dirty_report_fails_in_each_scan(self):
        for scope, findings in (('tree', 'gitleaks findings outside .publishallow: leak.txt'),
                                ('commits', 'gitleaks findings in the new commits outside .publishallow: leak.txt')):
            for report, message in (('none', 'gitleaks wrote no readable report'),
                                    ('{"truncated":', 'gitleaks wrote no readable report'),
                                    ('[{"File": "leak.txt"}]', findings)):
                with self.subTest(scope=scope, report=report):
                    result = self.push(**{scope: report})
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertIn(message, result.stderr)


if __name__ == '__main__':
    unittest.main()
