"""The Kotlin compile daemon's .kotlin/ state never reaches a commit in any Kotlin repository.

The daemon writes `.kotlin/sessions/*.salive` into the root of every Gradle build it compiles,
on every build. chronicle-models did not ignore `.kotlin/`, so `git add -A` committed one
(640a863, untracked again in 6d15a5c). Each Kotlin repository must ignore the directory, track
nothing under it, and refuse a force-added path in its own pre-commit hook (a submodule commit
never runs the root repository's hooks).
"""
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
KOTLIN_REPOS = ('.', 'chronicle', 'chronicle-server', 'chronicle-api', 'chronicle-models', 'rhizome', 'rhizome-client')
PROBE = '.kotlin/sessions/kotlin-compiler-probe.salive'


def git(repo, *args):
    return subprocess.run(['git', '-C', str(ROOT / repo), *args], capture_output=True, text=True, check=False)


class KotlinDaemonStateTests(unittest.TestCase):
    def test_every_kotlin_repository_is_the_full_list(self):
        # A new Kotlin submodule must be added to KOTLIN_REPOS, or this class stops covering it.
        modules = git('.', 'config', '--file', '.gitmodules', '--get-regexp', r'submodule\..*\.path').stdout.split()[1::2]
        kotlin = {m for m in modules if (ROOT / m / 'build.gradle').exists() or (ROOT / m / 'build.gradle.kts').exists()}
        self.assertEqual(kotlin, set(KOTLIN_REPOS) - {'.'})

    def test_daemon_state_is_ignored(self):
        for repo in KOTLIN_REPOS:
            with self.subTest(repo=repo):
                self.assertEqual(0, git(repo, 'check-ignore', '-q', PROBE).returncode,
                                 f'{repo}/.gitignore must ignore .kotlin/')

    def test_no_daemon_state_is_tracked(self):
        for repo in KOTLIN_REPOS:
            with self.subTest(repo=repo):
                self.assertEqual('', git(repo, 'ls-files', '--', '.kotlin').stdout)

    def test_pre_commit_refuses_a_force_added_path(self):
        for repo in KOTLIN_REPOS:
            with self.subTest(repo=repo):
                hooks = yaml.safe_load((ROOT / repo / 'lefthook.yml').read_text())
                command = hooks['pre-commit']['commands'].get('kotlin-daemon-state')
                self.assertIsNotNone(command, f'{repo}/lefthook.yml has no kotlin-daemon-state pre-commit command')
                self.assertEqual('.kotlin/**', command['glob'])
                self.assertNotIn('tags', command, 'an optional tag would skip the refusal')
                # lefthook runs the command through sh with the staged paths substituted.
                run = command['run'].replace('{staged_files}', PROBE)
                refused = subprocess.run(['sh', '-c', run], capture_output=True, text=True, check=False)
                self.assertNotEqual(0, refused.returncode)
                self.assertIn(PROBE, refused.stderr)


if __name__ == '__main__':
    unittest.main()
