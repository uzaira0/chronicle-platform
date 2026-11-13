#!/usr/bin/env python3
"""Dependency installs and scans run with no secrets; registry credentials exist only for the push.

- scripts/deps-sandbox.sh: a canary GHCR_TOKEN, gh token variable and SSH agent socket exported by
  the caller are absent inside the sandbox, as are the Docker socket and the caller's home; asking to
  pass a token in, or to mount the Docker socket, is refused. With --network none nothing is
  reachable; with --network registries only the allowlisted names, through the proxy, and no name
  resolves directly.
- The gate runner's security step, executed as the runner builds it (snapshot, this checkout's
  scripts/ mounted read-only, the gate image, the egress proxy) from a parent process holding every
  credential: a probe in place of local-ci.sh finds no canary in its environment or files, no Docker
  socket, no credentials directory, no direct route out and cannot write the gate scripts.
- scripts/renovate-run.sh, run with a docker and gh of the test's own: the Renovate container gets the
  token only by variable name (never on a command line or in a file) and a configuration under which
  Renovate runs no package manager (skipArtifactsUpdate, no postUpdateOptions, no allowed commands)
  and merges nothing.
- scripts/publish-images.sh --dry-run: every process the script starts before the push (the image
  inventory lookups next to each build included) runs without GHCR_TOKEN, the frontend dependency
  install and scans run through deps-sandbox.sh, the dependency age gate runs before any build, and
  `docker login` comes after every build and scan and right before the first push, with a logout
  after the last push and the cosign signatures that store beside the images.
"""
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CANARY = 'ghp_canaryCanaryCanaryCanaryCanary0000'
spec = importlib.util.spec_from_file_location('dependency_gate_runner', ROOT / 'scripts/dependency-gate-runner.py')
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner  # dataclasses look their module up here (3.12/3.13)
spec.loader.exec_module(runner)
DOCKER = bool(shutil.which('docker')) and subprocess.run(['docker', 'info'], capture_output=True,
                                                          check=False).returncode == 0


@unittest.skipUnless(DOCKER, 'needs a running Docker daemon')
class SandboxTests(unittest.TestCase):
    def run_sandbox(self, *command, extra=()):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as source:
            (Path(source) / 'marker').write_text('source tree\n')
            env = dict(os.environ, GHCR_TOKEN=CANARY, GH_TOKEN=CANARY, GITHUB_TOKEN=CANARY,
                       SSH_AUTH_SOCK='/private/var/run/canary-agent.sock')
            return subprocess.run(['bash', str(ROOT / 'scripts/deps-sandbox.sh'), *extra, source, '--', *command],
                                  capture_output=True, text=True, env=env, timeout=900, check=False)

    def test_the_sandbox_sees_the_source_and_no_secret(self):
        probe = ('cat /work/marker; env; ls -A /home/bun; test -e /var/run/docker.sock && echo DOCKER-SOCKET; '
                 'test -e /root/.docker && echo DOCKER-CONFIG; id -u; grep CapEff /proc/self/status')
        result = self.run_sandbox('sh', '-c', probe)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('source tree', result.stdout)
        for leaked in (CANARY, 'SSH_AUTH_SOCK', 'GHCR_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN', 'DOCKER-SOCKET', 'DOCKER-CONFIG'):
            self.assertNotIn(leaked, result.stdout)
        self.assertRegex(result.stdout, r'CapEff:\s+0+\n')

    def test_a_token_cannot_be_passed_in(self):
        result = self.run_sandbox('true', extra=('--env', f'GHCR_TOKEN={CANARY}'))
        self.assertEqual(2, result.returncode)
        self.assertIn('refusing to pass GHCR_TOKEN', result.stderr)

    def test_the_docker_socket_cannot_be_mounted_in(self):
        result = self.run_sandbox('true', extra=('--mount', '/var/run/docker.sock:/var/run/docker.sock'))
        self.assertEqual(2, result.returncode)
        self.assertIn('refusing to mount', result.stderr)

    def test_platform_runs_the_image_for_that_platform(self):
        """The gate's fuzz step runs as linux/amd64 (Jazzer has no linux/aarch64 library), whatever the host."""
        # A built image: docker run --platform of a pulled index digest whose other platform is already
        # stored fails on Docker Desktop ('cannot overwrite digest'); builds pull per platform.
        result = self.run_sandbox('uname', '-m', extra=('--image', 'gate', '--platform', 'linux/amd64'))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('x86_64', result.stdout.strip())
        refused = self.run_sandbox('true', extra=('--platform', 'windows/amd64'))
        self.assertEqual(2, refused.returncode)

    def test_a_base_image_runs_as_root_with_only_the_package_manager_capabilities_and_no_cache(self):
        """scripts/os-package-pins.py resolves apt pins inside each Dockerfile's own base image: root
        (apt-get update), only CHOWN, DAC_OVERRIDE, FOWNER, SETGID and SETUID (apt drops to _apt to
        download; CapEff 0xcb), and not the shared package cache the other sandbox images write."""
        base = re.search(r'^FROM (debian:13-slim@sha256:[0-9a-f]{64}) AS', (ROOT / 'selfhost/Dockerfile.fluentbit').read_text(),
                         re.MULTILINE).group(1)
        probe = 'id -u; grep CapEff /proc/self/status; test -e /cache && echo CACHE-MOUNTED; env'
        result = self.run_sandbox('sh', '-c', probe, extra=('--base-image', base))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(result.stdout.startswith('0\n'), result.stdout)
        self.assertRegex(result.stdout, r'CapEff:\s+0+cb\n')
        for leaked in (CANARY, 'CACHE-MOUNTED', '/cache', 'SSH_AUTH_SOCK', 'GHCR_TOKEN'):
            self.assertNotIn(leaked, result.stdout)

    def test_a_base_image_must_be_pinned_by_digest(self):
        result = self.run_sandbox('true', extra=('--base-image', 'debian:13-slim'))
        self.assertEqual(2, result.returncode)
        self.assertIn('--base-image takes a reference pinned by digest', result.stderr)

    def test_no_network_reaches_nothing_and_registries_reach_only_the_allowlist_through_the_proxy(self):
        # No internet needed: every probe here must fail, and the proxy's refusal is local.
        probe = ('for u in https://example.com/ https://1.1.1.1/; do '
                 'curl -fsS -o /dev/null --max-time 10 "$u" 2>/dev/null && echo "REACHED $u"; '
                 'curl --noproxy "*" -fsS -o /dev/null --max-time 10 "$u" 2>/dev/null && echo "DIRECT $u"; done; '
                 'getent hosts example.com >/dev/null && echo RESOLVED; echo done')
        for network in ('none', 'registries'):
            with self.subTest(network=network):
                result = self.run_sandbox('sh', '-c', probe, extra=('--network', network))
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual('done', result.stdout.strip())

    def test_the_proxy_refuses_unlisted_names_and_addresses(self):
        result = self.run_sandbox('sh', '-c', 'curl -sS -o /dev/null -w "%{http_code}" --max-time 20 https://example.com/; echo',
                                  extra=('--network', 'registries'))
        self.assertIn('403', result.stdout + result.stderr)


class SandboxImageBuildTests(unittest.TestCase):
    """deps-sandbox.sh with a docker of the test's own whose image build fails."""

    FAILING_DOCKER = """#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_LOG"
case "$1" in
  image) exit 1 ;;
  build) echo 'build failed: snapshot unreachable' >&2; exit 1 ;;
esac
exit 0
"""

    def test_a_failed_image_build_stops_the_sandbox_before_any_run(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            base = Path(folder)
            (base / 'docker').write_text(self.FAILING_DOCKER)
            (base / 'docker').chmod(0o755)
            (base / 'source').mkdir()
            env = dict(os.environ, PATH=f'{base}{os.pathsep}{os.environ["PATH"]}', FAKE_DOCKER_LOG=str(base / 'docker.log'))
            result = subprocess.run(['bash', str(ROOT / 'scripts/deps-sandbox.sh'), '--image', 'gate', str(base / 'source'),
                                     '--', 'true'], capture_output=True, text=True, env=env, timeout=120, check=False)
            calls = (base / 'docker.log').read_text().splitlines()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('build failed: snapshot unreachable', result.stderr)
        self.assertIn('could not build', result.stderr)
        self.assertFalse([call for call in calls if call.startswith(('run', 'network', 'create'))], calls)


@unittest.skipUnless(DOCKER, 'needs a running Docker daemon')
class GateSecurityStepCanaryTests(unittest.TestCase):
    """The runner's security step as it builds it, from a parent that holds every credential."""

    PROBE = r'''#!/usr/bin/env bash
# Stands in for local-ci.sh inside the gate sandbox: report what a dependency could reach.
security_jobs=(probe)
{
  echo "uid $(id -u)"
  env
  for path in /var/run/docker.sock /run/docker.sock /root/.docker "$HOME/.docker" "$HOME/.ssh" "$HOME/.config/gh" \
              "$HOME/.config/chronicle" /Users; do
    [ -e "$path" ] && echo "PRESENT $path"
  done
  ls -A "$HOME" | sed 's/^/HOME-ENTRY /'
  needle="__CANARY_HEAD__""__CANARY_TAIL__"  # joined here, so this file does not hold the canary itself
  grep -rIl -e "$needle" /work /home /tmp /root /etc /run /cache /opt 2>/dev/null | sed 's/^/FOUND /'
  curl --noproxy '*' -fsS -o /dev/null --max-time 10 https://1.1.1.1/ 2>/dev/null && echo DIRECT-ROUTE
  curl -fsS -o /dev/null --max-time 10 https://example.com/ 2>/dev/null && echo PROXY-ESCAPE
  [ -w /work/scripts/local-ci.sh ] && echo SCRIPTS-WRITABLE
  cat /work/marker
} > /reports/probe.txt 2>&1
'''

    def test_a_dependency_in_the_security_step_reaches_no_credential(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as directory:
            base = Path(directory)
            endpoint = runner.docker_host()
            trusted = base / 'trusted'  # a runner checkout whose local-ci.sh is the probe
            for name in ('scripts/deps-sandbox.sh', 'scripts/sandbox/Dockerfile.deps', 'scripts/sandbox/Dockerfile.gate',
                         'scripts/sandbox/Dockerfile.jdk', 'scripts/sandbox/egress-proxy.py',
                         'scripts/sandbox/egress-allowlist.txt', 'docker/Dockerfile.backend',
                         'selfhost/Dockerfile.backup', 'toolchain-manifest.yaml',
                         # the sandbox images install OS packages through these (the os-packages context)
                         'selfhost/os-packages/apk-install-aged.sh', 'selfhost/os-packages/apt-install-aged.sh',
                         'selfhost/os-packages/dnf-upgrade-aged.sh',
                         # chooses the subnets of the sandbox's two networks (--network registries)
                         'selfhost/network-subnet.py'):
                (trusted / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, trusted / name)
            (trusted / 'scripts/local-ci.sh').write_text(
                self.PROBE.replace('__CANARY_HEAD__', CANARY[:8]).replace('__CANARY_TAIL__', CANARY[8:]))
            tree = base / 'candidate'
            (tree / 'scripts').mkdir(parents=True)
            (tree / 'marker').write_text('candidate source mounted\n')
            (tree / 'scripts/local-ci.sh').write_text('echo candidate script ran > /reports/probe.txt\n')
            home = base / 'operator-home'
            for name, text in (('.config/gh/hosts.yml', f'oauth_token: {CANARY}\n'),
                               ('.docker/config.json', json.dumps({'auths': {'ghcr.io': {'auth': CANARY}}})),
                               ('.ssh/id_ed25519', CANARY), ('.config/chronicle/release-signing-key', CANARY)):
                (home / name).parent.mkdir(parents=True, exist_ok=True)
                (home / name).write_text(text)
            # A real operator's Docker configuration directory also holds the CLI plugins (buildx);
            # gate_docker_config lists them from it. Without them the sandbox images could only be
            # built by the legacy builder, which has no --build-context, so the step failed whenever
            # the images were not already cached.
            plugins = (home / '.docker/cli-plugins')
            plugins.mkdir()
            for path in runner.out(['docker', 'info', '--format', '{{range .ClientInfo.Plugins}}{{.Path}}{{"\\n"}}{{end}}'],
                                   Path.cwd(), check=False).splitlines():
                if path.strip():
                    (plugins / Path(path).name).symlink_to(Path(path).resolve())
            library = base / 'lib'
            library.mkdir()
            (library / 'robust_fetch.py').write_text('')
            work = base / 'work'
            logs = work / 'logs'
            reports = logs / 'reports'
            reports.mkdir(parents=True)
            saved = dict(os.environ)
            try:
                os.environ.update(GHCR_TOKEN=CANARY, GH_TOKEN=CANARY, GITHUB_TOKEN=CANARY, HOME=str(home),
                                  SSH_AUTH_SOCK=str(home / '.ssh/agent.sock'), DOCKER_CONFIG=str(home / '.docker'),
                                  CHRONICLE_RELEASE_SIGNING_KEY=str(home / '.config/chronicle/release-signing-key'),
                                  DOCKER_HOST=endpoint, ROBUST_FETCH_DIR=str(library))
                env = runner.host_env(work, 'b' * 40)
                command = runner.sandbox(trusted, work / 'sandbox', ['bash', 'scripts/local-ci.sh', 'probe'],
                                         'registries', {'CHRONICLE_LOCAL_CI_REPORT_DIR': '/reports'},
                                         (f'{reports}:/reports',))
                failed = runner.run_steps([runner.Step('security', [command], env)], tree, work, logs)
            finally:
                os.environ.clear()
                os.environ.update(saved)
            log = logs / 'security.log'
            self.assertEqual([], failed, log.read_text() if log.exists() else '')
            report = (reports / 'probe.txt').read_text()
        self.assertIn('candidate source mounted', report)  # the candidate is there, as data
        self.assertNotIn('candidate script ran', report)  # its own local-ci.sh is not what ran
        self.assertIn('uid 1000', report)
        self.assertNotIn(CANARY, report)
        for leak in ('PRESENT ', 'HOME-ENTRY ', 'FOUND ', 'DIRECT-ROUTE', 'PROXY-ESCAPE', 'SCRIPTS-WRITABLE',
                     'SSH_AUTH_SOCK', 'GHCR_TOKEN', 'GH_TOKEN', 'DOCKER_CONFIG', 'DOCKER_HOST'):
            self.assertNotIn(leak, report)


def keys(value) -> set[str]:
    """Every key at any depth of a JSON value."""
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in keys(v)}
    if isinstance(value, list):
        return {k for v in value for k in keys(v)}
    return set()


class RenovateRunTests(unittest.TestCase):
    FAKE_DOCKER = """#!/usr/bin/env python3
import json, os, sys
with open(os.environ['FAKE_DOCKER_LOG'], 'a') as log:
    log.write(json.dumps({'argv': sys.argv[1:], 'token_in_env': bool(os.environ.get('RENOVATE_TOKEN'))}) + '\\n')
print('INFO: Renovate finished')
"""

    def test_renovate_gets_the_token_by_name_and_runs_no_package_manager(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'docker').write_text(self.FAKE_DOCKER)
            (base / 'gh').write_text(f'#!/bin/sh\n[ "$1 $2" = "auth token" ] && echo {CANARY}\n')
            for tool in ('docker', 'gh'):
                (base / tool).chmod(0o755)
            env = dict(os.environ, PATH=f'{base}{os.pathsep}{os.environ["PATH"]}', FAKE_DOCKER_LOG=str(base / 'docker.log'),
                       CHRONICLE_RENOVATE_HOME=str(base / 'state'), CHRONICLE_RENOVATE_LOG_DIR=str(base / 'logs'))
            result = subprocess.run(['bash', str(ROOT / 'scripts/renovate-run.sh')], capture_output=True, text=True,
                                    env=env, timeout=120, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            calls = [json.loads(line) for line in (base / 'docker.log').read_text().splitlines()]
            config = json.loads((base / 'state/config.json').read_text())
            logs = ''.join(path.read_text() for path in (base / 'logs').iterdir())
        self.assertEqual(1, len(calls))
        self.assertTrue(calls[0]['token_in_env'])
        self.assertIn('RENOVATE_TOKEN', calls[0]['argv'])
        self.assertNotIn(CANARY, json.dumps(calls) + json.dumps(config) + logs + result.stdout + result.stderr)
        self.assertIs(True, config['skipArtifactsUpdate'])
        self.assertIs(False, config['automerge'])
        self.assertEqual([], config['allowedCommands'])
        self.assertEqual([], config['allowedUnsafeExecutions'])
        self.assertFalse({'postUpdateOptions', 'postUpgradeTasks'} & keys(config))
        self.assertFalse([rule for rule in config['packageRules'] if rule.get('automerge') is True])


class PublishOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env = dict(os.environ, GHCR_TOKEN=CANARY)
        result = subprocess.run(['bash', str(ROOT / 'scripts/publish-images.sh'), '2026.11.99', '--dry-run'],
                                capture_output=True, text=True, env=env, cwd=ROOT, timeout=300, check=False)
        assert result.returncode == 0, result.stderr
        cls.plan = result.stdout.splitlines()
        cls.source = (ROOT / 'scripts/publish-images.sh').read_text()

    def index(self, pattern, last=False):
        hits = [i for i, line in enumerate(self.plan) if re.search(pattern, line)]
        self.assertTrue(hits, f'no step matches {pattern}')
        return hits[-1] if last else hits[0]

    def test_login_happens_after_every_build_and_scan_and_right_before_push(self):
        login = self.index(r'docker login ghcr\.io')
        self.assertGreater(login, self.index(r'docker build', last=True))
        self.assertGreater(login, self.index(r'scan-selfhost-release-images\.sh', last=True))
        self.assertGreater(login, self.index(r'^scan_publication_source', last=True))
        self.assertEqual(login + 1, self.index(r'^docker push'))
        self.assertGreater(self.index(r'docker logout ghcr\.io'), self.index(r'^docker push', last=True))

    def test_the_age_gate_runs_before_any_build(self):
        self.assertLess(self.index(r'check-dependency-age\.py'), self.index(r'docker build'))

    def test_no_process_the_script_starts_sees_the_token(self):
        """python3 and git first on PATH record the arguments and environment of every process
        publish-images.sh starts, including the image inventory lookup it runs right before each build."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            log = base / 'environments.log'
            for tool in ('python3', 'git'):
                (base / tool).write_text(f'#!/bin/bash\n{{ printf -- "--- %s\\n" "$*"; /usr/bin/env; }} >> {shlex.quote(str(log))}\n'
                                         f'exec {shlex.quote(shutil.which(tool))} "$@"\n')
                (base / tool).chmod(0o755)
            env = dict(os.environ, GHCR_TOKEN=CANARY, PATH=f'{base}{os.pathsep}{os.environ["PATH"]}')
            result = subprocess.run(['bash', str(ROOT / 'scripts/publish-images.sh'), '2026.11.99', '--dry-run'],
                                    capture_output=True, text=True, env=env, cwd=ROOT, timeout=300, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            records = log.read_text().split('--- ')[1:]
        commands = [record.split('\n', 1)[0] for record in records]
        for component in ('backend', 'frontend', 'caddy', 'backup', 'postgres', 'grafana', 'fluentbit'):
            self.assertIn(f'- {component}', commands)  # the lookup next to that component's build ran
        for record in records:
            self.assertNotIn(CANARY, record)
            self.assertNotIn('GHCR_TOKEN=', record)
        self.assertNotIn(CANARY, '\n'.join(self.plan))

    def test_frontend_dependency_install_and_scans_run_in_the_sandbox(self):
        body = self.source.split('scan_publication_source() (', 1)[1].split('\n)\n', 1)[0]
        self.assertIn('scripts/deps-sandbox.sh', body)
        self.assertNotRegex(body, r'^\s*(CHRONICLE_[A-Z_]+=\S+\s+)*bash "\$snapshot/scripts/local-ci\.sh"', re.MULTILINE)

    def test_signing_is_unchanged(self):
        self.assertIn('run ssh-keygen -Y sign -n "$release_signer" -f "$release_signing_key" "$bundle.sha256"', self.source)
        self.assertIn("release_signing_key=${CHRONICLE_RELEASE_SIGNING_KEY:-$HOME/.config/chronicle/release-signing-key}",
                      self.source)


if __name__ == '__main__':
    unittest.main()
