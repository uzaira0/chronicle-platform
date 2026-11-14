#!/usr/bin/env python3
"""scripts/deps-regenerate.py: a bump of a source pin reaches every derived pin, and a second run is a no-op.

Works on copies of this checkout's real files (toolchain-manifest.yaml, chronicle-web/package.json, the
pgTAP Dockerfile, the contract test schema, the Gradle wrapper), so a moved or reformatted pin fails
here before it fails the gate runner. The steps that run Bun, Gradle or Go in the sandbox are
exercised by the gate runner's live run; what comes back from them (take_back) is tested here.
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
spec = importlib.util.spec_from_file_location('deps_regenerate', ROOT / 'scripts/deps-regenerate.py')
regen = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = regen  # deps-regenerate.py defines a dataclass, which looks its module up here
spec.loader.exec_module(regen)

FILES = (
    'toolchain-manifest.yaml',
    'tests/security/supply-chain-guardrails.sh',
    'chronicle-web/package.json',
    'chronicle-server/src/test/docker/pgtap/Dockerfile',
    'chronicle-server/src/test/kotlin/com/openlattice/chronicle/contract/ChronicleContractTestSchema.kt',
    'gradle/wrapper/gradle-wrapper.properties',
    'gradle/wrapper/gradle-wrapper.jar',
)
NEW_DIGEST = 'sha256:' + 'b' * 64


class RegenerateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        for name in FILES:
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, self.root / name)

    def tearDown(self):
        self.directory.cleanup()

    def edit(self, name: str, pattern: str, replacement: str) -> None:
        path = self.root / name
        text = path.read_text()
        updated = re.sub(pattern, replacement, text, count=1, flags=re.MULTILINE)
        self.assertNotEqual(updated, text, f'{pattern} not found in {name}')
        path.write_text(updated)

    def test_checkout_is_already_in_sync(self):
        changed = []
        regen.sync_bun(self.root, changed)
        regen.sync_postgres(self.root, changed)
        self.assertEqual(changed, [])

    def test_bun_bump_reaches_engines_and_types(self):
        self.edit('toolchain-manifest.yaml', r'^bun: "[^"]+"', 'bun: "9.9.9"')
        changed = []
        regen.sync_bun(self.root, changed)
        # The guardrail script reads the manifest itself: no derived copy to rewrite (one source).
        self.assertEqual(changed, ['chronicle-web/package.json'])
        package = json.loads((self.root / 'chronicle-web/package.json').read_text())
        self.assertEqual(package['engines']['bun'], '9.9.9')
        self.assertEqual(package['devDependencies']['bun-types'], '9.9.9')
        self.assertNotIn('bun', package['devDependencies'])
        guardrails = (ROOT / 'tests/security/supply-chain-guardrails.sh').read_text()
        self.assertNotRegex(guardrails, r'(?m)^BUN_VERSION="[0-9]')
        again = []
        regen.sync_bun(self.root, again)
        self.assertEqual(again, [])

    def test_postgres_bump_reaches_pgtap_and_contract_schema(self):
        self.edit('toolchain-manifest.yaml', r'^  image: "percona/percona-distribution-postgresql:[^"]+"',
                  '  image: "percona/percona-distribution-postgresql:18.7.1-1"')
        self.edit('toolchain-manifest.yaml', r'^  index_digest: "sha256:[0-9a-f]{64}"', f'  index_digest: "{NEW_DIGEST}"')
        changed = []
        regen.sync_postgres(self.root, changed)
        self.assertEqual(len(changed), 2)
        pgtap = (self.root / FILES[3]).read_text()
        self.assertIn(f'ARG PROD_POSTGRES_IMAGE=percona/percona-distribution-postgresql:18.7.1-1@{NEW_DIGEST}', pgtap)
        schema = (self.root / FILES[4]).read_text()
        self.assertIn(f'PROD_POSTGRES_IMAGE = "percona/percona-distribution-postgresql@{NEW_DIGEST}"', schema)

    def test_root_wrapper_is_copied_to_every_jvm_submodule(self):
        for module in regen.JVM_SUBMODULES:
            target = self.root / module / 'gradle/wrapper'
            target.mkdir(parents=True)
            (target / 'gradle-wrapper.properties').write_text('distributionUrl=old\n')
            (target / 'gradle-wrapper.jar').write_bytes(b'old')
        changed = []
        regen.sync_wrapper(self.root, changed)
        self.assertEqual(len(changed), 2 * len(regen.JVM_SUBMODULES))
        for module in regen.JVM_SUBMODULES:
            for name in ('gradle-wrapper.properties', 'gradle-wrapper.jar'):
                self.assertEqual((self.root / module / 'gradle/wrapper' / name).read_bytes(),
                                 (self.root / 'gradle/wrapper' / name).read_bytes())

    def test_gradle_inputs(self):
        for path in ('gradle/wrapper/gradle-wrapper.properties', 'gradles/libs.versions.toml', 'build.gradle.kts',
                     'chronicle-server', 'chronicle-server/gradle.lockfile', 'rhizome-client/build.gradle'):
            self.assertTrue(regen.GRADLE_INPUTS.match(path), path)
        for path in ('chronicle-web/bun.lock', 'selfhost/Dockerfile.caddy', 'chronicle/app/build.gradle.kts'):
            self.assertFalse(regen.GRADLE_INPUTS.match(path), path)


class TakeBackTests(unittest.TestCase):
    """Only the declared outputs of a sandbox step come back, and only as regular files."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        base = Path(self.directory.name)
        self.tree, self.copy = base / 'tree', base / 'copy'
        for directory in (self.tree, self.copy):
            (directory / 'web').mkdir(parents=True)
            (directory / 'web/bun.lock').write_text('old\n')
            (directory / 'scripts').mkdir()
            (directory / 'scripts/gate.py').write_text('gate\n')
        self.secret = base / 'operator-secret'
        self.secret.write_text('ghp_canary\n')

    def tearDown(self):
        self.directory.cleanup()

    def test_a_declared_output_comes_back_and_nothing_else_does(self):
        (self.copy / 'web/bun.lock').write_text('new\n')
        (self.copy / 'scripts/gate.py').write_text('raise SystemExit(0)\n')  # dependency code rewrote a gate
        changed = []
        self.assertTrue(regen.take_back(self.copy / 'web', self.tree / 'web', ('bun.lock',), changed, self.tree))
        self.assertEqual(['web/bun.lock'], changed)
        self.assertEqual('new\n', (self.tree / 'web/bun.lock').read_text())
        self.assertEqual('gate\n', (self.tree / 'scripts/gate.py').read_text())

    def test_a_symlink_output_is_refused_so_no_host_file_is_read_into_the_tree(self):
        (self.copy / 'web/bun.lock').unlink()
        (self.copy / 'web/bun.lock').symlink_to(self.secret)
        changed = []
        self.assertFalse(regen.take_back(self.copy / 'web', self.tree / 'web', ('bun.lock',), changed, self.tree))
        self.assertEqual([], changed)
        self.assertEqual('old\n', (self.tree / 'web/bun.lock').read_text())

    def test_a_symlinked_directory_on_the_way_is_refused(self):
        (self.copy / 'gradle').symlink_to(self.secret.parent)
        changed = []
        self.assertFalse(regen.take_back(self.copy, self.tree, ('gradle/operator-secret',), changed, self.tree))
        self.assertEqual([], changed)
        self.assertFalse((self.tree / 'gradle').exists())

    def test_the_sandbox_script_is_this_scripts_own(self):
        self.assertEqual(Path(regen.__file__).resolve().parent / 'deps-sandbox.sh', regen.SANDBOX)
        self.assertTrue(os.path.isfile(regen.SANDBOX))


class GoReplacementTests(unittest.TestCase):
    """2026-11-13: selfhost/caddy/module/go.mod replaces go-jose v3 with /go-jose-v3, a directory that only
    selfhost/Dockerfile.caddy's build makes. `go mod tidy` in the sandbox stopped at "reading /go-jose-v3/go.mod:
    no such file or directory", so no version in that go.mod could be raised through this script (met raising
    OpenTelemetry for GHSA-q7gw-24fr-5p69). The Go step gives the sandbox each such directory, made the way the
    image build makes it."""

    def test_every_absolute_replacement_in_a_go_module_has_a_source(self):
        found = 0
        for module in regen.GO_MODULES:
            for replaced, directory in regen.ABSOLUTE_REPLACE.findall((ROOT / module / 'go.mod').read_text()):
                found += 1
                self.assertIn((module, directory), regen.GO_REPLACEMENTS,
                              f'{module}/go.mod replaces {replaced} with {directory}; go mod tidy cannot run without it')
                source = regen.GO_REPLACEMENTS[(module, directory)]
                self.assertEqual(replaced, source.module)
                dockerfile = (ROOT / source.dockerfile).read_text()
                self.assertRegex(dockerfile, rf'(?m)^ARG {source.version_arg}=v[0-9]')
                self.assertIn(f'{source.module}@${{{source.version_arg}}}', dockerfile)
                self.assertIn(Path(source.patch).name, dockerfile)
                self.assertTrue((ROOT / source.patch).is_file())
        self.assertGreaterEqual(found, 1, 'selfhost/caddy/module/go.mod no longer replaces go-jose v3: drop GO_REPLACEMENTS')

    def test_tidy_runs_with_the_replacement_directory_made_from_the_dockerfiles_version_and_patch(self):
        prepared, tidied = [], []

        def run_sandbox(source, command, image, network, mounts=()):
            prepared.append((Path(source), command, image, network))
            self.assertEqual((Path(source) / 'replacement.patch').read_bytes(),
                             (ROOT / 'selfhost/caddy/go-jose-v3-rsa-bounds.patch').read_bytes())
            (Path(source) / 'tree').mkdir()
            (Path(source) / 'tree/go.mod').write_text('module github.com/go-jose/go-jose/v3\n')
            return True

        saved = regen.run_sandbox, regen.sandbox, regen.changed_against
        regen.run_sandbox = run_sandbox
        regen.sandbox = lambda root, scratch, subdir, command, outputs, changed, **kw: tidied.append((subdir, command, kw)) or True
        regen.changed_against = lambda root, base, pattern: True
        try:
            with tempfile.TemporaryDirectory() as scratch:
                self.assertTrue(regen.tidy_go(ROOT, Path(scratch), 'HEAD', []))
                (source, command, image, network), = prepared
                version = re.search(r'(?m)^ARG GO_JOSE_V3_VERSION=(\S+)$', (ROOT / 'selfhost/Dockerfile.caddy').read_text()).group(1)
                self.assertEqual(f'github.com/go-jose/go-jose/v3@{version}', command[-1])
                self.assertEqual(('go', 'gomodules'), (image, network))
                by_module = {subdir: (command, kw) for subdir, command, kw in tidied}
                self.assertEqual(set(regen.GO_MODULES), set(by_module))
                command, kw = by_module['selfhost/caddy/module']
                self.assertEqual(['go', 'mod', 'tidy'], command)
                self.assertEqual((f'{source}/tree:/go-jose-v3:ro',), tuple(kw.get('mounts', ())))
                self.assertEqual(('go', 'gomodules'), (kw.get('image'), kw.get('network')))
                self.assertFalse(by_module['selfhost/backup-image/go-cron'][1].get('mounts'))
        finally:
            regen.run_sandbox, regen.sandbox, regen.changed_against = saved

    def test_a_replacement_that_could_not_be_made_fails_the_step_before_tidy(self):
        tidied = []
        saved = regen.run_sandbox, regen.sandbox, regen.changed_against
        regen.run_sandbox = lambda source, command, image, network, mounts=(): False
        regen.sandbox = lambda root, scratch, subdir, command, outputs, changed, **kw: tidied.append(subdir) or True
        regen.changed_against = lambda root, base, pattern: True
        try:
            with tempfile.TemporaryDirectory() as scratch:
                self.assertFalse(regen.tidy_go(ROOT, Path(scratch), 'HEAD', []))
        finally:
            regen.run_sandbox, regen.sandbox, regen.changed_against = saved
        self.assertNotIn('selfhost/caddy/module', tidied)

    def test_only_the_go_step_asks_for_the_go_module_network(self):
        """storage.googleapis.com is every public bucket; the one caller of that network is the Go step, which
        runs `go mod tidy` and a module download, never module code."""
        users = sorted(path.relative_to(ROOT).as_posix()
                       for pattern in ('scripts/*.py', 'scripts/*.sh', 'scripts/sandbox/*', 'selfhost/*.sh', 'selfhost/*.py')
                       for path in ROOT.glob(pattern)
                       if path.is_file() and b'gomodules' in path.read_bytes())
        # The browsers list only names the other list in its comment.
        self.assertEqual(['scripts/deps-regenerate.py', 'scripts/deps-sandbox.sh',
                          'scripts/sandbox/egress-allowlist-browsers.txt',
                          'scripts/sandbox/egress-allowlist-gomodules.txt'], users)
        source = (ROOT / 'scripts/deps-regenerate.py').read_text()
        self.assertEqual(2, source.count("network='gomodules'"), 'the replacement download and go mod tidy')

    def test_the_sandbox_command_carries_each_mount(self):
        args = regen.sandbox_command(Path('/x/copy'), ['go', 'mod', 'tidy'], 'go', 'registries', ('/x/tree:/go-jose-v3:ro',))
        self.assertEqual(['--mount', '/x/tree:/go-jose-v3:ro'], args[args.index('--mount'):args.index('--mount') + 2])
        self.assertEqual(['/x/copy', '--', 'go', 'mod', 'tidy'], args[-5:])
        self.assertLess(args.index('--mount'), args.index('/x/copy'))


class GradleVerificationPomTests(unittest.TestCase):
    """2026-11-07: kotlin-stdlib 2.4.21 publishes Gradle module metadata, so `:p:dependencies` never fetched its
    POM, the regenerated verification-metadata.xml had no entry for it, and dependencyCheckAnalyze (which asks
    for every POM) failed verification. The Gradle step must also resolve each project's POMs."""

    def test_the_gradle_step_resolves_every_projects_poms_through_the_init_script(self):
        calls = []
        saved = regen.sandbox
        regen.sandbox = lambda root, scratch, subdir, command, outputs, changed, **kw: calls.append(command) or True
        try:
            self.assertTrue(regen.regenerate_gradle(ROOT, ROOT / 'build', []))
        finally:
            regen.sandbox = saved
        (command,) = calls
        self.assertEqual(regen.POM_INIT, command[command.index('--init-script') + 1])
        self.assertIn('--write-verification-metadata', command)
        for project in regen.GRADLE_PROJECTS:
            self.assertIn(f':{project}:resolveVerificationPoms', command)
        init = (ROOT / regen.POM_INIT).read_text()
        self.assertIn("tasks.register('resolveVerificationPoms')", init)
        self.assertIn('withArtifacts(MavenModule, MavenPomArtifact)', init)

    def test_the_metadata_has_the_runtime_kotlin_stdlib_pom(self):
        version = re.search(r"^ext\.kotlin_version='([^']+)'", (ROOT / 'gradles/chronicle.gradle').read_text(),
                            re.MULTILINE).group(1)
        text = (ROOT / 'gradle/verification-metadata.xml').read_text()
        component = text.split(f'<component group="org.jetbrains.kotlin" name="kotlin-stdlib" version="{version}">', 1)[1]
        self.assertIn(f'<artifact name="kotlin-stdlib-{version}.pom">', component.split('</component>', 1)[0])



def git(repo: Path, *args: str) -> str:
    return subprocess.run(['git', '-C', str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


class OsPackagePinTests(unittest.TestCase):
    """A new base image has its own package versions: deps-regenerate.py resolves the OS-package pins of each
    Dockerfile whose FROM lines changed (scripts/os-package-pins.py --write, this script's own copy)."""
    HELPER_CALL = ('RUN --mount=type=bind,source=os-packages/apk-install-aged.sh,target=/usr/local/sbin/a.sh \\\n'
                   '    sh /usr/local/sbin/a.sh v3.24 --add gettext --pin gettext=1.0-r0\n')

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name) / 'repo'
        self.root.mkdir()
        git(self.root, 'init', '-q', '-b', 'main')
        git(self.root, 'config', 'user.email', 't@example.invalid')
        git(self.root, 'config', 'user.name', 't')
        (self.root / 'selfhost').mkdir()
        self.dockerfile = self.root / 'selfhost/Dockerfile.x'
        self.dockerfile.write_text('FROM alpine:3.24@sha256:' + 'a' * 64 + '\n' + self.HELPER_CALL)
        (self.root / 'selfhost/Dockerfile.plain').write_text('FROM alpine:3.24@sha256:' + 'a' * 64 + '\n')
        git(self.root, 'add', '-A')
        git(self.root, 'commit', '-q', '-m', 'base')
        self.base = git(self.root, 'rev-parse', 'HEAD')
        self.log = Path(self.directory.name) / 'argv.json'
        stub = Path(self.directory.name) / 'os-package-pins.py'
        stub.write_text(f'import json, sys\nopen({str(self.log)!r}, "w").write(json.dumps(sys.argv[1:]))\n'
                        'print("selfhost/Dockerfile.x")\n')
        self.saved = regen.OS_PINS
        regen.OS_PINS = stub

    def tearDown(self):
        regen.OS_PINS = self.saved
        self.directory.cleanup()

    def test_a_new_base_image_refreshes_that_dockerfiles_pins(self):
        for name in ('Dockerfile.x', 'Dockerfile.plain'):
            path = self.root / 'selfhost' / name
            path.write_text(path.read_text().replace('a' * 64, 'b' * 64))
        changed = []
        self.assertTrue(regen.refresh_os_packages(self.root, self.base, changed))
        argv = json.loads(self.log.read_text())
        self.assertEqual(['--root', str(self.root), '--dockerfile', 'selfhost/Dockerfile.x', '--write'], argv)
        self.assertEqual(['selfhost/Dockerfile.x'], changed)

    def test_pins_stay_when_no_base_image_moved(self):
        self.dockerfile.write_text(self.dockerfile.read_text().replace('gettext=1.0-r0', 'gettext=1.0-r1'))
        changed = []
        self.assertTrue(regen.refresh_os_packages(self.root, self.base, changed))
        self.assertFalse(self.log.exists())
        self.assertEqual([], changed)

    def test_the_pin_script_is_this_scripts_own(self):
        self.assertEqual(Path(regen.__file__).resolve().parent / 'os-package-pins.py', self.saved)

if __name__ == '__main__':
    unittest.main()
