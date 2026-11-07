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
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('deps_regenerate', ROOT / 'scripts/deps-regenerate.py')
regen = importlib.util.module_from_spec(spec)
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
