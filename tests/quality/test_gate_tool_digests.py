#!/usr/bin/env python3
"""Every gate tool scripts/local-ci.sh downloads, and every third-party import of a release script,
is pinned by a digest committed in the repo.

A checksums file from the same GitHub release as the asset cannot vouch for it (a replaced asset plus
a replaced checksums file would pass), so toolchain-manifest.yaml gate_tools commits each asset's sha256,
PMD included. play-upload.py imports Google's client libraries only as locked with hashes in
chronicle/scripts/play-upload.requirements.txt.
"""
import ast
import hashlib
import json
import os
import re
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STDLIB = runpy.run_path(str(ROOT / 'scripts/check-python-dev-pins.py'))['stdlib_modules']()
GATE = ROOT / 'scripts/local-ci.sh'
PLATFORMS = ('darwin-amd64', 'darwin-arm64', 'linux-amd64', 'linux-arm64')
TOOLS = {'container-structure-test': 'ensure_container_structure_test', 'hadolint': 'ensure_hadolint',
         'ast-grep': 'ensure_ast_grep', 'pmd': 'ensure_pmd', 'bearer': 'ensure_bearer',
         'osv-scanner': 'ensure_osv_scanner', 'grype': 'ensure_grype', 'syft': 'ensure_syft',
         'detekt-cli': 'ensure_detekt', 'bearer-rules': 'ensure_bearer_rules'}


def manifest(root=ROOT):
    out = subprocess.run(['yq', '-o=json', '.gate_tools', str(root / 'toolchain-manifest.yaml')],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def bash(script, env, cwd):
    # cwd is a scratch folder: a broken gate script must not drop files into the repository.
    return subprocess.run(['bash', '-s'], input='source "$GATE_SCRIPT"\n' + script, capture_output=True, text=True,
                          timeout=60, check=False, cwd=cwd, env=dict(os.environ, GATE_SCRIPT=str(GATE), **env))


class DownloadVerificationTests(unittest.TestCase):
    """download_asset_with_checksum against a fixture manifest and fixture release files."""

    def run_download(self, asset_bytes, checksum_bytes, committed):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root / 'toolchain-manifest.yaml').write_text(
                f'gate_tools:\n  fake:\n    version: "1.0"\n    sha256:\n      any: "{committed}"\n')
            (root / 'asset').write_bytes(asset_bytes)
            (root / 'sums').write_text(f'{hashlib.sha256(checksum_bytes).hexdigest()}  fake-asset\n')
            script = ('ROOT_DIR="$FIXTURE"\n'
                      'download_asset() { case "$1" in *sums) cp "$FIXTURE/sums" "$2" ;; *) cp "$FIXTURE/asset" "$2" ;; esac; }\n'
                      'download_asset_with_checksum "$(pinned_tool_sha256 fake 1.0 any)" https://x/fake-asset https://x/sums '
                      'fake-asset "$FIXTURE/out"\n')
            return bash(script, {'FIXTURE': str(root)}, root)

    def test_the_genuine_asset_passes(self):
        good = b'genuine release asset'
        result = self.run_download(good, good, hashlib.sha256(good).hexdigest())
        self.assertEqual(0, result.returncode, result.stderr)

    def test_a_replaced_asset_with_a_matching_replaced_checksums_file_is_refused(self):
        result = self.run_download(b'replaced asset', b'replaced asset', hashlib.sha256(b'genuine').hexdigest())
        self.assertNotEqual(0, result.returncode)
        self.assertIn('differs from the committed digest', result.stderr)

    def test_a_replaced_asset_under_the_genuine_checksums_file_is_refused(self):
        result = self.run_download(b'replaced asset', b'genuine', hashlib.sha256(b'genuine').hexdigest())
        self.assertNotEqual(0, result.returncode)

    def test_no_committed_digest_refuses_before_downloading(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root / 'toolchain-manifest.yaml').write_text('gate_tools:\n  fake:\n    version: "1.0"\n    sha256: {}\n')
            script = ('ROOT_DIR="$FIXTURE"\n'
                      'download_asset() { echo "downloaded $1"; : > "$2"; }\n'
                      'download_asset_with_checksum "$(pinned_tool_sha256 fake 1.0 linux-amd64)" https://x/a https://x/s a "$FIXTURE/out"\n')
            result = bash(script, {'FIXTURE': str(root)}, root)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn('downloaded', result.stdout)
        self.assertIn('no committed sha256', result.stderr)

    def test_a_version_the_manifest_does_not_pin_is_refused(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root / 'toolchain-manifest.yaml').write_text(f'gate_tools:\n  fake:\n    version: "1.0"\n    sha256:\n      any: "{"a" * 64}"\n')
            result = bash('ROOT_DIR="$FIXTURE"\npinned_tool_sha256 fake 2.0 any\n', {'FIXTURE': str(root)}, root)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('pins version 1.0', result.stderr)


class EveryToolIsPinnedTests(unittest.TestCase):
    """Each ensure_* function, on each platform, verifies its download with the manifest's digest."""

    STUBS = r'''
ROOT_DIR="$WORK/project"; mkdir -p "$ROOT_DIR"
cp "$FIXTURE_MANIFEST" "$ROOT_DIR/toolchain-manifest.yaml"
LOCAL_BIN_DIR="$WORK/bin"; mkdir -p "$LOCAL_BIN_DIR"
machine_os() { echo "${PLATFORM%-*}"; }
machine_arch() { echo "${PLATFORM#*-}"; }
require_cmd() { :; }
require_jdk21() { :; }
command() { [[ "$1" == -v ]] && return 1; builtin command "$@"; }
download_asset() { : > "$2"; }
download_asset_with_checksum() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]] || exit 9
  printf '%s\n' "$1" >> "$WORK/verified"; fixture_binary "$5"
}
fixture_binary() { printf '#!/bin/sh\nprintf "%%s\\n" "%s"\n' "$FIXTURE_VERSION_OUTPUT" > "$1"; chmod +x "$1"; }
sha256_check() { printf '%s\n' "$1" >> "$WORK/verified"; }
curl() { local out; while (($#)); do [[ "$1" == -o ]] && out="$2"; shift; done; : > "$out"; }
unzip() { mkdir -p "${@: -1}/pmd-bin-$PMD_VERSION"; }
extract_binary_from_tar() { fixture_binary "$3"; }
extract_binary_from_zip() { fixture_binary "$3"; }
'''

    def test_every_downloaded_tool_has_a_committed_digest_on_every_platform(self):
        pins = manifest()
        self.assertEqual(set(TOOLS), set(pins), 'gate_tools must list exactly the tools local-ci.sh downloads')
        for tool, function in TOOLS.items():
            for platform in PLATFORMS:
                with self.subTest(tool=tool, platform=platform), tempfile.TemporaryDirectory() as work:
                    if tool == 'ast-grep':
                        version_output = 'ast-grep ' + pins[tool]['version']
                    elif tool == 'hadolint':
                        version_output = 'Haskell Dockerfile Linter ' + pins[tool]['version'].lstrip('v')
                    else:
                        version_output = 'fixture'
                    # The rule archives are unpacked, not run: the stub download is empty.
                    stubs = self.STUBS + ('tar() { :; }\n' if tool == 'bearer-rules' else '')
                    result = bash(stubs + f'{function}\n', {'WORK': work, 'PLATFORM': platform,
                                  'FIXTURE_MANIFEST': str(ROOT / 'toolchain-manifest.yaml'),
                                  'FIXTURE_VERSION_OUTPUT': version_output}, work)
                    self.assertEqual(0, result.returncode, result.stderr)
                    verified = (Path(work) / 'verified').read_text().split()
                    if tool == 'bearer-rules':  # one archive per language, the same on every platform
                        self.assertEqual(sorted(pins[tool]['sha256'].values()), sorted(verified))
                        continue
                    expected = pins[tool]['sha256'].get(platform) or pins[tool]['sha256']['any']
                    self.assertEqual([expected], verified)

    def test_every_download_in_the_gate_goes_through_a_verified_function(self):
        # A new `download_asset` or `curl -o` in an ensure_* function must be followed by sha256_check;
        # this test lists the ensure_* functions, so a new one fails until it is added to TOOLS.
        functions = subprocess.run(['bash', '-c', 'source "$1"; compgen -A function ensure_', 'x', str(GATE)],
                                   capture_output=True, text=True, check=True).stdout.split()
        downloading = []
        for name in functions:
            body = subprocess.run(['bash', '-c', 'source "$1"; declare -f "$2"', 'x', str(GATE), name],
                                  capture_output=True, text=True, check=True).stdout
            if 'download_asset' in body or 'curl ' in body:
                downloading.append(name)
        self.assertEqual(sorted(TOOLS.values()), sorted(downloading))


# Top-level module -> the distributions that provide it, for release-script imports.
MODULE_DISTRIBUTIONS = {
    'google': {'google-auth'}, 'googleapiclient': {'google-api-python-client'}, 'packaging': {'packaging'},
}
RELEASE_NAME = re.compile(r'release|publish|upload|sign|bundle', re.IGNORECASE)


class ReleaseScriptImportsArePinnedTests(unittest.TestCase):
    def release_scripts(self):
        files = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '--recurse-submodules',
                                'scripts/*.py', 'chronicle/scripts/*.py', 'selfhost/**/*.py'],
                               capture_output=True, text=True, check=True).stdout.split()
        return [f for f in files if RELEASE_NAME.search(Path(f).name) and not Path(f).name.startswith('test')]

    def third_party_imports(self, path):
        local = {p.name for p in (ROOT / 'selfhost').iterdir() if p.is_dir()} | {p.stem for p in path.parent.glob('*.py')}
        modules = set()
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                modules |= {alias.name.split('.')[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules.add(node.module.split('.')[0])
        return sorted(m for m in modules if m not in STDLIB and m not in local and m != '__future__')

    def test_every_third_party_import_of_a_release_script_is_hash_locked(self):
        scripts = self.release_scripts()
        self.assertIn('chronicle/scripts/play-upload.py', scripts)
        for script in scripts:
            path = ROOT / script
            imports = self.third_party_imports(path)
            if not imports:
                continue
            with self.subTest(script=script):
                lock = path.with_name(path.stem + '.requirements.txt')
                self.assertTrue(lock.exists(), f'{script} imports {imports} with no {lock.name}')
                text = lock.read_text()
                pinned = set(re.findall(r'^([A-Za-z0-9_.-]+)==', text, re.MULTILINE))
                for line in re.findall(r'^[A-Za-z0-9_.-]+==.*?(?=^[A-Za-z0-9#]|\Z)', text, re.MULTILINE | re.DOTALL):
                    self.assertIn('--hash=sha256:', line, line.splitlines()[0])
                for module in imports:
                    self.assertIn(module, MODULE_DISTRIBUTIONS, f'{script}: map {module} to its distribution and lock it')
                    self.assertTrue(MODULE_DISTRIBUTIONS[module] <= pinned, f'{script}: {module} is not in {lock.name}')


if __name__ == '__main__':
    unittest.main()
