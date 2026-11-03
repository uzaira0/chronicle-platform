"""Installed and discovered gate binaries must report the manifest's version."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
import zipfile

from test_gate_tool_digests import manifest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / 'scripts/local-ci.sh'


class GateToolRuntimePinTests(unittest.TestCase):
    def test_web_uses_the_installed_runtime_and_exact_manifest_pins(self):
        source = (ROOT / 'scripts/verify-toolchain.sh').read_text()
        section = source.split('# ── 3. Bun pins', 1)[1].split('# ── 4. Version sync', 1)[0]
        guard = (ROOT / 'tests/security/supply-chain-guardrails.sh').read_text()
        marker = '"$REPORT_DIR/web-runtime-pin-mismatches.txt" <<\'PY\'\n'
        policy = guard.split(marker, 1)[1].split('\nPY\n', 1)[0]
        scratch = ROOT / 'build/operator-test-runs'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            web = root / 'chronicle-web'
            web.mkdir()
            (root / 'scripts').mkdir()
            (root / 'scripts/chronicle-web-bun-smoke.sh').write_text('')
            security = root / 'tests/security'
            security.mkdir(parents=True)
            (security / 'supply-chain-guardrails.sh').write_text('BUN_VERSION="1.3.12"\n')
            (web / 'bun.lock').write_text('"bun-types@1.3.12"\n')
            bun = root / 'bun'
            package = {'engines': {'bun': '1.3.12'}, 'devDependencies': {'bun-types': '1.3.12'}}
            for version, engine, types, package_version in (
                ('1.3.12', '1.3.12', '1.3.12', '1.3.12'),
                ('1.3.14', '1.3.12', '1.3.12', '1.3.12'),
                ('1.3.12', '>=1.3.12', '1.3.12', '1.3.12'),
                ('1.3.12', '1.3.12', '1.3.14', '1.3.12'),
                ('1.3.12', '1.3.12', '1.3.12', '1.3.14'),
            ):
                with self.subTest(version=version, engine=engine, types=types, package_version=package_version):
                    bun.write_text('#!/bin/sh\nprintf "%s\\n" ' + shlex.quote(version) + '\n')
                    bun.chmod(0o755)
                    package['engines']['bun'] = engine
                    package['devDependencies'] = {'bun-types': types, 'bun': package_version}
                    manifest = web / 'package.json'
                    manifest.write_text(json.dumps(package))
                    environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'])
                    script = ('ROOT_DIR="$1"\nBUN=1.3.12\nFAILURES=0\n'
                              'fail() { echo "$*"; FAILURES=$((FAILURES + 1)); }\n'
                              'ok() { echo "$*"; }\n# ── 3. Bun pins' + section + '\nexit "$FAILURES"\n')
                    result = subprocess.run(['bash', '-s', '--', str(root)], input=script,
                                            capture_output=True, text=True, timeout=20, env=environment)
                    self.assertEqual(any(pin != '1.3.12' for pin in (version, engine, types, package_version)),
                                     result.returncode != 0, result.stdout + result.stderr)
                    result = subprocess.run([sys.executable, '-', str(manifest), '1.3.12', str(root / 'report')],
                                            input=policy, capture_output=True, text=True, timeout=20)
                    self.assertEqual(any(pin != '1.3.12' for pin in (engine, types, package_version)), result.returncode != 0,
                                     result.stdout + result.stderr)

    def run_tool(self, tool, *, cached=None, global_version=None, downloaded=None, prime_global=False):
        pins = manifest()
        version = pins[tool]['version']
        expected = 'ast-grep ' + version if tool == 'ast-grep' else 'Haskell Dockerfile Linter ' + version.lstrip('v')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            local = root / 'local'
            local.mkdir()
            global_bin = root / 'global'
            global_bin.mkdir()

            def binary(path, output):
                path.write_text('#!/bin/sh\nprintf "%s\\n" ' + shlex.quote(output) + '\n')
                path.chmod(0o755)

            if cached is not None:
                binary(local / tool, expected if cached == 'pinned' else cached)
            if global_version is not None:
                if global_version == 'unavailable':
                    (global_bin / tool).write_text('#!/bin/sh\nexit 1\n')
                    (global_bin / tool).chmod(0o755)
                else:
                    binary(global_bin / tool, expected if global_version == 'pinned' else global_version)
            original_global = (global_bin / tool).read_bytes() if (global_bin / tool).exists() else None
            payload = root / 'payload'
            binary(payload, expected if downloaded is None else downloaded)
            asset = root / 'asset'
            if tool == 'ast-grep':
                with zipfile.ZipFile(asset, 'w') as archive:
                    archive.write(payload, 'ast-grep')
            else:
                asset.write_bytes(payload.read_bytes())
            digest = hashlib.sha256(asset.read_bytes()).hexdigest()
            pins[tool]['sha256'] = {platform: digest for platform in ('darwin-amd64', 'darwin-arm64', 'linux-amd64', 'linux-arm64')}
            (root / 'toolchain-manifest.yaml').write_text(json.dumps({'gate_tools': pins}))
            script = '''source "$GATE_SCRIPT"
ROOT_DIR="$FIXTURE"
machine_os() { echo linux; }
machine_arch() { echo arm64; }
native_mktemp="$(command -v mktemp)"
mktemp() {
  local path
  path="$("$native_mktemp" "$@")" || return
  printf '%s\n' "$path" >> "$FIXTURE/temps"
  printf '%s\n' "$path"
}
download_asset() {
  printf 'download\n' >> "$FIXTURE/downloads"
  case "$1" in *.sha256) printf '%s  %s\n' "$FIXTURE_DIGEST" hadolint-linux-arm64 > "$2" ;;
    *) cp "$FIXTURE/asset" "$2" ;; esac
}
'''
            if prime_global:
                script += 'hash -p "$FIXTURE/global/' + tool + '" ' + tool + '\n'
            function = 'ensure_ast_grep' if tool == 'ast-grep' else 'ensure_hadolint'
            script += function + '\nprintf "resolved:%s\\n" "$(' + tool + ' --version)"\n'
            result = subprocess.run(['bash', '-s'], input=script, capture_output=True, text=True, timeout=20,
                                    env=dict(os.environ, GATE_SCRIPT=str(GATE), FIXTURE=str(root), FIXTURE_DIGEST=digest,
                                             TMPDIR=str(root), CHRONICLE_LOCAL_BIN_DIR=str(local),
                                             PATH=str(global_bin) + os.pathsep + os.environ['PATH']))
            downloaded_asset = (root / 'downloads').exists()
            global_unchanged = original_global is None or (global_bin / tool).read_bytes() == original_global
            if (root / 'temps').exists():
                for path in (root / 'temps').read_text().splitlines():
                    self.assertTrue(Path(path).is_relative_to(root / 'build/tool-downloads'), path)
        self.assertTrue(global_unchanged, 'The helper must never replace the global binary')
        return result, downloaded_asset, expected

    def test_wrong_global_ast_grep_installs_the_verified_local_pin(self):
        result, downloaded, expected = self.run_tool('ast-grep', global_version='ast-grep 0.51.0', prime_global=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(downloaded)
        self.assertIn('resolved:' + expected, result.stdout)

    def test_correct_global_ast_grep_can_be_reused(self):
        result, downloaded, expected = self.run_tool('ast-grep', global_version='pinned')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(downloaded)
        self.assertIn('resolved:' + expected, result.stdout)

    def test_wrong_cached_binaries_are_replaced_by_the_verified_pin(self):
        for tool in ('ast-grep', 'hadolint'):
            with self.subTest(tool=tool):
                result, downloaded, expected = self.run_tool(tool, cached='wrong cached version')
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue(downloaded)
                self.assertIn('resolved:' + expected, result.stdout)

    def test_correct_local_pin_wins_over_a_cached_global_command(self):
        for tool in ('ast-grep', 'hadolint'):
            with self.subTest(tool=tool):
                result, downloaded, expected = self.run_tool(tool, cached='pinned', global_version='wrong global version', prime_global=True)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertFalse(downloaded)
                self.assertIn('resolved:' + expected, result.stdout)

    def test_installed_binary_must_report_the_pinned_version(self):
        for tool in ('ast-grep', 'hadolint'):
            with self.subTest(tool=tool):
                result, downloaded, _ = self.run_tool(tool, global_version='unavailable', downloaded='wrong installed version')
                self.assertTrue(downloaded)
                self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertNotIn('resolved:', result.stdout)


if __name__ == '__main__':
    unittest.main()
