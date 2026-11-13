"""Every ast-grep the gates and hooks run is the toolchain-manifest.yaml gate_tools pin.

2026-11-07: the gates pinned 0.42.1, chronicle-web's own copy was 0.45.2, and scripts/i18n-lint.sh (the
pre-push hook) demanded "0.45.2 or newer" from whatever was first on PATH, so it refused the pinned binary
and ran Homebrew's 0.51.0. Three versions; rules and waiver hashes depend on how a version parses.
"""
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATH_RUNNERS = ('scripts/i18n-lint.sh', 'scripts/i18n-lint-mutation.sh')


def drift(root=ROOT):
    """The places whose ast-grep version disagrees with the manifest pin, as messages; empty when in line."""
    manifest = (root / 'toolchain-manifest.yaml').read_text()
    pin = re.search(r'^  ast-grep:\n    version: "([^"]+)"', manifest, re.MULTILINE)
    if not pin:
        return ['toolchain-manifest.yaml has no gate_tools ast-grep version']
    pin = pin.group(1)
    found = []
    gate = re.search(r'^ensure_ast_grep\(\) \{\n  local bin="\$LOCAL_BIN_DIR/ast-grep" version="([^"]+)"',
                     (root / 'scripts/local-ci.sh').read_text(), re.MULTILINE)
    if not gate or gate.group(1) != pin:
        found.append(f'scripts/local-ci.sh ensure_ast_grep installs {gate.group(1) if gate else "nothing"}, manifest pins {pin}')
    package = json.loads((root / 'chronicle-web/package.json').read_text())
    web = {**package.get('dependencies', {}), **package.get('devDependencies', {})}.get('@ast-grep/cli')
    if web != pin:
        found.append(f'chronicle-web/package.json @ast-grep/cli is {web}, manifest pins {pin}')
    locked = re.search(r'"@ast-grep/cli": \["@ast-grep/cli@([^"]+)"', (root / 'chronicle-web/bun.lock').read_text())
    if not locked or locked.group(1) != pin:
        found.append(f'chronicle-web/bun.lock resolves @ast-grep/cli {locked.group(1) if locked else "nothing"}, manifest pins {pin}')
    for name in PATH_RUNNERS:
        source = (root / name).read_text()
        if not re.search(r'^source scripts/local-ci\.sh\nensure_ast_grep$', source, re.MULTILINE):
            found.append(f'{name} runs ast-grep without ensure_ast_grep (would use whatever is on PATH)')
        if re.search(r'ast-grep[^\n]*\b\d+\.\d+\.\d+', source):
            found.append(f'{name} names an ast-grep version of its own')
    return found


class AstGrepOneVersionTest(unittest.TestCase):
    def test_every_ast_grep_is_the_manifest_pin(self):
        self.assertEqual([], drift())

    def test_each_kind_of_drift_is_reported(self):
        files = ['toolchain-manifest.yaml', 'scripts/local-ci.sh', 'chronicle-web/package.json',
                 'chronicle-web/bun.lock', *PATH_RUNNERS]
        pin = re.search(r'^  ast-grep:\n    version: "([^"]+)"', (ROOT / 'toolchain-manifest.yaml').read_text(),
                        re.MULTILINE).group(1)
        cases = {
            'scripts/local-ci.sh': (f'ast-grep" version="{pin}"', 'ast-grep" version="0.42.1"', 'ensure_ast_grep installs 0.42.1'),
            'chronicle-web/package.json': (f'"@ast-grep/cli": "{pin}"', '"@ast-grep/cli": "0.45.2"', '@ast-grep/cli is 0.45.2'),
            'chronicle-web/bun.lock': (f'"@ast-grep/cli@{pin}"', '"@ast-grep/cli@0.45.2"', 'resolves @ast-grep/cli 0.45.2'),
            'scripts/i18n-lint.sh': ('source scripts/local-ci.sh\nensure_ast_grep\n',
                                     'ast_grep_version=$(ast-grep --version) # minimum 0.45.2\n', 'without ensure_ast_grep'),
        }
        for changed, (old, new, expected) in cases.items():
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in files:
                    (root / name).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / name, root / name)
                text = (root / changed).read_text()
                self.assertIn(old, text)
                (root / changed).write_text(text.replace(old, new, 1))
                self.assertTrue(any(expected in message for message in drift(root)), drift(root))


if __name__ == '__main__':
    unittest.main()
