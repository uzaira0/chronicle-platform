"""Every version a Dockerfile fetches outside FROM and the OS-package helpers is a `# renovate:` ARG.

A version written into a RUN line (a download URL, `git clone --branch`, `module@version`, `pip install x==y`)
is invisible to Renovate, so it is never proposed, and to scripts/check-dependency-age.py, so a change to it
is never aged. The 2026-11-06 launch audit (CI-B1) found five such pins in release images
(selfhost/Dockerfile.grafana plugin 0.33.1, Grafana v13.2.5 source and go-jose v4.1.8,
selfhost/Dockerfile.caddy go-jose v3.0.5, selfhost/Dockerfile.backup debianutils 5.23.2) and more in the
dependency sandbox images. The convention (docs/SUPPLY-CHAIN.md):

    # renovate: datasource=<datasource> depName=<name>[ versioning=<versioning>]
    ARG NAME_VERSION=<the datasource's own version or tag>

renovate.json's Dockerfile custom manager reads it and so does the age gate; these tests hold the two
readings equal on the real Dockerfiles.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('check_dependency_age', ROOT / 'scripts/check-dependency-age.py')
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)

# A version in a RUN line: a URL carrying a dotted version, a clone of a tag, module@version, a pip pin.
LITERAL_PIN = re.compile(
    r'https?://[^\s"\']*\d+\.\d+[^\s"\']*'
    r'|--branch\s+v?\d'
    r'|[\w./-]+@v\d+\.\d+'
    r'|[A-Za-z0-9_.-]+==\d')


def literal_pins(run: str) -> list[str]:
    """The literal versions in one RUN instruction. A URL counts when a dotted number is left after its
    ${...} expansions are removed, so `.../download/v8.30.1/gitleaks_${arch}.tar.gz` is still a pin."""
    pins = []
    for match in LITERAL_PIN.finditer(run):
        text = match.group(0)
        if text.startswith('http') and not re.search(r'\d+\.\d+', re.sub(r'\$\{[^}]*\}', '', text)):
            continue
        if not text.startswith('http') and '${' in text:
            continue
        pins.append(text)
    return pins


def dockerfiles() -> list[str]:
    listed = subprocess.run(['git', '-C', str(ROOT), 'ls-files'], capture_output=True, text=True, check=True).stdout
    return sorted(p for p in listed.splitlines() if re.search(r'(^|/)Dockerfile[^/]*$', p) and (ROOT / p).is_file())


def run_instructions(text: str) -> list[str]:
    """Each RUN instruction with its continuation lines joined; comment lines inside it dropped."""
    found, current = [], None
    for line in text.splitlines():
        stripped = line.strip()
        if current is None:
            if re.match(r'RUN\b', stripped, re.IGNORECASE):
                current = stripped
                if not stripped.endswith('\\'):
                    found.append(current)
                    current = None
            continue
        if stripped.startswith('#'):
            continue
        current += ' ' + stripped
        if not stripped.endswith('\\'):
            found.append(current)
            current = None
    if current is not None:
        found.append(current)
    return found


def renovate_dockerfile_manager() -> dict:
    config = json.loads((ROOT / 'renovate.json').read_text())
    managers = [m for m in config['customManagers']
                if any('Dockerfile' in pattern for pattern in m['managerFilePatterns'])]
    if len(managers) != 1:
        raise AssertionError(f'renovate.json has {len(managers)} Dockerfile custom managers, expected 1')
    return managers[0]


def js_regex(pattern: str) -> re.Pattern:
    """Renovate's matchStrings are JavaScript regexes with (?<name>...) groups and no flags."""
    return re.compile(pattern.replace('(?<', '(?P<'))


def file_regex(pattern: str) -> re.Pattern:
    return js_regex(pattern.strip('/'))


class LiteralPinTests(unittest.TestCase):
    def test_no_run_line_carries_a_version(self):
        offenders = []
        for path in dockerfiles():
            for run in run_instructions((ROOT / path).read_text()):
                offenders += [f'{path}: {pin}' for pin in literal_pins(run)]
        self.assertEqual([], offenders, 'move each version into a `# renovate:` ARG (docs/SUPPLY-CHAIN.md)')

    def test_the_detector_finds_the_audit_specimens(self):
        """The five pins the launch audit named, as they were written before the fix."""
        specimens = (
            'RUN wget -q -O /plugin.zip https://grafana.com/api/plugins/victoriametrics-logs-datasource/versions/0.33.1/download',
            'RUN git clone --quiet --depth 1 --branch v13.2.5 https://github.com/grafana/grafana /src',
            'RUN go work edit -replace=github.com/go-jose/go-jose/v4=github.com/go-jose/go-jose/v4@v4.1.8',
            'RUN dir="$(go mod download -json github.com/go-jose/go-jose/v3@v3.0.5)"',
            'RUN curl -o /tmp/d.tar.xz https://deb.debian.org/debian/pool/main/d/debianutils/debianutils_5.23.2.tar.xz',
            'RUN uv pip install "ruff==0.17.2"',
        )
        for run in specimens:
            with self.subTest(run=run):
                self.assertTrue(literal_pins(run))
        self.assertTrue(literal_pins('RUN curl https://github.com/g/g/releases/download/v8.30.1/g_${arch}.tar.gz'))
        self.assertEqual([], literal_pins('RUN wget "https://grafana.com/x/versions/${TAG#v}/download"'))
        self.assertEqual([], literal_pins('RUN go mod download "example.com/m@${M_VERSION}"'))


class AnnotationTests(unittest.TestCase):
    """renovate.json and the age gate read the same pins from the real Dockerfiles."""

    # Every pin the audit and the sandbox review named, as (file, datasource, depName).
    REQUIRED = frozenset({
        ('selfhost/Dockerfile.grafana', 'github-releases', 'VictoriaMetrics/victorialogs-datasource'),
        ('selfhost/Dockerfile.grafana', 'github-releases', 'grafana/grafana'),
        ('selfhost/Dockerfile.grafana', 'go', 'github.com/go-jose/go-jose/v4'),
        ('selfhost/Dockerfile.caddy', 'go', 'github.com/go-jose/go-jose/v3'),
        ('selfhost/Dockerfile.backup', 'custom.debian-source', 'debianutils'),
        ('scripts/sandbox/Dockerfile.gate', 'pypi', 'ruff'),
        ('scripts/sandbox/Dockerfile.gate', 'github-releases', 'gitleaks/gitleaks'),
        ('scripts/sandbox/Dockerfile.gate', 'github-releases', 'mikefarah/yq'),
        ('scripts/sandbox/Dockerfile.gate', 'github-releases', 'koalaman/shellcheck'),
        ('scripts/sandbox/Dockerfile.gate', 'github-releases', 'astral-sh/uv'),
        ('scripts/sandbox/Dockerfile.deps', 'github-releases', 'mikefarah/yq'),
        ('docker/hetzner/percona/Dockerfile', 'github-releases', 'curl/curl'),
        ('docker/hetzner/crowdsec/Dockerfile.hardened', 'github-releases', 'google/re2'),
    })

    def renovate_reads(self) -> set[tuple[str, str, str, str]]:
        manager = renovate_dockerfile_manager()
        patterns = [file_regex(p) for p in manager['managerFilePatterns']]
        found = set()
        for path in dockerfiles():
            if not any(p.search(path) for p in patterns):
                continue
            text = (ROOT / path).read_text()
            for match_string in manager['matchStrings']:
                for match in js_regex(match_string).finditer(text):
                    found.add((path, match['datasource'], match['depName'], match['currentValue']))
        return found

    def gate_reads(self, renovate_only: bool = False) -> set[tuple[str, str, str, str]]:
        return {(path, a.datasource, a.dep_name, a.value)
                for path in dockerfiles() for a in gate.dockerfile_annotations((ROOT / path).read_text())
                if a.renovate or not renovate_only}

    def test_renovate_and_the_age_gate_read_the_same_pins(self):
        """Renovate reads every `# renovate:` pin and nothing else; the gate reads those and the
        `# age-gate-only:` ones."""
        self.assertEqual(self.gate_reads(renovate_only=True), self.renovate_reads())
        self.assertEqual({('selfhost/Dockerfile.caddy', 'go', 'github.com/go-jose/go-jose/v3', 'v3.0.5')},
                         self.gate_reads() - self.gate_reads(renovate_only=True))

    def test_every_audited_pin_is_annotated(self):
        read = {(path, datasource, name) for path, datasource, name, _ in self.gate_reads()}
        self.assertEqual(set(), self.REQUIRED - read)

    def test_the_manager_covers_every_dockerfile(self):
        patterns = [file_regex(p) for p in renovate_dockerfile_manager()['managerFilePatterns']]
        self.assertEqual([], [path for path in dockerfiles() if not any(p.search(path) for p in patterns)])

    def test_every_annotation_dates_through_a_known_registry(self):
        for path in dockerfiles():
            _, unknown = gate.parse_file(Path(path).name, (ROOT / path).read_text(), path)
            with self.subTest(dockerfile=path):
                self.assertEqual(set(), unknown)

    def test_an_annotation_must_sit_on_the_line_above_its_arg(self):
        text = '# renovate: datasource=go depName=example.com/m\n\nARG M_VERSION=v1.0.0\n'
        self.assertEqual([], gate.dockerfile_annotations(text))
        self.assertEqual(1, len(gate.dockerfile_annotations(text.replace('\n\n', '\n'))))


class RenovateImageTests(unittest.TestCase):
    def test_renovate_proposes_its_own_image(self):
        """scripts/renovate-run.sh pins the Renovate image by digest; a script manager must read it."""
        config = json.loads((ROOT / 'renovate.json').read_text())
        text = (ROOT / 'scripts/renovate-run.sh').read_text()
        hits = []
        for manager in config['customManagers']:
            if not any(file_regex(p).search('scripts/renovate-run.sh') for p in manager['managerFilePatterns']):
                continue
            for match_string in manager['matchStrings']:
                hits += [m['depName'] for m in js_regex(match_string).finditer(text)]
        self.assertEqual(['renovate/renovate'], hits)

    def test_go_jose_v3_never_reaches_renovate(self):
        """OSV names v4.0.0 as the v3 fix; Renovate's vulnerability branch rewrote selfhost/caddy/module/go.mod
        to that other module on 2026-11-08 although a packageRule disabled the package. ignoreDeps drops it at
        extraction, so no lookup or vulnerability branch happens."""
        config = json.loads((ROOT / 'renovate.json').read_text())
        self.assertIn('github.com/go-jose/go-jose/v3', config.get('ignoreDeps', []))


if __name__ == '__main__':
    unittest.main()
