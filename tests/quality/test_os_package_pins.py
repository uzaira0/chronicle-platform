#!/usr/bin/env python3
"""OS packages in release images enter only at pinned versions older than the dependency wait.

- Every release Dockerfile (chronicle_ops.images.SOURCE_IMAGES, all stages) installs, upgrades or
  downloads distribution packages only through selfhost/os-packages/ (no bare `apk upgrade`,
  `apk add`, `apt-get install|download|upgrade`, `dnf|yum|microdnf install|upgrade`), each helper
  bind-mounted from that directory, every --add with a pin.
- scripts/check-dependency-age.py reads those pins and fails a changed one that is younger than its
  wait, counts a new --pin name as a new package name, and an --upgrade as a change of a known one.
- The registry publish-time parsers (APK index `t:`, snapshot.debian.org first_seen, Launchpad
  date_published, UBI primary.xml) and the pin proposer's dependency closure, on fixtures.
- With Docker, apk-install-aged.sh in the pinned Alpine base: a full closure installs; an unpinned
  dependency, a vanished --pin, a wrong branch and a misplaced --pin/--upgrade fail; a vanished
  --upgrade keeps the base version.
"""
import contextlib
import datetime as dt
import gzip
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'selfhost'))
import itertools

import os_packages
from chronicle_ops.images import SOURCE_IMAGES

spec = importlib.util.spec_from_file_location('check_dependency_age', ROOT / 'scripts/check-dependency-age.py')
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate  # dataclasses look their module up here (3.12/3.13)
spec.loader.exec_module(gate)
pins_spec = importlib.util.spec_from_file_location('os_package_pins', ROOT / 'scripts/os-package-pins.py')
pins_tool = importlib.util.module_from_spec(pins_spec)
sys.modules[pins_spec.name] = pins_tool  # dataclasses look their module up here (3.12/3.13)
pins_spec.loader.exec_module(pins_tool)

RELEASE_DOCKERFILES = sorted({(ROOT / 'selfhost' / image.dockerfile).resolve() for image in SOURCE_IMAGES})
BARE_INSTALL = re.compile(r'\b(apk\s+(add|upgrade|fix)|apt-get\s+(install|upgrade|dist-upgrade|download)|'
                          r'apt\s+(install|upgrade)|(dnf|yum|microdnf)\s+(-y\s+)?(install|upgrade|update|reinstall|downgrade))\b')


def instructions(text: str) -> list[str]:
    """Dockerfile instructions with continuation lines joined and comments dropped."""
    lines = [line for line in text.splitlines() if not line.lstrip().startswith('#')]
    return [part.strip() for part in re.sub(r'\\\n', ' ', '\n'.join(lines)).splitlines() if part.strip()]


class ReleaseDockerfileTests(unittest.TestCase):
    def test_the_release_dockerfiles_are_the_seven_images(self):
        self.assertEqual(7, len(RELEASE_DOCKERFILES))

    def test_no_release_dockerfile_installs_a_package_outside_the_helpers(self):
        for dockerfile in RELEASE_DOCKERFILES:
            for instruction in instructions(dockerfile.read_text()):
                with self.subTest(dockerfile=dockerfile.name, instruction=instruction[:80]):
                    self.assertNotRegex(instruction, BARE_INSTALL)

    def test_every_helper_call_is_bind_mounted_and_every_add_is_pinned(self):
        calls = 0
        for dockerfile in RELEASE_DOCKERFILES:
            text = dockerfile.read_text()
            for call in os_packages.helper_calls(text):
                calls += 1
                with self.subTest(dockerfile=dockerfile.name, helper=call.helper):
                    self.assertRegex(text, rf'--mount=type=bind,source=(selfhost/)?os-packages/{re.escape(call.helper)},'
                                           rf'target=/usr/local/sbin/{re.escape(call.helper)}')
                    sections = call.sections
                    pinned = {os_packages.split_pin(w)[0] for w in sections['pin'] + sections['upgrade']}
                    self.assertEqual([], [name for name in sections['add'] if name not in pinned])
                    self.assertTrue(all('=' in w for w in sections['pin'] + sections['upgrade']))
                    self.assertTrue(call.stage_from and '@sha256:' in call.stage_from, call.stage_from)
        # backend (builder apt, runtime apk), frontend, caddy, grafana, backup (apt, dnf), postgres, fluentbit
        self.assertEqual(9, calls)

    def test_each_helper_exists_and_is_posix_sh(self):
        for helper in os_packages.HELPERS:
            text = (ROOT / 'selfhost/os-packages' / helper).read_text()
            self.assertTrue(text.startswith('#!/bin/sh\n'), helper)


SANDBOX_DOCKERFILES = sorted((ROOT / 'scripts/sandbox').glob('Dockerfile.*'))


class SandboxDockerfileTests(unittest.TestCase):
    """The dependency sandbox images (scripts/deps-sandbox.sh) take OS packages through the same helpers.

    Their build context is scripts/sandbox, so the helpers come from the os-packages build context
    deps-sandbox.sh passes (selfhost/os-packages)."""

    def test_the_sandbox_dockerfiles_are_the_three_images(self):
        self.assertEqual(['Dockerfile.deps', 'Dockerfile.gate', 'Dockerfile.jdk'], [p.name for p in SANDBOX_DOCKERFILES])

    def test_no_sandbox_dockerfile_installs_a_package_outside_the_helpers(self):
        for dockerfile in SANDBOX_DOCKERFILES:
            for instruction in instructions(dockerfile.read_text()):
                with self.subTest(dockerfile=dockerfile.name, instruction=instruction[:80]):
                    self.assertNotRegex(instruction, BARE_INSTALL)

    def test_every_sandbox_helper_call_is_mounted_from_the_os_packages_context_and_pinned(self):
        for dockerfile in SANDBOX_DOCKERFILES:
            text = dockerfile.read_text()
            calls = os_packages.helper_calls(text)
            with self.subTest(dockerfile=dockerfile.name):
                self.assertEqual(1, len(calls))
            for call in calls:
                with self.subTest(dockerfile=dockerfile.name, helper=call.helper):
                    self.assertRegex(text, rf'--mount=type=bind,from=os-packages,source={re.escape(call.helper)},'
                                           rf'target=/usr/local/sbin/{re.escape(call.helper)}')
                    sections = call.sections
                    pinned = {os_packages.split_pin(w)[0] for w in sections['pin'] + sections['upgrade']}
                    self.assertTrue(sections['add'])
                    self.assertEqual([], [name for name in sections['add'] if name not in pinned])
                    self.assertTrue(call.stage_from and '@sha256:' in call.stage_from, call.stage_from)

    def test_the_deps_image_fetches_the_gate_images_yq(self):
        """Debian's yq package is another program, so Dockerfile.deps fetches mikefarah's release as
        Dockerfile.gate does: the same version and the same checksum for each architecture."""
        def yq(name):
            text = (ROOT / 'scripts/sandbox' / name).read_text()
            sums = {arch: re.search(r'yq_sum=([0-9a-f]{64})', block).group(1)
                    for arch, block in re.findall(r'\b(arm64|amd64)\)(.*?);;', text, re.DOTALL)}
            return re.findall(r'mikefarah/yq/releases/download/(v[\d.]+)/', text), sums
        deps, gate = yq('Dockerfile.deps'), yq('Dockerfile.gate')
        self.assertEqual(['v4.54.1'], deps[0])
        self.assertEqual(deps[0], gate[0])
        self.assertEqual({'arm64', 'amd64'}, set(deps[1]))
        self.assertEqual(deps[1], gate[1])

    def test_the_jdk_image_default_is_the_backend_builder(self):
        """os-package-pins.py resolves Dockerfile.jdk's pins against FROM ${JDK_IMAGE}'s default, and
        deps-sandbox.sh builds it from docker/Dockerfile.backend's builder: the two must be one image."""
        builder = re.search(r'^FROM (eclipse-temurin:\S+@sha256:[0-9a-f]{64}) AS builder$',
                            (ROOT / 'docker/Dockerfile.backend').read_text(), re.MULTILINE).group(1)
        for name in ('Dockerfile.jdk', 'Dockerfile.gate'):
            with self.subTest(dockerfile=name):
                self.assertIn(f'ARG JDK_IMAGE={builder}\n', (ROOT / 'scripts/sandbox' / name).read_text())


class ParserTests(unittest.TestCase):
    DOCKERFILE = textwrap.dedent('''\
        FROM alpine:3.24@sha256:{a} AS base
        # RUN sh /usr/local/sbin/apk-install-aged.sh v3.24 --pin ignored=1
        RUN --mount=type=bind,source=os-packages/apk-install-aged.sh,target=/usr/local/sbin/apk-install-aged.sh \\
            sh /usr/local/sbin/apk-install-aged.sh v3.24 \\
              --add gettext \\
              --pin gettext=1.0-r0 libintl=1.0-r0 \\
              --upgrade tzdata=2026f-r0 && \\
            addgroup -S app
        FROM debian:13-slim@sha256:{b}
        RUN --mount=type=bind,source=os-packages/apt-install-aged.sh,target=/usr/local/sbin/apt-install-aged.sh \\
            sh /usr/local/sbin/apt-install-aged.sh debian 20261023T000000Z --download \\
              --pin libbrotli1=1.1.0-2+deb13u1
        ''').format(a='a' * 64, b='b' * 64)

    def test_calls_sections_and_stages(self):
        calls = os_packages.helper_calls(self.DOCKERFILE)
        self.assertEqual(['apk-install-aged.sh', 'apt-install-aged.sh'], [c.helper for c in calls])
        apk, apt = calls
        self.assertEqual(['v3.24'], apk.sections['positional'])
        self.assertEqual(['gettext'], apk.sections['add'])
        self.assertEqual(['tzdata=2026f-r0'], apk.sections['upgrade'])
        self.assertTrue(apk.stage_from.startswith('alpine:3.24@'))
        self.assertEqual(['--download'], apt.sections['flags'])
        self.assertTrue(apt.stage_from.startswith('debian:13-slim@'))

    def test_a_stage_from_an_arg_resolves_to_its_default(self):
        text = textwrap.dedent('''\
            ARG BASE=alpine:3.24@sha256:{a}
            FROM ${{BASE}}
            RUN --mount=type=bind,from=os-packages,source=apk-install-aged.sh,target=/usr/local/sbin/apk-install-aged.sh \\
                sh /usr/local/sbin/apk-install-aged.sh v3.24 --add gettext --pin gettext=1.0-r0
            ''').format(a='a' * 64)
        self.assertEqual('alpine:3.24@sha256:' + 'a' * 64, os_packages.helper_calls(text)[0].stage_from)
        self.assertIsNone(os_packages.helper_calls(text.replace('ARG BASE=alpine', 'ARG OTHER=alpine'))[0].stage_from)

    def test_entries_mark_upgrades(self):
        entries = gate.parse_dockerfile(self.DOCKERFILE, 'Dockerfile')
        os_entries = {(e.ecosystem, e.name, e.version, e.path) for e in entries if e.ecosystem != 'oci'}
        self.assertEqual({('apk', 'v3.24/gettext', '1.0-r0', 'Dockerfile'),
                          ('apk', 'v3.24/libintl', '1.0-r0', 'Dockerfile'),
                          ('apk', 'v3.24/tzdata', '2026f-r0', 'Dockerfile (upgrade)'),
                          ('deb', 'debian/libbrotli1', '1.1.0-2+deb13u1', 'Dockerfile')}, os_entries)
        implied = os_packages.implied_base(entries, gate.major, gate.Entry)
        self.assertEqual({('apk', 'v3.24/tzdata', '2026.base-image')}, {(e.ecosystem, e.name, e.version) for e in implied})

    def test_rewrite_replaces_only_the_arguments(self):
        call = os_packages.helper_calls(self.DOCKERFILE)[0]
        text = pins_tool.rewrite(self.DOCKERFILE, call, ['v3.24'],
                                 {'add': ['gettext'], 'pin': ['gettext=1.1-r0', 'libintl=1.1-r0'], 'upgrade': []})
        self.assertIn('sh /usr/local/sbin/apk-install-aged.sh v3.24 \\\n      --add gettext \\\n'
                      '      --pin gettext=1.1-r0 libintl=1.1-r0 && \\\n    addgroup -S app', text)
        self.assertNotIn('tzdata', text)
        self.assertEqual(self.DOCKERFILE.split('FROM debian')[1], text.split('FROM debian')[1])


class AgeGateTests(unittest.TestCase):
    """check-dependency-age.py over a throwaway repository whose Dockerfile pins OS packages."""

    LINE = ('FROM alpine:3.24@sha256:' + 'a' * 64 + '\n'
            'RUN --mount=type=bind,source=os-packages/apk-install-aged.sh,target=/usr/local/sbin/apk-install-aged.sh \\\n'
            '    sh /usr/local/sbin/apk-install-aged.sh v3.24{args}\n')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'repo'
        self.root.mkdir()
        for args in (['init', '-q', '-b', 'main'], ['config', 'user.email', 't@example.invalid'], ['config', 'user.name', 't']):
            subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True)
        self.write(' --upgrade tzdata=2026e-r0')
        subprocess.run(['git', '-C', str(self.root), 'add', '-A'], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(self.root), 'commit', '-q', '-m', 'base'], check=True, capture_output=True)
        self.fixture = {'times': {}, 'osv': {}}

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, args: str) -> None:
        (self.root / 'Dockerfile').write_text(self.LINE.format(args=args))

    def gate(self) -> tuple[int, str]:
        fixture = Path(self.tmp.name) / 'fixture.json'
        fixture.write_text(json.dumps(self.fixture))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = gate.main(['--root', str(self.root), '--base', 'HEAD', '--today', '2026-11-06',
                              '--lookup-fixture', str(fixture), '--cache', str(Path(self.tmp.name) / 'cache.json')])
        return code, output.getvalue()

    def test_a_young_upgrade_fails_and_an_aged_one_passes(self):
        self.write(' --upgrade tzdata=2026f-r0')
        self.fixture['times']['apk:v3.24/tzdata@2026f-r0'] = '2026-11-05T00:00:00Z Alpine APKINDEX t:'
        code, out = self.gate()
        self.assertEqual(1, code, out)
        self.assertIn('apk:v3.24/tzdata@2026f-r0', out)
        self.assertIn('routine updates wait 7 days', out)
        self.assertNotIn('new package name', out)  # an --upgrade changes a package the base image has
        self.fixture['times']['apk:v3.24/tzdata@2026f-r0'] = '2026-10-20T00:00:00Z Alpine APKINDEX t:'
        code, out = self.gate()
        self.assertEqual(0, code, out)

    def test_a_new_pinned_name_needs_review(self):
        self.write(' --add su-exec --pin su-exec=0.3-r0 --upgrade tzdata=2026e-r0')
        self.fixture['times']['apk:v3.24/su-exec@0.3-r0'] = '2025-10-08T00:00:00Z Alpine APKINDEX t:'
        code, out = self.gate()
        self.assertEqual(1, code, out)
        self.assertIn('apk:v3.24/su-exec@0.3-r0 (Dockerfile): new package name', out)

    def test_an_unanswerable_lookup_is_indeterminate(self):
        self.write(' --upgrade tzdata=2026f-r0')
        code, out = self.gate()
        self.assertEqual(2, code, out)
        self.assertIn('[indeterminate] apk:v3.24/tzdata@2026f-r0', out)


def apkindex(*packages: dict) -> str:
    blocks = []
    for package in packages:
        lines = [f'P:{package["P"]}', f'V:{package["V"]}', f't:{package.get("t", 1700000000)}']
        lines += [f'{key}:{package[key]}' for key in ('D', 'p', 'k') if key in package]
        blocks.append('\n'.join(lines))
    return '\n\n'.join(blocks) + '\n\n'


class LookupTests(unittest.TestCase):
    def test_apk_time_reads_the_index_build_time(self):
        index = apkindex({'P': 'tzdata', 'V': '2026f-r0', 't': 1793750400})
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:gz') as tar:
            data = index.encode()
            info = tarfile.TarInfo('APKINDEX')
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        urls = []

        def get(candidates, min_bytes=2, extra=None):
            urls.append(candidates[0])
            return archive.getvalue()

        stamp, source = os_packages.apk_time(gate.Entry('apk', 'v3.24/tzdata', '2026f-r0'), get, {})
        self.assertEqual(dt.datetime(2026, 11, 4, tzinfo=dt.UTC), stamp)
        self.assertIn('APKINDEX t:', source)
        self.assertEqual('https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/APKINDEX.tar.gz', urls[0])
        with self.assertRaises(LookupError):
            os_packages.apk_time(gate.Entry('apk', 'v3.24/tzdata', '2026e-r0'), get, {})

    def test_deb_time_uses_the_earliest_amd64_first_seen(self):
        debian = {'result': [{'architecture': 'amd64', 'hash': 'h1'}, {'architecture': 'arm64', 'hash': 'h2'}],
                  'fileinfo': {'h1': [{'first_seen': '20261020T090000Z'}, {'first_seen': '20261022T090000Z'}],
                               'h2': [{'first_seen': '20261001T000000Z'}]}}
        stamp, source = os_packages.deb_time(gate.Entry('deb', 'debian/xz-utils', '5.4.1-1+deb12u2'),
                                             lambda urls, **_: debian)
        self.assertEqual(dt.datetime(2026, 10, 20, 9, tzinfo=dt.UTC), stamp)
        self.assertEqual('snapshot.debian.org first_seen', source)
        ubuntu = {'entries': [
            {'binary_package_version': '8.18.0-1ubuntu2.8', 'date_published': '2026-10-21T10:00:00+00:00',
             'distro_arch_series_link': 'https://api.launchpad.net/1.0/ubuntu/resolute/amd64'},
            {'binary_package_version': '8.18.0-1ubuntu2.8', 'date_published': '2026-10-01T10:00:00+00:00',
             'distro_arch_series_link': 'https://api.launchpad.net/1.0/ubuntu/resolute/riscv64'}]}
        stamp, source = os_packages.deb_time(gate.Entry('deb', 'ubuntu/curl', '8.18.0-1ubuntu2.8'),
                                             lambda urls, **_: ubuntu)
        self.assertEqual(dt.datetime(2026, 10, 21, 10, tzinfo=dt.UTC), stamp)
        self.assertEqual('Launchpad date_published', source)

    def test_rpm_time_is_the_later_of_file_and_build_time(self):
        repomd = (b'<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary">'
                  b'<location href="repodata/x-primary.xml.gz"/></data></repomd>')
        primary = gzip.compress(
            b'<metadata xmlns="http://linux.duke.edu/metadata/common"><package type="rpm"><name>expat</name>'
            b'<arch>x86_64</arch><version epoch="0" ver="2.5.0" rel="6.el9_8.7"/>'
            b'<time file="1792540067" build="1792485711"/></package></metadata>')

        def get(urls, min_bytes=2, extra=None):
            return repomd if urls[0].endswith('repomd.xml') else primary

        stamp, source = os_packages.rpm_time(gate.Entry('rpm', 'el9/expat', '2.5.0-6.el9_8.7'), get, {})
        self.assertEqual(dt.datetime.fromtimestamp(1792540067, dt.UTC), stamp)
        self.assertIn('primary.xml', source)


class ProposalTests(unittest.TestCase):
    BASE = os_packages.parse_apk_database(apkindex(
        {'P': 'musl', 'V': '1.2.6-r3', 'p': 'so:libc.musl-x86_64.so.1=1'},
        {'P': 'tzdata', 'V': '2026e-r0'}, {'P': 'busybox', 'V': '1.37.0-r31', 'p': '/bin/sh'}))
    INDEX = os_packages.parse_apk_database(apkindex(
        {'P': 'musl', 'V': '1.2.6-r3', 'p': 'so:libc.musl-x86_64.so.1=1'},
        {'P': 'tzdata', 'V': '2026f-r0', 't': 1793750400},
        {'P': 'busybox', 'V': '1.37.0-r32', 't': 1790000000, 'p': '/bin/sh'},
        {'P': 'gettext', 'V': '1.0-r0', 'D': 'so:libc.musl-x86_64.so.1 so:libintl.so.8 /bin/sh', 't': 1776000000},
        {'P': 'libintl', 'V': '1.0-r0', 'p': 'so:libintl.so.8=8.4.0', 't': 1776000000}))

    def test_closure_pins_what_the_base_lacks_and_upgrades_only_aged_versions(self):
        now = dt.datetime(2026, 11, 6, tzinfo=dt.UTC)

        def aged(_name, old, new, built):
            return pins_tool.aged(now, old, new, dt.datetime.fromtimestamp(int(built), dt.UTC))

        pins, upgrades, problems = os_packages.apk_proposal(['gettext'], self.BASE, self.INDEX, aged)
        self.assertEqual(['gettext=1.0-r0', 'libintl=1.0-r0'], pins)
        self.assertEqual(['busybox=1.37.0-r32'], upgrades)  # tzdata 2026f is two days old: the base version stays
        self.assertEqual([], problems)

    def test_a_young_addition_is_a_problem(self):
        now = dt.datetime(2026, 4, 13, tzinfo=dt.UTC)

        def aged(_name, old, new, built):
            return pins_tool.aged(now, old, new, dt.datetime.fromtimestamp(int(built), dt.UTC))

        _, _, problems = os_packages.apk_proposal(['gettext'], self.BASE, self.INDEX, aged)
        self.assertTrue(any('gettext=1.0-r0 has not aged' in p for p in problems), problems)

    def test_debian_versions_compare_as_dpkg_does(self):
        # The fluentbit stage once resolved against a snapshot whose security pocket did not answer and
        # proposed libbrotli1 1.1.0-2+b7, the vulnerable build the deb13u1 pin replaces.
        self.assertEqual(-1, os_packages.debian_compare('1.1.0-2+b7', '1.1.0-2+deb13u1'))
        self.assertEqual(1, os_packages.debian_compare('1:2.53.0-1', '2.60-1'))
        self.assertEqual(-1, os_packages.debian_compare('1.0~rc1-1', '1.0-1'))
        self.assertEqual(0, os_packages.debian_compare('1.0', '1.0-0'))

    def test_a_pin_never_moves_back(self):
        pins, kept = os_packages.never_back(['libbrotli1=1.1.0-2+b7', 'libcurl4t64=8.14.1-2+deb13u8'],
                                            {'libbrotli1': '1.1.0-2+deb13u1', 'libcurl4t64': '8.14.1-2+deb13u7'})
        self.assertEqual(['libbrotli1=1.1.0-2+deb13u1', 'libcurl4t64=8.14.1-2+deb13u8'], pins)
        self.assertEqual(['libbrotli1'], kept)

    def test_snapshots_are_taken_a_full_major_wait_ago(self):
        self.assertEqual('20261023T000000Z', pins_tool.snapshot_now(dt.datetime(2026, 11, 6, 15, tzinfo=dt.UTC)))

    def test_apt_resolution_runs_in_the_sandbox_behind_the_egress_proxy(self):
        """The base image's apt resolves through scripts/deps-sandbox.sh --network registries (the
        allowlisting HTTPS proxy), never on Docker's default network, over HTTPS to the snapshot."""
        call = os_packages.helper_calls(ParserTests.DOCKERFILE)[1]
        image = 'debian@sha256:' + 'c' * 64
        seen = []

        def run(command, **_kwargs):
            seen.append(command)
            return subprocess.CompletedProcess(command, 0, 'pin libbrotli1=1.1.0-2+deb13u1\n', '')

        with mock.patch.object(pins_tool, 'amd64_reference', lambda _reference: image), \
                mock.patch.object(pins_tool.subprocess, 'run', run):
            positional, sections, problems = pins_tool.propose_apt(call, ROOT, dt.datetime(2026, 11, 6, 15, tzinfo=dt.UTC))
        self.assertEqual([], problems)
        self.assertEqual(['libbrotli1=1.1.0-2+deb13u1'], sections['pin'])
        self.assertEqual(['debian', '20261106T000000Z'], positional)
        [command] = seen
        self.assertEqual(['bash', str(ROOT / 'scripts/deps-sandbox.sh')], command[:2])
        options, helper = command[:command.index('--')], command[command.index('--') + 1:]
        pairs = list(itertools.pairwise(options))
        self.assertIn(('--network', 'registries'), pairs)
        self.assertIn(('--base-image', image), pairs)
        self.assertIn(('--platform', 'linux/amd64'), pairs)
        self.assertIn(('--mount', f'{ROOT / "selfhost/os-packages/apt-install-aged.sh"}:/usr/local/sbin/apt-install-aged.sh:ro'),
                      pairs)
        self.assertTrue(any(a == '--mount' and b.endswith(':/etc/ssl/certs/ca-certificates.crt:ro') for a, b in pairs))
        self.assertEqual(['sh', '/usr/local/sbin/apt-install-aged.sh', 'debian', '20261023T000000Z', '--https',
                          '--download', '--resolve', 'libbrotli1'], helper)


def docker_ready() -> bool:
    return bool(shutil.which('docker')) and subprocess.run(['docker', 'info'], capture_output=True,
                                                           check=False).returncode == 0


@unittest.skipUnless(docker_ready(), 'needs a running Docker daemon')
class DnfHelperTests(unittest.TestCase):
    """dnf-upgrade-aged.sh in the pinned Percona base (linux/amd64)."""

    def test_metadata_that_does_not_load_is_indeterminate_not_a_kept_base_version(self):
        base = re.search(r'^FROM (percona/\S+@sha256:[0-9a-f]{64})$', (ROOT / 'selfhost/Dockerfile.postgres').read_text(),
                         re.MULTILINE).group(1)
        helper = ROOT / 'selfhost/os-packages/dnf-upgrade-aged.sh'
        result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--user', '0', '-e', 'DNF_METADATA_BACKOFF=0',
                                 '--entrypoint', 'sh', '-v', f'{helper}:/h.sh:ro', pins_tool.amd64_reference(base),
                                 '/h.sh', 'el9', '--upgrade', 'expat=2.5.0-6.el9_8.7'],
                                capture_output=True, text=True, timeout=900, check=False)
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertIn('metadata did not load', result.stderr)
        self.assertNotIn('keeping the base image', result.stderr)


@unittest.skipUnless(docker_ready(), 'needs a running Docker daemon and the Alpine index')
class ApkHelperTests(unittest.TestCase):
    """apk-install-aged.sh in the release images' pinned Alpine base (linux/amd64)."""

    @classmethod
    def setUpClass(cls):
        base = re.search(r'^FROM (alpine:3\.24@sha256:[0-9a-f]{64})$', (ROOT / 'selfhost/Dockerfile.frontend').read_text(),
                         re.MULTILINE).group(1)
        cls.image = pins_tool.amd64_reference(base)
        call = os_packages.helper_calls((ROOT / 'docker/Dockerfile.backend').read_text())[1]
        cls.closure = call.sections['pin']

    def run_helper(self, *args: str) -> subprocess.CompletedProcess:
        helper = ROOT / 'selfhost/os-packages/apk-install-aged.sh'
        return subprocess.run(['docker', 'run', '--rm', '-v', f'{helper}:/h.sh:ro', self.image, 'sh', '/h.sh', *args],
                              capture_output=True, text=True, timeout=600, check=False)

    def test_the_backend_closure_installs(self):
        result = self.run_helper('v3.24', '--add', 'gettext', 'su-exec', '--pin', *self.closure)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_an_index_that_does_not_update_is_indeterminate_not_a_policy_failure(self):
        helper = ROOT / 'selfhost/os-packages/apk-install-aged.sh'
        result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '-e', 'APK_UPDATE_BACKOFF=0',
                                 '-v', f'{helper}:/h.sh:ro', self.image, 'sh', '/h.sh', 'v3.24', '--add', 'su-exec',
                                 '--pin', *self.closure], capture_output=True, text=True, timeout=600, check=False)
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertIn('index did not update', result.stderr)

    def test_an_unpinned_dependency_fails(self):
        result = self.run_helper('v3.24', '--add', 'gettext', '--pin', 'gettext=' + dict(
            os_packages.split_pin(p) for p in self.closure)['gettext'])
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn('neither the base image', result.stderr)

    def test_a_vanished_addition_fails_and_a_vanished_upgrade_keeps_the_base(self):
        result = self.run_helper('v3.24', '--add', 'su-exec', '--pin', 'su-exec=0.0.1-r0')
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn('base lacks su-exec', result.stderr)
        result = self.run_helper('v3.24', '--upgrade', 'busybox=0.0.1-r0')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("keeping the base image's busybox=", result.stderr)

    def test_misplaced_pins_and_a_wrong_branch_fail(self):
        self.assertIn('belongs under --upgrade', self.run_helper('v3.24', '--pin', 'busybox=1-r0').stderr)
        self.assertIn('belongs under --pin', self.run_helper('v3.24', '--upgrade', 'su-exec=0.3-r0').stderr)
        result = self.run_helper('v3.23')
        self.assertEqual(1, result.returncode)
        self.assertIn('pins are for v3.23', result.stderr)


@unittest.skipUnless(docker_ready(), 'needs a running Docker daemon')
class AptHelperTests(unittest.TestCase):
    """apt-install-aged.sh --https: the snapshot over HTTPS, through HTTPS_PROXY (the sandbox's proxy
    admits only CONNECT to port 443), in the fluentbit stage's pinned Debian base, with no network."""

    def test_https_points_every_snapshot_source_at_https_and_apt_at_the_proxy(self):
        base = re.search(r'^FROM (debian:13-slim@sha256:[0-9a-f]{64}) AS', (ROOT / 'selfhost/Dockerfile.fluentbit').read_text(),
                         re.MULTILINE).group(1)
        helper = ROOT / 'selfhost/os-packages/apt-install-aged.sh'
        probe = ('sh /h.sh debian 20261023T000000Z --https --resolve curl >/dev/null 2>&1; '
                 'cat /etc/apt/sources.list.d/snapshot-* /etc/apt/apt.conf.d/90apt-install-aged-proxy')
        result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '-e', 'HTTPS_PROXY=http://egress-proxy:3128',
                                 '-v', f'{helper}:/h.sh:ro', base, 'sh', '-c', probe],
                                capture_output=True, text=True, timeout=600, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        uris = re.findall(r'^URIs: (\S+)', result.stdout, re.MULTILINE)
        self.assertTrue(uris, result.stdout)
        self.assertTrue(all(uri.startswith('https://snapshot.debian.org/archive/') for uri in uris), uris)
        self.assertIn('Acquire::https::Proxy "http://egress-proxy:3128";', result.stdout)

    def test_ubuntu_ports_install_exact_pins_from_the_live_mirror_and_never_resolve(self):
        """snapshot.ubuntu.com keeps no ubuntu-ports (HTTP 401 for every ports path, 2026-11-06), so a
        source build on an arm64 host (the backend builder, deps-sandbox.sh --jdk) installs the exact
        pins from the live ports mirror, with the same exact-version check; resolving still refuses."""
        base = re.search(r'^FROM (eclipse-temurin:\S+@sha256:[0-9a-f]{64}) AS builder$',
                         (ROOT / 'docker/Dockerfile.backend').read_text(), re.MULTILINE).group(1)
        helper = ROOT / 'selfhost/os-packages/apt-install-aged.sh'

        def run(*args):
            return subprocess.run(['docker', 'run', '--rm', '--platform', 'linux/arm64', '--network', 'none',
                                   '-v', f'{helper}:/h.sh:ro', base, 'sh', '/h.sh', *args],
                                  capture_output=True, text=True, timeout=600, check=False)

        installing = run('ubuntu', '20261023T000000Z', '--add', 'git', '--pin', 'git=1:2.53.0-1ubuntu1.1')
        self.assertEqual(1, installing.returncode, installing.stderr)
        self.assertIn('installs the exact pins from the live mirror only', installing.stderr)
        self.assertNotIn('has no snapshot equivalent', installing.stderr)
        self.assertIn('git=1:2.53.0-1ubuntu1.1 is in neither the live mirror nor', installing.stderr)  # no network here
        resolving = run('ubuntu', '20261023T000000Z', '--resolve', 'git')
        self.assertEqual(1, resolving.returncode, resolving.stderr)
        self.assertIn('has no snapshot equivalent', resolving.stderr)


if __name__ == '__main__':
    unittest.main()
