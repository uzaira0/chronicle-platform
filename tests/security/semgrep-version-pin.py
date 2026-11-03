#!/usr/bin/env python3
"""The engineering gate and the toolchain checker refuse any Semgrep but the manifest pin.

Semgrep versions differ in what the repo rules match: 1.155.0 reports nothing on a raw
SQLException rethrow that 1.182.0 reports, so an unpinned scanner made the engineering job pass
on one host and fail on another. A fake `semgrep` first on PATH stands in for each version.
"""

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def manifest_pin():
    completed = subprocess.run(['yq', '-r', '.semgrep', str(ROOT / 'toolchain-manifest.yaml')],
                               capture_output=True, text=True, check=True)
    pin = completed.stdout.strip()
    if not pin or pin == 'null':
        raise SystemExit('toolchain-manifest.yaml does not pin semgrep')
    return pin


def fake_semgrep(directory, version):
    path = Path(directory) / 'semgrep'
    path.write_text(f'#!/bin/sh\necho {version}\n', encoding='utf-8')
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return {**os.environ, 'PATH': f'{directory}{os.pathsep}{os.environ["PATH"]}'}


def gate(env):
    return subprocess.run(['bash', '-c', 'source "$1"; require_semgrep_pin', 'gate', str(ROOT / 'scripts/local-ci.sh')],
                          cwd=ROOT, env=env, capture_output=True, text=True, check=False)


def toolchain(env):
    return subprocess.run(['bash', str(ROOT / 'scripts/verify-toolchain.sh')],
                          cwd=ROOT, env=env, capture_output=True, text=True, check=False)


def main():
    pin = manifest_pin()
    problems = []
    with tempfile.TemporaryDirectory() as directory:
        env = fake_semgrep(directory, '1.155.0')
        refused = gate(env)
        if refused.returncode == 0 or f'not the manifest pin {pin}' not in refused.stderr:
            problems.append(f'engineering gate accepted semgrep 1.155.0: {refused.returncode} {refused.stderr.strip()}')
        drift = toolchain(env)
        if '[fail] semgrep is 1.155.0' not in drift.stderr:
            problems.append('verify-toolchain.sh did not report semgrep 1.155.0 as drift')

        env = fake_semgrep(directory, pin)
        accepted = gate(env)
        if accepted.returncode != 0:
            problems.append(f'engineering gate refused the pinned semgrep {pin}: {accepted.stderr.strip()}')
        if f'[ok] semgrep -> {pin}' not in toolchain(env).stdout:
            problems.append(f'verify-toolchain.sh did not accept the pinned semgrep {pin}')
    if problems:
        print('\n'.join(problems), file=sys.stderr)
        return 1
    print(f'semgrep pin {pin}: enforced by the engineering gate and verify-toolchain.sh')
    return 0


if __name__ == '__main__':
    sys.exit(main())
