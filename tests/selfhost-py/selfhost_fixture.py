"""Copy the publisher's operator inventory into isolated test installations."""

from dataclasses import dataclass
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_POSTGRES_PASSWORD = "synthetic-test-password"
FIXTURE_POSTGRES_APP_PASSWORD = "synthetic-app-test-password"


def run_cert_init(tls_dir, *, script=ROOT / "selfhost/cert-init.sh", base=None, timeout=60, **settings):
    """Run cert-init.sh on this host into tls_dir. It runs as root in its container; a no-op chown stands in
    for the group-0 ownership step, the only one that needs root. Defaults: internal dashboard, behind proxy."""
    tls_dir = Path(tls_dir)
    commands = tls_dir.parent / (tls_dir.name + "-commands")
    commands.mkdir(exist_ok=True)
    (commands / "chown").write_text("#!/bin/sh\nexit 0\n")
    (commands / "chown").chmod(0o755)
    environment = dict(os.environ if base is None else base, DASHBOARD_EXPOSURE="internal", TLS_MODE="behind-proxy",
                       POSTGRES_TLS_DIR="", BACKEND_TLS_DIR="", MONITORING_ENABLED="false")
    environment.update(settings, TLS_DIR=str(tls_dir), PATH=str(commands) + os.pathsep + os.environ["PATH"])
    return subprocess.run(["bash", str(script)], env=environment, capture_output=True, text=True, timeout=timeout)


def bundle_fixture_files(builder):
    return set(builder['operator_files']()) | {
        path.relative_to(ROOT / 'selfhost').as_posix()
        for directory in builder['BUNDLE_DIRECTORIES']
        for path in (ROOT / 'selfhost' / directory).rglob('*') if path.is_file()
    }


def copy_selfhost_fixture(destination, *, preserve_existing=False):
    destination = Path(destination)
    with patch.object(sys, 'path', sys.path[:]):
        builder = runpy.run_path(str(ROOT / 'scripts/build-selfhost-release.py'))
    for name in builder['operator_files']():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not preserve_existing or not target.exists():
            shutil.copy2(ROOT / 'selfhost' / name, target)


@dataclass
class MobileCanaryFixture:
    path: Path
    requests: dict
    credential: str


def mobile_canary_fixture(directory, public):
    from chronicle_ops.mobile_canary import API_KEY_HEADER, CANARY_ROUTES
    from chronicle_ops.receipts import write_json
    credential = 'synthetic-' + uuid.uuid4().hex
    base = public + '/chronicle/v4/study/' + str(uuid.uuid4()) + '/participant/smoke-' + uuid.uuid4().hex
    requests = {name: dict(url=base + suffix, body=[{'synthetic': True}], headers={API_KEY_HEADER: credential})
                for name, suffix in CANARY_ROUTES.items()}
    path = Path(directory) / 'mobile-canary.json'
    write_json(path, dict(requests, credential=credential))
    return MobileCanaryFixture(path=path, requests=requests, credential=credential)


@dataclass
class RotationFixture:
    host: Path
    commands: Path
    environment: dict


def rotation_fixture(root):
    host = root / 'selfhost'
    copy_selfhost_fixture(host)
    (host / '.env').write_text('COMPOSE_PROJECT_NAME=fixture\nCOMPOSE_FILE=overlays/backups.yml\n'
                             'ENABLE_ENCRYPTION=true\nPOSTGRES_PASSWORD=' + FIXTURE_POSTGRES_PASSWORD + '\n'
                             'POSTGRES_APP_PASSWORD=' + FIXTURE_POSTGRES_APP_PASSWORD + '\n'
                             'METRICS_PASSWORD=synthetic-metrics-password\n')
    (host / '.env').chmod(0o600)
    commands = root / 'commands'
    shutil.copytree(ROOT / 'tests/security/fixtures/selfhost-secret-rotation/commands', commands)
    for command in commands.iterdir():
        command.chmod(0o755)
    environment = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'], STATE_ROOT=str(host),
                       SELFHOST_ROTATION_TEST_REAL_PYTHON=sys.executable,
                       SELFHOST_ROTATION_TEST_ARGS_LOG=str(root / 'args'))
    for key, content in (('OLD_POSTGRES', FIXTURE_POSTGRES_PASSWORD), ('GENERATED', 'a' * 64),
                         ('OLD_POSTGRES_APP', FIXTURE_POSTGRES_APP_PASSWORD),
                         ('DB_APP_PASSWORD', FIXTURE_POSTGRES_APP_PASSWORD),
                         ('DASHBOARD', 'synthetic-dashboard-password'), ('DB_PASSWORD', FIXTURE_POSTGRES_PASSWORD),
                         ('TDE_STATE', 'chronicle_key|chronicle_keyring')):
        fixture = root / key
        fixture.write_text(content)
        environment['SELFHOST_ROTATION_TEST_' + key + '_FILE'] = str(fixture)
    environment['SELFHOST_ROTATION_TEST_KEYRING_BACKUP_FILE'] = str(host / 'backups/keyring/chronicle-keyring.per')
    environment['SELFHOST_ROTATION_TEST_MONITORING_LOG'] = str(root / 'monitoring.log')
    return RotationFixture(host=host, commands=commands, environment=environment)


if __name__ == '__main__':
    copy_selfhost_fixture(sys.argv[1])
