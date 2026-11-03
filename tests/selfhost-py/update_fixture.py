"""Signed release fixtures shared by launcher and updater behavior tests."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess

from chronicle_ops.common import run
from chronicle_ops.release import RELEASE_SIGNER
from selfhost_fixture import copy_selfhost_fixture
from test_release import complete_update_fixture

ROOT = Path(__file__).resolve().parents[2]


@dataclass
class UpdateFixture:
    root: Path
    host: Path
    release: Path
    environment: dict
    checksum: Path
    signature: Path

    def invoke(self, *arguments):
        return run(['bash', str(self.host / 'chronicle'), 'update', *arguments],
                   env=self.environment, capture=True, stderr=subprocess.PIPE, timeout=20)


def prepare_update(root, latest, scenario="valid"):
    release = root / "releases/current"
    selfhost = release / "selfhost"
    selfhost.mkdir(parents=True)
    copy_selfhost_fixture(selfhost)
    (release / "release-manifest.json").write_text(json.dumps({"release_version": "1.2.3"}))
    state = root / 'deployment-state'; state.mkdir()
    (selfhost / '.env').write_text(f"COMPOSE_PROJECT_NAME=study-production\nCHRONICLE_STATE_DIR='{state}'\nMIN_FREE_DISK_GIB=0\n")
    (selfhost / '.env').chmod(0o600)
    environment = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                       CHRONICLE_RELEASES_URL="https://updates.invalid/latest.json",
                       CURL_FIXTURE_DIR=str(root / "http"),
                       UPDATE_EXEC_RECORD=str(root / "handoff"))
    for key in ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX"):
        environment.pop(key, None)
    run(['bash', str(ROOT / 'tests/security/lib/selfhost-fixtures.sh'), 'update-fixture', str(root), latest],
        env=environment, capture=True, stderr=subprocess.PIPE, check=True, timeout=10)
    complete_update_fixture(root, latest)
    keys = (root / "fixture-signing-key", root / "other-signing-key")
    for key in keys:
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                       check=True, capture_output=True)
    shutil.copy2(str(keys[0]) + ".pub", selfhost / "release-signing.pub")
    key = keys[scenario == "foreign-signature"]
    checksum = root / "http" / f"chronicle-selfhost-{latest}.tar.gz.sha256"
    subprocess.run(["ssh-keygen", "-Y", "sign", "-n", RELEASE_SIGNER, "-f",
                    str(key), str(checksum)], check=True, capture_output=True)
    signature = checksum.with_name(checksum.name + ".sig")
    environment.update(DOCKER_FIXTURE_ROOT=str(root), MIN_FREE_DISK_GIB="0")
    return UpdateFixture(root=root, host=selfhost, release=release, environment=environment,
                         checksum=checksum, signature=signature)

