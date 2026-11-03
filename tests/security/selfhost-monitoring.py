#!/usr/bin/env -S python3 -s
"""Local regressions for self-host runtime, release assets and the Viewer API client."""

from __future__ import annotations

import base64
import json
import yaml
import gzip
import io
import os
import re
import runpy
import shlex
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import threading
import time
import sys
import urllib.request
from contextlib import redirect_stdout
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "selfhost"))
sys.path.insert(0, str(ROOT / "tests/selfhost-py"))
from chronicle_ops.route_surface import RETIRED_PREFIXES
from host_tools import modern_bash

USERS: dict[str, dict] = {}
NEXT_ID = 1
RELEASE_FIXTURE_VERSION = "2.0.0"
RELEASE_FIXTURE_PREVIOUS_VERSION = "1.9.0"


def bash_function(path: Path, name: str) -> str:
    source = path.read_text()
    start = source.index(name + "() {")
    return source[start:source.index("\n}\n", start) + 3]


def release_image_fixture(root: Path, builder: dict) -> tuple[dict[str, str], Path, str]:
    images = {name: f"ghcr.io/example/{name}@sha256:" + "a" * 64
              for name in builder["PLACEHOLDERS"].values()}
    overlay = root / "backups.yml"
    overlay.write_text((ROOT / "selfhost/overlays/backups.yml").read_text())
    backup = images["backup"]
    config = yaml.safe_load(overlay.read_text())
    config["services"]["db-backup"]["image"] = backup
    overlay.write_text(yaml.safe_dump(config))
    return images, overlay, backup


def publisher_dry_run(version: str) -> str:
    return subprocess.run(
        ["bash", str(ROOT / "scripts/publish-images.sh"), version, "--dry-run"],
        check=True, capture_output=True, text=True, timeout=10,
    ).stdout


def test_release_drafts() -> None:
    output = publisher_dry_run(RELEASE_FIXTURE_VERSION)
    command = shlex.split(next(line for line in output.splitlines() if line.startswith("gh release create ")))
    assert "--draft" in command and "--latest=false" in command
    assert "--prerelease" not in command
    assert "gh release edit" not in output


def test_prerelease_classification() -> None:
    for version in (f"{RELEASE_FIXTURE_VERSION}-rc.1", f"v{RELEASE_FIXTURE_VERSION}-2"):
        output = publisher_dry_run(version)
        command = shlex.split(next(line for line in output.splitlines() if line.startswith("gh release create ")))
        assert "--prerelease" in command and "--latest=false" in command


def test_release_signatures() -> None:
    runpy.run_path(str(ROOT / "scripts/build-selfhost-release.py"))
    from chronicle_ops.release import RELEASE_SIGNER
    output = publisher_dry_run(RELEASE_FIXTURE_VERSION)
    command = shlex.split(next(line for line in output.splitlines() if line.startswith("ssh-keygen ")))
    checksum = f"build/releases/chronicle-selfhost-{RELEASE_FIXTURE_VERSION}.tar.gz.sha256"
    assert command[:6] == ["ssh-keygen", "-Y", "sign", "-n", RELEASE_SIGNER, "-f"]
    assert command[-1] == checksum
    release = shlex.split(next(line for line in output.splitlines() if line.startswith("gh release create ")))
    assert checksum + ".sig" in release
    assert output.index("ssh-keygen ") < output.index("gh release create ")
    with tempfile.TemporaryDirectory() as folder:
        rejected = subprocess.run(
            ["bash", str(ROOT / "scripts/publish-images.sh"), RELEASE_FIXTURE_VERSION],
            env=dict(os.environ, GHCR_TOKEN="fixture", CHRONICLE_RELEASE_SIGNING_KEY=str(Path(folder) / "missing-key")),
            capture_output=True, text=True, timeout=10)
        assert rejected.returncode != 0 and "release signing key is missing" in rejected.stderr


def test_caddy_default_log_masks_handler_ips() -> None:
    snippets = (ROOT / "selfhost/caddy/snippets.caddy").read_text()
    default = snippets.split("(chronicle_default_log) {", 1)[1].split("\n}", 1)[0]
    assert "log default {" in default and "import chronicle_log_format" in default
    encoder = snippets.split("(chronicle_log_format) {", 1)[1].split("\n}", 1)[0]
    for field in ("remote_ip", "client_ip", "request>remote_ip", "request>client_ip"):
        assert re.search(r"^\s*" + re.escape(field) + r" ip_mask 16 32$", encoder, re.MULTILINE)
    common = snippets.split("(chronicle_common) {", 1)[1].split("\n}", 1)[0]
    assert "import chronicle_log_format" in common
    for name in ("Caddyfile.split", "Caddyfile.split.local", "Caddyfile.split.tls"):
        source = (ROOT / "selfhost" / name).read_text()
        global_start = source.index("\n{\n")
        assert source.index("import snippets.caddy") < global_start
        assert "import chronicle_default_log" in source[global_start:source.index("\n}", global_start)]


def test_mobile_snat_abuse_limits() -> None:
    snippets = (ROOT / "selfhost/caddy/snippets.caddy").read_text()
    snat = snippets.split("(chronicle_snat_match) {", 1)[1].split("\n}", 1)[0]
    for field in ("remote_ip", "client_ip"):
        assert field + " {$CADDY_TRUSTED_PROXIES:127.0.0.1/32}" in snat
    zones = dict(re.findall(r"zone (\w+) \{(.*?)^\t\t\}", snippets, re.MULTILINE | re.DOTALL))
    assert re.search(r"not \{\s*import chronicle_snat_match\s*\}", zones["mobile_abuse"])
    assert "events {$RATE_LIMIT_MOBILE_ABUSE_EVENTS:200}" in zones["mobile_abuse"]
    elevated = zones["mobile_lb_abuse"]
    assert "import chronicle_mobile_rate_match" in elevated
    assert "import chronicle_snat_match" in elevated
    assert "key {client_ip}" in elevated
    assert int(re.search(r"events (\d+)", elevated)[1]) > 200


def test_edge_limiter_keys_ignore_credentials() -> None:
    snippets = (ROOT / "selfhost/caddy/snippets.caddy").read_text()
    keys = re.findall(r"^\s*key (.+)$", snippets, re.MULTILINE)
    assert keys and all(key in ("{client_ip}", "{remote_ip}") for key in keys), keys


def test_fresh_candidate_runs_setup_up_verify() -> None:
    driver_path = ROOT / "tests/smoke/selfhost_release_setup.py"
    driver = runpy.run_path(str(driver_path))
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        cli = root / "chronicle"
        cli.write_text('''#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$1" >>"$CALLS"
if printenv "$WAIVER_VARIABLE" >/dev/null; then exit 1; fi
[[ "$FAIL_AT" != "$1" ]] || exit 1
generated_settings=generated-by-setup
case "$1" in
  setup)
    [[ ! -e .env && "$COMPOSE_PROJECT_NAME" == fixture-fresh ]]
    cat >/dev/null
    printf '%s\\n' "$generated_settings" >.env ;;
  up|verify)
    [[ "$(cat .env)" == "$generated_settings" ]]
    if [[ "$1" == verify ]]; then
      [[ "${2:-}" == --dashboard-password ]]
      IFS= read -r password
      [[ "$password" == "$SMOKE_PASSWORD" ]]
    fi ;;
  *) exit 1 ;;
esac
''')
        cli.chmod(0o755)
        calls = root / "calls"
        env = dict(os.environ, COMPOSE_PROJECT_NAME="fixture-fresh", DOMAIN="public.example.org",
                   SMOKE_PASSWORD="fixture-password",
                   CALLS=str(calls), WAIVER_VARIABLE=driver["BACKUP_WAIVER_KEY"])
        env[driver["BACKUP_WAIVER_KEY"]] = "fixture-ambient-waiver"
        for monitoring, failure in (("false", ""), ("true", ""), ("true", "setup"), ("true", "up"), ("true", "verify")):
            (root / ".env").unlink(missing_ok=True)
            calls.unlink(missing_ok=True)
            result = subprocess.run([sys.executable, "-s", str(driver_path),
                                     str(root), "--install"],
                                    env=dict(env, ENABLE_MONITORING=monitoring, FAIL_AT=failure),
                                    capture_output=True, text=True, timeout=10)
            assert (result.returncode == 0) == (not failure), result.stderr
            expected = ["setup", "up", "verify"]
            if failure:
                expected = expected[:expected.index(failure) + 1]
            assert calls.read_text().splitlines() == expected
            assert (root / ".env").exists() == (failure != "setup")


def test_backup_sbom_inventory() -> None:
    sha256 = runpy.run_path(str(ROOT / "scripts/build-selfhost-release.py"))["sha256"]
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        syft = bin_dir / "syft"
        syft_real = subprocess.check_output(['bash', '-c', 'source "$1"; ensure_syft; command -v syft',
                                             'fixture', str(ROOT / 'scripts/local-ci.sh')], text=True, timeout=30).strip()
        syft.write_text('#!/bin/sh\n[ "$1" != "${FAIL_IMAGE:-}" ] || exit 7\ncase "$1" in dir:*) exec "$REAL_SYFT" "$@";; esac\n'
                        'printf \'{"spdxVersion":"SPDX-2.3","name":"%s","packages":[{"externalRefs":[{"referenceLocator":"pkg:apk/alpine/zlib@1"}]}]}\\n\' "$1"\n')
        syft.chmod(0o755)
        from chronicle_ops.images import SOURCE_IMAGES
        refs = [f"ghcr.io/example/{image.component}@sha256:" + str(index) * 64
                for index, image in enumerate(SOURCE_IMAGES, 1)]
        assets = root / "release assets"
        command = ["bash", str(ROOT / "scripts/write-image-sboms.sh"), RELEASE_FIXTURE_VERSION]
        environment = dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=str(bin_dir), REAL_SYFT=syft_real,
                           PATH=str(bin_dir) + os.pathsep + os.environ["PATH"])
        result = subprocess.run([*command, str(assets), *refs], env=environment,
                                capture_output=True, text=True, check=False, timeout=30)
        assert result.returncode == 0, result.stderr
        manifest = json.loads((assets / f"chronicle-image-sboms-{RELEASE_FIXTURE_VERSION}.json").read_text())
        assert [row["image"] for row in manifest["sboms"]] == refs
        assert {row["asset"] for row in manifest["sboms"]} == {f"chronicle-{image.component}-{RELEASE_FIXTURE_VERSION}.spdx.json" for image in SOURCE_IMAGES}
        for row in manifest["sboms"]:
            assert sha256(assets / row["asset"]) == row["sha256"]
            assert json.loads((assets / row["asset"]).read_text())["name"] == row["image"]
        frontend = next(row for row in manifest["sboms"] if row["image"] == refs[next(i for i, image in enumerate(SOURCE_IMAGES) if image.component == "frontend")])
        image_packages = json.loads((assets / frontend["asset"]).read_text())["packages"]
        assert any(ref.get("referenceLocator", "").startswith("pkg:apk/")
                   for package in image_packages for ref in package.get("externalRefs", []))
        inventory, = frontend["inventories"]
        assert sha256(assets / inventory["asset"]) == inventory["sha256"]
        packages = json.loads((assets / inventory["asset"]).read_text())["packages"]
        assert any(ref.get("referenceLocator", "").startswith("pkg:npm/")
                   for package in packages for ref in package.get("externalRefs", []))
        for line in (assets / f"chronicle-image-sboms-{RELEASE_FIXTURE_VERSION}.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            assert sha256(assets / name) == digest
        assert len(result.stdout.splitlines()) == len(refs) + 3
        failed_assets = root / 'failed assets'
        failed = subprocess.run([*command, str(failed_assets), *refs],
                                env=dict(environment, FAIL_IMAGE=refs[0]),
                                capture_output=True, text=True, timeout=30, check=False)
        assert failed.returncode != 0 and not failed.stdout
        assert not list(failed_assets.iterdir()), 'a failed image scan published release assets'
    output = publisher_dry_run(RELEASE_FIXTURE_VERSION)
    writer = next(line for line in output.splitlines() if "write-image-sboms.sh " in line)
    assert "backup_digest" in writer


def test_release_changelog() -> None:
    builder = runpy.run_path(str(ROOT / "scripts/build-selfhost-release.py"))
    with tempfile.TemporaryDirectory() as folder:
        changelog = Path(folder) / "CHANGELOG.md"
        previous = RELEASE_FIXTURE_PREVIOUS_VERSION
        prerelease = f"{RELEASE_FIXTURE_VERSION}-rc.10"
        for headings, accepted in (
            (["Unreleased", RELEASE_FIXTURE_VERSION, previous], True),
            ([prerelease, f"{RELEASE_FIXTURE_VERSION}-rc.2", previous], True),
            (["Unreleased", previous], False),
            ([RELEASE_FIXTURE_VERSION, RELEASE_FIXTURE_VERSION], False),
            ([f"{RELEASE_FIXTURE_VERSION}+build.1", f"{RELEASE_FIXTURE_VERSION}+build.2"], False),
            ([previous, RELEASE_FIXTURE_VERSION], False),
        ):
            changelog.write_text("\n".join(f"## [{version}]" for version in headings))
            target = prerelease if prerelease in headings else RELEASE_FIXTURE_VERSION
            try:
                builder["require_changelog"](changelog, target)
            except SystemExit:
                assert not accepted, headings
            else:
                assert accepted, headings


def test_public_source_equality() -> None:
    source = (ROOT / "scripts/publish.sh").read_text()
    function = "cmd_verify_source() {" + source.split("cmd_verify_source() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
    harness = """set -euo pipefail
fail() { echo "$*" >&2; exit 1; }
all_labels() { printf '%s\\n' module root; }
repo_dir() { printf '%s\\n' "$1"; }
public_tip() { printf '%s-tip\\n' "$1"; }
build_tree() { printf '%s-tree\\n' "$1"; }
git() {
  if [[ "$2" == "$MISMATCH" ]]; then printf 'stale-tree\\n';
  else printf '%s-tree\\n' "$2"; fi
}
"""
    for mismatch in ("none", "module", "root"):
        result = subprocess.run(["bash", "-c", harness + function + "cmd_verify_source\n"],
                                env=dict(os.environ, MISMATCH=mismatch), capture_output=True, text=True)
        assert (result.returncode == 0) == (mismatch == "none"), result.stderr
        if mismatch == "none":
            assert result.stdout == "root-tip\n"
    output = publisher_dry_run(RELEASE_FIXTURE_VERSION)
    assert output.index("verify-source") < output.index("docker login") < output.index("docker push")


def test_public_researcher_credentials() -> None:
    snippets = (ROOT / "selfhost/caddy/snippets.caddy").read_text()
    block = snippets.split("(chronicle_strip_researcher_bearer) {", 1)[1].split("\n}", 1)[0]
    path_pattern = re.search(r"@publicResearcherSurface path_regexp (.+)", block).group(1)
    retired = snippets.split("(chronicle_mobile) {", 1)[1].split("\n}", 1)[0]
    deny_pattern = re.search(r"path_regexp (.+)", retired).group(1)
    for prefix in RETIRED_PREFIXES:
        assert re.search(deny_pattern, prefix + "/x")
    assert "respond @chronicle_retired_api 404" in retired
    for path in ("/chronicle/v3/study/x/participants", "/chronicle/v3/permissions",
                 "/chronicle/v3/admin/x", "/chronicle/v3/organization/x",
                 "/chronicle/v3/survey/x", "/chronicle/v4/study/x"):
        assert re.search(path_pattern, path), path
    replacements = re.findall(r'request_header Cookie `([^`]+)` ""', block)
    assert replacements and "respond" not in block
    for cookie, expected in (("chronicle_auth=jwt; ol_csrf_token=x", "ol_csrf_token=x"),
                             ("ol_csrf_token=x; authorization=Bearer%20jwt", "ol_csrf_token=x"),
                             ("__Host-chronicle-form=session;\tchronicle_auth=jwt", "__Host-chronicle-form=session"),
                             ("chronicle_auth=jwt; authorization=jwt; __Host-chronicle-form=session", "__Host-chronicle-form=session"),
                             ("__Host-chronicle-form=session", "__Host-chronicle-form=session"),
                             ("other_chronicle_auth=jwt", "other_chronicle_auth=jwt")):
        for pattern in replacements:
            cookie = re.sub(pattern, "", cookie)
        assert cookie == expected, cookie
    assert "request_header @publicResearcherSurface -Authorization" in block
    assert "-Cookie" not in block
    for name in ("Caddyfile.split", "Caddyfile.split.local", "Caddyfile.split.tls"):
        public, internal = (ROOT / "selfhost" / name).read_text().split(":8081 {", 1)
        assert public.index("import chronicle_strip_researcher_bearer") < public.index("import chronicle_mobile")
        assert "import chronicle_strip_researcher_bearer" not in internal


def test_backup_probe_caches_verified_file_identity() -> None:
    from chronicle_ops import dump
    contents = runpy.run_path(str(ROOT / "tests/selfhost-py/test_restore.py"))["DUMP"]
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        last = root / "backups/last"; last.mkdir(parents=True)
        path = last / "chronicle-1.sql.gz"; path.write_bytes(gzip.compress(contents))
        dump.publish_backup(path, "chronicle", {})
        cache = root / 'cache.json'
        with patch.object(dump, "validate_dump", wraps=dump.validate_dump) as validate:
            for _ in range(2):
                assert dump.cached_verified_backup(last.parent, 'chronicle', cache, '@daily').path == path
            assert validate.call_count == 1
            with patch.object(time, "time", return_value=time.time() + dump.backup_max_age_seconds('@daily') + 1):
                try:
                    dump.cached_verified_backup(last.parent, 'chronicle', cache, '@daily')
                except dump.DumpError:
                    pass
                else:
                    raise AssertionError('cached stale backup accepted')
            path.write_bytes(b"corrupt replacement")
            try:
                dump.cached_verified_backup(last.parent, 'chronicle', cache, '@daily')
            except dump.DumpError:
                pass
            else:
                raise AssertionError('cached replaced backup accepted')
            assert validate.call_count == 2

def test_cadvisor_oom_counter(rules: dict) -> None:
    fixture = 'container_oom_events_total{name="chronicle-postgres-1"} 1'
    metric = fixture.split("{", 1)[0]
    expression = rules["container-oom"]["data"][0]["model"]["expr"]
    assert metric + '{name!=""}' in expression
    dashboard = json.loads((ROOT / "selfhost/monitoring/grafana-dashboards/containers.json").read_text())
    oom = next(panel for panel in dashboard["panels"] if "OOM" in panel["title"])
    assert metric in oom["targets"][0]["expr"]
    assert "failure_type" not in expression + oom["targets"][0]["expr"]


def test_release_signature_rejects_tampered_checksum() -> None:
    builder = runpy.run_path(str(ROOT / "scripts/build-selfhost-release.py"))
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        key = root / "fixture-key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                       check=True, capture_output=True, timeout=10)
        checksum = root / "candidate.tar.gz.sha256"
        checksum.write_text("a" * 64 + "  candidate.tar.gz\n")
        subprocess.run(["ssh-keygen", "-Y", "sign", "-n", builder["RELEASE_SIGNER"], "-f", str(key), str(checksum)],
                       check=True, capture_output=True, timeout=10)
        signature, public_key = Path(str(checksum) + ".sig"), Path(str(key) + ".pub")
        builder["verify_release_signature"](checksum, signature, public_key)
        checksum.write_text("tampered checksum\n")
        try:
            builder["verify_release_signature"](checksum, signature, public_key)
        except SystemExit:
            pass
        else:
            raise AssertionError("tampered checksum signature was accepted")


def test_release_archive_rejects_unsafe_inventory() -> None:
    builder = runpy.run_path(str(ROOT / "scripts/build-selfhost-release.py"))
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        bundle = f"chronicle-selfhost-{RELEASE_FIXTURE_VERSION}"
        archive = root / f"{bundle}.tar.gz"
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({builder["UPGRADE_FLOOR_KEY"]: builder["UPGRADE_FROM_MINIMUM"], builder["MIGRATIONS_KEY"]: {"V1__fixture.sql": "a" * 64}, "release_version": RELEASE_FIXTURE_VERSION, "source_revision": "a" * 40,
                                        "images": {"backend": "example/backend@sha256:" + "a" * 64}}))
        cli = root / "chronicle"
        cli.write_text("#!/bin/sh\nexit 0\n")
        cli.chmod(0o755)
        checksum = Path(str(archive) + ".sha256")
        for extra in (None, f"{bundle}/../outside", f"{bundle}/selfhost/.env", f"{bundle}/chronicle-server/source.kt"):
            with tarfile.open(archive, "w:gz") as source:
                builder["add_to_tar"](source, manifest, f"{bundle}/release-manifest.json", 0)
                builder["add_to_tar"](source, cli, f"{bundle}/selfhost/chronicle", 0)
                if extra:
                    builder["add_to_tar"](source, cli, extra, 0)
            checksum.write_text(f'{builder["sha256"](archive)}  {archive.name}\n')
            try:
                actual = builder["inspect_release_archive"](archive, checksum)
            except SystemExit:
                assert extra is not None
            else:
                assert extra is None
                assert actual["release_version"] == RELEASE_FIXTURE_VERSION


def test_candidate_smoke_matches_images_and_archive() -> None:
    builder = runpy.run_path(str(ROOT / "scripts/build-selfhost-release.py"))
    complete = runpy.run_path(str(ROOT / "tests/selfhost-py/test_release.py"))["complete_manifest_fixture"]
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        bundle = root / "candidate"
        host = bundle / "selfhost"
        (host / "overlays").mkdir(parents=True)
        (host / "chronicle").touch()
        (bundle / "release-manifest.json").write_text(json.dumps({"release_version": RELEASE_FIXTURE_VERSION}))
        images, overlay, backup = release_image_fixture(root, builder)
        shutil.copy2(overlay, host / 'overlays/backups.yml')
        complete(bundle, images=images)
        builder["require_smoke_images"](bundle, images, backup)
        for selected, selected_backup in ((dict(images, backend="foreign/image@sha256:" + "c" * 64), backup),
                                          (images, "foreign/backup@sha256:" + "c" * 64)):
            try:
                builder["require_smoke_images"](bundle, selected, selected_backup)
            except SystemExit:
                pass
            else:
                raise AssertionError("candidate accepted different runtime images")
        archive = root / "candidate.tar.gz"
        archive.write_bytes(b"exact downloaded candidate")
        result = root / "result.txt"
        evidence = dict(status="passed", **{builder["SMOKE_ARCHIVE_HASH_FIELD"]: builder["sha256"](archive)},
                        **builder["SMOKE_REQUIRED_EVIDENCE"])
        required = ("credential_rotation_consumers", "inode_full_recovery", "certificate_renewal")
        evidence.update(dict.fromkeys(required, "pass"))
        for field in (*required, *builder["SMOKE_REQUIRED_EVIDENCE"]):
            for changed in ({key: value for key, value in evidence.items() if key != field},
                            dict(evidence, **{field: "missing fresh-install proof"})):
                result.write_text("".join(f"{key}={value}\n" for key, value in changed.items()))
                try:
                    builder["require_smoke_result"](result, archive)
                except SystemExit:
                    pass
                else:
                    raise AssertionError(f"promotion accepted a missing or mismatched {field}")
        result.write_text("".join(f"{key}={value}\n" for key, value in evidence.items()))
        builder["require_smoke_result"](result, archive)
        archive.write_bytes(b"different archive after the drill")
        try:
            builder["require_smoke_result"](result, archive)
        except SystemExit:
            pass
        else:
            raise AssertionError("promotion accepted a different archive")


def test_release_promotion_uses_installed_key() -> None:
    builder = runpy.run_path(str(ROOT / "scripts/build-selfhost-release.py"))
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        old_key, new_key = root / "old-key", root / "new-key"
        for key in (old_key, new_key):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                           check=True, capture_output=True, timeout=10)
        images, overlay, _ = release_image_fixture(root, builder)
        cli = root / "chronicle"
        cli.write_text("#!/bin/sh\nexit 0\n")
        cli.chmod(0o755)
        archive = root / f"chronicle-selfhost-{RELEASE_FIXTURE_VERSION}.tar.gz"
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({builder["UPGRADE_FLOOR_KEY"]: builder["UPGRADE_FROM_MINIMUM"], builder["MIGRATIONS_KEY"]: {"V1__fixture.sql": "a" * 64}, "release_version": RELEASE_FIXTURE_VERSION,
                                        "source_revision": "b" * 40,
                                        "public_revision": "c" * 40, "images": images}))
        bundle = archive.name.removesuffix(".tar.gz")
        with tarfile.open(archive, "w:gz") as source:
            builder["add_to_tar"](source, manifest, f"{bundle}/release-manifest.json", 0)
            builder["add_to_tar"](source, Path(str(new_key) + ".pub"), f"{bundle}/selfhost/release-signing.pub", 0)
            builder["add_to_tar"](source, overlay, f"{bundle}/selfhost/overlays/backups.yml", 0)
            builder["add_to_tar"](source, cli, f"{bundle}/selfhost/chronicle", 0)
        Path(str(archive) + ".sha256").write_text(f'{builder["sha256"](archive)}  {archive.name}\n')

        subprocess.run(["ssh-keygen", "-Y", "sign", "-n", builder["RELEASE_SIGNER"], "-f", str(old_key),
                        str(archive) + ".sha256"], check=True, capture_output=True, timeout=10)
        result = root / "result.txt"
        evidence = dict(status="passed", **{builder["SMOKE_ARCHIVE_HASH_FIELD"]: builder["sha256"](archive)},
                        **builder["SMOKE_REQUIRED_EVIDENCE"])
        result.write_text("".join(f"{key}={value}\n" for key, value in evidence.items()))
        bin_dir = root / "bin"
        bin_dir.mkdir()
        shutil.copy2(ROOT / 'tests/security/fixtures/selfhost-promotion/gh', bin_dir / 'gh')
        (bin_dir / 'gh').chmod(0o700)
        for name, command in {
            "git": '#!/bin/sh\ncase "$*" in *ls-remote*) exit 0;; *) printf "fixture-repository\\n";; esac\n',
            "docker": '#!/bin/sh\n[ "$1 $2" = "manifest inspect" ] && [ -d "$DOCKER_CONFIG" ] && [ ! -f "$DOCKER_CONFIG/config.json" ]\n',
        }.items():
            executable = bin_dir / name
            executable.write_text(command)
            executable.chmod(0o755)
        env = dict(os.environ, ASSETS=str(root), RELEASE_CATALOG="[[]]",
                   PROMOTED=str(root / "promoted"), PATH=str(bin_dir) + os.pathsep + os.environ["PATH"])
        def promote():
            return subprocess.run(["bash", str(ROOT / "scripts/publish-images.sh"), RELEASE_FIXTURE_VERSION, '--promote', str(result)],
                                 env=env, capture_output=True, text=True, timeout=15)
        for key, accepted in ((new_key, False), (old_key, True)):
            env["CHRONICLE_RELEASE_VERIFY_KEY"] = str(key) + ".pub"
            promoted = promote()
            assert (promoted.returncode == 0) == accepted, promoted.stderr
        arguments = (root / "promoted").read_text().splitlines()
        assert arguments[2] == RELEASE_FIXTURE_VERSION and '--latest=true' in arguments
        from chronicle_ops.update import version_key
        newer = str(version_key(RELEASE_FIXTURE_VERSION)[0] + 1) + '.0.0'
        env['RELEASE_CATALOG'] = json.dumps([[dict(tag_name=newer, draft=False, prerelease=False)]])
        assert promote().returncode == 0
        assert '--latest=false' in (root / "promoted").read_text().splitlines()
        with patch.dict(os.environ, CHRONICLE_RELEASE_VERIFY_KEY=str(old_key) + ".pub"):
            output = publisher_dry_run(RELEASE_FIXTURE_VERSION)
        assert f"ssh-keygen -lf {old_key}.pub -E sha256" in output

def test_public_release_tag_matches_source() -> None:
    builder = runpy.run_path(str(ROOT / "scripts/build-selfhost-release.py"))
    revision = "a" * 40
    ref = f"refs/tags/{RELEASE_FIXTURE_VERSION}"
    for refs, accepted in (("", True), (f"{revision}\t{ref}\n", True),
                           (f"{'b' * 40}\t{ref}\n{revision}\t{ref}^{{}}\n", True),
                           (f"{'b' * 40}\t{ref}\n", False),
                           (f"{revision}\t{ref}\n{'b' * 40}\t{ref}^{{}}\n", False)):
        with patch.object(builder["subprocess"], "run", return_value=subprocess.CompletedProcess([], 0, refs)):
            try:
                builder["require_public_release_tag"]("fixture-remote", RELEASE_FIXTURE_VERSION, revision)
            except SystemExit:
                assert not accepted
            else:
                assert accepted


def test_release_images_require_anonymous_registry_access() -> None:
    builder = runpy.run_path(str(ROOT / "scripts/build-selfhost-release.py"))
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        archive = root / "candidate.tar.gz"
        manifest = root / "release-manifest.json"
        images, overlay, backup = release_image_fixture(root, builder)
        manifest.write_text(json.dumps({builder["UPGRADE_FLOOR_KEY"]: builder["UPGRADE_FROM_MINIMUM"], builder["MIGRATIONS_KEY"]: {"V1__fixture.sql": "a" * 64}, "images": images}))
        with tarfile.open(archive, "w:gz") as source:
            builder["add_to_tar"](source, manifest, "candidate/release-manifest.json", 0)
            builder["add_to_tar"](source, overlay, "candidate/selfhost/overlays/backups.yml", 0)
        digest = builder["digest_reference"]
        assert digest("busybox:1.37.0-musl@sha256:" + "a" * 64) == "busybox@sha256:" + "a" * 64
        assert digest("registry.example:5443/team/app:1.2@sha256:" + "b" * 64) == "registry.example:5443/team/app@sha256:" + "b" * 64
        assert digest("registry.example:5443/app@sha256:" + "c" * 64) == "registry.example:5443/app@sha256:" + "c" * 64
        for private in ("", *images.values()):
            calls = []
            def inspect(command, *, env, **kwargs):
                assert command[:3] == ["docker", "manifest", "inspect"]
                assert not list(Path(env["DOCKER_CONFIG"]).iterdir())
                calls.append(command[-1])
                return subprocess.CompletedProcess(command, int(private != "" and command[-1] == digest(private)))
            with patch.object(builder["subprocess"], "run", side_effect=inspect):
                try:
                    builder["require_public_archive_images"](archive)
                except SystemExit:
                    assert private
                else:
                    assert not private and set(calls) == {digest(pin) for pin in images.values()}


def test_smoke_monitoring_certificate_uses_state_directory() -> None:
    source = (ROOT / "tests/smoke/selfhost-release-smoke.sh").read_text()
    resolver = source.split("<<'PY_MONITORING_CA'\n", 1)[1].split("\nPY_MONITORING_CA", 1)[0]
    with tempfile.TemporaryDirectory() as folder:
        # The resolver prints a resolved path; macOS temporary folders sit behind the /var -> /private/var link.
        root = Path(folder).resolve()
        bundle = root / "current"
        bundle.mkdir()
        for setting, state in (("", bundle), ("CHRONICLE_STATE_DIR=\n", bundle),
                               ("CHRONICLE_STATE_DIR='../previous release'\n", root / "previous release"),
                               (f"CHRONICLE_STATE_DIR='{root / 'preserved state'}'\n", root / "preserved state")):
            (bundle / ".env").write_text(setting)
            output = io.StringIO()
            with patch.object(sys, "argv", ["monitoring-ca", str(bundle)]), redirect_stdout(output):
                exec(compile(resolver, "smoke-monitoring-ca", "exec"), {})
            assert output.getvalue().strip() == str(state / "tls/monitoring.crt")
    assert '--cacert "$monitoring_ca"' in source
    assert 'cafile=os.environ["MONITORING_CA_FILE"]' in source


def test_monitoring_references_survive_scrape_allowlist() -> None:
    monitoring = ROOT / "selfhost/monitoring"
    renderer = (monitoring / "render-config.sh").read_text()
    backend = renderer.split("  - job_name: chronicle-backend\n", 1)[1].split("  - job_name:", 1)[0]
    keep = re.compile(re.search(r"regex: '(chronicle_[^']+)'", backend)[1])
    references = set()
    for path in [monitoring / "grafana-alerting/rules.yml", *sorted((monitoring / "grafana-dashboards").glob("*.json"))]:
        references.update(re.findall(r"\bchronicle_[a-z][a-z0-9_]+\b", path.read_text()))
    # These jobs scrape textfiles without the backend's name filter.
    for path in (monitoring / "probe.sh", monitoring / "record-operation.sh", monitoring / "render-config.sh"):
        references.difference_update(re.findall(r"(?m)^chronicle_[a-z][a-z0-9_]+", path.read_text()))
    assert references, "no backend monitoring expressions were checked"
    assert all(keep.fullmatch(metric) for metric in references), sorted(metric for metric in references if not keep.fullmatch(metric))
    # The browser's only failure signal reaches operators through this counter: a dashboard panel must chart it by kind.
    metrics = (ROOT / "chronicle-server/src/main/kotlin/com/openlattice/chronicle/observability/ChronicleMetrics.kt").read_text()
    browser = re.search(r'val browserErrorsTotal: Counter = Counter.build\(\)\s*\.name\("([^"]+)"\)', metrics)[1]
    charted = [target["expr"] for path in sorted((monitoring / "grafana-dashboards").glob("*.json"))
               for panel in json.loads(path.read_text()).get("panels", []) for target in panel.get("targets", [])]
    assert any(re.search(rf"\b{browser}\[", expr) and re.search(r"\bby\s*\(kind\)", expr) for expr in charted), \
        f"no operator dashboard panel charts {browser} by kind"


def test_password_alert_counts_dashboard_login_failures(rules: dict) -> None:
    rule = rules["failed-login-spike"]
    query = rule["data"][0]
    datasources = (ROOT / "selfhost/monitoring/grafana-datasources.yml").read_text()
    metrics_uid = re.search(r'uid: (\S+)\s+type: prometheus', datasources)[1]
    assert query["datasourceUid"] == query["model"]["datasource"]["uid"] == metrics_uid
    assert query["model"]["datasource"]["type"] == "prometheus"
    assert query["model"]["instant"] is True
    expression = re.fullmatch(r'sum\(increase\((\w+)\{endpoint=~"([^"]+)",method="([^"]+)",status=~"([^"]+)"\}\[15m\]\)\)',
                              query["model"]["expr"])
    assert expression, "password failures require an endpoint-specific window count"
    metric, endpoint_pattern, method, status_pattern = expression.groups()
    server = ROOT / "chronicle-server/src/main/kotlin/com/openlattice/chronicle"
    metrics = (server / "observability/ChronicleMetrics.kt").read_text()
    assert metric == re.search(r'val apiErrorsTotal: Counter = Counter.build\(\)\s*\.name\("([^"]+)"\)', metrics)[1]
    filter_source = (server / "observability/ApiMetricsFilter.kt").read_text()
    assert "HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE" in filter_source
    assert ".labels(normalizedPath, method, status.toString())" in filter_source
    auth = (server / "controllers/AuthTokenController.kt").read_text()
    bases = re.findall(r'"([^"]+)"', re.search(r'@RequestMapping\(value = \[([^\]]+)\]', auth)[1])
    login_mapping = auth.split("public fun dashboardLogin(", 1)[0].rsplit("@PostMapping(", 1)[1]
    suffix = re.search(r'path = \["([^"]+)"\]', login_mapping)[1]
    paths = [base + suffix for base in bases]
    assert len(paths) == 2 and method == "POST"
    for path in paths:
        assert re.fullmatch(endpoint_pattern, path), "both servlet route variants must count on either exposure"
        for status in (401, 429):
            assert re.fullmatch(status_pattern, str(status))
        for status in (200, 400, 403, 404, 500):
            assert not re.fullmatch(status_pattern, str(status))
        for other in (path + "/extra", path.replace(suffix, "/session"), path.replace(suffix, "/testing-login")):
            assert not re.fullmatch(endpoint_pattern, other)
    threshold = float(re.fullmatch(r'\$B > ([0-9.]+)', rule["data"][-1]["model"]["expression"])[1])
    assert threshold == 20 and rule["for"] == "0s"
    test_monitoring_references_survive_scrape_allowlist()
    renderer = (ROOT / "selfhost/monitoring/render-config.sh").read_text()
    dropped_labels = re.compile(re.search(r"- regex: '([^']+)'\s*action: labeldrop", renderer)[1])
    assert not any(dropped_labels.fullmatch(label) for label in ("endpoint", "method", "status"))
    runbook = (ROOT / "selfhost/monitoring/runbooks.html").read_text().split('id="failed-login-spike"', 1)[1].split("</section>", 1)[0]
    assert query["model"]["expr"] in runbook
    assert "internal or public" in runbook and "basic_auth" not in runbook


def test_operation_writers_serialize_metrics_and_events() -> None:
    import fcntl
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        writer = root / "record-operation.sh"
        writer.write_text((ROOT / "selfhost/monitoring/record-operation.sh").read_text().replace("/metrics", str(root)))
        processes = []
        with (root / ".operations.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                for operation, outcome in (("verify", "failure"), ("status", "success")):
                    processes.append(subprocess.Popen(["bash", str(writer), operation, outcome],
                                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE))
                for process in processes:
                    try:
                        process.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        pass
                    else:
                        raise AssertionError("operation writer bypassed the shared volume lock")
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
                for process in processes:
                    output, error = process.communicate(timeout=10)
                    assert process.returncode == 0, error.decode()
        metrics = (root / "operations.prom").read_text()
        assert 'operation="verify",outcome="failure"' in metrics
        assert 'operation="status",outcome="success"' in metrics
        assert len((root / "operator-events.jsonl").read_text().splitlines()) == len(processes)


def test_operation_event_lock_failure_never_writes() -> None:
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        writer = root / "record-operation.sh"
        writer.write_text((ROOT / "selfhost/monitoring/record-operation.sh").read_text().replace("/metrics", str(root)))
        flock = root / "flock"
        flock.write_text("#!/bin/sh\nexit 23\n")
        flock.chmod(0o700)
        harness = root / "record.sh"
        harness.write_text('source "$1"\nrecord_event logs-probe success fixture || exit $?\n')
        result = subprocess.run([modern_bash(), str(harness), str(writer)],
                                env=dict(os.environ, PATH=f'{root}{os.pathsep}{os.environ["PATH"]}'),
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 23, result.stderr
        assert not (root / "operator-events.jsonl").exists()


def test_published_digest_matches_repository() -> None:
    source = (ROOT / "scripts/publish-images.sh").read_text()
    start = source.index("resolve_published_digest() {")
    function = source[start:source.index("\n}\n", start) + 3]
    reference = f"ghcr.io/example/chronicle-selfhost-backup:{RELEASE_FIXTURE_VERSION}"
    expected = reference.rsplit(":", 1)[0] + "@sha256:" + "a" * 64
    foreign = "127.0.0.1:5000/backup@sha256:" + "b" * 64
    harness = 'set -euo pipefail\ndocker() { printf "%s\\n" "$DIGEST_FIXTURE"; }\n' + function + 'resolve_published_digest "$1"\n'
    for digests in ([foreign, expected], [foreign]):
        result = subprocess.run(["bash", "-c", harness, "fixture", reference],
                                env=dict(os.environ, DIGEST_FIXTURE=json.dumps(digests)), capture_output=True, text=True, timeout=10)
        assert (result.returncode == 0) == (expected in digests), result.stderr
        if expected in digests:
            assert result.stdout.strip() == expected
    assert source.index("--untracked-files=all") < source.index("stamp push")


def test_disk_forecast(rules: dict) -> None:
    rule = rules["disk-predicted-full"]
    models = {entry["refId"]: entry["model"] for entry in rule["data"]}
    assert "predict_linear(container_fs_usage_bytes" in models["A"]["expr"]
    assert "/ container_fs_limit_bytes" in models["A"]["expr"]
    comparison = re.fullmatch(r"\$B ([<>]) ([0-9.]+)", models[rule["condition"]]["expression"])
    assert comparison
    operator, threshold = comparison[1], float(comparison[2])
    for projected_usage, alerting in ((0.1, False), (0.85, False), (0.96, True), (1.04, True)):
        actual = projected_usage > threshold if operator == ">" else projected_usage < threshold
        assert actual == alerting, projected_usage


def test_missing_asset_cache() -> None:
    spa = (ROOT / "selfhost/caddy/snippets.caddy").read_text().split("(chronicle_spa) {", 1)[1]
    hashed = re.search(r"@hashed \{(.*?)\n\s*\}", spa, re.DOTALL).group(1)
    assert re.search(r"^\s*file\s*$", hashed, re.MULTILINE)
    assert spa.index('header Cache-Control "no-cache"') < spa.index("header @hashed Cache-Control")
    assert spa.index("header @hashed Cache-Control") < spa.index("try_files {path} /index.html")
    assert "route {" in spa


def test_failure_selectors(rules: dict) -> None:
    enrollment_query = rules["enrollment-failures"]["data"][0]["model"]["expr"]
    endpoint_pattern = re.search(r'endpoint=~"([^"]+)"', enrollment_query)[1]
    classifier = (ROOT / "chronicle-server/src/main/kotlin/com/openlattice/chronicle/configuration/MobileApiSignatureFilter.kt").read_text()
    metric_endpoint = re.search(r'ENROLLMENT_METRIC_ENDPOINT = "([^"]+)"', classifier)[1]
    assert re.fullmatch(endpoint_pattern, metric_endpoint)
    filter_source = (ROOT / "chronicle-server/src/main/kotlin/com/openlattice/chronicle/observability/ApiMetricsFilter.kt").read_text()
    assert "MobileApiSignatureFilter.enrollmentMetricEndpoint(request)" in filter_source
    deletion = rules["deletion-failures"]["data"][0]["model"]["expr"]
    assert 'chronicle_data_deletion_operations_total{outcome="failed"}' in deletion
    dashboard = json.loads((ROOT / "selfhost/monitoring/grafana-dashboards/application.json").read_text())
    panel = next(panel for panel in dashboard["panels"] if panel["title"] == "Participant form access failures")
    assert 'chronicle_participant_form_access_total{outcome="rejected"}' in panel["targets"][0]["expr"]


def test_no_panel_or_alert_reads_the_removed_async_export(rules: dict) -> None:
    # The server emits no chronicle_export_* metric, so a panel or alert on one only ever reads empty.
    for path in sorted((ROOT / "selfhost/monitoring").rglob("*")):
        if path.is_file() and path.suffix in {".json", ".yml", ".yaml", ".sh", ".html"}:
            assert "chronicle_export_" not in path.read_text(encoding="utf-8"), path
    assert "export-failures" not in rules


def test_failure_alerts_detect_sparse_events(rules: dict) -> None:
    for uid, failures in (("deletion-failures", 1), ("enrollment-failures", 6),
                          ("background-task-failures", 1)):
        rule = rules[uid]
        models = {row["refId"]: row["model"] for row in rule["data"]}
        query = re.fullmatch(r'sum(?: by \(task\) )?\(increase\((\w+)(?:\{[^}]+\})?\[(\d+)([mh])\]\)\)', models["A"]["expr"])
        assert query, "isolated failures require a window count"
        threshold = re.fullmatch(r'\$B > ([0-9.]+)', models[rule["condition"]]["expression"])
        assert threshold and rule["for"] == "0s", "failed jobs must alert on the first evaluation"
        window = int(query[2]) * (60 if query[3] == "m" else 3600)
        for count, alerting in ((0, False), (failures, True)):
            samples = [(0, 0), (window // 2, count), (window, count)]
            increase = samples[-1][1] - samples[0][1]
            assert (increase > float(threshold[1])) == alerting, uid


def test_probe_staleness_accounts_for_collection_cycle(rules: dict) -> None:
    rule = rules["probe-stale"]
    models = {row["refId"]: row["model"] for row in rule["data"]}
    source = (ROOT / "selfhost/monitoring/probe.sh").read_text()
    assert 'chronicle_operational_probe_interval_seconds $PROBE_INTERVAL_SECONDS' in source
    assert source.index('now="$(date +%s)"') > source.index('backups_bytes="$(dir_bytes /backups)')
    expr = models["A"]["expr"]
    assert expr == 'time()-chronicle_operational_probe_timestamp_seconds-chronicle_operational_probe_interval_seconds'
    threshold = float(re.fullmatch(r'\$B > ([0-9.]+)', models[rule["condition"]]["expression"])[1])
    pending = int(rule["for"].removesuffix("s"))
    scrape_lag = 15
    for interval in (30, 300):
        for collection in (30, 100):
            completions = [collection + n * (interval + collection) for n in range(3)]
            since = None
            # Each healthy collection is published, then scraped after the normal scrape lag.
            for now in range(completions[0] + scrape_lag, completions[-1] + scrape_lag + 1):
                published = max(done for done in completions if done + scrape_lag <= now)
                stale = now - published - interval > threshold
                since = now if stale and since is None else since if stale else None
                assert since is None or now - since < pending, (interval, collection, now)
            # A stopped probe still alerts after the configured allowance and pending period.
            since = None
            fired = False
            for now in range(completions[-1], int(completions[-1] + interval + threshold + pending + scrape_lag)):
                stale = now - completions[-1] - interval > threshold
                since = now if stale and since is None else since if stale else None
                fired |= since is not None and now - since >= pending
            assert fired, "a stopped probe must still raise the critical stale alert"


def probe_certificate_check(public_trust: str = "", database_authenticated: bool = False, logs_delivered: bool = False) -> None:
    scratch_parent = Path(os.environ.get(
        "SELFHOST_MONITORING_TEST_ROOT",
        ROOT / "build/operator-test-runs/selfhost-monitoring",
    ))
    scratch_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_root = Path(tempfile.mkdtemp(prefix="probe-certificates.", dir=scratch_parent))
    try:
        bin_dir = run_root / "bin"
        tls_dir = run_root / "tls-fixture"
        metrics_dir = run_root / "metrics-fixture"
        bin_dir.mkdir()
        tls_dir.mkdir()
        metrics_dir.mkdir()
        (tls_dir / "internal-cert.pem").write_text("fixture certificate", encoding="utf-8")
        public_ca = tls_dir / ("local-ca.crt" if public_trust == "local" else "public-ca.crt")
        public_ca.write_text("fixture public CA")
        external_log = run_root / "external-check.log"
        external_args = run_root / "external-openssl-args.log"

        probe_source = (ROOT / "selfhost/monitoring/probe.sh").read_text(encoding="utf-8")
        probe_source = probe_source.replace('dashboard_ca("/tls")', 'dashboard_ca(' + json.dumps(str(tls_dir)) + ')')
        probe_source = probe_source.replace("/metrics", str(metrics_dir))
        probe_source = probe_source.replace('logs_probe_category=""', 'logs_probe_category="probe_previous"')
        probe_source = probe_source.replace("/tls/local-ca.crt", str(tls_dir / "local-ca.crt"))
        writer = run_root / "record-operation.sh"
        writer.write_text((ROOT / "selfhost/monitoring/record-operation.sh").read_text().replace("/metrics", str(metrics_dir)))
        probe_source = probe_source.replace("/monitoring/record-operation.sh", str(writer))
        probe = run_root / "probe.sh"
        probe.write_text(probe_source, encoding="utf-8")
        probe.chmod(0o700)

        stubs = {
            "date": """#!/usr/bin/env bash
if [[ ${1:-} == +%s ]]; then printf '1800000000'; exit 0; fi
if [[ ${1:-} == -u ]]; then printf '2027-01-01T00:00:00Z'; exit 0; fi
if [[ ${1:-} == -d ]]; then
  case ${2:-} in
    PUBLIC_EXPIRY) printf '1900000000' ;;
    INTERNAL_EXPIRY) printf '2000000000' ;;
    *) exit 1 ;;
  esac
  exit 0
fi
exit 1
""",
            "pg_isready": "#!/usr/bin/env bash\nexit 0\n",
            "psql": '''#!/usr/bin/env bash
[[ "$PGCONNECT_TIMEOUT" == 5 && "$PGOPTIONS" == *statement_timeout=* ]] || exit 1
[[ "$PROBE_TEST_DB_AUTH" == true ]] || exit 1
if [[ "$*" == *pg_database_size* ]]; then printf '100|2|100|5|0|0'; else printf '1'; fi
''',
            "curl": '''#!/usr/bin/env bash
if [[ "$*" == *select/logsql/query* ]]; then
  [[ "$PROBE_TEST_LOGS_DELIVERED" != true ]] || printf '{"failure_category":"probe_previous"}'
  exit 0
fi
if [[ "$*" == *public-origin.example.test* && -n "$PROBE_TEST_PUBLIC_CA" ]]; then
  [[ "$*" == *"--cacert $PROBE_TEST_PUBLIC_CA"* ]] || exit 60
fi
printf '204'
''',
            "wget": "#!/usr/bin/env bash\nexit 0\n",
            "timeout": """#!/usr/bin/env bash
shift
printf 'checked\\n' >>"$PROBE_TEST_EXTERNAL_LOG"
exec "$@"
""",
            "openssl": """#!/usr/bin/env bash
if [[ ${1:-} == rand ]]; then printf 'abcdef0123456789'; exit 0; fi
if [[ ${1:-} == s_client ]]; then
  printf '%s\\n' "$*" >>"$PROBE_TEST_OPENSSL_ARGS"
  [[ "$*" == *-verify_return_error* && "$*" == *-verify_hostname* ]] || exit 1
  case "$*" in
    *'-connect web:8081'*) printf 'served-internal\\n' ;;
    *'-connect public-origin.example.test:8443'*)
      [[ -z "$PROBE_TEST_PUBLIC_CA" || "$*" == *"-CAfile $PROBE_TEST_PUBLIC_CA"* ]] || exit 1
      printf 'served-public\\n' ;;
    *) exit 1 ;;
  esac
  exit 0
fi
if [[ ${1:-} == x509 ]]; then
  [[ "$*" != *' -in '* ]] || exit 1
  read -r marker
  case "$marker" in
    served-public) printf 'notAfter=PUBLIC_EXPIRY\\n' ;;
    served-internal) printf 'notAfter=INTERNAL_EXPIRY\\n' ;;
    *) exit 1 ;;
  esac
  exit 0
fi
exit 1
""",
        }
        for name, contents in stubs.items():
            path = bin_dir / name
            path.write_text(contents, encoding="utf-8")
            path.chmod(0o700)

        env = os.environ.copy()
        env.update({
            "PATH": f"{bin_dir}:/usr/bin:/bin:{Path(shutil.which('flock')).parent}",
            "PROBE_TEST_EXTERNAL_LOG": str(external_log),
            "PROBE_TEST_OPENSSL_ARGS": str(external_args),
            "PROBE_INTERVAL_SECONDS": "300",
            "POSTGRES_PASSWORD": "fixture-postgres-password",
            "DOMAIN": "private-configured-domain.test",
            "PUBLIC_TLS_URL": "https://public-origin.example.test:8443/study",
            "DASHBOARD_BASE_URL": "https://management.example.test:8443",
            "PYTHONPATH": str(ROOT / "selfhost"),
            "LOGS_HEALTH_URL": "http://victorialogs:9428/health",
            "ENABLE_ENCRYPTION": "false",
            "PROBE_TEST_DB_AUTH": str(database_authenticated).lower(),
            "PROBE_TEST_LOGS_DELIVERED": str(logs_delivered).lower(),
            "PROBE_TEST_PUBLIC_CA": str(public_ca) if public_trust else "",
            "PUBLIC_CA_FILE": str(public_ca) if public_trust == "private" else "",
            "COMPOSE_FILE_SELECTION": "overlays/mode-local-https.yml" if public_trust == "local" else "",
            "BACKUP_SCHEDULE": "@weekly" if public_trust == "local" else "",
        })
        errors = run_root / 'probe-stderr'
        error_stream = errors.open('w')
        process = subprocess.Popen(
            [modern_bash(), str(probe)], env=env,
            stdout=subprocess.DEVNULL, stderr=error_stream,
        )
        try:
            deadline = time.monotonic() + 10
            output = metrics_dir / "operational.prom"
            while time.monotonic() < deadline and not output.exists():
                if process.poll() is not None:
                    raise AssertionError("probe exited before writing its metrics")
                time.sleep(0.05)
            assert output.exists(), "probe did not write operational metrics"
            assert 'command not found' not in errors.read_text()
            events = [json.loads(line) for line in (metrics_dir / 'operator-events.jsonl').read_text().splitlines()]
            assert any(event['operation'] == 'logs-probe' and event['outcome'] == 'success' for event in events)
            metrics = output.read_text(encoding="utf-8")
            assert "chronicle_certificate_expiry_timestamp_seconds 1900000000" in metrics
            assert "chronicle_internal_certificate_expiry_timestamp_seconds 2000000000" in metrics
            assert "chronicle_public_probe_success 1" in metrics
            assert f"chronicle_database_up {int(database_authenticated)}" in metrics
            assert f"chronicle_logs_pipeline_up {int(logs_delivered)}" in metrics
            # The stale-backup alert compares backup age with the configured schedule's overdue window.
            from chronicle_ops.dump import backup_max_age_seconds
            overdue = backup_max_age_seconds(env["BACKUP_SCHEDULE"])
            assert f"chronicle_backup_max_age_seconds {overdue}" in metrics, metrics
            # The disk-pressure alert reads doctor's low-free threshold instead of keeping its own.
            from chronicle_ops.common import LOW_FREE_PERCENT
            assert f"chronicle_disk_low_free_ratio {LOW_FREE_PERCENT / 100}" in metrics, metrics
            # An unmeasured value is absent, not a misleading zero.
            database_bytes = re.findall(r"(?m)^chronicle_postgres_database_bytes (.*)$", metrics)
            assert database_bytes == (["100"] if database_authenticated else []), database_bytes
            # There is no asynchronous export or export store; the probe reports nothing about them.
            assert [line for line in metrics.splitlines() if "chronicle_export_" in line] == []
            unmeasured_prefixes = ("chronicle_observability_storage_bytes", "chronicle_backup_storage_bytes")
            if not database_authenticated:
                unmeasured_prefixes += ("chronicle_postgres_", "chronicle_flyway_")
            unmeasured = [line for line in metrics.splitlines() if line.startswith(unmeasured_prefixes)]
            assert unmeasured == [], f"unmeasured values must emit no sample: {unmeasured}"
            assert external_log.read_text(encoding="utf-8") == "checked\nchecked\n"
            arguments = external_args.read_text(encoding="utf-8")
            assert "-connect public-origin.example.test:8443 -servername public-origin.example.test -verify_hostname public-origin.example.test" in arguments
            assert "-connect web:8081 -servername management.example.test -verify_hostname management.example.test -partial_chain -CAfile " + str(tls_dir / "internal-cert.pem") in arguments
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            error_stream.close()
    finally:
        shutil.rmtree(run_root)


class GrafanaStub(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:
        pass

    def reply(self, status: int, payload: dict | None = None) -> None:
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self) -> dict:
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")

    def do_GET(self) -> None:
        login = parse_qs(urlparse(self.path).query).get("loginOrEmail", [""])[0]
        user = USERS.get(login)
        self.reply(200, user) if user else self.reply(404, {"message": "not found"})

    def do_POST(self) -> None:
        global NEXT_ID
        payload = self.body()
        assert self.path == "/api/admin/users"
        user = {"id": NEXT_ID, "login": payload["login"], "password": payload["password"], "role": "Viewer"}
        NEXT_ID += 1
        USERS[user["login"]] = user
        self.reply(200, {"id": user["id"]})

    def do_PATCH(self) -> None:
        payload = self.body()
        user = next(user for user in USERS.values() if user["id"] == int(self.path.rsplit("/", 1)[1]))
        user["role"] = payload["role"]
        self.reply(200, {"message": "updated"})

    def do_PUT(self) -> None:
        payload = self.body()
        user_id = int(self.path.split("/")[4])
        user = next(user for user in USERS.values() if user["id"] == user_id)
        user["password"] = payload["password"]
        self.reply(200, {"message": "updated"})

    def do_DELETE(self) -> None:
        user_id = int(self.path.rsplit("/", 1)[1])
        login = next(login for login, user in USERS.items() if user["id"] == user_id)
        del USERS[login]
        self.reply(200, {"message": "deleted"})


# Nothing listens on the discard port, so a request routed through this proxy fails.
UNREACHABLE_PROXY = "http://127.0.0.1:9"


def viewer_call(base: str, operation: str, password: str, ca: Path) -> str:
    fields = [base, "test-admin-password", operation, "observer", password]
    result = subprocess.run(
        ["python3", str(ROOT / "selfhost/monitoring/grafana-user.py")],
        # A university host's proxy cannot reach the private Grafana listener; the call must not use it.
        env=dict(os.environ, GRAFANA_CA_FILE=str(ca), HTTPS_PROXY=UNREACHABLE_PROXY, https_proxy=UNREACHABLE_PROXY,
                 HTTP_PROXY=UNREACHABLE_PROXY, http_proxy=UNREACHABLE_PROXY, NO_PROXY="", no_proxy=""),
        input=b"\0".join(field.encode() for field in fields) + b"\0",
        check=True,
        capture_output=True,
    )
    output = (result.stdout + result.stderr).decode()
    assert "test-admin-password" not in output
    assert not password or password not in output
    return output


def test_grafana_viewer_lifecycle() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), GrafanaStub)
    tls_fixture = tempfile.TemporaryDirectory()
    ca = Path(tls_fixture.name) / "certificate.crt"
    key = Path(tls_fixture.name) / "private.fixture"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-out", str(ca), "-keyout", str(key)], check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"https://127.0.0.1:{server.server_port}"
    try:
        viewer_call(base, "add", "first-viewer-password", ca)
        assert USERS["observer"]["role"] == "Viewer"
        viewer_call(base, "reset", "second-viewer-password", ca)
        assert USERS["observer"]["password"] == "second-viewer-password"
        viewer_call(base, "remove", "", ca)
        assert "observer" not in USERS
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        tls_fixture.cleanup()


def test_monitoring_configuration() -> None:
    alerts = json.loads((ROOT / "selfhost/monitoring/grafana-alerting/rules.yml").read_text())
    runbooks = (ROOT / "selfhost/monitoring/runbooks.html").read_text()
    for group in alerts["groups"]:
        for rule in group["rules"]:
            anchor = rule["annotations"]["runbook_url"].rsplit("#", 1)[1]
            assert f'id="{anchor}"' in runbooks, f"missing runbook anchor: {anchor}"

    rules = {rule["uid"]: rule for group in alerts["groups"] for rule in group["rules"]}
    test_disk_forecast(rules)
    test_failure_selectors(rules)
    test_no_panel_or_alert_reads_the_removed_async_export(rules)
    test_failure_alerts_detect_sparse_events(rules)
    test_probe_staleness_accounts_for_collection_cycle(rules)
    test_cadvisor_oom_counter(rules)
    assert 'up{job="chronicle-log-forwarder"}' in rules["logs-down"]["data"][0]["model"]["expr"]
    # Failed erasure/retention deletion and failed restore/upgrade are data-integrity failures.
    for uid in ("deletion-failures", "operation-failed"):
        assert rules[uid]["labels"]["severity"] == "critical", f"{uid} must be critical"
    test_password_alert_counts_dashboard_login_failures(rules)
    permission_expr = rules["permission-change"]["data"][0]["model"]["expr"]
    selectors = re.findall(r'\{endpoint=~"([^"]+)",method=~?"([^"]+)"\}', permission_expr)
    assert selectors, "permission-change must select request counts by endpoint and method"

    def alerts_on(endpoint: str, method: str) -> bool:
        return any(re.fullmatch(path, endpoint) and re.fullmatch(methods, method) for path, methods in selectors)

    # Every current permission/principal route, on both servlet prefixes: anything but a GET or one of the
    # lookup POSTs (getSecurablePrincipal, searchUsers, getAcl, getAcls, getAclExplanation) changes access.
    lookups = {"/principal", "/principal/users/search", "/v3/permissions", "/v3/permissions/bulk", "/v3/permissions/explain"}
    inventory = json.loads((ROOT / "chronicle-server/src/test/resources/route-inventory.json").read_text())
    routes = [(route["path"], route["method"]) for route in inventory
              if re.search(r"/(v3/permissions|principal)(/|$)", route["path"])]
    assert len(routes) >= 20, routes
    for endpoint, method in routes:
        lookup = method == "GET" or (method == "POST" and endpoint.removeprefix("/chronicle") in lookups)
        assert alerts_on(endpoint, method) != lookup, f"permission-change {'fires on lookup' if lookup else 'misses'} {method} {endpoint}"

    policies_text = (ROOT / "selfhost/monitoring/grafana-alerting/notification-policies.yml").read_text()
    json.loads(policies_text)
    assert "mute_time_intervals" not in policies_text and "muteTimes" not in policies_text, \
        "notification routing must not be muted; an attached channel has to receive alerts"
    contact_points = json.loads((ROOT / "selfhost/monitoring/grafana-alerting/contactpoints.yml").read_text())
    receiver = contact_points["contactPoints"][0]["receivers"][0]
    assert receiver["settings"]["url"] == "$CHRONICLE_ALERT_WEBHOOK_URL"
    overlay = (ROOT / "selfhost/overlays/monitoring.yml").read_text()
    assert "CHRONICLE_ALERT_WEBHOOK_URL: ${CHRONICLE_ALERT_WEBHOOK_URL:-" in overlay
    assert "CHRONICLE_ALERT_WEBHOOK_URL=" in (ROOT / "selfhost/.env.example").read_text()
    runbook_md = (ROOT / "selfhost/docs/MONITORING-RUNBOOK.md").read_text()
    assert "## Attach a notification channel" in runbook_md
    assert "permanently muted" not in runbook_md

    stale = {row["refId"]: row["model"] for row in rules["backup-stale"]["data"]}
    assert stale["A"]["expr"] == ("chronicle_backups_expected * (time()-chronicle_backup_latest_success_timestamp_seconds"
                                  "-chronicle_backup_max_age_seconds)")
    assert stale[rules["backup-stale"]["condition"]]["expression"] == "$B > 0"
    pressure = {row["refId"]: row["model"] for row in rules["disk-pressure"]["data"]}
    assert pressure["A"]["expr"] == ('1-(container_fs_usage_bytes{id="/"}/container_fs_limit_bytes{id="/"})'
                                     ' - on() group_left() chronicle_disk_low_free_ratio')
    assert pressure[rules["disk-pressure"]["condition"]]["expression"] == "$B < 0"
    assert not re.search(r"[0-9]", rules["disk-pressure"]["title"] + rules["disk-pressure"]["annotations"]["summary"])

    alert_text = json.dumps(alerts)
    assert "chronicle_tde_expected * (1 - chronicle_tde_healthy)" in alert_text
    assert "database-connection-pressure" in alert_text
    assert "chronicle_certificate_expiry_timestamp_seconds" in alert_text
    assert "chronicle_internal_certificate_expiry_timestamp_seconds" in alert_text

    dashboard = json.loads((ROOT / "selfhost/monitoring/grafana-dashboards/system-overview.json").read_text())
    certificate_panels = {panel["title"]: panel for panel in dashboard["panels"] if "certificate" in panel["title"].casefold()}
    assert "Public certificate days remaining" in certificate_panels
    assert "Internal certificate days remaining" in certificate_panels
    assert "chronicle_certificate_expiry_timestamp_seconds" in certificate_panels["Public certificate days remaining"]["targets"][0]["expr"]
    assert "chronicle_internal_certificate_expiry_timestamp_seconds" in certificate_panels["Internal certificate days remaining"]["targets"][0]["expr"]


ALERT_RECORDER = r'''
import json, os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
root = Path("/records")
class Recorder(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        status = int((root / "status").read_text())
        record = root / ("%05d.json" % len(list(root.glob("*.json"))))
        temporary = record.with_suffix(".new")
        temporary.write_text(json.dumps({"status": status, "path": self.path, "body": body.decode()}))
        os.replace(temporary, record)
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()
HTTPServer(("0.0.0.0", 8080), Recorder).serve_forever()
'''
ALERT_TARGETS = {
    "backup-stale": ("Chronicle verified backup is stale", "backup", "critical"),
    "operation-failed": ("A guarded Chronicle operator command failed", "operations", "critical"),
    "disk-pressure": ("Chronicle host filesystem is low on free space", "storage", "warning"),
}


def alert_samples(state: str) -> str:
    now = time.time()
    fault = state == "fault"
    return "\n".join((
        "chronicle_backups_expected 1",
        "chronicle_backup_max_age_seconds 93600",
        f"chronicle_backup_latest_success_timestamp_seconds {now - (200000 if fault else 60):.0f}",
        f'chronicle_operator_operation_timestamp_seconds{{operation="update",outcome="success",failure_category="none"}} {now - 600:.0f}',
        # A failure older than the alert's hour is history, not a current failure.
        f'chronicle_operator_operation_timestamp_seconds{{operation="update",outcome="failure",failure_category="verify"}} '
        f"{now - (10 if fault else 7200):.0f}",
        'container_fs_limit_bytes{id="/"} 100000000000',
        f'container_fs_usage_bytes{{id="/"}} {95000000000 if fault else 40000000000}',
        "chronicle_disk_low_free_ratio 0.10",
    )) + "\n"


def test_alerts_reach_the_operator_webhook() -> None:
    """Shipped rules, policy and contact point in real Grafana and VictoriaMetrics, delivered to a recorder."""
    grafana_image = os.environ.get("SELFHOST_GRAFANA_TEST_IMAGE") or "chronicle-selfhost-grafana:test"
    if not os.environ.get("SELFHOST_GRAFANA_TEST_IMAGE"):
        subprocess.run(["docker", "build", "-q", "-t", grafana_image, "-f", str(ROOT / "selfhost/Dockerfile.grafana"),
                        str(ROOT / "selfhost")], check=True, stdout=subprocess.DEVNULL)
    overlay = (ROOT / "selfhost/overlays/monitoring.yml").read_text()
    metrics_image = re.search(r"image: (victoriametrics/victoria-metrics:\S+)", overlay).group(1)
    helper_image = [line.split()[1] for line in (ROOT / "selfhost/Dockerfile.backup").read_text().splitlines()
                    if line.startswith("FROM ")][-1]
    titles = {title: uid for uid, (title, _service, _severity) in ALERT_TARGETS.items()}
    admin_password = "alert-test-admin-" + os.urandom(12).hex()
    webhook_token = "alert-test-token-" + os.urandom(12).hex()
    run = Path(tempfile.mkdtemp(prefix="alert-delivery-"))
    suffix = os.urandom(4).hex()
    network, names = "chronicle-sat-r1-alert-test-" + suffix, [f"chronicle-sat-r1-alert-{role}-{suffix}" for role in ("vm", "recorder", "grafana")]
    vm, recorder, grafana = names
    state = {"value": "healthy", "stop": False}
    pusher = None
    try:
        # Timing only: one evaluation per 10 s and short waits, so the test does not need the shipped hours.
        alerting = run / "alerting"
        shutil.copytree(ROOT / "selfhost/monitoring/grafana-alerting", alerting)
        provisioned = json.loads((alerting / "rules.yml").read_text())
        provisioned["groups"][0]["interval"] = "10s"
        for rule in provisioned["groups"][0]["rules"]:
            if rule["uid"] in ALERT_TARGETS:
                rule["for"] = "10s"
        (alerting / "rules.yml").write_text(json.dumps(provisioned))
        policies = json.loads((alerting / "notification-policies.yml").read_text())
        for policy in [policies["policies"][0], *policies["policies"][0]["routes"]]:
            policy.update(group_wait="1s", group_interval="10s")
        (alerting / "notification-policies.yml").write_text(json.dumps(policies))
        records = run / "records"
        records.mkdir()
        def receiver_status(status):
            temporary = records / "status.new"
            temporary.write_text(str(status))
            os.replace(temporary, records / "status")
        receiver_status(200)
        (run / "recorder.py").write_text(ALERT_RECORDER)
        for path in [run, *run.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        records.chmod(0o777)
        subnet = subprocess.run([sys.executable, str(ROOT / "selfhost/network-subnet.py"), "select",
                                 "10.251.1.0/24", network], check=True, capture_output=True, text=True).stdout.strip()
        subprocess.run(["docker", "network", "create", "--subnet", subnet, network], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["docker", "run", "-d", "--name", vm, "--network", network, "--network-alias", "victoriametrics",
                        "-p", "127.0.0.1::8428", metrics_image, "-retentionPeriod=1d"], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["docker", "run", "-d", "--name", recorder, "--network", network, "--network-alias", "recorder",
                        "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{records}:/records", "-v", f"{run}/recorder.py:/recorder.py:ro",
                        "--entrypoint", "python3", helper_image, "/recorder.py"], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["docker", "run", "-d", "--name", grafana, "--network", network, "-p", "127.0.0.1::3000",
                        "-e", "GF_SECURITY_ADMIN_PASSWORD=" + admin_password, "-e", "GF_PATHS_PLUGINS=/opt/chronicle-plugins",
                        "-e", "GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false", "-e", "GF_ANALYTICS_REPORTING_ENABLED=false",
                        "-e", "CHRONICLE_ALERT_WEBHOOK_URL=http://recorder:8080/hook/" + webhook_token,
                        "-v", f"{ROOT}/selfhost/monitoring/grafana-datasources.yml:/etc/grafana/provisioning/datasources/chronicle.yml:ro",
                        "-v", f"{alerting}:/etc/grafana/provisioning/alerting:ro",
                        "-v", f"{ROOT}/selfhost/monitoring/runbooks.html:/usr/share/grafana/public/runbooks/index.html:ro",
                        grafana_image], check=True, stdout=subprocess.DEVNULL)

        def port(container: str, inner: str) -> str:
            return subprocess.run(["docker", "port", container, inner], check=True, capture_output=True,
                                  text=True).stdout.split(":")[-1].strip()

        metrics_url = f"http://127.0.0.1:{port(vm, '8428/tcp')}/api/v1/import/prometheus"
        grafana_url = f"http://127.0.0.1:{port(grafana, '3000/tcp')}"
        def push() -> None:
            while not state["stop"]:
                try:
                    urllib.request.urlopen(urllib.request.Request(metrics_url, alert_samples(state["value"]).encode()), timeout=5).read()
                except OSError:
                    pass
                time.sleep(5)

        pusher = threading.Thread(target=push, daemon=True)
        pusher.start()

        def deliveries() -> list[dict]:
            found = []
            for path in sorted(records.glob("*.json")):
                record = json.loads(path.read_text())
                record["payload"] = json.loads(record["body"])
                found.append(record)
            return found

        def delivered(status: int) -> dict[str, dict]:
            alerts = {}
            for record in deliveries():
                if record["status"] == status:
                    for alert in record["payload"]["alerts"]:
                        alerts.setdefault(alert["labels"]["alertname"], alert)
            return alerts

        def wait_for(condition, timeout: float, message: str) -> None:
            deadline = time.monotonic() + timeout
            while not condition():
                if time.monotonic() > deadline:
                    logs = subprocess.run(["docker", "logs", "--tail", "40", grafana], capture_output=True, text=True)
                    raise AssertionError(message + "\n" + logs.stdout + logs.stderr)
                time.sleep(2)

        # Healthy: the pipeline delivers (an unconfigured deployment check fires on no data) but no target fires.
        config_invalid = "Chronicle configuration validation failed"
        wait_for(lambda: config_invalid in delivered(200), 240, "Grafana never delivered any alert")
        time.sleep(40)
        assert not set(titles) & set(delivered(200)), delivered(200).keys()
        # The receiver is down while the faults begin, then recovers.
        receiver_status(503)
        state["value"] = "fault"
        wait_for(lambda: set(titles) <= set(delivered(503)), 240, "Grafana did not attempt the failing receiver")
        receiver_status(200)
        wait_for(lambda: set(titles) <= set(delivered(200)), 240, "Grafana did not redeliver after the receiver recovered")
        runbooks = (ROOT / "selfhost/monitoring/runbooks.html").read_text()
        for title, uid in titles.items():
            alert = delivered(200)[title]
            assert alert["status"] == "firing", alert
            _, service, severity = ALERT_TARGETS[uid]
            for label, expected in dict(severity=severity, service=service, scope="selfhost").items():
                assert alert["labels"][label] == expected, (label, alert)
            assert alert["annotations"]["runbook_url"] == "/public/runbooks/index.html#" + uid, alert
            assert f'id="{alert["annotations"]["runbook_url"].split("#", 1)[1]}"' in runbooks, alert
        for record in deliveries():
            assert record["path"] == "/hook/" + webhook_token, record["path"]
            for secret in (admin_password, webhook_token):
                assert secret not in record["body"], "a delivery carried a credential"
            for field in ("participant", "study_id", "random_device_id"):
                assert field not in record["body"].casefold(), field
        # Recovery clears the alerts; the shipped contact point keeps resolution on the dashboard only.
        state["value"] = "healthy"

        def active() -> set[str]:
            request = urllib.request.Request(grafana_url + "/api/alertmanager/grafana/api/v2/alerts")
            request.add_header("Authorization", "Basic " + base64.b64encode(b"admin:" + admin_password.encode()).decode())
            return {alert["labels"]["alertname"] for alert in json.loads(urllib.request.urlopen(request, timeout=10).read())}

        wait_for(lambda: not set(titles) & active(), 240, "the alerts did not clear after recovery")
        time.sleep(30)
        assert not [record for record in deliveries() if record["payload"]["status"] == "resolved"
                    and set(titles) & {alert["labels"]["alertname"] for alert in record["payload"]["alerts"]}]
    finally:
        state["stop"] = True
        if pusher is not None:
            pusher.join(timeout=10)
        subprocess.run(["docker", "rm", "-fv", *names], capture_output=True)
        subprocess.run(["docker", "network", "rm", network], capture_output=True)
        shutil.rmtree(run, ignore_errors=True)
    print("self-host alert delivery passed")


def main() -> None:
    if sys.argv[1:] == ["--alert-delivery"]:
        test_alerts_reach_the_operator_webhook()
        return
    test_release_drafts()
    test_prerelease_classification()
    test_release_signatures()
    test_caddy_default_log_masks_handler_ips()
    test_mobile_snat_abuse_limits()
    test_edge_limiter_keys_ignore_credentials()
    test_fresh_candidate_runs_setup_up_verify()
    test_backup_sbom_inventory()
    test_release_changelog()
    test_public_source_equality()
    test_public_researcher_credentials()
    test_backup_probe_caches_verified_file_identity()
    test_release_signature_rejects_tampered_checksum()
    test_release_archive_rejects_unsafe_inventory()
    test_candidate_smoke_matches_images_and_archive()
    test_release_promotion_uses_installed_key()
    test_public_release_tag_matches_source()
    test_release_images_require_anonymous_registry_access()
    test_smoke_monitoring_certificate_uses_state_directory()
    test_monitoring_references_survive_scrape_allowlist()
    test_operation_writers_serialize_metrics_and_events()
    test_operation_event_lock_failure_never_writes()
    test_published_digest_matches_repository()
    test_missing_asset_cache()
    probe_certificate_check()
    probe_certificate_check("local", True, True)
    probe_certificate_check("private", True, True)
    test_grafana_viewer_lifecycle()
    test_monitoring_configuration()

    sanitizer = (ROOT / "selfhost/monitoring/sanitize.lua").read_text()
    assert 'source["message"]' not in sanitizer
    assert 'source["stack"]' not in sanitizer
    assert 'record["log"]' in sanitizer  # accepted as input, never emitted verbatim
    fluent = (ROOT / "selfhost/monitoring/fluent-bit.conf").read_text()
    for source in ("chronicle.audit", "chronicle.operator", "chronicle.*", "chronicle.postgres"):
        assert source in fluent
    compose = (ROOT / "selfhost/docker-compose.yml").read_text()
    assert "LOG_FORMAT: json" in compose
    assert "log_line_prefix=chronicle_pg" in compose
    release_smoke = (ROOT / "tests/smoke/selfhost-release-smoke.sh").read_text()
    assert "cadvisor_version_info" not in release_smoke
    assert '.labels.job == "chronicle-containers"' in release_smoke
    assert "up%7Bjob%3D%22chronicle-containers%22%7D%20%3D%3D%201" in release_smoke
    assert "monitoring_deadline=$((SECONDS + 60))" in release_smoke
    caddy_access_log = (ROOT / "selfhost/caddy/snippets.caddy").read_text()
    for source_redaction in (
        "format filter {",
        "request>headers delete",
        "request>uri delete",
        "request>remote_ip ip_mask 16 32",
        "request>client_ip ip_mask 16 32",
        "wrap json",
    ):
        assert source_redaction in caddy_access_log
    assert "password" not in (ROOT / "selfhost/monitoring/record-operation.sh").read_text().casefold()
    # The launcher delegates receipts to chronicle_ops; the Python writer owns the field set.
    receipts = (ROOT / "selfhost/chronicle_ops/receipts.py").read_text()
    receipt_start = receipts.index("def write_operation_receipt(")
    receipt_end = receipts.index("\ndef ", receipt_start + 1)
    receipt_writer = receipts[receipt_start:receipt_end]
    for field in ("operation", "timestamp", "releaseVersion", "outcome", "failureCategory"):
        assert f'"{field}"' in receipt_writer
    for forbidden in ("PASSWORD", "SECRET", "TOKEN", "viewer"):
        assert forbidden not in receipt_writer
    print("self-host monitoring tests passed")


if __name__ == "__main__":
    main()
