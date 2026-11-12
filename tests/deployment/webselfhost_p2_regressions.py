#!/usr/bin/env python3
"""Focused deployment regressions for the web self-host setup."""

from __future__ import annotations

import hashlib
import json
import importlib.util
import inspect
import os
import re
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRATCH_DIR = Path(os.environ.get('TMPDIR', ROOT / 'build/operator-test-runs')) / Path(__file__).stem


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def check_w11() -> None:
    snippets = read("selfhost/caddy/snippets.caddy")
    routes = read("chronicle-server/src/main/kotlin/com/openlattice/chronicle/filters/ResearcherApiKeyRoutes.kt")
    caddyfiles = [read(f"selfhost/Caddyfile.split{suffix}") for suffix in ("", ".local", ".tls")]
    docs = read("selfhost/docs/DEPLOYMENT-COMPATIBILITY.md")

    assert "@researcherNoApiKey" in snippets and "respond @researcherNoApiKey 404" in snippets
    matcher = re.search(r"@researcherNoApiKey\s*\{([^}]*)\}", snippets, re.S)
    assert matcher, "the public denial must be scoped to researcher-only V3 exports without an API key"
    block = matcher.group(1)
    assert "not header X-Api-Key *" in block
    assert "time-use-diary/[^/]+/(data|participants/data)" in block
    assert "survey/[^/]+/questionnaire/[^/]+/data" in block
    assert "time-use-diary/[^/]+/ids" in snippets and "questionnaire/[^/]+/responses" in snippets
    assert 'Route("GET", TUD, "/data", READ_ONLY)' in routes
    assert 'Route("GET", TUD, "/participants/data", READ_ONLY)' in routes
    assert 'Route("GET", SURVEY, "/questionnaire/$SEGMENT/data", READ_ONLY)' in routes
    assert all("import chronicle_deny_researcher_v3" in caddy for caddy in caddyfiles)
    assert all("import chronicle_strip_researcher_bearer" in caddy for caddy in caddyfiles)
    assert "X-Api-Key" in docs and "public" in docs.lower() and "scoped" in docs.lower()


def check_w12() -> None:
    snippets = read("selfhost/caddy/snippets.caddy")
    spa = snippets.split("(chronicle_spa) {", 1)[1]
    matcher = re.search(r"@hashed\s*\{\s*path_regexp ([^\n]+)\s+file\s*\}", spa)
    assert matcher, "immutable caching must require both a hashed path and an existing file"
    pattern = re.compile(matcher.group(1))
    assert pattern.fullmatch("/chunk-app123.js")
    # build-modern.ts names CSS by the sha256 of its final bytes, so only that name is immutable.
    assert pattern.fullmatch("/chunk-by70j4d2-239fc9ce.css")
    assert not pattern.fullmatch("/chunk-style9.css")

    fonts = ROOT / "chronicle-web" / "vendor" / "equal" / "packages" / "tokens" / "dist" / "fonts"
    font_files = sorted(fonts.glob("*.woff2"))
    assert font_files, "the build's font inventory must exercise the immutable matcher"
    for font in font_files:
        digest = hashlib.sha256(font.read_bytes()).hexdigest()[:8]
        assert pattern.fullmatch(f"/fonts/{font.stem}-{digest}.woff2"), font.name
    assert not pattern.fullmatch("/fonts/atkinson-hyperlegible-latin-400-normal.woff2")
    assert not pattern.fullmatch("/index.html")
    directives = ('route {', 'header Cache-Control "no-cache"', '@hashed {',
                  'header @hashed Cache-Control "public, max-age=31536000, immutable"',
                  'try_files {path} /index.html', 'file_server')
    positions = [spa.index(directive) for directive in directives]
    assert positions == sorted(positions), "cache policy must be set before the SPA fallback rewrite"


def check_w49() -> None:
    expected = "oven/bun:1.4.4-alpine@sha256:4cf82f5686b196504fe119db3fcd9185b191f82ece82c40680e597228ec6070a"
    assert f"FROM {expected} AS builder" in read("selfhost/Dockerfile.frontend")
    package = json.loads(read("chronicle-web/package.json"))
    assert package.get("engines", {}).get("bun") == "1.4.4"
    assert package.get("devDependencies", {}).get("bun-types") == "1.4.4"
    assert "bun" not in package.get("devDependencies", {}), "the bun npm placeholder would shadow the runtime"


def check_w47() -> None:
    for path in (
        "docker/Dockerfile.backend",
        "selfhost/Dockerfile.frontend",
        "selfhost/Dockerfile.caddy",
    ):
        dockerfile = read(path)
        assert "COPY LICENSE /usr/share/doc/chronicle/LICENSE" in dockerfile, path
        assert "org.opencontainers.image.source=\"https://github.com/uzaira0/chronicle-platform\"" in dockerfile, path
        assert "Corresponding Chronicle source:" in dockerfile and "SOURCE_REF" in dockerfile, path
    assert "COPY chronicle-web/LICENSE /usr/share/doc/chronicle/LICENSE-chronicle-web" in read("selfhost/Dockerfile.frontend")
    assert "!LICENSE" in read(".dockerignore")
    assert "!chronicle-web/LICENSE" in read(".dockerignore")
    assert read("LICENSE").lstrip().startswith("GNU GENERAL PUBLIC LICENSE")
    assert read("chronicle-web/LICENSE").lstrip().startswith("GNU GENERAL PUBLIC LICENSE")
    publisher = read("scripts/publish-images.sh")
    assert publisher.count('SOURCE_REF=$release') == 3


def check_w50() -> None:
    spec = importlib.util.spec_from_file_location(
        "build_selfhost_release", ROOT / "scripts" / "build-selfhost-release.py"
    )
    assert spec and spec.loader
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)

    scratch = SCRATCH_DIR
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="W50-", dir=scratch) as temporary:
        fixture_root = Path(temporary)
        source = fixture_root / "selfhost" / "config"
        source.mkdir(parents=True)
        tracked = source / "config.yml"
        untracked = source / "extra.yml"
        tracked.write_bytes(b"same bytes\n")
        untracked.write_bytes(tracked.read_bytes())
        manifest = {"selfhost/config/config.yml"}
        rejected = fixture_root / "rejected"
        if "tracked_paths" in inspect.signature(builder.copy_tree).parameters:
            try:
                builder.copy_tree(
                    source,
                    rejected,
                    tracked_paths=manifest,
                    repository_root=fixture_root,
                )
            except SystemExit as error:
                assert "untracked release input" in str(error)
            else:
                raise AssertionError("the bundle builder accepted an untracked config file")
        else:
            builder.copy_tree(source, rejected)
            assert not (rejected / "extra.yml").exists(), "the bundle included an untracked config file"

        untracked.unlink()
        first = fixture_root / "first"
        second = fixture_root / "second"
        for destination in (first, second):
            builder.copy_tree(
                source,
                destination,
                tracked_paths=manifest,
                repository_root=fixture_root,
            )
        assert sorted(path.name for path in first.iterdir()) == ["config.yml"]
        assert (first / "config.yml").read_bytes() == (second / "config.yml").read_bytes()


def check_w51() -> None:
    compose = yaml.safe_load(read("selfhost/docker-compose.yml"))
    subnet = "${CHRONICLE_SUBNET:-172.28.0.0/16}"
    # The backend trusts forwarded client addresses only from web's fixed address on core.
    web = "${CHRONICLE_CORE_PREFIX:?run ./chronicle setup or update, which choose the core network}.2"
    backend = compose["services"]["backend"]["environment"]
    guard = compose["services"]["config-guard"]["environment"]
    assert backend["CHRONICLE_TRUSTED_PROXY_CIDRS"] == web + "/32"
    assert guard["CHRONICLE_SUBNET"] == subnet
    assert "CHRONICLE_TRUSTED_PROXY_CIDRS" not in guard  # the guard checks the prefix only
    assert compose["services"]["web"]["networks"]["core"]["ipv4_address"] == web
    assert compose["networks"]["default"]["ipam"]["config"][0]["subnet"] == subnet
    assert compose["networks"]["core"]["internal"] is True

    validator = ROOT / "selfhost" / "guard-config.sh"

    def accepted(network: str, trusted: str) -> bool:
        result = subprocess.run(
            ["bash", str(validator), "--validate-compose-subnet", network, trusted],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.returncode == 0

    assert accepted("192.168.240.0/24", "192.168.240.0/24")
    assert not accepted("192.168.240.0/24", "172.28.0.0/16")
    assert not accepted("8.8.8.0/24", "8.8.8.0/24")
    assert not accepted("192.168.240.1/24", "192.168.240.1/24")
    assert subprocess.run(["bash", str(validator), "--validate-core-prefix", "10.252.3"],
                          check=False, capture_output=True).returncode == 0
    assert subprocess.run(["bash", str(validator), "--validate-core-prefix", "8.8.8"],
                          check=False, capture_output=True).returncode != 0
    docs = read("selfhost/docs/DEPLOYMENT-COMPATIBILITY.md")
    assert "CHRONICLE_SUBNET" in docs and "CHRONICLE_TRUSTED_PROXY_CIDRS" in docs and "CHRONICLE_CORE_PREFIX" in docs


def check_w52() -> None:
    caddyfiles = [read(f"selfhost/Caddyfile.split{suffix}") for suffix in ("", ".local", ".tls")]
    for caddy in caddyfiles:
        assert "trusted_proxies static {$CADDY_TRUSTED_PROXIES:127.0.0.1/32}" in caddy
        assert "trusted_proxies_strict" in caddy
        assert "client_ip_headers X-Forwarded-For" in caddy
        assert "trusted_proxies static private_ranges" not in caddy
    compose = yaml.safe_load(read("selfhost/docker-compose.yml"))
    assert compose["services"]["web"]["environment"]["CADDY_TRUSTED_PROXIES"] == (
        "${CADDY_TRUSTED_PROXIES:-127.0.0.1/32}"
    )
    snippets = read("selfhost/caddy/snippets.caddy")
    assert "key {client_ip}" in snippets

    validator = ROOT / "selfhost" / "guard-config.sh"
    valid = subprocess.run(
        ["bash", str(validator), "--validate-forwarder-cidrs", "10.40.0.0/24 2001:db8:1234::/48"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    broad = subprocess.run(
        ["bash", str(validator), "--validate-forwarder-cidrs", "0.0.0.0/0"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert valid.returncode == 0 and broad.returncode != 0
    docs = read("selfhost/docs/DEPLOYMENT-COMPATIBILITY.md")
    assert "CADDY_TRUSTED_PROXIES" in docs and "right" in docs.lower()


def check_w54() -> None:
    dockerfile = read("selfhost/Dockerfile.caddy")
    assert re.search(r"^USER 10001:0$", dockerfile, re.M), "Caddy image must default to the edge UID"
    assert "chown -R 10001:0 /data /config" in dockerfile

    compose = yaml.safe_load(read("selfhost/docker-compose.yml"))
    services = compose["services"]
    web = services["web"]
    init = services["caddy-storage-init"]
    assert web["user"] == "10001:0"
    assert "ALL" in web["cap_drop"] and "NET_BIND_SERVICE" in web["cap_add"]
    assert web["read_only"] is True
    assert web["depends_on"]["caddy-storage-init"]["condition"] == "service_completed_successfully"
    assert init["user"] == "0:0" and init["cap_drop"] == ["ALL"]
    # DAC_READ_SEARCH: rollback leaves root files under 10001-owned 0700 dirs.
    assert init["cap_add"] == ["CHOWN", "DAC_READ_SEARCH"] and init["read_only"] is True
    assert "chown -R 10001:0 /data /config" in " ".join(init["command"])
    assert {"caddy_data:/data", "caddy_config:/config"}.issubset(set(init["volumes"]))

    monitoring = yaml.safe_load(read("selfhost/overlays/monitoring.yml"))["services"]["metrics-exporter"]
    assert monitoring["user"] == "10001:0"
    # The caddy binary carries cap_net_bind_service; a non-root exec without it is EPERM.
    assert "ALL" in monitoring["cap_drop"] and monitoring["cap_add"] == ["NET_BIND_SERVICE"]
    assert any("uid=10001,gid=0" in mount for mount in monitoring["tmpfs"])

    cert_init = read("selfhost/cert-init.sh")
    assert 'chown "${TLS_OWNER}:0" "$1"' in cert_init
    assert 'protect "$TLS_DIR/key.pem" 640' in cert_init
    assert 'protect "$KEY" 640' in cert_init
    for overlay in (
        "selfhost/overlays/mode-behind-proxy-internal.yml",
        "selfhost/overlays/mode-own-tls-internal.yml",
        "selfhost/overlays/mode-local-https.yml",
    ):
        content = yaml.safe_load(read(overlay))["services"]
        assert "cert-init" in content and "web" in content, overlay
        assert any(":/etc/caddy/certs:ro" in volume for volume in content["web"]["volumes"]), overlay
    local_export = yaml.safe_load(read("selfhost/overlays/mode-local-https.yml"))["services"]["ca-export"]
    assert local_export["user"] == "0:0", "host certificate export remains a privileged one-shot"


def check_w55() -> None:
    compose = yaml.safe_load(read("selfhost/docker-compose.yml"))["services"]
    postgres = compose["postgres"]
    assert postgres["read_only"] is True
    assert "postgres_data:/data/db" in postgres["volumes"]
    assert "postgres_tde_keyring:/var/lib/postgresql/tde-keyring" in postgres["volumes"]
    postgres_tmpfs = postgres["tmpfs"]
    assert any(mount.startswith("/tmp:size=") for mount in postgres_tmpfs)
    assert any(mount.startswith("/var/run/postgresql:size=") for mount in postgres_tmpfs)
    assert all("size=" in mount for mount in postgres_tmpfs)

    backup = yaml.safe_load(read("selfhost/overlays/backups.yml"))["services"]["db-backup"]
    assert backup["read_only"] is True
    assert any(mount.startswith("/tmp:size=") for mount in backup["tmpfs"])
    assert "${CHRONICLE_STATE_DIR:-.}/backups:/backups:z" in backup["volumes"]

    ca_export = yaml.safe_load(read("selfhost/overlays/mode-local-https.yml"))["services"]["ca-export"]
    assert ca_export["read_only"] is True
    assert any(mount.startswith("/tmp:size=") for mount in ca_export["tmpfs"])
    assert "${CHRONICLE_STATE_DIR:-.}/tls:/out:z" in ca_export["volumes"]


def check_w56() -> None:
    spec = importlib.util.spec_from_file_location('release_inventory', ROOT / 'scripts/build-selfhost-release.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    tracked = {'selfhost/' + name for name in builder.operator_files()}
    with tempfile.TemporaryDirectory(dir=SCRATCH_DIR) as folder:
        bundle = Path(folder)
        builder.copy_operator_files(bundle, tracked)
        for name in ('network-policy.sh', 'doctor.sh', 'rotation-http.sh',
                     'chronicle_ops/setup_env.py'):
            assert (bundle / 'selfhost' / name).is_file(), name


def check_w61() -> None:
    socket_proxy = yaml.safe_load(read("selfhost/overlays/monitoring.yml"))["services"]["docker-socket-proxy"]
    assert 1 <= socket_proxy["pids_limit"] <= 128
    # Since c34f742c the proxy runs HAProxy on Chronicle's own config instead of the image's
    # environment-driven template (POST=0 and friends no longer exist): only GET on the listed
    # read paths passes, so no write (POST, PUT, DELETE) reaches the socket.
    assert socket_proxy["entrypoint"] == ["haproxy"]
    assert "/etc/haproxy/chronicle.cfg" in socket_proxy["command"]
    assert "./monitoring/docker-api.cfg:/etc/haproxy/chronicle.cfg:ro,z" in socket_proxy["volumes"]
    assert "environment" not in socket_proxy, "the image's env template is unused; settings there do nothing"
    config = read("selfhost/monitoring/docker-api.cfg")
    assert re.search(r"(?m)^\s*acl read_method method GET\s*$", config)
    assert re.search(r"(?m)^\s*http-request deny deny_status 403 unless read_method allowed_path\s*$", config)
    assert "/var/run/docker.sock:/var/run/docker.sock:ro" in socket_proxy["volumes"]


def check_w67() -> None:
    sys.path.insert(0, str(ROOT / 'selfhost'))
    from chronicle_ops.images import SOURCE_IMAGES, bundle_images
    expected = bundle_images(ROOT / 'selfhost') - {image.placeholder for image in SOURCE_IMAGES}
    assert expected and all(re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image) for image in expected)

    plan = subprocess.run(['bash', str(ROOT / 'scripts/publish-images.sh'), '1.2.3', '--dry-run'],
                          check=True, capture_output=True, text=True).stdout.splitlines()
    scans = [index for index, line in enumerate(plan) if 'scan-selfhost-release-images.sh' in line]
    pushes = [index for index, line in enumerate(plan) if line.startswith('docker push ')]
    assert len(scans) == len(SOURCE_IMAGES) + 1
    assert len(pushes) == len(SOURCE_IMAGES) and max(scans) < min(pushes)
    # Container-infra I1-I3 and B8: every built image passes the image policy, the third-party images get
    # the SSH, listener and policy checks too, and an ignore entry that suppressed nothing fails the run;
    # all before anything is pushed.
    policies = [line for line in plan if 'scripts/check-image-policy.py' in line]
    assert sorted(line.split()[-1].split('=', 1)[0] for line in policies) == sorted(image.component for image in SOURCE_IMAGES)
    runtime = [index for index, line in enumerate(plan) if 'scripts/check-runtime-images.py' in line]
    stale = [index for index, line in enumerate(plan) if 'check-trivy-waivers.py' in line and '--reports' in line]
    assert len(runtime) == 1 and len(stale) == 1 and max(scans) < stale[0] < min(pushes) and runtime[0] < min(pushes)
    assert all('CHRONICLE_TRIVY_REPORT_DIR=' in plan[index] for index in scans)
    # Container-infra I6 / audit AF-T8: every pushed digest is signed and its BuildKit provenance attested
    # with the image-signing key while still logged in, both verified against the shipped public key, and
    # the Sigstore bundles go into the release.
    assert all('BUILDX_METADATA_PROVENANCE=max' in line and '--metadata-file' in line for line in plan if ' docker build ' in line)
    logout = next(index for index, line in enumerate(plan) if line.startswith('docker logout ghcr.io'))
    for command in ('cosign sign ', 'cosign attest ', 'cosign verify ', 'cosign verify-attestation '):
        calls = [index for index, line in enumerate(plan) if line.startswith(command)]
        assert len(calls) == len(SOURCE_IMAGES) and max(pushes) < min(calls) and max(calls) < logout, command
    assert all('--signing-config' in line and '--bundle' in line for line in plan if line.startswith(('cosign sign ', 'cosign attest ')))
    assert any('build-selfhost-release.py' in line and '--image-signatures' in line for line in plan)

    # The publish gate itself: a failed check of one image is recorded, the remaining checks and images
    # still run, and require_image_checks then fails naming each failure before the source check and
    # the push. The shipped functions run here against recording stand-ins for the four checks.
    publish = read("scripts/publish-images.sh")
    gate = publish[publish.index("# Nothing reaches the registry with"):publish.index("build_component() {")]
    SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="W67-gate-", dir=SCRATCH_DIR) as temporary:
        fixture = Path(temporary)
        (fixture / "scripts").mkdir()
        gate_calls = fixture / "calls"
        for name in ("check-image-no-ssh-server.sh", "check-image-listeners.sh", "scan-selfhost-release-images.sh"):
            (fixture / "scripts" / name).write_text(
                'name=${0##*/}\n'
                'printf \'%s %s\\n\' "$name" "$*" >> "$GATE_CALLS"\n'
                'case ",${GATE_FAIL:-}," in *",$name ${!#},"*) exit 1 ;; esac\n', encoding="utf-8")
        (fixture / "scripts" / "check-image-policy.py").write_text(
            "import os, sys\n"
            "name = os.path.basename(sys.argv[0])\n"
            "open(os.environ['GATE_CALLS'], 'a').write(name + ' ' + ' '.join(sys.argv[1:]) + '\\n')\n"
            "sys.exit(f'{name} {sys.argv[-1]}' in os.environ.get('GATE_FAIL', '').split(','))\n", encoding="utf-8")
        harness = fixture / "gate.sh"
        harness.write_text(
            "set -euo pipefail\n"
            "dry_run=''\n"
            f"root={fixture}\n"
            f"trivy_reports={fixture}/reports\n"
            "stamp() { :; }\n"
            'run() { "$@"; }\n'
            + gate +
            "scan_image tag-a a\n"
            "scan_image tag-b b\n"
            "if declare -F require_image_checks >/dev/null; then require_image_checks; fi\n"
            "echo reached-push\n", encoding="utf-8")
        every_check = [f"{name} {argument}" for tag, component in (("tag-a", "a"), ("tag-b", "b"))
                       for name, argument in (("check-image-no-ssh-server.sh", tag), ("check-image-listeners.sh", tag),
                                              ("check-image-policy.py", f"{component}={tag}"),
                                              ("scan-selfhost-release-images.sh", tag))]
        for failing, named in (("", []),
                               ("check-image-no-ssh-server.sh tag-a", ["tag-a: SSH server"]),
                               ("check-image-listeners.sh tag-a,scan-selfhost-release-images.sh tag-b",
                                ["tag-a: listeners", "tag-b: trivy scan"]),
                               ("check-image-policy.py b=tag-b", ["tag-b: image policy"])):
            gate_calls.write_text("", encoding="utf-8")
            result = subprocess.run(["bash", str(harness)], capture_output=True, text=True,
                                    env=dict(os.environ, GATE_CALLS=str(gate_calls), GATE_FAIL=failing))
            assert gate_calls.read_text(encoding="utf-8").splitlines() == every_check, (failing, result.stderr)
            assert result.returncode == (1 if named else 0), (failing, result.stderr)
            assert ("reached-push" in result.stdout) == (not named), (failing, result.stdout)
            if named:
                lines = result.stderr.splitlines()[-len(named) - 1:]
                assert lines[0] == f"error: {len(named)} image checks failed; nothing was pushed:", result.stderr
                assert [line.strip() for line in lines[1:]] == named, result.stderr
    assert publish.index("\nrequire_image_checks\nrun require_unchanged_source\n") < publish.index("\nstamp push\n")

    # Images are built and scanned for the platform the ignore-file purls name; an unpinned build on
    # an arm64 host made arm64 images whose findings no x86_64 entry matched (2026.11.12).
    builds = [line for line in plan if ' docker build ' in line]
    assert builds and all('docker build --platform linux/amd64 ' in line for line in builds), builds
    ignore = yaml.safe_load(read(".trivyignore.yaml"))["vulnerabilities"]
    assert all('arch=x86_64' in purl or 'arch=noarch' in purl for item in ignore for purl in item.get("purls", [])
               if purl.startswith("pkg:rpm/")), "rpm ignore entries must name the release platform"
    assert ignore and all((item.get("paths") or item.get("purls")) and item.get("statement") and item.get("expired_at") for item in ignore)

    helper = ROOT / "scripts" / "scan-selfhost-release-images.sh"
    scratch = SCRATCH_DIR
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="W67-", dir=scratch) as temporary:
        fixture = Path(temporary)
        bin_dir = fixture / "bin"
        bin_dir.mkdir()
        log = fixture / "trivy.log"
        stub = bin_dir / "trivy"
        # Records every call. The gating scan (--exit-code N) of TRIVY_FAIL_IMAGE exits N as trivy does for
        # a finding; the report scan (--output FILE) writes FILE, or fails for TRIVY_FAIL_REPORT_IMAGE.
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "printf '%s\\n' \"$*\" >> \"$TRIVY_LOG\"\n"
            "previous='' output='' gating='' image=''\n"
            "for argument in \"$@\"; do\n"
            "  [[ \"$previous\" != --output ]] || output=$argument\n"
            "  [[ \"$previous\" != --exit-code ]] || gating=$argument\n"
            "  previous=$argument\n"
            "  image=$argument\n"
            "done\n"
            "if [[ -n \"$gating\" && \"$image\" == \"${TRIVY_FAIL_IMAGE:-}\" ]]; then exit \"$gating\"; fi\n"
            "if [[ -n \"$output\" && \"$image\" == \"${TRIVY_FAIL_REPORT_IMAGE:-}\" ]]; then exit 1; fi\n"
            "[[ -z \"$output\" ]] || printf '{}\\n' > \"$output\"\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
        env["TRIVY_LOG"] = str(log)
        explicit = ["ghcr.io/example/backend:v1.2.3", "ghcr.io/example/frontend:v1.2.3"]
        for command, inventory, source in ((["bash", str(helper)], sorted(expected), ["--image-src", "remote"]),
                                           (["bash", str(helper), *explicit], explicit, [])):
            env.pop("TRIVY_FAIL_IMAGE", None)
            passed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
            assert passed.returncode == 0, passed.stderr
            scans = [line.split() for line in log.read_text(encoding="utf-8").splitlines()]
            assert [args[-1] for args in scans] == inventory
            for args in scans:
                # Secrets too (container-infra I8): a key copied into a layer and deleted later still ships.
                assert args[:-1] == ["image", "--quiet", "--platform", "linux/amd64", *source, "--scanners", "vuln,secret", "--severity", "HIGH,CRITICAL",
                                    "--exit-code", "1", "--skip-db-update", "--skip-java-db-update",
                                    "--ignorefile", str(ROOT / ".trivyignore.yaml")], args
            log.unlink()
            # A finding fails the run after every image has been scanned, and the last lines name the
            # images that failed. Stopping at the first one (the 2026.11.12 image gate) hid the findings
            # of the images behind it.
            for failing in (inventory[0], inventory[-1]):
                env["TRIVY_FAIL_IMAGE"] = failing
                failed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
                assert failed.returncode == 1, failed.stderr
                assert [line.split()[-1] for line in log.read_text(encoding="utf-8").splitlines()] == inventory
                summary = failed.stderr.splitlines()[-2:]
                assert summary[0].startswith(f"error: 1 of {len(inventory)} images failed the release scan"), failed.stderr
                assert summary[1].split() == [failing, "(finding,", "secret", "or", "scanner", "error)"], failed.stderr
                log.unlink()
        # With a report directory each image also gets a JSON report of its waived findings, which
        # tests/security/check-trivy-waivers.py --reports reads to find ignore entries that match nothing.
        # An image with a finding gets its report too: the report is what a waiver is written from.
        reports = fixture / "reports"
        env["CHRONICLE_TRIVY_REPORT_DIR"] = str(reports)
        names = [re.sub(r"[^A-Za-z0-9._-]", "_", image) + ".json" for image in explicit]
        for failing, failing_report in ((None, None), (explicit[0], None), (explicit[1], None), (None, explicit[0])):
            env.pop("TRIVY_FAIL_IMAGE", None)
            env.pop("TRIVY_FAIL_REPORT_IMAGE", None)
            if failing:
                env["TRIVY_FAIL_IMAGE"] = failing
            if failing_report:
                env["TRIVY_FAIL_REPORT_IMAGE"] = failing_report
            reported = subprocess.run(["bash", str(helper), *explicit], cwd=ROOT, env=env, capture_output=True, text=True)
            assert reported.returncode == (1 if failing or failing_report else 0), reported.stderr
            calls = [line.split() for line in log.read_text(encoding="utf-8").splitlines()]
            assert [args[-1] for args in calls] == [image for image in explicit for _ in (0, 1)]
            for args in calls[1::2]:
                assert "--show-suppressed" in args and args[args.index("--format") + 1] == "json"
                assert "--exit-code" not in args and args[args.index("--output") + 1].startswith(str(reports) + "/")
            written = sorted(path.name for path in reports.iterdir())
            assert written == sorted(name for name, image in zip(names, explicit) if image != failing_report), written
            if failing_report:
                assert reported.stderr.splitlines()[-1].split() == [failing_report, "(report", "not", "written)"], reported.stderr
            for path in reports.iterdir():
                path.unlink()
            log.unlink()
        env.pop("TRIVY_FAIL_REPORT_IMAGE", None)
        del env["CHRONICLE_TRIVY_REPORT_DIR"]
        for invalid in ("", "--download-db-only", "image:tag\nanother:tag"):
            rejected = subprocess.run(["bash", str(helper), invalid], env=env, capture_output=True)
            assert rejected.returncode != 0 and not log.exists()


def check_w48() -> None:
    monitoring = runpy.run_path(str(ROOT / 'tests/security/selfhost-monitoring.py'))
    monitoring['test_backup_sbom_inventory']()


def check_w79() -> None:
    guard = ROOT / "selfhost" / "guard-config.sh"

    def allowed(host: str) -> bool:
        result = subprocess.run(
            ["bash", str(guard), "--validate-public-host", host],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.returncode == 0

    for host in (
        "study.hospital.corp",
        "gateway.home",
        "mail.example.mail",
        "chronicle.internal",
        "host.home.arpa",
        "device.lan",
        "service.local",
        "server.invalid",
        "study.example.org",
    ):
        assert not allowed(host), host
    assert allowed("study.university.edu")
    assert not allowed("192.168.1.50")  # the local-https mode continues accepting private LAN addresses
    setup = read("selfhost/chronicle")
    assert 'bash ./guard-config.sh --validate-public-host "$domain"' in setup
    docs = read("selfhost/docs/DEPLOYMENT-COMPATIBILITY.md").lower()
    assert "corp" in docs and "home" in docs and "mail" in docs and "local-https" in docs


def check_cross_s02() -> None:
    example = read("selfhost/.env.example")
    assert re.search(r"(?m)^CHRONICLE_SESSION_IDLE_MINUTES=15$", example)
    compose = yaml.safe_load(read("selfhost/docker-compose.yml"))["services"]
    expected_expression = "${CHRONICLE_SESSION_IDLE_MINUTES:-15}"
    for service in ("config-guard", "backend"):
        assert compose[service]["environment"]["CHRONICLE_SESSION_IDLE_MINUTES"] == expected_expression

    guard = ROOT / "selfhost" / "guard-config.sh"

    def allowed(value: str) -> bool:
        result = subprocess.run(
            ["bash", str(guard), "--validate-session-idle-minutes", value],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.returncode == 0

    def compose_value(supplied: str | None) -> str:
        match = re.fullmatch(r"\$\{([A-Z0-9_]+):-([0-9]+)\}", expected_expression)
        assert match
        return supplied or match.group(2)

    for supplied in (None, "", "1", "15", "120"):
        assert allowed(compose_value(supplied)), supplied
    for invalid in ("0", "121", "-1", "1.0", "abc", "1000", "000"):
        assert not allowed(compose_value(invalid)), invalid

    # The server enforces the same range at startup (ChronicleAuthConfigurationTest).
    for path in ("selfhost/README.md", "selfhost/docs/DEPLOYMENT-COMPATIBILITY.md"):
        docs = read(path)
        assert "CHRONICLE_SESSION_IDLE_MINUTES" in docs and "120" in docs and "15" in docs


CHECKS = {
    "W11": check_w11,
    "W12": check_w12,
    "W47": check_w47,
    "W49": check_w49,
    "W50": check_w50,
    "W51": check_w51,
    "W52": check_w52,
    "W54": check_w54,
    "W55": check_w55,
    "W56": check_w56,
    "W61": check_w61,
    "W67": check_w67,
    "W48": check_w48,
    "W79": check_w79,
    "CROSS-S02": check_cross_s02,
}


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--all":
        for name, check in CHECKS.items():
            check()
            print(f"{name} deployment regression passed")
        return
    if len(sys.argv) != 2 or sys.argv[1] not in CHECKS:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} --all|{'|'.join(CHECKS)}")
    CHECKS[sys.argv[1]]()
    print(f"{sys.argv[1]} deployment regression passed")


if __name__ == "__main__":
    main()
