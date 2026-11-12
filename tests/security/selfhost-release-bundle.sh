#!/usr/bin/env bash
set -euo pipefail
export CHRONICLE_RECONCILE_ENABLED=false

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
BUILDER="${ROOT_DIR}/scripts/build-selfhost-release.py"
SOURCE_REVISION="$(git -C "$ROOT_DIR" rev-parse HEAD)"
# The builder requires a CHANGELOG entry for the bundle version: use the newest released heading.
RELEASE_VERSION=$(git -C "$ROOT_DIR" show "${SOURCE_REVISION}:CHANGELOG.md" |
  sed -n 's/^## \[\([0-9][0-9.]*\)\]$/\1/p' | sed -n 1p)
RUN_PARENT="${SELFHOST_RELEASE_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-release}"
BACKEND_IMAGE='ghcr.io/example/chronicle-backend@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
FRONTEND_IMAGE='ghcr.io/example/chronicle-selfhost-frontend@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
CADDY_IMAGE='ghcr.io/example/chronicle-selfhost-caddy@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
BACKUP_IMAGE='ghcr.io/example/chronicle-selfhost-backup@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
GRAFANA_IMAGE='ghcr.io/example/chronicle-selfhost-grafana@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
POSTGRES_IMAGE='ghcr.io/example/chronicle-selfhost-postgres@sha256:9999999999999999999999999999999999999999999999999999999999999999'
FLUENTBIT_IMAGE='ghcr.io/example/chronicle-selfhost-fluentbit@sha256:8888888888888888888888888888888888888888888888888888888888888888'
PRIVATE_REGISTRY_IMAGE='registry.example.org:5443/chronicle/backend@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'

fail() {
  echo "self-host release bundle test failed: $*" >&2
  exit 1
}

[[ "$RUN_PARENT" == /* ]] || fail "test run parent must be absolute"
case "$RUN_PARENT" in
  /tmp|/tmp/*|/private/tmp|/private/tmp/*|/var/folders|/var/folders/*)
    fail "test run parent must not use a system temporary directory"
    ;;
esac
[[ -x "$BUILDER" ]] || fail "release builder is missing or not executable"

umask 077
/bin/mkdir -p "$RUN_PARENT"
RUN_DIR="$(/usr/bin/mktemp -d "${RUN_PARENT}/run.XXXXXX")"
trap '/bin/rm -rf -- "$RUN_DIR"' EXIT

# The publisher archives HEAD. Give its clean-source check that same immutable tree,
# leaving developer edits in place; fresh-bundle Python tests package the working files.
SOURCE_SNAPSHOT="${RUN_DIR}/committed-inputs"
mkdir "$SOURCE_SNAPSHOT"
git -C "$ROOT_DIR" archive "$SOURCE_REVISION" -- \
  selfhost docker/init-db-roles.sql LICENSE THIRD-PARTY.md CHANGELOG.md SECURITY.md |
  tar -xf - -C "$SOURCE_SNAPSHOT"
run_builder() {
  GIT_WORK_TREE="$SOURCE_SNAPSHOT" GIT_OPTIONAL_LOCKS=0 "$BUILDER" "$@"
}

# The fixture digests exist in no registry: answer the builder's provenance-label lookup for them and pass
# every other docker call through.
REAL_DOCKER="$(command -v docker)"
INPUTS_TREE="$(git -C "$ROOT_DIR" rev-parse "${SOURCE_REVISION}^{tree}")"
MISLABELLED_IMAGE='ghcr.io/example/chronicle-backend@sha256:9999999999999999999999999999999999999999999999999999999999999999'
/bin/mkdir "${RUN_DIR}/bin"
cat >"${RUN_DIR}/bin/docker" <<STUB
#!/usr/bin/env bash
if [[ "\$1 \$2" == "image inspect" ]]; then
  case "\${@: -1}" in
    "$MISLABELLED_IMAGE") echo 0000000000000000000000000000000000000000 linux/amd64; exit 0 ;;
    "$BACKEND_IMAGE"|"$FRONTEND_IMAGE"|"$CADDY_IMAGE"|"$BACKUP_IMAGE"|"$GRAFANA_IMAGE"|"$POSTGRES_IMAGE"|"$FLUENTBIT_IMAGE"|"$PRIVATE_REGISTRY_IMAGE")
      echo "$INPUTS_TREE linux/amd64"; exit 0 ;;
  esac
fi
# The launcher's daemon-architecture preflight (test_host_architecture covers it): answer the release
# platform so a run on an arm64 workstation reaches the wizard steps this test checks.
if [[ "\$*" == "info --format {{.Architecture}}" ]]; then echo x86_64; exit 0; fi
exec "$REAL_DOCKER" "\$@"
STUB
/bin/chmod 700 "${RUN_DIR}/bin/docker"
export PATH="${RUN_DIR}/bin:${PATH}"

python3 - "$BUILDER" "$RUN_DIR" <<'PY'
import importlib.util
from pathlib import Path
import sys

builder_path = Path(sys.argv[1])
run_dir = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("selfhost_release_builder", builder_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

release_root = run_dir / "containment-root"
release_root.mkdir()
outside = run_dir / "outside.txt"
outside.write_text("must not be copied\n", encoding="utf-8")
try:
    module.resolve_within(
        release_root,
        release_root / ".." / outside.name,
        strict=True,
        description="test input",
    )
except SystemExit as error:
    if "escapes its release root" not in str(error):
        raise
else:
    raise SystemExit("release path containment helper accepted traversal outside its root")
PY

build_bundle() {
  local output_dir="$1"
  /bin/mkdir -p "$output_dir"
  run_builder \
    --version "v${RELEASE_VERSION}" \
    --source-revision "$SOURCE_REVISION" \
    --public-revision fedcba9876543210fedcba9876543210fedcba98 \
    --source-date-epoch 1700000000 \
    --backend-image "$BACKEND_IMAGE" \
    --frontend-image "$FRONTEND_IMAGE" \
    --caddy-image "$CADDY_IMAGE" \
    --backup-image "$BACKUP_IMAGE" \
    --grafana-image "$GRAFANA_IMAGE" \
    --postgres-image "$POSTGRES_IMAGE" \
    --fluentbit-image "$FLUENTBIT_IMAGE" \
    --output-dir "$output_dir" >/dev/null
}

build_bundle "${RUN_DIR}/first"
build_bundle "${RUN_DIR}/second"

run_builder \
  --version "v${RELEASE_VERSION}" \
  --source-revision "$SOURCE_REVISION" \
  --source-date-epoch 1700000000 \
  --backend-image "$PRIVATE_REGISTRY_IMAGE" \
  --frontend-image "$FRONTEND_IMAGE" \
  --caddy-image "$CADDY_IMAGE" \
  --backup-image "$BACKUP_IMAGE" \
  --grafana-image "$GRAFANA_IMAGE" \
  --postgres-image "$POSTGRES_IMAGE" \
  --fluentbit-image "$FLUENTBIT_IMAGE" \
  --output-dir "${RUN_DIR}/private-registry" >/dev/null \
  || fail "builder rejected an immutable image in a private registry with an explicit port"
grep -Fqx "BACKEND_IMAGE=${PRIVATE_REGISTRY_IMAGE}" \
  "${RUN_DIR}/private-registry/chronicle-selfhost-${RELEASE_VERSION}/selfhost/.env.example" \
  || fail "private-registry image was not rendered into the release bundle"

ARCHIVE="${RUN_DIR}/first/chronicle-selfhost-${RELEASE_VERSION}.tar.gz"
CHECKSUM="${ARCHIVE}.sha256"
BUNDLE="${RUN_DIR}/first/chronicle-selfhost-${RELEASE_VERSION}"
[[ -s "$ARCHIVE" && -s "$CHECKSUM" && -d "$BUNDLE" ]] || fail "builder did not emit all bundle artifacts"
python3 - "$BUILDER" "$BUNDLE" <<'PY_OFFLINE_LINKS'
from pathlib import Path
import runpy
import sys
runpy.run_path(sys.argv[1])['require_offline_links'](Path(sys.argv[2]))
PY_OFFLINE_LINKS

first_hash="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
second_hash="$(sha256sum "${RUN_DIR}/second/$(basename "$ARCHIVE")" | awk '{print $1}')"
[[ "$first_hash" == "$second_hash" ]] || fail "identical inputs did not produce a reproducible archive"
(cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$CHECKSUM")" >/dev/null) \
  || fail "published archive checksum does not verify"

tar -tzf "$ARCHIVE" >"${RUN_DIR}/archive-members.txt"
python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); sys.exit(m.get("public_revision") != "fedcba9876543210fedcba9876543210fedcba98")' \
  "${BUNDLE}/release-manifest.json" || fail "manifest does not record the public source revision"
publish_plan="$(cd "$ROOT_DIR" && bash scripts/publish-images.sh "$RELEASE_VERSION" --dry-run 2>&1)" \
  || fail "publish-images dry run failed"
grep -Fq -- '--public-revision' <<<"$publish_plan" || fail "publish does not pass the public revision to the builder"
grep -Eq 'gh release create .*--target' <<<"$publish_plan" || fail "GitHub release is not pinned to the public revision"
# No image reaches the registry with a fixable HIGH/CRITICAL finding.
for image_name in chronicle-backend chronicle-selfhost-frontend chronicle-selfhost-caddy; do
  scan_line=$(grep -n "bash .*scan-selfhost-release-images.sh .*${image_name}:" <<<"$publish_plan" | sed -n 1p | cut -d: -f1 || true)
  push_line=$(grep -n "docker push .*${image_name}:" <<<"$publish_plan" | sed -n 1p | cut -d: -f1 || true)
  [[ -n "$scan_line" && -n "$push_line" && "$scan_line" -lt "$push_line" ]] \
    || fail "publish pushes ${image_name} without a blocking trivy HIGH/CRITICAL scan first"
done
# Fail fast: the first image is scanned before the last one is built.
first_scan=$(grep -n 'bash .*scan-selfhost-release-images.sh ' <<<"$publish_plan" | sed -n 1p | cut -d: -f1)
last_build=$(grep -n 'docker build ' <<<"$publish_plan" | tail -1 | cut -d: -f1)
[[ -n "$first_scan" && -n "$last_build" && "$first_scan" -lt "$last_build" ]] \
  || fail "publish builds every image before scanning any"
grep -Fq -- '--severity HIGH,CRITICAL --exit-code 1' "$ROOT_DIR/scripts/scan-selfhost-release-images.sh" || fail "publish scan does not gate HIGH and CRITICAL"
# A dedicated write:packages token, never the operator's general gh token.
! grep -Fq 'gh auth token' "$ROOT_DIR/scripts/publish-images.sh" || fail "publish logs in to GHCR with the general gh token"
grep -Fq 'printf %s "$ghcr_token" | docker login ghcr.io' <<<"$publish_plan" \
  || fail "publish does not log in with the GHCR_TOKEN it took (unexported) at start"
unset_token_out="$(cd "$ROOT_DIR" && env -u GHCR_TOKEN bash scripts/publish-images.sh "$RELEASE_VERSION" 2>&1)" \
  && fail "publish ran without GHCR_TOKEN"
grep -Fq 'GHCR_TOKEN' <<<"$unset_token_out" || fail "publish without GHCR_TOKEN did not name the missing token"
grep -Fqx "chronicle-selfhost-${RELEASE_VERSION}/selfhost/docker-compose.yml" "${RUN_DIR}/archive-members.txt" \
  || fail "archive lacks selfhost/docker-compose.yml"
for shipped in CHANGELOG.md SECURITY.md LICENSE THIRD-PARTY.md \
               selfhost/docs/INCIDENT-RESPONSE.md selfhost/backup-prune-hook.sh selfhost/network-subnet.py selfhost/release-signing.pub \
               selfhost/secrets-init.sh selfhost/monitoring/docker-compose.grafana-alerts-closed.yml \
               selfhost/monitoring/docker-api-strip-env.lua; do
  grep -Fqx "chronicle-selfhost-${RELEASE_VERSION}/${shipped}" "${RUN_DIR}/archive-members.txt" \
    || fail "archive lacks ${shipped}"
done
grep -Fqx "chronicle-selfhost-${RELEASE_VERSION}/docker/init-db-roles.sql" "${RUN_DIR}/archive-members.txt" \
  || fail "archive lacks the database role bootstrap dependency"
grep -Fqx "chronicle-selfhost-${RELEASE_VERSION}/selfhost/backup-entrypoint.sh" "${RUN_DIR}/archive-members.txt" \
  || fail "archive lacks the restart-safe backup entrypoint"

grep -Fqx "chronicle-selfhost-${RELEASE_VERSION}/selfhost/rotate-secret.sh" "${RUN_DIR}/archive-members.txt" \
  || fail "archive lacks the guarded secret-rotation command"
grep -Fqx "chronicle-selfhost-${RELEASE_VERSION}/selfhost/docs/UPGRADE-ROLLBACK.md" "${RUN_DIR}/archive-members.txt" \
  || fail "archive lacks upgrade/rollback recovery instructions"
grep -Fqx "chronicle-selfhost-${RELEASE_VERSION}/selfhost/docs/SECRET-ROTATION.md" "${RUN_DIR}/archive-members.txt" \
  || fail "archive lacks secret-rotation recovery instructions"
grep -Fqx "chronicle-selfhost-${RELEASE_VERSION}/selfhost/docs/DEPLOYMENT-COMPATIBILITY.md" "${RUN_DIR}/archive-members.txt" \
  || fail "archive lacks the supported deployment compatibility contract"
grep -Fqx "chronicle-selfhost-${RELEASE_VERSION}/selfhost/docs/UNINSTALL-DATA-DELETION.md" "${RUN_DIR}/archive-members.txt" \
  || fail "archive lacks data-deletion and complete-uninstall instructions"
if grep -Eq '/(chronicle-server|chronicle-web|chronicle-api|rhizome|gradle)(/|$)|Dockerfile' \
    "${RUN_DIR}/archive-members.txt"; then
  fail "archive contains source/build-tooling paths"
fi
if grep -Fq '/experimental/' "${RUN_DIR}/archive-members.txt"; then
  fail "archive includes an experimental deployment path"
fi

ENV_EXAMPLE="${BUNDLE}/selfhost/.env.example"
env_example_mode="$(stat -c '%a' "$ENV_EXAMPLE" 2>/dev/null || stat -f '%Lp' "$ENV_EXAMPLE")"
[[ "$env_example_mode" == 600 ]] ||
  fail "bundled .env.example mode is ${env_example_mode}; plain cp would expose deployment secrets"
# Every bundle directory is bind-mounted or searched by a container user (config-guard as the
# postgres uid, config/ by the backend user); only the runtime dirs are private.
while IFS= read -r dir; do
  dir_mode="$(stat -c '%a' "$dir" 2>/dev/null || stat -f '%Lp' "$dir")"
  [[ "$dir_mode" == 755 ]] ||
    fail "bundle directory $dir is mode ${dir_mode} under umask 077; container users cannot search it"
done < <(find "$BUNDLE" -type d ! -path "${BUNDLE}/selfhost/backups" ! -path "${BUNDLE}/selfhost/tls")
for pair in "backups:700" "tls:755"; do
  dir="${BUNDLE}/selfhost/${pair%%:*}"
  dir_mode="$(stat -c '%a' "$dir" 2>/dev/null || stat -f '%Lp' "$dir")"
  [[ "$dir_mode" == "${pair##*:}" ]] ||
    fail "bundle directory $dir is mode ${dir_mode}; expected ${pair##*:} (dumps private, tls searchable by cert-init consumers)"
done
grep -Fqx "BACKEND_IMAGE=${BACKEND_IMAGE}" "$ENV_EXAMPLE" || fail "backend digest was not rendered"
grep -Fqx "SELFHOST_FRONTEND_IMAGE=${FRONTEND_IMAGE}" "$ENV_EXAMPLE" || fail "frontend digest was not rendered"
grep -Fqx "CADDY_IMAGE=${CADDY_IMAGE}" "$ENV_EXAMPLE" || fail "Caddy digest was not rendered"
! grep -Fq '__CHRONICLE_' "$ENV_EXAMPLE" || fail "generated env file retains image placeholders"
grep -Fq './backup-entrypoint.sh:/selfhost/backup-entrypoint.sh:ro' \
  "${BUNDLE}/selfhost/overlays/backups.yml" \
  || fail "backup overlay does not use the bundled readiness wrapper"
grep -Fq 'respond @chronicle_retired_api 404' \
  "${BUNDLE}/selfhost/caddy/snippets.caddy" \
  || fail "bundle does not reject retired mobile API prefixes"
[[ -f "${BUNDLE}/selfhost/monitoring/grafana-datasources.yml" ]] \
  || fail "bundle omits the Grafana metrics/logs data-source provisioning"
for dashboard in system-overview application database-storage containers operational-events operational-logs; do
  [[ -f "${BUNDLE}/selfhost/monitoring/grafana-dashboards/${dashboard}.json" ]] \
    || fail "bundle omits the ${dashboard} monitoring dashboard"
done
[[ -f "${BUNDLE}/selfhost/monitoring/grafana-alerting/rules.yml" ]] \
  || fail "bundle omits dashboard-visible alert provisioning"
[[ -x "${BUNDLE}/selfhost/monitoring/probe.sh" ]] \
  || fail "bundle omits the executable operational probe"
"${ROOT_DIR}/tests/security/selfhost-log-sanitizer.sh" >/dev/null \
  || fail "structured log sanitizer fixtures failed"
[[ -x "${BUNDLE}/selfhost/rotate-secret.sh" ]] || fail "bundled secret-rotation command is not executable"
[[ -x "${BUNDLE}/selfhost/chronicle" ]] || fail "bundled operator command is not executable"
help_output="$(cd "$BUNDLE" && selfhost/chronicle help)" \
  || fail "bundled operator help fails outside the selfhost directory"
grep -Fq './chronicle doctor [--json]' <<<"$help_output" \
  || fail "bundled operator help omits doctor"
grep -Fq 'deletion-status) cmd_deletion_status' "${BUNDLE}/selfhost/chronicle" \
  || fail "bundled operator command omits deletion proof status"
grep -Fq 'doctor) cmd_doctor' "${BUNDLE}/selfhost/chronicle" \
  || fail "bundled operator command omits actionable diagnostics"
grep -Fq 'monitoring) cmd_monitoring' "${BUNDLE}/selfhost/chronicle" \
  || fail "bundled operator command omits monitoring viewer management"
grep -Fq 'write_operation_receipt()' "${BUNDLE}/selfhost/chronicle" \
  || fail "bundled operator command omits secret-free operation receipts"
grep -Fq 'restore) cmd_restore' "${BUNDLE}/selfhost/chronicle" \
  || fail "bundled operator command omits guarded restore orchestration"
source "$ROOT_DIR/tests/security/lib/selfhost-fixtures.sh"
SELFHOST_PYTHON_PACKAGE="${BUNDLE}/selfhost" run_selfhost_python_suite \
    test_restore.RestoreTests.test_success_order_permissions_and_profile \
  || fail "bundled restore command does not mark an orchestrated one-shot restore"
grep -Fq 'direct restore-service execution is disabled' "${BUNDLE}/selfhost/restore.sh" \
  || fail "bundled restore service permits unsafe direct execution"

# The shipped updater enforces the reset floor before staging or stopping writers.
SELFHOST_PYTHON_PACKAGE="${BUNDLE}/selfhost" run_selfhost_python_suite \
  test_forward_update.ForwardPolicyTests.test_floor_and_downgrade_are_refused \
  || fail "bundled update does not enforce the upgrade floor"

mapfile -t bundled_modes < <(
  find "${BUNDLE}/selfhost/overlays" -maxdepth 1 -type f -name 'mode-*.yml' -exec basename {} \; | LC_ALL=C sort
)
expected_modes=$'mode-behind-proxy-internal.yml\nmode-local-https.yml\nmode-own-tls-internal.yml'
[[ "$(printf '%s\n' "${bundled_modes[@]}")" == "$expected_modes" ]] \
  || fail "bundle does not contain exactly the three supported deployment modes"
[[ ! -e "${BUNDLE}/selfhost/Caddyfile" && ! -e "${BUNDLE}/selfhost/Caddyfile.tls" ]] \
  || fail "bundle contains obsolete public-dashboard Caddyfiles"
grep -Fq 'CHRONICLE_STATE_DIR=.' "$ENV_EXAMPLE" \
  || fail "bundle omits release-independent mutable state configuration"
grep -Fq 'SECRET_ROTATION_WAIT_TIMEOUT_SECONDS=300' "$ENV_EXAMPLE" \
  || fail "bundle omits the bounded secret-rotation wait"
grep -Fqx 'RESTORE_START_WAIT_TIMEOUT_SECONDS=3600' "$ENV_EXAMPLE" \
  || fail "bundle omits the bounded post-restore health wait"
postgres_service="$({
  awk '
    /^  postgres:$/ { in_postgres = 1; next }
    in_postgres && /^  [[:alnum:]_-]+:$/ { exit }
    in_postgres { print }
  ' "${BUNDLE}/selfhost/docker-compose.yml"
})"
grep -Fq 'start_period: 90s' <<<"$postgres_service" \
  || fail "bundled PostgreSQL healthcheck does not tolerate first-boot initialization"
grep -Fq 'start_period: 240s' "${BUNDLE}/selfhost/docker-compose.yml" \
  || fail "bundled backend healthcheck does not tolerate the encrypted first-boot initialization window"
grep -Fq 'generate_series(0, 65535)' "${BUNDLE}/selfhost/db-init.sh" \
  || fail "bundled database initialization does not seed ID ranges in one transaction"
grep -Fq 'SELECT partition_index, 0, -9223372036854775808' "${BUNDLE}/selfhost/db-init.sh" \
  || fail "bundled database initialization does not preserve the Range initial cursor"
grep -Fq 'partial id_gen bootstrap' "${BUNDLE}/selfhost/db-init.sh" \
  || fail "bundled database initialization does not fail closed on a partial ID range set"
grep -Fq 'first_partition <> 0 OR last_partition <> 65535' "${BUNDLE}/selfhost/db-init.sh" \
  || fail "bundled database initialization does not reject a corrupt ID partition range"
# The shared runner imports the bundled package before tests can alter their search path.
SELFHOST_PYTHON_PACKAGE="${BUNDLE}/selfhost" run_selfhost_python_suite test_update test_release.ReleaseTests \
  test_upstream_runtime.UpstreamRuntimeTests.test_reset_release_refuses_all_in_place_handoffs_before_reading_old_state
grep -Fq '.chronicle-restore.lock' "${BUNDLE}/selfhost/rotate-secret.sh" \
  || fail "bundled secret rotation does not exclude an active restore"
grep -Fq "IF (SELECT key_name FROM pg_tde_key_info()) IS NULL THEN" \
  "${BUNDLE}/selfhost/init-tde.sh" \
  || fail "bundle would reset a rotated TDE principal key during db-init"

python3 - "$BUNDLE" "$SOURCE_REVISION" "$RELEASE_VERSION" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

bundle = Path(sys.argv[1])
manifest = json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8"))
assert manifest["schema_version"] == 1
assert manifest["release_version"] == sys.argv[3]
assert manifest["source_revision"] == sys.argv[2]
for relative, expected in manifest["files"].items():
    actual = hashlib.sha256((bundle / relative).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"checksum mismatch: {relative}")
PY

setup_password='turnkey-dashboard-password-123!'
# A non-public hostname must stop the wizard at the hostname question, not at `up`.
if write_selfhost_setup_answers "$setup_password" false false --public-host study.pilot.test |
    (cd "${BUNDLE}/selfhost" && ./chronicle setup) \
    >"${RUN_DIR}/turnkey-setup-badhost.log" 2>&1; then
  fail "setup accepted a non-public hostname"
fi
grep -Fq 'is not a public DNS name' "${RUN_DIR}/turnkey-setup-badhost.log" || fail "setup did not explain the refused hostname"
[[ ! -e "${BUNDLE}/selfhost/.env" ]] || fail "setup wrote .env for a refused hostname"
# The refusal leaves its own failed-setup receipt; the assertions below want the real one.
/bin/rm -rf -- "${BUNDLE}/selfhost/operator-receipts"
SELFHOST_SETUP_MONITORING=y write_selfhost_setup_answers "$setup_password" false false \
    --public-host turnkey.study-host.org \
    --backup-storage-encryption-waiver synthetic-bundle-test-fixture-no-study-data |
  (cd "${BUNDLE}/selfhost" && \
    CADDY_SETUP_HASH_IMAGE='caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d' \
    ./chronicle setup) >"${RUN_DIR}/turnkey-setup.log" 2>&1 \
  || { cat "${RUN_DIR}/turnkey-setup.log" >&2; fail "interactive turnkey setup failed"; }
! grep -Fq "$setup_password" "${RUN_DIR}/turnkey-setup.log" || fail "setup printed its dashboard password"
grep -Fq 'Next:  ./chronicle up' "${RUN_DIR}/turnkey-setup.log" || fail "setup did not give the guarded startup command"
setup_env_mode="$(stat -c '%a' "${BUNDLE}/selfhost/.env" 2>/dev/null || stat -f '%Lp' "${BUNDLE}/selfhost/.env")"
[[ "$setup_env_mode" == 600 ]] || fail "turnkey setup did not protect .env"
grep -Fq ':overlays/monitoring.yml' "${BUNDLE}/selfhost/.env" || fail "turnkey setup did not enable selected monitoring"
setup_receipt="$(find "${BUNDLE}/selfhost/operator-receipts/operations" -type f -name '*-setup-*.json' -print -quit)"
[[ -n "$setup_receipt" ]] || fail "turnkey setup did not write an operation receipt"
python3 - "$setup_receipt" <<'PY'
import json, sys
receipt = json.load(open(sys.argv[1], encoding="utf-8"))
assert receipt["operation"] == "setup"
assert receipt["outcome"] == "success"
assert receipt["failureCategory"] == "none"
assert set(receipt) == {"operation", "timestamp", "releaseVersion", "outcome", "failureCategory", "durationSeconds"}
assert isinstance(receipt["durationSeconds"], int) and receipt["durationSeconds"] >= 0
PY

(cd "${BUNDLE}/selfhost" && ./verify-config.sh >/dev/null) \
  || fail "standalone bundle config contract failed"
SELFHOST_MATRIX_ROOT="${BUNDLE}/selfhost" \
  SELFHOST_MATRIX_TEST_ROOT="${RUN_DIR}/bundle-matrix" \
  "${ROOT_DIR}/tests/security/selfhost-combination-matrix.sh" >/dev/null \
  || fail "standalone bundle supported-combination matrix failed"

/bin/cp "$ENV_EXAMPLE" "${BUNDLE}/selfhost/.env"
copied_env_mode="$(stat -c '%a' "${BUNDLE}/selfhost/.env" 2>/dev/null || stat -f '%Lp' "${BUNDLE}/selfhost/.env")"
[[ "$copied_env_mode" == 600 ]] || fail "cp .env.example .env did not retain private mode 0600"
# Backup retention has no default; setup records the operator's choice.
# perl -pi: BSD sed would take -E as the backup suffix and match nothing.
perl -pi -e 's/^(BACKUP_KEEP_DAYS|BACKUP_KEEP_WEEKS|BACKUP_KEEP_MONTHS|PRE_OP_BACKUP_KEEP_DAYS)=$/${1}=all/' \
  "${BUNDLE}/selfhost/.env"
# Setup also writes the internal core network's prefix; take the shipped first choice.
core_prefix="$(python3 "${BUNDLE}/selfhost/network-subnet.py" default-core)"
perl -pi -e "s/^CHRONICLE_CORE_PREFIX=\$/CHRONICLE_CORE_PREFIX=${core_prefix}/" "${BUNDLE}/selfhost/.env"
# Setup also records the operator UID/GID that owns the state directories.
printf 'CHRONICLE_HOST_UID=%s\nCHRONICLE_HOST_GID=%s\n' "$(id -u)" "$(id -g)" >>"${BUNDLE}/selfhost/.env"
(cd "${BUNDLE}/selfhost" && docker compose config --images >"${RUN_DIR}/compose-images.txt") \
  || fail "standalone bundle does not render with Docker Compose"
for expected_image in "$BACKEND_IMAGE" "$CADDY_IMAGE" "$BACKUP_IMAGE"; do
  grep -Fqx "$expected_image" "${RUN_DIR}/compose-images.txt" \
    || fail "rendered Compose omits release image: ${expected_image}"
done
if (cd "${BUNDLE}/selfhost" && docker compose config --format json | jq -e \
    'any(.services[]; has("build"))' >/dev/null); then
  fail "rendered release Compose contains a build definition"
fi

set +e
run_builder \
  --version "v${RELEASE_VERSION}" \
  --source-revision "$SOURCE_REVISION" \
  --source-date-epoch 1700000000 \
  --backend-image ghcr.io/example/chronicle-backend:latest \
  --frontend-image "$FRONTEND_IMAGE" \
  --caddy-image "$CADDY_IMAGE" \
  --backup-image "$BACKUP_IMAGE" \
  --grafana-image "$GRAFANA_IMAGE" \
  --postgres-image "$POSTGRES_IMAGE" \
  --fluentbit-image "$FLUENTBIT_IMAGE" \
  --output-dir "${RUN_DIR}/invalid" >"${RUN_DIR}/invalid.log" 2>&1
invalid_status=$?
set -e
[[ "$invalid_status" -ne 0 ]] || fail "builder accepted a mutable backend image"
grep -Fq 'must be an immutable name@sha256 reference' "${RUN_DIR}/invalid.log" \
  || fail "mutable-image rejection was not comprehensible"

set +e
run_builder \
  --version "v${RELEASE_VERSION}" \
  --source-revision "$SOURCE_REVISION" \
  --source-date-epoch 1700000000 \
  --backend-image "$MISLABELLED_IMAGE" \
  --frontend-image "$FRONTEND_IMAGE" \
  --caddy-image "$CADDY_IMAGE" \
  --backup-image "$BACKUP_IMAGE" \
  --grafana-image "$GRAFANA_IMAGE" \
  --postgres-image "$POSTGRES_IMAGE" \
  --fluentbit-image "$FLUENTBIT_IMAGE" \
  --output-dir "${RUN_DIR}/mislabelled" >"${RUN_DIR}/mislabelled.log" 2>&1
invalid_status=$?
set -e
[[ "$invalid_status" -ne 0 ]] || fail "builder accepted an image built from another source tree"
grep -Fq 'backend image was not built from the declared source inputs tree' "${RUN_DIR}/mislabelled.log" \
  || fail "source-tree provenance rejection was not comprehensible"

invalid_version_index=0
for invalid_version in v01.2.3 v1.2.3-01 v1.2.3-rc.; do
  invalid_version_index=$((invalid_version_index + 1))
  set +e
  run_builder \
    --version "$invalid_version" \
    --source-revision "$SOURCE_REVISION" \
    --source-date-epoch 1700000000 \
    --backend-image "$BACKEND_IMAGE" \
    --frontend-image "$FRONTEND_IMAGE" \
    --caddy-image "$CADDY_IMAGE" \
    --backup-image "$BACKUP_IMAGE" \
    --grafana-image "$GRAFANA_IMAGE" \
    --postgres-image "$POSTGRES_IMAGE" \
    --fluentbit-image "$FLUENTBIT_IMAGE" \
    --output-dir "${RUN_DIR}/invalid-version-${invalid_version_index}" \
    >"${RUN_DIR}/invalid-version-${invalid_version_index}.log" 2>&1
  invalid_status=$?
  set -e
  [[ "$invalid_status" -ne 0 ]] ||
    fail "builder accepted invalid semantic version: $invalid_version"
done

overflow_dir="${RUN_DIR}/invalid-source-date"
set +e
run_builder \
  --version "v${RELEASE_VERSION}" \
  --source-revision "$SOURCE_REVISION" \
  --source-date-epoch 4294967296 \
  --backend-image "$BACKEND_IMAGE" \
  --frontend-image "$FRONTEND_IMAGE" \
  --caddy-image "$CADDY_IMAGE" \
  --backup-image "$BACKUP_IMAGE" \
  --grafana-image "$GRAFANA_IMAGE" \
  --postgres-image "$POSTGRES_IMAGE" \
  --fluentbit-image "$FLUENTBIT_IMAGE" \
  --output-dir "$overflow_dir" >"${RUN_DIR}/invalid-source-date.log" 2>&1
invalid_status=$?
set -e
[[ "$invalid_status" -ne 0 ]] || fail "builder accepted a source date outside gzip's range"
grep -Fq 'must fit the gzip timestamp range' "${RUN_DIR}/invalid-source-date.log" \
  || fail "invalid source-date rejection was not comprehensible"
if [[ -d "$overflow_dir" ]] && find "$overflow_dir" -mindepth 1 -print -quit | grep . >/dev/null; then
  fail "builder published partial outputs after rejecting an invalid archive timestamp"
fi

echo "self-host release bundle test passed"
