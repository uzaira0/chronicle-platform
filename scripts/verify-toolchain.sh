#!/usr/bin/env bash
# Toolchain drift checker — enforces toolchain-manifest.yaml against the repo.
#
# Covers root AND submodules: gradle wrappers, workflow JDK pins, Bun pins,
# Kotlin/Mockito/Flyway version sync, and the single Postgres test/prod image
# constant. Run standalone, from scripts/local-ci.sh, or from ci.yml. Exits
# non-zero on any drift; every check names the file and the expected pin.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT_DIR/toolchain-manifest.yaml"
FAILURES=0

fail() { printf '[fail] %s\n' "$*" >&2; FAILURES=$((FAILURES + 1)); }
ok()   { printf '[ok] %s\n' "$*"; }

manifest_value() { # dotted.path
  yq -r ".$1" "$MANIFEST"
}

JDK="$(manifest_value jdk.build_runtime)"
ANDROID_JDK="$(manifest_value jdk.android_launcher)"
GRADLE="$(manifest_value gradle.wrapper)"
ANDROID_GRADLE="$(manifest_value gradle.android_wrapper)"
KOTLIN="$(manifest_value kotlin)"
BUN="$(manifest_value bun)"
PG_IMAGE="$(manifest_value postgres.image)"
PG_DIGEST="$(manifest_value postgres.index_digest)"
KC_PG_IMAGE="$(manifest_value keycloak_postgres.image)"
KC_PG_DIGEST="$(manifest_value keycloak_postgres.index_digest)"
FLYWAY="$(manifest_value flyway.version)"
PYTHON_MIN="$(manifest_value python)"
SEMGREP="$(manifest_value semgrep)"
SELFHOST_BACKUP_IMAGE="$(manifest_value selfhost_images.backup)"
SELFHOST_CADVISOR_IMAGE="$(manifest_value selfhost_images.cadvisor)"
SELFHOST_SOCKET_PROXY_IMAGE="$(manifest_value selfhost_images.docker_socket_proxy)"
SELFHOST_VM_IMAGE="$(manifest_value selfhost_images.victoria_metrics)"
SELFHOST_VL_IMAGE="$(manifest_value selfhost_images.victoria_logs)"
SELFHOST_FLUENT_BIT_IMAGE="$(manifest_value selfhost_images.fluent_bit)"
SELFHOST_GRAFANA_IMAGE="$(manifest_value selfhost_images.grafana)"
SELFHOST_KEYCLOAK_IMAGE="$(manifest_value selfhost_images.keycloak)"

# ── 1. Gradle wrappers ────────────────────────────────────────────────────────
for m in . chronicle-server chronicle-api rhizome rhizome-client; do
  f="$ROOT_DIR/$m/gradle/wrapper/gradle-wrapper.properties"
  if grep -q "gradle-${GRADLE}-bin.zip" "$f" 2>/dev/null; then
    ok "wrapper $m -> $GRADLE"
  else
    fail "wrapper $m is not Gradle $GRADLE ($f)"
  fi
done
f="$ROOT_DIR/chronicle/gradle/wrapper/gradle-wrapper.properties"
if grep -q "gradle-${ANDROID_GRADLE}-bin.zip" "$f" 2>/dev/null; then
  ok "wrapper chronicle (Android) -> $ANDROID_GRADLE"
else
  fail "Android wrapper is not Gradle $ANDROID_GRADLE ($f)"
fi

# ── 1b. Python floor (python3 on PATH runs scripts/, tests/, selfhost/ helpers) ──
if command -v python3 >/dev/null 2>&1; then
  PY_VER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
  if [[ "$(printf '%s\n%s\n' "$PYTHON_MIN" "$PY_VER" | sort -V | head -1)" == "$PYTHON_MIN" ]]; then
    ok "python3 -> $PY_VER (floor $PYTHON_MIN)"
    # PyYAML and openpyxl are pinned with hashes in requirements-dev.txt; a missing or different
    # installed version fails here instead of silently changing generated contracts and gate results.
    python3 -I "$ROOT_DIR/tests/quality/test_check_python_dev_pins.py" >/dev/null 2>&1 \
      || fail "tests/quality/test_check_python_dev_pins.py fails: run it for details"
    if PIN_REPORT="$(python3 -I "$ROOT_DIR/scripts/check-python-dev-pins.py" 2>&1)"; then
      ok "${PIN_REPORT#\[ok\] }"
    else
      fail "python tooling pins: ${PIN_REPORT//$'\n'/; }"
    fi
  else
    fail "python3 is $PY_VER, floor is $PYTHON_MIN ($(command -v python3)); uv python install $PYTHON_MIN --default"
  fi
else
  fail "python3 not on PATH (floor $PYTHON_MIN)"
fi

# ── 1b2. Semgrep (the engineering job's repo rules) ─────────────────────────────
# Semgrep versions differ in what the repo rules match (1.155.0 missed a raw SQLException rethrow
# that 1.182.0 reports), so an unpinned scanner made the engineering gate host-dependent.
if command -v semgrep >/dev/null 2>&1; then
  SEMGREP_ACTIVE="$(semgrep --version 2>/dev/null | head -1)"
  if [[ "$SEMGREP_ACTIVE" == "$SEMGREP" ]]; then
    ok "semgrep -> $SEMGREP"
  else
    fail "semgrep is ${SEMGREP_ACTIVE:-unknown} ($(command -v semgrep)), manifest semgrep is $SEMGREP; uv tool install semgrep==$SEMGREP"
  fi
else
  fail "semgrep not on PATH (manifest semgrep is $SEMGREP); uv tool install semgrep==$SEMGREP"
fi

# ── 1c. Active JDK major ─────────────────────────────────────────────────────
# The manifest declared jdk.build_runtime and nothing compared it to the JDK that actually
# runs the build, so a JDK 21 shell passed every check while the manifest said 25.
# Resolution mirrors scripts/local-ci.sh require_jdk21: JAVA_HOME wins, then the usual
# local install dirs for the manifest major, then whatever `java` is on PATH.
JAVA_BIN=""
if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]]; then
  JAVA_BIN="$JAVA_HOME/bin/java"
else
  for cand in "$HOME/.local/jdks/temurin-$JDK" "$HOME/.sdkman/candidates/java/current" \
              "/usr/lib/jvm/temurin-$JDK-jdk" "/usr/lib/jvm/java-$JDK-openjdk" \
              "${HOMEBREW_PREFIX:-/opt/homebrew}/opt/openjdk@$JDK/libexec/openjdk.jdk/Contents/Home" \
              "/usr/local/opt/openjdk@$JDK/libexec/openjdk.jdk/Contents/Home"; do
    if [[ -x "$cand/bin/java" ]]; then JAVA_BIN="$cand/bin/java"; break; fi
  done
  [[ -n "$JAVA_BIN" ]] || JAVA_BIN="$(command -v java || true)"
fi
if [[ -z "$JAVA_BIN" ]]; then
  fail "no java found (manifest jdk.build_runtime is $JDK): install it or set JAVA_HOME"
else
  JAVA_VERSION="$("$JAVA_BIN" -version 2>&1 | awk -F '"' '/version/ { print $2; exit }')"
  JAVA_MAJOR="${JAVA_VERSION%%.*}"
  [[ "$JAVA_MAJOR" == "1" ]] && JAVA_MAJOR="$(cut -d. -f2 <<<"$JAVA_VERSION")"
  if [[ "$JAVA_MAJOR" == "$JDK" ]]; then
    ok "active JDK -> $JAVA_MAJOR ($JAVA_BIN)"
  else
    fail "active JDK is $JAVA_MAJOR (${JAVA_VERSION:-unknown}) at $JAVA_BIN, manifest jdk.build_runtime is $JDK; export JAVA_HOME=\$HOME/.local/jdks/temurin-$JDK"
  fi
fi

# The Android dials are separate (AGP certification boundary) and the launcher JDK is an
# operator choice, but android_bytecode IS declared in the build and was never checked.
ANDROID_BYTECODE="$(manifest_value jdk.android_bytecode)"
ANDROID_BUILD="$ROOT_DIR/chronicle/app/build.gradle"
ANDROID_JVM_STALE="$(grep -Ehn '^[[:space:]]*(source|target)Compatibility[[:space:]]|jvmTarget[[:space:]]*=' \
  "$ANDROID_BUILD" 2>/dev/null | grep -Ev "(Compatibility ${ANDROID_BYTECODE}\$|JVM_${ANDROID_BYTECODE}\$)" || true)"
if [[ ! -f "$ANDROID_BUILD" ]]; then
  ok "chronicle/ submodule not checked out — skipping Android bytecode check"
elif [[ -z "$ANDROID_JVM_STALE" ]]; then
  ok "chronicle/app/build.gradle bytecode -> $ANDROID_BYTECODE (launcher JDK $ANDROID_JDK)"
else
  fail "Android bytecode drift in chronicle/app/build.gradle (expected $ANDROID_BYTECODE): $(head -1 <<<"$ANDROID_JVM_STALE")"
fi

# ── 2. Workflow JDK pins (root + submodules) ─────────────────────────────────
# JDK pins live in the Gradle builds and docker images checked below; there are no hosted workflows.

# ── 3. Bun pins (root + web submodule; Node must not reappear) ───────────────
# Remember the failure count so the closing summary is only printed when this section
# actually passed -- otherwise a drift prints "[fail] ..." immediately followed by
# "[ok] bun pins checked", and anyone scanning for [ok] reads the green line.
BUN_FAILURES_BEFORE=$FAILURES
# Node is not a dependency: bun runs every script and substitutes itself for
# `#!/usr/bin/env node` bins when node is absent (verified: playwright/biome/eslint
# run with no node on PATH). Keep it from creeping back in as a declared engine.
grep -q '"node":' "$ROOT_DIR/chronicle-web/package.json" \
  && fail "chronicle-web/package.json declares engines.node; Node is not a dependency (bun only)"
grep -Eq 'have_cmd node|command -v node' "$ROOT_DIR/scripts/chronicle-web-bun-smoke.sh" \
  && fail "chronicle-web-bun-smoke.sh requires node; bun only"
# The guard script hardcodes its own Bun literal (they cannot depend on yq);
# cross-check them against the manifest so the gates cannot contradict each other.
grep -Eq "^[[:space:]]*BUN_VERSION=[\"']?${BUN}" "$ROOT_DIR/tests/security/supply-chain-guardrails.sh" \
  || fail "supply-chain-guardrails.sh BUN_VERSION != $BUN"

# Gate commands use the installed runtime; package scripts and types must match it.
if command -v bun >/dev/null 2>&1; then
  BUN_ACTIVE="$(bun --version 2>/dev/null)"
  if [[ "$BUN_ACTIVE" == "$BUN" ]]; then
    ok "active Bun -> $BUN"
  else
    fail "active Bun is ${BUN_ACTIVE:-unknown} ($(command -v bun)), manifest bun is $BUN"
  fi
else
  fail "bun not on PATH (manifest bun is $BUN)"
fi

PKG="$ROOT_DIR/chronicle-web/package.json"
if [[ -f "$PKG" ]]; then
  ENGINE_BUN="$(jq -r '.engines.bun // ""' "$PKG")"
  [[ "$ENGINE_BUN" == "$BUN" ]] \
    || fail "chronicle-web/package.json engines.bun must be exactly $BUN (found $ENGINE_BUN)"
  for dep in bun bun-types; do
    ver="$(jq -r --arg d "$dep" '(.dependencies[$d] // .devDependencies[$d]) // ""' "$PKG")"
    [[ "$ver" == "$BUN" ]] \
      || fail "chronicle-web/package.json must pin $dep to $BUN (found ${ver:-none})"
  done
  # The lockfile is what `--frozen-lockfile` actually enforces, so a package.json that
  # matches the manifest while bun.lock does not still fails every install and CI job.
  LOCK="$ROOT_DIR/chronicle-web/bun.lock"
  if [[ -f "$LOCK" ]]; then
    grep -q "\"bun-types@${BUN}\"" "$LOCK" \
      || fail "chronicle-web/bun.lock does not resolve bun-types to $BUN — regenerate the web lockfile with the pinned Bun runtime"
  fi
fi
[[ "$FAILURES" -eq "$BUN_FAILURES_BEFORE" ]] \
  && ok "bun pins checked (expected $BUN, incl. chronicle-web package.json + bun.lock)"

# ── 4. Version sync: Kotlin, Flyway, Mockito floor ───────────────────────────
# Anchored to line starts so a commented-out old pin cannot satisfy the check.
grep -Eq "^[[:space:]]*ext\.kotlin_version='${KOTLIN}'" "$ROOT_DIR/gradles/chronicle.gradle" \
  && ok "kotlin $KOTLIN in gradles/chronicle.gradle" \
  || fail "gradles/chronicle.gradle kotlin_version != $KOTLIN"

# Kotlin pins are necessarily duplicated in every pluginManagement block (settings
# files cannot read external config) and in the root stdlib forces — sweep them all.
for f in settings.gradle.kts build.gradle.kts \
  chronicle-server/settings.gradle chronicle-api/settings.gradle \
  chronicle-models/settings.gradle rhizome/settings.gradle rhizome-client/settings.gradle; do
  STALE="$(grep -En "^[^/]*(kotlin[^:]*version|kotlin-stdlib-jdk[78]:)" "$ROOT_DIR/$f" 2>/dev/null | grep -v "${KOTLIN}" || true)"
  if [[ -n "$STALE" ]]; then
    fail "kotlin pin drift in $f (expected $KOTLIN): $(head -1 <<<"$STALE")"
  else
    ok "kotlin pins in $f -> $KOTLIN"
  fi
done

grep -q "ext.flyway_version='${FLYWAY}'" "$ROOT_DIR/gradles/chronicle.gradle" \
  && ok "flyway $FLYWAY in gradles/chronicle.gradle" \
  || fail "gradles/chronicle.gradle flyway_version != $FLYWAY"

grep -q "flyway/flyway:${FLYWAY}" "$ROOT_DIR/scripts/flyway-migrate.sh" \
  && ok "flyway $FLYWAY in scripts/flyway-migrate.sh" \
  || fail "scripts/flyway-migrate.sh image != flyway/flyway:$FLYWAY"

# ── 5. Postgres image constant ────────────────────────────────────────────────
grep -Fq "PROD_POSTGRES_IMAGE = \"${PG_IMAGE%%:*}@${PG_DIGEST}\"" \
  "$ROOT_DIR/chronicle-server/src/test/kotlin/com/openlattice/chronicle/contract/ChronicleContractTestSchema.kt" \
  && ok "testcontainer image constant -> ${PG_IMAGE%%:*}@$PG_DIGEST" \
  || fail "ChronicleContractTestSchema.PROD_POSTGRES_IMAGE != ${PG_IMAGE%%:*}@$PG_DIGEST"
grep -Fq "ARG PROD_POSTGRES_IMAGE=${PG_IMAGE}@${PG_DIGEST}" "$ROOT_DIR/chronicle-server/src/test/docker/pgtap/Dockerfile" \
  && ok "pgTAP image default -> ${PG_IMAGE}@$PG_DIGEST" \
  || fail "chronicle-server/src/test/docker/pgtap/Dockerfile default != ${PG_IMAGE}@$PG_DIGEST"

# No test source may hard-code its own copy of the image string (they must reference
# the constant): a duplicate literal is invisible to a manifest bump.
DUP_PINS="$(grep -rEn '= *"percona/percona-distribution-postgresql' "$ROOT_DIR/chronicle-server/src" \
  | grep -v 'ChronicleContractTestSchema.kt' || true)"
[[ -z "$DUP_PINS" ]] \
  && ok "no duplicate image literals in chronicle-server test sources" \
  || fail "duplicate postgres image literal outside ChronicleContractTestSchema: $(head -1 <<<"$DUP_PINS")"

# The digest the manifest records must be the one every digest-pinned artifact uses.
# Without this, a bump could move the tag and leave the old digest in place — which pins
# the OLD image, silently, because a digest always wins over a tag. docker/ and k8s/ are
# frozen until they are ported as selfhost overlays, so only the
# shipped selfhost tree is held to the manifest in this script.
DIGEST_STALE="$(grep -rEn 'percona/percona-distribution-postgresql:[^@[:space:]]+@sha256:[0-9a-f]+' \
  "$ROOT_DIR/selfhost" 2>/dev/null | grep -v "@${PG_DIGEST}" || true)"
[[ -z "$DIGEST_STALE" ]] \
  && ok "every digest-pinned percona reference -> $PG_DIGEST" \
  || fail "postgres digest drift: $(head -1 <<<"$DIGEST_STALE")"

# ── 6. Self-host bundle ───────────────────────────────────────────────────────
# selfhost/ ships separately and was invisible to this checker, so a manifest bump used
# to leave it on the old major. The release Postgres image is built FROM the pinned parent.
SELFHOST_STALE="$(grep -rn 'percona/percona-distribution-postgresql' \
  "$ROOT_DIR/selfhost/docker-compose.yml" "$ROOT_DIR/selfhost/.env.example" "$ROOT_DIR/selfhost/Dockerfile.postgres" 2>/dev/null \
  | grep -v "$PG_IMAGE" || true)"
[[ -z "$SELFHOST_STALE" ]] \
  && ok "selfhost bundle -> $PG_IMAGE" \
  || fail "selfhost postgres image drift: $(head -1 <<<"$SELFHOST_STALE")"
grep -Fxq "FROM ${PG_IMAGE}@${PG_DIGEST}" "$ROOT_DIR/selfhost/Dockerfile.postgres" \
  && ok "selfhost release Postgres parent -> $PG_DIGEST" \
  || fail "selfhost/Dockerfile.postgres must build FROM ${PG_IMAGE}@${PG_DIGEST}"

# Backup is now built from the pinned Percona parent, not the published backup
# fixture image. Grafana's pinned parent lives in its source-build Dockerfile.
for image_contract in \
  "overlays/monitoring.yml|$SELFHOST_CADVISOR_IMAGE" \
  "overlays/monitoring.yml|$SELFHOST_SOCKET_PROXY_IMAGE" \
  "overlays/monitoring.yml|$SELFHOST_VM_IMAGE" \
  "overlays/monitoring.yml|$SELFHOST_VL_IMAGE" \
  "overlays/monitoring.yml|$SELFHOST_FLUENT_BIT_IMAGE" \
  "Dockerfile.grafana|$SELFHOST_GRAFANA_IMAGE"; do
  selfhost_file="${image_contract%%|*}"
  selfhost_image="${image_contract#*|}"
  awk -v image="$selfhost_image" '($1 == "image:" || $1 == "FROM") && $2 == image { found=1 } END { exit !found }' "$ROOT_DIR/selfhost/$selfhost_file" \
    && ok "selfhost/$selfhost_file -> $selfhost_image" \
    || fail "selfhost/$selfhost_file does not use manifest image $selfhost_image"
done

# ── 7. Preloaded libraries ────────────────────────────────────────────────────
# The image ships no percona_pg_telemetry, so naming it in shared_preload_libraries makes
# the server exit with FATAL: could not access file "percona_pg_telemetry".
PRELOAD_TELEMETRY="$(grep -rn 'shared_preload_libraries=[^[:space:]]*percona_pg_telemetry' \
  "$ROOT_DIR/selfhost" 2>/dev/null || true)"
[[ -z "$PRELOAD_TELEMETRY" ]] \
  && ok "no shared_preload_libraries names percona_pg_telemetry" \
  || fail "percona_pg_telemetry preloaded but absent from the image — postgres will not start: $(head -1 <<<"$PRELOAD_TELEMETRY")"

# ── 8. Keycloak's Postgres (SSO tier, stock image, no pg_tde) ─────────────────
# Anchored to a real image reference (an `image:` key, a Dockerfile FROM, or a quoted
# literal in a guardrail test) so that prose ABOUT the pin does not read as drift.
KC_STALE="$(grep -rEn '(^[[:space:]]*(-[[:space:]]*)?image:[[:space:]]*|^FROM[[:space:]]+|")postgres:[0-9]+[^[:space:]"]*-alpine' \
  "$ROOT_DIR/selfhost" "$ROOT_DIR/tests" 2>/dev/null \
  | grep -v "$KC_PG_IMAGE" || true)"
[[ -z "$KC_STALE" ]] \
  && ok "keycloak postgres -> $KC_PG_IMAGE" \
  || fail "keycloak postgres drift: $(head -1 <<<"$KC_STALE")"

KC_DIGEST_STALE="$(grep -rEn 'postgres:[0-9]+[^[:space:]"]*-alpine@sha256:[0-9a-f]+' \
  "$ROOT_DIR/selfhost/experimental" 2>/dev/null | grep -v "@${KC_PG_DIGEST}" || true)"
[[ -z "$KC_DIGEST_STALE" ]] \
  && ok "keycloak postgres digest -> $KC_PG_DIGEST" \
  || fail "keycloak postgres digest drift: $(head -1 <<<"$KC_DIGEST_STALE")"

# ── 9. Every manifest-pinned image in the shipped tree ────────────────────────
# Require the exact pin INCLUDING the digest on every `image:` key under selfhost/ for the
# repositories the manifest pins — a tag-only reference is not pinned.
for pinned in "$SELFHOST_BACKUP_IMAGE" "$SELFHOST_CADVISOR_IMAGE" "$SELFHOST_VM_IMAGE" \
              "$SELFHOST_VL_IMAGE" "$SELFHOST_FLUENT_BIT_IMAGE" "$SELFHOST_GRAFANA_IMAGE" \
              "$SELFHOST_KEYCLOAK_IMAGE"; do
  repo="${pinned%%:*}"
  IMAGE_STALE="$(grep -rEn "^[[:space:]]*(-[[:space:]]*)?image:[[:space:]]*\"?${repo}[:@]" \
    "$ROOT_DIR/selfhost" 2>/dev/null \
    | grep -Fv "$pinned" || true)"
  [[ -z "$IMAGE_STALE" ]] \
    && ok "$repo -> $pinned (all selfhost references)" \
    || fail "image pin drift for $repo (expected $pinned): $(head -1 <<<"$IMAGE_STALE")"
done


# ── 10. Downloaded gate tools and release-script imports ──────────────────────
# Every tool scripts/local-ci.sh downloads must verify against the sha256 committed in this
# manifest's gate_tools (a release's own checksums file can be replaced along with its asset),
# and every third-party import of a release script must be hash-locked beside it.
if python3 "$ROOT_DIR/tests/quality/test_gate_tool_digests.py" >/dev/null 2>&1; then
  ok "gate tool downloads and release-script imports are digest-pinned"
else
  fail "a downloaded gate tool or a release-script import has no committed digest: python3 tests/quality/test_gate_tool_digests.py"
fi

echo
if [[ "$FAILURES" -gt 0 ]]; then
  printf 'TOOLCHAIN DRIFT: %d failure(s) — fix the pins or update toolchain-manifest.yaml deliberately\n' "$FAILURES" >&2
  exit 1
fi
printf 'Toolchain manifest verified: no drift\n'
