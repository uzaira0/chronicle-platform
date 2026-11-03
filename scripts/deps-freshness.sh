#!/usr/bin/env bash
# Dependency freshness gate: every pin in toolchain-manifest.yaml (plus the JVM
# framework pins it documents) is compared with the latest upstream release.
#
# Exit 1 when a pin is a MAJOR version behind and not listed under
# `freshness.accepted_behind` in the manifest. Minor/patch drift is reported only.
# Also exit 1 when a direct chronicle-web dependency's newest registry release is older than
# `freshness.web_max_release_age_days` and not listed, with a reason and an expiry, under
# `freshness.web_stale_accepted` (scripts/web_dependency_age.py).
# Read-only; needs curl, jq, yq, gh (for GitHub release lookups).
#
#   scripts/deps-freshness.sh            # table + gate
#   scripts/deps-freshness.sh --json     # machine output
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 "$ROOT_DIR/scripts/check-dependency-overrides.py" >&2 || exit $?
MANIFEST="$ROOT_DIR/toolchain-manifest.yaml"
JSON=0; [[ "${1:-}" == "--json" ]] && JSON=1
for c in curl jq yq gh; do command -v "$c" >/dev/null 2>&1 || { echo "[fail] missing $c" >&2; exit 127; }; done

pin() { yq -r ".$1 // \"\"" "$MANIFEST"; }
gh_latest() { # repo [tag-regex-to-keep]
  local v
  v="$(gh api "repos/$1/releases/latest" --jq .tag_name 2>/dev/null)"
  if [[ -z "$v" ]]; then
    v="$(gh api "repos/$1/tags?per_page=60" --jq '[.[].name | select(test("'"${2:-^v?[0-9]+\\.[0-9]+(\\.[0-9]+)?$}"'"))] | .[0]' 2>/dev/null)"
  fi
  printf '%s' "$v"
}
hub_latest() { # repo tag-regex [name-filter]
  curl -fsS --max-time 20 "https://hub.docker.com/v2/repositories/$1/tags?page_size=100&name=${3:-}" 2>/dev/null \
    | jq -r --arg re "$2" '[.results[].name | select(test($re))] | sort_by(split("[.-]"; "") | map(tonumber? // 0)) | last // ""'
}
hub_latest_major() { # repo tag-regex-after-major pinned-tag: the next major's newest tag if one exists, else the pinned major's
  local repo="$1" tail="$2" major v m
  major="$(cut -d. -f1 <<<"$3")"
  for m in $((major + 1)) "$major"; do
    v="$(hub_latest "$repo" "^$m$tail" "$m.")"
    [[ -n "$v" ]] && { printf '%s' "$v"; return; }
  done
}
maven_latest() { # metadata-url
  curl -fsS --max-time 20 "$1" 2>/dev/null | grep -oE '<version>[0-9]+\.[0-9]+\.[0-9]+</version>' | sed 's/<[^>]*>//g' | sort -V | tail -1
}
num() { grep -oE '[0-9]+(\.[0-9]+)*' <<<"$1" | head -1; }
major() { cut -d. -f1 <<<"$(num "$1")"; }
minor() { cut -d. -f2 <<<"$(num "$1").0"; }

declare -a ROWS
FAIL=0
accepted="$(yq -r '.freshness.accepted_behind // [] | .[]' "$MANIFEST" 2>/dev/null | tr '\n' ' ')"

row() { # name pinned latest
  local name="$1" pinned="$2" latest="$3" status="ok" note=""
  if [[ -z "$latest" || "$latest" == null ]]; then status="unknown"; note="lookup failed"; FAIL=1
  elif printf '%s\n' "${latest#v}" "${pinned#v}" | sort -V -C; then status="current"
  elif [[ "$(major "$pinned")" -lt "$(major "$latest")" ]]; then
    if [[ " $accepted " == *" $name "* ]]; then status="major-behind (accepted)"; else status="MAJOR-BEHIND"; FAIL=1; fi
  elif [[ "$(minor "$pinned")" -lt "$(minor "$latest")" ]]; then status="minor-behind"
  else status="patch-behind"; fi
  ROWS+=("$name|$pinned|$latest|$status|$note")
}

# --- manifest pins -----------------------------------------------------------
row jdk            "$(pin jdk.build_runtime)"       "$(gh api repos/adoptium/temurin25-binaries/releases/latest --jq .tag_name 2>/dev/null | grep -oE '[0-9]+' | head -1)"
row gradle         "$(pin gradle.wrapper)"          "$(gh_latest gradle/gradle)"
row gradle-android "$(pin gradle.android_wrapper)"  "$(gh_latest gradle/gradle)"
row kotlin         "$(pin kotlin)"                  "$(gh_latest JetBrains/kotlin)"
row bun            "$(pin bun)"                     "$(gh_latest oven-sh/bun)"
row python         "$(pin python)"                  "$(gh api 'repos/python/cpython/tags?per_page=40' --jq '[.[].name | select(test("^v3\\.[0-9]+\\.[0-9]+$"))] | .[0]' 2>/dev/null)"
row flyway         "$(pin flyway.version)"          "$(gh_latest flyway/flyway)"
pg="$(pin postgres.image)";            row postgres-percona   "${pg##*:}"                "$(hub_latest_major percona/percona-distribution-postgresql '\.[0-9]+\.[0-9]+-[0-9]+$' "${pg##*:}")"
kpg="$(pin keycloak_postgres.image)";  row postgres-keycloak  "${kpg##*:}"              "$(hub_latest_major library/postgres '\.[0-9]+-alpine$' "${kpg##*:}")"
img() { local v; v="$(pin "selfhost_images.$1")"; v="${v%%@*}"; printf '%s' "${v##*:}"; }
row grafana          "$(img grafana)"          "$(gh_latest grafana/grafana)"
row victoria-metrics "$(img victoria_metrics)" "$(gh_latest VictoriaMetrics/VictoriaMetrics)"
row victoria-logs    "$(img victoria_logs)"    "$(gh api 'repos/VictoriaMetrics/VictoriaLogs/releases/latest' --jq .tag_name 2>/dev/null)"
row fluent-bit       "$(img fluent_bit)"       "$(gh_latest fluent/fluent-bit)"
row cadvisor         "$(img cadvisor)"         "$(gh_latest google/cadvisor)"
row keycloak         "$(img keycloak)"         "$(gh_latest keycloak/keycloak)"

# --- JVM framework pins documented in the manifest ---------------------------
gv() { grep -oE "^ext\.$1_version='[^']+'" "$ROOT_DIR/gradles/chronicle.gradle" | head -1 | sed "s/.*='//; s/'//"; }
row spring-framework "$(gv spring_framework)"  "$(maven_latest https://repo1.maven.org/maven2/org/springframework/spring-core/maven-metadata.xml)"
row hazelcast        "$(gv hazelcast)"         "$(maven_latest https://repo1.maven.org/maven2/com/hazelcast/hazelcast/maven-metadata.xml)"
row android-agp      "$(grep -oE 'com.android.tools.build:gradle:[0-9.]+' "$ROOT_DIR/chronicle/build.gradle" | head -1 | sed 's/.*://')" "$(maven_latest https://dl.google.com/dl/android/maven2/com/android/tools/build/gradle/maven-metadata.xml)"

# --- direct chronicle-web dependencies: unmaintained packages ---------------------
# Its table and findings go to stderr, so --json output stays machine-readable.
web_policy="$(yq -o=json '.freshness' "$MANIFEST")"
python3 "$ROOT_DIR/scripts/web_dependency_age.py" "$ROOT_DIR/chronicle-web/package.json" /dev/stdin <<<"$web_policy" >&2 \
  || { FAIL=1; echo "[fail] an unmaintained direct chronicle-web dependency (see above)" >&2; }

# --- output ------------------------------------------------------------------
if [[ $JSON -eq 1 ]]; then
  printf '%s\n' "${ROWS[@]}" | jq -R -s 'split("\n") | map(select(length>0) | split("|") | {name:.[0],pinned:.[1],latest:.[2],status:.[3],note:.[4]})'
else
  printf '%-18s %-14s %-14s %s\n' COMPONENT PINNED LATEST STATUS
  for r in "${ROWS[@]}"; do IFS='|' read -r n p l s x <<<"$r"; printf '%-18s %-14s %-14s %s %s\n' "$n" "$p" "$l" "$s" "$x"; done
fi
if [[ $FAIL -eq 1 ]]; then
  echo "[fail] a lookup failed or a pin is a major version behind and not listed under freshness.accepted_behind in toolchain-manifest.yaml" >&2
  exit 1
fi
echo "[ok] dependency freshness: no unaccepted major drift" >&2
