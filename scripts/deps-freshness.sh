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
#   scripts/deps-freshness.sh                       # table + gate
#   scripts/deps-freshness.sh --json                # machine output
#   scripts/deps-freshness.sh --fetch-github DIR    # only the GitHub lookups, saved to DIR
#
# The dependency gate runner's sandbox has no gh login: the runner saves the GitHub lookups with
# --fetch-github (the repositories are named below, nothing is read from the checkout) and the
# sandboxed report reads them from CHRONICLE_GITHUB_API_CACHE instead of calling gh. A lookup missing
# from that directory is a failed lookup.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# GitHub repositories whose newest release (or, with none, newest version tag) is compared below,
# and the other GitHub API paths the report reads.
GH_LATEST_REPOS=(gradle/gradle JetBrains/kotlin oven-sh/bun flyway/flyway grafana/grafana
                 VictoriaMetrics/VictoriaMetrics fluent/fluent-bit google/cadvisor keycloak/keycloak)
GH_PATHS=(repos/adoptium/temurin25-binaries/releases/latest 'repos/python/cpython/tags?per_page=40'
          repos/VictoriaMetrics/VictoriaLogs/releases/latest)
for repo in "${GH_LATEST_REPOS[@]}"; do GH_PATHS+=("repos/$repo/releases/latest" "repos/$repo/tags?per_page=60"); done
cache_file() { printf '%s/%s.json' "$1" "$(tr -c 'A-Za-z0-9._-' '_' <<<"$2")"; }

if [[ "${1:-}" == "--fetch-github" ]]; then
  dir="${2:?--fetch-github takes a directory}"
  [[ -d "$dir" ]] || { echo "[fail] $dir is not a directory" >&2; exit 2; }
  command -v gh >/dev/null 2>&1 || { echo "[fail] missing gh" >&2; exit 127; }
  saved=0
  for path in "${GH_PATHS[@]}"; do
    file="$(cache_file "$dir" "$path")"
    # A repository without releases answers 404 for releases/latest: no file, the report reads its tags.
    if gh api "$path" > "$file.part" 2>/dev/null && jq -e . "$file.part" >/dev/null 2>&1; then
      mv "$file.part" "$file"; saved=$((saved + 1))
    else
      rm -f "$file.part"
    fi
  done
  echo "[ok] saved $saved of ${#GH_PATHS[@]} GitHub lookups to $dir" >&2
  exit 0
fi

python3 "$ROOT_DIR/scripts/check-dependency-overrides.py" >&2 || exit $?
MANIFEST="$ROOT_DIR/toolchain-manifest.yaml"
JSON=0; [[ "${1:-}" == "--json" ]] && JSON=1
needed=(curl jq yq); [[ -n "${CHRONICLE_GITHUB_API_CACHE:-}" ]] || needed+=(gh)
for c in "${needed[@]}"; do command -v "$c" >/dev/null 2>&1 || { echo "[fail] missing $c" >&2; exit 127; }; done

github_api() { # path: the API response, from CHRONICLE_GITHUB_API_CACHE when set, else from gh
  if [[ -n "${CHRONICLE_GITHUB_API_CACHE:-}" ]]; then
    cat "$(cache_file "$CHRONICLE_GITHUB_API_CACHE" "$1")" 2>/dev/null
  else
    gh api "$1" 2>/dev/null
  fi
}
pin() { yq -r ".$1 // \"\"" "$MANIFEST"; }
gh_latest() { # repo [tag-regex-to-keep]
  local v
  v="$(github_api "repos/$1/releases/latest" | jq -r '.tag_name // empty' 2>/dev/null)"
  if [[ -z "$v" ]]; then
    # The pattern goes in with --arg: spliced into the filter text, its \. was an invalid jq string escape.
    v="$(github_api "repos/$1/tags?per_page=60" \
      | jq -r --arg re "${2:-^v?[0-9]+\.[0-9]+(\.[0-9]+)?$}" '[.[].name | select(test($re))] | .[0] // empty' 2>/dev/null)"
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
num() { grep -oE '[0-9]+(\.[0-9]+)*' <<<"$1" | sed -n 1p; }
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
row jdk            "$(pin jdk.build_runtime)"       "$(github_api repos/adoptium/temurin25-binaries/releases/latest | jq -r '.tag_name // empty' 2>/dev/null | grep -oE '[0-9]+' | sed -n 1p)"
row gradle         "$(pin gradle.wrapper)"          "$(gh_latest gradle/gradle)"
row gradle-android "$(pin gradle.android_wrapper)"  "$(gh_latest gradle/gradle)"
row kotlin         "$(pin kotlin)"                  "$(gh_latest JetBrains/kotlin)"
row bun            "$(pin bun)"                     "$(gh_latest oven-sh/bun)"
row python         "$(pin python)"                  "$(github_api 'repos/python/cpython/tags?per_page=40' | jq -r '[.[].name | select(test("^v3\\.[0-9]+\\.[0-9]+$"))] | .[0] // empty' 2>/dev/null)"
row flyway         "$(pin flyway.version)"          "$(gh_latest flyway/flyway)"
pg="$(pin postgres.image)";            row postgres-percona   "${pg##*:}"                "$(hub_latest_major percona/percona-distribution-postgresql '\.[0-9]+\.[0-9]+-[0-9]+$' "${pg##*:}")"
kpg="$(pin keycloak_postgres.image)";  row postgres-keycloak  "${kpg##*:}"              "$(hub_latest_major library/postgres '\.[0-9]+-alpine$' "${kpg##*:}")"
img() { local v; v="$(pin "selfhost_images.$1")"; v="${v%%@*}"; printf '%s' "${v##*:}"; }
row grafana          "$(img grafana)"          "$(gh_latest grafana/grafana)"
row victoria-metrics "$(img victoria_metrics)" "$(gh_latest VictoriaMetrics/VictoriaMetrics)"
row victoria-logs    "$(img victoria_logs)"    "$(github_api 'repos/VictoriaMetrics/VictoriaLogs/releases/latest' | jq -r '.tag_name // empty' 2>/dev/null)"
row fluent-bit       "$(img fluent_bit)"       "$(gh_latest fluent/fluent-bit)"
row cadvisor         "$(img cadvisor)"         "$(gh_latest google/cadvisor)"
row keycloak         "$(img keycloak)"         "$(gh_latest keycloak/keycloak)"

# --- JVM framework pins documented in the manifest ---------------------------
gv() { grep -oE "^ext\.$1_version='[^']+'" "$ROOT_DIR/gradles/chronicle.gradle" | sed -n 1p | sed "s/.*='//; s/'//"; }
row spring-framework "$(gv spring_framework)"  "$(maven_latest https://repo1.maven.org/maven2/org/springframework/spring-core/maven-metadata.xml)"
row hazelcast        "$(gv hazelcast)"         "$(maven_latest https://repo1.maven.org/maven2/com/hazelcast/hazelcast/maven-metadata.xml)"
row android-agp      "$(grep -oE 'com.android.tools.build:gradle:[0-9.]+' "$ROOT_DIR/chronicle/build.gradle" | sed -n 1p | sed 's/.*://')" "$(maven_latest https://dl.google.com/dl/android/maven2/com/android/tools/build/gradle/maven-metadata.xml)"

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
