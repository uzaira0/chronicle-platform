#!/usr/bin/env bash
# Hardcoded-English guard across the monorepo. Exits non-zero on the first surface with findings.
#   make i18n-lint            everything
#   scripts/i18n-lint.sh web|android|server|ios   one surface
# Needs: semgrep (pip install semgrep), jq, bun (web only). ast-grep is the toolchain-manifest.yaml
# gate_tools pin, installed into .local/bin by local-ci's ensure_ast_grep (checksum-verified): a
# different ast-grep first on PATH (Homebrew's, cargo's) is never used.
set -euo pipefail
cd "$(dirname "$0")/.."
surfaces=("$@"); [ ${#surfaces[@]} -eq 0 ] && surfaces=(web android server ios)
required_tools=(jq)
for s in "${surfaces[@]}"; do
  if [[ "$s" == ios && -f chronicle-ios/lint/i18n/semgrep.yml ]]; then required_tools+=(semgrep); fi
done
for tool in "${required_tools[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "i18n-lint: required tool missing: $tool" >&2
    exit 1
  fi
done
# shellcheck source=scripts/local-ci.sh
source scripts/local-ci.sh
ensure_ast_grep
status=0
for s in "${surfaces[@]}"; do
  echo "== i18n-lint: $s"
  case "$s" in
    web)
      # The Spanish report is informational here: missing keys are expected mid-translation and are
      # filled through `make i18n-sheet-import`; `bun run i18n:report es --check` is the strict gate.
      (cd chronicle-web && python3 ../scripts/i18n-lint-cases.py lint/i18n/cases && ast-grep scan src/modern && { bun run --silent i18n:report es | grep -E '^[a-z-]+: ' || true; }) || status=1 ;;
    android)
      (cd chronicle && python3 ../scripts/i18n-lint-cases.py lint/i18n/cases && ast-grep scan app/src/main collection-*/src/main) || status=1 ;;
    server)
      (cd chronicle-server && python3 ../scripts/i18n-lint-cases.py lint/i18n/cases && ast-grep scan src/main) || status=1 ;;
    ios)
      if [ -f chronicle-ios/lint/i18n/semgrep.yml ]; then
        (
          cd chronicle-ios || exit
          bash scripts/i18n-lint-selftest.sh || exit
          targets=()
          for target in chronicle ChronicleScreenTimeReport; do
            [[ ! -d "$target" ]] || targets+=("$target")
          done
          ((${#targets[@]} > 0)) || { echo "ios: source directories missing" >&2; exit 1; }
          semgrep --metrics=off --error --quiet --config lint/i18n/semgrep.yml "${targets[@]}"
        ) || status=1
      else
        echo "ios: no rules yet"; fi ;;
    *) echo "unknown surface: $s"; exit 2 ;;
  esac
done
exit $status
