#!/usr/bin/env bash
# Mutation test for the hardcoded-English guard: plants a violation inside each real source tree,
# proves the surface's lint entry point fails and names the probe, plants the same violation in
# an ignored location and proves it passes, then removes every probe (also on interruption).
#   scripts/i18n-lint-mutation.sh [web|android|server|ios ...]
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
surfaces=("$@"); [ ${#surfaces[@]} -eq 0 ] && surfaces=(web android server ios)
probes=()
cleanup() { for p in "${probes[@]:-}"; do [ -n "$p" ] && rm -f "$p"; done; }
trap cleanup EXIT INT TERM
status=0
plant() { # plant <path> <content>
  mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; probes+=("$1")
}
expect_fail() { # expect_fail <label> <probe-path> <rule-id> <cmd...>
  local label=$1 probe=$2 rule=$3; shift 3
  local out; out=$("$@" 2>&1); local rc=$?
  if [ $rc -ne 0 ] && grep -q "$rule" <<<"$out" && grep -q "$(basename "$probe")" <<<"$out"; then
    echo "PASS $label: exit $rc, reported $rule at $(basename "$probe")"
  else
    echo "FAIL $label: exit $rc"; echo "$out" | tail -5; status=1
  fi
}
expect_pass() { # expect_pass <label> <cmd...>
  local label=$1; shift
  local out; out=$("$@" 2>&1); local rc=$?
  if [ $rc -eq 0 ]; then echo "PASS $label: exit 0 (probe in an ignored location is not reported)"
  else echo "FAIL $label: exit $rc"; echo "$out" | tail -5; status=1; fi
}
for s in "${surfaces[@]}"; do
  echo "== mutation: $s"
  case "$s" in
    web)
      plant chronicle-web/src/modern/routes/zz-i18n-probe.tsx "export function Probe() { return <p title=\"Probe title\">Probe text here</p>; }"
      expect_fail "web real tree" chronicle-web/src/modern/routes/zz-i18n-probe.tsx web-i18n-jsx-text bash -c 'cd chronicle-web && bun run --silent i18n:lint'
      rm -f chronicle-web/src/modern/routes/zz-i18n-probe.tsx
      plant chronicle-web/src/modern/routes/zz-i18n-probe.test.tsx "export function Probe() { return <p title=\"Probe title\">Probe text here</p>; }"
      expect_pass "web ignored path (*.test.tsx)" bash -c 'cd chronicle-web && bun run --silent i18n:lint'
      rm -f chronicle-web/src/modern/routes/zz-i18n-probe.test.tsx ;;
    android)
      plant chronicle/app/src/main/java/com/openlattice/chronicle/ZzI18nProbe.kt "package com.openlattice.chronicle
class ZzI18nProbe(private val view: android.widget.TextView) { fun show() { view.text = \"Probe text here\" } }"
      expect_fail "android real tree" chronicle/app/src/main/java/com/openlattice/chronicle/ZzI18nProbe.kt android-i18n-ui-literal bash -c 'cd chronicle && ast-grep scan app/src/main collection-*/src/main'
      rm -f chronicle/app/src/main/java/com/openlattice/chronicle/ZzI18nProbe.kt
      plant chronicle/app/src/test/java/com/openlattice/chronicle/ZzI18nProbe.kt "package com.openlattice.chronicle
class ZzI18nProbe(private val view: android.widget.TextView) { fun show() { view.text = \"Probe text here\" } }"
      expect_pass "android ignored path (src/test)" bash -c 'cd chronicle && ast-grep scan app/src/main app/src/test collection-*/src/main'
      rm -f chronicle/app/src/test/java/com/openlattice/chronicle/ZzI18nProbe.kt ;;
    server)
      plant chronicle-server/src/main/kotlin/com/openlattice/chronicle/controllers/ZzI18nProbe.kt "package com.openlattice.chronicle.controllers
import org.springframework.http.HttpStatus
import org.springframework.web.server.ResponseStatusException
class ZzI18nProbe { fun a(): Nothing = throw ResponseStatusException(HttpStatus.NOT_FOUND, \"Probe text here\") }"
      expect_fail "server real tree" chronicle-server/src/main/kotlin/com/openlattice/chronicle/controllers/ZzI18nProbe.kt server-i18n-response-literal bash -c 'cd chronicle-server && ast-grep scan src/main'
      rm -f chronicle-server/src/main/kotlin/com/openlattice/chronicle/controllers/ZzI18nProbe.kt
      plant chronicle-server/src/main/kotlin/com/openlattice/chronicle/configuration/ZzI18nProbeSecurityHardeningConfig.kt "package com.openlattice.chronicle.configuration
class ZzI18nProbeSecurityHardeningConfig(private val response: jakarta.servlet.http.HttpServletResponse) { fun a() = response.sendError(400, \"Probe text here\") }"
      expect_fail "server: only the exact hardening filter files are excluded" chronicle-server/src/main/kotlin/com/openlattice/chronicle/configuration/ZzI18nProbeSecurityHardeningConfig.kt server-i18n-response-literal bash -c 'cd chronicle-server && ast-grep scan src/main'
      rm -f chronicle-server/src/main/kotlin/com/openlattice/chronicle/configuration/ZzI18nProbeSecurityHardeningConfig.kt
      plant chronicle-server/src/test/kotlin/com/openlattice/chronicle/ZzI18nProbe.kt "package com.openlattice.chronicle
class ZzI18nProbe(private val response: jakarta.servlet.http.HttpServletResponse) { fun a() = response.sendError(400, \"Probe text here\") }"
      expect_pass "server ignored path (src/test)" bash -c 'cd chronicle-server && ast-grep scan src/main src/test'
      rm -f chronicle-server/src/test/kotlin/com/openlattice/chronicle/ZzI18nProbe.kt ;;
    ios)
      plant chronicle-ios/chronicle/Views/ZzI18nProbe.swift "final class ZzI18nProbe { var statusText = \"\"; func run() { statusText = \"Probe text here\" } }"
      expect_fail "ios real tree" chronicle-ios/chronicle/Views/ZzI18nProbe.swift ios-i18n-status-literal bash -c 'cd chronicle-ios && semgrep --metrics=off --error --quiet --config lint/i18n/semgrep.yml chronicle ChronicleScreenTimeReport'
      rm -f chronicle-ios/chronicle/Views/ZzI18nProbe.swift
      plant chronicle-ios/chronicleTests/ZzI18nProbe.swift "final class ZzI18nProbe { var statusText = \"\"; func run() { statusText = \"Probe text here\" } }"
      expect_pass "ios ignored path (chronicleTests)" bash -c 'cd chronicle-ios && semgrep --metrics=off --error --quiet --config lint/i18n/semgrep.yml chronicle ChronicleScreenTimeReport chronicleTests'
      rm -f chronicle-ios/chronicleTests/ZzI18nProbe.swift ;;
    *) echo "unknown surface: $s"; exit 2 ;;
  esac
done
echo "== root entry point"
plant chronicle-server/src/main/kotlin/com/openlattice/chronicle/controllers/ZzI18nProbe.kt "package com.openlattice.chronicle.controllers
class ZzI18nProbe(private val response: jakarta.servlet.http.HttpServletResponse) { fun a() = response.sendError(400, \"Probe text here\") }"
expect_fail "scripts/i18n-lint.sh propagates a surface failure" chronicle-server/src/main/kotlin/com/openlattice/chronicle/controllers/ZzI18nProbe.kt server-i18n-response-literal scripts/i18n-lint.sh server
rm -f chronicle-server/src/main/kotlin/com/openlattice/chronicle/controllers/ZzI18nProbe.kt
leftovers=$(git -C chronicle-web status --short | grep -c ZzI18n; git -C chronicle status --short | grep -c ZzI18n; git -C chronicle-server status --short | grep -c ZzI18n; git -C chronicle-ios status --short | grep -c ZzI18n)
[ "$(echo "$leftovers" | tr -d '\n0')" = "" ] && echo "PASS no probe left behind" || { echo "FAIL probes left behind"; status=1; }
exit $status
