#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORT_DIR="${1:-$ROOT_DIR/tests/security/reports}"

mkdir -p "$REPORT_DIR"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

pass() {
  echo "PASS: $*"
}

echo "=== Chronicle deploy guardrails ==="

# ./chronicle setup writes secrets to a mkstemp .env.setup-* file before os.replace; an
# interrupted setup must not leave it one `git add -A` away from a commit.
for env_file in .env .env.local .env.setup-abc123 .env.backup.20260101; do
  if ! git -C "$ROOT_DIR" check-ignore -q "selfhost/${env_file}"; then
    fail "selfhost/${env_file} must be gitignored"
  fi
done
if git -C "$ROOT_DIR" check-ignore -q selfhost/.env.example; then
  fail "selfhost/.env.example must stay tracked"
fi
pass "Self-host gitignore covers every .env* file except .env.example"

# Bun auto-loads .env* in chronicle-web; a developer's local file must stay out of commits.
for env_file in .env .env.local .env.production .env.development.local; do
  if ! git -C "$ROOT_DIR/chronicle-web" check-ignore -q "$env_file"; then
    fail "chronicle-web/${env_file} must be gitignored"
  fi
done
if git -C "$ROOT_DIR/chronicle-web" check-ignore -q .env.example; then
  fail "chronicle-web/.env.example must stay tracked"
fi
pass "Web gitignore covers every .env* file except .env.example"

# Application log archives are deleted by age; DefaultRolloverStrategy max
# counts only %i within one date, so without a Delete action daily archives never go away.
python3 - "$ROOT_DIR/chronicle-server/src/main/resources/log4j2.xml" <<'PY' || fail "application RollingFile appenders do not delete old archives, or would delete audit logs"
import fnmatch
import re
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
problems = []
for appender in root.iter("RollingFile"):
    if appender.get("name") == "AuditFile":
        continue
    delete = appender.find("./DefaultRolloverStrategy/Delete")
    age = delete.find(".//IfLastModified") if delete is not None else None
    glob = delete.find("IfFileName") if delete is not None else None
    if delete is None or age is None or not age.get("age") or glob is None:
        problems.append(f"{appender.get('name')} has no age-based Delete action")
        continue
    pattern = glob.get("regex", glob.get("glob", "")).replace("${serviceName}", "chronicle")
    matches = (lambda name: re.fullmatch(pattern, name) is not None) if glob.get("regex") else \
        (lambda name: fnmatch.fnmatch(name, pattern))
    for name in ("audit.2026-01-01.log.gz", "audit.2026-01-01.log", "audit.log",
                 "chronicle.log", "chronicle-json.log"):
        if matches(name):
            problems.append(f"{appender.get('name')} Delete pattern {pattern} matches protected log {name}")
    archive = appender.get("filePattern").rsplit("/", 1)[-1].replace("${serviceName}", "chronicle")
    archive = re.sub(r"%d\{[^}]+\}", "01-01-26-00-00-00", archive).replace("%i", "1")
    if not matches(archive):
        problems.append(f"{appender.get('name')} Delete pattern {pattern} matches none of its archives")
if problems:
    print("\n".join(problems), file=sys.stderr)
    sys.exit(1)
PY
pass "application log archives are deleted by age; audit logs are not"

# macOS ships bash 3.2 as /bin/bash, and ./chronicle setup runs guard-config.sh with it. Bash 4
# case expansions (${x,,} / ${x^^}) are a "bad substitution" there, which made setup refuse
# every production hostname. The alert-webhook check kept one (`${host,,}`) on its plain-HTTP
# branch, so bash 3.2 refused the default loopback webhook. The launcher and every script beside
# it are searched; the scripts under selfhost/monitoring run in containers and are not.
if grep -En '\$\{[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?(,,|\^\^)' "$ROOT_DIR/selfhost/chronicle" "$ROOT_DIR"/selfhost/*.sh; then
  fail "a self-host launcher script uses bash-4-only case expansion; macOS /bin/bash 3.2 cannot run it"
fi
BASH32_IMAGE='bash:3.2@sha256:0fd7cb8499c63a3c9345e7088a9cd83bb69f6e895e83833859aff838a0312091'
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker image inspect "$BASH32_IMAGE" >/dev/null 2>&1 || docker pull -q "$BASH32_IMAGE" >/dev/null
  for bash32_case in 'study.research-host.org:0' 'Study.Research-Host.ORG:0' '8.8.8.8:0' '[2606:4700:4700::1111]:0' \
                     'localhost:1' '192.168.1.50:1' '[fd00::1]:1' 'study.example.org:1'; do
    bash32_host="${bash32_case%:*}"; bash32_want="${bash32_case##*:}"
    bash32_rc=0
    docker run --rm --network none -v "$ROOT_DIR/selfhost/guard-config.sh:/guard-config.sh:ro" \
      -v "$ROOT_DIR/selfhost/network-policy.sh:/network-policy.sh:ro" \
      "$BASH32_IMAGE" bash /guard-config.sh --validate-public-host "$bash32_host" \
      >"$REPORT_DIR/bash32-guard.log" 2>&1 || bash32_rc=$?
    [[ "$bash32_rc" == "$bash32_want" ]] ||
      fail "bash 3.2 guard-config.sh --validate-public-host ${bash32_host}: exit ${bash32_rc}, want ${bash32_want} ($(cat "$REPORT_DIR/bash32-guard.log"))"
    ! grep -q 'bad substitution' "$REPORT_DIR/bash32-guard.log" ||
      fail "bash 3.2 cannot parse guard-config.sh"
  done
  pass "guard-config.sh host classifier gives the same answers under bash 3.2"
  # The last character of each case is the wanted exit status; the URL itself contains colons.
  for bash32_case in 'http://127.0.0.1:9/dashboard-only:0' 'http://LocalHost:9093/relay:0' \
                     'https://alerts.research-host.org/hook:0' 'http://alerts.research-host.org/hook:1' \
                     'http://127.evil.research-host.org/hook:1'; do
    bash32_url="${bash32_case%:*}"; bash32_want="${bash32_case##*:}"
    bash32_rc=0
    docker run --rm --network none -v "$ROOT_DIR/selfhost/guard-config.sh:/guard-config.sh:ro" \
      -v "$ROOT_DIR/selfhost/network-policy.sh:/network-policy.sh:ro" \
      "$BASH32_IMAGE" bash /guard-config.sh --validate-alert-webhook "$bash32_url" \
      >"$REPORT_DIR/bash32-guard.log" 2>&1 || bash32_rc=$?
    [[ "$bash32_rc" == "$bash32_want" ]] ||
      fail "bash 3.2 guard-config.sh --validate-alert-webhook ${bash32_url}: exit ${bash32_rc}, want ${bash32_want} ($(cat "$REPORT_DIR/bash32-guard.log"))"
    ! grep -q 'bad substitution' "$REPORT_DIR/bash32-guard.log" ||
      fail "bash 3.2 cannot run the alert-webhook check in guard-config.sh"
  done
  pass "guard-config.sh alert-webhook check gives the same answers under bash 3.2"
else
  fail "docker is required to run guard-config.sh under bash 3.2"
fi

echo "Deploy guardrails complete. Reports directory: $REPORT_DIR"
