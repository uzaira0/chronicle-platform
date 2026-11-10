#!/usr/bin/env bash
# Chronicle security log alerting: periodic review of system activity.
#
# Cron-run (every 15 min) scanner over the signals this host actually has:
#   - VictoriaLogs (traefik-access stream) for edge auth-failure / 5xx / rate-limit spikes
#   - docker logs for backend / postgres / keycloak error and tamper signals
#   - CrowdSec active decisions
#   - postgres for TDE coverage, replication health, Flyway ledger failures
#   - host for disk pressure and encrypted-backup freshness
#
# Delivery: every finding is appended to the local alert log; HIGH/CRITICAL
# findings also open (or comment on) a GitHub issue labeled `security-alert`
# in the chronicle-platform repo — the same box→GitHub channel the deploy poller uses.
# Alert bodies carry ONLY counts and thresholds (no log excerpts) per
# docs/security/production-observability-privacy-contract.md.
#
# Dedupe: per-alert-key cooldown (default 6h) in the state dir, so a sustained
# condition doesn't spam an issue per run. A CRITICAL upgrade bypasses cooldown.
#
# Catalog + procedure: docs/security/log-alerting-and-activity-review.md
#
# Usage:
#   scripts/security-log-alerts.sh            # scan + deliver
#   DRY_RUN=1 scripts/security-log-alerts.sh  # scan, log to stdout, no GitHub
set -uo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ── config ────────────────────────────────────────────────────────────────
WINDOW="${ALERT_WINDOW:-15m}"                 # docker-logs --since / LogsQL _time window
# No default. This used to fall back to uzaira0/chronicle-platform, which became a PUBLIC repo --
# every 15 minutes this filed an issue naming the host, the container, and the outage
# window, world-readable. Alert bodies are operational detail by nature, so the
# destination has to be a deliberate choice: set ALERT_GH_REPO to a PRIVATE repo, or
# leave it unset and alerts go only to $ALERT_LOG on this box. An unset value must never
# resolve to somewhere public again.
GH_REPO="${ALERT_GH_REPO:-}"
STATE_DIR="${ALERT_STATE_DIR:-$HOME/.config/chronicle/alert-state}"
ALERT_LOG="${ALERT_LOG:-/var/log/chronicle-security-alerts.log}"
COOLDOWN_SECS="${ALERT_COOLDOWN_SECS:-21600}" # 6h per alert key
BACKUP_DIR="${CHRONICLE_BACKUP_ROOT:-/opt/chronicle/backups}"
BACKUP_MAX_AGE_HOURS=26
ENV_FILE="${CHRONICLE_ENV_FILE:-/etc/chronicle/chronicle.env}"
DRY_RUN="${DRY_RUN:-0}"
export -n POSTGRES_PASSWORD 2>/dev/null || true

# thresholds per window
THRESH_BACKEND_ERRORS=10
THRESH_PG_ERRORS=5
THRESH_PG_PERMISSION_DENIED=5
THRESH_EDGE_AUTH_FAIL=50
THRESH_EDGE_RATELIMIT=100
THRESH_EDGE_5XX=25
THRESH_KEYCLOAK_LOGIN_ERRORS=10
THRESH_CROWDSEC_ACTIVE_BANS=3
THRESH_DISK_HIGH=90
THRESH_DISK_CRIT=95
THRESH_REPLICA_LAG_SECS=60

REQUIRED_CONTAINERS=(
  chronicle-backend chronicle-postgres chronicle-postgres-replica
  edge-traefik chronicle-crowdsec chronicle-keycloak
  chronicle-frontend chronicle-grafana chronicle-victoria-logs
  chronicle-victoria-metrics chronicle-fluent-bit chronicle-docker-proxy
)

mkdir -p "$STATE_DIR"
[ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] && [ -O "$STATE_DIR" ] || {
  printf 'security alert state directory must be current-user-owned and not a symlink: %s\n' "$STATE_DIR" >&2
  exit 1
}
chmod 700 "$STATE_DIR"
[ ! -L "$ALERT_LOG" ] || ALERT_LOG="$STATE_DIR/alerts.log"
touch "$ALERT_LOG" 2>/dev/null || ALERT_LOG="$STATE_DIR/alerts.log"
touch "$ALERT_LOG"
chmod 600 "$ALERT_LOG"

log_line() { printf '[%s] %s\n' "$(date -Is)" "$*" >> "$ALERT_LOG"; [ "$DRY_RUN" = "1" ] && printf '%s\n' "$*"; }

# ── delivery ─────────────────────────────────────────────────────────────
# alert KEY SEVERITY MESSAGE — message must contain counts only, never log content.
FIRED=0
alert() {
  local key="$1" severity="$2" msg="$3"
  FIRED=$((FIRED + 1))
  log_line "[$severity] $key: $msg"
  [ "$DRY_RUN" = "1" ] && return 0
  # Only HIGH/CRITICAL page out to GitHub; MEDIUM/INFO stay in the local log
  # and are picked up by the weekly review (see the activity-review doc).
  case "$severity" in HIGH|CRITICAL) ;; *) return 0 ;; esac
  # No destination configured: the alert is already in $ALERT_LOG above, and that is the
  # whole delivery. Returning here is what keeps an unset ALERT_GH_REPO from being handed
  # to gh, which would otherwise resolve the repo from the checkout's own git remote --
  # i.e. silently right back to the public repo this was moved off.
  [ -n "$GH_REPO" ] || return 0
  command -v gh >/dev/null 2>&1 || return 0
  local stamp_file="$STATE_DIR/last-$key" now last=0
  now=$(date +%s)
  [ -f "$stamp_file" ] && last=$(cat "$stamp_file" 2>/dev/null || echo 0)
  if [ $((now - last)) -lt "$COOLDOWN_SECS" ] && [ "$severity" != "CRITICAL" ]; then
    return 0
  fi
  echo "$now" > "$stamp_file"
  local title="[security-alert][$severity] $key"
  local body
  body="**$severity** \`$key\` from the Chronicle production monitor at $(date -Is)

$msg

Window: $WINDOW. Runbook: docs/security/log-alerting-and-activity-review.md → docs/security/incident-response-runbook.md. Counts only by design — inspect the source logs on the box."
  # Comment on the existing open issue for this key if there is one; else create.
  local existing
  existing=$(gh issue list -R "$GH_REPO" --state open --label security-alert \
    --search "\"$key\" in:title" --json number -q '.[0].number' 2>/dev/null)
  if [ -n "$existing" ]; then
    printf '%s\n' "$body" \
      | gh issue comment "$existing" -R "$GH_REPO" --body-file - >/dev/null 2>&1 || true
  else
    gh label create security-alert -R "$GH_REPO" --color D93F0B \
      --description "Automated security log alert" >/dev/null 2>&1 || true
    printf '%s\n' "$body" \
      | gh issue create -R "$GH_REPO" --title "$title" --label security-alert \
          --body-file - >/dev/null 2>&1 || true
  fi
}

# ── helpers ───────────────────────────────────────────────────────────────
file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

require_private_file() {
  local path="$1" description="$2" mode
  : "$description"
  [ -f "$path" ] && [ ! -L "$path" ] || return 1
  mode=$(file_mode "$path") || return 1
  [ "$mode" = "600" ] || return 1
  [ -O "$path" ] || return 1
  return 0
}

PG_INPUT_FILE=""
cleanup_private_inputs() {
  [ -n "$PG_INPUT_FILE" ] && [ -f "$PG_INPUT_FILE" ] && rm -f -- "$PG_INPUT_FILE"
}
trap cleanup_private_inputs EXIT

vlogs_count() { # LogsQL filter → count within $WINDOW
  local ip
  ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    chronicle-victoria-logs 2>/dev/null) || { echo 0; return; }
  curl -s --max-time 10 "http://${ip}:9428/select/logsql/query" \
    --data-urlencode "query=_time:${WINDOW} $1 | stats count() as hits" \
    | jq -r '.hits // 0' 2>/dev/null || echo 0
}

pg() { # read-only psql on the primary (peer-auth + parallel-scan footguns handled)
  local sql="$1" key value pw="" user="" db="" result status
  require_private_file "$ENV_FILE" "Chronicle environment file" || return 1
  while IFS='=' read -r key value; do
    case "$key" in
      POSTGRES_PASSWORD) pw="$value" ;;
      POSTGRES_USER) user="$value" ;;
      POSTGRES_DB) db="$value" ;;
    esac
  done < "$ENV_FILE"
  [ -n "$pw" ] && [ -n "$user" ] && [ -n "$db" ] || return 1
  PG_INPUT_FILE=$(mktemp "$STATE_DIR/.pg-input.XXXXXX") || return 1
  chmod 600 "$PG_INPUT_FILE"
  {
    printf '%s\n' "$pw"
    printf '%s\n' "$sql"
  } > "$PG_INPUT_FILE"
  result=$(docker exec -i chronicle-postgres sh -ceu '
    IFS= read -r PGPASSWORD
    export PGPASSWORD
    export PGOPTIONS="-c max_parallel_workers_per_gather=0"
    exec psql -h 127.0.0.1 -U "$1" -d "$2" -tA
  ' sh "$user" "$db" < "$PG_INPUT_FILE" 2>/dev/null)
  status=$?
  rm -f -- "$PG_INPUT_FILE"
  PG_INPUT_FILE=""
  [ "$status" -eq 0 ] || return "$status"
  printf '%s' "$result"
}

# ── 1. container health ───────────────────────────────────────────────────
for c in "${REQUIRED_CONTAINERS[@]}"; do
  running=$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null || echo missing)
  if [ "$running" != "true" ]; then
    alert "container-down-$c" CRITICAL "container $c is not running (state: $running)"
    continue
  fi
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$c" 2>/dev/null)
  if [ "$health" != "healthy" ] && [ "$health" != "none" ]; then
    alert "container-unhealthy-$c" CRITICAL "container $c health is '$health'"
  fi
done

# ── 2. backend error signals ──────────────────────────────────────────────
backend_logs=$(docker logs chronicle-backend --since "$WINDOW" 2>&1 || true)
# HttpMessageNotReadableException / "Unreadable request body" are client-input
# noise (the v49 devices POST empty bodies to /reminders on their poll loop) —
# malformed-request floods still surface via the edge 4xx/5xx/ratelimit checks.
n=$(grep ' ERROR ' <<<"$backend_logs" | grep -cv 'HttpMessageNotReadableException\|Unreadable request body' || true)
[ "${n:-0}" -ge "$THRESH_BACKEND_ERRORS" ] \
  && alert backend-error-spike HIGH "$n backend ERROR lines in $WINDOW (threshold $THRESH_BACKEND_ERRORS)"
n=$(grep -c 'RLSContextException' <<<"$backend_logs" || true)
[ "${n:-0}" -ge 1 ] \
  && alert backend-rls-context-failure CRITICAL "$n RLSContextException occurrences in $WINDOW — authorization context failed closed; investigate"
n=$(grep -c 'tables FAILED' <<<"$backend_logs" || true)
[ "${n:-0}" -ge 1 ] \
  && alert backend-tde-health-failed CRITICAL "EncryptionHealthService reported unencrypted tables ($n log lines in $WINDOW)"

# ── 3. postgres error / tamper signals ────────────────────────────────────
pg_logs=$(docker logs chronicle-postgres --since "$WINDOW" 2>&1 || true)
n=$(grep -c 'immutable' <<<"$pg_logs" || true)
[ "${n:-0}" -ge 1 ] \
  && alert pg-audit-tamper-attempt CRITICAL "$n blocked mutation attempts against append-only audit tables in $WINDOW"
n=$(grep -c 'permission denied' <<<"$pg_logs" || true)
[ "${n:-0}" -ge "$THRESH_PG_PERMISSION_DENIED" ] \
  && alert pg-permission-denied-spike HIGH "$n 'permission denied' errors in $WINDOW (threshold $THRESH_PG_PERMISSION_DENIED) — possible RLS/privilege probing"
n=$(grep -cE '^.*ERROR' <<<"$pg_logs" || true)
[ "${n:-0}" -ge "$THRESH_PG_ERRORS" ] \
  && alert pg-error-spike HIGH "$n postgres ERROR lines in $WINDOW (threshold $THRESH_PG_ERRORS)"

# ── 4. edge signals (VictoriaLogs traefik-access) ─────────────────────────
auth_fail=$(( $(vlogs_count '{stream="traefik-access"} "\"DownstreamStatus\":401"') \
            + $(vlogs_count '{stream="traefik-access"} "\"DownstreamStatus\":403"') ))
[ "$auth_fail" -ge "$THRESH_EDGE_AUTH_FAIL" ] \
  && alert edge-auth-failure-spike HIGH "$auth_fail edge 401/403 responses in $WINDOW (threshold $THRESH_EDGE_AUTH_FAIL)"
n=$(vlogs_count '{stream="traefik-access"} "\"DownstreamStatus\":429"')
[ "${n:-0}" -ge "$THRESH_EDGE_RATELIMIT" ] \
  && alert edge-ratelimit-spike MEDIUM "$n rate-limited (429) responses in $WINDOW (threshold $THRESH_EDGE_RATELIMIT)"
n=$(vlogs_count '{stream="traefik-access"} ("\"DownstreamStatus\":500" OR "\"DownstreamStatus\":502" OR "\"DownstreamStatus\":503" OR "\"DownstreamStatus\":504")')
[ "${n:-0}" -ge "$THRESH_EDGE_5XX" ] \
  && alert edge-5xx-spike HIGH "$n edge 5xx responses in $WINDOW (threshold $THRESH_EDGE_5XX)"
# Access logs intentionally omit request paths because they contain durable study
# and participant identifiers. Preserve a source-safe regression signal by
# counting 400 responses on the named mobile routers instead of matching a URI.
n=$(vlogs_count '{stream="traefik-access"} ("\"RouterName\":\"chronicle-mobile@docker\"" OR "\"RouterName\":\"chronicle-mobile-proxy-fallback@docker\"") "\"DownstreamStatus\":400"')
[ "${n:-0}" -ge 3 ] \
  && alert mobile-request-rejection-spike HIGH "$n rejected mobile requests in $WINDOW — inspect privacy-restricted backend diagnostics locally"

# ── 5. keycloak (SSO broker) login failures ───────────────────────────────
n=$(docker logs chronicle-keycloak --since "$WINDOW" 2>&1 | grep -c 'LOGIN_ERROR' || true)
[ "${n:-0}" -ge "$THRESH_KEYCLOAK_LOGIN_ERRORS" ] \
  && alert keycloak-login-failure-spike HIGH "$n Keycloak LOGIN_ERROR events in $WINDOW (threshold $THRESH_KEYCLOAK_LOGIN_ERRORS)"

# ── 6. crowdsec active decisions ──────────────────────────────────────────
n=$(docker exec chronicle-crowdsec cscli decisions list -o json 2>/dev/null | jq 'length' 2>/dev/null || echo 0)
[ "${n:-0}" -ge 1 ] && log_line "[INFO] crowdsec-active-bans: $n active decision group(s)"
[ "${n:-0}" -ge "$THRESH_CROWDSEC_ACTIVE_BANS" ] \
  && alert crowdsec-ban-wave MEDIUM "$n concurrent CrowdSec decision groups active (threshold $THRESH_CROWDSEC_ACTIVE_BANS)"

# ── 7. disk pressure ──────────────────────────────────────────────────────
for mount in /home /; do
  pct=$(df --output=pcent "$mount" 2>/dev/null | tail -1 | tr -dc '0-9')
  [ -z "$pct" ] && continue
  if [ "$pct" -ge "$THRESH_DISK_CRIT" ]; then
    alert "disk-critical-${mount//\//_}" CRITICAL "$mount at ${pct}% (critical threshold $THRESH_DISK_CRIT%)"
  elif [ "$pct" -ge "$THRESH_DISK_HIGH" ]; then
    alert "disk-high-${mount//\//_}" HIGH "$mount at ${pct}% (threshold $THRESH_DISK_HIGH%)"
  fi
done

# ── 8. encrypted-backup freshness ─────────────────────────────────────────
newest=$(ls -t "$BACKUP_DIR" 2>/dev/null | head -1)
if [ -z "$newest" ]; then
  alert backup-missing CRITICAL "no backups found under $BACKUP_DIR"
else
  age_hours=$(( ( $(date +%s) - $(stat -c %Y "$BACKUP_DIR/$newest") ) / 3600 ))
  [ "$age_hours" -gt "$BACKUP_MAX_AGE_HOURS" ] \
    && alert backup-stale CRITICAL "newest backup is ${age_hours}h old (max $BACKUP_MAX_AGE_HOURS h) — nightly backup failing"
  [ -f "$BACKUP_DIR/$newest/manifest.json" ] \
    || alert backup-incomplete HIGH "newest backup ($newest) has no manifest.json — backup job likely failed mid-run"
fi

# ── 9. database invariants ────────────────────────────────────────────────
n=$(pg "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_am a ON a.oid=c.relam WHERE n.nspname='public' AND c.relkind='r' AND a.amname <> 'tde_heap'" || echo "")
if [ -n "$n" ]; then
  [ "$n" -ge 1 ] && alert tde-coverage-gap HIGH "$n public table(s) not on tde_heap — run docker/migrate-tde.sh"
  repl=$(pg "SELECT count(*) FROM pg_stat_replication WHERE state='streaming'")
  [ "${repl:-0}" -eq 0 ] && alert replica-not-streaming HIGH "no streaming replica attached to the primary"
  lag=$(pg "SELECT COALESCE(EXTRACT(EPOCH FROM MAX(replay_lag))::int, 0) FROM pg_stat_replication")
  [ "${lag:-0}" -ge "$THRESH_REPLICA_LAG_SECS" ] \
    && alert replica-lag MEDIUM "replica replay lag ${lag}s (threshold $THRESH_REPLICA_LAG_SECS s)"
  failed=$(pg "SELECT count(*) FROM flyway_schema_history WHERE NOT success")
  [ "${failed:-0}" -ge 1 ] && alert flyway-failed-migration HIGH "$failed failed migration(s) in flyway_schema_history"
else
  alert alerting-pg-unreachable HIGH "alert scanner could not query postgres (creds or container issue) — DB-invariant checks did not run"
fi

log_line "scan complete: $FIRED finding(s) [window=$WINDOW dry_run=$DRY_RUN]"
exit 0
