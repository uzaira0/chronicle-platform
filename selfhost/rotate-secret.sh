#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Strip inherited secret exports before startup probes or any external command.
SECRET_ENV_KEYS=(
  DASHBOARD_PASSWORD DASHBOARD_PASSWORD_HASH POSTGRES_PASSWORD POSTGRES_APP_PASSWORD JWT_SECRET JWT_SECRET_PREVIOUS METRICS_PASSWORD
  CHRONICLE_INTERNAL_WEB_SECRET GRAFANA_ADMIN_PASSWORD
  CHRONICLE_REVIEWER_ACCESS_SECRET CHRONICLE_ALERT_WEBHOOK_URL
)
for secret_key in "${SECRET_ENV_KEYS[@]}"; do
  export -n "${secret_key?}" 2>/dev/null || true
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROTATION_ARGS=("$@")
cd "$SCRIPT_DIR"
source "$SCRIPT_DIR/network-policy.sh"

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

warn() {
  printf 'WARNING: %s\n' "$*" >&2
}

log() {
  printf '%s\n' "$*"
}

usage() {
  cat <<'EOF'
Usage:
  ./chronicle rotate-secret [--yes] dashboard
  ./chronicle rotate-secret [--yes] jwt [--revoke-sessions]
  ./chronicle rotate-secret [--yes] internal-web
  ./chronicle rotate-secret [--yes] reviewer
  ./chronicle rotate-secret [--yes] metrics
  ./chronicle rotate-secret [--yes] postgres
  ./chronicle rotate-secret [--yes] postgres-app
  ./chronicle rotate-secret [--yes] grafana
  ./chronicle rotate-secret [--yes] tde
  ./chronicle rotate-secret recover --forward|--rollback [--yes]

--validate checks command arguments without accessing deployment settings or rotating a secret.

Passwords and generated secrets are never accepted as command arguments or printed. The
dashboard command reads a chosen password silently; every other command generates a new
256-bit value directly into the mode-0600 .env file.

If a host crash leaves .chronicle-secret-rotation behind, do not delete it. Review the
runbook, confirm no rotation process remains, and use recover to finish the published
credential or restore the saved pre-rotation configuration.
EOF
}

dc() {
  local anonymous
  anonymous="$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" python3 -c \
    'import sys; from chronicle_ops.common import before_compose; print(*before_compose(sys.argv[1], sys.argv[2:]))' "$PROJECT" "$@")"
  if [[ -z "$anonymous" ]]; then
    docker compose -p "$PROJECT" "$@"
    return
  fi
  # This command can remove containers that mount anonymous volumes (one per VOLUME path of the
  # PostgreSQL image that no named volume covers). Compose leaves those volumes, so they are
  # removed after it (chronicle_ops/common.py after_compose). The subshell has its own signal
  # handlers: an interrupt during Compose still stops Compose, and the removal runs before this
  # script's traps do.
  (
    trap : HUP INT TERM
    status=0
    docker compose -p "$PROJECT" "$@" || status=$?
    # From here a signal ends this at once (after_compose_status stops the Docker call it waits
    # for), and the Docker calls together are limited to AFTER_COMPOSE_SECONDS.
    trap - HUP INT TERM
    after=0
    # shellcheck disable=SC2086 # one volume name per word
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" python3 -c \
      'import sys; from chronicle_ops.common import after_compose_status; sys.exit(after_compose_status(sys.argv[1], sys.argv[2:]))' "$PROJECT" $anonymous || after=$?
    if (( after > 128 )); then exit "$after"; fi
    if (( after )); then warn "could not check for anonymous volumes left by removed containers"; fi
    exit "$status"
  )
}

# Core and monitoring service lists come from chronicle_ops/services.py, as for ./chronicle up.
service_roles() {
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" CHRONICLE_OPS_PROJECT="$PROJECT" python3 -m chronicle_ops "$@"
}

confirm() {
  local prompt="$1" answer
  [[ "$ASSUME_YES" == true ]] && return 0
  [[ -t 0 ]] || fail "confirmation requires a terminal; review the runbook, then repeat with --yes"
  read -rp "${prompt} [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || fail "rotation cancelled"
}

service_running() {
  local service="$1" container_id
  container_id="$(dc ps -q "$service" 2>/dev/null)"
  [[ -n "$container_id" ]] || fail "Compose service '$service' is not running"
  [[ "$(docker inspect -f '{{.State.Running}}' "$container_id" 2>/dev/null)" == true ]] ||
    fail "Compose service '$service' is not running"
}

write_phase() {
  local phase="$1"
  python3 - "$ROTATION_DIR" "$phase" <<'PY'
from pathlib import Path
import os
import sys

root = Path(sys.argv[1])
phase = sys.argv[2]
temporary = root / f".phase.{os.getpid()}"
destination = root / "phase"
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(temporary, flags, 0o600)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(f"{phase}\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)
    directory_fd = os.open(root, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
}

sync_transaction_metadata() {
  python3 - "$ROTATION_DIR" <<'PY'
from pathlib import Path
import os
import sys

root = Path(sys.argv[1])
for name in ("old.env", "kind", "action", "owner-pid", "started-at"):
    fd = os.open(root / name, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
directory_fd = os.open(root, os.O_RDONLY)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
}

write_tde_recovery_metadata() {
  printf '%s\0%s\0' "$OLD_TDE_KEY" "$NEW_TDE_KEY" | python3 /dev/fd/3 "$ROTATION_DIR" 3<<'PY'
from pathlib import Path
import os
import sys

root = Path(sys.argv[1])
values = sys.stdin.buffer.read().split(b"\0")
if values and values[-1] == b"":
    values.pop()
if len(values) != 2 or any(not value for value in values):
    raise SystemExit("malformed TDE recovery metadata")

for name, value in zip(("old-tde-key", "new-tde-key"), values):
    temporary = root / f".{name}.{os.getpid()}"
    destination = root / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(value + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

directory_fd = os.open(root, os.O_RDONLY)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
}

# The one supported command that resumes or settles another operation's marker.
recovery_command() {
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" python3 -c \
    'import sys; from pathlib import Path; from chronicle_ops.reconcile import recovery_command; print(recovery_command(Path(sys.argv[1])))' "$1"
}

begin_transaction() {
  local kind="$1" action="$2"
  [[ ! -e "$UPGRADE_LOCK_DIR" && ! -L "$UPGRADE_LOCK_DIR" ]] ||
    fail "an upgrade is active or incomplete ($UPGRADE_LOCK_DIR); do not rotate secrets concurrently. Run $(recovery_command "$UPGRADE_LOCK_DIR")"
  [[ ! -e "$RESTORE_LOCK_DIR" && ! -L "$RESTORE_LOCK_DIR" ]] ||
    fail "a restore is active or incomplete ($RESTORE_LOCK_DIR); do not rotate secrets concurrently. Run $(recovery_command "$RESTORE_LOCK_DIR")"
  if ! /bin/mkdir "$ROTATION_DIR" 2>/dev/null; then
    fail "a prior secret rotation is active or incomplete ($ROTATION_DIR). Do not delete it; follow the interrupted-rotation procedure in docs/SECRET-ROTATION.md."
  fi
  if ! /bin/chmod 0700 "$ROTATION_DIR"; then
    /bin/rmdir "$ROTATION_DIR" 2>/dev/null || true
    fail "could not protect the secret-rotation transaction directory"
  fi
  # Close the check-then-mkdir race with the other state-changing operator commands. If a
  # competing lock appeared, this directory is still empty and can be released safely.
  if [[ -e "$UPGRADE_LOCK_DIR" || -L "$UPGRADE_LOCK_DIR" ]]; then
    /bin/rmdir "$ROTATION_DIR" 2>/dev/null || true
    fail "an upgrade started while the secret-rotation lock was being acquired; rotation did not start"
  fi
  if [[ -e "$RESTORE_LOCK_DIR" || -L "$RESTORE_LOCK_DIR" ]]; then
    /bin/rmdir "$ROTATION_DIR" 2>/dev/null || true
    fail "a restore started while the secret-rotation lock was being acquired; rotation did not start"
  fi
  /bin/cp .env "${ROTATION_DIR}/old.env"
  /bin/chmod 0600 "${ROTATION_DIR}/old.env"
  printf '%s\n' "$kind" >"${ROTATION_DIR}/kind"
  printf '%s\n' "$action" >"${ROTATION_DIR}/action"
  printf '%s\n' "$$" >"${ROTATION_DIR}/owner-pid"
  printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"${ROTATION_DIR}/started-at"
  /bin/chmod 0600 "${ROTATION_DIR}/kind" "${ROTATION_DIR}/action" \
    "${ROTATION_DIR}/owner-pid" "${ROTATION_DIR}/started-at"
  # The durable phase marker is the recovery commit point. Flush every file it refers to
  # before publishing it so a power loss cannot preserve `prepared` without its metadata.
  sync_transaction_metadata
  write_phase prepared
  TRANSACTION_ACTIVE=true
  ROLLBACK_REQUIRED=true
}

remove_transaction() {
  [[ -d "$ROTATION_DIR" ]] || return 0
  /bin/rm -f -- \
    "${ROTATION_DIR}/old.env" \
    "${ROTATION_DIR}/kind" \
    "${ROTATION_DIR}/action" \
    "${ROTATION_DIR}/phase" \
    "${ROTATION_DIR}/owner-pid" \
    "${ROTATION_DIR}/started-at" \
    "${ROTATION_DIR}/old-tde-key" \
    "${ROTATION_DIR}/new-tde-key"
  local phase_temporary
  for phase_temporary in \
      "${ROTATION_DIR}"/.phase.* \
      "${ROTATION_DIR}"/.old-tde-key.* \
      "${ROTATION_DIR}"/.new-tde-key.*; do
    [[ -e "$phase_temporary" || -L "$phase_temporary" ]] || continue
    /bin/rm -f -- "$phase_temporary"
  done
  /bin/rmdir "$ROTATION_DIR"
  TRANSACTION_ACTIVE=false
}

env_update() {
  (($# >= 2 && $# % 2 == 0)) || fail "internal error: env_update needs key/value pairs"
  {
    while (($#)); do
      printf '%s\0%s\0' "$1" "$2"
      shift 2
    done
  } | PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" python3 /dev/fd/3 .env 3<<'PY'
from pathlib import Path
import os
import sys
from chronicle_ops.envfile import assignment, quote_env

path = Path(sys.argv[1])
raw = sys.stdin.buffer.read().split(b"\0")
if raw and raw[-1] == b"":
    raw.pop()
if len(raw) % 2:
    raise SystemExit("malformed secret update payload")

allowed = {
    "DASHBOARD_PASSWORD_HASH",
    "POSTGRES_PASSWORD",
    "POSTGRES_APP_PASSWORD",
    "JWT_SECRET",
    "JWT_SECRET_PREVIOUS",
    "JWT_SECRET_PREVIOUS_EXPIRES_AT",
    "METRICS_PASSWORD",
    "CHRONICLE_INTERNAL_WEB_SECRET",
    "CHRONICLE_REVIEWER_ACCESS_ENABLED",
    "CHRONICLE_REVIEWER_ACCESS_SECRET",
    "GRAFANA_ADMIN_PASSWORD",
}
updates = {}
for index in range(0, len(raw), 2):
    key = raw[index].decode("ascii")
    value = raw[index + 1].decode("utf-8")
    if key not in allowed:
        raise SystemExit(f"unsupported secret key: {key}")
    if key in updates:
        raise SystemExit(f"duplicate secret update: {key}")
    if any(character in value for character in ("\x00", "\n", "\r")):
        raise SystemExit(f"{key} contains a character that cannot be represented safely in .env")
    updates[key] = value

lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
for key, value in updates.items():
    encoded = quote_env(value)
    if not encoded.startswith(("'", '"')):
        encoded = "'" + encoded + "'"
    matches = [index for index, line in enumerate(lines)
               if (match := assignment.fullmatch(line.strip())) and match[1] == key]
    if not matches and key in {"JWT_SECRET_PREVIOUS", "JWT_SECRET_PREVIOUS_EXPIRES_AT"}:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(f"{key}={encoded}\n")
        continue
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one {key} assignment in .env")
    lines[matches[0]] = f"{key}={encoded}\n"
text = "".join(lines)

temporary = path.with_name(f".{path.name}.rotation-{os.getpid()}")
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
  /bin/chmod 0600 .env
}

restore_old_env() {
  python3 - .env "${ROTATION_DIR}/old.env" <<'PY'
from pathlib import Path
import os
import sys

destination = Path(sys.argv[1])
source = Path(sys.argv[2])
data = source.read_bytes()
temporary = destination.with_name(f".{destination.name}.rollback-{os.getpid()}")
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)
    directory_fd = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
  /bin/chmod 0600 .env
}

apply_configuration() {
  if [[ "$APPLY_MODE" == full ]]; then
    local service service_list
    local -a startup_services=()
    local export_ca=false
    # Only core services gate the rotation; optional monitoring restarts after them and only warns.
    service_list="$(service_roles compose-services core)" || return 1
    while IFS= read -r service; do
      if [[ "$service" == ca-export ]]; then export_ca=true
      elif [[ -n "$service" ]]; then startup_services+=("$service"); fi
    done <<< "$service_list"
    ((${#startup_services[@]} > 0)) || return 1
    dc up -d --wait --wait-timeout "$SECRET_ROTATION_WAIT_TIMEOUT_SECONDS" --remove-orphans "${startup_services[@]}" || return 1
    service_roles start-monitoring
    if [[ "$export_ca" == true ]]; then dc run --rm --no-deps ca-export || return 1; fi
  else
    ((${#APPLY_SERVICES[@]} > 0)) || fail "internal error: no services selected for rotation"
    local -a running_services=()
    local service refresh_monitoring=false
    # The services below are recreated with --no-deps, so rewrite their credential files first.
    dc run --rm --no-deps secrets-init || return 1
    for service in "${APPLY_SERVICES[@]}"; do
      if [[ "$service" == monitoring-config ]]; then
        dc run --rm --no-deps monitoring-config || return 1
        refresh_monitoring=true
      else
        running_services+=("$service")
      fi
    done
    ((${#running_services[@]} > 0)) || fail "internal error: no running services selected for rotation"
    dc up -d --wait --wait-timeout "$SECRET_ROTATION_WAIT_TIMEOUT_SECONDS" \
      --no-deps --force-recreate --renew-anon-volumes "${running_services[@]}" || return 1
    if [[ "$refresh_monitoring" == true ]] && ! wait_for_metrics_target; then
      printf 'ERROR: VictoriaMetrics did not report the chronicle-backend target up after credential refresh\n' >&2
      return 1
    fi
  fi
}

wait_for_metrics_target() {
  local targets deadline=$((SECONDS + SECRET_ROTATION_WAIT_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    if targets="$(dc exec -T grafana wget -T 8 -qO- \
        http://victoriametrics:8428/api/v1/targets 2>/dev/null)" &&
      printf '%s' "$targets" | python3 -c '
import json
import sys

try:
    targets = json.load(sys.stdin).get("data", {}).get("activeTargets", [])
except (ValueError, AttributeError):
    raise SystemExit(1)
raise SystemExit(0 if any(
    target.get("labels", {}).get("job") == "chronicle-backend" and target.get("health") == "up"
    for target in targets if isinstance(target, dict)
) else 1)
'; then
      return 0
    fi
    sleep 1
  done
  return 1
}

dashboard_login_code() { # password url -> status; password goes as JSON on stdin
  local password="$1" url="$2"
  printf '%s' "$password" |
    python3 -c 'import json,sys; sys.stdout.write(json.dumps({"password": sys.stdin.read()}))' |
    curl -s --cacert "$DASHBOARD_CA" --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 15 \
      -H 'Content-Type: application/json' --data-binary @- "$url"
}

postgres_query() {
  local auth_password="$1" sql="$2" username="${3:-${POSTGRES_USER:-chronicle}}"
  {
    printf '%s\0' "$auth_password"
    printf '%s\n' "$sql"
  } | dc exec -T postgres /bin/bash -euc '
    IFS= read -r -d "" PGPASSWORD
    export PGPASSWORD
    exec psql -X -qAt -v ON_ERROR_STOP=1 -h 127.0.0.1 \
      -U "$1" -d "${POSTGRES_DB:-chronicle}" -f -
  ' bash "$username"
}

postgres_can_auth() {
  postgres_query "$1" 'SELECT 1;' "${POSTGRES_ROTATION_ROLE:-${POSTGRES_USER:-chronicle}}" 2>/dev/null | grep -x 1 >/dev/null
}

postgres_alter_password() {
  local auth_password="$1" target_password="$2" escaped
  escaped="${target_password//\'/\'\'}"
  if [[ "${POSTGRES_ROTATION_KEY:-POSTGRES_PASSWORD}" == POSTGRES_APP_PASSWORD ]]; then
    postgres_query "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is not set}" \
      "ALTER ROLE chronicle_app WITH PASSWORD '${escaped}';" >/dev/null
  else
    postgres_query "$auth_password" "ALTER ROLE CURRENT_USER WITH PASSWORD '${escaped}';" >/dev/null
  fi
}

tde_state() {
  postgres_query "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is not set}" \
    "SELECT key_name || '|' || provider_name FROM pg_tde_key_info();"
}

tde_set_active_key() {
  local key_name="$1" escaped_key
  escaped_key="${key_name//\'/\'\'}"
  postgres_query "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is not set}" \
    "SELECT pg_tde_set_key_using_database_key_provider('${escaped_key}', 'chronicle_keyring');" \
    >/dev/null
}

verify_tde_encrypted_tables() {
  local counts plain encrypted
  counts="$(postgres_query "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is not set}" "
SELECT
  count(*) FILTER (WHERE a.amname <> 'tde_heap')::text || '|' ||
  count(*) FILTER (WHERE a.amname = 'tde_heap')::text
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_am a ON a.oid = c.relam
WHERE n.nspname = 'public' AND c.relkind = 'r';
")"
  plain="${counts%%|*}"
  encrypted="${counts#*|}"
  [[ "$counts" == *'|'* && "$plain" =~ ^[0-9]+$ && "$encrypted" =~ ^[0-9]+$ ]] ||
    fail "could not verify the encrypted-table state after TDE rotation"
  [[ "$plain" -eq 0 && "$encrypted" -gt 0 ]] ||
    fail "TDE rotation verification found ${plain} plain and ${encrypted} encrypted public tables"
}

copy_and_verify_live_keyring() {
  local backup_keyring="${STATE_ROOT}/backups/keyring/chronicle-keyring.per" mode
  # db-init mounts both the live keyring volume and the host backup tree. Its copy is atomic,
  # byte-compared, and preserves an already rotated active key.
  dc run --rm --no-deps db-init
  [[ -s "$backup_keyring" ]] || fail "the rotated live keyring was not copied into the backup set"
  mode="$(python3 - "$backup_keyring" <<'PY'
from pathlib import Path
import stat
import sys

path = Path(sys.argv[1])
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
    raise SystemExit("keyring backup is not a regular file")
print(oct(stat.S_IMODE(metadata.st_mode))[2:])
PY
)"
  [[ "$mode" == 600 ]] || fail "the keyring backup is mode ${mode}, expected 600"
}

take_pre_rotation_backup() {
  command -v gzip >/dev/null 2>&1 || fail "gzip is required for the pre-rotation backup"
  local directory="${STATE_ROOT}/backups/secret-rotation"
  local timestamp partial final checksum schema_excludes catalog_gate option
  local -a schema_options
  schema_excludes=$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" python3 -m chronicle_ops.dump --dump-excludes) ||
    fail "could not load the SQL backup schema policy"
  schema_options=()
  while IFS= read -r option; do schema_options+=("$option"); done <<<"$schema_excludes"
  catalog_gate=$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" python3 -m chronicle_ops.dump --catalog-gate) ||
    fail "could not load the SQL backup catalog policy"
  postgres_query "${POSTGRES_PASSWORD}" "$catalog_gate" >/dev/null || fail "database objects do not match the restore policy"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  /bin/mkdir -p "$directory"
  /bin/chmod 0700 "${STATE_ROOT}/backups" "$directory" ||
    fail "cannot make the backup directory ${directory} private (mode 0700); fix its ownership before rotating"
  final="${directory}/chronicle-pre-tde-${timestamp}-$$.sql.gz"
  partial="${final}.partial"
  BACKUP_PARTIAL="$partial"
  exec 8>"$partial"
  python3 -c 'import fcntl; fcntl.flock(8, fcntl.LOCK_EX)' || fail "could not lock the pre-rotation dump"
  if ! dc exec -T postgres /bin/bash -euc '
      PGPASSWORD="${POSTGRES_PASSWORD:-$(cat "$POSTGRES_PASSWORD_FILE")}" exec pg_dump -h 127.0.0.1 \
        -U "${POSTGRES_USER:-chronicle}" -d "${POSTGRES_DB:-chronicle}" \
        --no-owner "$@"
    ' chronicle-dump "${schema_options[@]}" | gzip -9 >&8; then
    /bin/rm -f -- "$partial"
    BACKUP_PARTIAL=""
    fail "the pre-rotation SQL dump failed"
  fi
  if [[ ! -s "$partial" ]] || ! gzip -t "$partial"; then
    /bin/rm -f -- "$partial"
    BACKUP_PARTIAL=""
    fail "the pre-rotation SQL dump failed gzip verification"
  fi
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" python3 -m chronicle_ops.dump \
    --stamp-installed "$partial" "$SCRIPT_DIR" || fail "could not stamp the pre-rotation backup"
  /bin/mv "$partial" "$final"
  exec 8>&-
  BACKUP_PARTIAL=""
  /bin/chmod 0600 "$final"
  checksum="$(python3 -c 'import hashlib,sys
h=hashlib.sha256()
with open(sys.argv[1],"rb") as handle:
    for chunk in iter(lambda: handle.read(1 << 20), b""):
        h.update(chunk)
print(h.hexdigest())' "$final")"
  RECEIPT_DETAIL="backup=${final};sha256=${checksum}"
}

write_receipt() {
  local kind="$1" action="$2" timestamp path
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  /bin/mkdir -p "$RECEIPT_DIR"
  /bin/chmod 0700 "$RECEIPT_DIR"
  path="${RECEIPT_DIR}/${timestamp}-${kind}-${action}-$$.json"
  ROTATION_RECEIPT_KIND="$kind" \
  ROTATION_RECEIPT_ACTION="$action" \
  ROTATION_RECEIPT_VERSION="${RELEASE_VERSION:-unknown}" \
  ROTATION_RECEIPT_TIMESTAMP="$timestamp" \
  ROTATION_RECEIPT_DETAIL="$RECEIPT_DETAIL" \
    python3 - "$path" <<'PY'
from pathlib import Path
import json
import os
import sys

path = Path(sys.argv[1])
document = {
    "schema_version": 1,
    "status": "completed",
    "secret": os.environ["ROTATION_RECEIPT_KIND"],
    "action": os.environ["ROTATION_RECEIPT_ACTION"],
    "release_version": os.environ["ROTATION_RECEIPT_VERSION"],
    "completed_at_utc": os.environ["ROTATION_RECEIPT_TIMESTAMP"],
}
detail = os.environ.get("ROTATION_RECEIPT_DETAIL", "")
if detail:
    document["verification"] = detail
temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
  /bin/chmod 0600 "$path"
  log "Rotation receipt: $path"
}

complete_transaction() {
  local kind="$1" action="$2"
  write_phase verified
  write_receipt "$kind" "$action"
  ROLLBACK_REQUIRED=false
  remove_transaction
}

rollback_on_error() {
  local original_status=$?
  trap - EXIT
  if [[ -n "$BACKUP_PARTIAL" ]]; then
    /bin/rm -f -- "$BACKUP_PARTIAL"
    BACKUP_PARTIAL=""
  fi
  if [[ "$original_status" -eq 0 || "$ROLLBACK_REQUIRED" != true || "$TRANSACTION_ACTIVE" != true ]]; then
    exit "$original_status"
  fi

  set +e
  warn "rotation failed; attempting to restore the previous credential and service configuration"
  local rollback_status=0
  if [[ "$EXTERNAL_CHANGED" == true ]]; then
    case "$ROTATION_KIND" in
      postgres|postgres-app)
        # The ALTER may or may not have committed: reverse it, or confirm it never applied.
        postgres_alter_password "$NEW_SECRET" "$OLD_SECRET" ||
          postgres_can_auth "$OLD_SECRET" || rollback_status=1
        ;;
      grafana)
        # The change may or may not have applied: reverse it, or confirm it never did.
        grafana_change_password "$NEW_SECRET" "$OLD_SECRET" "$GRAFANA_URL" ||
          grafana_can_auth "$OLD_SECRET" || rollback_status=1
        ;;
      tde)
        tde_set_active_key "$OLD_TDE_KEY" || rollback_status=1
        ;;
    esac
  fi

  if [[ "$rollback_status" -eq 0 && "$ROTATION_KIND" != tde ]]; then
    restore_old_env || rollback_status=1
    if [[ "$rollback_status" -eq 0 ]]; then
      apply_configuration >/dev/null 2>&1 || rollback_status=1
    fi
  fi

  if [[ "$rollback_status" -eq 0 ]]; then
    remove_transaction || rollback_status=1
    warn "the previous credential and service configuration were restored"
  fi
  if [[ "$rollback_status" -ne 0 ]]; then
    warn "automatic rollback was incomplete; preserve $ROTATION_DIR and follow docs/SECRET-ROTATION.md before restarting services"
  fi
  exit "$original_status"
}

env_value_from_file() {
  local path="$1" key="$2"
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" python3 - "$path" "$key" <<'PY'
from chronicle_ops.envfile import read_env, value
from chronicle_ops.common import require
from pathlib import Path
import sys

path = Path(sys.argv[1])
key = sys.argv[2]
settings = read_env(path)
require(key in settings, f"expected exactly one {key} assignment in {path}")
decoded = value(settings, key)
if "\x00" in decoded or "\n" in decoded or "\r" in decoded:
    raise SystemExit(f"invalid control character in {key}")
sys.stdout.write(decoded)
PY
}

env_differs_from_saved() {
  local key current_value old_value
  for key in "$@"; do
    current_value="$(env_value_from_file .env "$key")" ||
      fail "could not read $key from the current .env"
    old_value="$(env_value_from_file "${ROTATION_DIR}/old.env" "$key")" ||
      fail "could not read $key from the saved pre-rotation .env"
    if [[ "$current_value" != "$old_value" ]]; then
      current_value=""; old_value=""
      return 0
    fi
    current_value=""; old_value=""
  done
  return 1
}

load_transaction() {
  [[ -d "$ROTATION_DIR" && ! -L "$ROTATION_DIR" ]] ||
    fail "no recoverable secret-rotation directory exists at $ROTATION_DIR"
  [[ ! -e "$UPGRADE_LOCK_DIR" && ! -L "$UPGRADE_LOCK_DIR" ]] ||
    fail "an upgrade is active or incomplete ($UPGRADE_LOCK_DIR); do not recover secrets concurrently. Run $(recovery_command "$UPGRADE_LOCK_DIR")"
  [[ ! -e "$RESTORE_LOCK_DIR" && ! -L "$RESTORE_LOCK_DIR" ]] ||
    fail "a restore is active or incomplete ($RESTORE_LOCK_DIR); do not recover secrets concurrently. Run $(recovery_command "$RESTORE_LOCK_DIR")"

  TRANSACTION_ACTIVE=true
  ROLLBACK_REQUIRED=false
  if [[ ! -e "${ROTATION_DIR}/phase" ]]; then
    TRANSACTION_PREPARED=false
    return 0
  fi

  python3 - "$ROTATION_DIR" <<'PY'
from pathlib import Path
import os
import stat
import sys

root = Path(sys.argv[1])
for name in ("old.env", "kind", "action", "phase"):
    path = root / name
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"unsafe rotation transaction file: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SystemExit(f"rotation transaction file is not private: {path}")
    if metadata.st_uid != os.geteuid():
        raise SystemExit(f"rotation transaction file has the wrong owner: {path}")
PY

  SAVED_ROTATION_KIND="$(<"${ROTATION_DIR}/kind")"
  SAVED_ROTATION_ACTION="$(<"${ROTATION_DIR}/action")"
  SAVED_ROTATION_PHASE="$(<"${ROTATION_DIR}/phase")"
  case "${SAVED_ROTATION_KIND}:${SAVED_ROTATION_ACTION}" in
    dashboard:rotate|jwt:rotate|internal-web:rotate|reviewer:rotate|metrics:rotate|postgres:rotate|postgres-app:rotate|grafana:rotate|tde:rotate) ;;
    *) fail "rotation transaction kind/action metadata is unsupported" ;;
  esac
  case "$SAVED_ROTATION_PHASE" in
    prepared|env-published|database-updated|grafana-updated|tde-metadata-ready|tde-updated|verified) ;;
    *) fail "rotation transaction phase metadata is unsupported" ;;
  esac
  if [[ "$SAVED_ROTATION_KIND" == tde && "$SAVED_ROTATION_PHASE" != prepared ]]; then
    python3 - "$ROTATION_DIR" <<'PY'
from pathlib import Path
import os
import stat
import sys

root = Path(sys.argv[1])
for name in ("old-tde-key", "new-tde-key"):
    path = root / name
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"unsafe TDE transaction file: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_uid != os.geteuid():
        raise SystemExit(f"TDE transaction file is not private and operator-owned: {path}")
PY
  fi
  TRANSACTION_PREPARED=true
}

configure_apply() {
  APPLY_MODE=services
  APPLY_SERVICES=()
  case "$1" in
    dashboard) APPLY_SERVICES=(backend web) ;;
    jwt|reviewer) APPLY_SERVICES=(backend) ;;
    metrics)
      APPLY_SERVICES=(backend)
      if [[ "${COMPOSE_FILE:-}" == *overlays/monitoring.yml* ]]; then
        APPLY_SERVICES+=(victoriametrics monitoring-config)
      fi
      ;;
    internal-web) APPLY_SERVICES=(backend web) ;;
    postgres|postgres-app)
      POSTGRES_ROTATION_KEY=POSTGRES_PASSWORD
      POSTGRES_ROTATION_ROLE="${POSTGRES_USER:-chronicle}"
      if [[ "$1" == postgres-app ]]; then
        POSTGRES_ROTATION_KEY=POSTGRES_APP_PASSWORD
        POSTGRES_ROTATION_ROLE=chronicle_app
        APPLY_SERVICES=(backend)
      else
        APPLY_MODE=full
      fi
      ;;
    grafana) APPLY_SERVICES=(grafana) ;;
    tde) ;;
    *) fail "internal error: unsupported rotation kind" ;;
  esac
}

ensure_recovery_service_running() {
  local service="$1" container_id deadline
  container_id="$(dc ps -q "$service" 2>/dev/null || true)"
  if [[ -z "$container_id" ]]; then
    log "Starting the existing $service service for recovery (without dependent services)."
    dc up -d --no-deps "$service"
  fi
  deadline=$((SECONDS + SECRET_ROTATION_WAIT_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    container_id="$(dc ps -q "$service" 2>/dev/null || true)"
    if [[ -n "$container_id" ]] &&
        [[ "$(docker inspect -f '{{.State.Running}}' "$container_id" 2>/dev/null || true)" == true ]]; then
      return 0
    fi
    sleep 1
  done
  fail "Compose service '$service' did not enter the running state within ${SECRET_ROTATION_WAIT_TIMEOUT_SECONDS}s"
}

complete_recovery() {
  local detail="$1"
  RECEIPT_DETAIL="original_action=${SAVED_ROTATION_ACTION};original_phase=${SAVED_ROTATION_PHASE};${detail}"
  complete_transaction "$SAVED_ROTATION_KIND" "recover-${RECOVERY_DIRECTION}"
  log "Interrupted ${SAVED_ROTATION_KIND} rotation recovered ${RECOVERY_DIRECTION}."
}

recover_environment_rotation() {
  local -a keys=()
  configure_apply "$SAVED_ROTATION_KIND"
  case "$SAVED_ROTATION_KIND" in
    dashboard) keys=(DASHBOARD_PASSWORD_HASH) ;;
    jwt) keys=(JWT_SECRET) ;;
    internal-web) keys=(CHRONICLE_INTERNAL_WEB_SECRET) ;;
    reviewer) keys=(CHRONICLE_REVIEWER_ACCESS_ENABLED CHRONICLE_REVIEWER_ACCESS_SECRET) ;;
    metrics) keys=(METRICS_PASSWORD) ;;
    *) fail "internal error: not an environment-only rotation" ;;
  esac

  if [[ "$RECOVERY_DIRECTION" == forward ]]; then
    env_differs_from_saved "${keys[@]}" ||
      fail "the current .env still has the saved pre-rotation value; recover --rollback, then start a new rotation"
    apply_configuration
    if [[ "$SAVED_ROTATION_KIND" == dashboard ]]; then
      end_dashboard_sessions
      complete_recovery "web_health=verified;dashboard_auth=operator_check_required"
      warn "the cleartext dashboard password is not stored; rerun ./chronicle verify --dashboard-password"
    else
      complete_recovery "service_health=verified;published_configuration=retained"
    fi
  else
    restore_old_env
    apply_configuration
    complete_recovery "service_health=verified;previous_configuration=restored"
  fi
}

recover_postgres_rotation() {
  local current_secret old_secret
  configure_apply "$SAVED_ROTATION_KIND"
  current_secret="$(env_value_from_file .env "$POSTGRES_ROTATION_KEY")" ||
    fail "could not read the current database credential"
  old_secret="$(env_value_from_file "${ROTATION_DIR}/old.env" "$POSTGRES_ROTATION_KEY")" ||
    fail "could not read the saved pre-rotation database credential"
  [[ -n "$current_secret" && -n "$old_secret" ]] || fail "PostgreSQL recovery found an empty password"
  ensure_recovery_service_running postgres

  if [[ "$RECOVERY_DIRECTION" == forward ]]; then
    [[ "$current_secret" != "$old_secret" ]] ||
      fail "the new PostgreSQL password was never published; recover --rollback, then start a new rotation"
    if postgres_can_auth "$current_secret"; then
      :
    elif postgres_can_auth "$old_secret"; then
      postgres_alter_password "$old_secret" "$current_secret"
    else
      fail "neither the current nor saved PostgreSQL password authenticates; preserve the transaction directory"
    fi
    apply_configuration
    postgres_can_auth "$current_secret" || fail "PostgreSQL rejected the forward-recovered password"
    complete_recovery "database_auth=verified;compose_stack=healthy;published_configuration=retained"
  else
    if postgres_can_auth "$old_secret"; then
      :
    elif [[ "$current_secret" != "$old_secret" ]] && postgres_can_auth "$current_secret"; then
      postgres_alter_password "$current_secret" "$old_secret"
    else
      fail "neither the saved nor current PostgreSQL password authenticates; preserve the transaction directory"
    fi
    restore_old_env
    apply_configuration
    postgres_can_auth "$old_secret" || fail "PostgreSQL rejected the restored password"
    complete_recovery "database_auth=verified;compose_stack=healthy;previous_configuration=restored"
  fi
  current_secret=""; old_secret=""
}

create_and_activate_tde_key() {
  local key_name="$1" escaped_key
  escaped_key="${key_name//\'/\'\'}"
  postgres_query "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is not set}" "
BEGIN;
SELECT pg_tde_create_key_using_database_key_provider('${escaped_key}', 'chronicle_keyring');
SELECT pg_tde_set_key_using_database_key_provider('${escaped_key}', 'chronicle_keyring');
COMMIT;
" >/dev/null
}

recover_tde_rotation() {
  local state provider
  configure_apply "$SAVED_ROTATION_KIND"
  OLD_TDE_KEY="$(<"${ROTATION_DIR}/old-tde-key")"
  NEW_TDE_KEY="$(<"${ROTATION_DIR}/new-tde-key")"
  [[ "$OLD_TDE_KEY" =~ ^[A-Za-z0-9_.-]{1,128}$ ]] || fail "saved old TDE key name is malformed"
  [[ "$NEW_TDE_KEY" =~ ^[A-Za-z0-9_.-]{1,128}$ ]] || fail "saved new TDE key name is malformed"
  [[ "$OLD_TDE_KEY" != "$NEW_TDE_KEY" ]] || fail "saved TDE key names are identical"
  ensure_recovery_service_running postgres
  state="$(tde_state)"
  provider="${state#*|}"
  [[ "$state" == *'|'* && "$provider" == chronicle_keyring ]] ||
    fail "could not verify the active chronicle_keyring TDE provider"

  if [[ "$RECOVERY_DIRECTION" == forward ]]; then
    case "${state%%|*}" in
      "$NEW_TDE_KEY") ;;
      "$OLD_TDE_KEY")
        # A prior automatic rollback may have left the new key in the keyring. Adopt it if
        # present; otherwise create and activate it as one database transaction.
        tde_set_active_key "$NEW_TDE_KEY" 2>/dev/null || create_and_activate_tde_key "$NEW_TDE_KEY"
        ;;
      *) fail "the active TDE key matches neither saved recovery key; preserve the transaction directory" ;;
    esac
    [[ "$(tde_state)" == "${NEW_TDE_KEY}|chronicle_keyring" ]] ||
      fail "forward recovery did not activate the saved new TDE key"
    copy_and_verify_live_keyring
    verify_tde_encrypted_tables
    complete_recovery "tde_provider=chronicle_keyring;encrypted_tables=verified;keyring_backup=verified"
  else
    case "${state%%|*}" in
      "$OLD_TDE_KEY") ;;
      "$NEW_TDE_KEY") tde_set_active_key "$OLD_TDE_KEY" ;;
      *) fail "the active TDE key matches neither saved recovery key; preserve the transaction directory" ;;
    esac
    [[ "$(tde_state)" == "${OLD_TDE_KEY}|chronicle_keyring" ]] ||
      fail "rollback recovery did not reactivate the saved old TDE key"
    copy_and_verify_live_keyring
    verify_tde_encrypted_tables
    complete_recovery "tde_provider=chronicle_keyring;encrypted_tables=verified;keyring_backup=verified;previous_key=reactivated"
  fi
  OLD_TDE_KEY=""; NEW_TDE_KEY=""
}

recover_transaction() {
  load_transaction
  if [[ "$TRANSACTION_PREPARED" != true ]]; then
    [[ "$RECOVERY_DIRECTION" == rollback ]] ||
      fail "the crash occurred before transaction preparation completed; only recover --rollback is safe"
    confirm "Confirm no secret-rotation process remains, then remove this pre-publication lock?"
    remove_transaction
    log "Removed an incomplete pre-publication rotation lock; .env was never changed by that transaction."
    return 0
  fi

  if [[ "$SAVED_ROTATION_KIND" == tde && "$SAVED_ROTATION_PHASE" == prepared ]]; then
    [[ "$RECOVERY_DIRECTION" == rollback ]] ||
      fail "TDE key activation had not reached its durable metadata checkpoint; only recover --rollback is safe"
    confirm "Confirm no secret-rotation process remains, then remove this pre-activation TDE lock?"
    remove_transaction
    log "Removed an interrupted TDE rotation before its durable key-activation checkpoint. The active database key was not changed by that transaction."
    return 0
  fi

  confirm "Confirm no secret-rotation process remains and recover ${SAVED_ROTATION_KIND} ${RECOVERY_DIRECTION}?"
  case "$SAVED_ROTATION_KIND" in
    dashboard|jwt|internal-web|reviewer|metrics) recover_environment_rotation ;;
    postgres|postgres-app) recover_postgres_rotation ;;
    grafana) recover_grafana_rotation ;;
    tde) recover_tde_rotation ;;
    *) fail "internal error: unsupported recovery kind" ;;
  esac
}

# The backend refuses every token issued at or before this cutoff (the one restore writes).
# Runs only after the new hash is live, so the old password cannot mint a session behind it.
end_dashboard_sessions() {
  postgres_query "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is not set}" "$(PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="$SCRIPT_DIR" python3 -c 'from chronicle_ops.dump import SESSION_CUTOFF_SQL; print(SESSION_CUTOFF_SQL)')" \
    >/dev/null || fail "could not end dashboard sessions issued under the old password"
}

rotate_dashboard() {
  case "${COMPOSE_FILE:-}" in
    *mode-*-internal.yml*|*mode-local-https.yml*) ;;
    *) fail "the dashboard password exists only in an internal-dashboard mode" ;;
  esac
  service_running backend
  service_running web
  DASHBOARD_URL="$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" python3 -c \
    'from chronicle_ops.common import dashboard_origin; from chronicle_ops.envfile import read_env; print(dashboard_origin(read_env(".env")))')"
  [[ "$DASHBOARD_URL" == https://* ]] || fail "dashboard rotation requires an HTTPS management origin"
  DASHBOARD_CA="$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" python3 -c \
    'import sys; from chronicle_ops.common import dashboard_ca; print(dashboard_ca(sys.argv[1]))' "$STATE_ROOT/tls")"
  local password confirmation hash image
  printf 'Choose a new dashboard password (at least 16 characters). It is read silently,\n'
  printf 'sent to the digest-pinned Caddy image over stdin, and never printed.\n'
  read -rsp 'New dashboard password: ' password; printf '\n'
  read -rsp 'Confirm dashboard password: ' confirmation; printf '\n'
  [[ "$password" == "$confirmation" ]] || fail "dashboard passwords do not match"
  [[ ${#password} -ge 16 ]] || fail "dashboard password must be at least 16 characters"
  image="${CADDY_IMAGE:-}"
  case "$image" in
    ""|__CHRONICLE_*)
      image='caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d'
      ;;
  esac
  hash="$(printf '%s\n' "$password" | docker run --rm -i --network none --read-only \
    --entrypoint caddy "$image" hash-password | tr -d '\r\n')"
  [[ "$hash" == \$2* ]] || fail "Caddy did not return a bcrypt password hash"

  configure_apply dashboard
  OLD_SECRET="${DASHBOARD_PASSWORD_HASH:-}"
  NEW_SECRET="$hash"
  begin_transaction dashboard rotate
  env_update DASHBOARD_PASSWORD_HASH "$hash"
  write_phase env-published
  apply_configuration
  end_dashboard_sessions

  # Check the source ACL before submitting the new password to the app login.
  local code deadline
  code="$(curl -s --cacert "$DASHBOARD_CA" --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 15 \
    "${DASHBOARD_URL}/chronicle/api/web/study")"
  if [[ "$code" == 403 && "${INTERNAL_BIND:-127.0.0.1}" != 127.* && "${INTERNAL_BIND:-}" != ::1 && "${INTERNAL_BIND:-}" != '[::1]' ]]; then
    RECEIPT_DETAIL="dashboard_source=denied;dashboard_auth=operator_check_required"
    warn "host is outside the researcher ACL; verify the new password from an allowed researcher browser at $DASHBOARD_URL/chronicle/"
  else
    [[ "$code" == 401 ]] || fail "dashboard API must require an app session (HTTP $code)"
    deadline=$((SECONDS + 75))
    while :; do
      code="$(dashboard_login_code "$password" "${DASHBOARD_URL}/chronicle/v3/auth/dashboard-login")"
      [[ "$code" == 429 && $SECONDS -lt $deadline ]] || break
      sleep 15
    done
    [[ "$code" == 200 ]] || fail "new dashboard credential did not establish a backend session (HTTP $code)"
    RECEIPT_DETAIL="dashboard_application_session=verified"
  fi
  complete_transaction dashboard rotate
  password=""; confirmation=""; hash=""; NEW_SECRET=""; OLD_SECRET=""
  log "Dashboard password rotated; earlier dashboard sessions must sign in again. Acceptance: $RECEIPT_DETAIL"
}

rotate_jwt() {
  local now expires_at
  service_running backend
  now="$(date +%s)"
  [[ "${DASHBOARD_SESSION_MINUTES:-480}" =~ ^[1-9][0-9]{0,4}$ ]] || fail "DASHBOARD_SESSION_MINUTES must be whole minutes"
  if [[ "$REVOKE_JWT_SESSIONS" == true ]]; then
    confirm "Rotate JWT signing and invalidate every active dashboard session?"
    expires_at=0
  else
    if [[ -n "${JWT_SECRET_PREVIOUS:-}" && "${JWT_SECRET_PREVIOUS_EXPIRES_AT:-0}" =~ ^[0-9]{1,11}$ ]] &&
        (( JWT_SECRET_PREVIOUS_EXPIRES_AT > now )); then
      fail "the previous JWT overlap is still active; wait for it to expire or use --revoke-sessions"
    fi
    confirm "Rotate JWT signing while keeping active dashboard sessions until their configured expiry?"
    expires_at=$((now + ${DASHBOARD_SESSION_MINUTES:-480} * 60))
  fi
  configure_apply jwt
  OLD_SECRET="${JWT_SECRET:?JWT_SECRET is not set}"
  NEW_SECRET="$(openssl rand -hex 32)"
  begin_transaction jwt rotate
  if [[ "$REVOKE_JWT_SESSIONS" == true ]]; then
    env_update JWT_SECRET "$NEW_SECRET" JWT_SECRET_PREVIOUS "" JWT_SECRET_PREVIOUS_EXPIRES_AT 0
  else
    env_update JWT_SECRET "$NEW_SECRET" JWT_SECRET_PREVIOUS "$OLD_SECRET" JWT_SECRET_PREVIOUS_EXPIRES_AT "$expires_at"
  fi
  write_phase env-published
  apply_configuration
  RECEIPT_DETAIL="backend_health=verified;previous_key_expires_at=$expires_at"
  complete_transaction jwt rotate
  NEW_SECRET=""; OLD_SECRET=""
  if [[ "$REVOKE_JWT_SESSIONS" == true ]]; then
    log "JWT signing secret rotated. Existing dashboard sessions must sign in again."
  else
    log "JWT signing secret rotated. Existing dashboard sessions retain their configured expiry."
  fi
}

rotate_internal_web() {
  service_running backend
  service_running web
  confirm "Rotate the proxy-to-backend internal web secret and recreate both services?"
  configure_apply internal-web
  OLD_SECRET="${CHRONICLE_INTERNAL_WEB_SECRET:?CHRONICLE_INTERNAL_WEB_SECRET is not set}"
  NEW_SECRET="$(openssl rand -hex 32)"
  begin_transaction internal-web rotate
  env_update CHRONICLE_INTERNAL_WEB_SECRET "$NEW_SECRET"
  write_phase env-published
  apply_configuration
  RECEIPT_DETAIL="backend_health=verified;web_health=verified"
  complete_transaction internal-web rotate
  NEW_SECRET=""; OLD_SECRET=""
  log "Internal web secret rotated; Caddy and the backend are synchronized."
}

rotate_reviewer() {
  service_running backend
  service_running postgres
  [[ "${CHRONICLE_REVIEWER_STUDY_ID:-}" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] ||
    fail "set CHRONICLE_REVIEWER_STUDY_ID to the synthetic reviewer study UUID first"
  [[ "${CHRONICLE_REVIEWER_PARTICIPANT_ID:-}" =~ ^[a-zA-Z0-9_.-]{1,255}$ ]] ||
    fail "set CHRONICLE_REVIEWER_PARTICIPANT_ID to a non-PII Chronicle participant ID first"
  local scope_state
  source "$SCRIPT_DIR/doctor.sh"
  scope_state="$(reviewer_scope_state "$CHRONICLE_REVIEWER_STUDY_ID" "$CHRONICLE_REVIEWER_PARTICIPANT_ID")" || fail "could not verify the configured Play reviewer scope"
  [[ "$scope_state" == ok ]] ||
    fail "configured Play reviewer scope is unavailable (${scope_state:-query-failed}); create or reactivate it in the dashboard first"
  confirm "Generate a new Play reviewer credential, invalidate the current one, and recreate the backend?"
  configure_apply reviewer
  OLD_SECRET="${CHRONICLE_REVIEWER_ACCESS_SECRET:-}"
  NEW_SECRET="$(openssl rand -hex 32)"
  begin_transaction reviewer rotate
  env_update CHRONICLE_REVIEWER_ACCESS_ENABLED true CHRONICLE_REVIEWER_ACCESS_SECRET "$NEW_SECRET"
  write_phase env-published
  apply_configuration
  RECEIPT_DETAIL="backend_health=verified;reviewer_scope=${CHRONICLE_REVIEWER_STUDY_ID}"
  complete_transaction reviewer rotate
  NEW_SECRET=""; OLD_SECRET=""
  log "Play reviewer credential rotated. Copy it from .env in a trusted editor directly into Play Console."
}

rotate_metrics() {
  service_running backend
  local monitoring_enabled=false
  configure_apply metrics
  if ((${#APPLY_SERVICES[@]} > 1)); then
    monitoring_enabled=true
    service_running victoriametrics
    service_running grafana
  fi
  if [[ "$monitoring_enabled" == true ]]; then
    confirm "Rotate the backend metrics credential and refresh the monitoring scraper?"
  else
    confirm "Rotate the backend metrics credential and recreate the backend?"
  fi
  OLD_SECRET="${METRICS_PASSWORD:?METRICS_PASSWORD is not set}"
  NEW_SECRET="$(openssl rand -hex 32)"
  begin_transaction metrics rotate
  env_update METRICS_PASSWORD "$NEW_SECRET"
  write_phase env-published
  apply_configuration
  RECEIPT_DETAIL="backend_health=verified"
  [[ "$monitoring_enabled" != true ]] || RECEIPT_DETAIL="${RECEIPT_DETAIL};backend_scrape_target=verified"
  complete_transaction metrics rotate
  NEW_SECRET=""; OLD_SECRET=""
  if [[ "$monitoring_enabled" == true ]]; then
    log "Metrics credential rotated and the monitoring backend target is healthy."
  else
    log "Metrics credential rotated. Update any separately configured scraper from the mode-0600 .env file."
  fi
}

rotate_postgres() {
  service_running postgres
  service_running backend
  confirm "Rotate the $ROTATION_KIND database credential and recreate its dependent services?"
  configure_apply "$ROTATION_KIND"
  OLD_SECRET="${!POSTGRES_ROTATION_KEY}"
  postgres_can_auth "$OLD_SECRET" || fail "the current .env password cannot authenticate to PostgreSQL"
  NEW_SECRET="$(openssl rand -hex 32)"
  begin_transaction "$ROTATION_KIND" rotate
  env_update "$POSTGRES_ROTATION_KEY" "$NEW_SECRET"
  write_phase env-published
  # As for TDE: a lost acknowledgement can hide a committed ALTER. Mark it begun first so a
  # failure reverses it, or preserves the transaction with NEW_SECRET still in .env.
  EXTERNAL_CHANGED=true
  postgres_alter_password "$OLD_SECRET" "$NEW_SECRET"
  write_phase database-updated
  apply_configuration
  postgres_can_auth "$NEW_SECRET" || fail "PostgreSQL rejected the rotated password after restart"
  RECEIPT_DETAIL="database_auth=verified;compose_stack=healthy"
  complete_transaction "$ROTATION_KIND" rotate
  printf -v "$POSTGRES_ROTATION_KEY" '%s' "$NEW_SECRET"
  NEW_SECRET=""; OLD_SECRET=""
  log "PostgreSQL credential rotated and dependent services returned healthy."
}


rotate_tde() {
  [[ "${ENABLE_ENCRYPTION:-true}" == true ]] || fail "TDE encryption is disabled"
  [[ "${COMPOSE_FILE:-}" == *overlays/backups.yml* ]] ||
    fail "TDE rotation requires the supported backups overlay"
  service_running postgres
  confirm "Take a fresh SQL backup and rotate the pg_tde principal key online?"
  begin_transaction tde rotate
  take_pre_rotation_backup
  local state provider
  POSTGRES_PASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is not set}"
  state="$(tde_state)"
  OLD_TDE_KEY="${state%%|*}"
  provider="${state#*|}"
  [[ -n "$OLD_TDE_KEY" && "$state" == *'|'* ]] || fail "could not determine the active TDE key"
  [[ "$provider" == chronicle_keyring ]] ||
    fail "unexpected TDE provider '$provider' (expected chronicle_keyring)"
  NEW_TDE_KEY="chronicle_key_$(date -u +%Y%m%dT%H%M%SZ)_${RANDOM}"
  # Publish and fsync both candidate names and then a durable phase marker before changing
  # PostgreSQL. Thus `prepared` always means activation was never attempted, while
  # `tde-metadata-ready` is sufficient to recover either side of the database transaction.
  write_tde_recovery_metadata
  write_phase tde-metadata-ready
  # A connection loss can make the result of COMMIT ambiguous to the caller. Mark the
  # external operation as begun before invoking it so the EXIT trap either reactivates the
  # old key or preserves the durable transaction for explicit recovery.
  EXTERNAL_CHANGED=true
  create_and_activate_tde_key "$NEW_TDE_KEY"
  write_phase tde-updated
  state="$(tde_state)"
  [[ "$state" == "${NEW_TDE_KEY}|chronicle_keyring" ]] ||
    fail "TDE key verification did not report the newly activated key"
  copy_and_verify_live_keyring
  verify_tde_encrypted_tables
  RECEIPT_DETAIL="${RECEIPT_DETAIL};tde_provider=chronicle_keyring;encrypted_tables=verified;keyring_backup=verified"
  complete_transaction tde rotate
  log "TDE principal key rotated after a verified fresh SQL backup."
}

# Tests source this file for its functions; only a direct run rotates anything.
[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

ASSUME_YES=false
VALIDATE_ONLY=false
REVOKE_JWT_SESSIONS=false
RECOVERY_DIRECTION=""
POSITIONAL=()
while (($#)); do
  case "$1" in
    --yes) ASSUME_YES=true ;;
    --validate) VALIDATE_ONLY=true ;;
    --revoke-sessions) REVOKE_JWT_SESSIONS=true ;;
    --forward|--rollback)
      [[ -z "$RECOVERY_DIRECTION" ]] || { usage >&2; fail "choose only one recovery direction"; }
      RECOVERY_DIRECTION="${1#--}"
      ;;
    -h|--help) usage; exit 0 ;;
    --*) usage >&2; fail "unknown option: $1" ;;
    *) POSITIONAL+=("$1") ;;
  esac
  shift
done

[[ ${#POSITIONAL[@]} -eq 1 ]] || {
  usage >&2
  exit 2
}
ROTATION_KIND="${POSITIONAL[0]}"
[[ "$REVOKE_JWT_SESSIONS" != true || "$ROTATION_KIND" == jwt ]] || fail "--revoke-sessions is valid only with jwt"
ROTATION_ACTION=rotate
if [[ "$ROTATION_KIND" == recover ]]; then
  [[ -n "$RECOVERY_DIRECTION" ]] || {
    usage >&2
    fail "recover requires exactly one of --forward or --rollback"
  }
  ROTATION_ACTION="$RECOVERY_DIRECTION"
elif [[ -n "$RECOVERY_DIRECTION" ]]; then
  usage >&2
  fail "--forward and --rollback are valid only with recover"
fi

case "$ROTATION_KIND" in
  recover) ROTATION_HANDLER=recover_transaction ;;
  dashboard) ROTATION_HANDLER=rotate_dashboard ;;
  jwt) ROTATION_HANDLER=rotate_jwt ;;
  internal-web) ROTATION_HANDLER=rotate_internal_web ;;
  reviewer) ROTATION_HANDLER=rotate_reviewer ;;
  metrics) ROTATION_HANDLER=rotate_metrics ;;
  postgres|postgres-app) ROTATION_HANDLER=rotate_postgres ;;
  grafana) ROTATION_HANDLER=rotate_grafana ;;
  tde) ROTATION_HANDLER=rotate_tde ;;
  *) usage >&2; fail "unknown secret: $ROTATION_KIND" ;;
esac

if [[ "$VALIDATE_ONLY" == true ]]; then
  log "Accepted rotation command: $ROTATION_KIND $ROTATION_ACTION"
  exit 0
fi

for command in docker python3 openssl curl date; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done
if ! PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" python3 -c \
    'import os, sys; from chronicle_ops.common import holds_operation_lock; sys.exit(0 if holds_operation_lock(os.environ.get("CHRONICLE_OPS_STATE", ".")) else 1)'; then
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" exec python3 -m chronicle_ops operation-lock -- "$SCRIPT_DIR/rotate-secret.sh" "${ROTATION_ARGS[@]}"
fi
docker compose version >/dev/null 2>&1 || fail "the Docker Compose plugin is unavailable"
[[ -f .env && ! -L .env ]] || fail ".env must be a regular file; run ./chronicle setup first"
env_mode="$(stat -c '%a' .env 2>/dev/null || stat -f '%Lp' .env 2>/dev/null || true)"
[[ "$env_mode" == 600 ]] ||
  fail ".env is mode ${env_mode:-unknown}; run chmod 600 .env before rotating credentials"

# .env is the deployment authority. Load values for shell decisions without exporting the
# entire secret set into docker, curl, Python, or any other child process.
# shellcheck disable=SC1091
. ./.env
for secret_key in "${SECRET_ENV_KEYS[@]}"; do
  export -n "${secret_key?}" 2>/dev/null || true
done

PROJECT="${COMPOSE_PROJECT_NAME:-chronicle-selfhost}"
STATE_TEXT="${CHRONICLE_STATE_DIR:-.}"
if [[ "$STATE_TEXT" == /* ]]; then
  STATE_ROOT="$STATE_TEXT"
else
  STATE_ROOT="${SCRIPT_DIR}/${STATE_TEXT#./}"
fi
STATE_ROOT="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$STATE_ROOT")"
[[ -d "$STATE_ROOT" ]] || fail "CHRONICLE_STATE_DIR does not exist: $STATE_ROOT"
CHRONICLE_OPS_STATE="$STATE_ROOT" CHRONICLE_OPS_PROJECT="$PROJECT" \
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$SCRIPT_DIR" python3 -m chronicle_ops owner-check ||
  fail "secret rotation must run from the active selfhost directory"
: "${SECRET_ROTATION_WAIT_TIMEOUT_SECONDS:=300}"
[[ "$SECRET_ROTATION_WAIT_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] ||
  fail "SECRET_ROTATION_WAIT_TIMEOUT_SECONDS must be a positive integer"
(( SECRET_ROTATION_WAIT_TIMEOUT_SECONDS <= 3600 )) ||
  fail "SECRET_ROTATION_WAIT_TIMEOUT_SECONDS must not exceed 3600"

ROTATION_DIR="${STATE_ROOT}/.chronicle-secret-rotation"
UPGRADE_LOCK_DIR="${STATE_ROOT}/.chronicle-upgrade.lock"
RESTORE_LOCK_DIR="${STATE_ROOT}/.chronicle-restore.lock"
RECEIPT_DIR="${STATE_ROOT}/operator-receipts/secret-rotations"
TRANSACTION_ACTIVE=false
ROLLBACK_REQUIRED=false
EXTERNAL_CHANGED=false
APPLY_MODE=services
APPLY_SERVICES=()
OLD_SECRET=""
NEW_SECRET=""
OLD_TDE_KEY=""
NEW_TDE_KEY=""
RECEIPT_DETAIL=""
BACKUP_PARTIAL=""
SAVED_ROTATION_KIND=""
SAVED_ROTATION_ACTION=""
SAVED_ROTATION_PHASE=""
TRANSACTION_PREPARED=false
GRAFANA_URL=""
DASHBOARD_URL=""
DASHBOARD_CA=""

trap rollback_on_error EXIT
source "$SCRIPT_DIR/rotation-http.sh"
"$ROTATION_HANDLER"
