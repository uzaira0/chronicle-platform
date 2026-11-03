#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bundle=${1:?usage: restore-drill.sh BACKUP_BUNDLE}
bundle=$(realpath "$bundle")
secrets_dir=${CHRONICLE_SECRETS_DIR:?Set CHRONICLE_SECRETS_DIR}
# Must match docker/hetzner/compose.yml — the runtime moved to Percona 18.6.1-4 (see
# toolchain-manifest.yaml postgres.image); drilling on the old 17 image proves nothing
# about the deployed cluster. The expected major is asserted against the running server below.
image=${CHRONICLE_PERCONA_IMAGE:-localhost/chronicle-percona:18.6.1-4-hardened}
expected_pg_major=${CHRONICLE_PG_EXPECTED_MAJOR:-18}
test -f "$bundle/complete"
(cd "$bundle" && sha256sum -c SHA256SUMS)

stamp=$(date -u +%Y%m%dT%H%M%SZ)
container="chronicle-restore-drill-$stamp-$$"
data_volume="$container-data"
keyring_volume="$container-keyring"

cleanup() {
  podman rm -f "$container" >/dev/null 2>&1 || true
  podman volume rm "$data_volume" "$keyring_volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

podman volume create "$data_volume" >/dev/null
podman volume create "$keyring_volume" >/dev/null
podman run -d \
  --name "$container" \
  --network none \
  --read-only \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add FOWNER \
  --cap-add SETGID \
  --cap-add SETUID \
  --memory 2g \
  --pids-limit 512 \
  --user 0:0 \
  --env POSTGRES_USER=chronicle \
  --env POSTGRES_DB=chronicle \
  --env POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password \
  --env PGDATA=/data/db \
  --env PG_TDE_KEY_PROVIDER=file \
  --volume "$data_volume:/data/db" \
  --volume "$keyring_volume:/var/lib/postgresql/tde-keyring" \
  --volume "$script_dir/../init-db-roles.sql:/docker-entrypoint-initdb.d/10-init-db-roles.sql:ro" \
  --volume "$script_dir/postgres/set-app-role-password.sh:/docker-entrypoint-initdb.d/15-set-app-role-password.sh:ro" \
  --volume "$script_dir/../../selfhost/database-app-role.sql:/etc/chronicle/database-app-role.sql:ro" \
  --volume "$script_dir/../init-db-encryption.sh:/docker-entrypoint-initdb.d/20-init-db-encryption.sh:ro" \
  --volume "$secrets_dir/chronicle-postgres-password:/run/chronicle-source/postgres_password:ro" \
  --volume "$secrets_dir/chronicle-postgres-app-password:/run/chronicle-source/postgres_app_password:ro" \
  --tmpfs /tmp:noexec,nosuid,nodev,size=128m \
  --tmpfs /run/postgresql:noexec,nosuid,nodev,size=16m,mode=0770 \
  --tmpfs /run/secrets:noexec,nosuid,nodev,size=1m,mode=0700 \
  --entrypoint /bin/bash \
  "$image" -euc '
    chown 26:26 /run/postgresql /run/secrets
    install -o 26 -g 26 -m 0600 /run/chronicle-source/postgres_password /run/secrets/postgres_password
    install -o 26 -g 26 -m 0600 /run/chronicle-source/postgres_app_password /run/secrets/postgres_app_password
    mkdir -p /var/lib/postgresql/tde-keyring
    chown 26:26 /var/lib/postgresql/tde-keyring
    exec /entrypoint.sh "$@"
  ' -- \
    -c password_encryption=scram-sha-256 \
    -c shared_preload_libraries=pg_tde,pgaudit \
    -c default_table_access_method=tde_heap \
    -c max_parallel_workers_per_gather=0 >/dev/null

status=
for _ in $(seq 1 90); do
  status=$(podman inspect --format '{{.State.Status}}' "$container" 2>/dev/null || true)
  if [[ "$status" == running ]] && podman exec "$container" sh -euc '
    export PGPASSWORD="$(cat /run/secrets/postgres_password)"
    pg_isready -h 127.0.0.1 -U chronicle -d chronicle >/dev/null
  '; then
    break
  fi
  sleep 2
done
if [[ "$status" != running ]]; then
  podman logs "$container" >&2
  exit 1
fi

actual_pg_major=$(podman exec "$container" sh -euc '
  export PGPASSWORD="$(cat /run/secrets/postgres_password)"
  exec psql -h 127.0.0.1 -U chronicle -d chronicle -X -q -At -c "SHOW server_version_num"
')
if [[ "$((actual_pg_major / 10000))" != "$expected_pg_major" ]]; then
  echo "FATAL: drill image $image runs PostgreSQL server_version_num=$actual_pg_major, expected major $expected_pg_major" >&2
  exit 1
fi

podman exec -i "$container" sh -euc '
  export PGPASSWORD="$(cat /run/secrets/postgres_password)"
  exec pg_restore -h 127.0.0.1 -U chronicle -d chronicle \
    --exit-on-error --no-owner --no-privileges
' < "$bundle/chronicle.dump"

actual=$(podman exec -i "$container" sh -euc '
  export PGPASSWORD="$(cat /run/secrets/postgres_password)"
  psql -h 127.0.0.1 -U chronicle -d chronicle -X -v ON_ERROR_STOP=1 \
    -f /docker-entrypoint-initdb.d/10-init-db-roles.sql >/dev/null
  exec psql -h 127.0.0.1 -U chronicle -d chronicle -X -q -v ON_ERROR_STOP=1 -At
' <<'SQL'
DO $$
DECLARE item record;
BEGIN
  FOR item IN
    SELECT format('%I.%I', n.nspname, c.relname) AS relation_name
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_am a ON a.oid = c.relam
    WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.amname <> 'tde_heap'
  LOOP
    EXECUTE format('ALTER TABLE %s SET ACCESS METHOD tde_heap', item.relation_name);
  END LOOP;
END
$$;

SELECT jsonb_build_object(
  'public_regular_tables', (
    SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
  ),
  'tde_heap_tables', (
    SELECT count(*) FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_am a ON a.oid = c.relam
    WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.amname = 'tde_heap'
  ),
  'rls_tables', (
    SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relrowsecurity
  ),
  'participants', (SELECT count(*) FROM study_participants),
  'devices', (SELECT count(*) FROM devices),
  'sensor_data', (SELECT count(*) FROM sensor_data),
  'android_sensor_data', (SELECT count(*) FROM android_sensor_data)
);
SELECT pg_tde_verify_key();
SQL
)
actual=$(head -n 1 <<<"$actual")
expected=$(<"$bundle/oracle.json")
jq -e -n --argjson expected "$expected" --argjson actual "$actual" '
  [
    "public_regular_tables",
    "tde_heap_tables",
    "rls_tables",
    "participants",
    "devices",
    "sensor_data",
    "android_sensor_data"
  ] | all(.[]; $expected[.] == $actual[.])
' >/dev/null

echo "isolated Chronicle restore drill passed: $actual"
