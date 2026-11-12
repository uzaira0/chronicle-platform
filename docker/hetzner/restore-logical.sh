#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bundle=${1:?usage: restore-logical.sh BACKUP_BUNDLE}
bundle=$(realpath "$bundle")
test -f "$bundle/complete"
(cd "$bundle" && sha256sum -c SHA256SUMS)

compose=(podman compose -f "$script_dir/compose.yml")
"${compose[@]}" stop traefik backend >/dev/null 2>&1 || true
"${compose[@]}" up -d postgres

for _ in $(seq 1 60); do
  postgres_cid=$(podman ps -a \
    --filter label=io.podman.compose.project=chronicle-next \
    --filter label=io.podman.compose.service=postgres \
    --format '{{.ID}}' | sed -n 1p)
  status=$(podman inspect --format '{{.State.Health.Status}}' "$postgres_cid" 2>/dev/null || true)
  [[ "$status" == healthy ]] && break
  sleep 2
done
if [[ "${status:-}" != healthy ]]; then
  "${compose[@]}" logs postgres >&2
  exit 1
fi

table_count=$("${compose[@]}" exec -T postgres sh -euc '
  export PGPASSWORD="$(cat /run/secrets/postgres_password)"
  exec psql -h 127.0.0.1 -U chronicle -d chronicle -X -At
' <<'SQL'
SELECT count(*)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p')
  AND NOT EXISTS (
    SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype = 'e'
  );
SQL
)
if [[ "$table_count" != 0 ]]; then
  echo "restore target is not fresh ($table_count application tables); refusing destructive merge" >&2
  exit 1
fi

"${compose[@]}" exec -T postgres sh -euc '
  export PGPASSWORD="$(cat /run/secrets/postgres_password)"
  exec pg_restore -h 127.0.0.1 -U chronicle -d chronicle \
    --exit-on-error --no-owner --no-privileges
' < "$bundle/chronicle.dump"

"${compose[@]}" exec -T postgres sh -euc '
  export PGPASSWORD="$(cat /run/secrets/postgres_password)"
  psql -h 127.0.0.1 -U chronicle -d chronicle -X -v ON_ERROR_STOP=1 \
    -f /docker-entrypoint-initdb.d/10-init-db-roles.sql
  exec psql -h 127.0.0.1 -U chronicle -d chronicle -X -v ON_ERROR_STOP=1
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

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_am a ON a.oid = c.relam
    WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.amname <> 'tde_heap'
  ) THEN
    RAISE EXCEPTION 'restored application tables remain outside tde_heap';
  END IF;
END
$$;
SQL

"${compose[@]}" up -d backend crowdsec traefik
echo "Chronicle restore completed from $bundle"
