#!/usr/bin/env bash
set -euo pipefail

backend_tag=${CHRONICLE_BACKEND_TAG:?Set CHRONICLE_BACKEND_TAG}
secrets_dir=${CHRONICLE_SECRETS_DIR:?Set CHRONICLE_SECRETS_DIR}
tls_dir=${CHRONICLE_TLS_DIR:?Set CHRONICLE_TLS_DIR}
image="localhost/chronicle-backend:${backend_tag}"
network=chronicle-next_chronicle-db
container_name=chronicle-next-migrate

[[ -f "$secrets_dir/chronicle-postgres-password" ]]
[[ -f "$tls_dir/ca.crt" ]]
podman image exists "$image"
podman network exists "$network"
[[ "$(podman inspect chronicle-next_postgres_1 --format '{{.State.Health.Status}}')" == healthy ]]
if podman container exists chronicle-next_backend_1; then
  echo "backend container must be removed before owner migration and restore reconciliation" >&2
  exit 1
fi
if podman container exists "$container_name"; then
  echo "migration container already exists: $container_name" >&2
  exit 1
fi

podman run --rm --name "$container_name" \
  --read-only \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add SETGID \
  --cap-add SETUID \
  --user 0:0 \
  --memory 512m \
  --pids-limit 128 \
  --network "$network" \
  --ip 10.89.41.4 \
  --env POSTGRES_MIGRATION_JDBC_URL='jdbc:postgresql://postgres:5432/chronicle?sslmode=verify-full&sslrootcert=/app/ssl/ca.crt' \
  --env POSTGRES_MIGRATION_USER=chronicle \
  --env POSTGRES_MIGRATION_PASSWORD_FILE=/run/migration/postgres_password \
  --volume "$secrets_dir/chronicle-postgres-password:/run/chronicle-source/postgres_password:ro" \
  --volume "$tls_dir/ca.crt:/app/ssl/ca.crt:ro" \
  --tmpfs /tmp:noexec,nosuid,nodev,size=64m \
  --tmpfs /run/migration:noexec,nosuid,nodev,size=1m,mode=0700 \
  --entrypoint /bin/sh \
  "$image" -euc '
    chown chronicle:chronicle /run/migration
    umask 077
    dd if=/run/chronicle-source/postgres_password \
      of=/run/migration/postgres_password 2>/dev/null
    chown chronicle:chronicle /run/migration/postgres_password
    exec su-exec chronicle java -Xms64m -Xmx256m -cp "/server/lib/*" \
      com.openlattice.chronicle.upgrades.FlywayMigrationCommand
  '
