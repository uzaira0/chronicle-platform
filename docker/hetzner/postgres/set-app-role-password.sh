#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${POSTGRES_APP_PASSWORD:-}" ]]; then
  POSTGRES_APP_PASSWORD=$(cat /run/secrets/postgres_app_password)
fi
test -n "$POSTGRES_APP_PASSWORD"
export POSTGRES_APP_PASSWORD

psql \
  --username "${POSTGRES_USER:-chronicle}" \
  --dbname "${POSTGRES_DB:-chronicle}" \
  --set ON_ERROR_STOP=1 --quiet --file /etc/chronicle/database-app-role.sql

unset POSTGRES_APP_PASSWORD
