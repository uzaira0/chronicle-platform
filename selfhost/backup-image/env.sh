#!/usr/bin/env bash
# Upstream prodrigestivill script; the only Chronicle change is the BACKUP_KEEP_* check (number or all).
# Warnings reflect upstream syntax and sourced variables.
# shellcheck disable=SC2034,SC2057,SC2155,SC2166,SC2307
# Pre-validate the environment
if [ "${POSTGRES_DB}" = "**None**" -a "${POSTGRES_DB_FILE}" = "**None**" ]; then
  echo "You need to set the POSTGRES_DB or POSTGRES_DB_FILE environment variable."
  exit 1
fi

if [ "${POSTGRES_HOST}" = "**None**" ]; then
  if [ -n "${POSTGRES_PORT_5432_TCP_ADDR}" ]; then
    POSTGRES_HOST=${POSTGRES_PORT_5432_TCP_ADDR}
    POSTGRES_PORT=${POSTGRES_PORT_5432_TCP_PORT}
  else
    echo "You need to set the POSTGRES_HOST environment variable."
    exit 1
  fi
fi

if [ "${POSTGRES_USER}" = "**None**" -a "${POSTGRES_USER_FILE}" = "**None**" ]; then
  echo "You need to set the POSTGRES_USER or POSTGRES_USER_FILE environment variable."
  exit 1
fi

if [ "${POSTGRES_PASSWORD}" = "**None**" -a "${POSTGRES_PASSWORD_FILE}" = "**None**" -a "${POSTGRES_PASSFILE_STORE}" = "**None**" ]; then
  echo "You need to set the POSTGRES_PASSWORD or POSTGRES_PASSWORD_FILE or POSTGRES_PASSFILE_STORE environment variable or link to a container named POSTGRES."
  exit 1
fi

#Process vars
if [ "${POSTGRES_DB_FILE}" = "**None**" ]; then
  POSTGRES_DBS=$(echo "${POSTGRES_DB}" | tr , " ")
elif [ -r "${POSTGRES_DB_FILE}" ]; then
  POSTGRES_DBS=$(cat "${POSTGRES_DB_FILE}")
else
  echo "Missing POSTGRES_DB_FILE file."
  exit 1
fi
if [ "${POSTGRES_USER_FILE}" = "**None**" ]; then
  export PGUSER="${POSTGRES_USER}"
elif [ -r "${POSTGRES_USER_FILE}" ]; then
  export PGUSER=$(cat "${POSTGRES_USER_FILE}")
else
  echo "Missing POSTGRES_USER_FILE file."
  exit 1
fi
if [ "${POSTGRES_PASSWORD_FILE}" = "**None**" -a "${POSTGRES_PASSFILE_STORE}" = "**None**" ]; then
  export PGPASSWORD="${POSTGRES_PASSWORD}"
elif [ -r "${POSTGRES_PASSWORD_FILE}" ]; then
  export PGPASSWORD=$(cat "${POSTGRES_PASSWORD_FILE}")
elif [ -r "${POSTGRES_PASSFILE_STORE}" ]; then
  export PGPASSFILE="${POSTGRES_PASSFILE_STORE}"
else
  echo "Missing POSTGRES_PASSWORD_FILE or POSTGRES_PASSFILE_STORE file."
  exit 1
fi
export PGHOST="${POSTGRES_HOST}"
export PGPORT="${POSTGRES_PORT}"
# Chronicle: bash arithmetic evaluates a word as 0, which would prune almost every dump.
# "all" keeps a tier forever (the operator's choice in ./chronicle setup).
for keep in BACKUP_KEEP_MINS BACKUP_KEEP_DAYS BACKUP_KEEP_WEEKS BACKUP_KEEP_MONTHS; do
  if [[ "${!keep}" != all && ! "${!keep}" =~ ^(0|[1-9][0-9]{0,8})$ ]]; then
    echo "${keep} must be all or a non-negative decimal integer (received '${!keep}')."
    exit 1
  fi
done
KEEP_MINS=${BACKUP_KEEP_MINS}
KEEP_DAYS=${BACKUP_KEEP_DAYS}
KEEP_WEEKS=${BACKUP_KEEP_WEEKS}
KEEP_MONTHS=${BACKUP_KEEP_MONTHS}
[[ "$KEEP_WEEKS" == all ]] || KEEP_WEEKS=`expr $(((${BACKUP_KEEP_WEEKS} * 7) + 1))`
[[ "$KEEP_MONTHS" == all ]] || KEEP_MONTHS=`expr $(((${BACKUP_KEEP_MONTHS} * 31) + 1))`

# Validate backup dir
if [ '!' -d "${BACKUP_DIR}" -o '!' -w "${BACKUP_DIR}" -o '!' -x "${BACKUP_DIR}" ]; then
  echo "BACKUP_DIR points to a file or folder with insufficient permissions."
  exit 1
fi
