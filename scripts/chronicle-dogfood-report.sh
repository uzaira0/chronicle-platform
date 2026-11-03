#!/bin/bash
set -euo pipefail

# Preserve the supported environment override in this shell only. It must be removed from
# the exported environment before dirname, awk, Docker, or any other host child is spawned.
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"
export -n POSTGRES_PASSWORD
unset PGPASSWORD FLYWAY_PASSWORD

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STUDY_ID="${CHRONICLE_STUDY_ID:?Set CHRONICLE_STUDY_ID to the enrolled study UUID}"
PARTICIPANT_ID="${CHRONICLE_PARTICIPANT_ID:-}"
POSTGRES_CONTAINER="${CHRONICLE_POSTGRES_CONTAINER:-chronicle-postgres}"
POSTGRES_USER="${POSTGRES_USER:-}"
POSTGRES_DB="${POSTGRES_DB:-}"

usage() {
  cat <<'EOF'
Usage: scripts/chronicle-dogfood-report.sh [options]

Prints a local Postgres data-quality dogfood report for one Chronicle
participant. Covers: device/app-version inventory, upload buffer queue depth,
usage event counts, ActivityClass coverage and top missing-activityClass
packages, device lifecycle events (shutdown/startup, screen/keyguard,
battery/power/network), hardware sensor sample counts and types, the modeled
sensor availability matrix, last upload timestamps per stream, malformed row
counts, duplicate/replay counts, clock skew, future-timestamp rows, and stale
participants.

Database and API credentials are never printed. The selected study and participant
identifiers are included intentionally so an operator can attribute the local report.

Options:
  --study-id UUID         study UUID
  --participant-id ID     participant ID
  -h, --help              show help

Environment overrides: CHRONICLE_STUDY_ID, CHRONICLE_PARTICIPANT_ID,
CHRONICLE_POSTGRES_CONTAINER, POSTGRES_USER, POSTGRES_DB, POSTGRES_PASSWORD.
Postgres credentials are read from docker/.env when not set in the environment.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --study-id) STUDY_ID="${2:?missing --study-id value}"; shift 2 ;;
    --participant-id) PARTICIPANT_ID="${2:?missing --participant-id value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -f "$ROOT_DIR/docker/.env" ]]; then
  [[ -n "$POSTGRES_USER" ]] || POSTGRES_USER="$(awk -F= '/^POSTGRES_USER=/{print substr($0,index($0,"=")+1)}' "$ROOT_DIR/docker/.env")"
  [[ -n "$POSTGRES_DB" ]] || POSTGRES_DB="$(awk -F= '/^POSTGRES_DB=/{print substr($0,index($0,"=")+1)}' "$ROOT_DIR/docker/.env")"
  [[ -n "$POSTGRES_PASSWORD" ]] || POSTGRES_PASSWORD="$(awk -F= '/^POSTGRES_PASSWORD=/{print substr($0,index($0,"=")+1)}' "$ROOT_DIR/docker/.env")"
fi

if [[ -z "$PARTICIPANT_ID" && -f /tmp/chronicle-tablet-upload-test-ids.txt ]]; then
  PARTICIPANT_ID="$(sed -n '1p' /tmp/chronicle-tablet-upload-test-ids.txt)"
fi

[[ -n "$PARTICIPANT_ID" ]] || { echo "Missing participant id." >&2; exit 1; }
[[ -n "$POSTGRES_USER" && -n "$POSTGRES_DB" && -n "$POSTGRES_PASSWORD" ]] || {
  echo "Missing Postgres credentials. Provide docker/.env or env vars." >&2
  exit 1
}

psql_report() {
  {
    printf '%s\n' "$POSTGRES_PASSWORD"
    /bin/cat
  } | docker exec -i \
    "$POSTGRES_CONTAINER" \
    /bin/bash -euc '
      IFS= read -r PGPASSWORD
      export PGPASSWORD
      postgres_user="$1"
      postgres_db="$2"
      study_id="$3"
      participant_id="$4"
      exec psql -h 127.0.0.1 -U "$postgres_user" -d "$postgres_db" \
        -v ON_ERROR_STOP=1 \
        -v study_id="$study_id" \
        -v participant_id="$participant_id" \
        -P pager=off
    ' chronicle-dogfood-report "$POSTGRES_USER" "$POSTGRES_DB" \
      "$STUDY_ID" "$PARTICIPANT_ID"
}

echo "Chronicle dogfood report"
echo "study_id=$STUDY_ID"
echo "participant_id=$PARTICIPANT_ID"
echo "generated_at=$(date -Is)"
echo

psql_report <<'SQL'
\echo '== Device Inventory =='
SELECT
  random_device_id,
  device_type,
  source_device ->> 'manufacturer' AS manufacturer,
  source_device ->> 'model' AS model,
  source_device ->> 'os' AS os,
  source_device ->> 'osVersion' AS os_version
FROM devices
WHERE study_id = :'study_id'::uuid
  AND participant_id = :'participant_id'
ORDER BY random_device_id;

\echo '== Upload Buffer =='
SELECT
  upload_type,
  count(*) AS batches,
  coalesce(sum(jsonb_array_length(data)), 0) AS buffered_items,
  min(uploaded_at) AS oldest_buffered_at,
  max(uploaded_at) AS newest_buffered_at
FROM upload_buffer
WHERE study_id = :'study_id'::uuid
  AND participant_id = :'participant_id'
GROUP BY upload_type
ORDER BY upload_type;

\echo '== Usage Events Summary =='
SELECT
  count(*) AS total_usage_rows,
  count(activity_class) AS rows_with_activity_class,
  round(100.0 * count(activity_class) / nullif(count(*), 0), 1) AS pct_with_activity_class,
  min(event_timestamp) AS first_event_at,
  max(event_timestamp) AS latest_event_at,
  max(uploaded_at) AS latest_uploaded_at,
  round(avg(extract(epoch FROM uploaded_at - event_timestamp))::numeric, 1) AS avg_upload_lag_seconds,
  round(max(extract(epoch FROM uploaded_at - event_timestamp))::numeric, 1) AS max_upload_lag_seconds,
  count(*) FILTER (WHERE event_timestamp > uploaded_at + interval '5 minutes') AS future_skew_rows
FROM chronicle_usage_events
WHERE study_id = :'study_id'
  AND participant_id = :'participant_id';

\echo '== ActivityClass Coverage By App =='
SELECT
  app_package_name,
  count(*) AS total_rows,
  count(activity_class) AS rows_with_activity_class,
  round(100.0 * count(activity_class) / nullif(count(*), 0), 1) AS pct_with_activity_class
FROM chronicle_usage_events
WHERE study_id = :'study_id'
  AND participant_id = :'participant_id'
GROUP BY app_package_name
ORDER BY total_rows DESC, app_package_name
LIMIT 25;

\echo '== Top Activity Classes =='
SELECT
  app_package_name,
  activity_class,
  count(*) AS rows
FROM chronicle_usage_events
WHERE study_id = :'study_id'
  AND participant_id = :'participant_id'
  AND activity_class IS NOT NULL
GROUP BY app_package_name, activity_class
ORDER BY rows DESC, app_package_name, activity_class
LIMIT 25;

\echo '== Sensor Data Summary =='
SELECT
  count(*) AS total_sensor_rows,
  count(DISTINCT sensor_type) AS sensor_type_count,
  min(sample_timestamp) AS first_sample_at,
  max(sample_timestamp) AS latest_sample_at,
  count(*) FILTER (WHERE sample_timestamp > now() + interval '5 minutes') AS future_skew_rows
FROM android_sensor_data
WHERE study_id = :'study_id'::uuid
  AND participant_id = :'participant_id';

\echo '== Sensor Data By Type =='
SELECT
  sensor_type,
  count(*) AS rows,
  min(sample_timestamp) AS first_sample_at,
  max(sample_timestamp) AS latest_sample_at
FROM android_sensor_data
WHERE study_id = :'study_id'::uuid
  AND participant_id = :'participant_id'
GROUP BY sensor_type
ORDER BY rows DESC, sensor_type;

\echo '== Sensor Availability =='
SELECT
  random_device_id,
  reported_at,
  array_length(available_sensors, 1) AS available_count,
  available_sensors
FROM android_device_sensor_availability
WHERE study_id = :'study_id'::uuid
  AND participant_id = :'participant_id'
ORDER BY reported_at DESC;

\echo '== Sensor Availability Matrix (modeled Chronicle sensors) =='
-- Cross-joins the full modeled AndroidSensorType inventory against the latest
-- reported availability so every modeled sensor shows present/absent/unknown.
-- The phone checks every modeled type and lists the ones the device has.
WITH modeled(sensor) AS (
  VALUES
    ('accelerometer'), ('gyroscope'), ('magnetometer'), ('gravity'),
    ('linearAcceleration'), ('rotationVector'), ('stepCounter'), ('light'),
    ('proximity'), ('significantMotion'), ('tiltDetector'),
    ('screenOrientation')
),
latest AS (
  SELECT available_sensors
  FROM android_device_sensor_availability
  WHERE study_id = :'study_id'::uuid
    AND participant_id = :'participant_id'
  ORDER BY reported_at DESC
  LIMIT 1
)
SELECT
  m.sensor AS modeled_sensor,
  CASE
    WHEN l.available_sensors IS NULL THEN 'unknown_no_report'
    WHEN m.sensor = ANY (l.available_sensors) THEN 'available'
    ELSE 'unavailable'
  END AS status
FROM modeled m
LEFT JOIN latest l ON true
ORDER BY m.sensor;

\echo '== Device Lifecycle Events =='
-- Lifecycle events are system-origin usage-style rows: app_package_name = 'android'.
SELECT
  interaction_type,
  count(*) AS events,
  min(event_timestamp) AS first_event_at,
  max(event_timestamp) AS latest_event_at
FROM chronicle_usage_events
WHERE study_id = :'study_id'
  AND participant_id = :'participant_id'
  AND app_package_name = 'android'
GROUP BY interaction_type
ORDER BY events DESC, interaction_type;

\echo '== Device Lifecycle Event Categories =='
SELECT
  CASE
    WHEN interaction_type IN ('Device Startup', 'Device Shutdown') THEN 'shutdown_startup'
    WHEN interaction_type IN ('Screen Interactive', 'Screen Non-interactive', 'Keyguard Hidden') THEN 'screen_keyguard'
    WHEN interaction_type IN (
      'Battery Low', 'Battery Okay', 'Battery Charging', 'Battery Discharging',
      'Power Save Mode On', 'Power Save Mode Off',
      'Network Connected', 'Network Disconnected'
    ) THEN 'battery_power_network'
    WHEN interaction_type = 'Low Memory' THEN 'memory'
    ELSE 'other'
  END AS lifecycle_category,
  count(*) AS events
FROM chronicle_usage_events
WHERE study_id = :'study_id'
  AND participant_id = :'participant_id'
  AND app_package_name = 'android'
GROUP BY lifecycle_category
ORDER BY events DESC, lifecycle_category;

\echo '== Top Missing-ActivityClass Packages =='
-- App packages with the most usage rows that have no activity_class set.
SELECT
  app_package_name,
  count(*) AS total_rows,
  count(*) FILTER (WHERE activity_class IS NULL) AS rows_missing_activity_class,
  round(
    100.0 * count(*) FILTER (WHERE activity_class IS NULL) / nullif(count(*), 0),
    1
  ) AS pct_missing_activity_class
FROM chronicle_usage_events
WHERE study_id = :'study_id'
  AND participant_id = :'participant_id'
  AND app_package_name <> 'android'
GROUP BY app_package_name
HAVING count(*) FILTER (WHERE activity_class IS NULL) > 0
ORDER BY rows_missing_activity_class DESC, app_package_name
LIMIT 25;

\echo '== Last Upload Timestamps By Stream =='
-- chronicle_usage_events records an uploaded_at; android_sensor_data does not,
-- so the sensor stream uses the latest sample_timestamp as the freshness proxy.
SELECT 'usage_events' AS stream,
  max(uploaded_at) AS last_uploaded_at,
  'uploaded_at' AS timestamp_source
FROM chronicle_usage_events
WHERE study_id = :'study_id'
  AND participant_id = :'participant_id'
  AND app_package_name <> 'android'
UNION ALL
SELECT 'device_lifecycle' AS stream,
  max(uploaded_at) AS last_uploaded_at,
  'uploaded_at' AS timestamp_source
FROM chronicle_usage_events
WHERE study_id = :'study_id'
  AND participant_id = :'participant_id'
  AND app_package_name = 'android'
UNION ALL
SELECT 'sensor_samples' AS stream,
  max(sample_timestamp) AS last_uploaded_at,
  'sample_timestamp' AS timestamp_source
FROM android_sensor_data
WHERE study_id = :'study_id'::uuid
  AND participant_id = :'participant_id';

\echo '== Upload Queue Depth (server-side upload_buffer) =='
SELECT
  upload_type,
  count(*) AS pending_batches,
  coalesce(sum(jsonb_array_length(data)), 0) AS pending_items
FROM upload_buffer
WHERE study_id = :'study_id'::uuid
  AND participant_id = :'participant_id'
GROUP BY upload_type
ORDER BY upload_type;

\echo '== Malformed Row Counts =='
-- Rows present in final storage that are missing a required field. Backend
-- rejects malformed payloads at upload, so non-zero here flags a storage issue.
SELECT 'usage_missing_timestamp' AS check,
  count(*) FILTER (WHERE event_timestamp IS NULL) AS malformed_rows
FROM chronicle_usage_events
WHERE study_id = :'study_id'
  AND participant_id = :'participant_id'
UNION ALL
SELECT 'usage_missing_package' AS check,
  count(*) FILTER (WHERE app_package_name IS NULL OR app_package_name = '')
FROM chronicle_usage_events
WHERE study_id = :'study_id'
  AND participant_id = :'participant_id'
UNION ALL
SELECT 'sensor_missing_type' AS check,
  count(*) FILTER (WHERE sensor_type IS NULL OR sensor_type = '')
FROM android_sensor_data
WHERE study_id = :'study_id'::uuid
  AND participant_id = :'participant_id';

\echo '== Duplicate / Replay Counts =='
-- Backend does not yet expose dedup/replay counters; report zero plus an
-- explicit not_tracked marker until those counters exist (plan step 11A.15).
\echo 'duplicate_upload_count=0'
\echo 'duplicate_upload_count_not_tracked=true'
\echo 'replay_upload_count=0'
\echo 'replay_upload_count_not_tracked=true'

\echo '== Clock Skew Distribution (event_timestamp vs uploaded_at) =='
SELECT
  count(*) AS total_rows,
  count(*) FILTER (WHERE event_timestamp > uploaded_at) AS future_event_rows,
  count(*) FILTER (WHERE event_timestamp > uploaded_at + interval '5 minutes') AS future_skew_rows,
  round(min(extract(epoch FROM event_timestamp - uploaded_at))::numeric, 1) AS min_skew_seconds,
  round(avg(extract(epoch FROM event_timestamp - uploaded_at))::numeric, 1) AS avg_skew_seconds,
  round(max(extract(epoch FROM event_timestamp - uploaded_at))::numeric, 1) AS max_skew_seconds
FROM chronicle_usage_events
WHERE study_id = :'study_id'
  AND participant_id = :'participant_id';

\echo '== Stale Participants In Study =='
-- Participants whose most recent upload is older than 7 days (or who have no
-- usage rows at all). Scoped to the study, not just the report participant.
WITH last_upload AS (
  SELECT participant_id, max(uploaded_at) AS last_uploaded_at
  FROM chronicle_usage_events
  WHERE study_id = :'study_id'
  GROUP BY participant_id
)
SELECT
  d.participant_id,
  lu.last_uploaded_at,
  CASE
    WHEN lu.last_uploaded_at IS NULL THEN 'no_usage_rows'
    WHEN lu.last_uploaded_at < now() - interval '7 days' THEN 'stale'
    ELSE 'active'
  END AS freshness
FROM (
  SELECT DISTINCT participant_id
  FROM devices
  WHERE study_id = :'study_id'::uuid
) d
LEFT JOIN last_upload lu ON lu.participant_id = d.participant_id
WHERE lu.last_uploaded_at IS NULL
   OR lu.last_uploaded_at < now() - interval '7 days'
ORDER BY lu.last_uploaded_at NULLS FIRST, d.participant_id
LIMIT 50;

\echo '== App Version / Device Inventory =='
SELECT
  random_device_id,
  source_device ->> 'manufacturer' AS manufacturer,
  source_device ->> 'model' AS model,
  source_device ->> 'os' AS os,
  source_device ->> 'osVersion' AS os_version,
  source_device ->> 'appVersion' AS app_version,
  source_device ->> 'appPackageName' AS app_package
FROM devices
WHERE study_id = :'study_id'::uuid
  AND participant_id = :'participant_id'
ORDER BY random_device_id;
SQL
