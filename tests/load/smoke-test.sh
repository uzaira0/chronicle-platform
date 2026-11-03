#!/usr/bin/env bash
set -euo pipefail
# Use an enrolled device whose current consent enables usage_events and sensor_accelerometer.
# BASE_URL, API_KEY, TEST_STUDY_ID, TEST_PARTICIPANT_ID and TEST_RANDOM_DEVICE_ID are operator fixtures.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
export BASE_URL="${BASE_URL:-http://127.0.0.1:40320}"
export API_KEY="${API_KEY:?API_KEY for an enrolled device is required}"
export TEST_STUDY_ID="${TEST_STUDY_ID:?TEST_STUDY_ID is required}"
export TEST_PARTICIPANT_ID="${TEST_PARTICIPANT_ID:?TEST_PARTICIPANT_ID is required}"
export TEST_RANDOM_DEVICE_ID="${TEST_RANDOM_DEVICE_ID:?TEST_RANDOM_DEVICE_ID bound to API_KEY is required}"
python3 - "$ROOT_DIR" <<'PY_SMOKE'
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
import os, runpy, sys
fixture = runpy.run_path(str(Path(sys.argv[1]) / 'tests/deployment/selfhost-client.py'))
if os.environ.get('UPLOAD_CONNECT_TO'):
    fixture['configure_fixture_address'](os.environ['BASE_URL'], os.environ['UPLOAD_CONNECT_TO'].split(':', 2)[2])
study, participant = os.environ['TEST_STUDY_ID'], os.environ['TEST_PARTICIPANT_ID']
payloads = fixture['batches'](study, participant, datetime.now(timezone.utc).isoformat())
headers = {fixture['API_KEY_HEADER']: os.environ['API_KEY'], fixture['DEVICE_HEADER']: os.environ['TEST_RANDOM_DEVICE_ID']}
base = os.environ['BASE_URL'].rstrip('/') + '/chronicle/v4/study/' + quote(study, safe='') + '/participant/' + quote(participant, safe='')
phone = fixture['client'](os.environ.get('CA_CERT'))
for kind, suffix in (('usage', '/android'), ('sensors', '/android/sensors')):
    answer = fixture['request'](phone, base + suffix, 'POST', payloads[kind], headers)
    # usage answers with an UploadReceipt; the other routes with a row count.
    accepted = len(answer['acceptedIds']) if kind == 'usage' else answer
    if accepted != len(payloads[kind]):
        raise SystemExit(f'{kind} did not acknowledge the submitted batch')
    print(f'PASS {kind}: {accepted} acknowledged row(s)')
PY_SMOKE
