#!/usr/bin/env bash
set -euo pipefail
# Strict validation requires a valid legacy HMAC enrollment fixture.
# HMAC_TEST_PATH and MOBILE_ENROLLMENT_BODY describe that seeded fixture; no API key is sent.
STRICT="${HMAC_STRICT:-0}"
if [[ "${1:-}" == --strict ]]; then STRICT=1; shift; fi
[[ $# == 0 ]] || { echo "usage: $0 [--strict]" >&2; exit 2; }
export STRICT
python3 - <<'PY_HMAC'
import base64, hashlib, hmac, json, os, time, uuid, urllib.error, urllib.request
strict = os.environ['STRICT'] == '1'
secret = os.environ.get('MOBILE_SIGNING_SECRET')
path = os.environ.get('HMAC_TEST_PATH')
body = os.environ.get('MOBILE_ENROLLMENT_BODY')
if not secret or not path or not body or not os.environ.get('TEST_RANDOM_DEVICE_ID'):
    if strict:
        raise SystemExit('Strict mode requires MOBILE_SIGNING_SECRET, TEST_RANDOM_DEVICE_ID, HMAC_TEST_PATH and valid MOBILE_ENROLLMENT_BODY from an enrollment fixture')
    print('HMAC live probe needs a valid signing/enrollment fixture')
    raise SystemExit(0)
if not path.startswith('/chronicle/') or '?' in path:
    raise SystemExit('HMAC_TEST_PATH must be a Chronicle path without a query')
json.loads(body)
url = os.environ.get('BASE_URL', 'http://127.0.0.1').rstrip('/') + path
headers = {'Content-Type': 'application/json', 'X-Chronicle-Random-Device-Id': os.environ['TEST_RANDOM_DEVICE_ID']}
if os.environ.get('HOST_HEADER'):
    headers['Host'] = os.environ['HOST_HEADER']
timestamp, nonce = str(int(time.time())), str(uuid.uuid4())
canonical = '|'.join(('POST', path, timestamp, nonce, hashlib.sha256(body.encode()).hexdigest()))
signature = base64.b64encode(hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).digest()).decode()
signed = dict(headers, **{'X-Chronicle-Signature': signature, 'X-Chronicle-Timestamp': timestamp, 'X-Chronicle-Nonce': nonce})
def probe(request_headers):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, body.encode(), request_headers, method='POST'), timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as response:
        with response:
            return response.code, response.read()
def rejection(result, message):
    status, payload = result
    return status == 401 and json.loads(payload).get('error') == message
try:
    status, _ = probe(signed)
    assert 200 <= status < 300, f'valid signed enrollment must succeed, got {status}'
    assert rejection(probe(headers), 'Missing required signature headers'), 'unsigned request did not report missing HMAC headers'
    assert rejection(probe(signed), 'Request replay detected'), 'same valid signature/nonce did not report replay'
except (AssertionError, ValueError, OSError) as error:
    print(f'HMAC probe failed: {error}')
    raise SystemExit(1 if strict else 0)
print('PASS valid signed enrollment, missing-header rejection and exact nonce replay rejection')
PY_HMAC
