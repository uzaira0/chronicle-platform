#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUN_ROOT="${SELFHOST_LOG_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-log-sanitizer}"
IMAGE='fluent/fluent-bit:5.1.3@sha256:c5542543523c9678398dd78d927c05e8425ec15b038f226b67b3b019b1a70845'

fail() { printf 'self-host log sanitizer test failed: %s\n' "$*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || fail "docker is required"
command -v timeout >/dev/null 2>&1 || command -v gtimeout >/dev/null 2>&1 ||
  fail "timeout or gtimeout is required"
TIMEOUT=timeout
command -v timeout >/dev/null 2>&1 || TIMEOUT=gtimeout
[[ "$RUN_ROOT" == /* ]] || fail "test root must be absolute"
case "$RUN_ROOT" in /tmp|/tmp/*|/private/tmp|/private/tmp/*) fail "test root must not use a system temporary directory" ;; esac
/bin/mkdir -p "$RUN_ROOT"
output="${RUN_ROOT}/latest.log"
container="chronicle-sat-r1-log-sanitizer-$$"
outage="chronicle-sat-r1-log-outage-$$"
cleanup() {
  docker rm -fv "$container" "${outage}-sink" "${outage}-fluent-bit" >/dev/null 2>&1 || true
  docker network rm "$outage" >/dev/null 2>&1 || true
  [[ -z "${outage_dir:-}" ]] || rm -rf -- "$outage_dir"
}
trap cleanup EXIT HUP INT TERM

"$TIMEOUT" 30 docker run -d --name "$container" --network none \
  -v "${ROOT_DIR}/selfhost/monitoring/sanitize.lua:/sanitize.lua:ro" \
  -v "${ROOT_DIR}/selfhost/monitoring/parsers.conf:/parsers.conf:ro" \
  "$IMAGE" /fluent-bit/bin/fluent-bit -f 1 -R /parsers.conf \
  -i dummy -p tag=chronicle.web \
    -p 'dummy={"ts":1786580000.5,"level":"error","request":{"method":"GET","uri":"/chronicle/v3/study/123e4567-e89b-12d3-a456-426614174000?token=TOPSECRET_9","headers":{"Authorization":["Bearer TOPSECRET_9"]}},"status":500,"duration":0.125,"message":"participant=p-123 TOPSECRET_9"}' \
  -i dummy -p tag=chronicle.backend \
    -p 'dummy={"log":"{\"timestamp\":\"2026-08-13T00:00:00Z\",\"severity\":\"WARN\",\"request_id\":\"request-safe-1\",\"method\":\"POST\",\"route\":\"/chronicle/v3/participant/private-name?secret=TOPSECRET_9\",\"message\":\"TOPSECRET_9\"}"}' \
  -i dummy -p tag=chronicle.postgres \
    -p 'dummy={"log":"chronicle_pg timestamp_seconds=1786580000.500 sqlstate=23505 ERROR: statement SELECT TOPSECRET_9"}' \
  -F parser -m 'chronicle.*' -p key_name=log -p parser=chronicle_json -p reserve_data=true -p preserve_key=false \
  -F parser -m chronicle.postgres -p key_name=log -p parser=chronicle_postgres -p reserve_data=true -p preserve_key=false \
  -F lua -m 'chronicle.*' -p script=/sanitize.lua -p call=sanitize \
  -o stdout -m 'chronicle.*' -p format=json_lines >/dev/null

ready=false
for _ in {1..30}; do
  docker logs "$container" >"$output" 2>&1 || true
  if grep -q '"service":"web"' "$output" &&
     grep -q '"service":"backend"' "$output" &&
     grep -q '"service":"postgres"' "$output"; then
    ready=true
    break
  fi
  sleep 0.5
done
[[ "$ready" == true ]] || { cat "$output" >&2; fail "Fluent Bit fixture did not emit every source within 15 seconds"; }

python3 - "$output" <<'PY'
import json
import sys

rows = []
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    if not line.startswith("{"):
        continue
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        continue
    if row.get("service") in {"web", "backend", "postgres"}:
        rows.append(row)

by_service = {}
for row in rows:
    by_service.setdefault(row["service"], row)
assert set(by_service) == {"web", "backend", "postgres"}, by_service.keys()
assert by_service["web"]["route"] == "/chronicle/v3/study/{id}"
assert by_service["web"]["status"] == "500"
assert by_service["web"]["duration_ms"] == 125
assert by_service["backend"]["route"] == "/chronicle/v3/participant/{id}"
assert by_service["backend"]["request_id"] == "request-safe-1"
assert by_service["postgres"]["sqlstate"] == "23505"

allowed = {
    "date", "timestamp", "service", "stream", "severity", "request_id", "error_id",
    "operation", "result", "failure_category", "release_version", "status", "method",
    "route", "duration_ms", "sqlstate", "exception_class", "message",
}
for row in by_service.values():
    assert set(row) <= allowed, set(row) - allowed
serialized = json.dumps(by_service, sort_keys=True)
for forbidden in (
    "TOPSECRET_9", "p-123", "123e4567-e89b-12d3-a456-426614174000",
    "Authorization", "SELECT", "private-name", "token=",
):
    assert forbidden not in serialized, forbidden
print("self-host structured log sanitizer test passed")
PY

# Collector outage, restart and storage budget, with the shipped fluent-bit.conf and the shipped Docker
# fluentd driver options. VictoriaLogs is replaced by a recorder that can be stopped and started.
outage_dir="$(mktemp -d "${RUN_ROOT}/outage.XXXXXX")"
mkdir -p "${outage_dir}/etc" "${outage_dir}/state" "${outage_dir}/sink"
chmod 0777 "${outage_dir}/sink"
cp "${ROOT_DIR}/selfhost/monitoring/fluent-bit.conf" "${ROOT_DIR}/selfhost/monitoring/parsers.conf" \
  "${ROOT_DIR}/selfhost/monitoring/sanitize.lua" "${outage_dir}/etc/"
helper_image=$(awk '/^FROM /{image=$2} END{print image}' "${ROOT_DIR}/selfhost/Dockerfile.backup")
cat >"${outage_dir}/sink.py" <<'PY'
import http.server
class Recorder(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with open("/data/received.jsonl", "ab") as received:
            received.write(body if body.endswith(b"\n") else body + b"\n")
        self.send_response(204)
        self.end_headers()
    def log_message(self, *args):
        pass
http.server.ThreadingHTTPServer(("0.0.0.0", 9428), Recorder).serve_forever()
PY
subnet="$(python3 "${ROOT_DIR}/selfhost/network-subnet.py" select 10.251.3.0/24 "$outage")"
docker network create --subnet "$subnet" "$outage" >/dev/null
# The helper image declares volumes, so every sink container gets anonymous ones of its own.
sink_volumes=''
start_sink() {
  docker rm -fv "${outage}-sink" >/dev/null 2>&1 || true
  docker run -d --name "${outage}-sink" --network "$outage" --network-alias victorialogs --memory 128m \
    --user "$(id -u):$(id -g)" -v "${outage_dir}/sink.py:/sink.py:ro" -v "${outage_dir}/sink:/data" \
    --entrypoint python3 "$helper_image" /sink.py >/dev/null
  sink_volumes+=" $(docker inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{end}}{{end}}' "${outage}-sink")"
}
start_collector() { # the shipped service's user namespace, memory limit and read-only root
  docker rm -fv "${outage}-fluent-bit" >/dev/null 2>&1 || true
  docker run -d --name "${outage}-fluent-bit" --network "$outage" --user "$(id -u):$(id -g)" --memory 128m \
    --read-only --tmpfs /tmp --tmpfs /run -p 127.0.0.1::24224 \
    -v "${outage_dir}/etc:/fluent-bit/etc:ro" -v "${outage_dir}/state:/fluent-bit/state" "$IMAGE" >/dev/null
  forward_port=$(docker port "${outage}-fluent-bit" 24224/tcp | sed -n 1p | cut -d: -f2)
  for _ in {1..40}; do
    docker logs "${outage}-fluent-bit" >"${outage_dir}/collector.log" 2>&1
    grep -q 'listening on' "${outage_dir}/collector.log" && return 0
    sleep 0.25
  done
  fail "Fluent Bit did not start its forward input"
}
emit() { # first last: one backend container writes numbered events through Docker's fluentd driver
  local started=$SECONDS
  "$TIMEOUT" 60 docker run --rm -i --network none --log-driver fluentd \
    --log-opt "fluentd-address=127.0.0.1:${forward_port}" --log-opt fluentd-async=true \
    --log-opt fluentd-buffer-limit=4096 --log-opt tag=chronicle.backend --entrypoint bash "$helper_image" \
    -s -- "$1" "$2" "${3:-padding}" >/dev/null <<'SH' || fail "the writer failed while the log collector was degraded"
for i in $(seq "$1" "$2"); do
  printf '{"severity":"INFO","operation":"outage","request_id":"seq-%06d-%s"}\n' "$i" "$3"
done
SH
  (( SECONDS - started < 30 )) || fail "the writer blocked for $((SECONDS - started)) s on the log collector"
}
received_check() { # mode first last
  python3 - "${outage_dir}/sink/received.jsonl" "$@" <<'PY'
import json, re, sys
path, mode, first, last = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
try:
    rows = [json.loads(line) for line in open(path) if line.strip()]
except FileNotFoundError:
    rows = []
ids = [int(match[1]) for row in rows if (match := re.match(r"seq-(\d{6})", row.get("request_id", "")))]
assert len(ids) == len(set(ids)), "duplicate delivery"
wanted = set(range(first, last + 1))
if mode == "all":
    sys.exit(0 if wanted <= set(ids) else 1)
# "bounded": some of the range arrived, nothing outside what was written, nothing twice.
assert set(ids) <= set(range(1, last + 1)), "events never written were delivered"
sys.exit(0 if set(ids) & wanted else 1)
PY
}
wait_for() {
  for _ in {1..240}; do received_check "$@" && return 0; sleep 0.5; done
  docker logs "${outage}-fluent-bit" 2>&1 | tail -20 >&2
  fail "the sink did not receive events $2-$3 ($1)"
}
wait_for_collector_log() {
  for _ in {1..120}; do
    docker logs "${outage}-fluent-bit" >"${outage_dir}/collector.log" 2>&1
    grep -Eq "$1" "${outage_dir}/collector.log" && return 0
    sleep 0.5
  done
  tail -20 "${outage_dir}/collector.log" >&2
  fail "the collector never reported $1"
}
start_sink
start_collector
emit 1 50
wait_for all 1 50
# Sink outage across a collector restart: filesystem chunks must survive and replay once.
docker stop "${outage}-sink" >/dev/null
emit 51 100
wait_for_collector_log 'failed to flush chunk'
docker stop -t 10 "${outage}-fluent-bit" >/dev/null
start_sink
docker start "${outage}-fluent-bit" >/dev/null
wait_for all 1 100
# Past the storage budget: storage stays bounded, the loss is reported, and the writer never blocks.
# Same option, scaled from 128M so the test writes megabytes, not hundreds of them.
grep -Eq '^ +storage\.total_limit_size +128M$' "${outage_dir}/etc/fluent-bit.conf" || fail "shipped storage budget changed"
# perl -pi: GNU and BSD sed disagree on -i.
perl -pi -e 's/^( *storage\.total_limit_size *)128M$/${1}2M/' "${outage_dir}/etc/fluent-bit.conf"
docker stop "${outage}-sink" >/dev/null
start_collector
emit 101 60100 padpadpadpadpadpadpadpadpadpadpadpadpadpadpadpadpadpadpad
wait_for_collector_log 'fail to drop enough chunks|could not ingest|dropping chunk'
# Apparent bytes of the buffer files (du -b is GNU-only).
stored=$(python3 -c 'import os, sys; print(sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(sys.argv[1]) for f in fs))' "${outage_dir}/state/forward.0")
(( stored <= 2 * 2 * 1024 * 1024 )) || fail "filesystem buffer grew to ${stored} bytes past its 2M budget"
[[ "$(docker inspect --format '{{.State.Running}} {{.State.OOMKilled}}' "${outage}-fluent-bit")" == 'true false' ]] ||
  fail "the collector did not survive the overflow"
start_sink
docker restart -t 10 "${outage}-fluent-bit" >/dev/null
wait_for bounded 101 60100
# The run must leave no volume: each of the three sink containers had its own (18 were left per run).
docker rm -fv "${outage}-sink" >/dev/null
left=0
for volume in $sink_volumes; do
  ! docker volume inspect "$volume" >/dev/null 2>&1 || left=$((left + 1))
done
(( left == 0 )) || fail "${left} anonymous volumes of the sink containers were left behind"
echo "self-host log collector outage test passed"
