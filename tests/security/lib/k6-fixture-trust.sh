#!/usr/bin/env bash
# k6_run_trusting_fixture_ca VARS -- K6_RUN_ARGS...: `k6 run K6_RUN_ARGS` that trusts the fixture CA in
# SSL_CERT_FILE on every host. VARS is a space-separated list of environment variable names the script
# reads through __ENV.
#
# k6 is a Go program. Go reads SSL_CERT_FILE only on Linux and the other Unix ports
# (crypto/x509/root_unix.go); on macOS it verifies with the platform verifier and ignores SSL_CERT_FILE,
# so a per-run fixture CA never reaches it. curl and Python honour the same file, which is why only the
# k6 steps of the 2026.11.12 release smoke failed there ("certificate is not trusted"). On macOS this runs
# the pinned Linux k6 instead, on the host network so 127.0.0.1 reaches the same loopback listeners
# (the smoke's TLS proxy fixture already runs that way), with the CA mounted and SSL_CERT_FILE pointing
# at it. Verification stays on: nothing here skips or relaxes it.
#
# Paths in K6_RUN_ARGS must be under ROOT_DIR or REPORT_DIR; both are mounted at the same path.

K6_LINUX_IMAGE='grafana/k6:2.3.0@sha256:2dd4756ec6e14e62778916e1eb850108e4b499304c02df56760fa0bdb0fba0b8'

k6_run_trusting_fixture_ca() {
  local names=$1
  shift
  [[ ${1:-} == -- ]] || { echo 'k6_run_trusting_fixture_ca requires -- before the k6 run arguments' >&2; return 2; }
  shift
  if [[ -z ${SSL_CERT_FILE:-} || $(uname -s) != Darwin ]]; then
    k6 run "$@"
    return
  fi
  [[ -f $SSL_CERT_FILE ]] || { echo "SSL_CERT_FILE does not exist: $SSL_CERT_FILE" >&2; return 2; }
  : "${ROOT_DIR:?ROOT_DIR is required}" "${REPORT_DIR:?REPORT_DIR is required}"
  command -v docker >/dev/null || { echo 'docker is required to run k6 with a fixture CA on macOS' >&2; return 2; }
  local name forward=()
  for name in $names; do
    [[ $name =~ ^[A-Z_][A-Z0-9_]*$ ]] || { echo "invalid variable name: $name" >&2; return 2; }
    # -e NAME (no value) copies the value from this environment, so secrets never reach argv.
    [[ -n ${!name+set} ]] && forward+=(-e "$name")
  done
  # The source tree is read-only; the report directory (often inside it) is the one writable mount.
  local mounts=(-v "$REPORT_DIR:$REPORT_DIR")
  [[ $REPORT_DIR -ef $ROOT_DIR ]] || mounts=(-v "$ROOT_DIR:$ROOT_DIR:ro" "${mounts[@]}")
  docker run --rm --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" --tmpfs /k6-home:rw,size=64m \
    "${mounts[@]}" -v "$SSL_CERT_FILE:/fixture/ca.crt:ro" \
    -e SSL_CERT_FILE=/fixture/ca.crt -e HOME=/k6-home -e K6_NO_USAGE_REPORT=true ${forward[@]+"${forward[@]}"} \
    -w "$ROOT_DIR" \
    "$K6_LINUX_IMAGE" run "$@"
}
