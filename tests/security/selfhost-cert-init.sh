#!/usr/bin/env bash
# cert-init.sh against a scratch ./tls: atomic internal-pair generation, rejection of unusable
# existing pairs, and operator-owned files that a plain cp can renew.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
source "$ROOT_DIR/tests/security/lib/selfhost-python.sh"
command -v openssl >/dev/null || { echo "FAIL: missing tool: openssl" >&2; exit 1; }
CERT_INIT_SCRIPT="${SELFHOST_CERT_INIT_SCRIPT:-$ROOT_DIR/selfhost/cert-init.sh}"
RUN_PARENT="${TMPDIR:-${ROOT_DIR}/build/operator-test-runs}/selfhost-cert-init"
mkdir -p "$RUN_PARENT"
RUN_DIR=$(mktemp -d "${RUN_PARENT}/run.XXXXXX")
trap 'rm -rf -- "$RUN_DIR"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# The container runs as root; here chown only records what cert-init asked for.
mkdir -p "$RUN_DIR/bin"
cat >"$RUN_DIR/bin/chown" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$CERT_INIT_CHOWN_LOG"
EOF
chmod +x "$RUN_DIR/bin/chown"
export CERT_INIT_CHOWN_LOG="$RUN_DIR/chown.log"
TLS="$RUN_DIR/tls"

cert_init() { # <TLS_MODE>
  env PATH="$RUN_DIR/bin:$PATH" TLS_DIR="$TLS" TLS_MODE="$1" DASHBOARD_EXPOSURE=internal \
    bash "$CERT_INIT_SCRIPT" >"$RUN_DIR/output" 2>&1
}
pair_matches() { # <cert> <key>
  [[ "$(openssl x509 -in "$1" -noout -pubkey)" == "$(openssl pkey -in "$2" -pubout)" ]]
}
mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }

# Fresh generation publishes a matching pair, leaves no temporaries, and keeps the files
# owned by the owner of ./tls, group 0, key 0640.
mkdir "$TLS"
cert_init behind-proxy || { cat "$RUN_DIR/output" >&2; fail 'fresh generation failed'; }
pair_matches "$TLS/internal-cert.pem" "$TLS/internal-key.pem" || fail 'generated pair does not match'
[[ -z "$(find "$TLS" -name '.internal-*')" ]] || fail 'generation left temporary files'
[[ "$(mode "$TLS/internal-key.pem")" == 640 && "$(mode "$TLS/internal-cert.pem")" == 644 ]] \
  || fail 'unexpected generated modes'
grep -Eq "^$(id -u):0 $TLS/\.?internal-key" "$CERT_INIT_CHOWN_LOG" \
  || fail 'key was not left owned by the ./tls owner in group 0'
grep -Fxq "$(id -u):0 $TLS/internal-ca.srl" "$CERT_INIT_CHOWN_LOG" \
  || fail 'CA serial file was not left owned by the ./tls owner in group 0'
echo 'PASS: fresh internal pair generated atomically, operator-owned, group-readable by Caddy'
anchor=$(sha256sum "$TLS/internal-ca.crt")
env PATH="$RUN_DIR/bin:$PATH" TLS_DIR="$TLS" TLS_MODE=behind-proxy DASHBOARD_EXPOSURE=internal \
  INTERNAL_BIND=100.64.25.1 INTERNAL_CERT_SANS=DNS:dashboard.mgmt.example.org \
  bash "$CERT_INIT_SCRIPT" >"$RUN_DIR/output" 2>&1
openssl verify -CAfile "$TLS/internal-ca.crt" -verify_hostname dashboard.mgmt.example.org "$TLS/internal-cert.pem" >/dev/null || fail 'SAN change did not renew generated leaf'
[[ $(sha256sum "$TLS/internal-ca.crt") == "$anchor" ]] || fail 'SAN renewal replaced the trust anchor'
echo 'PASS: management SAN renewal preserves the trusted CA'
env PATH="$RUN_DIR/bin:$PATH" TLS_DIR="$TLS" TLS_MODE=behind-proxy DASHBOARD_EXPOSURE=internal \
  INTERNAL_BIND=100.64.25.1 INTERNAL_CERT_SANS=DNS:dashboard.mgmt.example.org HTTP_BIND=10.20.0.5 POOL_LISTENER_TLS=true \
  bash "$CERT_INIT_SCRIPT" >"$RUN_DIR/output" 2>&1 || { cat "$RUN_DIR/output" >&2; fail 'pool listener SAN renewal failed'; }
openssl verify -CAfile "$TLS/internal-ca.crt" -verify_ip 10.20.0.5 "$TLS/internal-cert.pem" >/dev/null ||
  fail 'TLS pool listener address is not in the generated leaf'
openssl verify -CAfile "$TLS/internal-ca.crt" -verify_hostname dashboard.mgmt.example.org "$TLS/internal-cert.pem" >/dev/null ||
  fail 'pool listener SAN dropped the operator management SAN'
[[ $(sha256sum "$TLS/internal-ca.crt") == "$anchor" ]] || fail 'pool SAN renewal replaced the trust anchor'
echo 'PASS: a TLS pool listener address is added to the generated leaf under the same CA'

# Dashboard CA rotation (SECRET-ROTATION.md): move the CA pair and its leaf aside, rerun cert-init.
mkdir "$RUN_DIR/retired-ca"
mv "$TLS/internal-ca.crt" "$TLS/internal-ca.key" "$TLS/internal-cert.pem" "$TLS/internal-key.pem" "$RUN_DIR/retired-ca/"
cert_init behind-proxy || { cat "$RUN_DIR/output" >&2; fail 'cert-init did not recreate a moved-aside CA'; }
[[ $(sha256sum <"$TLS/internal-ca.crt") != $(sha256sum <"$RUN_DIR/retired-ca/internal-ca.crt") ]] || fail 'CA rotation kept the old CA'
[[ "$(openssl pkey -in "$TLS/internal-ca.key" -pubout)" != "$(openssl pkey -in "$RUN_DIR/retired-ca/internal-ca.key" -pubout)" ]] \
  || fail 'CA rotation reused the old CA key'
openssl verify -CAfile "$TLS/internal-ca.crt" "$TLS/internal-cert.pem" >/dev/null || fail 'new leaf is not signed by the new CA'
openssl verify -CAfile "$RUN_DIR/retired-ca/internal-ca.crt" "$TLS/internal-cert.pem" >/dev/null 2>&1 \
  && fail 'new leaf still verifies against the retired CA'
anchor=$(sha256sum "$TLS/internal-ca.crt")
echo 'PASS: moving the dashboard CA aside issues a new CA and a leaf only it signs'

# A nonempty but truncated certificate (an interrupted older write) is not accepted.
good_key=$(<"$TLS/internal-key.pem")
head -c 200 "$TLS/internal-cert.pem" >"$TLS/internal-cert.trunc" && mv "$TLS/internal-cert.trunc" "$TLS/internal-cert.pem"
chmod 0644 "$TLS/internal-key.pem"   # as a careless copy leaves it
cert_init behind-proxy || { cat "$RUN_DIR/output" >&2; fail 'truncated certificate was not regenerated'; }
pair_matches "$TLS/internal-cert.pem" "$TLS/internal-key.pem" || fail 'regenerated pair does not match'
[[ -s "$TLS/internal-cert.pem.invalid" && -s "$TLS/internal-key.pem.invalid" ]] || fail 'invalid pair not kept aside'
[[ "$(<"$TLS/internal-key.pem")" != "$good_key" ]] || fail 'stale key reused with a new certificate'
[[ "$(mode "$TLS/internal-key.pem.invalid")" == 600 ]] || fail 'key moved aside is readable by others'
echo 'PASS: truncated existing certificate is moved aside and regenerated'

# The generated pair is replaced in its last 30 days; an operator's own
# certificate near expiry is kept and only warned about.
rm -f "$TLS"/internal-*
openssl req -x509 -newkey rsa:2048 -nodes -days 5 -subj /CN=chronicle-dashboard \
  -keyout "$TLS/internal-key.pem" -out "$TLS/internal-cert.pem" >/dev/null 2>&1
expiring_cert=$(<"$TLS/internal-cert.pem")
cert_init behind-proxy || { cat "$RUN_DIR/output" >&2; fail 'expiring generated certificate was not renewed'; }
[[ "$(<"$TLS/internal-cert.pem.expired")" == "$expiring_cert" ]] || fail 'expiring pair not kept aside'
openssl x509 -checkend $((30 * 86400)) -noout -in "$TLS/internal-cert.pem" >/dev/null ||
  fail 'renewed certificate still expires within 30 days'
pair_matches "$TLS/internal-cert.pem" "$TLS/internal-key.pem" || fail 'renewed pair does not match'
openssl req -x509 -newkey rsa:2048 -nodes -days 5 -subj /CN=dashboard.example.org -addext "subjectAltName=DNS:localhost,DNS:web,IP:127.0.0.1,IP:::1" \
  -keyout "$TLS/internal-key.pem" -out "$TLS/internal-cert.pem" >/dev/null 2>&1
operator_cert=$(<"$TLS/internal-cert.pem")
cert_init behind-proxy || { cat "$RUN_DIR/output" >&2; fail 'expiring operator certificate refused'; }
[[ "$(<"$TLS/internal-cert.pem")" == "$operator_cert" ]] || fail 'operator certificate was replaced'
grep -Fq 'expires within 30 days; replace' "$RUN_DIR/output" || fail 'no expiry warning for operator certificate'
echo 'PASS: expiring generated pair renewed; operator certificate kept with a warning'

# A failed generation publishes nothing at the final names.
rm -f "$TLS"/internal-*
cat >"$RUN_DIR/bin/openssl" <<'EOF'
#!/usr/bin/env bash
# Write a partial key, then die as on a full disk.
for ((i = 1; i <= $#; i++)); do [[ "${!i}" == -keyout ]] && { j=$((i + 1)); printf 'partial' >"${!j}"; }; done
exit 1
EOF
chmod +x "$RUN_DIR/bin/openssl"
! cert_init behind-proxy || fail 'failed generation reported success'
rm "$RUN_DIR/bin/openssl"
[[ ! -e "$TLS/internal-key.pem" && ! -e "$TLS/internal-cert.pem" ]] || fail 'failed generation left final files'
[[ -z "$(find "$TLS" -name '.internal-*')" ]] || fail 'failed generation left temporary files'
echo 'PASS: interrupted generation leaves nothing that a later start would accept'

# Own TLS: a mismatched operator pair is refused, never silently accepted.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=a -keyout "$TLS/key.pem" -out "$TLS/cert.pem" >/dev/null 2>&1
openssl genpkey -algorithm RSA -out "$TLS/other-key.pem" >/dev/null 2>&1
cp "$TLS/key.pem" "$RUN_DIR/own-key.pem"
cp "$TLS/other-key.pem" "$TLS/key.pem"
chmod 0644 "$TLS/key.pem"
! cert_init own-tls || fail 'mismatched own-tls pair accepted'
[[ "$(mode "$TLS/key.pem")" == 600 ]] || fail 'rejected own-tls key left readable by others'
grep -Fq 'not a matching certificate' "$RUN_DIR/output" || fail 'missing own-tls mismatch diagnostic'
cp "$RUN_DIR/own-key.pem" "$TLS/key.pem"   # renewal with a plain cp
cert_init own-tls || { cat "$RUN_DIR/output" >&2; fail 'matching own-tls pair refused'; }
grep -Fqx "$(id -u):0 $TLS/key.pem" "$CERT_INIT_CHOWN_LOG" || fail 'own key not left with the ./tls owner'
[[ "$(mode "$TLS/key.pem")" == 640 ]] || fail 'own key mode is not 0640'
echo 'PASS: own-tls pair validated and left operator-owned'
echo 'PASS: selfhost-cert-init'

# Credential-bearing service endpoints get reusable, matching certificates and a Java store.
cat >"$RUN_DIR/bin/id" <<'EOF'
#!/usr/bin/env bash
if [[ "${2:-}" == postgres ]]; then printf '26\n'; else exec /usr/bin/id "$@"; fi
EOF
chmod +x "$RUN_DIR/bin/id"
mkdir -p "$RUN_DIR/postgres-tls" "$RUN_DIR/backend-tls"
env PATH="$RUN_DIR/bin:$PATH" TLS_DIR="$TLS" TLS_MODE=behind-proxy DASHBOARD_EXPOSURE=public \
  POSTGRES_TLS_DIR="$RUN_DIR/postgres-tls" BACKEND_TLS_DIR="$RUN_DIR/backend-tls" \
  MONITORING_ENABLED=true GRAFANA_BIND=127.0.0.1 bash "$CERT_INIT_SCRIPT" >"$RUN_DIR/service-output" 2>&1
generated_cert=$(sha256sum "$RUN_DIR/postgres-tls/postgres.crt")
env PATH="$RUN_DIR/bin:$PATH" TLS_DIR="$TLS" TLS_MODE=behind-proxy DASHBOARD_EXPOSURE=public \
  POSTGRES_TLS_DIR="$RUN_DIR/postgres-tls" bash "$CERT_INIT_SCRIPT" >"$RUN_DIR/service-output" 2>&1
[[ $(sha256sum "$RUN_DIR/postgres-tls/postgres.crt") == "$generated_cert" ]] || fail 'a rerun regenerated a valid certificate'
for pair in "$RUN_DIR/postgres-tls/postgres" "$RUN_DIR/backend-tls/backend" "$TLS/monitoring"; do
  pair_matches "$pair.crt" "$pair.key" || fail "service TLS pair is unusable"
  expected_mode=640
  [[ "$pair" == "$RUN_DIR/postgres-tls/postgres" ]] && expected_mode=600
  [[ "$(mode "$pair.key")" == "$expected_mode" ]] || fail "service key mode is incompatible with its reader"
done
openssl verify -CAfile "$TLS/monitoring.crt" -verify_ip 127.0.0.1 "$TLS/monitoring.crt" >/dev/null || fail "Grafana certificate cannot authenticate its private listener"
openssl pkcs12 -in "$RUN_DIR/backend-tls/backend.p12" -passin pass: -info -noout >/dev/null 2>&1 || fail "backend store is unusable"
env PATH="$RUN_DIR/bin:$PATH" TLS_DIR="$TLS" TLS_MODE=behind-proxy DASHBOARD_EXPOSURE=public \
  MONITORING_ENABLED=true GRAFANA_BIND=192.168.25.1 bash "$CERT_INIT_SCRIPT" >"$RUN_DIR/service-output" 2>&1
openssl verify -CAfile "$TLS/monitoring.crt" -verify_ip 192.168.25.1 "$TLS/monitoring.crt" >/dev/null || fail "changed Grafana binding did not renew its certificate"
echo 'PASS: PostgreSQL/backend/Grafana service TLS material generated and validated'

# Institutional leaves only need the configured management identity.
TLS="$RUN_DIR/operator-tls"
mkdir "$TLS"
cert_init behind-proxy || { cat "$RUN_DIR/output" >&2; fail 'operator fixture CA generation failed'; }
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj /CN=management.example.org \
  -addext 'subjectAltName=DNS:management.example.org' \
  -keyout "$TLS/internal-key.pem" -out "$TLS/internal-cert.pem" >/dev/null 2>&1
operator_digest=$(sha256sum "$TLS/internal-cert.pem")
env PATH="$RUN_DIR/bin:$PATH" TLS_DIR="$TLS" TLS_MODE=behind-proxy DASHBOARD_EXPOSURE=internal \
  DASHBOARD_BASE_URL=https://management.example.org:8443 \
  bash "$CERT_INIT_SCRIPT" >"$RUN_DIR/output" 2>&1 ||
  { cat "$RUN_DIR/output" >&2; fail 'valid management-only operator certificate refused'; }
[[ $(sha256sum "$TLS/internal-cert.pem") == "$operator_digest" ]] || fail 'operator management certificate replaced'
selected_anchor=$(selfhost_python -c \
  'from chronicle_ops.common import dashboard_ca; import sys; print(dashboard_ca(sys.argv[1]))' "$TLS")
[[ "$selected_anchor" == "$TLS/internal-cert.pem" ]] || fail 'unrelated retained CA selected for the operator certificate'
env PATH="$RUN_DIR/bin:$PATH" TLS_DIR="$TLS" TLS_MODE=behind-proxy DASHBOARD_EXPOSURE=internal \
  DASHBOARD_BASE_URL=https://wrong.example.org \
  bash "$CERT_INIT_SCRIPT" >"$RUN_DIR/output" 2>&1 && fail 'operator certificate accepted for wrong management identity'
echo 'PASS: operator certificate preserved and checked against the configured management identity'
