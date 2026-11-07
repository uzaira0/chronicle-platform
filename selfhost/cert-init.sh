#!/usr/bin/env bash
# Prepares ./tls so Caddy can actually read what it is asked to serve, as a one-shot compose
# service so `docker compose up -d` produces a working stack with no prior step. It has two
# jobs, and which ones apply is decided by the mode overlay that set TLS_MODE and
# DASHBOARD_EXPOSURE on this service.
#
# Both jobs exist because of the same constraint: Caddy runs as uid 10001, gid 0, with
# cap_drop: ALL. It can read a key only through the group-read bit, so a private key at 0600
# owned by anyone else is unreadable and the listener fails to start.
set -euo pipefail

: "${TLS_MODE:=behind-proxy}"
: "${DASHBOARD_EXPOSURE:=public}"
: "${DOMAIN:=localhost}"
: "${INTERNAL_BIND:=127.0.0.1}"
: "${INTERNAL_CERT_SANS:=}"
: "${TLS_DIR:=/tls}"

# Docker creates a missing bind-mount source as 0755 root, which is already traversable.
# Set it anyway so a directory the operator created as 0700 does not silently deny Caddy.
chmod 755 "$TLS_DIR"

# Caddy runs as uid 10001, gid 0 with no capabilities: it reads a file through the owner bits
# only if it owns it, otherwise through the group bits for gid 0. So each file stays owned by
# whoever owns ./tls (the operator, who can then renew it with a plain cp), in group 0, and
# the key is 0640: readable by Caddy, never world-readable on the host. A root-owned ./tls,
# or an owner this container cannot map, falls back to root ownership.
TLS_OWNER="$(stat -c %u "$TLS_DIR" 2>/dev/null || stat -f %u "$TLS_DIR")"
protect() { # <path> <mode>
  chown "${TLS_OWNER}:0" "$1" 2>/dev/null || chown 0:0 "$1"
  chmod "$2" "$1"
}

# A nonempty file is not necessarily usable: accept only a certificate and private key that
# parse and belong together. -passin keeps an encrypted key from waiting for a passphrase.
valid_pair() { # <cert> <key>
  local cert_public key_public
  cert_public="$(openssl x509 -in "$1" -noout -pubkey 2>/dev/null)" &&
    key_public="$(openssl pkey -passin pass: -in "$2" -pubout 2>/dev/null)" &&
    [[ -n "$cert_public" && "$cert_public" == "$key_public" ]]
}

covers_sans() { # certificate SANs
  local identity check_option
  for identity in ${2//,/ }; do
    check_option=-checkhost
    [[ "$identity" != IP:* ]] || check_option=-checkip
    openssl x509 "$check_option" "${identity#*:}" -noout -in "$1" >/dev/null 2>&1 || return 1
  done
}

prepare_service_pair() { # directory name SAN owner [key mode]
  local directory="$1" name="$2" san="$3" owner="$4" key_mode="${5:-640}" crt key tmp_crt tmp_key
  local renew=false
  mkdir -p "$directory"
  crt="$directory/$name.crt"; key="$directory/$name.key"
  if ! valid_pair "$crt" "$key" || ! openssl x509 -checkend $((30 * 86400)) -noout -in "$crt" >/dev/null 2>&1; then
    renew=true
  else
    covers_sans "$crt" "$san" || renew=true
  fi
  if [[ "$renew" == true ]]; then
    tmp_crt="$(mktemp "$directory/.cert.XXXXXX")"
    tmp_key="$(mktemp "$directory/.key.XXXXXX")"
    if ! openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
        -keyout "$tmp_key" -out "$tmp_crt" -subj "/CN=$name" \
        -addext "subjectAltName=$san" >/dev/null 2>&1 || ! valid_pair "$tmp_crt" "$tmp_key"; then
      rm -f "$tmp_crt" "$tmp_key"
      echo "FATAL: could not generate $name service certificate" >&2
      return 1
    fi
    mv -f "$tmp_crt" "$crt"; mv -f "$tmp_key" "$key"
  fi
  chown "$owner" "$directory" "$crt" "$key"
  chmod 755 "$directory"; chmod 644 "$crt"; chmod "$key_mode" "$key"
  service_certificates+=("$crt")
}

service_certificates=()
if [[ -n "${POSTGRES_TLS_DIR:-}" ]]; then
  prepare_service_pair "$POSTGRES_TLS_DIR" postgres 'DNS:postgres,DNS:localhost,IP:127.0.0.1' "$(id -u postgres):$(id -g postgres)" 600
fi
if [[ -n "${BACKEND_TLS_DIR:-}" ]]; then
  # cert-init and the optional monitoring-cert-init both prepare this pair. Neither waits on the
  # other in Compose (monitoring must never gate Chronicle), so they serialize on the volume.
  mkdir -p "$BACKEND_TLS_DIR"
  exec 9>"$BACKEND_TLS_DIR/.cert-init.lock"
  flock 9
  prepare_service_pair "$BACKEND_TLS_DIR" backend 'DNS:backend,DNS:localhost,IP:127.0.0.1' 100:101
  openssl pkcs12 -export -in "$BACKEND_TLS_DIR/backend.crt" -inkey "$BACKEND_TLS_DIR/backend.key" \
    -name rhizomessl -passout pass: -out "$BACKEND_TLS_DIR/.backend.p12.new"
  chown 100:101 "$BACKEND_TLS_DIR/.backend.p12.new"
  chmod 600 "$BACKEND_TLS_DIR/.backend.p12.new"
  mv -f "$BACKEND_TLS_DIR/.backend.p12.new" "$BACKEND_TLS_DIR/backend.p12"
  exec 9>&-
fi
if [[ "${MONITORING_ENABLED:-false}" == true ]]; then
  monitoring_directory=${MONITORING_TLS_DIR:-$TLS_DIR}
  prepare_service_pair "$monitoring_directory" monitoring "DNS:grafana,DNS:localhost,IP:127.0.0.1,IP:${GRAFANA_BIND:-127.0.0.1}" "${TLS_OWNER}:0"
  # Host-side health, rotation and viewer clients need only the public trust certificate.
  cp "$monitoring_directory/monitoring.crt" "$TLS_DIR/.monitoring.crt.new"
  protect "$TLS_DIR/.monitoring.crt.new" 644
  mv -f "$TLS_DIR/.monitoring.crt.new" "$TLS_DIR/monitoring.crt"
fi

if ((${#service_certificates[@]})); then
  service_digest_file="${SERVICE_CERTIFICATE_DIGEST_FILE:-$TLS_DIR/service-certificates.sha256}"
  sha256sum "${service_certificates[@]}" >"$service_digest_file"
  protect "$service_digest_file" 644
fi

# ------------------------------------------------------------- the operator's certificate
if [[ "$TLS_MODE" == own-tls ]]; then
  if [[ -s "$TLS_DIR/cert.pem" && -s "$TLS_DIR/key.pem" ]]; then
    # Close a copied key to others first, so a key this check rejects is not left readable.
    chmod go-rwx "$TLS_DIR/key.pem"
    valid_pair "$TLS_DIR/cert.pem" "$TLS_DIR/key.pem" || {
      echo "FATAL: ./tls/cert.pem and ./tls/key.pem are not a matching certificate and unencrypted private key" >&2
      exit 1
    }
    protect "$TLS_DIR/cert.pem" 644
    protect "$TLS_DIR/key.pem" 640
    echo "  ok   ./tls/cert.pem and ./tls/key.pem prepared for Caddy"
  else
    echo "FATAL: TLS_MODE=own-tls but ./tls/cert.pem or ./tls/key.pem is missing or empty" >&2
    exit 1
  fi
fi

# ------------------------------------------------------- the internal dashboard listener
# The internal listener runs TLS so the dashboard password never crosses the wire in clear.
# Caddy's own `tls internal` cannot serve it: the site block is a bare :PORT reached by IP,
# so the local CA has no name to issue for and the handshake fails outright. A self-signed
# certificate with explicit IP SANs does work.
[[ "$DASHBOARD_EXPOSURE" == internal ]] || exit 0

CRT="$TLS_DIR/internal-cert.pem"
KEY="$TLS_DIR/internal-key.pem"

# The participant-facing DOMAIN is deliberately NOT in this certificate. The public listener
# owns that name through either Caddy's local CA or the operator's real certificate. Loading a
# second self-signed certificate for the same name lets Caddy select the dashboard certificate
# on the public listener and breaks the documented CA trust path for Android. The private
# dashboard defaults to localhost/INTERNAL_BIND; an operator who needs another management-only
# name can add it explicitly through INTERNAL_CERT_SANS.
SAN="DNS:localhost,DNS:web,IP:127.0.0.1,IP:::1"
[[ "$INTERNAL_BIND" != 127.0.0.1 && "$INTERNAL_BIND" != 0.0.0.0 ]] && SAN="${SAN},IP:${INTERNAL_BIND}"
# With POOL_LISTENER_TLS the load balancer reaches the pool listener by HTTP_BIND.
POOL_SAN=""
[[ "${POOL_LISTENER_TLS:-true}" == true && "${HTTP_BIND:-127.0.0.1}" != 0.0.0.0 ]] && POOL_SAN="IP:${HTTP_BIND:-127.0.0.1}"
EXTRA_SANS="${POOL_SAN}${INTERNAL_CERT_SANS:+${POOL_SAN:+,}$INTERNAL_CERT_SANS}"
[[ -n "$EXTRA_SANS" ]] && SAN="${SAN},${EXTRA_SANS}"
management_host="${DASHBOARD_BASE_URL:-$INTERNAL_BIND}"
management_host="${management_host#https://}"
management_host="${management_host%%/*}"
if [[ "$management_host" == '['* ]]; then
  management_host="${management_host#'['}"
  management_host="${management_host%%']'*}"
elif [[ -n "${DASHBOARD_BASE_URL:-}" ]]; then
  management_host="${management_host%%:*}"
fi
REQUIRED_SAN="DNS:$management_host"
[[ "$management_host" != *:* && ! "$management_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || REQUIRED_SAN="IP:$management_host"
SAN="${SAN},${REQUIRED_SAN}"


# Idempotent, so replacing these two files with a real certificate survives every `up`.
if [[ -s "$CRT" && -s "$KEY" ]]; then
  # Close a copied key to others first, so a key moved aside below is not left readable.
  chmod go-rwx "$KEY"
  if valid_pair "$CRT" "$KEY"; then
    # The generated pair lasts 825 days and nothing else renews it: replace it in its last 30
    # days. An operator's own certificate (any other subject) is theirs to renew; only warn.
    if openssl x509 -checkend $((30 * 86400)) -noout -in "$CRT" >/dev/null 2>&1; then
      expiring=false
    else
      expiring=true
    fi
    local_sans_match=false
    covers_sans "$CRT" "${REQUIRED_SAN}${EXTRA_SANS:+,$EXTRA_SANS}" && local_sans_match=true
    if [[ "$local_sans_match" == false && "$(openssl x509 -noout -subject -nameopt RFC2253 -in "$CRT" 2>/dev/null)" != 'subject=CN=chronicle-dashboard' ]]; then
      covers_sans "$CRT" "$REQUIRED_SAN" || {
        echo "FATAL: operator internal certificate does not cover management identity: $REQUIRED_SAN" >&2
        exit 1
      }
    fi
    if [[ ( "$expiring" == false && "$local_sans_match" == true ) ||
      "$(openssl x509 -noout -subject -nameopt RFC2253 -in "$CRT" 2>/dev/null)" != 'subject=CN=chronicle-dashboard' ]]; then
      [[ "$expiring" == false ]] ||
        echo "  warn ./tls/internal-cert.pem expires within 30 days; replace both internal-*.pem files" >&2
      protect "$CRT" 644
      protect "$KEY" 640
      echo "  ok   internal dashboard certificate already present (./tls/internal-cert.pem)"
      exit 0
    fi
    mv -f "$CRT" "$CRT.expired"
    mv -f "$KEY" "$KEY.expired"
    echo "  warn generated internal certificate expires within 30 days; moved aside as *.expired"
  else
    # Otherwise Caddy could never start. Keep the unusable pair for inspection and regenerate.
    mv -f "$CRT" "$CRT.invalid"
    mv -f "$KEY" "$KEY.invalid"
    echo "  warn internal certificate and key were not a matching pair; moved aside as *.invalid"
  fi
fi

# Generate beside the final names and rename only a complete, matching pair, so an
# interruption or a full disk never leaves files that the check above would have to reject.
TMP_KEY="$(mktemp "$TLS_DIR/.internal-key.XXXXXX")"
TMP_CRT="$(mktemp "$TLS_DIR/.internal-cert.XXXXXX")"
TMP_CSR="$TMP_CRT.csr"
TMP_EXT="$TMP_CRT.ext"
TMP_CA_KEY="$TMP_KEY.ca"
TMP_CA_CRT="$TMP_CRT.ca"
trap 'rm -f "$TMP_KEY" "$TMP_CRT" "$TMP_CSR" "$TMP_EXT" "$TMP_CA_KEY" "$TMP_CA_CRT"' EXIT
CA_CRT="$TLS_DIR/internal-ca.crt"
CA_KEY="$TLS_DIR/internal-ca.key"
if [[ ! -s "$CA_CRT" && ! -s "$CA_KEY" ]]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout "$TMP_CA_KEY" -out "$TMP_CA_CRT" -subj '/CN=Chronicle dashboard CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'subjectKeyIdentifier=hash' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
  valid_pair "$TMP_CA_CRT" "$TMP_CA_KEY"
  protect "$TMP_CA_CRT" 644
  protect "$TMP_CA_KEY" 600
  mv -f "$TMP_CA_KEY" "$CA_KEY"
  mv -f "$TMP_CA_CRT" "$CA_CRT"
fi
valid_pair "$CA_CRT" "$CA_KEY" && openssl x509 -checkend $((30 * 86400)) -noout -in "$CA_CRT" >/dev/null || {
  echo 'FATAL: dashboard CA needs reviewed trust-anchor replacement' >&2; exit 1;
}
printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' "$SAN" >"$TMP_EXT"
{ openssl req -new -newkey rsa:2048 -sha256 -nodes -keyout "$TMP_KEY" -out "$TMP_CSR" \
    -subj '/CN=chronicle-dashboard' >/dev/null 2>&1 &&
  openssl x509 -req -in "$TMP_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
    -days 825 -sha256 -extfile "$TMP_EXT" -out "$TMP_CRT" >/dev/null 2>&1 && valid_pair "$TMP_CRT" "$TMP_KEY"; } || {
  echo 'FATAL: could not generate the internal dashboard certificate' >&2; exit 1;
}

protect "$TMP_CRT" 644
protect "$TMP_KEY" 640
# -CAcreateserial leaves the CA's serial file root-owned in the operator's directory.
protect "$TLS_DIR/internal-ca.srl" 644
mv -f "$TMP_KEY" "$KEY"
mv -f "$TMP_CRT" "$CRT"

echo "  ok   generated a CA-signed certificate for the dashboard (./tls/internal-cert.pem)"
echo "       SANs: ${SAN}"
echo "       Browsers will warn until you trust it; replace both files to use a real cert."
