#!/usr/bin/env bash
set -euo pipefail

output_dir=${1:?usage: generate-postgres-tls.sh OUTPUT_DIR}
umask 077
mkdir -p "$output_dir"
test ! -e "$output_dir/postgres.key" || {
  echo "refusing to overwrite existing PostgreSQL TLS material" >&2
  exit 1
}

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$work_dir/ca.key"
openssl req -x509 -new -sha256 -days 825 \
  -key "$work_dir/ca.key" \
  -subj "/CN=Chronicle Hetzner PostgreSQL CA" \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -out "$output_dir/ca.crt"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$output_dir/postgres.key"
openssl req -new -sha256 \
  -key "$output_dir/postgres.key" \
  -subj "/CN=postgres" \
  -out "$work_dir/postgres.csr"
printf '%s\n' 'subjectAltName=DNS:postgres' 'extendedKeyUsage=serverAuth' \
  'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid,issuer' > "$work_dir/extensions"
openssl x509 -req -sha256 -days 397 \
  -in "$work_dir/postgres.csr" \
  -CA "$output_dir/ca.crt" \
  -CAkey "$work_dir/ca.key" \
  -CAcreateserial \
  -extfile "$work_dir/extensions" \
  -out "$output_dir/postgres.crt"

chmod 0600 "$output_dir/postgres.key"
chmod 0644 "$output_dir/postgres.crt" "$output_dir/ca.crt"
# Strict, as Python 3.13+ clients verify: a CA-signed leaf without an Authority Key Identifier fails here.
openssl verify -x509_strict -CAfile "$output_dir/ca.crt" "$output_dir/postgres.crt"
