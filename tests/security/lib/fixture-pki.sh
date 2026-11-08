#!/usr/bin/env bash
# Throwaway test PKI for the load-balancer fixtures of the release smoke and the topology drill.
#
# Every CA-signed certificate carries subjectKeyIdentifier and authorityKeyIdentifier. Python 3.13+ verifies
# with VERIFY_X509_STRICT by default and refuses a CA-signed leaf without an Authority Key Identifier
# ("Missing Authority Key Identifier"); `openssl x509 -req -extfile` writes only the extensions it is given.
# The product's own issuer (selfhost/cert-init.sh) sets both; these fixtures must too.

# fixture_ca DIR CN: self-signed CA at DIR/ca.key, DIR/ca.crt.
fixture_ca() {
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$2" \
    -keyout "$1/ca.key" -out "$1/ca.crt" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -addext subjectKeyIdentifier=hash >/dev/null 2>&1
}

# fixture_leaf_ext DIR NAME HOST: the extension file for a TLS server leaf for HOST at DIR/NAME.ext.
fixture_leaf_ext() {
  printf '%s\n' "subjectAltName=DNS:$3" 'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' 'extendedKeyUsage=serverAuth' \
    'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid,issuer' >"$1/$2.ext"
}

# fixture_leaf DIR NAME HOST: key, CSR and DIR/ca-signed server leaf for HOST at DIR/NAME.{key,csr,ext,crt}.
fixture_leaf() {
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$3" \
    -keyout "$1/$2.key" -out "$1/$2.csr" >/dev/null 2>&1 &&
  fixture_leaf_ext "$1" "$2" "$3" &&
  openssl x509 -req -in "$1/$2.csr" -CA "$1/ca.crt" -CAkey "$1/ca.key" -CAcreateserial -days 2 \
    -extfile "$1/$2.ext" -out "$1/$2.crt" >/dev/null 2>&1
}
