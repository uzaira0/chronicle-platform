#!/bin/sh
# Makes the local-https mode's certificate authority reachable by a human with a phone.
#
# In that mode Caddy signs the server certificate with a CA it generated itself, so every
# device rejects the server until that CA is installed on it. The CA is already downloadable
# at http://$DOMAIN/local-ca.crt (see the :80 block in Caddyfile.split.local); this only
# solves the last step, which is getting that URL into a phone without typing an IP address
# into a mobile browser.
#
# Runs once, after web is healthy, and only in overlays/mode-local-https.yml.
set -eu

CA_SRC=/data/caddy/pki/authorities/local/root.crt
CA_OUT=/out/local-ca.crt
if [ "${LOCAL_HTTP_PORT:-80}" = 80 ]; then
  URL="http://${DOMAIN}/local-ca.crt"
else
  URL="http://${DOMAIN}:${LOCAL_HTTP_PORT}/local-ca.crt"
fi

# Caddy provisions the CA lazily, on the first certificate it issues. The healthcheck web
# waits for proves the listener answers, which is after that -- but the file is written by a
# background job, so allow a few seconds rather than racing it.
i=0
while [ ! -s "$CA_SRC" ] && [ "$i" -lt 30 ]; do
  i=$((i + 1))
  sleep 1
done

if [ ! -s "$CA_SRC" ]; then
  echo "FATAL: Caddy has not created a local CA at ${CA_SRC}." >&2
  echo "       Is DOMAIN=${DOMAIN} an address this machine actually has? Caddy cannot" >&2
  echo "       issue a certificate for a name that resolves nowhere." >&2
  exit 1
fi

# A copy beside the compose file, for the researcher's own laptop and for any device that
# is easier to load a file onto than to point at a URL.
cp "$CA_SRC" "$CA_OUT"
# This one-shot runs as root; leave the copy owned like the directory it lands in.
chown "$(stat -c '%u:%g' /out)" "$CA_OUT"
chmod 644 "$CA_OUT"

echo
echo "======================================================================"
echo " This stack's certificate authority (trial mode)"
echo "======================================================================"
echo
echo "  The invitation link carries this CA, and the Chronicle app trusts it for this"
echo "  server only. The phone's browser does not: even past its warning, Chrome on"
echo "  Android can refuse the invitation page's request to this server and show"
echo "  \"Invitation unavailable\"."
echo
echo "  Install the CA on a test device that opens the invitation in its browser, or"
echo "  that enrolls by typing the server address instead of using the link:"
echo "  1. Put the device on the SAME wifi as this machine."
echo "  2. Scan the QR code below, or open:  ${URL}"
echo "  3. Android: Settings -> Security -> Encryption & credentials ->"
echo "             Install a certificate -> CA certificate."
echo "     iOS:     the profile downloads, then Settings -> General ->"
echo "             VPN & Device Management -> install it, THEN"
echo "             Settings -> General -> About -> Certificate Trust"
echo "             Settings -> turn it on. iOS needs both steps."
echo
qrencode -t ANSIUTF8 -m 2 "$URL" || echo "  (could not render the QR code — use the URL above)"
echo
echo "  A copy is also in the configured state directory at tls/local-ca.crt."
echo
echo "  This CA is for YOUR OWN test devices. For a real study use a certificate"
echo "  participants' phones already trust"
echo "  (overlays/mode-behind-proxy-internal.yml or overlays/mode-own-tls-internal.yml)."
echo "======================================================================"
echo
