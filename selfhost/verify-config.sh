#!/usr/bin/env bash
# Single-source-of-truth check for the self-host bundle.
#
#   ./verify-config.sh
#
# A configuration value in this bundle can appear in up to four places:
#
#   .env.example          what the operator is told to set
#   docker-compose.yml    what is passed into the backend container
#   backend-entrypoint.sh the default applied when it is unset
#   config/*.template     where it is actually consumed
#
# Nothing enforces that those agree, and the failure is silent: add ${FOO} to a template,
# forget the compose passthrough, and the entrypoint's default is used instead of the
# operator's value with no warning. This script makes that a hard error.
#
# It also checks that all three supported Caddyfile variants share one route definition,
# so their public-ingest and private-dashboard listeners cannot drift.
set -uo pipefail

cd "$(dirname "$0")" || exit 1
export CHRONICLE_HOST_UID="${CHRONICLE_HOST_UID:-$(id -u)}"
export CHRONICLE_HOST_GID="${CHRONICLE_HOST_GID:-$(id -g)}"

FAILED=0
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILED=1; }
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; }

vars_in() { grep -ohE '\$\{[A-Z_][A-Z0-9_]*' "$@" 2>/dev/null | sed 's/\${//' | sort -u; }

TEMPLATE_VARS=$(vars_in config/*.template)
ENTRYPOINT_DEFAULTS=$(grep -oE '^: "\$\{[A-Z_][A-Z0-9_]*' backend-entrypoint.sh | sed 's/.*{//' | sort -u)
ENTRYPOINT_REQUIRED=$(sed -n 's/^for required in \(.*\); do/\1/p' backend-entrypoint.sh | tr ' ' '\n' | sort -u)
# A third way the entrypoint can guarantee a value: compute one. CHRONICLE_INTERNAL_WEB_SECRET
# is generated per boot rather than defaulted, so it never takes the `: "${VAR:=...}"` shape,
# but envsubst is just as certain to find it set.
ENTRYPOINT_GENERATED=$(grep -oE '^[[:space:]]*[A-Z_][A-Z0-9_]*="?\$\(' backend-entrypoint.sh |
  sed 's/=.*//; s/^[[:space:]]*//' | sort -u)
ENV_EXAMPLE_VARS=$(grep -oE '^#? *[A-Z_][A-Z0-9_]*=' .env.example | tr -d '# =' | sort -u)
# Only the backend service's environment block — a plain grep would also pick up
# postgres's POSTGRES_INITDB_ARGS and friends, which the backend never sees.
COMPOSE_PASSED=$(awk '
  /^  [a-z]/            { in_svc = ($0 ~ /^  backend:/); in_env = 0 }
  in_svc && /^    environment:/ { in_env = 1; next }
  in_svc && /^    [a-z]/       { in_env = 0 }
  in_env && /^      [A-Z_]/    { sub(/:.*/, ""); gsub(/ /, ""); print }
' docker-compose.yml | sort -u)
# Credentials reach the backend as files instead (secrets-init.sh writes them, the entrypoint's
# `for pair in VAR:file ...` list loads them), so their absence from the environment block
# above is not a missing passthrough.
SECRET_FILE_PAIRS=$(awk '/^  for pair in /,/; do$/' backend-entrypoint.sh | grep -oE '[A-Z_][A-Z0-9_]*:[a-z-]+')
FILE_PASSED=$(printf '%s\n' "$SECRET_FILE_PAIRS" | sed 's/:.*//' | sort -u)
COMPOSE_PASSED=$(sort -u <(printf '%s\n' "$COMPOSE_PASSED") <(printf '%s\n' "$FILE_PASSED") | sed '/^$/d')

echo "Config contract"

# 1. Every variable a template consumes must be either defaulted or required at boot.
#    Otherwise envsubst yields an empty string and the backend parses invalid YAML.
missing_default=$(comm -23 <(echo "$TEMPLATE_VARS") \
  <(sort -u <(echo "$ENTRYPOINT_DEFAULTS") <(echo "$ENTRYPOINT_REQUIRED") <(echo "$ENTRYPOINT_GENERATED")))
if [[ -n "$missing_default" ]]; then
  fail "template vars with no default, generator, or required-check in backend-entrypoint.sh:"
  echo "$missing_default" | sed 's/^/         /'
else
  ok "every config/*.template variable is defaulted or required ($(echo "$TEMPLATE_VARS" | wc -l) vars)"
fi

# 2. Every secret the entrypoint hard-requires must be documented for the operator.
undocumented=$(comm -23 <(echo "$ENTRYPOINT_REQUIRED") <(echo "$ENV_EXAMPLE_VARS"))
if [[ -n "$undocumented" ]]; then
  fail "required secrets absent from .env.example: $(echo "$undocumented" | tr '\n' ' ')"
else
  ok "required secrets are documented in .env.example"
fi

# 2b. Every credential file the backend loads is one secrets-init writes for it.
unwritten=""
for pair in $SECRET_FILE_PAIRS; do
  grep -qE "^write /out/backend \"\\\$backend\" ${pair#*:} " secrets-init.sh || unwritten+="${pair#*:} "
done
if [[ -n "$SECRET_FILE_PAIRS" && -z "$unwritten" ]]; then
  ok "every backend credential file is written by secrets-init.sh ($(echo "$SECRET_FILE_PAIRS" | wc -l | tr -d ' ') files)"
else
  fail "backend credential files that secrets-init.sh does not write: ${unwritten:-none listed in backend-entrypoint.sh}"
fi

# 3. Every required secret must actually reach the container.
not_passed=$(comm -23 <(echo "$ENTRYPOINT_REQUIRED") <(echo "$COMPOSE_PASSED"))
if [[ -n "$not_passed" ]]; then
  fail "required secrets not passed to backend in docker-compose.yml: $(echo "$not_passed" | tr '\n' ' ')"
else
  ok "required secrets are passed through docker-compose.yml"
fi

# 4. A value passed by compose but never consumed is dead config the operator will
#    reasonably expect to do something.
for v in $COMPOSE_PASSED; do
  # These settings are consumed directly by Kotlin services rather than a rendered template:
  # security/session values bind to Spring, while the trusted proxy CIDRs are read by
  # ClientIpResolver.
  # CHRONICLE_SECURITY_* are bound by Spring relaxed binding inside the app, not by a template.
  # LOG_DIR is read by chronicle-server/src/main/resources/log4j2.xml
  # (${env:LOG_DIR:-/var/log/chronicle}), which is inside the image and not visible here.
  # LOG_FORMAT is read directly by log4j2.xml and does not pass through a rendered config
  # template. CHRONICLE_RECORD_STAFF_IP is read directly by ClientIpRecord.
  case "$v" in
    CHRONICLE_SERVER_*|CHRONICLE_SECURITY_*|CHRONICLE_RECORD_STAFF_IP|\
    CHRONICLE_SESSION_IDLE_MINUTES|CHRONICLE_TRUSTED_PROXY_CIDRS|\
    POSTGRES_HOST|POSTGRES_PORT|LOG_DIR|LOG_FORMAT) continue ;;
  esac
  if ! grep -q "\${$v}" config/*.template 2>/dev/null && ! grep -q "\${$v:" backend-entrypoint.sh 2>/dev/null; then
    fail "docker-compose.yml passes $v to the backend but nothing consumes it"
  fi
done
[[ $FAILED -eq 0 ]] && ok "no dead variables passed to the backend"

# 4b. A value the operator is told to set, which a template consumes, but which never
#     reaches the container: the entrypoint default wins and the setting silently does
#     nothing. This is worse than an error -- TESTING_LOGIN_ENABLED=true looked applied.
silent=$(comm -12 <(echo "$TEMPLATE_VARS") <(echo "$ENV_EXAMPLE_VARS") | comm -23 - <(echo "$COMPOSE_PASSED"))
if [[ -n "$silent" ]]; then
  fail "documented in .env.example and used by a template, but not passed to the backend (setting them does nothing): $(echo "$silent" | tr '\n' ' ')"
else
  ok "every documented setting a template consumes actually reaches the backend"
fi

# The backend session-minting endpoint verifies the dashboard password against this hash;
# without the rendered field POST /chronicle/v3/auth/dashboard-login rejects every password.
if grep -Fq 'dashboardPasswordHash: "${DASHBOARD_PASSWORD_HASH}"' config/chronicle-auth.yaml.template; then
  ok "dashboard bcrypt hash is rendered into the backend auth configuration"
else
  fail "config/chronicle-auth.yaml.template does not render DASHBOARD_PASSWORD_HASH for dashboard sessions"
fi

echo
echo "Route definitions"

# 5. Every supported listener must import the shared snippets rather than inlining routes,
#    or its public-ingest and private-dashboard lists can silently diverge.
CADDYFILES="Caddyfile.split Caddyfile.split.local Caddyfile.split.tls"
for f in $CADDYFILES; do
  if ! grep -q '^import snippets.caddy' "$f"; then
    fail "$f does not import snippets.caddy"
  elif grep -qE '^[[:space:]]*reverse_proxy /chronicle' "$f"; then
    fail "$f defines routes inline instead of importing them from caddy/snippets.caddy"
  else
    ok "$f imports the shared route definitions"
  fi
done
if ! grep -Fq 'respond /datastore/* 404' caddy/snippets.caddy; then
  fail "shared Caddy deny rules do not block the retired top-level /datastore/* alias"
else
  ok "shared Caddy deny rules block the retired top-level /datastore/* alias"
fi

for access_log_filter in \
  'format filter {' \
  'request>headers delete' \
  'request>uri delete' \
  'request>remote_ip ip_mask 16 32' \
  'request>client_ip ip_mask 16 32' \
  'wrap json'; do
  if ! grep -Fq "$access_log_filter" caddy/snippets.caddy; then
    fail "caddy/snippets.caddy does not redact access-log field: ${access_log_filter}"
  fi
done

# 6. The direct backend/admin surfaces blocked by the hardened reference must be refused here on
#    every listener, including the internal one.
for f in $CADDYFILES; do
  if ! grep -q 'import chronicle_deny_direct' "$f"; then
    fail "$f does not deny the direct backend routes (/chronicle/datastore, /principal, ...)"
  else
    ok "$f denies direct backend/admin routes"
  fi
done

# 7. Anything reverse-proxied must not also be denied, and vice versa — a prefix appearing
#    in both lists means one of them is dead and the intent is ambiguous.
#    `handle <prefix> { … reverse_proxy … }` counts as proxying that prefix too — the web
#    API is served that way so its rewrite cannot un-match its own block.
proxied=$(grep -oE '(reverse_proxy|handle) (/chronicle|/prometheus)[^ ]*' caddy/snippets.caddy | awk '{print $2}' | sort -u)
denied=$(grep -oE 'respond (/chronicle|/prometheus)[^ ]* 404' caddy/snippets.caddy | awk '{print $2}' | sort -u)
overlap=$(comm -12 <(echo "$proxied") <(echo "$denied"))
# chronicle_deny_dashboard_api deliberately mirrors chronicle_dashboard_api for the split
# public listener, so those are expected; anything else is not.
unexpected=$(comm -23 <(echo "$overlap") <(printf '%s\n' '/chronicle/api/web/*' '/chronicle/limits/*' | sort))
if [[ -n "$unexpected" ]]; then
  fail "prefixes both proxied and denied outside the split mirror: $(echo "$unexpected" | tr '\n' ' ')"
else
  ok "proxy and deny lists do not contradict each other"
fi

# Current mobile clients use v4 device operations and v3 generalized settings.
# /health reflects backend readiness; retired prefixes return 404 at the edge.
for route_contract in \
  'reverse_proxy /chronicle/v3/* https://backend:8443' \
  'reverse_proxy /chronicle/v4/* https://backend:8443' \
  'handle /health' \
  'rewrite * /chronicle/internal/health/ready' \
  'reverse_proxy https://backend:8443'; do
  if ! grep -Fq "$route_contract" caddy/snippets.caddy; then
    fail "Android mobile contract is missing public route: $route_contract"
  else
    ok "Android mobile contract exposes: $route_contract"
  fi
done

if grep -Fq 'respond @chronicle_retired_api 404' caddy/snippets.caddy; then
  ok "Retired mobile API prefixes are denied"
else
  fail "Retired mobile API prefixes must be denied"
fi

service_block() {
  awk -v service="$1" '
    $0 == "  " service ":" { in_service = 1; next }
    in_service && /^  [a-zA-Z0-9_-]+:$/ { exit }
    in_service { print }
  ' docker-compose.yml
}

echo
echo "Public origin validation"

public_host_validation_ok=true
for accepted_host in \
  'research.study-host.org' \
  '8.8.8.8' \
  '[2606:4700:4700::1111]'; do
  if ! ./guard-config.sh --validate-public-host "$accepted_host"; then
    fail "configuration guard rejects public host ${accepted_host}"
    public_host_validation_ok=false
  fi
done
for rejected_host in \
  '0.0.0.0' \
  '10.0.0.1' \
  '100.64.0.1' \
  '127.0.0.1' \
  '169.254.1.1' \
  '172.16.0.1' \
  '192.168.1.1' \
  '192.0.2.1' \
  '198.51.100.1' \
  '203.0.113.1' \
  '198.18.0.1' \
  '224.0.0.1' \
  '255.255.255.255' \
  'https://research.study-host.org' \
  'research.study-host.org/path' \
  'research.study-host.org:0' \
  'research.study-host.org:65536' \
  'https://localhost' \
  'https://reviewer.local' \
  'https://[::1]' \
  'https://[::ffff:192.0.2.1]' \
  'https://[2001:db8::1]' \
  'https://[fd00::1]' \
  'https://[fe80::1]' \
  'https://[ff02::1]' \
  '999.999.999.999' \
  'study.example.org' \
  'example.com' \
  'lab.internal' \
  'router.home.arpa' \
  'nas.lan'; do
  if ./guard-config.sh --validate-public-host "$rejected_host"; then
    fail "configuration guard accepts clearly non-public host ${rejected_host}"
    public_host_validation_ok=false
  fi
done
for accepted_origin in \
  'https://research.study-host.org' \
  'https://8.8.8.8' \
  'https://1.1.1.1:8443' \
  'https://[2606:4700:4700::1111]'; do
  if ! ./guard-config.sh --validate-public-origin "$accepted_origin"; then
    fail "configuration guard rejects HTTPS root origin ${accepted_origin}"
    public_host_validation_ok=false
  fi
done
for rejected_origin in \
  'research.study-host.org' \
  'http://research.study-host.org' \
  'ftp://research.study-host.org' \
  'https://user@research.study-host.org' \
  'https://research.study-host.org/' \
  'https://research.study-host.org/path' \
  'https://research.study-host.org?query=1' \
  'https://research.study-host.org#fragment' \
  'https://research.study-host.org:0' \
  'https://research.study-host.org:65536'; do
  if ./guard-config.sh --validate-public-origin "$rejected_origin"; then
    fail "configuration guard accepts invalid public root origin ${rejected_origin}"
    public_host_validation_ok=false
  fi
done
if ! grep -Fq 'local_trial_origin="https://${DOMAIN}"' guard-config.sh ||
   ! grep -Fq 'local_trial_origin+=":${local_https_port}"' guard-config.sh ||
   ! grep -Fq 'CHRONICLE_PUBLIC_BASE_URL must be empty or exactly ${local_trial_origin}' guard-config.sh; then
  fail "local trial mode does not bind its participant origin to DOMAIN and its selected HTTPS port"
else
  ok "local trial mode binds its participant origin to DOMAIN and its selected HTTPS port"
fi
if [[ "$public_host_validation_ok" == true ]]; then
  ok "public modes require valid public hosts and exact HTTPS root origins"
fi

config_guard_service=$(service_block config-guard)
if ! grep -Fq 'CHRONICLE_PUBLIC_BASE_URL:' <<<"$config_guard_service"; then
  fail "config-guard cannot validate an explicit CHRONICLE_PUBLIC_BASE_URL"
else
  ok "config-guard receives an explicit CHRONICLE_PUBLIC_BASE_URL"
fi

backend_service=$(service_block backend)
web_service=$(service_block web)
if ! grep -Fq '/chronicle/internal/health/ready' <<<"$backend_service"; then
  fail "backend healthcheck does not use dependency-aware readiness"
elif grep -Fq '/chronicle/v3/study' <<<"$backend_service"; then
  fail "backend healthcheck still treats an arbitrary study API response as healthy"
else
  ok "backend healthcheck uses dependency-aware readiness"
fi
if ! grep -A2 -F 'backend:' <<<"$web_service" | grep -F 'condition: service_healthy' >/dev/null; then
  fail "web starts before the backend is dependency-ready"
else
  ok "web waits for dependency-aware backend health"
fi

if ! grep -Fq 'window.__CHRONICLE_RUNTIME_CONFIG__' caddy/snippets.caddy ||
   ! grep -Fq 'serverUrl: "{$CHRONICLE_PUBLIC_BASE_URL}"' caddy/snippets.caddy ||
   ! grep -Fq 'allowPrivateServerUrl: {$CHRONICLE_ALLOW_PRIVATE_ENROLLMENT_ORIGIN:false}' caddy/snippets.caddy ||
   ! grep -Fq 'CHRONICLE_PUBLIC_BASE_URL:' <<<"$web_service"; then
  fail "self-host dashboard does not use the canonical participant-facing public origin"
elif ! grep -Fq 'CHRONICLE_ALLOW_PRIVATE_ENROLLMENT_ORIGIN: "true"' overlays/mode-local-https.yml; then
  fail "local HTTPS trial does not explicitly permit its LAN enrollment origin"
elif grep -R -F -q \
  'CHRONICLE_ALLOW_PRIVATE_ENROLLMENT_ORIGIN: "true"' \
  overlays \
  --exclude='mode-local-https.yml'; then
  fail "a production-facing deployment mode enables private enrollment origins"
else
  ok "self-host dashboard uses the canonical participant-facing public origin"
fi

# Invitation links carry the CA root only where the bundle's own CA signs the certificate.
if ! sed '/^[[:space:]]*#/d' caddy/snippets.caddy | grep -F 'localCa: {$CHRONICLE_LOCAL_CA:false}' >/dev/null ||
   ! grep -Eq '^[[:space:]]+CHRONICLE_LOCAL_CA: "true"[[:space:]]*(#.*)?$' overlays/mode-local-https.yml ||
   ! awk '/^:8081 \{/,/^}/' Caddyfile.split.local | grep -E '^[[:space:]]*import local_ca_download[[:space:]]*(#.*)?$' >/dev/null; then
  fail "local HTTPS trial dashboard cannot put its CA root in invitation links"
elif grep -R -E -q "^[[:space:]]+CHRONICLE_LOCAL_CA: [\"']?true[\"']?[[:space:]]*(#.*)?$" overlays --exclude='mode-local-https.yml'; then
  fail "a deployment mode without the bundle's private CA puts a CA root in invitation links"
else
  ok "only the local HTTPS trial puts its CA root in invitation links"
fi

if ! grep -Fq ': "${CHRONICLE_PUBLIC_BASE_URL:=https://${DOMAIN}}"' backend-entrypoint.sh ||
   ! grep -Fq 'public-base-url: "${CHRONICLE_PUBLIC_BASE_URL}"' config/mobile-security.yaml.template; then
  fail "enrollment manifests do not use the configured canonical https://DOMAIN origin"
else
  ok "enrollment manifests use the configured canonical public HTTPS origin"
fi

if awk '/^  [a-z-]+:$/ { in_web = ($1 == "web:") } in_web && /^    init: true$/ { found = 1 } END { exit !found }' docker-compose.yml
then
  ok "web runs an init that reaps its HTTPS healthcheck's helper processes"
else
  fail "web has no init: zombie ssl_client processes from its healthcheck exhaust pids_limit"
fi

if grep -Fq 'SAN="${SAN},DNS:${DOMAIN}"' cert-init.sh; then
  fail "internal dashboard certificate claims the participant-facing DOMAIN"
  printf '       That certificate can shadow the local-CA/public certificate on Caddy\047s HTTPS listener.\n'
elif ! grep -Fq 'SAN="DNS:localhost,DNS:web,IP:127.0.0.1,IP:::1"' cert-init.sh ||
     ! grep -Fq 'INTERNAL_CERT_SANS' cert-init.sh; then
  fail "internal dashboard certificate SAN ownership is incomplete"
else
  ok "public and internal TLS certificate names cannot shadow one another"
fi

if PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY_ORIGIN'
from chronicle_ops.env_migration import merge_env
from chronicle_ops.envfile import read_env, value
old = {"CHRONICLE_PUBLIC_BASE_URL": "'https://alias.example.org:8443'", "POSTGRES_DB": "custom"}
text = merge_env(old, open('.env.example').read(), None, '.', ['docker-compose.yml'], preserve_images=True)
import tempfile
from pathlib import Path
with tempfile.TemporaryDirectory() as folder:
    path = Path(folder) / 'settings'
    path.write_text(text)
    saved = read_env(path)
assert value(saved, 'CHRONICLE_PUBLIC_BASE_URL') == 'https://alias.example.org:8443'
assert value(saved, 'POSTGRES_DB') == 'custom'
PY_ORIGIN
then
  ok "environment merge preserves saved public origin and database settings (host acceptance remains separate)"
else
  fail "environment merge loses saved operator settings"
fi

for reviewer_contract in \
  'reviewer-enrollment:' \
  'enabled: ${CHRONICLE_REVIEWER_ACCESS_ENABLED}' \
  'secret: "${CHRONICLE_REVIEWER_ACCESS_SECRET}"' \
  'study-id: "${CHRONICLE_REVIEWER_STUDY_ID}"' \
  'participant-id: "${CHRONICLE_REVIEWER_PARTICIPANT_ID}"'; do
  if ! grep -Fq "$reviewer_contract" config/mobile-security.yaml.template; then
    fail "reviewer bootstrap config is missing: $reviewer_contract"
  fi
done
[[ $FAILED -eq 0 ]] && ok "reviewer bootstrap is fully operator-configured and disabled by default"

if ! grep -Fq 'doctor_add reviewer-scope' doctor.sh; then
  fail "reviewer setup can be enabled without verifying the live synthetic study/participant scope"
elif ! grep -Fq './chronicle doctor' README.md ||
     ! grep -Fq 'reviewer-scope' docs/CONFIGURATION.md; then
  fail "reviewer live-scope creation and reset checks are not documented"
else
  ok "doctor and reviewer rotation verify the live synthetic reviewer scope"
fi

for public_contract in \
  'redir /reviewer /chronicle/reviewer permanent' \
  'reverse_proxy /chronicle/v4/mobile/reviewer-enrollment https://backend:8443'; do
  if ! grep -Fq "$public_contract" caddy/snippets.caddy; then
    fail "public participant/reviewer route is missing: $public_contract"
  else
    ok "public route is explicit: $public_contract"
  fi
done
for f in $CADDYFILES; do
  imports=$(grep -c 'import chronicle_public_entrypoints' "$f")
  if [[ "$imports" -lt 2 ]]; then
    fail "$f does not expose policy/reviewer entrypoints on both listeners"
  elif ! awk '
      /^:8081 \{/ { inside = 1; entry = 0; gate = 0; next }
      inside && /import chronicle_public_entrypoints/ { entry = NR }
      inside && /import chronicle_dashboard_guard/ { gate = NR }
      inside && /^}/ { exit !(entry > 0 && gate > entry) }
      END { if (!inside) exit 1 }
    ' "$f"; then
    fail "$f puts public policy/reviewer entrypoints behind dashboard authentication"
  else
    ok "$f serves public policy/reviewer entrypoints before dashboard authentication"
  fi
done

# 8. The rate limiter is a compiled-in plugin, not a built-in. Release Compose must use
#    the dedicated digest-pinned Caddy image and every variant must declare the handler
#    order -- stock Caddy cannot parse the config.
if grep -q 'rate_limit' caddy/snippets.caddy; then
  if grep -q 'image: ${CADDY_IMAGE:?' docker-compose.yml && ! grep -q '^[[:space:]]*build:' docker-compose.yml; then
    ok "proxy uses the required pre-built Caddy release image"
  else
    fail "caddy/snippets.caddy uses rate_limit but Compose does not require the pre-built CADDY_IMAGE"
  fi
  for f in $CADDYFILES; do
    grep -q 'order rate_limit' "$f" || fail "$f uses rate_limit but never declares 'order rate_limit before basic_auth'"
  done
fi

# A release bundle is installable on a clean Linux host precisely because Compose never
# references the source workspace or invokes a local build. Keep this assertion close to
# the config checks operators already run.
if grep -q '^[[:space:]]*build:' docker-compose.yml overlays/*.yml; then
  fail "release Compose contains a local build: block — self-hosters must only pull pinned images"
else
  ok "release Compose contains no local source builds"
fi
if grep -qE 'context:[[:space:]]+\.\.|dockerfile:' docker-compose.yml overlays/*.yml; then
  fail "release Compose references source-workspace build paths"
else
  ok "release Compose has no source-workspace build paths"
fi

# The same operator command also supports the public source-clone path. Source images must
# be tied to the checked-out superproject revision; a fixed :source tag made `git pull`
# appear successful while the old backend/dashboard/proxy kept running indefinitely.
if PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 - <<'PY_SOURCE_IMAGES'
from chronicle_ops.images import SOURCE_IMAGES
from chronicle_ops.envfile import read_env, value
settings = read_env('.env.example')
variables = {image.variable for image in SOURCE_IMAGES}
if len(variables) != len(SOURCE_IMAGES):
    raise SystemExit('duplicate source-image owner')
for image in SOURCE_IMAGES:
    reference = value(settings, image.variable)
    if not reference:
        raise SystemExit('missing first-party image configuration')
    if reference.startswith('__CHRONICLE_') and reference != image.placeholder:
        raise SystemExit('image placeholder belongs to another build owner')
PY_SOURCE_IMAGES
then
  ok "source-clone image registry covers the configured first-party images"
else
  fail "source-clone image registry does not match the configuration"
fi
grep -Fq 'submodule status --recursive -- "${SOURCE_SUBMODULES[@]}"' chronicle \
  || fail "source-clone builds do not reject submodules that differ from the pinned revision"

for image_var in BACKEND_IMAGE CADDY_IMAGE POSTGRES_IMAGE; do
  grep -Fq "image: \${${image_var}:?" docker-compose.yml \
    || fail "docker-compose.yml does not require ${image_var}"
done
grep -Fq 'image: ${CADDY_IMAGE:?' overlays/mode-local-https.yml \
  || fail "local HTTPS overlay does not require the release CADDY_IMAGE"

duplicate_env_keys="$(
  awk -F= '/^[A-Z][A-Z0-9_]*=/{print $1}' .env.example | sort | uniq -d
)"
if [[ -n "$duplicate_env_keys" ]]; then
  fail ".env.example assigns the same key more than once: $(printf '%s' "$duplicate_env_keys" | tr '\n' ' ')"
else
  ok ".env.example has one authority for every setting"
fi

if grep -REq -- '^[[:space:]]*-[[:space:]]+\./(backups|tls):' docker-compose.yml overlays/*.yml; then
  fail "mutable backups/TLS bind mounts bypass CHRONICLE_STATE_DIR"
else
  ok "mutable backups/TLS bind mounts use the release-independent state directory"
fi

echo
echo "Deployment modes"

# 9. Every Caddyfile variant must be reachable from some mode overlay, and every mode
#    overlay must agree with its own filename about what it deploys. This is the contract
#    that replaced the generated exposure.yml: the mode is now a static file the operator
#    names in COMPOSE_FILE, so nothing regenerates it and nothing else can correct it.
#    A drifting overlay is silent -- it mounts a real Caddyfile and starts a real stack,
#    just not the one the operator chose.
MODE_NAMES=(behind-proxy-internal own-tls-internal local-https)
MODE_CADDYFILES=(Caddyfile.split Caddyfile.split.tls Caddyfile.split.local)
seen_caddyfiles=""
for ((mode_index=0; mode_index<${#MODE_NAMES[@]}; mode_index++)); do
  mode="${MODE_NAMES[$mode_index]}"
  f="overlays/mode-${mode}.yml"
  want="${MODE_CADDYFILES[$mode_index]}"
  if [[ ! -f "$f" ]]; then
    fail "$f is missing — .env.example and docker-compose.yml both offer this mode"
    continue
  fi
  # The filename encodes TLS_MODE-DASHBOARD_EXPOSURE; both must be set on config-guard (so
  # the guard checks the right combination) and on cert-init (so it generates the right
  # certificate). Splitting on the LAST hyphen: 'behind-proxy' itself contains one.
  if [[ "$mode" == local-https ]]; then
    # The only mode whose name is not "<tls>-<exposure>": there is no public variant of a
    # trial mode whose CA nobody else trusts, so its exposure is internal by definition.
    want_tls=local-https; want_exposure=internal
  else
    want_tls="${mode%-*}"; want_exposure="${mode##*-}"
  fi
  for svc in config-guard cert-init; do
    block=$(awk -v s="  ${svc}:" '$0 == s {f=1; next} /^  [a-z]/ {f=0} f' "$f")
    [[ "$block" == *"TLS_MODE: ${want_tls}"* ]] \
      || fail "$f does not set TLS_MODE: ${want_tls} on ${svc}"
    [[ "$block" == *"DASHBOARD_EXPOSURE: ${want_exposure}"* ]] \
      || fail "$f does not set DASHBOARD_EXPOSURE: ${want_exposure} on ${svc}"
  done
  if ! grep -q "\./${want}:/etc/caddy/Caddyfile:ro" "$f"; then
    fail "$f does not mount ./${want} as the Caddyfile"
  else
    seen_caddyfiles="${seen_caddyfiles} ${want}"
    ok "overlays/mode-${mode}.yml deploys ${want}"
  fi
  # The internal listener and the own-tls listener both read certificates from the
  # release-independent state directory.
  if [[ "$want_exposure" == internal || "$want_tls" == own-tls ]]; then
    grep -Fq '${CHRONICLE_STATE_DIR:-.}/tls:/etc/caddy/certs:ro' "$f" \
      || fail "$f needs state-dir TLS mounted at /etc/caddy/certs — Caddy would fail to load its certificate"
  fi
done
for f in $CADDYFILES; do
  case " ${seen_caddyfiles} " in
    *" $f "*) ;;
    *) fail "$f is not deployed by any overlays/mode-*.yml — it is dead config" ;;
  esac
done

# 10. The base compose file must NOT publish ports or mount a Caddyfile of its own. If it
#     did, a mode overlay could only add to it, so a stack composed with the internal mode
#     would still publish the public-mode listener alongside it.
if awk '/^  (web|web-forward):/{f=1;next} /^  [a-z]/{f=0} f' docker-compose.yml | grep -E '^\s+(ports:|- \./Caddyfile)' >/dev/null; then
  fail "docker-compose.yml publishes ports on 'web-forward' or 'web', or mounts a Caddyfile on 'web' — that belongs to the mode overlay, and cannot be overridden away by one"
else
  ok "base compose leaves ports and the Caddyfile entirely to the mode overlay"
fi

# 11. Every setup step must exist as a service, or
#     `docker compose up -d` silently produces a stack with unencrypted tables, no
#     dashboard certificate and a world-readable ./backups.
for svc in config-guard cert-init db-init migrate; do
  grep -q "^  ${svc}:" docker-compose.yml \
    || fail "docker-compose.yml has no ${svc} service — plain 'docker compose up -d' would skip what it does"
done
# .env.example leaves CHRONICLE_CORE_PREFIX to setup (network-subnet.py select-core); render with
# the range's first /24, the shell value taking precedence over --env-file.
CHRONICLE_CORE_PREFIX="${CHRONICLE_CORE_PREFIX:-$(python3 ./network-subnet.py default-core)}" \
  docker compose --env-file .env.example -f docker-compose.yml config --format json | python3 -c '
import json, sys
services = json.load(sys.stdin)["services"]
sys.exit(not all(services[service]["depends_on"][dependency]["condition"] == "service_completed_successfully"
                 for service, dependency in (("backend", "migrate"), ("migrate", "db-init"))))
' ||
  fail "backend must wait for the migration service, which must wait for database encryption initialization"

ok "the one-shot services that make 'docker compose up -d' sufficient are all wired in"

# 12. The restore path. Piping a dump into a database that still has its schema skips every
#     CREATE and then appends every COPY, so a table without a primary key ends up holding
#     each row twice while psql exits 0 -- `audit` is such a table. The restore service drops
#     the schema first, which is the only reason that is not the documented procedure.
if ! grep -q '^  restore:' docker-compose.yml; then
  fail "docker-compose.yml has no restore service — operators are left piping dumps into psql, which silently doubles rows in tables with no primary key"
elif ! grep -q 'profiles:' <(awk '/^  restore:/{f=1;next} /^  [a-z]/{f=0} f' docker-compose.yml); then
  # Without the profile it is an ordinary service, so `docker compose up -d` would run it
  # and every boot would drop the schema and restore over it.
  fail "the restore service has no profiles: — 'docker compose up -d' would run it and wipe the database on every boot"
elif [[ ! -x restore.sh ]]; then
  fail "restore.sh is missing or not executable — the restore service cannot run"
else
  ok "restore runs only when named, and drops the schema before restoring"
fi

# 13. A timestamped principal key selected by rotate-secret must survive every future
#     db-init run. Re-selecting the bootstrap key on `down`/`up` makes rotation appear to
#     succeed until the first restart. The copied keyring is also the only way the encrypted
#     data volume can be remounted after losing its live keyring volume.
if ! grep -Fq "IF (SELECT key_name FROM pg_tde_key_info()) IS NULL THEN" init-tde.sh; then
  fail "init-tde.sh does not preserve an already active rotated principal key"
elif grep -Fq "IS DISTINCT FROM '\${KEY_NAME}'" init-tde.sh; then
  fail "init-tde.sh still forces the bootstrap key after an online rotation"
else
  ok "db-init preserves an active rotated TDE principal key"
fi
if ! grep -Fq 'source_digest="$(sha256sum "$KEYRING_SRC")"' db-init.sh ||
    ! grep -Fq '"$source_digest" == "$destination_digest"' db-init.sh; then
  fail "db-init does not byte-verify the recoverable keyring copy"
else
  ok "db-init byte-verifies the recoverable keyring copy"
fi

# 1. Every curl that probes THIS deployment must bypass HTTP_PROXY, or a proxied host lets
#    the university proxy answer for Caddy. Only the release download may egress, and it must
#    go through HTTPS_PROXY: cmd_update in ./chronicle and chronicle_ops/update.py's curl.
update_start=$(grep -nE '^cmd_update\(\) \{' chronicle | cut -d: -f1)
update_end=$(awk -v s="$update_start" 'NR>s && /^cmd_[a-z_]+\(\) \{/ {print NR; exit}' chronicle)
proxied=$(awk -v s="$update_start" -v e="$update_end" \
  'NR>=s && NR<e {next} /^[[:space:]]*#/ {next} /[[:space:]"(]curl[[:space:]]/ && !/--noproxy/ && !/external_origin/ {print NR": "$0}' chronicle)
if [[ -n "$proxied" ]]; then
  fail "deployment probes honour HTTP_PROXY (add --noproxy '*'): ${proxied}"
else
  ok "every deployment probe in ./chronicle bypasses HTTP_PROXY"
fi
python_proxy=$(PYTHONPATH=. python3 -c 'from chronicle_ops.config_inventory import proxy_violations; print("; ".join(proxy_violations(".")))') ||
  fail "could not inspect the Python curl calls"
if [[ -n "$python_proxy" ]]; then
  fail "proxy use outside the release download, or a release download that ignores HTTPS_PROXY: ${python_proxy}"
else
  ok "Python deployment probes bypass the proxy; release discovery and download honour HTTPS_PROXY"
fi
# 2. macOS has no sha256sum; python3 is already required by both scripts.
if grep -q 'sha256sum' rotate-secret.sh; then
  fail "rotate-secret.sh depend on sha256sum (absent on macOS)"
else
  ok "rotate-secret.sh compute digests without sha256sum"
fi
# 3. upgrade-receipts/ is created 0700 by upgrade.sh and adopt; the readability guard must
#    skip it or every check/up after an upgrade fails, and the printed fix must not chmod it.
if grep -q -- "-path ./upgrade-receipts" chronicle &&
   grep -Fq 'unreadable=$(find . "${keep_private[@]}" -o' chronicle &&
   grep -Fq 'find . "${keep_private[@]}" -o -exec chmod' chronicle; then
  ok "readability guard and its remediation leave upgrade-receipts/ private"
else
  fail "readability guard does not prune upgrade-receipts/ (check/up fail after every upgrade)"
fi
# 4. config-guard writes configuration.prom into the root-owned textfile volume.
if awk '/^  config-guard:/{f=1;next} f&&/^  [a-z]/{f=0} f' overlays/monitoring.yml | grep 'user: "0:0"' >/dev/null; then
  ok "monitoring overlay runs config-guard as root for the textfile volume"
else
  fail "monitoring overlay config-guard is not user 0:0; configuration.prom can never be written"
fi
# 5. The internal listener is :8081 over the self-signed internal cert in every Caddyfile
#    variant; :80 matches by host in own-tls/local-https and answers an empty 200.
if grep -q 'DASHBOARD_BASE_URL: ${DASHBOARD_BASE_URL:-}' overlays/monitoring.yml &&
   grep -Fq "':web:8081'" monitoring/probe.sh &&
   grep -Fq 'curl --connect-to "$INTERNAL_CONNECT" --cacert "$internal_ca" -sS --max-time 8' monitoring/probe.sh &&
   grep -q '"https://127.0.0.1:8081/health"' docker-compose.yml; then
  ok "web healthcheck and monitoring probe hit the :8081 internal listener over TLS"
else
  fail "web healthcheck/monitoring probe do not target https://…:8081/health (vacuous health)"
fi

echo
echo "Configuration guardrails"

# Every operator-tunable variable Compose reads is documented, and every documented
# setting is read. The internal names are set by ./chronicle or the image.
compose_internal_vars=$(PYTHONPATH=. python3 -c \
  'from chronicle_ops.config_inventory import COMPOSE_SUPPLIED; print("\n".join(sorted(COMPOSE_SUPPLIED)))') ||
  fail "could not read the Compose variables the bundle supplies itself"
undocumented_compose=$(comm -23 \
  <(grep -ohE '\$\{[A-Z_][A-Z0-9_]*' docker-compose.yml overlays/*.yml | sed 's/\${//' | sort -u) \
  <(sort -u <(echo "$ENV_EXAMPLE_VARS") <(echo "$compose_internal_vars")))
if [[ -n "$undocumented_compose" ]]; then
  fail "Compose reads settings that .env.example does not document: $(echo "$undocumented_compose" | tr '\n' ' ')"
else
  ok "every setting Compose reads is documented in .env.example"
fi
undocumented_runtime=$(PYTHONPATH=. python3 - "$ENV_EXAMPLE_VARS" <<'PY'
import sys
from chronicle_ops.config_inventory import undocumented_runtime_settings
print(' '.join(undocumented_runtime_settings('.', sys.argv[1].split())))
PY
) || fail "could not inspect Python and shell setting readers"
if [[ -n "$undocumented_runtime" ]]; then
  fail "Python or shell reads settings that .env.example does not document: $undocumented_runtime"
else
  ok "every Python and shell override is documented or supplied internally"
fi
unread_example=""
for k in $ENV_EXAMPLE_VARS; do
  grep -rqw -- "$k" docker-compose.yml overlays chronicle ./*.sh \
    config monitoring chronicle_ops caddy \
    Caddyfile.split Caddyfile.split.local Caddyfile.split.tls || unread_example+="$k "
done
if [[ -n "$unread_example" ]]; then
  fail ".env.example documents settings nothing reads: ${unread_example}"
else
  ok "every .env.example setting is read by the bundle"
fi

# One default for ENABLE_ENCRYPTION everywhere, or the probe stops watching TDE health.
encryption_defaults=$(grep -ohE 'ENABLE_ENCRYPTION:-[a-z]+' docker-compose.yml overlays/*.yml | sort -u)
if [[ "$encryption_defaults" != 'ENABLE_ENCRYPTION:-true' ]] ||
   ! grep -Fq ': "${ENABLE_ENCRYPTION:=true}"' monitoring/probe.sh; then
  fail "ENABLE_ENCRYPTION fallbacks disagree: $(echo "$encryption_defaults" | tr '\n' ' ') (probe.sh must default to true too)"
else
  ok "every ENABLE_ENCRYPTION fallback is true"
fi

# L4: a hung query, an idle open transaction, or a stuck lock cannot hold one of the backend's
# pooled connections forever; the one-shot jobs that rewrite or reload whole tables opt out.
postgres_service=$(service_block postgres)
for timeout_setting in statement_timeout idle_in_transaction_session_timeout lock_timeout; do
  grep -Fq -- "- ${timeout_setting}=" <<<"$postgres_service" \
    || fail "postgres runs without a server-side ${timeout_setting}"
done
for long_job in db-init restore; do
  grep -Fq 'PGOPTIONS: "-c statement_timeout=0 -c lock_timeout=0 -c idle_in_transaction_session_timeout=0"' \
    <<<"$(service_block "$long_job")" || fail "${long_job} would inherit the server statement/lock timeouts"
done
[[ $FAILED -eq 0 ]] && ok "postgres bounds statements, idle transactions and lock waits; restore and db-init opt out"

# Per-service contract across the base file and every overlay: log caps and
# container hardening. A service that only overrides a base service is
# checked through the base definition.
service_contract_violations=$(python3 - docker-compose.yml overlays/*.yml <<'PY'
import sys
from chronicle_ops.verify import service_contract_violations
print(service_contract_violations(sys.argv[1:]))
PY
) || fail "could not inspect the service hardening contract"
if [[ "$service_contract_violations" == __NO_YAML__ ]]; then
  echo "  --   per-service hardening/logging contract not checked (python3 PyYAML is not installed)"
elif [[ -n "$service_contract_violations" ]]; then
  fail "service hardening/logging contract violations:"
  echo "$service_contract_violations" | sed 's/^/         /'
else
  ok "every service meets hardening limits; only the documented isolated proxy holds the Docker socket"
fi

echo
if [[ $FAILED -ne 0 ]]; then
  echo "Config verification FAILED"
  exit 1
fi
echo "Config verified: no drift"
