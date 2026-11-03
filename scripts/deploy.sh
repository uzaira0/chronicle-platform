#!/usr/bin/env bash
# Chronicle Deployment Script
#
# Performs rolling deployments with health verification and rollback capability.
# Designed for healthcare platform requirements: audit trail, zero-downtime,
# and automated rollback on failure.
#
# Usage:
#   ./scripts/deploy.sh --environment staging --tag sha-abc1234
#   ./scripts/deploy.sh --environment production --tag v1.2.0
#   ./scripts/deploy.sh --rollback --environment production
#   ./scripts/deploy.sh --verify-only --environment staging
#
# Required environment or flags:
#   --environment   staging|production
#   --tag           Release tag used to resolve the immutable registry digest
#   --backend-image (optional) Override backend image name
#   --frontend-image (optional) Override frontend image name
#   --env-file      (optional) Explicit environment file; defaults to docker/.env.<environment>.local
#
# Environment variables (set in .env.<environment> or export):
#   BACKEND_IMAGE    ghcr.io registry path for backend
#   FRONTEND_IMAGE   ghcr.io registry path for frontend
#   IMAGE_TAG        Release tag used for the initial pull and release log
#   BACKEND_DIGEST   Optional pinned backend SHA-256 digest
#   FRONTEND_DIGEST  Optional pinned frontend SHA-256 digest

set -euo pipefail

# ─────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKER_DIR="${PROJECT_ROOT}/docker"
DEPLOY_LOG="${PROJECT_ROOT}/deploy-audit.log"
STATE_DIR="${PROJECT_ROOT}/.deploy-state"
COMPOSE_BASE="${DOCKER_DIR}/docker-compose.traefik.yml"
COMPOSE_PROD="${DOCKER_DIR}/docker-compose.production.yml"

# Timeouts
BACKEND_HEALTH_TIMEOUT=120    # seconds
FRONTEND_HEALTH_TIMEOUT=30    # seconds

# ─────────────────────────────────────────────────────────
# Parse arguments
# ─────────────────────────────────────────────────────────
ENVIRONMENT=""
IMAGE_TAG=""
BACKEND_DIGEST="${BACKEND_DIGEST:-}"
FRONTEND_DIGEST="${FRONTEND_DIGEST:-}"
BACKEND_IMAGE_ARG=""
FRONTEND_IMAGE_ARG=""
ENV_FILE_ARG=""
ROLLBACK=false
VERIFY_ONLY=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --environment|-e) ENVIRONMENT="$2"; shift 2 ;;
    --tag|-t) IMAGE_TAG="$2"; shift 2 ;;
    --backend-image) BACKEND_IMAGE_ARG="$2"; shift 2 ;;
    --frontend-image) FRONTEND_IMAGE_ARG="$2"; shift 2 ;;
    --env-file) ENV_FILE_ARG="$2"; shift 2 ;;
    --rollback) ROLLBACK=true; shift ;;
    --verify-only) VERIFY_ONLY=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --help|-h)
      echo "Usage: $0 --environment <staging|production> --tag <image-tag>"
      echo ""
      echo "Options:"
      echo "  --environment, -e   Target environment (staging or production)"
      echo "  --tag, -t           Docker image tag to deploy"
      echo "  --backend-image     Override backend image path"
      echo "  --frontend-image    Override frontend image path"
      echo "  --env-file          Explicit environment file"
      echo "  --rollback          Rollback to previous deployment"
      echo "  --verify-only       Only run health verification"
      echo "  --dry-run           Show what would be done without executing"
      echo "  --help, -h          Show this help"
      exit 0
      ;;
    *) echo "ERROR: Unknown argument: $1"; exit 1 ;;
  esac
done

# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────
log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "[${ts}] [${level}] ${msg}"
  echo "[${ts}] [${level}] ${msg}" >> "${DEPLOY_LOG}" 2>/dev/null || true
}

log_info()  { log "INFO" "$@"; }
log_warn()  { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_audit() { log "AUDIT" "$@"; }

die() {
  log_error "$@"
  exit 1
}

# The backend reads its secrets from copies backend-secrets-init stages (see
# docker-compose.traefik.yml). `up --no-deps` skips that one-shot, so run it first and
# stop on failure; otherwise a rotated secret, or a fresh volume, never reaches the backend.
stage_backend_secrets() {
  compose_cmd run --rm --no-deps backend-secrets-init >/dev/null ||
    die "backend-secrets-init failed; the backend cannot read its secrets"
}

compose_cmd() {
  local env_file
  env_file="$(env_file_path)"

  docker compose \
    --env-file "${env_file}" \
    -f "${COMPOSE_BASE}" \
    -f "${COMPOSE_PROD}" \
    "$@"
}

env_file_path() {
  if [[ -n "${ENV_FILE_ARG}" ]]; then
    printf '%s\n' "${ENV_FILE_ARG}"
    return
  fi

  if [[ -n "${ENVIRONMENT}" && -f "${DOCKER_DIR}/.env.${ENVIRONMENT}.local" ]]; then
    printf '%s\n' "${DOCKER_DIR}/.env.${ENVIRONMENT}.local"
    return
  fi

  if [[ -n "${ENVIRONMENT}" && -f "${DOCKER_DIR}/.env.${ENVIRONMENT}" ]]; then
    printf '%s\n' "${DOCKER_DIR}/.env.${ENVIRONMENT}"
    return
  fi

  printf '%s\n' "${DOCKER_DIR}/.env"
}

env_value() {
  local env_file="$1"
  local key="$2"
  awk -F= -v key="${key}" '
    $0 ~ /^[[:space:]]*#/ { next }
    $1 == key {
      value = substr($0, index($0, "=") + 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      gsub(/^"|"$/, "", value)
      gsub(/^'\''|'\''$/, "", value)
      print value
    }
  ' "${env_file}" | tail -n 1
}

is_placeholder_value() {
  local value="$1"
  case "${value}" in
    ""|CHANGE_ME*|change-me*|change_me*|*CHANGE_ME*|*change-me*|*example.com*|unknown)
      return 0
      ;;
  esac
  return 1
}

require_env_value() {
  local env_file="$1"
  local key="$2"
  local value
  value="$(env_value "${env_file}" "${key}")"
  if is_placeholder_value "${value}"; then
    die "Environment file '${env_file}' must set a real value for ${key}"
  fi
}

require_env_equals() {
  local env_file="$1"
  local key="$2"
  local expected="$3"
  local value
  value="$(env_value "${env_file}" "${key}")"
  if [[ "${value}" != "${expected}" ]]; then
    die "Environment file '${env_file}' must set ${key}=${expected}"
  fi
}

validate_mobile_signing_config() {
  local env_file="$1"
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PROJECT_ROOT/selfhost" python3 - "$env_file" <<'PY_VALIDATE'
from pathlib import Path
import sys
from chronicle_ops.credentials import validate_mobile_signing_configuration
from chronicle_ops.envfile import read_env

try:
    validate_mobile_signing_configuration(read_env(Path(sys.argv[1])))
except ValueError as error:
    sys.exit(str(error))
PY_VALIDATE
}

require_env_url_scheme() {
  local env_file="$1"
  local key="$2"
  local expected_scheme="$3"
  local value
  value="$(env_value "${env_file}" "${key}")"
  if [[ "${value}" != "${expected_scheme}://"* ]]; then
    die "Environment file '${env_file}' must set ${key} to a ${expected_scheme}:// URL"
  fi
}

file_mode() {
  stat -f "%Lp" "$1" 2>/dev/null || stat -c "%a" "$1"
}

validate_env_file() {
  local env_file
  env_file="$(env_file_path)"

  if [[ ! -f "${env_file}" ]]; then
    die "Environment file '${env_file}' does not exist. Use --env-file or create docker/.env.${ENVIRONMENT}."
  fi
  if [[ ! -r "${env_file}" ]]; then
    die "Environment file '${env_file}' is not readable"
  fi
  if [[ "${ENVIRONMENT}" == "production" ]]; then
    local rel_env_file="${env_file}"
    case "${rel_env_file}" in
      "${PROJECT_ROOT}/"*) rel_env_file="${rel_env_file#"${PROJECT_ROOT}/"}" ;;
    esac
    if git -C "${PROJECT_ROOT}" ls-files --error-unmatch "${rel_env_file}" >/dev/null 2>&1; then
      die "Refusing to deploy production with git-tracked env file '${env_file}'. Copy it to docker/.env.production.local or pass --env-file to an untracked 0600 file."
    fi
    local mode
    mode="$(file_mode "${env_file}")"
    if (( (8#${mode} & 8#077) != 0 )); then
      die "Production env file '${env_file}' must not be readable or writable by group/other users. Run: chmod 600 '${env_file}'"
    fi
  fi

  log_info "Using environment file: ${env_file}"

  require_env_value "${env_file}" "DOMAIN"
  require_env_value "${env_file}" "POSTGRES_PASSWORD"
  require_env_value "${env_file}" "JWT_SECRET"
  require_env_value "${env_file}" "HAZELCAST_SERVER_PASSWORD"
  require_env_value "${env_file}" "HAZELCAST_CLIENT_PASSWORD"
  validate_mobile_signing_config "${env_file}"

  if [[ "${ENVIRONMENT}" == "production" ]]; then
    require_env_value "${env_file}" "CHRONICLE_INTERNAL_WEB_SECRET"
    require_env_value "${env_file}" "CROWDSEC_BOUNCER_API_KEY"
    require_env_value "${env_file}" "GRAFANA_ADMIN_PASSWORD"
    require_env_equals "${env_file}" "CHRONICLE_SECURITY_COOKIE_SECURE" "true"
    require_env_equals "${env_file}" "CHRONICLE_SECURITY_REQUIRE_MFA" "true"
    require_env_equals "${env_file}" "OIDC_ENABLED" "true"
    require_env_value "${env_file}" "OIDC_CLIENT_SECRET"
    local keycloak_default_idp oidc_idp_hint
    keycloak_default_idp="$(env_value "${env_file}" "KEYCLOAK_DEFAULT_IDP")"
    oidc_idp_hint="$(env_value "${env_file}" "OIDC_IDP_HINT")"
    keycloak_default_idp="${keycloak_default_idp:-upstream-oidc}"
    oidc_idp_hint="${oidc_idp_hint:-upstream-oidc}"
    if [[ "${keycloak_default_idp}" != "${oidc_idp_hint}" ]]; then
      die "KEYCLOAK_DEFAULT_IDP and OIDC_IDP_HINT must select the same broker"
    fi
    if [[ "${keycloak_default_idp}" == "upstream-saml" ]]; then
      die "MFA enforcement cannot use the disabled upstream SAML example until current-session AuthnContext is mapped to approved amr/acr assurance"
    fi
    require_env_equals "${env_file}" "CHRONICLE_SECURITY_MFA_IDP_PROOF_VERIFIED" "true"
    require_env_equals "${env_file}" "TESTING_LOGIN_ENABLED" "false"
    require_env_equals "${env_file}" "ALLOW_PRODUCTION_TESTING_LOGIN" "false"
    require_env_equals "${env_file}" "PG_TDE_KEY_PROVIDER" "vault"
    require_env_value "${env_file}" "PG_TDE_VAULT_URL"
    require_env_url_scheme "${env_file}" "PG_TDE_VAULT_URL" "https"
    require_env_value "${env_file}" "PG_TDE_VAULT_TOKEN"
    require_env_equals "${env_file}" "VAULT_ENABLED" "true"
    require_env_value "${env_file}" "VAULT_ADDR"
    require_env_url_scheme "${env_file}" "VAULT_ADDR" "https"
    require_env_value "${env_file}" "VAULT_TOKEN"
  fi
}

# ─────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────
validate_args() {
  if [[ -z "${ENVIRONMENT}" ]]; then
    die "Missing required --environment flag"
  fi

  if [[ "${ENVIRONMENT}" != "staging" && "${ENVIRONMENT}" != "production" ]]; then
    die "Invalid environment '${ENVIRONMENT}'. Must be 'staging' or 'production'."
  fi

  validate_env_file

  if [[ "${VERIFY_ONLY}" == true ]]; then
    return
  fi

  if [[ "${ROLLBACK}" == true ]]; then
    if [[ ! -f "${STATE_DIR}/previous-tag" ]]; then
      die "No previous deployment state found. Cannot rollback."
    fi
    return
  fi

  if [[ -z "${IMAGE_TAG}" ]]; then
    die "Missing required --tag flag"
  fi

  case "${IMAGE_TAG}" in
    latest|main|master|develop|dev|staging|production|CHANGE_ME*|change_me*|change-me*)
      die "Refusing mutable or placeholder image tag '${IMAGE_TAG}'. Use a CD-produced sha-* or v* tag."
      ;;
  esac
}

# ─────────────────────────────────────────────────────────
# State management (for rollback)
# ─────────────────────────────────────────────────────────
save_state() {
  mkdir -p "${STATE_DIR}"

  # Save current state as "previous" before deploying
  if [[ -f "${STATE_DIR}/current-tag" ]]; then
    cp "${STATE_DIR}/current-tag" "${STATE_DIR}/previous-tag"
    cp "${STATE_DIR}/current-backend-image" "${STATE_DIR}/previous-backend-image" 2>/dev/null || true
    cp "${STATE_DIR}/current-frontend-image" "${STATE_DIR}/previous-frontend-image" 2>/dev/null || true
    cp "${STATE_DIR}/current-backend-digest" "${STATE_DIR}/previous-backend-digest" 2>/dev/null || true
    cp "${STATE_DIR}/current-frontend-digest" "${STATE_DIR}/previous-frontend-digest" 2>/dev/null || true
  fi

  # Save new state as current
  echo "${IMAGE_TAG}" > "${STATE_DIR}/current-tag"
  echo "${BACKEND_IMAGE}" > "${STATE_DIR}/current-backend-image"
  echo "${FRONTEND_IMAGE}" > "${STATE_DIR}/current-frontend-image"
  echo "${BACKEND_DIGEST}" > "${STATE_DIR}/current-backend-digest"
  echo "${FRONTEND_DIGEST}" > "${STATE_DIR}/current-frontend-digest"
  date -u +"%Y-%m-%dT%H:%M:%SZ" > "${STATE_DIR}/last-deploy-time"
  echo "${ENVIRONMENT}" > "${STATE_DIR}/last-deploy-environment"
}

load_rollback_state() {
  IMAGE_TAG="$(cat "${STATE_DIR}/previous-tag")"
  BACKEND_IMAGE="$(cat "${STATE_DIR}/previous-backend-image" 2>/dev/null || echo "${BACKEND_IMAGE}")"
  FRONTEND_IMAGE="$(cat "${STATE_DIR}/previous-frontend-image" 2>/dev/null || echo "${FRONTEND_IMAGE}")"
  BACKEND_DIGEST="$(cat "${STATE_DIR}/previous-backend-digest" 2>/dev/null || true)"
  FRONTEND_DIGEST="$(cat "${STATE_DIR}/previous-frontend-digest" 2>/dev/null || true)"
  log_info "Rollback target: tag=${IMAGE_TAG}"
}

# ─────────────────────────────────────────────────────────
# Health checks
# ─────────────────────────────────────────────────────────
wait_for_healthy() {
  local service="$1"
  local url="$2"
  local timeout="$3"
  local elapsed=0
  local interval=5

  log_info "Waiting for ${service} to become healthy (timeout: ${timeout}s)..."

  while [[ ${elapsed} -lt ${timeout} ]]; do
    if curl -q --noproxy '*' -sf --max-time 5 "${url}" > /dev/null 2>&1; then
      log_info "${service} healthy after ${elapsed}s"
      return 0
    fi
    sleep "${interval}"
    elapsed=$((elapsed + interval))
  done

  log_error "${service} failed to become healthy after ${timeout}s"
  return 1
}

verify_deployment() {
  local failed=0

  log_info "Verifying deployment health..."

  # Check container states
  local unhealthy
  unhealthy=$(compose_cmd ps --format json 2>/dev/null | \
    python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        c = json.loads(line)
        state = c.get('Health', c.get('State', 'unknown'))
        if state not in ('healthy', 'running'):
            print(f\"{c.get('Service','?')}: {state}\")
    except: pass
" 2>/dev/null || true)

  if [[ -n "${unhealthy}" ]]; then
    log_error "Unhealthy containers detected:"
    echo "${unhealthy}" | while read -r line; do log_error "  ${line}"; done
    failed=1
  fi

  # Backend dependency-aware readiness endpoint
  if ! curl -q --noproxy '*' -sf --max-time 10 http://127.0.0.1:40320/chronicle/internal/health/ready > /dev/null 2>&1; then
    log_error "Backend readiness check failed (port 40320)"
    failed=1
  else
    log_info "Backend readiness check passed"
  fi

  # Frontend health endpoint
  if ! curl -q --noproxy '*' -sf --max-time 5 http://127.0.0.1:8080/health > /dev/null 2>&1; then
    log_error "Frontend health check failed (port 8080)"
    failed=1
  else
    log_info "Frontend health check passed"
  fi

  # PostgreSQL (via compose exec)
  if ! compose_cmd exec -T postgres pg_isready -q 2>/dev/null; then
    log_error "PostgreSQL health check failed"
    failed=1
  else
    log_info "PostgreSQL health check passed"
  fi

  if [[ ${failed} -ne 0 ]]; then
    log_error "Deployment verification FAILED"
    return 1
  fi

  log_info "Deployment verification PASSED"
  return 0
}

# ─────────────────────────────────────────────────────────
# Image operations
# ─────────────────────────────────────────────────────────
pull_images() {
  log_info "Resolving immutable image refs for release tag ${IMAGE_TAG}"

  if [[ "${DRY_RUN}" == true ]]; then
    log_info "[DRY RUN] Would pull images"
    return 0
  fi

  if [[ -n "${BACKEND_DIGEST}" ]]; then
    [[ "${BACKEND_DIGEST}" =~ ^[0-9a-f]{64}$ ]] || die "BACKEND_DIGEST must be 64 lowercase SHA-256 hex characters"
    docker pull "${BACKEND_IMAGE}@sha256:${BACKEND_DIGEST}" || die "Failed to pull pinned backend image"
  else
    docker pull "${BACKEND_IMAGE}:${IMAGE_TAG}" || die "Failed to pull backend image"
    BACKEND_DIGEST="$(resolve_image_digest "${BACKEND_IMAGE}:${IMAGE_TAG}" "${BACKEND_IMAGE}")"
  fi
  if [[ -n "${FRONTEND_DIGEST}" ]]; then
    [[ "${FRONTEND_DIGEST}" =~ ^[0-9a-f]{64}$ ]] || die "FRONTEND_DIGEST must be 64 lowercase SHA-256 hex characters"
    docker pull "${FRONTEND_IMAGE}@sha256:${FRONTEND_DIGEST}" || die "Failed to pull pinned frontend image"
  else
    docker pull "${FRONTEND_IMAGE}:${IMAGE_TAG}" || die "Failed to pull frontend image"
    FRONTEND_DIGEST="$(resolve_image_digest "${FRONTEND_IMAGE}:${IMAGE_TAG}" "${FRONTEND_IMAGE}")"
  fi

  log_info "Images pulled successfully"
}

resolve_image_digest() { # <pulled reference> <repository>
  local reference=$1 repository=$2 repo_digest digest
  local listed
  listed="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$reference")" \
    || die "Could not read immutable repository digest for ${reference}"
  while IFS= read -r repo_digest; do
    case "$repo_digest" in
      "${repository}"@sha256:*)
        digest=${repo_digest#"${repository}"@sha256:}
        [[ "$digest" =~ ^[0-9a-f]{64}$ ]] && { printf '%s' "$digest"; return 0; }
        ;;
    esac
  done <<< "$listed"
  die "Pulled image ${reference} did not expose a validated repository digest"
}

# ─────────────────────────────────────────────────────────
# Database migrations (Flyway, fail-closed)
# ─────────────────────────────────────────────────────────
# Migrations are applied HERE, before the backend container is recreated, so a
# failed migration aborts the deploy and the running backend keeps serving on
# the last-good schema. The backend's own FlywayMigrationService then finds an
# up-to-date ledger at startup (and is itself fail-closed as a second gate).
check_migrations() {
  log_info "Applying database migrations (Flyway)..."

  local flyway_runner="${SCRIPT_DIR}/flyway-migrate.sh"
  [[ -x "${flyway_runner}" ]] || die "Migration runner not found or not executable: ${flyway_runner}"

  if [[ "${DRY_RUN}" == true ]]; then
    log_info "[DRY RUN] Migration status (flyway info):"
    CHRONICLE_ENV_FILE="$(env_file_path)" "${flyway_runner}" info || log_warn "[DRY RUN] flyway info failed"
    return 0
  fi

  if ! CHRONICLE_ENV_FILE="$(env_file_path)" "${flyway_runner}" migrate; then
    log_audit "DEPLOY_ABORTED reason=migration_failure environment=${ENVIRONMENT} tag=${IMAGE_TAG}"
    die "Flyway migration failed — deploy aborted before backend restart (schema unchanged rollback not attempted; investigate flyway_schema_history)"
  fi

  log_info "Database migrations applied"
}

# ─────────────────────────────────────────────────────────
# Schema postconditions
# ─────────────────────────────────────────────────────────
# A healthy backend does NOT imply a correct schema (the pre-Flyway upgrade
# system swallowed failures for months). Assert the invariants directly.
check_schema_postconditions() {
  local postconditions="${SCRIPT_DIR}/verify-schema-postconditions.sh"
  [[ -x "${postconditions}" ]] || { log_warn "Postcondition script missing: ${postconditions}"; return 1; }

  log_info "Verifying schema postconditions..."
  if ! CHRONICLE_ENV_FILE="$(env_file_path)" "${postconditions}"; then
    log_error "Schema postconditions FAILED — see output above"
    return 1
  fi
  log_info "Schema postconditions PASSED"
}

# ─────────────────────────────────────────────────────────
# Deployment
# ─────────────────────────────────────────────────────────
deploy() {
  log_audit "DEPLOY_START environment=${ENVIRONMENT} tag=${IMAGE_TAG} user=$(whoami) hostname=$(hostname)"

  # Export image references for docker-compose.production.yml
  export IMAGE_TAG BACKEND_IMAGE FRONTEND_IMAGE BACKEND_DIGEST FRONTEND_DIGEST

  if [[ "${DRY_RUN}" == true ]]; then
    BACKEND_DIGEST="${BACKEND_DIGEST:-$(printf '%064d' 0)}"
    FRONTEND_DIGEST="${FRONTEND_DIGEST:-$(printf '%064d' 0)}"
    export BACKEND_DIGEST FRONTEND_DIGEST
    log_info "[DRY RUN] Would deploy with:"
    log_info "  BACKEND_IMAGE=${BACKEND_IMAGE}@sha256:${BACKEND_DIGEST}"
    log_info "  FRONTEND_IMAGE=${FRONTEND_IMAGE}@sha256:${FRONTEND_DIGEST}"
    log_info "  Environment: ${ENVIRONMENT}"
    compose_cmd config --quiet 2>/dev/null && log_info "  Compose config: valid" || log_warn "  Compose config: invalid"
    # Surface pending-migration status too — a surprise migration should show up in
    # the dry run, not first appear mid-real-deploy.
    check_migrations
    return 0
  fi

  # Pull images
  pull_images
  export BACKEND_DIGEST FRONTEND_DIGEST

  # Save state for potential rollback
  save_state

  # Check migrations
  check_migrations

  # Rolling restart: update frontend first (stateless, fast), then backend
  log_info "Starting rolling deployment..."

  # Step 1: Update frontend (fast, stateless)
  log_info "Updating frontend..."
  compose_cmd up -d --no-deps --remove-orphans chronicle-frontend
  if ! wait_for_healthy "frontend" "http://127.0.0.1:8080/health" "${FRONTEND_HEALTH_TIMEOUT}"; then
    log_error "Frontend failed health check — initiating rollback"
    rollback_deployment
    exit 1
  fi

  # Step 2: Update backend (may run migrations)
  log_info "Updating backend..."
  stage_backend_secrets
  compose_cmd up -d --no-deps chronicle-backend
  if ! wait_for_healthy "backend" "http://127.0.0.1:40320/chronicle/internal/health/ready" "${BACKEND_HEALTH_TIMEOUT}"; then
    log_error "Backend failed health check — initiating rollback"
    rollback_deployment
    exit 1
  fi

  # Step 3: Full verification
  if ! verify_deployment; then
    log_error "Post-deploy verification failed — initiating rollback"
    rollback_deployment
    exit 1
  fi

  # Step 3.5: TDE conversion for any tables the migrations just created. The live
  # cluster sets default_table_access_method=tde_heap, making this a no-op — but on a
  # rebuilt box without that setting, skipping it would fail postcondition check 5
  # on every table-adding deploy (the poller runs the same step; keep them symmetric).
  if [[ -x "${SCRIPT_DIR}/../docker/migrate-tde.sh" ]]; then
    log_info "Ensuring TDE coverage for newly created tables..."
    "${SCRIPT_DIR}/../docker/migrate-tde.sh" || log_warn "migrate-tde.sh reported failures — postconditions will catch any unencrypted table"
  fi

  # Step 4: Schema postconditions. No container rollback here — migrations are
  # already applied and additive, so the old image would not repair a schema
  # invariant failure; it needs operator investigation, not a bounce.
  if ! check_schema_postconditions; then
    log_audit "DEPLOY_SCHEMA_POSTCONDITIONS_FAILED environment=${ENVIRONMENT} tag=${IMAGE_TAG}"
    die "Schema postconditions failed after deploy — containers left running, investigate before next deploy"
  fi

  # Clean up old images (keep last 3)
  log_info "Cleaning up old images..."
  docker image prune -f --filter "until=168h" 2>/dev/null || true

  log_audit "DEPLOY_COMPLETE environment=${ENVIRONMENT} tag=${IMAGE_TAG} user=$(whoami)"
  log_info "Deployment successful: ${IMAGE_TAG} -> ${ENVIRONMENT}"

  # Show running containers
  compose_cmd ps
}

rollback_deployment() {
  log_audit "ROLLBACK_START environment=${ENVIRONMENT} failed_tag=${IMAGE_TAG} user=$(whoami)"

  if [[ ! -f "${STATE_DIR}/previous-tag" ]]; then
    log_error "No previous state to rollback to. Manual intervention required."
    log_error "Container logs:"
    compose_cmd logs --tail=50 chronicle-backend chronicle-frontend 2>&1 | tail -100
    return 1
  fi

  load_rollback_state
  log_info "Rolling back to: tag=${IMAGE_TAG}"

  pull_images
  export IMAGE_TAG BACKEND_IMAGE FRONTEND_IMAGE BACKEND_DIGEST FRONTEND_DIGEST

  stage_backend_secrets
  compose_cmd up -d --no-deps chronicle-backend chronicle-frontend

  if wait_for_healthy "backend" "http://127.0.0.1:40320/chronicle/internal/health/ready" "${BACKEND_HEALTH_TIMEOUT}" && \
     wait_for_healthy "frontend" "http://127.0.0.1:8080/health" "${FRONTEND_HEALTH_TIMEOUT}"; then
    log_audit "ROLLBACK_COMPLETE environment=${ENVIRONMENT} restored_tag=${IMAGE_TAG}"
    log_info "Rollback successful. Restored tag: ${IMAGE_TAG}"

    # Update current state to reflect rollback
    echo "${IMAGE_TAG}" > "${STATE_DIR}/current-tag"
    echo "${BACKEND_IMAGE}" > "${STATE_DIR}/current-backend-image"
    echo "${FRONTEND_IMAGE}" > "${STATE_DIR}/current-frontend-image"
    echo "${BACKEND_DIGEST}" > "${STATE_DIR}/current-backend-digest"
    echo "${FRONTEND_DIGEST}" > "${STATE_DIR}/current-frontend-digest"
  else
    log_error "ROLLBACK FAILED. Manual intervention required!"
    log_error "Container logs:"
    compose_cmd logs --tail=50 chronicle-backend chronicle-frontend 2>&1 | tail -100
    log_audit "ROLLBACK_FAILED environment=${ENVIRONMENT} attempted_tag=${IMAGE_TAG}"
    return 1
  fi
}

# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────
main() {
  validate_args

  # Set default image names if not provided
  BACKEND_IMAGE="${BACKEND_IMAGE_ARG:-${BACKEND_IMAGE:-ghcr.io/uzaira0/chronicle/chronicle-backend}}"
  FRONTEND_IMAGE="${FRONTEND_IMAGE_ARG:-${FRONTEND_IMAGE:-ghcr.io/uzaira0/chronicle/chronicle-frontend}}"

  if [[ "${VERIFY_ONLY}" == true ]]; then
    verify_deployment
    exit $?
  fi

  if [[ "${ROLLBACK}" == true ]]; then
    load_rollback_state
    log_info "Initiating manual rollback to tag=${IMAGE_TAG}"
    pull_images
    export IMAGE_TAG BACKEND_IMAGE FRONTEND_IMAGE BACKEND_DIGEST FRONTEND_DIGEST
    stage_backend_secrets
    compose_cmd up -d --no-deps chronicle-backend chronicle-frontend
    if verify_deployment; then
      log_audit "MANUAL_ROLLBACK_COMPLETE environment=${ENVIRONMENT} tag=${IMAGE_TAG}"
      echo "${IMAGE_TAG}" > "${STATE_DIR}/current-tag"
      echo "${BACKEND_DIGEST}" > "${STATE_DIR}/current-backend-digest"
      echo "${FRONTEND_DIGEST}" > "${STATE_DIR}/current-frontend-digest"
    else
      die "Manual rollback verification failed. Check container logs."
    fi
    exit 0
  fi

  deploy
}

main "$@"
