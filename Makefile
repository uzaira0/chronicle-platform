# Chronicle Makefile — performance testing targets
#
# Prerequisites:
#   - k6 installed (https://k6.io/docs/get-started/installation/)
#   - Docker Compose stack running (see: make perf-up)
#   - JWT token exported (see: make perf-token)

BASE_URL ?= http://127.0.0.1:40320
JWT_TOKEN ?=
STUDY_ID ?=
MAX_VUS ?= 200

# ---------------------------------------------------------------------------
# Docker Compose helpers
# ---------------------------------------------------------------------------

.PHONY: perf-up perf-down perf-token

## Start the Chronicle backend + Postgres via Docker Compose
perf-up:
	cd docker && docker compose -p chronicle -f docker-compose.traefik.yml up -d chronicle-backend postgres
	@echo "Waiting for backend to be healthy..."
	@timeout 120 bash -c 'until curl -sf http://127.0.0.1:40320/actuator/health >/dev/null 2>&1; do sleep 2; done' || echo "WARN: health check timed out"
	@echo "Backend is up at $(BASE_URL)"

## Stop the Docker Compose stack and remove volumes
perf-down:
	cd docker && docker compose -p chronicle -f docker-compose.traefik.yml down -v

## Generate a JWT token for testing (requires docker/.env with JWT_SECRET)
perf-token:
	@cd docker && bash generate-jwt.sh

# ---------------------------------------------------------------------------
# Performance tests
# ---------------------------------------------------------------------------

.PHONY: perf-smoke perf-load perf-stress

## Smoke test — 1 VU, 10s, health + basic reads (CI-safe)
perf-smoke:
	k6 run \
		--env BASE_URL=$(BASE_URL) \
		--env JWT_TOKEN=$(JWT_TOKEN) \
		tests/performance/smoke.js

## Load test — 50 VUs, 30s, read + write endpoints
perf-load:
	k6 run \
		--env BASE_URL=$(BASE_URL) \
		--env JWT_TOKEN=$(JWT_TOKEN) \
		--env STUDY_ID=$(STUDY_ID) \
		tests/performance/load.js

## Stress test — ramp to 200+ VUs, find breaking points
perf-stress:
	k6 run \
		--env BASE_URL=$(BASE_URL) \
		--env JWT_TOKEN=$(JWT_TOKEN) \
		--env STUDY_ID=$(STUDY_ID) \
		--env MAX_VUS=$(MAX_VUS) \
		tests/performance/stress.js

# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------

.PHONY: help

## Show this help
help:
	@echo "Chronicle Performance Testing"
	@echo ""
	@echo "Docker:"
	@echo "  make perf-up       Start Chronicle backend via Docker Compose"
	@echo "  make perf-down     Stop and clean up Docker Compose stack"
	@echo "  make perf-token    Generate a JWT token for testing"
	@echo ""
	@echo "Tests:"
	@echo "  make perf-smoke    Smoke test (1 VU, 10s) — safe for CI"
	@echo "  make perf-load     Load test (50 VUs, 30s) — staging"
	@echo "  make perf-stress   Stress test (200 VUs, 5min) — manual"
	@echo ""
	@echo "Variables:"
	@echo "  BASE_URL=$(BASE_URL)"
	@echo "  JWT_TOKEN=<set via env or make perf-token>"
	@echo "  STUDY_ID=<uuid for write tests>"
	@echo "  MAX_VUS=$(MAX_VUS)"

i18n-lint: ## Fail on hardcoded English in web/Android/server/iOS UI paths (ast-grep + semgrep rules)
	scripts/i18n-lint.sh

.PHONY: i18n-sheet-export i18n-sheet-import i18n-sheet-test i18n-source-check i18n-source-stamp
i18n-source-check: ## Fail when a translation's English changed since it was translated: LANG=es
	python3 scripts/i18n-sheet.py check --lang "$(LANG)"

i18n-source-stamp: ## Record reviewed English for translated lines: LANG=es KEYS="key [file:key ...]"
	python3 scripts/i18n-sheet.py stamp --lang "$(LANG)" $(KEYS)

i18n-sheet-export: ## Export translator workbook: LANG=es OUT=<path.xlsx>
	python3 scripts/i18n-sheet.py export --lang "$(LANG)" --out "$(OUT)"

i18n-sheet-import: ## Import translator workbook: LANG=es IN=<path.xlsx>
	python3 scripts/i18n-sheet.py import --lang "$(LANG)" --in "$(IN)"

i18n-sheet-test: ## Test translator workbook export/import, placeholder rejection and English-change tracking
	bash scripts/test-i18n-sheet.sh

i18n-lint-proof: ## Prove the i18n guard: per-repo case suites plus the mutation test against the real trees
	scripts/i18n-lint.sh
	scripts/i18n-lint-mutation.sh
	$(MAKE) i18n-sheet-test

.PHONY: publish-stage publish-status publish-push publish-abandon
## Publish curated history to the public mirrors (see scripts/publish.sh):
##   make publish-stage REPO=all|<name>          lay the filtered snapshot over the public tip
##   make publish-status                         curated commits and remaining paths per repo
##   make publish-push REPO=all|<name> [DRY_RUN=1] [REPLACE=1]
##   make publish-abandon REPO=all|<name>
publish-stage:
	scripts/publish.sh stage $(or $(REPO),all) $(if $(BASE),--base $(BASE),)
publish-status:
	scripts/publish.sh status
publish-push:
	scripts/publish.sh push $(or $(REPO),all) $(if $(DRY_RUN),--dry-run,) $(if $(REPLACE),--replace,)
publish-abandon:
	scripts/publish.sh abandon $(or $(REPO),all)

.PHONY: release-images
release-images: ## Build, push, and bundle self-host images: RELEASE=<version> [DRY_RUN=1]
	@test -n "$(RELEASE)" || (echo "usage: make release-images RELEASE=<version> [DRY_RUN=1]" && exit 1)
	scripts/publish-images.sh "$(RELEASE)" $(if $(filter 1,$(DRY_RUN)),--dry-run,)

## Draft the CHANGELOG section from the curated commits staged for publish:
##   make changelog RELEASE=2026.9.10   (prints Markdown; paste and edit into CHANGELOG.md)
.PHONY: changelog
changelog:
	@test -n "$(RELEASE)" || (echo "usage: make changelog RELEASE=<version>" && exit 1)
	scripts/changelog-draft.sh $(RELEASE)
