# Chronicle Deployment Matrix

Use this matrix to choose the correct Docker Compose entrypoint. The compose files are not interchangeable.

| Scenario | Primary compose file(s) | When to use it | Notes |
|----------|-------------------------|----------------|-------|
| Local legacy all-in-one dev stack | `docker-compose.yml` | Quick local stack with bundled nginx | Uses the older local nginx flow documented in [README.md](/opt/chronicle/docker/README.md). |
| Source-checkout Traefik stack | `docker-compose.traefik.yml` | Developer-only stack built from this checkout behind an existing Traefik network | Its Chronicle image tags are local build outputs, not release pulls. Production uses `scripts/deploy.sh` with the production overlay. |
| Hardened Traefik overlay | `docker-compose.traefik.yml` + `docker-compose.security.yml` | When WAF, rate-limit overlays, or fail2ban/logging protections are required | See [security/README.md](/opt/chronicle/docker/security/README.md). |
| Legacy standalone reverse proxy | `docker-compose.prod.yml` with `--profile legacy-standalone` | Historical nginx-based stack only; not the active production path | Prefer `docker-compose.traefik.yml` plus `docker-compose.production.yml` through `scripts/deploy.sh`, or the `prod-backend` branch workflow for backend-only deploys. |
| Monitoring/event overlays | Base compose + `docker-compose.loki.yml` or `docker-compose.opensearch.yml` or `docker-compose.kafka.yml` | Add SIEM, log search, or event-streaming components to an existing deployment | Do not treat these as standalone entrypoints. Kafka requires `KAFKA_CLUSTER_ID`, `KAFKA_USER`, and `KAFKA_PASSWORD` in an untracked env file. |
| Temporal workflows | Base compose + `docker-compose.temporal.yml` | Add durable workflow engine for notifications, upload pipelines, scheduled ops | Requires base PostgreSQL. Admin tools via `--profile tools`. |
| RHEL 9 dedicated server | `docker-compose.traefik.yml` + `docker-compose.production.yml` or `k8s/overlays/production` | Internal dedicated host migration | Start with [docs/RHEL9-DEDICATED-SERVER-RUNBOOK.md](../docs/RHEL9-DEDICATED-SERVER-RUNBOOK.md). A 4-core/8 GB host is constrained; do not colocate the full monitoring/SSO/WAF stack there. |

## Current Defaults

- The root [README.md](/opt/chronicle/README.md) assumes `docker-compose.traefik.yml`.
- The active web auth path uses `/chronicle/v3/auth/session` plus
  `/chronicle/v3/auth/testing-login` in test-friendly environments.
- `docker/chronicle-config.json` is only a manual-diagnostics artifact produced by
  `generate-jwt.sh`; it is not deployed by default and is not part of the active
  runtime contract.
- External-domain and SSO allowlists must now be configured explicitly; do not assume Auth0 defaults.

## Validation

```bash
docker compose -f docker/docker-compose.traefik.yml config -q
docker compose -f docker/docker-compose.yml config -q
docker compose -f docker/docker-compose.prod.yml --profile legacy-standalone config -q
docker compose -f docker/docker-compose.traefik.yml -f docker/docker-compose.temporal.yml config -q
```

## Immutable image inputs

Production Compose resolves the requested release tags once, records the resulting digests,
and runs the services by `repository@sha256:digest`; rollback uses the recorded digest too.
The Compose base file's locally built Chronicle images are for source-checkout development and
are not release inputs.

Optional Loki, Temporal, and OpenSearch overlays require one owner-approved digest per image
through their `*_IMAGE_DIGEST` variables. They keep their documented version tag and fail
Compose interpolation when a digest is missing. Never copy a digest from an unrelated image or
architecture.

For Kubernetes, supply `CHRONICLE_BACKEND_IMAGE_DIGEST`,
`CHRONICLE_FRONTEND_IMAGE_DIGEST`, and `CHRONICLE_KEYCLOAK_IMAGE_DIGEST` as 64-character
lowercase SHA-256 values, then render and apply the immutable manifest:

```bash
bash scripts/render-k8s-production.sh | kubectl apply -f -
```

The source Kustomize files contain nondeployable digest sentinels; use the renderer for every
production apply.
