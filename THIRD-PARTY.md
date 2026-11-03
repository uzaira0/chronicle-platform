# Licenses of shipped components

The self-host scripts and configuration in this repository are under the GNU General Public
License v3.0 (`LICENSE`), the same license as the Chronicle submodules. Root files contributed
upstream by OpenLattice (methodic-labs) were published under the Apache License 2.0, which permits
their inclusion in a GPL-3.0 work. The container images a deployment runs carry their own licenses.

## Chronicle images

| Image | License | Source |
|---|---|---|
| `ghcr.io/uzaira0/chronicle-backend` | GPL-3.0 | https://github.com/uzaira0/chronicle-server |
| `ghcr.io/uzaira0/chronicle-selfhost-frontend` | GPL-3.0 | https://github.com/uzaira0/chronicle-web |
| `ghcr.io/uzaira0/chronicle-selfhost-caddy` | Apache-2.0 (Caddy and caddy-ratelimit); its Go module dependencies carry their own licenses (Apache-2.0, BSD and MIT), shipped in the image under `/usr/share/licenses/caddy-modules` | https://github.com/caddyserver/caddy and https://github.com/mholt/caddy-ratelimit, built by `selfhost/Dockerfile.caddy` |
| `ghcr.io/uzaira0/chronicle-selfhost-grafana` (monitoring overlay) | AGPL-3.0 (Grafana, unmodified) plus the Apache-2.0 victoriametrics-logs-datasource plugin 0.33.1 added at `/opt/chronicle-plugins` (its LICENSE ships beside it) | https://github.com/grafana/grafana (13.2.4) and https://github.com/VictoriaMetrics/victorialogs-datasource (v0.33.1), built by `selfhost/Dockerfile.grafana` |

Each Chronicle image is built from the commit recorded in `release-manifest.json` as
`public_revision`: a commit of https://github.com/uzaira0/methodic (the release tag points at
it) whose submodules pin the exact `chronicle-server` and `chronicle-web` source.

## Third-party images

Pulled unmodified by digest from their publishers. Licenses are the upstream projects'.

`ghcr.io/uzaira0/chronicle-selfhost-backup` (backups overlay) is built by this project from
https://github.com/prodrigestivill/docker-postgres-backup-local (MIT, commit d00896ab, scripts
vendored in `selfhost/backup-image/` and modified: `backup.sh` restore-checks each dump before it
publishes the daily/weekly/monthly links, keeps the newest verified dump out of rotation and
records a success marker; `env.sh` refuses non-numeric `BACKUP_KEEP_*`; `init.sh` clears the
success marker; `selfcheck.sh` and `selfcheck.py` are Chronicle additions) with go-cron (MIT) and
Debian run-parts (GPL-2.0, source:
https://deb.debian.org/debian/pool/main/d/debianutils/) on the pinned Percona image; licenses ship in
the image under /usr/share/doc.

| Image | Used by | Upstream |
|---|---|---|
| Percona Distribution for PostgreSQL (`POSTGRES_IMAGE`) | database | https://github.com/percona/postgres |
| `victoriametrics/victoria-metrics`, `victoriametrics/victoria-logs` | monitoring overlay | https://github.com/VictoriaMetrics/VictoriaMetrics |
| `fluent/fluent-bit` | monitoring overlay | https://github.com/fluent/fluent-bit |
| `ghcr.io/google/cadvisor` | monitoring overlay | https://github.com/google/cadvisor |
| `tecnativa/docker-socket-proxy` | monitoring overlay | https://github.com/Tecnativa/docker-socket-proxy |

## Dashboard design assets

| Component | Author | License | Source |
|---|---|---|---|
| Equal (`@eqds/tokens`, `@eqds/css`, `@eqds/react`, `@eqds/icons`) | Uzair Alam (project owner) | MIT | `chronicle-web/vendor/equal/`; provenance and LICENSE included there; private owner source, no upstream URL |

The bundled Atkinson Hyperlegible and IBM Plex Mono fonts retain their SIL OFL 1.1 licenses.
