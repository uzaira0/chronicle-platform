# Chronicle Docker Development Setup

This Docker Compose setup runs the legacy all-in-one Chronicle stack locally for development and testing.

- **nginx** - Reverse proxy (port 80)
- **backend** - Chronicle Server (Java/Kotlin API)
- **frontend** - React web application
- **postgres** - PostgreSQL 18 (Percona, pg_tde) database

## Prerequisites

- Docker and Docker Compose installed
- All submodules initialized (`git submodule update --init --recursive`)

## Quick Start

```bash
# From the repository root
cd docker

# Build and start all services
docker compose up --build

# Or run in background
docker compose up --build -d
```

The application will be available at: **http://localhost**

If you are working against the Traefik-aligned deployment path used by the root quick start, use [DEPLOYMENT-MATRIX.md](DEPLOYMENT-MATRIX.md) and prefer `docker-compose.traefik.yml` instead.

## Services

| Service   | Internal Port | External Port | Description                    |
|-----------|---------------|---------------|--------------------------------|
| nginx     | 80            | 80            | Reverse proxy                  |
| backend   | 40320         | -             | Chronicle API server           |
| frontend  | -             | -             | Static files (built at startup)|
| postgres  | 5432          | 5434          | PostgreSQL database            |

## API Routes

nginx routes requests as follows:

- `/chronicle/*` → backend (API)
- `/compliance/*` → backend (API)
- `/principal/*` → backend (API)
- `/import/*` → backend (API)
- `/datastore/*` → backend (API)
- `/*` → frontend (static files)

## Configuration

### Authentication

Authentication is in a testing-only transitional state for local development.

- The active web flow checks `/chronicle/v3/auth/session` first.
- Test-friendly deployments may expose `/chronicle/v3/auth/testing-login` so the
  server can mint Chronicle-managed cookies directly.
- `docker/generate-jwt.sh` is now a manual diagnostic helper for
  `/chronicle/v3/auth/set-cookie`, not the primary frontend bootstrap path.

### Database

Default PostgreSQL credentials:
- Host: `postgres` (internal) or `localhost:5434` (external)
- Database: `chronicle`
- Username: `oltest`
- Password: the `POSTGRES_PASSWORD` value from `docker/.env` (required; there is no default)

Connect with psql:
```bash
psql -h localhost -p 5434 -U oltest -d chronicle
```

### Backend Configuration

The backend configuration is in `rhizome-docker.yaml`. Key settings:
- Database connection points to the `postgres` container
- Tables are auto-initialized on startup
- Hazelcast runs in local/embedded mode

## Common Commands

```bash
# View logs
docker compose logs -f

# View logs for specific service
docker compose logs -f backend

# Restart a service
docker compose restart backend

# Stop all services
docker compose down

# Stop and remove volumes (clean slate)
docker compose down -v

# Rebuild a specific service
docker compose build backend
docker compose up -d backend
```

## Troubleshooting

### Backend fails to start
- Check if PostgreSQL is ready: `docker compose logs postgres`
- The backend waits for postgres health check before starting

### Frontend not loading
- Check nginx logs: `docker compose logs nginx`
- Verify frontend build completed: `docker compose logs frontend`

### Database connection issues
- Ensure postgres container is healthy: `docker compose ps`
- Check `rhizome-docker.yaml` for correct connection settings

### Port conflicts
- If port 80 is in use, edit `docker-compose.yml`:
  ```yaml
  nginx:
    ports:
      - "8080:80"  # Change 80 to available port
  ```

## Development Workflow

For active frontend development, you may prefer running the frontend locally:

```bash
# Start only backend services
docker compose up postgres backend nginx

# Run frontend dev server separately (with hot reload)
cd ../chronicle-web
bun install
bun run modern:dev
```

The modern Bun dev server runs on port 5173 by default. The legacy webpack shell remains available only for compatibility work.

## Production-Like Validation

Before treating a Docker-backed environment as release-ready, run the current
production-like validation from the repo root:

```bash
./scripts/chronicle-production-like-validation.sh
```

This does not prove real institutional SSO because that integration is not
available yet. It does verify the current Chronicle-owned auth/session bridge,
compose syntax, web checks/tests, and browser smoke.
