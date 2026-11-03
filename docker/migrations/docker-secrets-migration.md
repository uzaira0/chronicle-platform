# Migrate Secrets from Environment Variables to Docker Secrets

## Problem
All secrets (DB password, JWT secret, SMTP credentials) are passed as environment
variables, visible via `docker inspect chronicle-backend` to anyone with Docker socket access.

## Migration Steps

### 1. Create Docker secrets
```bash
echo "your-db-password" | docker secret create chronicle_db_password -
echo "your-jwt-secret" | docker secret create chronicle_jwt_secret -
echo "your-smtp-password" | docker secret create chronicle_smtp_password -
echo "your-grafana-password" | docker secret create chronicle_grafana_password -
```

### 2. Update docker-compose.traefik.yml
Add a top-level `secrets:` block and reference secrets in services:
```yaml
secrets:
  chronicle_db_password:
    external: true
  chronicle_jwt_secret:
    external: true

services:
  chronicle-backend:
    secrets:
      - chronicle_db_password
      - chronicle_jwt_secret
    environment:
      # Remove POSTGRES_PASSWORD, JWT_SECRET from env
      # Read from /run/secrets/chronicle_db_password at startup
```

### 3. Update entrypoint to read from secret files
Modify the backend command to read secrets from files:
```sh
export POSTGRES_PASSWORD=$(cat /run/secrets/chronicle_db_password)
export JWT_SECRET=$(cat /run/secrets/chronicle_jwt_secret)
```

### 4. Verify
```bash
# Should NOT show secrets anymore
docker inspect chronicle-backend --format='{{json .Config.Env}}' | python3 -m json.tool
```

## Note
This requires Docker Swarm mode (`docker swarm init`) for native Docker secrets.
For standalone Docker Compose, use `secrets` with `file:` driver instead of `external:`.
