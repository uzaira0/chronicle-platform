# Monitoring and alert runbook

Start with `./chronicle doctor`. It reports the failed check, likely cause, and recovery
command without exposing deployment secrets. After any repair, run `./chronicle doctor`
and `./chronicle verify`; both must pass.

The operational probe runs as the operator UID/GID selected by `./chronicle`, with no
capabilities. The monitoring initializer assigns its textfiles to that same account.
Two reviewed monitoring exceptions retain UID 0: `cadvisor` reads root-owned host cgroups
and Docker storage through read-only mounts; `docker-socket-proxy` alone mounts the host
Docker socket. Its HAProxy configuration permits only the GET container/info/version
endpoints, rejects writes, and listens on an internal network shared only with cAdvisor.
Both retain a read-only root filesystem, no capabilities, no-new-privileges, health checks,
and memory/PID ceilings. The socket still grants its holder host-level access if the proxy
process is compromised; disable the monitoring overlay when that access is unacceptable.

| Alert | Confirm | Likely cause | Recover |
|---|---|---|---|
| Backend, database, or web down | `./chronicle status`; `./chronicle logs backend postgres web` | The first fatal log line normally identifies configuration, migration, disk, or dependency failure. | Correct that first failure and run `./chronicle up`. |
| TDE unhealthy | `./chronicle check`; `./chronicle logs db-init postgres` | Principal key unavailable, default table access method changed, or an application table is not encrypted. | Do not recreate the keyring. Follow the bundled TDE recovery guidance, run `./chronicle up`, and confirm the alert clears. |
| Public probe down | `curl -fsS "$CHRONICLE_PUBLIC_BASE_URL/health"` from a separate machine (use `https://$DOMAIN` when the override is blank) | DNS, certificate, load-balancer, firewall, or listener binding. | Repair the external path, then run `./chronicle verify`. |
| Logs or metrics down | `./chronicle monitoring status`; `./chronicle logs victoriametrics victorialogs fluent-bit operational-probe` | Full observability disk, invalid retention, unavailable plugin, or failed scrape credentials. | Correct the first error and run `docker compose up -d monitoring-config victoriametrics victorialogs fluent-bit grafana`. |
| Configuration invalid | `./chronicle check` | An edited `.env`, missing overlay, wildcard bind, weak credential, or missing certificate. | Correct every `FAIL` line and run `./chronicle up`. |
| Backup stale or invalid | `./chronicle logs db-backup`; `STATE_DIR="$(bash -c 'source ./chronicle; need_env; printf "%s" "$STATE_ROOT"')" && gzip -t "$STATE_DIR"/backups/last/*.sql.gz` from the active release's `selfhost/` directory (backups live in the state directory that `CHRONICLE_STATE_DIR` names, which an update keeps; a new release's own backups directory is empty) | Scheduler failure, unavailable database/backend, full disk, or corrupt file. | Correct the cause and run `docker compose restart db-backup`; verify a new dump. |
| Disk or inode pressure | `df -h`; `df -i`; inspect the Database and Storage dashboard | Database growth, retained backups, container logs, or observability storage. | Add disk first or remove only documented disposable artifacts; never delete database volumes. |
| Backend/upload/enrollment/export/deletion/database errors | Correlate the Application dashboard time with Operational Logs | Bad requests, incompatible clients, failed background work, database pressure, or a backend defect. | Follow the correlated error ID, correct the cause, and verify the error rate returns to zero. |
| Repeated restart or OOM | `docker inspect <container>`; compare memory panels to configured limits | Resource limit too small or runaway workload. | Raise the documented service limit only after identifying the pressured service. |
| Certificate expiry | `openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" </dev/null 2>/dev/null \| openssl x509 -noout -dates` | Upstream or local certificate was not renewed. | Replace/renew it and run `./chronicle verify`. |
| Dashboard sign-in failures | Chronicle Operational Metrics in Explore: `chronicle_api_errors_total` for POST `/v3/auth/dashboard-login` or `/chronicle/v3/auth/dashboard-login`, status 401 or 429; the alert counts more than 20 in 15 minutes on internal and public exposures. | Password guessing, or one user with a forgotten password; 429 denotes backend rate limiting. | Restrict `DASHBOARD_ALLOWED_IPS` for internal access or the institution's public edge policy; run `./chronicle rotate-secret dashboard` if the password may be known. |
| Permission or role change | Study audit log at the alert time | An administrator granted or revoked study access. | Confirm the change was expected. If not, revoke it, rotate that administrator's credential, and follow [INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md). |
| Operator command failed | Open Operational Events and correlate its timestamp with logs | A setup, check, restore, rotation, or shutdown command exited unsuccessfully. | Rerun `./chronicle doctor`, then follow the command-specific runbook printed by the failed command. |

## Troubleshooting

| Failure | Confirm | Fix |
|---|---|---|
| Port in use | `./chronicle check` prints `PORT=N is already in use`; `ss -ltnp 'sport = :N'` names the holder | Stop the holder, or change that `*_PORT` in `.env`, then `./chronicle check && ./chronicle up`. |
| Wrong bind address | `./chronicle check` prints `*_BIND=... is not an address on this host` | Set that `*_BIND` in `.env` to one of the listed addresses, then `./chronicle check && ./chronicle up`. |
| Expired certificate (own TLS) | `openssl x509 -noout -enddate -in "$TLS_DIR/cert.pem"` | Replace the pair in the configured state directory, run `cert-init`, restart `web`, and verify the served certificate below. |
| Expired certificate (internal listener) | `openssl x509 -noout -enddate -in "$TLS_DIR/internal-cert.pem"` | Remove `$TLS_DIR/internal-cert.pem` and `$TLS_DIR/internal-key.pem`, then `./chronicle up` regenerates them. |
| Disk full | `df -h`; `./chronicle doctor` | Free or add space (never delete volumes), then `./chronicle up`. Postgres does not restart by itself after a failed start. |
| Migration failed (first install) | `./chronicle logs migrate` shows the first Flyway error | Correct the cause it names and run `./chronicle up`. For replacement, follow [upgrade and rollback](UPGRADE-ROLLBACK.md). |
| Upload rejected, clock skew | `timedatectl` shows `System clock synchronized: no` | `sudo timedatectl set-ntp true`; signed requests allow 30 s of skew. |

Run these commands from the active release's `selfhost/` directory. The launcher resolves
`CHRONICLE_STATE_DIR` from `.env`; a relative value is resolved against that directory, and
the default `.` means that directory. For an own-TLS renewal, install the replacement pair
in the resolved `tls/` directory. The subshell keeps these temporary variables local;
resolve `TLS_DIR` again before using it in later commands:

```bash
(
  set -euo pipefail
  STATE_DIR="$(bash -c 'source ./chronicle; need_env; printf "%s" "$STATE_ROOT"')" || exit 1
  TLS_DIR="${STATE_DIR}/tls"
  DOMAIN=chronicle.example.org
  install -m 0644 /path/to/new-cert.pem "$TLS_DIR/cert.pem"
  install -m 0600 /path/to/new-key.pem "$TLS_DIR/key.pem"
  docker compose run --rm --no-deps cert-init
  docker compose restart web
  ./chronicle verify
  openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" </dev/null 2>/dev/null |
    openssl x509 -noout -subject -enddate
)
```

## Viewer access

Grafana is never anonymous and never binds every interface. Create one account per trusted
observer with `./chronicle monitoring add-viewer NAME`; it receives only the Grafana Viewer
role. Remove or reset it with the corresponding `remove-viewer` or `reset-viewer` command.
Provisioned alerts are always visible in Grafana. To send them to a person, see
"Attach a notification channel" below.

The shared log stream is deliberately not a copy of application logs. Fluent Bit emits
only timestamp, service, severity, normalized route, status, duration, request/error ID,
operation, result, failure category, release version, SQLSTATE, and exception class. Every
approved source uses a structured envelope. It discards messages, query strings, headers,
payloads, SQL text, stack traces, and identity/address fields before ingestion; unknown lines
are represented only as generic service/severity events.

## Attach a notification channel

Alerts reach a person only through a webhook. Grafana sends every firing alert with the label
`scope=selfhost` to one contact point, `chronicle-dashboard-only`, defined in
`monitoring/grafana-alerting/contactpoints.yml`. Its URL comes from
`CHRONICLE_ALERT_WEBHOOK_URL`. When that is unset, the URL is the closed discard port
`http://127.0.0.1:9`, so delivery fails and alerts stay in Grafana only.
`./chronicle doctor` reports `alert-route` as a failure while the setting is empty and as
configured when it is nonempty; `./chronicle check` and `up` print the same warning. That check does not send a message or prove the receiver is
reachable; use Grafana's contact-point test below to confirm delivery to the operator.

1. Choose a receiver that accepts a JSON `POST`: a chat incoming webhook, a pager service,
   or an internal relay that forwards to email. Chronicle sends no email itself. Payloads
   hold only the alert name, labels, summary, and runbook link, never participant data.
2. In `.env`, add `CHRONICLE_ALERT_WEBHOOK_URL=https://...`. Many webhook URLs contain a
   token, so treat the value as a secret and never paste it into chat or a command line.
3. Apply it with `docker compose up -d grafana`. For a new release, run `./chronicle update`; it carries `.env` forward. Use the guarded `./chronicle restore "--trusted-sha256=${TRUSTED_SHA256}"`
   for compatible recovery data. Do not edit the generated `contactpoints.yml`.
4. Send a test: in Grafana, sign in as the admin user, open Alerting > Contact points,
   select `chronicle-dashboard-only`, and choose Test. Confirm the message arrives.
5. Grouping is by alert name, severity, and service. Grafana waits 30 s before the first
   message and repeats an unresolved alert every 24 h.

Only `webhook` is provisioned. For email, paging or another receiver protocol, point
`CHRONICLE_ALERT_WEBHOOK_URL` at an institution-managed JSON webhook relay that forwards
to that receiver. Updates preserve this protected environment setting. Keep the signed
`contactpoints.yml` unchanged: editing bundled provisioning files causes update's manifest
checksum validation to fail.

## Single-node scale ladder

Configure an off-host uptime probe against the public HTTPS `/health` URL at least every
minute, with a human notification destination. Test delivery by briefly stopping `web` in
a maintenance window, confirm the failure notification, restart it and confirm recovery.
The probe must run outside this host so a host outage can still produce a notification.
Record the destination owner, probe URL and last delivery test in the operations register.

1. Add disk when free-space, inode, or predicted-growth panels show pressure.
2. Add RAM when PostgreSQL/backend memory or connection pressure is sustained; add CPU for
   sustained ingestion CPU after confirming disk is not the bottleneck.
3. Adjust the documented `*_MEM_LIMIT`, PostgreSQL, and JVM values together, then compare
   the same dashboard window before and after.
4. The tested ceiling is one backend, one PostgreSQL, and one instance of each selected
   sidecar on one host. Use the dashboards as the cutover signal because data volume and
   collection modules dominate capacity. Multiple backend replicas, HA PostgreSQL, or
   multi-node storage require a separate deployment rather than `docker compose up --scale`.

## Service privileges

VictoriaMetrics and VictoriaLogs run as 65534, Fluent Bit as 100, Grafana as 472,
and the metrics exporter as 10001. The one-shot configuration job owns volume setup.
The root exceptions are cAdvisor, which reads host cgroups and Docker storage; the
isolated GET-only socket proxy, which connects to the root-owned Docker socket;
and the operational probe, which traverses the private backup directory using
only DAC_READ_SEARCH. Each keeps a read-only root, dropped capabilities and private
mounts or networks. Audit the running UIDs and health after an image update.

## Buffered log delivery

Docker's `fluentd-buffer-limit` counts messages, not bytes; these queues consume dockerd memory
outside container limits. Each of the three containers queues at most 4,096 messages while Fluent Bit
is unreachable; later messages are dropped and the app keeps running. The shared options use the Compose service label to select a tag.
Fluent Bit uses filesystem buffering for forwarded logs, at most 16 resident chunks and a
128 MiB queued-output ceiling. Its tail inputs retain their existing 10 MiB and 2 MiB limits.
When that disk queue fills, the oldest pending logs can be lost; investigate sink outages promptly.

Grafana's VictoriaLogs plugin is hash-verified during image build. Startup needs no plugin
repository access. Its generated certificates live in a dedicated named volume shared with
the certificate initializer; generated files are not individual bind sources.
