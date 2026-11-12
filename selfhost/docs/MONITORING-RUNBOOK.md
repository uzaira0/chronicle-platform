# Monitoring and alert runbook

Monitoring is optional and never gates Chronicle: `./chronicle up`, `update` and rollback wait
only for Chronicle's own services, then start the monitoring services with a separate bounded
wait. An unhealthy monitoring service is printed as a warning naming the service and
the command to read its log (for example `./chronicle logs grafana`), and `./chronicle doctor` reports it as a warning.
When Docker Compose cannot start monitoring at all (for example Docker has no address pool left
for its networks), the warning repeats Compose's own error and lists the services that were not
created. Those have no container and no logs: correct that error, then run `./chronicle up`.
A start that does not finish in time is reported as that, with the seconds it was given, and the
services are listed with the state Compose gives for each. When Compose cannot list them either,
the warning says their state is unknown and why; `./chronicle doctor` reports it once Docker answers.

Start with `./chronicle doctor`. It reports the failed check, likely cause, and recovery
command without exposing deployment secrets. After any repair, run `./chronicle doctor`
and `./chronicle verify`; both must pass.

The operational probe runs as the operator UID/GID selected by `./chronicle`, with no
capabilities. The monitoring initializer assigns its textfiles to that same account. Each
service's user and capabilities are listed under [Service privileges](#service-privileges).

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
Provisioned alerts are always visible in Grafana and, with no configuration, in the host's
system log; see "Where alerts go" below. To send them to a person, see "Attach a notification
channel".

The shared log stream is deliberately not a copy of application logs. Fluent Bit emits
only timestamp, service, severity, normalized route, status, duration, request/error ID,
operation, result, failure category, release version, SQLSTATE, and exception class. Every
approved source uses a structured envelope. It discards messages, query strings, headers,
payloads, SQL text, stack traces, and identity/address fields before ingestion; unknown lines
are represented only as generic service/severity events.

## Where alerts go

**With no configuration.** Grafana sends every firing alert with the label `scope=selfhost` to
one contact point, `chronicle-dashboard-only` (`monitoring/grafana-alerting/contactpoints.yml`).
Its URL comes from `CHRONICLE_ALERT_WEBHOOK_URL`; unset, it is the closed discard port
`http://127.0.0.1:9`, and no container gets a route out of the host. The host reads the alerts
instead: every 15 minutes the scheduled reconciliation runs `./chronicle doctor`, which asks
Grafana's Alertmanager API (over the private listener, as the admin) which alerts are firing and
writes each one to the host's system log with `logger`:

```
chronicle: Chronicle alert firing: <alert name> (<severity>): <summary>. Run ./chronicle doctor
```

at priority `user.crit`, again every 24 hours while it keeps firing (Grafana's own repeat
interval), and `Chronicle alert resolved: <alert name>` at `user.notice` once it stops. Read them
with `journalctl -t chronicle` (or `/var/log/syslog`, `/var/log/messages`). An institution that
forwards the host's syslog to central log collection receives them there with no further step.
`./chronicle doctor` lists firing alerts as `alerts-firing` and `./chronicle status` prints them
below the service table. `alert-route` in doctor says which of these applies; it warns only when
there is neither a webhook nor a schedule (no Linux cron, or `CHRONICLE_RECONCILE_ENABLED=false`),
because then alerts stay in Grafana. Nothing here pages a person: the system log is read when
someone or something reads it. To push alerts to a person, add a webhook:

## Attach a notification channel

A webhook delivers each alert to a person as Grafana fires it. `./chronicle doctor` reports
`alert-route` as configured when `CHRONICLE_ALERT_WEBHOOK_URL` is set; that check does not send a
message or prove the receiver is reachable; use Grafana's contact-point test below to confirm
delivery. The system-log path above keeps working alongside it.

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

Every long-running monitoring service keeps a read-only root filesystem, drops every capability
it does not list below, runs with no-new-privileges, and has memory and PID ceilings. One-shot
initializers (`monitoring-cert-init`, `monitoring-config`, `health-probe`) own volume setup and
exit. `operator` is the UID/GID `./chronicle` selects (`CHRONICLE_HOST_UID`/`GID`).

| Service | User | Capabilities added |
|---|---|---|
| `docker-socket-proxy` | root | none |
| `cadvisor` | 65532:65532 | none |
| `operational-probe` | operator | none |
| `public-probe` | operator | none |
| `egress-proxy` | 10001:0 | none |
| `metrics-exporter` | 10001:0 | NET_BIND_SERVICE |
| `monitoring-forward` | 10001:0 | none |
| `victoriametrics` | 65534:65534 | none |
| `victorialogs` | 65534:65534 | none |
| `fluent-bit` | 100:101 | none |
| `grafana` | 472:0 | none |

`docker-socket-proxy` is root because the host Docker socket is root-owned; its HAProxy permits
only the GET container/info/version endpoints, blanks every container's environment in what it
returns, and listens on an internal network shared only with cAdvisor. The socket still grants
its holder host-level access if the proxy process is compromised; disable the monitoring overlay
when that access is unacceptable. `cadvisor` is unprivileged and mounts only cgroups (`/sys`),
the host's `/proc` (per-container network counters), Docker's layer-id files and the backups
directory as a free-space mount point, all read-only: no container configuration, volume or host
root. Per-container disk usage needs Docker's storage directories, so it is not collected.
`metrics-exporter` keeps NET_BIND_SERVICE only because the caddy binary
carries that file capability. Audit the running UIDs and health after an image update.

## Buffered log delivery

Docker's `fluentd-buffer-limit` counts messages, not bytes; these queues consume dockerd memory
outside container limits. Each of the three containers queues at most 4,096 messages while Fluent Bit
is unreachable; later messages are dropped and the app keeps running. The shared options use the Compose service label to select a tag.
Fluent Bit uses filesystem buffering for forwarded logs, at most 16 resident chunks and a
128 MiB queued-output ceiling. Its tail inputs retain their existing 10 MiB and 2 MiB limits.
When that disk queue fills, the oldest pending logs can be lost; investigate sink outages promptly.

The forward input those containers deliver to (`FLUENT_BIT_FORWARD_PORT`, published on
`127.0.0.1` through monitoring-forward) has no authentication: Docker's `fluentd` log driver
cannot send Fluent Bit's shared key or use TLS, so requiring either would stop log delivery. Any
process on this host can write records to it, and they reach VictoriaLogs like any other. It
accepts writes only. Do not treat a VictoriaLogs record as proof of what a service did; the
backend's audit table and log files are the record ([INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md)).

Grafana's VictoriaLogs plugin is hash-verified during image build. Startup needs no plugin
repository access. Its generated certificates live in a dedicated named volume shared with
the certificate initializer; generated files are not individual bind sources.
