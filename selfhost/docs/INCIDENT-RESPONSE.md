# Security Incident Response

Use this when you suspect that someone reached data or credentials they should not have:
an unexpected login, a leaked `.env` or backup, a compromised host account, a lost laptop
with dashboard access, or a Chronicle security advisory that matches your version.

Run every command from the active bundle's `selfhost/` directory as the operator account.
Write down the time and the person for each step.

## 1. Collect

Collect before you change anything, so the evidence reflects the incident and not the
clean-up. Keep the copies private (mode `0700` directory, on a host you control).

```bash
case_dir="$HOME/chronicle-incident-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$case_dir"
./chronicle doctor --json >"$case_dir/doctor.json"      # contains no secrets
./chronicle status >"$case_dir/status.txt" 2>&1
docker compose ps -a >"$case_dir/compose-ps.txt"
docker compose logs --timestamps --no-color >"$case_dir/compose.log" 2>&1
# Application and audit log files (the file half of the audit trail)
docker compose cp backend:/var/log/chronicle "$case_dir/backend-logs"
# Database audit trail: request events and structured authorization/application events
docker compose exec -T postgres sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "\copy (SELECT * FROM public.audit) TO STDOUT WITH CSV HEADER"' \
  >"$case_dir/audit.csv" || exit 1
# Operator receipts: setup, upgrade, restore and rotation history
state_dir="$(bash -c 'source ./chronicle; need_env; printf "%s" "$STATE_ROOT"')" || exit 1
cp -a "$state_dir/operator-receipts" "$case_dir/" || exit 1
if [[ "$(uname -s)" == Darwin ]]; then
  ls -laT "$state_dir" "$state_dir/backups" "$state_dir/backups/last"
else
  ls -la --time-style=full-iso "$state_dir" "$state_dir/backups" "$state_dir/backups/last"
fi >"$case_dir/file-listing.txt" 2>&1
```

The configured state directory stays at its original absolute location after an update;
the recipe resolves it through the active launcher rather than assuming the release owns
the state. A receipt-copy failure stops collection visibly. Also keep the latest dump in
`$state_dir/backups/` (do not let rotation delete it: copy it into the
case directory) and your reverse proxy / load balancer and host SSH logs.

Never copy `.env` into the case directory, a ticket, a chat or an e-mail, and never paste
its values anywhere. It stays mode `0600` where it is. Record only that it exists and its
modification time (`stat .env`).

## 2. Isolate

Pick the smallest step that stops the exposure:

- **Stop everything:** `./chronicle down`. Data and backups are kept; participants' phones
  queue uploads and retry later.
- **Shut the dashboard only:** remove the suspect source ranges from
  `DASHBOARD_ALLOWED_IPS` (or set it to `127.0.0.1/32`), or set `INTERNAL_BIND=127.0.0.1`,
  then `./chronicle up`. Mobile ingest keeps working.
- **Shut the public listener:** remove the route on your load balancer, or run
  `./chronicle reconcile stop` before `docker compose stop web`. This pauses the boot and
  15-minute reconciliation schedule, which would otherwise restart `web`. The backend
  remains available for evidence collection. `web` also serves the internal dashboard;
  `./chronicle up` starts it again and resumes reconciliation when enabled.
- **Suspected host compromise:** take the host off the network and treat everything on it,
  including `backups/` and the keyring copy, as exposed. Rebuild on a clean host from a
  release bundle and restore from a backup taken before the compromise
  ([BACKUP-RESTORE.md](BACKUP-RESTORE.md)).

## 3. Rotate

Rotate every credential the attacker could have seen. Each command below has rollback and
writes a mode-`0600` receipt; details are in [SECRET-ROTATION.md](SECRET-ROTATION.md).

| Suspected exposure | Rotate |
|---|---|
| Dashboard password | `./chronicle rotate-secret dashboard` |
| Researcher sessions / JWT key | `./chronicle rotate-secret jwt --revoke-sessions` |
| `.env` file or host account | all of: `dashboard`, `jwt --revoke-sessions`, `internal-web`, `metrics`, `postgres`, `postgres-app`, `grafana` (if monitoring is on), `reviewer` (if enabled), then `tde`; replace and revoke `CHRONICLE_ALERT_WEBHOOK_URL` at its receiver (see SECRET-ROTATION.md), then replace the internal dashboard CA (row below) |
| Backups or the keyring copy | `./chronicle rotate-secret tde`, then destroy the exposed copies |
| Play Console reviewer credential | `./chronicle rotate-secret reviewer` |
| `tls/` directory or internal dashboard CA key | Replace the CA as in [SECRET-ROTATION.md](SECRET-ROTATION.md#internal-dashboard-ca) |

Per-device mobile API keys are revoked when a participant is withdrawn from the dashboard.
Also revoke VPN/SSH access for any person or key involved, and rotate any host, backup or
object-storage credentials that are not in `.env`.

### Emergency dashboard access

The dashboard has one shared researcher password and no per-user accounts. When someone
must reach study data during an incident and the current password is unknown or must not
be reused, the operator who controls the host:

1. Runs `./chronicle rotate-secret dashboard` to set a new password. This ends every
   dashboard session issued before the change.
2. If that person's network is not in `DASHBOARD_ALLOWED_IPS`, adds the narrowest source
   range for the duration of the access and runs `./chronicle up`.
3. Gives the password to that person out of band, and writes in the incident record who
   received it, when, and why. The audit trail attributes every dashboard action to the
   shared account (with a keyed source-address fingerprint only when
   `CHRONICLE_RECORD_STAFF_IP=true`), so this record is what ties actions to a person.
4. When the access is no longer needed, removes the temporary source range and rotates the
   dashboard password again.

## Upgrade to the fixed release

After preserving evidence and containing the incident, run `./chronicle update` from the
active post-reset installation to apply the latest stable fix, then `./chronicle verify`.
Use `./chronicle update <version>` when the advisory names a specific fixed release.
A failed update restores the pre-update safety dump and previous release automatically.
Pre-reset installations (2026.10.9 and earlier) require a fresh installation instead;
follow [upgrade and rollback](UPGRADE-ROLLBACK.md). On a compromised host, rebuild on a clean
host and restore an independently reviewed compatible backup as described above.

## 4. Notify

- **Your institution:** the information-security office, the data protection delegate if
  one is designated, and the IRB / ethics committee that approved the study.
- **Chronicle maintainers:** if the cause may be a Chronicle defect, report it privately
  through GitHub's private vulnerability reporting, as described in `SECURITY.md` at the
  bundle root. Do not open a public issue.

## 5. Recover and review

1. Upgrade to the fixed release with `./chronicle update` on a post-reset installation.
   Pre-reset installations require a fresh directory and fresh volumes. Follow
   [upgrade and rollback](UPGRADE-ROLLBACK.md). For recovery, guarded
   `./chronicle restore "--trusted-sha256=${TRUSTED_SHA256}" /backups/reviewed-recovery.sql.gz`
   accepts a reviewed backup from the same or an older post-reset release.
2. `./chronicle up`, `./chronicle verify`, `./chronicle doctor`.
3. Confirm that the rotated credentials work and the old ones fail.
4. Write a short review: timeline, cause, data affected, notifications sent, and what
   changes. Keep it with the case directory under the institution's
   approved retention schedule.
