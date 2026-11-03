# Secret Rotation and Interrupted-Operation Recovery

Run rotation commands from the `selfhost/` directory of the release that currently owns
the deployment. They update the existing mode-`0600` `.env`; they never accept a secret as
a command argument and never print a generated or chosen value.

```bash
(
  set -euo pipefail
  cd /absolute/path/to/chronicle-selfhost-<version>/selfhost
  chmod 600 .env
  ./chronicle rotate-secret --help
)
```

`--yes` skips the impact confirmation. It does not make a password appear in shell history:
the dashboard password is still read silently, and all other values are generated directly
into `.env`. Each service reconciliation has a bounded wait (300 seconds by default, set by
`SECRET_ROTATION_WAIT_TIMEOUT_SECONDS`).

Before the first rotation on a fresh installation, let the backend become healthy and run
`./chronicle verify`. Setup records generation dates (no credential values) in
`CHRONICLE_SECRET_GENERATED_AT` alongside the mode-0600 installation settings, and every
completed rotation writes a receipt under `operator-receipts/secret-rotations/`.
`./chronicle doctor` reports each secret's age in days from the newer of the two; the TDE key
uses its creation date until its first rotation. Doctor reports ages only: how old a secret
may get is your own policy.

Dashboard acceptance uses `DASHBOARD_BASE_URL` and the existing dashboard trust anchor,
with certificate verification and proxies bypassed. If a private management listener
deliberately excludes the operator host, a 403 retains the new credential and records
`dashboard_auth=operator_check_required`; complete sign-in from an allowed researcher
browser at the printed URL. A loopback listener returning 403 fails rotation, since that
would exclude the operator's SSH tunnel too. For recovery, use a reviewed backup from the same or an older post-reset release;
see [backup and restore](BACKUP-RESTORE.md).

## What each command changes

| Command | Effect | Expected interruption |
|---|---|---|
| `./chronicle rotate-secret dashboard` | Reads a new password twice, hashes it in the digest-pinned Caddy image over stdin, recreates `backend` and `web`, ends every dashboard session issued before the change, and proves the password opens the internal dashboard. Only the bcrypt hash is stored. | Every researcher signs in again with the new password. |
| `./chronicle rotate-secret jwt` | Generates a 256-bit signing value and recreates `backend`; retains the previous key for one `DASHBOARD_SESSION_MINUTES` window, including sessions without a key ID. | Existing sessions keep their own expiry. Another routine rotation waits until this overlap ends. |
| `./chronicle rotate-secret jwt --revoke-sessions` | Replaces the signing key and removes the previous key and its overlap. Use after a signing-key or `.env` leak. | All researcher sessions must sign in again. |
| `./chronicle rotate-secret internal-web` | Generates the Caddy-to-backend credential and recreates `backend` and `web` together. | API/dashboard requests may briefly retry. |
| `./chronicle rotate-secret reviewer` | Generates or rotates the reusable Play Console reviewer credential, enables its exact study-scoped route, and recreates `backend`. | The previous Console value immediately receives `401`; update Play Console in the same window. |
| `./chronicle rotate-secret metrics` | Generates the backend metrics credential. With `overlays/monitoring.yml`, refreshes its scraper secret and config, recreates `backend` and VictoriaMetrics, then verifies the backend target is up. | Update separately configured scrapers from the protected `.env`. |
| `./chronicle rotate-secret postgres` | Publishes a generated password, changes the live PostgreSQL role over stdin, then reconciles and health-checks the complete Compose stack. | This is the broadest restart; expect a short full-stack interruption. |
| `./chronicle rotate-secret postgres-app` | Rotates the independent `chronicle_app` login through the owner connection and recreates the backend. The owner credential and backup/restore connections retain their current password. | Brief backend restart; failed rotation restores the previous app credential and supports the same interrupted-operation recovery. |
| `./chronicle rotate-secret grafana` | Uses Grafana's authenticated password API, recreates Grafana, and verifies the new login. | Grafana only; requires `overlays/monitoring.yml`. The generated value remains only in `.env`. |
| `./chronicle rotate-secret tde` | Takes and gzip-verifies a fresh plain-SQL dump, activates a timestamped pg_tde principal key online, verifies all public tables remain encrypted, and atomically refreshes the backed-up keyring. | No PostgreSQL restart; requires encryption and the backups overlay. |

After any rotation, run:

```bash
./chronicle verify
# Internal-dashboard deployments can also prove the chosen password without shell history:
./chronicle verify --dashboard-password
```

Routine JWT rotation writes `JWT_SECRET_PREVIOUS_EXPIRES_AT` as absolute Unix seconds.
The running verifier checks it on every request; an expired key stays disabled across
restarts. Its protected value can remain in `.env` until the next rotation or be removed
with its expiry in a trusted editor after the overlap. Never copy either signing value
into a log, terminal output, or support ticket.

For Grafana, open `.env` only in a trusted local editor and move the new password directly
to the password manager used by the operators. Do not use `cat .env`, paste the value into a
chat, or put it in a command line.

The same rule applies to `CHRONICLE_REVIEWER_ACCESS_SECRET`: copy it from a trusted editor
directly into Play Console. It is deliberately not printed by the rotation command. Set the
synthetic study UUID and non-PII participant ID first; the command refuses to generate or
enable the credential without both, and it queries the live database to require an active
study plus a synthetic participant in `ENROLLED` state. Run
`./chronicle doctor` first and require the `reviewer-scope` check to be `ok`. Rotation
invalidates the previous reusable value
immediately and does not broaden it beyond the exact reviewer bootstrap endpoint.

## Internal dashboard CA

`tls/internal-ca.key` signs the generated internal dashboard certificate, which also serves
the pool listener when `POOL_LISTENER_TLS=true`. No `rotate-secret` command covers it.
cert-init creates a CA only when both `tls/internal-ca.crt` and `tls/internal-ca.key` are
absent, and refuses to start once the CA is within 30 days of expiry. To replace it after a
suspected key exposure, or before that refusal:

Run from the active release's `selfhost/` directory. Resolve the mounted state directory
through the launcher; updates can leave it outside this release:

```bash
(
  set -euo pipefail
  state_dir="$(bash -c 'source ./chronicle; need_env; printf "%s" "$STATE_ROOT"')" || exit 1
  TLS_DIR="$state_dir/tls"
  ca_archive="$(mktemp -d "$TLS_DIR/retired-dashboard-ca.XXXXXX")" || exit 1
  docker compose stop web || exit 1
  mv -- "$TLS_DIR/internal-ca.crt" "$TLS_DIR/internal-ca.key" \
    "$TLS_DIR/internal-cert.pem" "$TLS_DIR/internal-key.pem" "$ca_archive/" || exit 1
  ./chronicle up || exit 1
)
```

The archive directory is mode `0700` inside `tls/`, which the startup readability check
leaves owner-only. Destroy the old key when your incident procedure allows; nothing deletes
it for you. cert-init issues a new CA and a leaf with the same SANs.
Resolve the state directory again as above for subsequent commands (the block's variables
are local to its subshell). Replace the trusted CA using `$TLS_DIR/internal-ca.crt` on researcher machines and, with
`POOL_LISTENER_TLS=true`, on the load balancer; remove trust in the old CA there. Then run
`./chronicle verify`.

An operator-supplied `internal-cert.pem` is not signed by this CA; renew it with its issuer.

## TDE-specific recovery facts

The pre-rotation dump is written under:

```text
${CHRONICLE_STATE_DIR}/backups/secret-rotation/
```

It is ordinary compressed SQL and therefore as sensitive as the database. The completion
receipt records its path and SHA-256, not its contents. Rotation also runs the existing
`db-init` keyring-copy path after activating the key; that copy is atomic, byte-compared,
mode `0600`, and stored at `backups/keyring/chronicle-keyring.per`. Future `db-init` runs
preserve whichever principal key the database already reports as active instead of silently
returning to the bootstrap key.

Keep the whole `backups/` tree off-box as described in [BACKUP-RESTORE.md](BACKUP-RESTORE.md).
A valid SQL dump remains recoverable without pg_tde even if every keyring copy is lost.

## Automatic rollback

Before changing anything, the command creates this private transaction directory under the
resolved state directory:

```text
${CHRONICLE_STATE_DIR}/.chronicle-secret-rotation/
```

It contains the previous `.env` and non-secret operation metadata. PostgreSQL, Grafana, and
TDE rotations also know how to reverse the corresponding live external change. An ordinary
command failure triggers rollback automatically, reapplies the previous service
configuration, and removes the transaction only after rollback succeeds.

Do not run restore and rotation at the same time. Each command refuses the
other operation locks and rechecks after acquiring its own lock, closing the concurrent
start race. A completed operation writes a private, secret-free JSON receipt under:

```text
${CHRONICLE_STATE_DIR}/operator-receipts/secret-rotations/
```

The receipt records the release, operation, completion time, and verification result. It
does not contain old/new passwords, hashes, JWT/HMAC values, or keyring bytes.

## Recover after a host crash or `kill -9`

A hard interruption can prevent the EXIT trap from running. If
`.chronicle-secret-rotation` remains:

1. **Do not delete, rename, edit, or copy it.** `old.env` is the only saved prior credential
   set and is itself sensitive.
2. Confirm no `rotate-secret.sh` process is still running. Recovery also refuses a recorded
   owner PID that still exists.
3. Inspect only non-secret status first:

   ```bash
   docker compose ps --all
   docker compose logs --tail=100 backend web postgres grafana
   ```

4. Choose one direction:

   ```bash
   # Keep and finish the credential already published in the current .env:
   ./chronicle rotate-secret recover --forward

   # Restore old.env and reconcile services to the pre-rotation credential:
   ./chronicle rotate-secret recover --rollback
   ```

Recovery does not trust the last phase label alone. It compares the current `.env` with the
saved file; for PostgreSQL and Grafana it probes both candidate credentials without putting
either in argv; for TDE it accepts only the saved old/new key names and verifies the active
provider. If a new value had not yet been durably published, forward recovery refuses and
tells you to roll back before starting a new rotation. If neither external credential works,
or TDE reports an unrelated key, recovery stops and preserves all evidence rather than
guessing.

For TDE, both candidate key files are individually atomically published and flushed to disk,
then a durable `tde-metadata-ready` phase marker is published before PostgreSQL key activation
is attempted. A transaction still at `prepared` is therefore pre-activation: only
`recover --rollback` is accepted, and it safely removes even partially written key metadata.
At or after `tde-metadata-ready`, recovery requires both private metadata files and reconciles
the live key instead of relying on the phase label to say whether the database transaction
committed.

The direction is restart-safe: if recovery itself is interrupted, run the same direction
again. Do not switch direction after a partial recovery without first diagnosing the
reported state. A successful recovery health-checks the affected services, writes a recovery
receipt, and only then removes the transaction directory. Dashboard forward recovery cannot
reconstruct the cleartext password from its hash, so it requires the follow-up
`./chronicle verify --dashboard-password` check.

If recovery still fails, preserve `.env`, the transaction directory, relevant container
logs, and the secret-free receipts. Do not paste either `.env` file into an issue or support
chat.

## Credentials not handled by this command

- **`CHRONICLE_ALERT_WEBHOOK_URL`:** issue a replacement webhook at the receiver, revoke
  the old webhook, update the URL in `.env` using a trusted local editor, and run
  `./chronicle up`. Send a Grafana contact-point test and confirm delivery. Application
  sessions stay active; alert delivery resumes with the replacement receiver credential.
- **TLS private keys and certificates:** use your institution/CA's issuance and revocation
  procedure. Replace the matching certificate/key pair atomically in the state-directory
  `tls/` path, preserve private-key mode `0600`, recreate `web`, and verify the served chain.
  `rotate-secret` does not generate or revoke certificates.
