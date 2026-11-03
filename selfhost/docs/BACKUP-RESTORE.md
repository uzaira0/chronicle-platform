# Backup & Restore

The database files are encrypted at rest, but the backups are **not** — `pg_dump` reads
through the running server, so its output is ordinary compressed SQL with no encryption in
it. Any dump restores through `./chronicle restore` onto fresh volumes with a new keyring
([recover onto a fresh host](#recover-onto-a-fresh-host)).

That is deliberate. It means **the encryption key can never lock you out of your data** —
the dumps are a complete copy that needs no key. It also means the dumps are as sensitive
as the database itself: `${CHRONICLE_STATE_DIR:-.}/backups` is `0700` and owned by the deploying account, and you
should treat anywhere you copy it the same way.

Dumps leave out the withdrawal checkpoint and the TDE key-generation record. Restore keeps
the live copies: the key record describes this host's keyring, not the backup's study data.
A dump that still contains the key record restores; its copy is discarded inside the restore
transaction. `chronicle_ops/dump.py` owns the restore policy: application objects in
`public` come from the dump; continuity, key-generation evidence and installed `pg_tde`,
`pgcrypto` and `plpgsql` extension members stay live and are excluded from dumps. Restore
creates `pgcrypto` before replay when the database lacks it (a fresh volume), and the backup
self-check restores into scratch the same way, so a dump that needs a missing extension fails
there. Role definitions stay live; dump object ownership
is normalized to the restore user by `--no-owner`, while ACLs are restored.

Backup, rollback, pre-rotation backup and restore check the database catalogs against this
policy. An unknown schema, extension, owner or unsupported object class stops the operation.
Restore checks again inside its transaction, including after replay, so an older dump cannot
silently introduce an unclassified object. Review the policy when adding database objects.

Two links are not encrypted, as an **accepted residual risk** for a single-host install:

- **Dumps at rest.** Plain SQL on the host disk, in a `0700` directory; each dump is set to
  `0600` after every backup run. The control for the disk itself is **host full-disk
  encryption** (LUKS or your provider's encrypted volumes): use it whenever the disk may
  leave your control. `./chronicle check`, `doctor` and `verify` fail when backing-device
  encryption cannot be confirmed (Linux LUKS or macOS FileVault). For provider-managed encryption or another
  unavailable probe, obtain a reviewed waiver in the controlled operations register, with
  approver, scope, encryption evidence or compensating controls, expiry and review date.
  Set `BACKUP_STORAGE_ENCRYPTION_WAIVER` to that register reference in the protected
  `.env`; remove it when the waiver expires. Setup asks once for this reference when it cannot
  confirm storage encryption; an empty answer stops setup. Startup, checks, doctor and verify fail
  until storage encryption is confirmed or a reviewed waiver is recorded.
  The stack does not encrypt dumps itself, because a lost dump key
  would make the backups unrestorable. Encrypt dumps before they leave the host (below).
- **Service traffic.** JDBC requires verified PostgreSQL TLS, and PostgreSQL rejects
  plaintext TCP connections. Grafana and the authenticated backend metrics scrape use
  HTTPS with the bundled service certificate as their trust anchor, and so do every
  Caddy-to-backend request and the backup sidecar's readiness probe. The backend's plain
  HTTP port is used only by its own in-container healthcheck. Keep Grafana on a private
  management address and trust `tls/monitoring.crt` when opening it through an SSH tunnel.

A copy of the encryption keyring is kept at `backups/keyring/chronicle-keyring.per` under
that state directory so the backup set can also remount the data volume itself. **Back up
the whole state-directory `backups/` tree as one unit**,
and keep it somewhere other than the disk holding the data volume.

A dump becomes `last/<active-db>-latest.sql.gz` only after its scratch restore and
cleanup succeed. The adjacent verified marker binds the active database, timestamp,
and SHA-256; `verify` and `doctor` require it even when TDE is disabled. Verification
requires twice the larger live-database or uncompressed-dump size additionally free
on PostgreSQL storage. Doctor projects the retained gzip footprint separately against
backup storage. Startup/dependency/verification deadlines default to 3600 seconds.
Backup readiness (`BACKUP_STARTUP_TIMEOUT_SECONDS`), restore startup
(`RESTORE_START_WAIT_TIMEOUT_SECONDS`, falling back to `START_WAIT_TIMEOUT_SECONDS`) and
update startup (`UPGRADE_WAIT_TIMEOUT_SECONDS`, falling back to `START_WAIT_TIMEOUT_SECONDS`)
accept positive integer seconds above that default without a maximum. Set a finite wait
appropriate for the recovery or migration before starting the operation.
A successful `restore --no-start` writes a durable stop marker, so cron and reboot
reconciliation leave writers stopped until an explicit `up`.

## Automated backups (recommended)

Enable the overlay:

```ini
# .env — retain the existing mode overlay and append backups.yml
COMPOSE_FILE=docker-compose.yml:overlays/mode-behind-proxy-internal.yml:overlays/backups.yml
```

```bash
./chronicle check
./chronicle up
```

Dumps land in `${CHRONICLE_STATE_DIR:-.}/backups/` on the host, rotated
daily/weekly/monthly. `./chronicle setup` asks how long to keep each tier
(`BACKUP_KEEP_DAYS`, `BACKUP_KEEP_WEEKS`, `BACKUP_KEEP_MONTHS`): a number, or `all` to never
delete that tier. It suggests the backup image's own defaults (7 days, 4 weeks, 6 months);
answer from the institution's approved retention schedule.
A setup that reads its answers from a pipe gets no suggestion and must answer. Compose refuses
to start the backup sidecar until the values are set; nothing is pruned on a Chronicle-chosen clock.
`0` is not "no limit": it keeps only the newest dump of that tier.

`BACKUP_SCHEDULE` (default `@daily`) sets when the sidecar takes a dump. It accepts what the
sidecar's scheduler (go-cron, robfig/cron v3) accepts: a cron line of five fields (`0 3 * * 1-5`)
or six with leading seconds, with `*`, lists, ranges, steps and month or weekday names, optionally
prefixed by `TZ=<zone>`; `@hourly`, `@daily`, `@midnight`, `@weekly`, `@monthly`, `@yearly`,
`@annually`; or `@every <duration>` (`@every 6h`, `@every 1h30m`, `@every 1.5h`). When both the
day-of-month and the weekday field are restricted, the dump runs on days matching either one.
`./chronicle check` and `up` refuse a value the scheduler would reject or that never runs (such
as `0 3 30 2 *`), since the sidecar would otherwise sit idle. A backup is overdue once it is older
than the schedule's longest gap between runs plus 12 hours (36 hours for `@daily`, 3.5 days for
`0 3 * * 1-5`, 7.5 days for `@weekly`). `./chronicle verify`, `doctor` and the `backup-stale`
alert all use that window. Without a `TZ=` prefix the sidecar runs on UTC. With one, the window
follows that zone's daylight-saving changes: a run at a wall time the change skips does not happen
(`TZ=America/Santiago @daily` waits 47 hours across the September change, so it is overdue after
59 hours), and a run in a repeated hour happens twice.

Setup, `./chronicle check` and `./chronicle doctor` warn when the backup filesystem cannot hold
the chosen retention (the newest dump size times the number of dumps kept) and still keep
`MIN_FREE_DISK_GIB` free. A backup run that starts with less free space than `MIN_FREE_DISK_GIB`
fails; the failed run raises the `backup-stale` alert.
For a fresh installation, choose its backup directory explicitly. Copy reviewed compatible
backups there before running the guarded restore.
Copy encrypted backups to a separate host or storage account so a failed database disk
does not destroy the recovery copy.
Encrypt the complete backup directory, including the keyring, into a staging directory and
sync only that directory.

Replace the example GPG recipient with the institution's approved backup recipient.
Record key custodians, authorized access and a separately protected recovery method.
Test decryption where the recovery key is held. Encryption does not replace the recipient
and international-transfer assessment for the off-host destination. The existing recipe is:

```bash
(
  set -euo pipefail
  umask 077
  install -d -m 0700 /absolute/chronicle-state/backups-encrypted
  archive_tmp=/absolute/chronicle-state/backups-encrypted/chronicle-backups.tar.gz.gpg.partial
  trap 'rm -f -- "$archive_tmp"' EXIT
  tar -C /absolute/chronicle-state/backups -czf - . |
    gpg --batch --yes --encrypt --recipient ops@example.org >"$archive_tmp"
  mv -f "$archive_tmp" /absolute/chronicle-state/backups-encrypted/chronicle-backups.tar.gz.gpg
  trap - EXIT
  # Run from the host after encryption completes, on the approved copy schedule.
  rclone sync /absolute/chronicle-state/backups-encrypted remote:chronicle-backups
)
```

The sidecar takes one dump immediately after PostgreSQL is accepting connections and the
backend has completed Flyway migrations. It performs those checks inside its own startup
wrapper because Docker restart policies do not re-run Compose `depends_on` conditions
after a host or daemon restart. The default 3600-second (60-minute) bound is controlled by
`BACKUP_STARTUP_TIMEOUT_SECONDS`; a timeout leaves the scheduler stopped and the restart
policy tries the readiness sequence again instead of recording a failed initial backup.

> The stack requires `scram-sha-256` for *all* connections, including the local socket inside
> the container. The command below consumes the password already present in the PostgreSQL
> container; it does not export the host `.env` or put a password in Docker argv.

## Trigger one backup now

```bash
./chronicle backup
```

`backup` checks the active deployment owner and incomplete-operation interlocks under the
shared operation lock. It recreates only the configured backup sidecar as the operator uid
and waits for a new restore-verified dump and healthy scheduler. A failed run returns nonzero;
inspect `./chronicle logs db-backup` and `./chronicle doctor` before maintenance.

The restart-safe wrapper waits for PostgreSQL and the migrated backend, then the pinned
backup image's `BACKUP_ON_START` path writes an ordinary `.sql.gz` into the same rotated
backup tree used by `./chronicle restore`. A custom-format `pg_dump` written elsewhere is
not accepted by the guarded restore command; keep one backup format and one tested path.

## Restore

Before restoring, independently review the dump's source and record the expected SHA-256
digest through a trusted operator record. A `.sha256` file distributed beside the dump is
not independent provenance. Set `TRUSTED_SHA256` to that reviewed, lowercase 64-character
digest; `./chronicle restore` checks it and gzip integrity before acquiring the restore lock
or stopping writers. For a locally generated backup, review its source and operation record
before accepting that backup's digest for a manual restore.
Signed release installations require a Chronicle-stamped dump from the same release or
an older supported post-reset release. The release header is inside the hashed compressed
dump. A reviewed SHA-256 does not waive a missing header, a pre-reset version, or a newer
producing release; these inputs are rejected before writers stop.

```bash
TRUSTED_SHA256='<reviewed lowercase 64-character SHA-256>'
```

```bash
./chronicle restore "--trusted-sha256=${TRUSTED_SHA256}"
```

That restores the newest dump the backups overlay wrote
(`backups/last/chronicle-latest.sql.gz`). To pick a different one:

```bash
./chronicle restore "--trusted-sha256=${TRUSTED_SHA256}" /backups/daily/chronicle-20260809.sql.gz
```

The command resolves the selected container path below the host's configured `backups/`
directory and checks its gzip integrity before causing downtime. It then acquires
`${CHRONICLE_STATE_DIR}/.chronicle-restore.lock`, refuses to overlap an upgrade or secret
rotation, and stops the backend, dashboard proxy, database-initialization job, and backup
sidecar. It verifies those services are no longer running before invoking the destructive
one-shot restore service. If stopping or verification fails before that invocation, the
database is unchanged; the command restarts exactly the application services that were
running beforehand and releases the restore lock. A failed compensating restart is reported
separately so the operator can repair Compose and run `./chronicle up`.
Direct `docker compose run restore` execution is rejected because it cannot prove that
application writers are stopped.

Before the restore service drops anything, it writes the current database to
`backups/pre-restore-<timestamp>.sql.gz`, so restoring the wrong dump is recoverable. It
stops on the first error rather than continuing, and prints how many tables and rows landed
and whether they are encrypted. It also checkpoints current withdrawal receipts, revoked
mobile-key identifiers, withdrawn participants, deletion operations and
deletion tombstones in an owner-only schema that the selected dump cannot overwrite. Secret
hashes and credential values are never copied into this checkpoint.

The command also writes a mode-`0600` companion next to the safety dump, named
`pre-restore-<timestamp>.<suffix>.continuity.sql.gz`. Keep the safety dump and companion
together in the same protected backup set until reconciliation succeeds.

These safety dumps in the `backups/` root are outside the daily/weekly/monthly rotation. The backup
sidecar reclaims expired copies in its pre-backup hook, before free-space admission or
dumping, and again after backup. A copy can therefore disappear even if that backup later
fails. Copies expire only under the operator-selected
`PRE_OP_BACKUP_KEEP_DAYS`, which `./chronicle setup` asks for (days, or `all` to keep every
safety dump). Answer from the approved retention schedule and record
any incident hold and its review. Preserve a required copy before scheduled pruning;
restore stops the sidecar while it runs,
so a dump in use is never pruned. The companion is
the recovery copy of the owner-only checkpoint if the database volume is lost before the
current backend records its reconciliation receipt; it is not an ordinary application dump
and must never be restored into a running or previous-release backend.

After the dump lands, the restore service revokes every checkpointed mobile key and reapplies
`NOT_ENROLLED` before an application process can start. The current backend then blocks its
own startup while it validates the checkpoint digest and row counts, replays immutable
withdrawal receipts, and verifies any exact completed operation/tombstone proof already
present in the restored snapshot. For every completed proof the snapshot does not already
contain exactly, it rebuilds deletion steps from the current canonical asset registry and
physically re-erases the rows. It appends an immutable
`restore_continuity_reconciliations` receipt and drops the transient checkpoint in the same
transaction. An erasure an owner had started but not finished returns as `FAILED` and resumes on the
scheduler's next pass; a request nobody started stays pending. A conflict, missing relation,
changed digest, or incomplete erasure proof leaves the backend unhealthy and stopped with the checkpoint
preserved for diagnosis. Do not remove `chronicle_restore_continuity` manually.

**Restore time.** The command prints `Restore took N seconds.`, and every operation receipt
under `operator-receipts/operations/` records `durationSeconds`. Rehearse on a copy of your own
data and write down that figure as your recovery-time estimate; it grows with database size.
For reference: 61 s for a fixture database of 91 tables and
65,705 rows, including the bounded restart to a healthy stack.

On success, the command starts the complete stack with a bounded health wait; `db-init`
encrypts anything that arrived on plain heap. Confirm the restore receipt before reopening
external access:

```sql
SELECT checkpoint_id, source_schema_version, checkpoint_sha256,
       withdrawal_receipt_count, already_protected_deletion_count,
       replayed_completed_deletion_count, reconciled_at
FROM restore_continuity_reconciliations
ORDER BY reconciled_at DESC
LIMIT 1;
```

For release updates, use [upgrade and rollback](UPGRADE-ROLLBACK.md) and `./chronicle update`.
For recovery, use `./chronicle restore "--trusted-sha256=${TRUSTED_SHA256}"` with a reviewed
backup from the same release or an older post-reset release. The release version is included
inside the hashed compressed dump. A backup from a newer release is refused before services
stop or database mutation. Startup applies the target release's pending Flyway migrations.
Unheadered dumps and pre-reset dumps (2026.10.9 and earlier) are refused even with a
reviewed digest. Schema and continuity checks are additional requirements after admission. Tooling
stamps every dump, including pre-restore and pre-rotation safety dumps and continuity
companions, with its producing release version. Keep the encryption state and credentials
listed below with your recovery materials.

## Recover onto a fresh host

Install and verify the same signed release on an isolated replacement host with fresh
volumes. Follow Quick start only through extraction: **do not run `up` before restore**.
Setup's ordinary "Next: up" message is for a new study installation. The first setup on a
host leaves the boot and 15-minute reconciliation paused, so nothing starts the stack before
the restore; the explicit `up` after it resumes reconciliation. Restore the approved
configuration and TLS material, select the intended state directory, and copy the reviewed
dump into its protected `backups/` directory as `reviewed-recovery.sql.gz`. Recover any
outstanding continuity companion under the recovery owner's review before reopening access.
Use the original dump's independently recorded digest as `TRUSTED_SHA256`.

```bash
(
  set -euo pipefail
  ./chronicle setup
  ./chronicle restore --no-start "--trusted-sha256=${TRUSTED_SHA256}" /backups/reviewed-recovery.sql.gz
  ./chronicle up
  ./chronicle verify
  ./chronicle doctor --json
)
```

The guarded restore starts only its PostgreSQL and `db-init` dependencies before loading
the dump. It leaves `migrate`, backend and other writers stopped until the explicit `up`.
This ordering restores the original participant-token key before any fresh migration can
generate a competing key. `up` then runs migrations and continuity reconciliation. Preserve
the original backup set until the recovery owner has checked counts, credentials, the
continuity receipt and later corrections. An existing initialized installation still enforces
token-key continuity. If a replacement was already initialized with `up`, retain it for
diagnosis and repeat on isolated fresh volumes; do not disable the key check or overwrite
the protected checkpoint.

## Interrupted restore recovery

Keep external access closed. Correct the reported disk, certificate, port or runtime
failure first. Preserve the failed command's output, operation receipt, Compose logs,
`${CHRONICLE_STATE_DIR}/.chronicle-restore.lock/` (owner PID, phase and selected file), the
safety dump and its continuity companion. Never remove the lock, mutation marker or
`chronicle_restore_continuity` schema to make ordinary startup proceed.

One rule decides what recovery may do, for `restore --recover` and for rollback alike. A
`database-restored`, `starting-services` or `verified` phase means the database was replaced.
An earlier phase (`prepared`, `stopping-services`, `restoring`) without
`backups/.chronicle-restore-mutation-started` means the restore stopped before changing the
database: restore writes that marker before its replacement transaction begins. An earlier
phase with the marker is uncertain. Rollback skips its replay for a replaced database and
replays its reviewed dump otherwise.

For a replaced database, or one the restore never changed, run from the active release:

```bash
(
  set -euo pipefail
  ./chronicle restore --recover
  ./chronicle verify
  ./chronicle doctor --json
)
```

Recovery holds the same operation lock and checks the active release owner. It requires
the recorded restore PID to have exited and no running restore container (including
one-offs). For a replaced database it checks the live database catalog, then retries startup
and its health/continuity checks without replaying the dump. Only a successful startup
retires that exact restore lock. Another startup failure keeps it. For an unchanged database
it retires the lock and restarts the application services (with `--no-start`, it leaves
them stopped behind a stop marker).
Use `./chronicle restore --recover --no-start` to stop and verify every application writer,
retire a proven completed restore and leave a durable stop marker; only an explicit
`./chronicle up` resumes writers. Failure to stop a writer preserves the restore lock.

For an uncertain phase or missing/corrupt metadata, the outcome is not proven and recovery
refuses to retire either marker. Confirm the recorded PID and all restore containers have stopped;
have the recovery owner review PostgreSQL transaction logs and the database state. If the
outcome cannot be established, preserve the entire installation and perform the fresh-host
recovery above from the independently reviewed backup set. Do not start writers against an
uncertain database. This also avoids destroying the evidence or accepting an incomplete
continuity checkpoint. If an update owns the outer recovery journal, use
`./chronicle update` from its recorded recovery owner, following
[upgrade and rollback](UPGRADE-ROLLBACK.md#failed-or-interrupted-updates). Standalone
`restore --recover` refuses that outer lock: the updater owns retrying its recorded dump
or reusing a proven completed restore, and shares the process/container checks above.
Its journal must remain intact.


## What to back up besides the database

- `.env` — your secrets (store in a password manager, **not** next to the dumps).
- The configured `${CHRONICLE_STATE_DIR:-.}/tls/` directory. Own-TLS mode stores the
  supplied production certificate and key there; internal-dashboard modes also store the
  internal-listener certificate pair. Production TLS uses supplied files; Chronicle does not
  obtain or reissue production certificates. Keep an encrypted copy for rebuilds.

## Verify off-host copies

After each sync, compare the remote copy and test decryption. Record the approved copy
schedule and review frequency in the recovery plan below. Each parenthesized block runs in a subshell and
stops at its first failed command, so it prints its success line only when every step succeeded.

1. On the host, check that the encrypted staging directory matches the remote copy, file by
   file (size and checksum):

```bash
(
  set -euo pipefail
  rclone check /absolute/chronicle-state/backups-encrypted remote:chronicle-backups
  echo "remote copy matches the staging directory"
)
```

   Without rclone, compare checksum manifests from both sides. On the host:

```bash
(
  set -euo pipefail
  ( cd /absolute/chronicle-state/backups-encrypted && find . -type f -exec sha256sum {} + | sort -k2 ) >host.sha256
)
```

2. Where the recovery key is held, check that the off-host archive decrypts and contains a
   complete gzip tar stream. A failed copy stops the block, so an archive left in `./check/` by
   an earlier exercise is never reported as the current copy:

```bash
(
  set -euo pipefail
  rclone copy remote:chronicle-backups/chronicle-backups.tar.gz.gpg ./check/
  gpg --decrypt ./check/chronicle-backups.tar.gz.gpg | tar -tzf - >/dev/null
  echo "decrypts and is intact"
)
```

## Recovery plan and exercise record

Keep a tested recovery capability and evaluate it regularly. The institution chooses its recovery
objectives and exercise frequency from its risks. Keep a recovery copy separate from the
database disk and verify host/storage encryption as well as off-host encryption.

| Recovery plan field | Approved value / evidence |
|---|---|
| Recovery owner / alternate / authority to reopen access | ___ |
| Maximum acceptable data loss (recovery point objective) | ___ |
| Maximum acceptable interruption (recovery time objective) | ___ |
| Backup and encrypted off-host copy schedule / destination / custodian | ___ |
| Host/storage encryption evidence / key custody and recovery evidence | ___ |
| Retention schedule rows for scheduled, pre-operation and off-host copies | ___ |
| Restore exercise frequency / next exercise / plan reviewer | ___ |

The scheduled backup's scratch restore is a database check. Exercise the full recovery
path on an isolated release and controlled data copy too. Use the guarded restore
procedure above, with an independently reviewed digest. Check the continuity
reconciliation receipt and deletion proofs. Reapply and verify later
rectifications before reopening restored data.
Record failed checks and have the recovery owner approve resumption only after they are
resolved.

| Exercise record field | Result / evidence |
|---|---|
| Date / scenario / executor / reviewer / isolated destination | ___ |
| Backup source, age and reviewed digest / encrypted copy used | ___ |
| Off-host retrieval and decryption / key recovery result | ___ |
| Restore operation receipt / observed data loss and interruption | ___ |
| Continuity receipt / verified deletion proof / correction replay checks | ___ |
| Application access and collection checks / verification and doctor results | ___ |
| Objectives met / failures / remediation owner and due date | ___ |
| Reopening approval / cleanup evidence / next exercise | ___ |

## Check that backups restore

Use the automatic database check and the periodic recovery exercise together.

- **Every scheduled backup.** The sidecar restores each dump into a scratch database the
  same way `./chronicle restore` does (same extensions, table access method and
  stop-on-first-error replay) and compares the schema version, public tables and study and
  participant counts with the dump's source snapshot before publishing it. `./chronicle verify`
  prints `active database has a fresh restore-verified dump` and `./chronicle doctor` shows
  its `backup` row as `ok` only while the newest checked dump is fresh. A failed check
  publishes no new verified dump. Once the newest checked dump is overdue (the window in
  [Automated backups](#automated-backups-recommended)), `verify` and `doctor` fail, and with
  monitoring enabled `backup-stale` fires after its
  overdue condition holds for 900 seconds. `./chronicle logs db-backup` follows the last 100
  log lines and new output; look for `Restore self-check FAIL` and the preceding errors.
- **The full recovery path.** Off-host retrieval, decryption, guarded restore, continuity
  receipt and application checks are the periodic exercise in
  [Recovery plan and exercise record](#recovery-plan-and-exercise-record), on an isolated
  host at the frequency the plan sets.

Do not replay a dump by hand into another PostgreSQL. Dumps leave out `pgcrypto` and
`pg_tde`, so such a replay can miss tables and functions even when its row counts match.
