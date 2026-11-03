# Data Deletion and Uninstall

Chronicle has two different operations:

1. **Product data deletion** withdraws a participant or schedules a study for verified
   erasure while Chronicle remains installed.
2. **Uninstall** removes containers and, only when explicitly requested, storage owned by
   the installation.

Stopping or uninstalling containers is not proof that participant data was deleted.
Conversely, deleting a participant does not remove backups, exports, audit records, or the
Chronicle installation.

## Technical inventory recorded independently of optional modules

Disabling optional collection modules does not remove enrollment, access, or security
records. These records are created when the corresponding enrollment, form, or operator
action occurs; they are not a promise that every installation receives every category.

| Category | Recorded fields and storage | Readers and erasure path |
|---|---|---|
| Enrollment and devices | PostgreSQL enrollment/device rows bind `study_id`, `participant_id` and `random_device_id`; device type identifies the `platform`. Android device metadata includes `model`, device name, codename, brand, OS/SDK version, product, and supplied additional information. Acknowledgments include `app_version`, settings/disclosure versions, acknowledged modules, and timestamps. | Authorized study staff and enrollment/collection services. `WITHDRAW_AND_ERASE` includes device enrollment metadata; a collected-data purge preserves enrollment. |
| Form access and receipts | `participant_form_access_codes`, `participant_form_sessions` and `participant_form_submission_receipts` retain subject/scope identifiers, `form_kind`, resource/date scope, expiry/revocation times, hashed access/session/CSRF values, `idempotency_key`, `request_hash`, submission identifiers and completion timestamps. | Scoped participant access services and authorized study services. The registered erasure assets cover sessions, receipts and access codes; raw access/session credentials are not receipt fields. |
| Study and security audit | `study_settings_audit` records staff identifiers, study/settings revisions and before/after changes. `audit` records actor/role, action, resource identifiers, result, sanitized request path and `user_agent`, and timestamps; the backend also writes structured audit files to the `audit_logs` volume. | Authorized audit readers, the backend and institution-controlled log systems. Audit evidence has its own retention/access controls and is not proof of participant erasure. Include forwarded/off-host logs in the deletion decision. |
| Retention and deletion evidence | Deletion operations and `deletion_tombstones` retain scope, operation identifiers, request time, status, completion/proof information and replay fences. | Authorized deletion services and operators verifying deletion status. Retained tombstones/continuity evidence prevent deleted data from silently returning after restore. |

The current `ClientIpRecord` boundary withholds participant client addresses and stores
staff addresses as keyed references. Historical raw or unkeyed values are withheld by
`V1__fresh_schema.sql`; an `ip_address` column name does not mean raw IP
storage. Review the actual configured log sinks separately. Backup retention, exports,
pending deletion requests and off-host copies follow the controls described below.

Chronicle deletes no participant-scoped record on a timer. Downloads stream straight to the
researcher's browser; the server keeps no export files. Webhook
delivery records, finished background jobs and the study event stream are kept as well; list
them in the study's retention record and remove them only through an authorized purge.

Source inventory: `AndroidDevice.kt`, `PostgresColumns.kt`, `V1__fresh_schema.sql`
(including participant access), `AuditRequestContext`, `AuditService`,
`PostgresAuditingManager` (the single `audit` table), and `ChronicleDataAssetRegistry`.
Institutional disclosure, legal retention decisions and privacy policy wording are
the deploying institution's decisions.

Consent evidence in `participant_collection_acknowledgment` retains participant and random device IDs,
app, settings and disclosure versions, module decisions and timestamps after participant
or study erasure. This immutable evidence has no automatic purge; see
[authorized consent and withdrawal evidence purge](#authorized-consent-and-withdrawal-evidence-purge).

Participant erasure also retains withdrawal receipts containing participant and random device IDs
and withdrawal dates until full study erasure. Participant block tokens in deletion
operations, diagnostic-erasure fences, and restore continuity checkpoints use keyed HMAC-SHA256
references. The database retains a private key; application and maintenance request roles
cannot read it. The migration/function owner retains read permission. Backups retain the key,
and restore refuses a different key generation. These records remain pseudonymous personal data.
Apply the institution's access and retention controls to these records and their backups.

Storage failures retain the SQLState and failure class for retry and error classification. The boundary drops
database messages, bound values and nested causes. Connection pools disable pgjdbc server
error details and reject JDBC URLs that enable them. Console layouts also omit throwable
messages and cause chains.

## Before deleting anything

1. Confirm the request and the study/participant identifiers through your approved process.
2. Check legal, ethics-board, sponsor, and institutional retention requirements before you
   run an erasure; Chronicle never erases on a timer, so a pending request keeps the data.
3. If data must be retained or transferred, download each required data type under
   **Participants** > select the participants (or select all) > **Download data**, and the
   Time Use Diary and questionnaire data from the study's **Bulk Downloads** tab. Verify that
   each file opens before requesting deletion.
4. Record the request, scope, approver, study UUID, and later deletion operation UUIDs in the
   institution's controlled deletion register. Do not put participant identifiers in a
   public ticket or terminal transcript.

Downloaded exports and copies on analyst workstations are outside Chronicle. Inventory and
retain or destroy them under the same approved decision.

## Delete participant data

In the dashboard:

1. Open the study and select **Participants**.
2. Select one or more participants and choose **Delete**.
3. Read the confirmation and confirm the request.

Chronicle immediately changes each participant to `NOT_ENROLLED`, revokes form/export
access, and makes the participant's live rows inaccessible. It creates one
`WITHDRAW_AND_ERASE` operation per participant. Physical erasure starts only when an owner
presses **Erase now** on that request under **Participants** > **Deletion status**; it then runs
immediately. No amount of waiting erases anything.

The supported dashboard does not provide participant-deletion cancellation. Treat the
confirmation as final even though physical erasure waits for **Erase now**.

## Participant self-withdrawal

In-app **Withdraw from study** stops collection and follows the study's **Withdrawal**
setting. `KEEP_PRIOR_DATA` is the non-destructive default and the fallback when the setting
is absent. It retains uploaded data until a researcher explicitly deletes the participant.
Choosing `ERASE` records an erasure request, blocks processing of the participant's data and
keeps it until an owner runs the erasure. Participants shows **Withdrawn**, the withdrawal
date, and each pending erasure with the date it was requested. Press **Erase now** once the
protocol allows it. These actions are audited.

## Withdrawal after uninstall

Uninstalling the mobile app stops that app's collection. It does not erase uploaded data
or notify the institution of a withdrawal request. Keep the study's free electronic
withdrawal contact permanently available outside the app, including after uninstall.
Publish it through `researchContact` and `withdrawalUrl` in the participant policy.
Assign a monitored inbox owner and alternate; do not require reinstallation to request
withdrawal or exercise rights.

Authenticate the request through the approved institutional process. Record receipt,
participant code, scope, decision, collection-stop confirmation and response delivery.
Explain whether previously uploaded data will be erased or retained, and record the
continuing lawful basis and necessity for any retention. Withdrawal must not cause a
penalty or loss of care or benefits. Record each request in the institution's rights case
register.

Use the institution's approved retention schedule
for live data, consent/withdrawal evidence, audit logs, exports and backups. Record who
executes each deletion and when it is verified. Inventory residual copies on analyst
devices, at recipients and in backup systems; explain their approved handling and final
expiry to the requester. A collection stop is not completion evidence for erasure.

## Delete a study

Retention expiry shows a dashboard banner and raises an operator monitoring alert;
it does not revoke access or automatically erase a study. Record the
protocol retention deadline, responsible operator and planned erasure date in the
controlled deletion register. On that date request deletion, run **Erase now** and check
completion. Record the operation UUID, completion time and verified proof state. Escalate a
failed erasure before the deadline; access revocation alone is not completion evidence.

Archive the study first if the immediate goal is only to stop collection. Archiving is
reversible and is not deletion.

To request erasure:

1. Open the study's action menu and choose **Delete Study**.
2. Type the study title and choose **Schedule Deletion**.
3. Under **Participants** > **Deletion status**, press **Erase now** on the study erasure.

Chronicle immediately makes participant data inaccessible and records the request; nothing is
erased until step 3. Until then, use the same action menu and choose **Cancel Deletion** to
reactivate the study. Cancellation is no longer possible after the erasure starts.

## Verify deletion status and proof

Run this from the active release's `selfhost/` directory:

```bash
./chronicle deletion-status STUDY_UUID
```

To select one operation from the returned list:

```bash
./chronicle deletion-status STUDY_UUID OPERATION_UUID
```

The command validates both UUIDs before invoking Docker, sends them to PostgreSQL on stdin,
and does not display participant identifiers or proof hashes.

Interpret the result as follows:

| Field | Meaning |
|---|---|
| `status=QUARANTINED` | Requested at `requested_at`; live data is inaccessible and nothing is erased until an owner presses **Erase now**. |
| `status=ERASING` or `VERIFYING` | Physical deletion or residual-row verification is running. |
| `status=FAILED` | Erasure did not complete. The scheduler retries a started erasure; **Erase now** retries it at once. Preserve the operation UUID and inspect backend logs before escalating. |
| `status=COMPLETED` and `proof_state=verified` | Every registered asset reported zero residual rows and the durable tombstone matches the operation proof. |
| `status=COMPLETED` and `proof_state=missing-proof` | Do **not** treat this as verified deletion. Preserve evidence and investigate. |
| `status=CANCELLED` | The operation was cancelled before erasure. |

No row is not deletion proof. Recheck the study UUID and the active installation.

## Researcher access and "account deletion"

The supported self-host release does not provide a durable multi-user account directory. It
uses one static `local-admin` application principal behind the private dashboard's shared
network boundary and global password. Deleting that principal through the generic Principal
API is not a supported account-deletion workflow: the configured principal is recreated at
backend restart.

To revoke an operator's access:

1. Remove that person's VPN/private-network access.
2. Rotate the shared dashboard credential: `./chronicle rotate-secret dashboard`.
3. Rotate the JWT signing secret to invalidate existing Chronicle sessions:
   `./chronicle rotate-secret jwt --revoke-sessions`.
4. Rotate any separately shared export, host, or backup credentials.

## Authorized audit-log retention purge

Database `audit` records are retained indefinitely: Chronicle schedules no automatic purge.
Audit evidence has a separate retention decision from participant or study erasure. An
authorized database superuser may purge records only at the cutoff in the institution's
approved retention schedule, after confirming that
no legal, sponsor or investigation hold requires continued retention. Runtime application
roles cannot delete these records.

Record the approval, cutoff, affected database, executing operator and planned date in the
controlled deletion register. Have the authorized DBA prepare and review a purge scoped
to that cutoff. Connect with the protected superuser credential, count matching rows,
then execute the purge in a transaction. The current `prevent_audit_modification_trigger`
rejects every DELETE and UPDATE, including a superuser's. The DBA must explicitly lock
`public.audit` in ACCESS EXCLUSIVE mode, disable that named trigger on `public.audit`,
execute the approved DELETE, and re-enable the trigger, all in that same transaction.
Review the affected count and confirm the trigger is enabled before committing; roll back
the entire transaction on any failure or count mismatch. The lock blocks concurrent audit
writes until immutability is restored. Do not disable triggers at session or database scope.

Record the affected-row count, completion timestamp and verification query result in the
register. Apply the separate approved policy to structured audit files, forwarded logs and
backup copies; the SQL operation does not erase those copies. Keep the reviewed commands
and their results in the controlled register: this manual procedure creates no automatic
Chronicle purge receipt. Never broaden runtime grants or leave the trigger disabled.

## Authorized consent and withdrawal evidence purge

`participant_collection_acknowledgment` (consent evidence) and `mobile_withdrawal_requests`
(withdrawal receipts) have no automatic purge. Row-level policies refuse application deletes, apart
from study erasure removing that study's withdrawal receipts. Their retention end is the institution's decision. Purge them the same way
as audit logs above: record the approval, cutoff, study scope, executing operator and planned
date in the controlled deletion register; confirm no legal, sponsor or investigation hold
applies; connect as the protected database superuser; count the rows at or before the cutoff
(`recorded_at` for consent evidence, `created_at` for withdrawal receipts); delete
them in one transaction and commit only when the count matches the approved scope. Record the
count, completion time and verification query in the register. Backups keep these rows until
they age out (below). Do not weaken the row-level policies to do this.

## Backups can retain deleted records

The database backup schedule is independent of the live deletion ledger. A dump made before
deletion can contain the deleted rows until that dump ages out. `./chronicle setup` asks for
`BACKUP_KEEP_DAYS`, `BACKUP_KEEP_WEEKS` and `BACKUP_KEEP_MONTHS`; answer from the institution's
approved retention schedule. With `all`, a tier keeps deleted rows until you delete its dumps.
Record the effective expiry for each backup class and off-host destination; the suggested
backup image defaults do not establish a lawful retention period.

Full-database dumps in the `backups/` root and `backups/secret-rotation/` are **not** in that rotation:
`pre-restore-*.sql.gz` with its `*.continuity.sql.gz` companion
(written by `./chronicle restore`), and secret-rotation `*.sql.gz` dumps (written by
`./chronicle rotate-secret tde`). Each keeps every row
that existed when it was taken. The backup sidecar deletes them once they are older than
`PRE_OP_BACKUP_KEEP_DAYS` (chosen at setup from the approved schedule; see [BACKUP-RESTORE.md](BACKUP-RESTORE.md)), so
the longest a deleted row survives on the host is the later of that window and the
rotation above. After a restore, delete the safety dump and its companion yourself as soon
as the backend has written its `restore_continuity_reconciliations` receipt and you no
longer need a way back.

For each deletion request:

- record when the last pre-deletion backup expires or is approved for destruction,
  including any `pre-adopt-*`, `pre-upgrade-*`, `pre-restore-*`, and `secret-rotation/*.sql.gz` dumps taken before the deletion;
- include off-host backup systems and manually copied dumps in that decision; and
- preserve any required deletion proof separately before removing the installation.

| Residual-copy record | Value / evidence |
|---|---|
| Request / study / participant scope / deletion operation | ___ |
| Copy, location, custodian and downstream copies | ___ |
| Data remaining / continuing basis or hold / approved schedule row | ___ |
| Last pre-deletion backup / rotation or destruction date | ___ |
| Recipient correction/deletion request and response, where applicable | ___ |
| Actual destruction or expiry / verification / reviewer | ___ |

Restoring an old dump can reintroduce records that were deleted later. The guarded
`./chronicle restore` command checkpoints the newer withdrawal/deletion evidence, reapplies
credential and participation containment immediately, and the current backend refuses
readiness until it has verified exact completed proofs or physically replayed the missing
erasures, then written an immutable reconciliation receipt. Manual [rollback](UPGRADE-ROLLBACK.md#failed-or-interrupted-updates)
and automatic update rollback are rejected when the selected backup lacks
any protected fact. Never bypass that command or remove its continuity checkpoint to force an
older binary to start. Apply and verify later
rectifications before reopening restored records;
deletion continuity does not replay corrections.

## Stop Chronicle but keep all data

From the active `selfhost/` directory:

```bash
./chronicle down
```

This removes running containers and the Compose network. It intentionally retains named
volumes, `${CHRONICLE_STATE_DIR:-.}/backups`, TLS material, `.env`, and operator receipts.
Running `./chronicle up` later reuses them and resumes automatic reconciliation.
Bare Compose commands do not update the stop marker.

## Remove the application and all installation storage

This is irreversible. Do it only after export verification, a review of retention duties and
legal holds, and an explicit decision about whether deletion tombstones and audit evidence
must be preserved.

### 0. Pause and remove automatic reconciliation

From the active release, before removing any containers, volumes or state:

```bash
(
  set -euo pipefail
  ./chronicle down
  ./chronicle reconcile uninstall
)
```

The first command persists the stop marker while holding the shared operation lock.
The second removes only this project's `# chronicle-reconcile:<project>` crontab entries
and its launcher, leaving other cron jobs intact. Do not continue if either command fails.

### 1. Record the exact ownership boundary

Do not source `.env` into the shell and do not print the whole file. Record only these two
non-secret settings and the current directory:

```bash
grep -E '^[[:space:]]*(export[[:space:]]+)?(COMPOSE_PROJECT_NAME|CHRONICLE_STATE_DIR)=' .env
pwd -P
```

`.env` may write a setting as `export NAME=value` and may quote its value; record the value
without the prefix or quotes. Resolve `CHRONICLE_STATE_DIR` to one absolute path. A relative
value is relative to this `selfhost/` directory. If it is `.`, the release directory itself
contains `backups/`, `tls/`, receipts, and `.env` and will be deleted in the filesystem step
below.

Inventory every Docker volume bearing the exact project label before removal:

```bash
docker volume ls \
  --filter 'label=com.docker.compose.project=EXACT_PROJECT_NAME' \
  --format '{{.Name}}'
```

The base release normally owns PostgreSQL data, the TDE keyring, audit logs, frontend files,
and Caddy data/config volumes. Monitoring adds VictoriaMetrics, VictoriaLogs, and Grafana
volumes. A volume from a formerly enabled overlay can remain even when that overlay is no
longer in `COMPOSE_FILE`, which is why the label inventory is required.

### 2. Remove the current Compose resources

With the exact active `.env` and `COMPOSE_FILE` still present:

```bash
docker compose down --volumes --remove-orphans
```

Then repeat the label inventory. For each remaining name, inspect it before removal:

```bash
(
  set -euo pipefail
  docker volume inspect EXACT_VOLUME_NAME
  docker volume rm EXACT_VOLUME_NAME
)
```

Run `docker volume rm` only for names whose
`com.docker.compose.project` label exactly matches the recorded project. Do not use a broad
`docker volume prune`, wildcard, or `xargs` command; other applications may share the host.

### 3. Remove bind-mounted state and release files

`docker compose down --volumes` does **not** remove bind-mounted files. The resolved state
directory can contain:

- plain SQL backups and the copied TDE keyring under `backups/`;
- TLS private keys and certificates under `tls/`;
- upgrade and secret-rotation receipts; and
- an interrupted-operation directory such as `.chronicle-secret-rotation`.

Inspect the exact path and nested mounts before deletion:

```bash
realpath /ABSOLUTE/CHRONICLE_STATE_DIR
find /ABSOLUTE/CHRONICLE_STATE_DIR -maxdepth 2 -mindepth 1 -print
if command -v findmnt >/dev/null 2>&1; then
  findmnt -R /ABSOLUTE/CHRONICLE_STATE_DIR
else
  mount
fi
```

Move outside that directory, type the exact absolute path to confirm it, and keep deletion on
one filesystem:

```bash
(
  set -euo pipefail
  STATE_TO_DELETE=/ABSOLUTE/CHRONICLE_STATE_DIR
  case "$STATE_TO_DELETE" in
    ''|/|/home|/root|"$HOME") echo 'refusing unsafe state path' >&2; exit 1 ;;
  esac
  test "$STATE_TO_DELETE" = "$(realpath "$STATE_TO_DELETE")"
  test -d "$STATE_TO_DELETE"
  test ! -L "$STATE_TO_DELETE"
  printf 'Type the exact path to destroy: %s\n' "$STATE_TO_DELETE"
  IFS= read -r CONFIRM
  test "$CONFIRM" = "$STATE_TO_DELETE"
  cd /
  if [[ "$(uname -s)" == Darwin ]]; then
    rm -rf -x -- "$STATE_TO_DELETE"
  else
    rm -rf --one-file-system -- "$STATE_TO_DELETE"
  fi
)
```

If release bundles live outside that state directory, review and remove each exact release
directory separately. Their `.env` files contain credentials. Revoke/delete off-host backup
credentials and remove approved backup/export copies from their own systems; Docker cannot
do that for you.

Container images can remain safely as data-free application binaries and may be shared by
another installation. Remove only exact unused image digests after checking their consumers.

### 4. Verify the result

The following inventories should be empty for the recorded project:

```bash
docker ps -a \
  --filter 'label=com.docker.compose.project=EXACT_PROJECT_NAME' \
  --format '{{.Names}}'
docker volume ls \
  --filter 'label=com.docker.compose.project=EXACT_PROJECT_NAME' \
  --format '{{.Name}}'
```

Also verify that the reviewed state/release paths and approved off-host copies no longer
exist. Record the commands, approver, date, and retained proof in the controlled deletion
register. A clean Docker inventory alone does not prove that backups or exported files were
destroyed.

## Copies delivered to study webhooks

Enabled study webhooks send keyed participant references and enrollment/data-submission event metadata to
external HTTPS recipients. Local erasure removes Chronicle's delivery records and prevents
further delivery, but cannot recall copies already delivered. Use the controlled recipient
inventory from [CONFIGURATION.md](CONFIGURATION.md#study-webhook-recipients) to request and
verify deletion at each recipient and its downstream processors and backups. Record the
recipient, deletion request, completion evidence and any lawful retention exception.
