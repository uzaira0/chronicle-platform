# Upgrade and rollback

## Upgrade a post-reset installation

From the active release's `selfhost/` directory:

Check for a release first (exit 3 means one is available):

```bash
./chronicle update --check
```

Then run the update and its checks:

```bash
(
  set -euo pipefail
  ./chronicle update
  ./chronicle verify
  ./chronicle doctor --json
)
```

`update --check` reports the highest published stable release without downloading it
(exit 3 means an update is available). `update` downloads that release, verifies its
signature with the installed public key, checks every manifest digest, and preserves
`.env`, the Compose project, volumes and state directory. Use `./chronicle update <version>`
to select a published version explicitly. Selecting the installed version repairs it from
a new verified release directory. Downgrades are refused.

An update, a repair and a rollback remove the previous release's containers, and with each
container the anonymous volumes Docker made for it (one for every `VOLUME` path of the PostgreSQL
image that no named volume covers; they hold no data). The new containers get new ones. Named
volumes are never removed by these commands, apart from the ones a failed update itself created
(see "PostgreSQL major versions"), and neither is any other volume your Compose file mounts,
including one made with `docker volume create` and no name.
Releases before 2026.11.12 left those anonymous volumes behind;
[UNINSTALL-DATA-DELETION.md](UNINSTALL-DATA-DELETION.md) says how to list them, and which
anonymous volumes `./chronicle down` still leaves.

Files you edited inside the installed release (for example `docker-compose.yml`) do not stop
the update. The new release installs its own copy; your edited file and a diff against the new
release's copy are kept in `<state>/local-edits/<installed version>/`, and the update names
each one. Reapply what you still need; deployment settings belong in `.env`, which the update
always keeps.

The update also migrates `.env` itself and names each change: a renamed key moves to its new
name (`POSTGRES_LOCK_TIMEOUT` → `POSTGRES_LOCK_TIMEOUT_MS`, and the statement and
idle-in-transaction timeouts likewise); an empty `JWT_SECRET`, `METRICS_PASSWORD`,
`CHRONICLE_INTERNAL_WEB_SECRET` or `GRAFANA_ADMIN_PASSWORD` is generated as setup would; a
cleartext password in `DASHBOARD_PASSWORD_HASH` is replaced by its bcrypt hash; empty or repeated
`COMPOSE_FILE` entries are dropped, and a Compose file the release does not ship is left out
with a copy kept in `<state>/local-edits/<installed version>/`. Only a value the update cannot
derive stops it, before anything is stopped: an empty `POSTGRES_PASSWORD` or
`POSTGRES_APP_PASSWORD` (they must match the existing database), or no dashboard password at all.
A Compose file of your own is left out of the new release only: the running release is stopped,
dumped and (on a rollback) restarted with it, so a service it adds is stopped before the safety
dump like Chronicle's own. If that file moves PostgreSQL's data or keyring volume, starting the
new release without it would serve another database, so the update refuses before stopping
anything and names the file; move that volume selection out of it first.

Discovery and download are done by the release that is installed, before it hands over to the
new one, so what follows holds for updates run by 2026.11.12 or later. Release discovery and
downloads go through the proxy in `https_proxy`/`HTTPS_PROXY` (and honour `no_proxy`) when one is
set in the environment of `./chronicle update`; nothing else in the bundle uses a proxy. A failed
download is retried after 1, 2, 4 and 8 seconds within its transfer deadline. Discovery tries
`CHRONICLE_RELEASES_URL` (when set), then the GitHub API, then the GitHub releases feed, which is
not subject to the API's hourly limit for unauthenticated hosts; whichever answers, the signature
check is the same. The feed is read whatever name the repository has: GitHub redirects a renamed
repository's feed and downloads, and the links in the feed then carry the new name. A published release that is malformed or whose assets are still uploading is
skipped with a warning, so it never blocks an update to the newest complete release. The feed also
lists git tags that have no release; before a release found in the feed is selected its checksum is
asked for once, and a tag whose checksum GitHub answers with 404 is skipped the same way. Every source
offers the same releases: a published release whose tag is a stable version (no `-rc`-style
suffix), which is the version its signed manifest must carry.

### The first update from 2026.11.2

An update started on 2026.11.2 is discovered and downloaded by 2026.11.2's own code, which cannot
be changed: it ignores `HTTPS_PROXY` (every request bypasses proxies), does not retry, reads only
`CHRONICLE_RELEASES_URL` or the GitHub API, and requires `.env` to be mode 0600 (`chmod 600 .env`).
On a host that reaches GitHub directly this needs nothing. Before each release is published, every
supported installed release's own discovery is run on the catalog it will publish
(`scripts/check-release-discovery.py`), so no catalog row stops 2026.11.2 from finding it.

A host that reaches GitHub only through a proxy does this once, for the update to 2026.11.12 or
later; every update after it is run by the newer release and uses the proxy:

1. On any machine that can reach GitHub, download the new release's three assets from its GitHub
   release page: `chronicle-selfhost-<version>.tar.gz`, `.tar.gz.sha256` and `.tar.gz.sha256.sig`.
2. Put them on an HTTP or HTTPS server that the Chronicle host reaches directly, without the proxy
   (an internal web server; for HTTPS its certificate must be trusted by the host's `curl`), and
   beside them a `releases.json` that names them, as below (here for 2026.11.12 at
   `https://mirror.example.internal/chronicle/`):

   ```json
   [{"tag_name": "2026.11.12", "draft": false, "prerelease": false, "assets": [
     {"name": "chronicle-selfhost-2026.11.12.tar.gz",
      "browser_download_url": "https://mirror.example.internal/chronicle/chronicle-selfhost-2026.11.12.tar.gz"},
     {"name": "chronicle-selfhost-2026.11.12.tar.gz.sha256",
      "browser_download_url": "https://mirror.example.internal/chronicle/chronicle-selfhost-2026.11.12.tar.gz.sha256"},
     {"name": "chronicle-selfhost-2026.11.12.tar.gz.sha256.sig",
      "browser_download_url": "https://mirror.example.internal/chronicle/chronicle-selfhost-2026.11.12.tar.gz.sha256.sig"}]}]
   ```

3. Run the update with that file as the catalog:

   ```bash
   CHRONICLE_RELEASES_URL=https://mirror.example.internal/chronicle/releases.json ./chronicle update
   ```

The mirror needs no trust: the archive is still verified against the installed
`release-signing.pub` before anything is extracted or run.

Release downloads and image pulls each have a 600-second transfer deadline by default.
On a slow connection, set `CHRONICLE_TRANSFER_TIMEOUT_SECONDS` to a positive integer
number of seconds in the environment for `./chronicle update`. The same override applies
to archive downloads and candidate image pulls, and is inherited by the candidate launcher.
For example, after assigning your chosen duration to `transfer_seconds`:

```bash
CHRONICLE_TRANSFER_TIMEOUT_SECONDS="$transfer_seconds" ./chronicle update
```

This setting controls transfers; `START_WAIT_TIMEOUT_SECONDS` and
`UPGRADE_WAIT_TIMEOUT_SECONDS` control service startup waits.

The signed manifest's `upgrade_from_minimum` is the upgrade floor. Releases at or above
that floor upgrade in place. Releases before this reset (2026.10.9 and earlier) require a
fresh installation with fresh volumes; their dumps cannot migrate into the new baseline.
Keep required exports and independent recovery copies before retiring the old installation.
See [Quick start](../README.md#quick-start).

The installed release only downloads and verifies the signature, archive inventory,
digests and upgrade floor. It execs the candidate's own launcher under the inherited
operation lock; the candidate owns its service, image, file and overlay contracts.
The candidate validates PostgreSQL major compatibility, closes participant ingress,
stops all application writers and takes a verified safety dump. Chronicle's own images must be
pulled; a monitoring image the registry cannot serve is reported and the update continues
without it. It then stops the old project
and starts the candidate. Compose's one-shot `migrate` service applies pending Flyway
migrations before the backend starts. The updater runs `./chronicle verify` before reporting
success. It also runs the previous release's `./chronicle verify` before stopping anything; a
check that already failed there (for example a backup directory mode or an unconfirmed storage
encryption) is reported as a warning after the update and does not roll it back. Only a check
that passed before the update and fails after it rolls the update back, or one that got worse:
more tables on plain heap or more unwritable backup directories, or a backup directory mode that
gained a permission bit. The update records those pre-update results in its recovery journal, so
a resumed recovery or rollback judges the same way, including with an older release's verify.
If the pre-update verification cannot run at all (it times out after 600 seconds, or exits
without naming a check), a check that fails after the update is reported and does not roll it
back, because nothing shows whether it failed before.
Keep running `./chronicle` from the directory you installed. After the first update, its
`chronicle` forwards every command to the release that owns the deployment (recorded in
`<state>/.chronicle-owner`), and runs its own release again after a rollback to it; the
original launcher is kept beside it as `chronicle.release`. The update records the new owner and
installs this forwarder before it commits, inside its recovery journal: if either cannot be
written the update rolls back, and an update interrupted after its commit is finished by the next
`./chronicle update` from the same directory. If the ownership record is missing or names a
release that no longer exists, the forwarder stops and lists the releases installed for the
deployment instead of running an older one. If you move the installed directory, the next update
makes the directory it runs from the front door. Updates install each release at
`chronicle-releases/<version>/` next to the installed bundle (a repair of the same version gets
`<version>.1`); the update from 2026.11.2 still stages in a `chronicle-update-*` directory,
because 2026.11.2's own updater chooses it.
The old directory, private settings and safety dump remain available for recovery.

## Failed or interrupted updates

A failed startup or verification automatically restores the safety dump through guarded
rollback before restarting and verifying the previous release. This also applies to repairs.
The failed command returns a failure status even when rollback succeeds. Application writes
are stopped before the safety dump; data accepted before that stop remains intact.
Caddy reads a durable status file in the mounted TLS directory on every request, including
after restart. Mobile ingest and participant forms receive 503 with Retry-After until
verification passes and the update commits. The researcher dashboard shows the same
update message. Operator verification uses the internal web credential in a private
request header, passed over stdin and stripped by Caddy before proxying. Do not remove
the fence or publish backend ports to bypass it.

After process death or a host restart, run `./chronicle update` from the previous or candidate
directory (use the previous directory once rollback has archived the candidate settings).
`up`, `setup`, `restore` and `doctor` print that exact command when they find the recovery record.
Update and rollback publish the marker directory only together with its complete record, so an
interruption or a full disk never leaves a marker that has to be removed by hand. An empty
marker left by an older release's interrupted setup, restore or rollback recorded no changes;
the next command that takes the operation lock (for example `./chronicle up`) removes it and
says so, and `doctor` reports it until then.
It reads the durable recovery record under the shared lock. Before commit it deliberately
rolls back, even if the candidate had started successfully; after commit it verifies the
committed release and completes cleanup without restoring an older dump. A pre-migration interruption restarts the old
release; after migrations may have started, recovery restores the safety dump first.
Once the previous release serves again, the same command runs the update again: one rerun
finishes an interrupted update and exits 0 when it succeeds. An update that had already failed
(its startup or verification) when it was interrupted is not retried: the rerun finishes its
rollback and exits non-zero.
Rollback resumes through database restore, project shutdown, settings archival, ownership
transfer, startup and verification. Ingress and automatic reconciliation stay fenced until
the selected release is verified. Preserve the journal until this command completes.

Startup, update and rollback wait only for Chronicle's own services. The optional monitoring
services (those `overlays/monitoring.yml` adds) start afterwards with a separate wait of at most
300 seconds; one that is unhealthy is named in a warning with the command to read its log (for example `./chronicle logs grafana`) and
never fails the command or triggers a rollback. When Docker Compose itself fails to start them, the
warning repeats Compose's error and lists the services it did not create; a start that did not finish
in time, or services whose state Compose could not list, are reported as that. `./chronicle doctor` reports each one.

Update and rollback also start `db-backup` without waiting for it. It is healthy only after a
fresh full dump has passed a restore check, which can take up to `BACKUP_VERIFY_TIMEOUT_SECONDS`;
the update has already taken its own safety dump, so waiting only held participant ingress
closed. After the commit the update says whether `db-backup` is still taking that first backup
or has failed; scheduled backups run as before. `./chronicle doctor` reports `service-db-backup`
(a first backup in progress is a warning) and `./chronicle verify` still checks the newest
restore-verified backup; a backup that was already missing or stale before the update is a
warning, not a reason to roll back. A crontab the update or rollback cannot write is a warning
too: the release still starts and serves, and the next `./chronicle up` installs the schedule.

If the recovery itself fails, its journal stays and periodic reconciliation resumes: each run
refuses to start anything while the journal exists and logs the failure. Participant ingress
reopens on the data in place, as before the update, except while resuming would restore the
safety dump (the update failed after migrations started and the dump was not yet restored);
then it stays closed with 503, because the restore would discard uploads accepted meanwhile.

If rollback itself fails, keep services stopped and preserve
`CHRONICLE_STATE_DIR/.chronicle-upgrade.lock/recovery.json`, the restore lock (if present),
the previous directory, and the named dump and digest. Diagnose the reported failure;
never start the previous backend against a possibly newer schema. After resolving any
incomplete restore using [BACKUP-RESTORE.md](BACKUP-RESTORE.md), run from the candidate:

```bash
./chronicle rollback --from /path/to/previous/selfhost --trusted-sha256=... --yes /backups/pre-upgrade.sql.gz
```

Only select the previous release and dump recorded by this operation. Rollback restores
before restarting the previous backend, preserves current credential settings, and verifies
that release.

### PostgreSQL major versions

A release that moves to a new PostgreSQL major names new database and TDE keyring volumes in
its Compose file. `./chronicle update` then takes its usual safety dump, starts only the new
PostgreSQL on the empty new volumes, restores the dump into it, and starts the release, whose
migrations run on the restored data. The old volumes are never touched or removed: the previous
release still names them, so an automatic rollback (or a later guarded rollback, below) starts it
on them again with no restore. The update needs free space for a second copy of the database
and refuses before stopping anything when it is missing. It also refuses, before stopping
anything, a release whose new major would reuse the old volumes; publishing refuses such a
release first, comparing each supported published release's PostgreSQL major and database
volumes with the new one's. An automatic rollback removes the volumes the failed update created
(the new major's database volumes and any new secrets volumes), so a retry starts as the first
attempt did. A guarded rollback (above) after such an update restores the dump into the
previous release's own database volumes, the ones it starts on. Remove the old volumes with
`docker volume rm` (the update names them) only after the new release has run long enough to
trust it.

### Release signatures and key rotation

Release checksums are signed in the `chronicle-release` SSH namespace. The publisher
requires the private key at `~/.config/chronicle/release-signing-key`, or the path set by
`CHRONICLE_RELEASE_SIGNING_KEY`; it uploads the detached `.sha256.sig` alongside the
archive and checksum. Every new bundle contains the public key. Verify the downloaded checksum with an independently trusted public key before extraction.

For manual verification, download all three assets and use your installed public key:

```bash
(
  set -euo pipefail
  printf 'chronicle-release %s\n' "$(cat /path/to/current/selfhost/release-signing.pub)" > allowed_signers
  ssh-keygen -Y verify -f allowed_signers -I chronicle-release -n chronicle-release \
    -s chronicle-selfhost-<new-version>.tar.gz.sha256.sig \
    < chronicle-selfhost-<new-version>.tar.gz.sha256
  sha256sum -c chronicle-selfhost-<new-version>.tar.gz.sha256
)
```

Proceed to extraction only if both commands succeed. For a first installation, the public
key ships in the bundle. Follow [Quick start](../README.md#quick-start) to extract only the
key and run `ssh-keygen -lf release-signing.pub -E sha256`. Compare its fingerprint with
the one the maintainer sent separately, by email or message from your study's Chronicle
contact. If it differs, stop. Do not install. Only the fingerprint comes separately.

A changed signing key needs no operator step on 2026.11.12 and later. A release signed by a new
key carries two extra assets: `release-signing.pub`, the new key, and `release-signing.pub.sig`,
the installed key's signature over it in the separate `chronicle-release-key` namespace.
`./chronicle update` accepts the new key only through that signature, verifies the checksum with
it, and refuses the release unless its bundle ships the same key as `selfhost/release-signing.pub`,
which then becomes the installed key. Anything else is refused before extraction. Updaters before
2026.11.12 cannot rotate, so the key stays unchanged until no server runs one. For a manual
verification across a rotation, verify `release-signing.pub.sig` with the old key and namespace
`chronicle-release-key`, then the checksum with the new key. Do not replace a trusted key with one
from an unverified download.

## Restore across post-reset releases

Use the [guarded restore](BACKUP-RESTORE.md#restore) with a reviewed backup from the same
release or an older post-reset release. Newer-release backups are refused before mutation.
The target release applies its pending migrations after restore.
An empty replacement database is supported after the database encryption initializer runs.
Every restore invalidates pre-restore researcher sessions before access reopens.

## Removing unused release downloads

`./chronicle cleanup --releases-dir /absolute/path/to/releases` previews unused bundles and images. Review that output before
using `--apply`. Active and retained bundle inventories protect all their runtime images,
including PostgreSQL, backups and monitoring sidecars.
