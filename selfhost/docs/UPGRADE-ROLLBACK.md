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
stops all application writers and takes a verified safety dump. It then stops the old project
and starts the candidate. Compose's one-shot `migrate` service applies pending Flyway
migrations before the backend starts. The updater runs `./chronicle verify` before reporting
success. Use the new active directory printed by the command for future operations.
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
Rollback resumes through database restore, project shutdown, settings archival, ownership
transfer, startup and verification. Ingress and automatic reconciliation stay fenced until
the selected release is verified. Preserve the journal until this command completes.

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
that release. Automatic updates refuse PostgreSQL major changes against the same data volume. For a
major change, prepare fresh database volumes and follow [guarded restore](BACKUP-RESTORE.md#restore)
with a compatible post-reset backup; retain the old volumes until verification succeeds.

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

A changed signing key requires an independently confirmed fingerprint. Do not replace a trusted
key with one from an unverified download.

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
