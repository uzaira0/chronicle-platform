# Self-host platform and lifecycle qualification

These are release acceptance procedures for isolated, snapshotted VMs. Rendering and
Docker stubs supply no platform evidence. Record release/image digests, OS/kernel,
Docker/Compose versions, locale, daemon mode, filesystem devices, and each result.
Keep credentials, keys, cookies, raw logs, and participant data out of uploaded artifacts.
Use synthetic participants only. Rootless, enforcing SELinux with daemon labeling, and
cold offline Grafana remain unqualified until their cases pass on the release images.

## Inputs and common acceptance

Use Ubuntu 24.04 and a maintained RHEL 9 VM, with a separate client VM on a public
network, an LB VM, a researcher VPN network, and a forbidden institutional peer.
Snapshot before privileged/network/clock/filesystem changes. Preload the release's exact
images. Set `RELEASE_SELFHOST`, `PREVIOUS_SELFHOST`, `PUBLIC_ORIGIN`, `MANAGEMENT_ORIGIN`,
`TRUST_BUNDLE`, and `PROJECT` to reviewed fixture paths/origins; configure the deployment
through `./chronicle setup`. Supply passwords on stdin or an interactive prompt.

```bash
cd "$RELEASE_SELFHOST"
./chronicle check
./chronicle up
./chronicle verify --dashboard-password
./chronicle doctor --json > doctor.json
jq -e '.checks | all(.status != "fail")' doctor.json
```

From the separate researcher/phone VM (the helper is shipped in the release bundle):

```bash
python3 tests/deployment/selfhost-client.py --public "$PUBLIC_ORIGIN" \
  --management "$MANAGEMENT_ORIGIN" --ca "$TRUST_BUNDLE" --records client.json
```

Copy only `client.json` back to the server, then:

```bash
python3 tests/deployment/selfhost-client.py --assert-db --project "$PROJECT" --records client.json
```

The helper exercises browser cookie/Origin/CSRF, real enrollment, 15 plaintext Android
upload types, retries, and authenticated export/download. Study-level encrypted enrollment
is currently rejected by the server; do not report a positive encrypted-upload pass.
TDE is a separate database-at-rest feature and must pass its declared profiles below.

## Platform cases

| Finding | Exact procedure | Required evidence |
|---|---|---|
| F19 rootless | Install the distribution's rootless Docker prerequisites; as the non-root operator run `dockerd-rootless-setuptool.sh install`, `systemctl --user enable --now docker`, `sudo loginctl enable-linger "$USER"`, and select the rootless context. Run common acceptance with monitoring both absent and selected, restore a reviewed dump, rotate the dashboard secret, restart the user daemon, and run common acceptance again. | Record user-namespace ownership of backup/TLS files, bind reachability from both client VMs, cAdvisor/Fluent behavior, and restore results. Any failure keeps that mode unsupported; do not substitute rootful Docker. |
| F20 SELinux | On RHEL run `sudo setenforce 1`; confirm `getenforce` is `Enforcing` and Docker daemon/container labels are enabled (`docker info --format '{{json .SecurityOptions}}'`). Run common acceptance before relabeling. For a reviewed dedicated state directory, use `sudo semanage fcontext -a -t container_file_t "$STATE(/.*)?"` and `sudo restorecon -Rv "$STATE"`; apply reviewed labels to the dedicated bundle's mounted configuration too. Repeat startup, backup, restore, certificate renewal, and monitoring. Inspect `sudo ausearch -m AVC -ts recent`. | Actual enforcing startup and write/read mounts work with the documented labeling. Record required labels and AVC outcome. Disabling daemon labels or SELinux is a failed enforcing case. |
| Firewall / F09 | Ubuntu: enable ufw with SSH retained, allow only the LB source to the fixed pool address/port and VPN sources to management/Grafana. RHEL: make equivalent firewalld rich rules, reload, and enable the service. From each separate VM probe public HTTPS, private HTTPS, Grafana, and direct pool HTTP before and after reload/reboot. Also probe published ports from a Docker container on an untrusted bridge. | LB and approved researchers pass; forbidden peer/direct clients fail. Docker DNAT may bypass host INPUT rules: qualify the Docker forwarding path and Caddy source guard, not just `ufw status`. |
| F35 denied egress | Preload every selected digest, including monitoring. Snapshot, deny new outbound Internet connections at the VM gateway while retaining the LB/client links, remove only this fixture's Grafana data volume, then run `./chronicle up` with monitoring. Test Grafana login and both bundled datasource queries, `doctor`, backup, and reboot. Restore the gateway policy afterwards. | Cold Grafana starts without downloading a plugin and queries work. An image pull success or warm plugin cache is insufficient. If cold Grafana requires egress, retain the explicit egress requirement/unsupported offline status. |
| F49 time / non-UTC zone | Set `sudo timedatectl set-timezone America/Santiago`, enable chrony/NTP, verify synchronization, and run common acceptance. Snapshot; disable NTP and skew the server 10 minutes, then one day. Repeat strict client acceptance, signed legacy-client acceptance when enabled, session expiry, and certificate validity probes. Restore correct time/NTP immediately. | Record skew detected and acceptance failure, not successful unauthenticated health alone. Compare LB, host, and client clocks. |
| F50 DNS/proxy/CA/registry | Configure split public/AAAA and management DNS on the actual resolver; run acceptance with and without hairpin routing. Configure a reviewed corporate proxy/CA for the Docker daemon and separately for containers/client trust. Block a required registry at the gateway, run upgrade/adopt before writers stop, and measure elapsed time. Repeat with stalled DNS and a blackholed Docker socket. | Preparation returns within its 600-second bound (15 seconds for storage daemon probes); old writers remain usable, no migration checkpoint is mis-cleared, and retry succeeds after connectivity returns. Host CA configuration alone does not qualify container trust. |
| Restrictive ownership | With a non-root account in the rootful `docker` group and `umask 077`, run setup, up, backup, restore, upgrade/adopt, and password rotation. Use a path containing spaces. Restart without root. | No root-only operator artifacts, leaked passwords in argv, or unreadable certificate keys. The Docker group remains root-equivalent. |

## Real cron, ownership, and reboot (F01–F04, F32–F34)

Install real cron/cronie, util-linux/flock, and logger; enable the appropriate service:
`sudo systemctl enable --now cron` (Ubuntu) or `crond` (RHEL). First disable it and prove
setup/up refuses before publication when reconciliation is selected. Re-enable it.
Generate `es_CL.UTF-8`, remove the fixture operator's initially empty crontab, and run
`LC_ALL=es_CL.UTF-8 ./chronicle setup`; retain an unrelated preexisting cron job on rerun.
Set the operator's actual `DOCKER_HOST` or `DOCKER_CONTEXT` before `up` and verify the
installed schedule retains it. Record the schedule without credentials.

1. Install from a source checkout, run common acceptance, then adopt into a clean published
   bundle: `./chronicle adopt --from "$SOURCE_SELFHOST"`. Confirm `CHRONICLE_STATE_DIR`
   still names the source state, and `state/reconcile.sh` names the selected release.
2. Save a separately reviewed generated dump/digest. Run
   `./chronicle restore --yes --no-start --trusted-sha256="$REVIEWED_SHA" "$DUMP"`.
   Wait through a real scheduled tick (at least 16 minutes), then reboot the VM. Backend,
   web, and backup remain stopped; `state/.chronicle-stopped` persists. Resume explicitly
   with the selected launcher's `./chronicle up`, then run common acceptance.
3. Run two successive supported updates with the installed bundle's
   `./chronicle update "$NEXT_VERSION"`; qualify persisted upload rows after
   every hop. Run guarded `./chronicle rollback --yes --from "$PREVIOUS_SELFHOST" \
   --trusted-sha256="$PRE_UPGRADE_SHA" "$PRE_UPGRADE_DUMP"`; rows must match the reviewed
   backup and reconciliation must name the rollback owner. Upgrade forward again.
4. Hold the real state lock: `flock "$STATE/.reconcile.lock" sleep 90 &`.
   Start up/upgrade/restore/rollback/adopt separately while it is held; cron must skip and
   mutations must wait. Create the relevant recovery marker while the operation waits;
   after releasing the lock, it must recheck and refuse the stale decision. Repeat each
   marker type. Use a snapshotted fixture only; retain markers until reviewed recovery.
5. Reject a configuration before migration and prove old writers restart. Interrupt a
   real migration/startup or force post-start verification failure. Confirm the checkpoint
   retains the new owner and phase; old launchers and cron cannot start writers. Correct
   the failure, run new-owner `up` and `verify`, and confirm successful acceptance clears
   the checkpoint and transfers cron. Restore from the reviewed dump for rollback.
6. Restart Docker, then reboot. Wait for actual cron, run common acceptance remotely,
   and confirm stable container IDs for an unchanged routine reconciliation.

## Capacity, elapsed work, and served certificates

Use separate virtual disks for Docker data-root and state, and a separate ext4 PostgreSQL
volume. Do not treat a tmpfs drill as evidence for this layout. Mount each by UUID, put
Docker's `data-root` on its dedicated mount, and restart Docker before deployment.

- F11/F22/U5/U6: record `findmnt -T` and `df -h -i` for all three devices. Fill only a
  disposable device with a bounded `fallocate` fixture so it has less than 5 GiB free;
  setup/check/up must fail, and update/upgrade must retain their additional 3 GiB reserve
  on image/download storage. Leave state free while Docker storage is low, then reverse
  them. Format another test disk with `mkfs.ext4 -N 12000`, create empty fixture files
  until fewer than 10,000 inodes remain, and prove the pre-mutation guard rejects it.
- Grow synthetic study data until `pg_database_size` is representative of the deployment
  (at least the intended production size). Keep six-month-old rows. Test successful
  backup with more than twice the larger live/uncompressed dump size additionally free,
  then reduce available scratch below that requirement and prove failure before scratch
  restore. Force an actual dump/restore error; no unverified final/latest dump appears.
  Repeat failures and verify abandoned partial files remain bounded. Test TDE on and off.
- F25: use the grown dataset to make real verification exceed 90 seconds and a migration
  exceed 300 seconds. Set `START_WAIT_TIMEOUT_SECONDS`, `BACKUP_STARTUP_TIMEOUT_SECONDS`,
  `BACKUP_VERIFY_TIMEOUT_SECONDS`, and restore/upgrade timeout to 3600. Observe progressing
  work complete; a real stalled operation must fail within that bound. Do not replace
  measured work with sleep and call the duration qualified.
- F43: on a 4 GiB VM run blank-answer setup (monitoring defaults off), real ingest, backup,
  and export concurrently. Check `journalctl -k` for OOM and container restart counts.
  On a larger VM select monitoring and repeat; oversubscribed saved ceilings must be
  refused before settings publication.
- F30/F31: save the served management certificate using `openssl s_client -connect
  "$MANAGEMENT_HOST:$MANAGEMENT_PORT" -servername "$MANAGEMENT_HOST" -verify_return_error
  -verify_hostname "$MANAGEMENT_HOST" -CAfile "$DASHBOARD_CA" </dev/null` from the remote
  researcher. Add a management DNS SAN through setup and run up; verify the served serial
  and SAN change while the CA digest stays fixed. Repeat for near-expiry generated
  PostgreSQL/backend/Grafana leaves. Supply a mismatched operator SAN and prove refusal.
- F44/F45: run 150 routine successful up/doctor cycles, preserve failed and transition
  receipts, and check at most 96 successes per routine operation. Review `./chronicle
  cleanup --releases-dir "$RELEASE_PARENT"`, then run with `--apply` on the fixture.
  Active/state/recovery owners and the newest three releases must survive; old archives,
  checksums, and unused image references are removed. Repeat supported transitions.

## LB transport and released-device trust (F12/F13/F41/F42/F51)

The Docker harness supports a real TLS-terminating SNAT LB, with normalized client XFF
or the observed F5 behavior that supplies no XFF. Its fixture CA is explicitly trusted.
Qualify the released Android build separately against the institution's real certificate
chain; fixture CA success does not establish default device trust.

Use the institutional LB's transparent/source-preserving mode with return routing through
that LB; enable its documented source-preserving pool configuration and the host's approved
LB-interface forwarding rules. Capture the synthetic requests on the LB pool interface
and host ingress (`tcpdump -nn -i "$POOL_INTERFACE" tcp port "$POOL_PORT"`), then compare
Caddy's resolved identity and backend rate buckets. Also send direct bypass traffic from a
forbidden peer; original source preservation must not accidentally broaden ingress.
The Docker harness implements the IPv4 variant with `TOPOLOGY_SOURCE_PRESERVING=true`: real
HAProxy transparent sockets, a return route through the LB, and a host ingress rule that
blocks direct client access to the server bridge. Its isolated fixture uses NET_ADMIN/NET_RAW
and restores the temporary host rules/routes and reverse-path filtering settings on exit. Run it on a dedicated rootful Linux
Docker host and verify its actual packet path; it has not been run in this edit environment.
Do not label XFF insertion alone as transparent transport.

Run the helper with two phones concurrently and two browser sessions through shared VPN
SNAT. Send duplicate/forged XFF and XFP at public ingress; the LB must replace them. On an
untrusted direct path, forged `X-Forwarded-Proto: https` must neither grant ingress nor add
HSTS. From the trusted pool interface, a combined `http, https` proto is not accepted as
normalized HTTPS. Test normal Host and a replaced pool Host; manifests keep canonical
public origin, including a nonstandard external port.

The supported LB body contract comes from `MAX_REQUEST_SIZE_BYTES` in
`ontology/chronicle.linkml.yaml`, with 16 KiB headers and a
300-second idle timeout. Run a valid 9 MiB upload through the normal contract, then a
smaller body limit and require 413 without persisted rows. Use `tc netem` on the separate
client VM to model 256 kbit/s transfers and loss, and repeat upload with a lost
acknowledgement; exactly one row remains. Export representative data large enough to
stream longer than the short-idle test value, throttle the download with curl's
`--limit-rate`, and compare its SHA-256 with an unthrottled download. The Docker harness
already replays a paced 9 MiB upload, compares complete hashes of a paced 6 MiB export,
and rejects a stalled upload through a one-second idle variant before retrying successfully.
A short idle timeout
must fail visibly; the supported 300-second idle contract must complete within the
export/runtime bound. Representative production volumes and cellular loss remain manual
qualification beyond that Docker transfer check.
Stop PostgreSQL and observe the LB remove the pool on exact `/health` !=204, then restore
it. Run 8 parallel strict health requests without intermittent readiness failures.

## F52: all 14 runtime profiles

Run `bash tests/security/selfhost-combination-matrix.sh` for rendering only. On a fresh
VM snapshot select each declared profile in `selfhost/docs/DEPLOYMENT-COMPATIBILITY.md`,
once without and once with monitoring. Use valid fixture certificate chains for own TLS
and explicitly distribute the local CA for trial mode. For every case run common
acceptance, real upload/row assertions, export, startup verification when backups are
selected, daemon restart, reboot/cron, and the supported restore/upgrade path. The trial
without backups instead proves backup absence and its documented disposable status.
Record 14 separate results; rendering status is a separate field. A runtime failure keeps
that profile unqualified for the release.

The workflow's VM evidence gate consumes a reviewed JSON report with `backend_image`,
`frontend_image`, `caddy_image`, `findings` (F19,F20,F35,F49,F50,F52 -> `passed`), and
`runtime_profiles` (14 distinct profile-plus-monitoring IDs -> `passed`). Reports come
from the procedures above; the workflow validates evidence and does not execute or invent
VM tests. Keep raw evidence privately for review.
