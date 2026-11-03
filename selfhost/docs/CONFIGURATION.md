# Configuration and operations

- [Managing studies](#managing-studies)
- [Mobile apps](#mobile-apps)
- [Deployment compatibility](#deployment-compatibility)
- [Secret rotation](#secret-rotation)
- [Data deletion and uninstall](#data-deletion-and-uninstall)
- [Installing another release](#installing-another-release)


## Institutional LB and management inputs

Setup asks for the canonical public HTTPS origin, explicit LB source CIDRs,
`POOL_ALLOWED_IPS`, and the fixed pool port. A remote LB requires its actual source CIDRs:
blank, loopback-only and Docker-gateway-only sources are refused, including for SNAT without
client XFF. Obtain the source ranges from the institution's network owner before setup.
Loopback/gateway defaults apply only to a proxy on this host. Setup enables TLS for an
off-host pool hop unless an explicit reviewed `POOL_PLAINTEXT_WAIVER` is retained.
A port conflict is refused. When providing
forwarded client/protocol headers, the LB must replace them; SNAT without XFF supplies no original client
identity. The public HTTP surface defaults disabled; enable `PUBLIC_HTTP_ENABLED` only
when the LB exposes HTTP and redirects it to the canonical HTTPS origin.

The private researcher ACL defaults to loopback plus the selected Compose gateway, so host
access and SSH tunnels work through Docker's translated TCP peer. Supply approved VPN/researcher CIDRs
and `DASHBOARD_BASE_URL` for remote access. Setup derives its certificate SAN and browser
Origin entry, preserving extra saved SANs/origins. New generated pairs use
`tls/internal-ca.crt`; retain this trust anchor for post-reset recovery. Operator pairs
only need to cover the management identity. A deliberately excluded management host can
establish intentional source denial; complete dashboard sign-in from an allowed researcher
browser. A loopback dashboard must remain accessible from the operator host, and verification
fails on a 403 there. Existing operational answers survive a setup rerun.

Environment files accept `KEY=value`, optional `export`, literal single/double quotes,
and whitespace-separated comments. Quote spaces and shell punctuation. Commands,
interpolation, concatenated quotes, and backslash escapes are rejected before sourcing;
single quotes preserve dollar signs literally. The launcher and Python operations use
this same contract.

The upstream body contract is generated from `MAX_REQUEST_SIZE_BYTES` in
[`ontology/chronicle.linkml.yaml`](../../ontology/chronicle.linkml.yaml), with 16 KiB headers and 300-second idle
timeouts. Setup collects these values and refuses a smaller contract. Qualify actual
slow transfers and large exports using [platform procedures](../../tests/deployment/selfhost-platform.md).

## Managing studies

Everything is done from the web dashboard on the internal listener,
`https://<INTERNAL_BIND>:8081/chronicle` (default `https://127.0.0.1:8081/chronicle`, reachable
over an SSH tunnel); there is no admin CLI. `https://<your-domain>` is the participant/mobile
origin only: the SPA loads there, but the dashboard API answers 404.

1. Create a study. Give it a name; it gets a study ID (UUID).
2. Choose data-collection modules. Each module (app usage, accelerometer, step count,
   battery, connectivity, activity recognition, etc.) is toggled required / optional /
   off per study, and sensor modules carry their own sampling rate + duty cycle.
3. Add participants. Each participant gets an enrollment code / QR that encodes the
   study ID, participant ID, and your server URL.
4. Monitor. The dashboard shows enrolled devices and last-upload times.
5. Download. On Participants, tick participants (or select all shown, after *Show more*)
   and use *Download data*: one data type per download, as CSV, with optional start and
   end days in the study time zone, streamed straight to the browser. The study's Bulk
   Downloads tab has the whole-study Time Use Diary and per-questionnaire response CSVs.
   Output is plain and readable in R, Python, Excel; no proprietary tooling needed.

Which modules a given phone actually collects is the intersection of what the study
enables, what the participant consented to, and what the platform supports; a module a
device can't realize is silently dropped rather than blocking enrollment.

## Mobile apps

Participants need a Chronicle app build that points at your server. Public builds use
one-time enrollment links followed by per-device API keys; they do not carry a shared
deployment secret.

### Point the app at your server

The `open` build, which Google Play ships and which you can also sideload, trusts any valid
public-HTTPS Chronicle server:

- Android from Google Play; issue a one-time enrollment link from the dashboard. The
  link configures the server URL and the app displays it before the participant enrolls.
  No app rebuild or deployment-wide mobile secret is required.

- Android sideload; build the `open` product flavor:
  ```bash
  (
    set -euo pipefail
    cd chronicle           # the Android submodule
    ./gradlew :app:assembleOpenRelease
  )
  ```
  The `open` flavor sets `ALLOW_ANY_SERVER=true`. It accepts only a root URL on HTTPS; plain HTTP, URL credentials, query/fragment content, and
  path-prefixed base URLs are rejected. It trusts the system certificate store and a CA the
  phone owner installed, which is what the local trial mode relies on; see
  [Which Android build](../README.md#which-android-build). To ship a sideload build as a
  distinct store app, give it its own `applicationId` and store/signing configuration.

- iOS; in `chronicle-ios/chronicle/Config/Chronicle.local.xcconfig` set:
  ```
  CHRONICLE_ALLOW_ANY_SERVER = YES
  ```
  then build. Release builds validate the server certificate against the system trust
  store, so your server needs a valid publicly trusted cert (Caddy handles this).

### Public-client credentials

A client starts from a one-time enrollment link issued by the dashboard and, after
successful exchange, stores only its returned per-device API key. Deployment-wide mobile
signing keys and their rotation commands are unsupported. Setup generates only the
credentials required by the current deployment.

### Enroll a device

From the participant row in the dashboard, issue and scan the one-time enrollment QR/link.
Its access code is in the URL fragment rather than the query string, so browsers and
intermediaries do not send it as part of the HTTP request. Do not hand-construct, reuse, or
paste the code into support channels. Grant the OS permissions the study's modules need and
complete the per-module consent steps. The dashboard should then show the device with a
recent upload time.

### Play Console reviewer credential

Configure the scope through the dashboard; never reuse a real participant:

1. Create a dedicated reviewer study with active start/end dates. Complete its participant
   policy and save an explicit versioned Data Collection setting first. A legacy
   `AndroidSensor`-only setting is not valid for public enrollment.
2. Open Participants, add a synthetic non-PII ID such as `play-reviewer`, and keep it in
   `ENROLLED` state. The public reviewer route never changes researcher-controlled status.
3. Put only that study UUID and participant ID in `.env`, leave
   `CHRONICLE_REVIEWER_ACCESS_ENABLED=false`, start the stack, and run `./chronicle doctor`.
   Do not continue until the `reviewer-scope` check is `ok`; it verifies the live rows and
   active dates/status.
4. Run:

```bash
./chronicle rotate-secret reviewer
```

That command generates a 256-bit reusable secret directly into `.env`, enables the exact
reviewer endpoint, recreates the backend, and verifies readiness. Copy the value from a
trusted editor directly to Play Console. The browser/app submits it only in the
`X-Chronicle-Reviewer-Secret` header to
`POST /chronicle/v4/mobile/reviewer-enrollment`; never put it in a URL, local storage, or
Git. The response is `Cache-Control: no-store` and contains:

```json
{
  "enrollmentCode": "<fresh one-time code>",
  "preview": {
    "manifest": "<the normal authoritative enrollment manifest>",
    "manifestDigest": "<lowercase SHA-256 digest>"
  }
}
```

The reusable credential is scoped to that configured study only, is IP-rate-limited and
audited, and cannot authenticate any dashboard/admin API. Every successful call replaces
the prior outstanding reviewer invitation with a fresh 15-minute code. Normal participant
invitations keep their existing one-time behavior and are unaffected.

For a later review or a reset, use the dashboard to restore the same synthetic participant
to `ENROLLED` and ensure the study dates remain active. A prior destructive withdrawal must
be fully reset by an operator before reuse; the public route never bypasses pending deletion.
Then rerun `./chronicle doctor` and rotate the reviewer credential. Do not seed rows with SQL,
clone a real participant, or place the reusable secret in a participant field.

## Deployment compatibility

The release supports three private-dashboard modes, scheduled backups, optional monitoring,
and the exact storage combinations listed in
[DEPLOYMENT-COMPATIBILITY.md](DEPLOYMENT-COMPATIBILITY.md).

## Secret rotation

Do not hand-edit one side of a shared credential and restart containers piecemeal. Use
`./chronicle rotate-secret --help` to choose the dashboard, JWT, internal web, metrics,
PostgreSQL, Grafana, or TDE rotation command. It keeps a private recovery transaction,
health-checks the affected services, and writes secret-free receipts. See
[SECRET-ROTATION.md](SECRET-ROTATION.md), including the explicit forward/rollback command
for a host crash.

## Data deletion and uninstall

Deleting a participant or study is an application workflow with an owner-run erasure, verification,
and durable proof. Removing containers is not data deletion, and removing Docker volumes
does not remove bind-mounted backups. Follow
[UNINSTALL-DATA-DELETION.md](UNINSTALL-DATA-DELETION.md) for the exact distinction and safe
operator sequence.

## Installing another release

Post-reset releases upgrade in place with `./chronicle update`; `./chronicle update --check`
reports availability. `./chronicle update <version>` selects a published version and can
repair the current version. The updater preserves configuration and state and automatically
rolls back failed verification. Only pre-reset releases (2026.10.9 and earlier) require fresh
volumes. A reviewed backup restores into the same or a newer post-reset release; a newer
backup cannot restore into an older release. See [upgrade and rollback](UPGRADE-ROLLBACK.md).

## Verify the public mobile path

Routine `./chronicle verify` uses anonymous refusal and readiness probes. It does not
create a participant or replay uploads in a research study. Its output explicitly reports
that the mutating canary is not configured for operator verification.

The disposable release-smoke stack creates a dedicated synthetic study and exercises
enrollment, collection acknowledgment, and upload there. Run that release check before
publication. Never point the synthetic client at a live research study.

## Study webhook recipients

Study webhooks are managed through the authenticated API, not the dashboard. Inventory
registered recipients with `GET /chronicle/v3/study/{id}/webhooks` using a researcher session
with study access. Create recipients before enrollment: adding a destination is refused
while enrollments are active or pending. Creation, deletion and test delivery are audited. Enrollment and data-submission
events include keyed participant references, study context and record counts. Raw participant labels stay inside Chronicle. Inventory every recipient,
hosting country, transfer authorization and retention agreement before enabling delivery.
Keep the study's participant sharing disclosure consistent with these recipients. Chronicle
cannot erase copies already delivered: arrange and verify recipient-side deletion when a
participant or study is erased, including the recipient's backups and downstream processors.

Extend this inventory to **downloaded exports** and copies on analyst workstations, at
collaborators, in backup storage and exposed through support access. Record each recipient's
controller/processor role, data and subject scope, purpose, lawful basis, written or
electronic disclosure agreement, delivery date, retention schedule row and custodian.
Track onward recipients and evidence of correction, return or deletion; removing a local
export does not recall a delivered copy.

Assess whether each flow leaves the country, including remote access,
off-host backups and support. Record destination countries and the onward chain, the
adequacy decision or enforceable safeguards relied on, their evidence and approval.
For a specific non-habitual exception, record its precise statutory ground and supporting
facts before transfer. Keep the notice consistent with the actual flow, and record each
disclosure and international transfer in the institution's registers.

## Upload body deadlines

Every Caddy listener keeps the generated `UPLOAD_BODY_TIMEOUT_SECONDS` whole-body deadline
(300 seconds), even if bytes keep arriving. After a transport timeout or body-deadline
failure, Android keeps unacknowledged rows queued and retries with a smaller batch.
Oversized bodies and payload rejections also split down to single rows when needed.
This total read deadline is independent of the upstream idle timeout. Keep
both limits when replacing the supplied listeners; the topology drill checks an incomplete
trickled body and a complete upload separately. The upload-body-limit-edge job exercises the body ceiling.

## Database connection roles

Setup generates `POSTGRES_APP_PASSWORD` independently of the existing owner password.
The default and `chronicle` JDBC pools log in as `chronicle_app`, a non-owner login with
`NOSUPERUSER` and `NOBYPASSRLS`. Their table and index initializers remain disabled.
`POSTGRES_USER` and `POSTGRES_PASSWORD` select the explicit `bootstrap` pool for framework
schema initialization, Flyway, and protected restore authority. Missing owner configuration
fails startup. Database backup and restore commands continue to use the owner credential.

Both runtime pools retain their existing maximum of 20 and minimum idle of 5 connections.
The new bootstrap pool has provisional maximum 2 and minimum idle 0. Retain these values:
Flyway needs its lock/history connection alongside its migration connection. The upstream
offline bootstrap has no owner-pool budget. The combined per-backend ceiling therefore
increases from 40 to 42, with the minimum idle total remaining 10. Connection timeouts and
lifetimes retain their existing values. Rotate the app login with
`./chronicle rotate-secret postgres-app`; owner password rotation remains a separate operation.
