# Chronicle self-hosting guide

Chronicle is a research data-collection platform: participants install a mobile app
(Android/iOS) that uploads sensor and app-usage data to a server you control, and
researchers manage studies and export data from a web dashboard.

This directory deploys the Chronicle server with a bundled Percona PostgreSQL database.
Each installation keeps its study data in its own Docker volumes; configure your domain
and private researcher access during setup.


## Requirements

- A Linux host with Docker and the Docker Compose plugin **2.17 or newer**. The `./chronicle` script
  also runs on macOS for a local trial; deploy on Linux. See [Supported hosts](#supported-hosts).
- An **amd64 (x86_64)** Docker host for production. The release images are
  published for `linux/amd64` only; there are no arm64 images. On a Docker daemon that reports
  another architecture, the launcher runs the bundled Caddy image once with
  `--platform linux/amd64 --network none` and a no-op command. Where that works (Docker Desktop
  or OrbStack on an Apple silicon Mac, or a Linux host with amd64 binfmt/QEMU emulation), every
  command proceeds with a warning that performance is emulated and slower: fine for a trial. Only
  a daemon that cannot run amd64 images at all (`exec format error`) makes a fresh
  `./chronicle setup` refuse and `./chronicle check` fail. On a deployment that already exists,
  `up`, re-running `setup` and `update` only warn, so an update is never refused for it.
- Container runtime and kernel at or above the releases that fix the 2026 container-escape and
  kernel CVEs: Docker Engine **29.8.2**, containerd **2.2.10, 2.3.7 or 2.4.2** (the 1.7 line has no
  fix), runc **1.3.6 or 1.4.3**, and a kernel at **6.1.177, 6.6.144, 6.12.95, 6.18.38 or 7.1.3** or
  newer in its series (5.10.254 and 5.15.204 also carry both fixes), or a distribution kernel with
  the CVE-2026-31431 and CVE-2026-53362 fixes backported; both are on CISA's exploited list and
  reachable from a container under Docker's default seccomp profile. Install Docker from Docker's own
  repository (`docker-ce`, `containerd.io`) and upgrade with your package manager. `setup`, `check`,
  `up`, `update` and `doctor` warn when a version is older, naming the CVEs; they never refuse to
  run because of it. Only the Compose 2.17 floor is enforced, because older Compose cannot start
  the stack.
- Bash, **Python 3.9 or newer**, curl, OpenSSL, and OpenSSH tools with
  `ssh-keygen -Y` signing/verification support. Install these before verifying the signed
  download or running setup. The Linux recipes also use GNU coreutils, gzip, tar and
  iproute2 (`ip` and `ss`) for address and listener checks.
- An operator account in the `docker` group on rootful Docker. Rootless Docker and
  enforcing SELinux remain unqualified; use the [VM procedures](../tests/deployment/selfhost-platform.md) before declaring support.
  Membership of the `docker` group is **root-equivalent** on that host, so give it only to
  the people who run Chronicle. Nothing else on the normal path needs `sudo`:
  `setup`, `check`, `up`, `verify`, `restore` and `rotate-secret` run as that
  account, and every file they create (`.env`, `backups/`, receipts) is owned by its uid.
  Installing Docker itself, and `timedatectl set-ntp`, need root once.
- ~4 vCPU / 8 GB RAM is comfortable; a pilot with a handful of devices runs on
  2 vCPU / 4 GB. See [Sizing](#sizing).
- A hostname (e.g. `chronicle.example.org`) and a TLS certificate for it. On an
  institutional server this is normally your institution's load balancer + institutional
  cert; you do **not** need a public Let's Encrypt setup. See
  [Required configuration](#required-configuration).
- Outbound HTTPS to pull the images. Automatic reconciliation (restart after a reboot or a
  failed container) needs Linux with `cron`/`cronie`, `logger`, and an enabled, active
  `cron`/`crond` service. Without them nothing is refused: a new install starts with
  `CHRONICLE_RECONCILE_ENABLED=false`, and setup, update and doctor warn on a deployment that
  has it enabled. Install and enable cron, and the next `./chronicle up` or `./chronicle update` installs the schedule.

### Supported hosts

| Host | Tested | Bash | SELinux | Notes |
|---|---|---|---|---|
| RHEL 9 / Rocky / Alma 9, Docker CE | yes | 5.1 | Enforcing on the host; Docker daemon without `selinux-enabled` | Supported production host |
| Ubuntu 22.04 / 24.04, Docker CE | no | 5.1 / 5.2 | n/a (AppArmor) | Expected to work; report issues |
| macOS with OrbStack or Docker Desktop on an Intel Mac | trial only | 3.2 (`/bin/bash`) | n/a | Deploy on Linux; an Apple silicon Mac's Docker is arm64, which setup refuses |

SELinux: the bundle and state-directory bind mounts carry the shared `z` relabel option.
A daemon without `selinux-enabled` ignores it (checked on RHEL 9.8: file labels are
unchanged). With `selinux-enabled: true` the daemon relabels the bundle directory and the
`tls/` and `backups/` state directories as `container_file_t`; that path has not been run
end to end. Run the daemon with SELinux support off (the RHEL default for Docker CE), or
test it on a staging host before production.

## Quick start

Blocks enclosed in `( ... )` stop on failure without closing your interactive shell.
Their directory changes and variables stay inside the block.

From a published release bundle (download the archive, `.sha256`, and `.sha256.sig` from the
repository's GitHub Releases page):

The public key ships in the bundle. Only its fingerprint must come separately from the
maintainer, by email or message from your study's Chronicle contact.
The expected Ed25519 fingerprint is
`SHA256:PuOdejZ2d1CQgrWEF/tf95asMPC5RnsbCidg1PB6VSo`.
Replace `<version>` with the release version in the file name. Extract only the key:

```bash
(
  set -euo pipefail
  tar -xzOf chronicle-selfhost-<version>.tar.gz chronicle-selfhost-<version>/selfhost/release-signing.pub > release-signing.pub
  ssh-keygen -lf release-signing.pub -E sha256
)
```

Compare this fingerprint with the one the maintainer sent separately.
If it differs, stop. Do not install. If it matches, verify the signature and checksum below.
See [Release signatures and key rotation](docs/UPGRADE-ROLLBACK.md#release-signatures-and-key-rotation).
`./chronicle setup` also prints the installed fingerprint.

```bash
(
  # 1. Verify and extract the bundle. It contains no source and builds nothing:
  #    `up` pulls the digest-pinned images. On macOS use:
  #    shasum -a 256 -c chronicle-selfhost-<version>.tar.gz.sha256
  set -euo pipefail
  printf 'chronicle-release %s\n' "$(cat release-signing.pub)" > allowed_signers
  ssh-keygen -Y verify -f allowed_signers -I chronicle-release -n chronicle-release \
    -s chronicle-selfhost-<version>.tar.gz.sha256.sig < chronicle-selfhost-<version>.tar.gz.sha256
  sha256sum -c chronicle-selfhost-<version>.tar.gz.sha256
  tar -xzpf chronicle-selfhost-<version>.tar.gz
  cd chronicle-selfhost-<version>/selfhost

  # 2. Configure interactively. Secrets are generated and never printed.
  ./chronicle setup

  # 3. Validate the host, pull the digest-pinned images, and start.
  ./chronicle up

  # 4. Check that public routes work and the dashboard API stays private.
  ./chronicle verify

  # 5. Check backup age and service health; follow any reported recovery command.
  ./chronicle doctor
)
```

For subsequent commands, enter the installed bundle:

```bash
cd chronicle-selfhost-<version>/selfhost
```

### From a source checkout

```bash
(
  set -euo pipefail
  # 1. Clone the public repository. The operator script initializes only the server
  #    submodules it needs; chronicle-ios intentionally remains unchecked out.
  git clone https://github.com/uzaira0/chronicle-platform.git chronicle
  cd chronicle/selfhost

  # 2. Configure interactively. Secrets are generated and never printed.
  ./chronicle setup

  # 3. Validate the host, pull, and start. This is the whole deployment.
  ./chronicle up

  # 4. Check that public routes work and the dashboard API stays private.
  ./chronicle verify

  # 5. Check backup age and service health; follow any reported recovery command.
  ./chronicle doctor
  ./chronicle monitoring status    # when monitoring was selected during setup
)
```

For subsequent commands, enter `chronicle/selfhost` from the directory where you ran the block.

On a source checkout the first `up` builds the images from source, so it takes longer than
a restart.

To update a source checkout, first confirm that local work is committed on an appropriate
branch and that the current deployment has a recent verified backup. Then update by exact
gitlinks and let the operator command build the new revision:

```bash
(
  set -euo pipefail
  cd /path/to/chronicle
  git pull --ff-only
  git submodule update --init --recursive
  cd selfhost
  ./chronicle up
  ./chronicle verify
  ./chronicle doctor
)
```

Post-reset installations upgrade in place with `./chronicle update`, run from the directory you
installed; after an update, its `./chronicle` forwards to the new release, so that directory stays
the one place you run commands. Pre-reset releases (2026.10.9 and earlier) require a fresh
installation; see [upgrade and rollback](docs/UPGRADE-ROLLBACK.md).

`./chronicle setup` is the recommended path for a first-time operator. Copying
`.env.example` manually remains available for automation.
It generates deployment secrets directly into a mode-`0600` `.env`, asks you to choose the
dashboard password without echoing it, and sends that password to Caddy over stdin to
create a **bcrypt hash**. It never prints a generated secret or cleartext password. It also
writes the `COMPOSE_FILE` line that matches your answers, which is what makes step 3 need no
`-f` arguments.

Nothing starts until the configuration passes. `config-guard` runs first, and every other
service waits for it: placeholder secrets, a secret that is too short, a production mode
with no backups, a public dashboard with no reviewed authentication, `REQUIRE_MFA`
paired the wrong way; each stops the deployment before a container is started, with the
specific `.env` line to change. Then `cert-init` prepares the certificate the dashboard
listener needs, and `db-init` turns on encryption at rest *before* the backend first
connects, so every table is created encrypted rather than converted afterwards.

### No domain name yet? Trial it on this machine

`./chronicle setup` offers a third option: a trial on this machine, with test phones on
the same wifi. Caddy supplies a local certificate authority for the trial
inside the stack and issues its own certificate for this machine's LAN address.

```bash
./chronicle up
# Prints an optional CA-install QR code once the stack is healthy.
```

The Chronicle apps do **not** need that CA installed: in this mode the dashboard puts the CA
root certificate in each invitation link (`serverCa` parameter), and the apps trust it as an
extra root for that server only, with hostname checks unchanged. The phone's browser does not
read the link's CA. It warns when it opens the invitation page, and even after you continue
past the warning, Chrome on Android can refuse the page's own request to the server, so the
page shows "Invitation unavailable" and never reaches the app hand-off. On a trial phone that
opens the invitation in its browser, install the CA first (below). Android accepts a link CA for LAN IP addresses,
`localhost`, and `.local` names only when the connected peer also has a LAN address. iOS
accepts CA-bearing `chronicle://enroll` links for LAN IP addresses and `localhost`; use the
server's LAN IP instead of a `.local` name on iOS. URLSession does not expose the connected
peer during trust evaluation, so iOS cannot safely accept a name that might resolve publicly.
The dashboard's browser hand-off currently offers Android only; iOS needs a direct
`chronicle://enroll` invitation from the study team.

Install the CA on a device (the QR printed by `./chronicle up` points at
`http://<lan-ip>/local-ca.crt`) when a phone opens the invitation in its browser, or when
it enrolls by typing the server address rather than from the link.
It is a **trial mode**: never ask study participants to install a CA. To move to a real deployment, rerun `./chronicle setup`, choose option 1 or 2,
and enter the public hostname and production TLS choice. Setup replaces the trial LAN
`DOMAIN`, clears the private `CHRONICLE_PUBLIC_BASE_URL` override so Compose uses
`https://DOMAIN`, and writes the production `COMPOSE_FILE`. Keep `CHRONICLE_STATE_DIR`
pointed at the existing data directory. Then run `./chronicle check` and `./chronicle up`.

> Android caveat for the typed-address fallback: a user-installed CA is trusted by browsers
> but **not by apps**, unless the app ships a `network-security-config` that opts in. The Chronicle `open` build ships that
> entry (`app/src/open/res/xml/open_network_security_config.xml`), so use the `open` APK
> (`:app:assembleOpenRelease`, or the Google Play build, which is the open build) for trial
> phones. The research build stays system-CA-only; on it, enrollment fails with a TLS error
> while the same URL loads fine in Chrome on the same phone.

### Editing .env by hand instead

```bash
(
  set -euo pipefail
  cp .env.example .env
  chmod 600 .env
  ${EDITOR:-vi} .env          # DOMAIN, deployment secrets, and DASHBOARD_PASSWORD_HASH
  ./chronicle up
)
```

`.env` is the only file you edit. It carries `COMPOSE_FILE`, so plain `docker compose`
picks up the right overlays with no `-f` arguments; the deployment modes are described in
`.env.example` next to that line, and the default is the recommended one (your load
balancer terminates TLS, the dashboard is reachable only on a private interface, backups
on). Generate the password hash without putting the cleartext in shell history or process
arguments:

```bash
(
  set -euo pipefail
  read -rsp 'Dashboard password: ' DASHBOARD_PASSWORD; echo
  CADDY_IMAGE="$(sed -n 's/^CADDY_IMAGE=//p' .env)"
  printf '%s\n' "$DASHBOARD_PASSWORD" | docker run --rm -i --network none --read-only \
    --entrypoint caddy "$CADDY_IMAGE" hash-password
  unset DASHBOARD_PASSWORD
)
```

### Check the deployment

`./chronicle verify` calls the running server and checks that the researcher dashboard API is
absent from the public listener, that the direct backend routes are refused, that mobile
ingest is rate limited, that every table is encrypted and a key-free dump exists.
It exits non-zero if the deployment does not match `.env`.

Run `./chronicle check` before the first start on a new host. It repeats the configuration
checks and adds three that need the host itself:
whether the bind address is one this host has, whether the port is already taken,
and whether another Compose project of the same name would be adopted. On the plain
`docker compose up -d` path, Docker's own bind error is the fallback for the first two.

Then browse to the dashboard on the internal listener: `https://<INTERNAL_BIND>:8081/chronicle`
(e.g. `https://127.0.0.1:8081/chronicle`, reachable over an SSH tunnel). The dashboard API is
absent from the public listener by design, so the SPA loads on `https://<your-domain>` but every
call it makes returns 404; that domain is the participant/mobile origin only. Point a Chronicle
app build (see [Mobile apps](#mobile-apps)) at the domain to enroll a device.

Other `./chronicle` subcommands: `up` (check, then `docker compose up -d`), `restore` (stop every writer,
restore a verified dump, and restart only after health passes), `rotate-secret` (one guarded
credential change or interrupted-operation recovery), `deletion-status`, `status`, `logs`,
`doctor` (actionable checks, or machine-readable `--json`), `monitoring` (status and private
Viewer accounts), `down`. Use `./chronicle up` for normal operation. Direct Compose is an
automation-level interface only after `.env`, submodules, and images are prepared; it skips
host-address, port-collision, and deployment-ownership checks, and without exported
`CHRONICLE_HOST_UID`/`CHRONICLE_HOST_GID` it runs the backup and restore containers as root,
leaving root-owned dumps. Use the guarded restore
for recovery into the same or a newer post-reset release; use `./chronicle update` for new releases.

## Required configuration

Beyond flipping overlays on/off, these are the decisions/values the deploying team must
set. The participant-facing override and email are optional;
setup supplies safe defaults or generated values for the remaining entries where possible:

| # | What | Where | Notes |
|---|---|---|---|
| 1 | Listener hostname | `DOMAIN` in `.env` | The FQDN served by this stack or its direct proxy listener. |
| 2 | Participant-facing origin (optional) | `CHRONICLE_PUBLIC_BASE_URL` | Exact HTTPS root used in enrollment links and signed manifests when it differs from `https://DOMAIN`; no path, query, fragment, or credentials. |
| 3 | TLS strategy | see below | The main decision on an institutional box. |
| 4 | DB password | `POSTGRES_PASSWORD` | Any strong secret; only this stack uses it. |
| 4 | Runtime DB password | `POSTGRES_APP_PASSWORD` | Generated independently for the restricted `chronicle_app` login. |
| 6 | Dashboard access | see [Securing the dashboard](#securing-the-dashboard) | Internal listener + dashboard password, optionally behind your institution's access layer. |
| 7 | **Listen address** | `HTTP_BIND`, `HTTP_PORT` | Where your proxy reaches the stack. **Must not be `127.0.0.1` if the proxy is on another host**; see below. |

### TLS; the institutional decision

This stack does not manage certificates by default. Choose the model that fits your
infrastructure:

- Behind your institution's load balancer (recommended). Your F5 / nginx / Apache /
  cloud LB terminates TLS with the institution's certificate and forwards to
  `HTTP_BIND:HTTP_PORT`. Setup asks for the exact LB source CIDRs in
  `CADDY_TRUSTED_PROXIES` (the Compose gateway for a same-host proxy; explicit source CIDRs
  for a remote F5) and the pool ingress allowlist
  `POOL_ALLOWED_IPS`. When configured, only those peers may reach the public pool listener.
  An off-host LB requires explicit source CIDRs even when SNAT removes client XFF;
  blank, loopback-only and Docker-gateway-only sources are refused. Setup enables TLS
  for the off-host pool hop unless a reviewed `POOL_PLAINTEXT_WAIVER` is retained. The LB must
  overwrite `X-Forwarded-Proto` with exactly `https`. If it sends `X-Forwarded-For`, it must
  replace it with its observed client address. Do not use `private_ranges` as a trust shortcut.

  Set `CHRONICLE_PUBLIC_BASE_URL` to the externally served HTTPS origin, including an
  alias or nonstandard port. Set `PUBLIC_HTTP_ENABLED=true` only when external HTTP is
  exposed; verification then requires its redirect to that canonical HTTPS origin.
  The default is a TLS-only public endpoint with no port-80 requirement.

  > Set `HTTP_BIND` to a reachable private pool address and retain the fixed `HTTP_PORT`
  > configured in the LB. `./chronicle verify` and `doctor` probe canonical public HTTPS
  > with certificate validation from this host. Run the separate-host harness too:
  > host reachability does not establish phone or researcher reachability.

  An F5 that SNATs and sends no client `X-Forwarded-For` provides only the LB address.
  Trusting its CIDR cannot recover the original address. Authenticated uploads have no
  edge quota. For enrollment and public bootstrap routes, the shared ceiling rises to
  20,000 per mobile window only when both the socket peer and resolved client IP are trusted LB addresses. Request
  LB header insertion when per-client IP behavior is required.

  With `HTTP_BIND` off loopback the LB-to-pool hop runs TLS: setup sets
  `POOL_LISTENER_TLS=true`, the pool listener serves the generated internal certificate
  (its SANs include `HTTP_BIND`), and the LB re-encrypts to the pool member and trusts
  `tls/internal-ca.crt`. config-guard refuses plain HTTP off loopback unless
  `POOL_PLAINTEXT_WAIVER` names an approved controlled-register waiver.
- Terminate TLS on the stack with your own certificate. Drop `cert.pem` + `key.pem`
  (institution-issued or commercial) into `./tls`, then put
  `overlays/mode-own-tls-internal.yml` in `COMPOSE_FILE`. No Let's Encrypt. This adds no
  container; it swaps the same Caddy onto `Caddyfile.split.tls`, and `cert-init` fixes
  the key's ownership so Caddy, which runs with every capability dropped, can read it.

> If your certificate is issued by a **private/internal CA**, the mobile apps must be told
> to trust that CA; see [Mobile apps](#mobile-apps). A publicly trusted certificate
> (including most institutional certs that chain to a public root) needs no device changes.

## Architecture

```
           ── pick ONE way to terminate TLS ──
   ┌─────────────────────┐   ┌─────────────────────────────────────┐
   │ institution LB / F5 │   │ OR  a mode-own-tls-* overlay — the   │
   │ (institutional cert)│   │     SAME web container, with your    │
   │                     │   │     cert.pem/key.pem. No ACME.       │
   └──────────┬──────────┘   └──────────────────┬──────────────────┘
              │ https (X-Forwarded-Proto: https) │
              └───────────────┬──────────────────┘
                              ▼
                      ┌───────────────┐
                      │  Caddy (web)  │  serves the dashboard's static files,
                      │   :8080       │  routes /chronicle/{v2,v3,v4,api/web,study,…} → backend,
                      └───────┬───────┘  and optionally terminates TLS — one container
                              │ https (backend service certificate)
                      ┌───────▼───────┐        ┌──────────────┐
                      │    backend    │───────▶│  PostgreSQL  │  pg_tde tables → plain SQL dumps
                      │  (Spring)     │        └──────────────┘
                      └───────────────┘
```

The routing lives in three supported Caddyfiles, with the route lists factored into
`caddy/snippets.caddy`. All three import those same snippets, so their route
definitions cannot drift apart:

| File | Listens | Mounted by |
|---|---|---|
| `Caddyfile.split` | `:8080` pool (HTTPS when `POOL_LISTENER_TLS=true`), `:8081` internal (HTTPS) | `overlays/mode-behind-proxy-internal.yml`; the default |
| `Caddyfile.split.tls` | `:443` public, `:8081` internal (HTTPS) | `overlays/mode-own-tls-internal.yml` |
| `Caddyfile.split.local` | `:443` public (Caddy's own CA), `:80` CA download + redirect, `:8081` internal | `overlays/mode-local-https.yml`; trial only |

The overlay is what publishes the ports *and* what mounts the matching Caddyfile, in the
same file; so there is no combination of settings that mounts a config for a listener the
stack never publishes. `verify-config.sh` checks that pairing.

The base file publishes no ports. The selected mode publishes either the pool listener for
an upstream TLS proxy or HTTPS using your certificate/private trial CA; there is no forced
Let's Encrypt. Caddy reaches the backend over HTTPS, verified against the backend service
certificate that cert-init issues.

### What can leave the host

Containers that hold participant data or credentials cannot open a connection off the host
or resolve an external name. Web and the backend sit on an internal `core` network, and
PostgreSQL with its users (backend, backups, database jobs) on an internal `database` network
that web is not on. Two small forwarders that hold nothing carry the published ports. Monitoring
is internal too. The one container with a route out is `egress-proxy`, which tunnels only to
the hosts your settings name: your public URL, which `public-probe` checks, and, when
`CHRONICLE_ALERT_WEBHOOK_URL` points off this host, the webhook, which Grafana calls. Study
webhooks are off for that reason: registering one is refused and says why. Long-running
containers read their credentials from files, so `docker inspect` shows none. `./chronicle
update` applies all of this itself. Details, limits and a runtime check:
[docs/NETWORK-EGRESS.md](docs/NETWORK-EGRESS.md).

### Host firewalls and published ports

Only `web-forward` (and `monitoring-forward`, on loopback) publish ports. Docker opens a
published port with its own iptables/nftables rules in the `nat` and `FORWARD` paths, which run
before the input rules that UFW and firewalld manage, so a UFW or firewalld rule does not
stop traffic to a published port. Restrict who reaches the participant listener in one of
three places:

- the bind address: `HTTP_BIND`, `INTERNAL_BIND` and `GRAFANA_BIND` default to `127.0.0.1`;
  only the own-TLS and local-HTTPS modes publish 443/80 on every interface;
- `POOL_ALLOWED_IPS` (behind-proxy mode): Caddy refuses any other source, using the client
  address `web-forward` passes it;
- the `DOCKER-USER` chain, which Docker evaluates before its own rules, for example
  `iptables -I DOCKER-USER -i eth0 ! -s 203.0.113.0/24 -p tcp --dport 8080 -j DROP`
  (and the `ip6tables` equivalent; Docker's documentation, "Packet filtering and firewalls").

Check the result from another machine, for IPv4 and IPv6, with `nmap -Pn -p 1-65535 HOST`
(or `nc -vz HOST PORT` for each published port): only the ports your mode publishes on a
non-loopback address may answer.

Two traffic paths share the server:
- Mobile ingest (`/chronicle/v3/*`, `/chronicle/v4/*`); public clients authenticate
  with the per-device API key returned by one-time enrollment, never by a dashboard login.
  Never put a password gate in front of these paths.
- Dashboard (`/chronicle/…`); for researchers. Protect it (see
  [Securing the dashboard](#securing-the-dashboard)).

## Modular overlays

`COMPOSE_FILE` in `.env` is the list of compose files, colon-separated. Docker Compose
reads it from `.env` itself, which is why plain `docker compose up -d` needs no `-f`
arguments. Exactly one of the three supported `mode-*.yml` files must be in it; the rest
are optional within the declared combinations:

| Overlay | Adds | Put it in `COMPOSE_FILE` when… |
|---|---|---|
| `overlays/mode-*.yml` | The listener config and the ports for one deployment mode | Always; exactly one. See `.env.example`. |
| `overlays/backups.yml` | Scheduled `pg_dump` with rotation → `./backups`, plus one dump at startup | **Always in production, and required whenever encryption is on.** |
| `overlays/monitoring.yml` | Private Grafana, VictoriaMetrics, VictoriaLogs, sanitized Chronicle logs, host/container/application/database/backup probes and visible alerts | Trusted observers need to see operational mistakes and failures. |

The authoritative supported/rejected combinations, including encryption and backup
requirements, are in
[docs/DEPLOYMENT-COMPATIBILITY.md](docs/DEPLOYMENT-COMPATIBILITY.md).

```ini
# .env — default mode, backups, and monitoring:
COMPOSE_FILE=docker-compose.yml:overlays/mode-behind-proxy-internal.yml:overlays/backups.yml:overlays/monitoring.yml
```

There is **no observability stack in the base deployment**. Monitoring remains opt-in and
adds no required variable or health dependency when absent. `./chronicle setup` offers it
and writes the overlay, private bind, and retention values without manual Compose editing.

The backup sidecar waits for both PostgreSQL and the migrated backend before taking its
startup dump. That readiness check runs inside the container as well as through Compose,
so a host or Docker daemon restart cannot race the dump against database startup. Tune
`BACKUP_STARTUP_TIMEOUT_SECONDS` when a deliberately slow migration needs longer. It defaults
to 3600 seconds and accepts any positive integer without a one-hour maximum. Restore and
update startup waits use the same validation; see [backup and restore](docs/BACKUP-RESTORE.md).

Monitoring binds Grafana to `127.0.0.1:3000` by default. Use `GRAFANA_PORT` to avoid a
local collision or `GRAFANA_BIND` for one reviewed private interface; startup refuses a
wildcard bind. Reach the loopback default through an SSH tunnel. VictoriaMetrics retains
30 days and VictoriaLogs retains 14 days by default; each has a 5 GiB budget. The overlay
provisions immutable System, Application, Database and Storage, Containers, Operational
Events, and sanitized Operational Logs dashboards plus dashboard-visible alerts. It keeps
running when the application or configuration guard fails.

Create one read-only account per trusted observer; passwords are prompted without echo and
never appear in command arguments or receipts:

```bash
./chronicle monitoring status
./chronicle monitoring add-viewer alice
./chronicle monitoring reset-viewer alice
./chronicle monitoring remove-viewer alice
```

Firing and historical alert states are visible in Grafana. By default no notification leaves
the host, and none needs configuring to be recorded: every 15 minutes the scheduled
reconciliation writes each firing alert to the host's system log (`journalctl -t chronicle`,
priority `crit`, repeated daily while it fires, plus a `resolved` line), and `./chronicle doctor`
(`alerts-firing`) and `./chronicle status` list them. Set `CHRONICLE_ALERT_WEBHOOK_URL` to also
deliver alerts to a person (runbook sections "Where alerts go" and "Attach a notification
channel"). `alert-route` in doctor warns only when there is neither a webhook nor a schedule; it
never makes doctor or scheduled reconciliation fail. Test webhook delivery in Grafana using the bundled
[monitoring runbook](docs/MONITORING-RUNBOOK.md). Each alert links to that runbook.

Backend and Caddy emit structured JSON envelopes, PostgreSQL emits a parseable timestamp and
SQLSTATE prefix, and guarded operator commands emit JSON events. Fluent Bit accepts only these
four Chronicle sources and keeps only finite operational fields. Raw messages, headers,
queries, payloads, SQL, addresses, identity fields, and stack traces never enter VictoriaLogs;
an unknown line becomes a generic service/severity event instead of being forwarded verbatim.

Guarded routine commands also append mode-0600 JSON receipts below
`${CHRONICLE_STATE_DIR}/operator-receipts/operations/`. Each receipt contains only the
operation, UTC timestamp, release version, outcome, and finite failure category. Viewer
passwords and deployment credentials are never included. These receipts exist whether or not
the monitoring overlay is enabled; monitoring additionally projects the latest result into the
Operational Events dashboard.

## Securing the dashboard

With one of the `mode-*-internal` overlays (the default in `.env.example`) the researcher
dashboard is **not served on the public listener at all**; the API returns
404 there. The internal listener it does live on is protected by three independent
controls applied automatically.

1. Source-address allowlist. `DASHBOARD_ALLOWED_IPS` (space-separated CIDRs) decides
who may reach the dashboard at all. The default includes loopback and the selected Compose
gateway, which Docker presents for host access and SSH tunnels. Add your approved VPN or
researcher subnet for remote access:

```bash
DASHBOARD_ALLOWED_IPS='10.20.30.0/24'
```

It is matched against the real TCP peer address, not `X-Forwarded-For`, so a caller
cannot forge their way past it with a header. A disallowed source gets `403` and is never
offered a password prompt.

2. A single global username and password. Set once, shared by everyone who uses the
dashboard, and stored only as a bcrypt hash, so the cleartext cannot be recovered from
the server. (`./chronicle setup` asks you to choose it silently and writes just the hash.)
To change it without leaking it through shell history, process arguments, or an intermediate
file:

```bash
./chronicle rotate-secret dashboard
```

The command reads the password twice without echo, sends it to the digest-pinned Caddy
image over stdin, atomically updates `.env`, recreates the backend and edge, and proves the new password.

Researchers enter this shared dashboard password in the application login form.

3. TLS on the internal listener protects dashboard password entry and session cookies. The `cert-init` service
generates a leaf certificate with the requested SANs using the stable dashboard CA
`tls/internal-ca.crt`. Trust that CA on researcher machines; keep its private key private.
Keep the dashboard trust certificate with the installation recovery material.
Setup derives SANs and allowed browser origins from `DASHBOARD_BASE_URL`; extra identities
can be listed in `INTERNAL_CERT_SANS`. Generated leaves renew on SAN changes or within
30 days of expiry, and `up` reloads certificate consumers when fingerprints differ from
the last successful startup. Failed startup leaves that renewal pending for the next retry.
An operator certificate must cover the configured management identity; it is retained and must be renewed
by the operator. An invalid matching pair is moved aside as `*.invalid`. CA replacement
requires a reviewed trust distribution step.

Startup refuses to bring anything up if the password hash is missing or is not a bcrypt
hash, or if the allowlist is empty; any of which would mean no gate at all.
`./chronicle verify` proves from outside that the gate is closed. Ask it to read the correct
password without putting that value in shell history or an environment assignment:

```bash
./chronicle verify --dashboard-password
```

> Participant traffic is deliberately never gated: phones and the participant forms
> (`/chronicle/survey`, `/chronicle/questionnaire`, `/chronicle/time-use-diary`) cannot
> answer a password prompt, and they are served from the public listener.

### Internal-only dashboard (split exposure)

You usually cannot simply put the whole server behind the VPN: participant phones upload
from cellular networks, so ingest has to stay publicly reachable. Setting
a `mode-*-internal` overlay splits the two; one file both selects the Caddy config and
publishes the ports, so they cannot disagree:

```bash
# in .env
COMPOSE_FILE=docker-compose.yml:overlays/mode-behind-proxy-internal.yml:overlays/backups.yml
# then: ./chronicle up
```

That serves two listeners:

| | Port | Carries | Publish to |
|---|---|---|---|
| Public | `HTTP_PORT` (default 8080) | Mobile ingest, participant forms, static SPA | Your institutional proxy / the internet |
| Internal | 8081 | The above plus the researcher dashboard API | A VPN or management interface only |

Set `INTERNAL_BIND` in `.env` to that interface's IPv4 address (e.g. `INTERNAL_BIND=10.0.0.5`).
IPv6 addresses are refused: the stack network is IPv4, so Docker would show every client as its
gateway and the allowlist could never match. It defaults to `127.0.0.1`, so if you forget, the dashboard API is exposed to nothing and you
reach it over an SSH tunnel; it fails closed. `./chronicle check` refuses to start if the
address is not one this host has, rather than letting Docker fail obscurely later
(that check needs the host's own network namespace, so it is the one thing the compose path
cannot do for you).

Internal installs sign in with an explicit password through the existing dashboard login.
Setup writes its bcrypt hash in `DASHBOARD_PASSWORD_HASH`, sets `TESTING_LOGIN_ENABLED=false`
and keeps `REQUIRE_MFA=false` for internal exposure. Sign-out and the idle lock require the
password again. Caddy does not ask for the same password separately: researcher data and API
paths require an app session at the backend. The source allowlist, TLS, pre-auth rate limits,
security headers and public listener restrictions remain in place.

Startup requires the configured dashboard password hash. If it is missing, run
`./chronicle setup` to choose a dashboard password.

The internal listener, source-address allowlist and global password protect dashboard
access in this mode. Sessions use the configured idle deadline.

The backend enforces an idle deadline for researcher sessions. Set
`CHRONICLE_SESSION_IDLE_MINUTES` in `.env` to a decimal integer from `1` through `120`;
the default is `15` minutes, and `./chronicle check` rejects invalid values before startup.
Keep `TESTING_LOGIN_ENABLED=false` in every shipped installation.

Verify the boundary after starting. `./chronicle verify` is the supported check: it requests
the dashboard and test-login routes through the configured public HTTPS origin
(`CHRONICLE_PUBLIC_BASE_URL`) and requires 404. To repeat it by hand from a machine outside
your network, probe that same origin; every one of these must 404:

```bash
PUB=https://<public-host>   # your CHRONICLE_PUBLIC_BASE_URL
for path in /chronicle/v3/auth/testing-login /chronicle/v3/auth/session \
            /chronicle/api/web/study /datastore/ /chronicle/datastore/; do
  printf '%s %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "$PUB$path")" "$path"
done
```

The pool listener (`HTTP_PORT`, default 8080) serves HTTPS whenever pool TLS is on, the
default off loopback, so a plain-HTTP request to it proves nothing. Plaintext-waiver mode
only: with a retained `POOL_PLAINTEXT_WAIVER` that listener speaks HTTP, and you may also run
the loop from an address in `POOL_ALLOWED_IPS` with `PUB=http://<pool-address>:8080`.

The receiving listener determines the public/private boundary, including when an upstream
load balancer rewrites the source address.

The static dashboard files stay public: participant forms ship in the same JavaScript
bundle as the researcher screens, which load there but can fetch nothing.

Verify after starting; the first two must 404 and the rest must succeed:

```bash
# The internal listener is HTTPS; trust its dashboard CA.
PUB=https://<public-host>; INT=https://<internal-ip>:8081
curl -o /dev/null -w '%{http_code} api/web\n'    $PUB/chronicle/api/web/study        # 404
curl -o /dev/null -w '%{http_code} tud-data\n'   $PUB/chronicle/v3/time-use-diary/S/data  # 404
curl -o /dev/null -w '%{http_code} survey\n'     $PUB/chronicle/survey               # 200
curl -o /dev/null -w '%{http_code} ingest\n'     $PUB/chronicle/v4/                  # not 404
./chronicle verify --dashboard-password  # silent password entry proves app login and its session
```

## Rate limiting

Caddy applies IP quotas only to explicit login, enrollment, credential-exchange and public
entry-page routes. Authenticated API, upload and dashboard data routes have no edge quota.
On data routes the backend counts per IP only requests without a valid credential. A request
with a live device key, a live participant survey session or a valid researcher session is
never counted, so enrolled phones and survey pages behind one carrier or school NAT are not
limited by each other; invalid, expired or revoked credentials remain limited.

| Zone | Key | Default | Setting |
|---|---|---|---|
| Enrollment and public bootstrap | resolved client IP | 200 requests/second | `RATE_LIMIT_MOBILE_ABUSE_EVENTS`, `RATE_LIMIT_MOBILE_WINDOW` |
| Enrollment and public bootstrap through trusted SNAT LB | trusted LB IP | 20,000 per mobile window | fixed ceiling; `RATE_LIMIT_MOBILE_WINDOW` |
| Login and credential issue | resolved client IP | 200 requests/second | `RATE_LIMIT_WEB_ABUSE_EVENTS`, `RATE_LIMIT_WEB_WINDOW` |
| Internal login and public entry pages | socket peer IP | 300 requests/minute | `RATE_LIMIT_GUARD_EVENTS`, `RATE_LIMIT_GUARD_WINDOW` |

The backend validates device credentials and study/participant scope. Requests without a
valid credential share a per-IP bucket at 10 requests/minute with burst capacity 15 (the configured
1.5 multiplier). Enrollment preview and code exchange have their own annotated pre-authentication
tiers of 100 and 60 requests/minute, respectively. Edge quotas never depend on a caller's claimed credential value.
`./chronicle verify` uses a bounded anonymous burst to check that the edge or backend returns
429, including through an F5 that SNATs without client XFF.
The backend also limits dashboard login to 5 requests/minute. Several researchers behind
VPN SNAT share the unauthenticated login ceiling. Issued browser sessions do not have
backend or edge API buckets. Asset loading does not consume the login bucket.
Hashed JS/CSS/font assets bypass rate checks; the researcher source ACL
still applies. `/health` is exact readiness, returns 204 only when dependencies are usable,
and does not enter access logs.

Caddy accepts client identity only from the explicit trusted LB sources, resolves the chain
from the trusted end, and writes one normalized identity to the backend. A trusted LB with
no client header leaves all callers at its socket address. Only that trusted SNAT population
receives the higher enrollment/bootstrap ceiling; invalid anonymous uploads still share the
backend pre-authentication bucket. No trust
configuration can reconstruct missing client information. Over-limit requests return 429,
and verification checks that ceiling.

## Managing studies, participants, export, and deletion

Day-to-day study and participant actions are done from the dashboard; the CLI reports the
durable deletion proof. See
[docs/CONFIGURATION.md](docs/CONFIGURATION.md#managing-studies):

- Create a study, toggle which data-collection modules are required/optional, set
  sensor sampling rates.
- Add participants (each gets an enrollment code / QR).
- Download collected data from the Participants tab: tick participants (or *Select all
  participants shown*; the page shows 100 at a time, so use *Show more* first), then
  *Download data*. Each download is one data type as CSV, with optional start and end
  days in the study time zone and an optional filename. It streams straight to the
  browser; the server keeps no export files and runs no export jobs. The columns are
  described in `docs/PILOT-DATA.md` in the source repository.
- The study's Bulk Downloads tab has the whole-study Time Use Diary CSV per variant
  (DayTime / NightTime / Summarized) and every response for a questionnaire as CSV.

  Downloads are raw tables.

Participant and study deletion are verified workflows rather than volume removal.
A request immediately makes live rows inaccessible; physical erasure runs only when an owner
presses **Erase now**, and never on a timer. Backups follow their own retention policy. Read
[docs/UNINSTALL-DATA-DELETION.md](docs/UNINSTALL-DATA-DELETION.md) before either deleting
product data or removing an installation; those are deliberately different operations.

## Mobile apps

Participants need a Chronicle app pointed at *your* server. The `open` build, which Google
Play ships and which you can also sideload, accepts any valid public-HTTPS Chronicle server:

- Android from Google Play: open the one-time enrollment link issued by your dashboard.
  The link supplies your server URL, which remains visible on the enrollment screen for the
  participant to verify before continuing.
- Android sideload: build the `open` product flavor from the `chronicle/` submodule. A
  release build needs `app/signing.properties` and a non-debug keystore first (copy
  `app/signing.properties.example` and point it at your keystore), then
  `cd chronicle && ./gradlew :app:assembleOpenRelease` and
  `adb install -r app/build/outputs/apk/open/release/app-open-release.apk`.
  It is the same build Play ships and trusts any `https` server using the device system
  trust store (`ALLOW_ANY_SERVER`).
- iOS: set `CHRONICLE_ALLOW_ANY_SERVER = YES` in `Chronicle.local.xcconfig` and build.

### Which Android build

Google Play ships the `open` build for Android 8.0 or newer. It supports the pilot's
app-usage, activity-class, device-lifecycle, user-identification, upload, sensor-availability
and battery telemetry modules. Accessibility interaction, notification-listener and audio
collectors are excluded. It trusts publicly trusted CAs plus CAs the phone owner installed
(so the local trial CA works). The sideloaded `open` APK is the same build.

The battery dialog opens Android's general battery settings list. On Android 8 to 14 that is
**Battery optimization**: select **All apps** if necessary, choose **Chronicle**, select
**Don't optimize**, and confirm. On Android 15 and newer it is **App battery usage**: choose
**Chronicle**, tap **Allow background usage**, and select **Unrestricted**. Return to Chronicle
to check the grant; canceling or leaving optimization enabled does not grant an exemption.
The dialog quotes the labels of the phone's Android version; manufacturers may rename them.

Play and sideloaded builds use the application ID `com.bcm.chronicle`. A build signed with a different key (for example your own sideload over a
Play install) installs only after the old app is removed, which deletes data not yet
uploaded; the participant then enrolls again.

From the dashboard, issue a one-time enrollment link for the participant; the app
exchanges it once and stores the returned per-device API key. Setup generates no
deployment-wide mobile signing key. Details are in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md#mobile-apps).

Mobile apps and TLS trust. The apps validate the server certificate against the device
trust store. If your server's cert chains to a public CA (most institutional and
commercial certs do), nothing extra is needed. In the local HTTPS trial the invitation link
also carries the trial CA root, which Android trusts for that one LAN server; no profile
install is needed for the dashboard's Android link or QR enrollment. iOS accepts the same
CA parameter in a direct `chronicle://enroll` link using the server's LAN IP. The
Play (open) build also trusts CAs the phone owner installed, the fallback for a typed server
address; no build accepts plain HTTP. The research build trusts system CAs only. Android apps trust a
user-installed CA only through a network-security-config that opts in, as the open build does;
iOS without an invitation link: install + enable the CA profile (then it's system-trusted).

### Google Play reviewer access

Play Console needs an access credential that remains usable across review attempts, while
normal participant invitations must stay one-time. Chronicle keeps those roles separate:
the Console credential can call only `POST /chronicle/v4/mobile/reviewer-enrollment`; it
cannot authenticate dashboard, admin, export, or participant-data APIs. Each accepted call
returns a fresh 15-minute one-time enrollment code plus its consent manifest.

Prepare the pinned synthetic scope in the dashboard before enabling the credential:

1. Create a dedicated Play reviewer study whose start/end window includes the review
   period. Complete its participant policy (privacy/withdrawal/support URLs) and save an
   explicit versioned Data Collection setting before enrolling anything. Legacy
   `AndroidSensor`-only studies cannot issue public enrollment manifests.
2. In that study's Participants page, add one synthetic, non-PII participant such as
   `play-reviewer`, then explicitly set its status to `ENROLLED`. The public bootstrap does
   not change researcher-controlled participation state; never point this feature at a real
   participant.
3. Copy the study UUID and synthetic participant ID into the mode-`0600` `.env`:

```ini
CHRONICLE_REVIEWER_STUDY_ID=00000000-0000-0000-0000-000000000000
CHRONICLE_REVIEWER_PARTICIPANT_ID=play-reviewer
```

4. Leave `CHRONICLE_REVIEWER_ACCESS_ENABLED=false`, start the stack, and require
   `./chronicle doctor` to report `reviewer-scope` as `ok`. Configured scope IDs are checked
   even while the public credential is disabled; the doctor checks the live database, not
   just the four environment variables. If review left the participant paused or the study
   outside its dates, restore `ENROLLED` status and active dates in the
   dashboard, then rerun the doctor.
5. Generate and enable the credential without printing it:

```bash
./chronicle rotate-secret reviewer
```

The rotation command repeats the live scope check and refuses to publish a credential for
missing or inactive rows. For a later Play review, keep the same synthetic identity; reset
its dashboard status to `ENROLLED`, confirm the study remains active, run
`./chronicle doctor`, and rotate the reviewer credential for the new Console review window. If a prior
reviewer used destructive withdrawal, the operator must restore/reset this synthetic row
before reuse; the public route never bypasses a pending deletion.

Open `.env` in a trusted local editor and copy `CHRONICLE_REVIEWER_ACCESS_SECRET` directly
into Play Console. Do not place it in an enrollment URL, app storage, Git, logs, screenshots,
or support messages. The endpoint is IP-rate-limited and audited; repeated successful calls
intentionally issue a new one-time code and revoke an outstanding reviewer code. Rotating
the Console credential invalidates the old value immediately, so update Play Console in the
same maintenance window. To disable access, set `CHRONICLE_REVIEWER_ACCESS_ENABLED=false`
and recreate the backend; the route then answers `404`.

`./chronicle verify` exercises this authenticated endpoint when reviewer access is enabled.
That check mints a fresh invitation and replaces the prior outstanding reviewer code. Run
it before giving the reviewer a link, or issue a fresh link afterward.

## Day-2 operations

- Troubleshooting (port in use, wrong bind, expired certificate, disk full, failed
  migration): [docs/MONITORING-RUNBOOK.md#troubleshooting](docs/MONITORING-RUNBOOK.md#troubleshooting)
- Clock: keep the host NTP-synchronized. Signed mobile requests are accepted only
  within a 5-minute window with 30 s of clock skew, and certificate validity and backup
  schedules read the same clock. `./chronicle check` and `up` warn when the host clock is
  not synchronized (`timedatectl`/`chronyc`); fix with `sudo timedatectl set-ntp true`.
- Free disk floor: `./chronicle check` and `up` refuse to start with less than
  `MIN_FREE_DISK_GIB` (default 5) or fewer than 10,000 inodes free on any of the state
  directory, Docker data root and database volume filesystems, because Postgres stops
  hard on a full disk. `./chronicle doctor` fails on the same floor, and also warns when the
  host filesystem or the running database volume has less than 15% free, including when
  monitoring is disabled. `./chronicle update` needs 3 GiB more than the floor on the state and
  Docker filesystems (its safety dump and the staged release) and refuses below that;
  `doctor` and the daily update check warn ahead of time (the daily check also logs to
  syslog) so the space can be freed before the update.
- Converge after a host or daemon restart: Docker does not restart an unhealthy
  container, and a restart after a failed start (for example a full disk) is not retried.
  Production setup installs operator crontab entries at boot and every 15 minutes.
  They run idempotent `./chronicle up` followed by `doctor`, with a private state
  `reconcile.log` and an operator monitoring outcome for each scheduled job.
  They keep a started stack running and never perform the first start: the first setup on
  a host leaves them paused until your first successful `./chronicle up`.
  Disabling reconciliation removes this project's jobs. `./chronicle down` pauses it until a successful manual `up`. Keep cron
  enabled; check `crontab -l` and test a daemon restart before enrolling participants.
- Backups & restore: [docs/BACKUP-RESTORE.md](docs/BACKUP-RESTORE.md)
- Security incident: [docs/INCIDENT-RESPONSE.md](docs/INCIDENT-RESPONSE.md)
- Release availability: `./chronicle update --check` selects the highest published stable version.
  Apply it with `./chronicle update`, or select a published version with `./chronicle update <version>`.
  See [upgrade and rollback](docs/UPGRADE-ROLLBACK.md) for the pre-reset fresh-install boundary.
- Secret rotation and crash recovery:
  [docs/SECRET-ROTATION.md](docs/SECRET-ROTATION.md); guarded dashboard, JWT, internal,
  reviewer, metrics, PostgreSQL, Grafana and TDE procedures with automatic rollback.
  Phones use per-device credentials; deployment-wide mobile signing-key rotation is unsupported.
- Supported deployment combinations:
  [docs/DEPLOYMENT-COMPATIBILITY.md](docs/DEPLOYMENT-COMPATIBILITY.md).
- Participant/study deletion and complete uninstall:
  [docs/UNINSTALL-DATA-DELETION.md](docs/UNINSTALL-DATA-DELETION.md).
- Logs: `docker compose logs -f backend` (or any service).
- Audit trail: structured application events, including authorization denials, are stored
  in the append-only `audit` table together with request audit events. Request events are
  also written, as one JSON object per line for SIEM ingestion, to `audit.log` on the `audit_logs`
  volume (`docker compose exec backend cat /var/log/chronicle/audit.log`). That volume is
  separate from the container log stream, which is capped and rotated. The backend
  refuses to start if the volume is missing or unwritable, so the trail cannot be lost
  silently. Back the volume up alongside `./backups`. Incident evidence must include both
  database tables; see [docs/INCIDENT-RESPONSE.md](docs/INCIDENT-RESPONSE.md).

## At-rest encryption

On by default (`ENABLE_ENCRYPTION=true`), using Percona `pg_tde`, which is already in
the pinned Postgres image; nothing extra to install and no extra deployment step. The key
is generated on first start, by the `db-init` service, and kept on its own Docker volume,
separate from the data. This encrypts table storage; WAL remains plaintext in the
pinned image until server-key setup and restore/rotation recovery are validated.
Use encrypted host storage for the database volume and backups.

What it protects: encrypted table files copied without their keyring.
What it does not protect: anyone with root on the running box. The key is on the box by
design; that is the trade for not having a passphrase you could lose.

### Recovering without the key

Losing the keyring makes encrypted table storage permanently unreadable. The backups cover this:

- **The dumps in `./backups` need no key.** They are plain SQL, and the guarded restore
  loads them onto fresh volumes with a new keyring
  ([recover onto a fresh host](docs/BACKUP-RESTORE.md#recover-onto-a-fresh-host)).

  Do not replay a dump by hand with psql. Dumps leave out `pgcrypto` and `pg_tde`, so a
  replay into another PostgreSQL can miss tables and functions, and a replay into a database
  that still has the schema skips every `CREATE` and then appends every `COPY`, so tables
  without a primary key end up holding each row twice while psql still exits 0. Use the guarded
  `./chronicle restore --trusted-sha256=...` command only after independently reviewing the
  dump source and digest. The command verifies them before stopping application writers and
  dropping the schema. A `.sha256` sidecar shipped beside the dump is not independent
  provenance. See
  [docs/BACKUP-RESTORE.md](docs/BACKUP-RESTORE.md).
- Startup refuses `ENABLE_ENCRYPTION=true` without `overlays/backups.yml`, because that
  combination would create encrypted data with no key-free copy of it. `config-guard` fails
  and nothing else starts.
- A copy of the keyring is placed in `./backups/keyring` so the backup set is
  self-contained and the volume itself can be remounted, not just rebuilt from SQL.
- `./chronicle verify` checks all three: every table encrypted, a keyring copy present,
  and a key-free dump present.
- Online key rotation is guarded. `./chronicle rotate-secret tde` takes a verified
  pre-rotation SQL dump, activates a new principal key, proves the table/key state, refreshes
  the keyring copy atomically, and leaves restart-safe recovery metadata until completion.

So: back up `./backups` as a single unit and keep it somewhere the data volume isn't.
That directory is `0700` and owned by the account that deployed the stack, so other local
users cannot read the dumps.

Also:

- Every table is encrypted from creation, not converted afterwards. `db-init` runs before
  the backend and sets the database default access method to `tde_heap`, so the tables
  Flyway creates on that first boot and on later migrations are born encrypted.
- Query parallelism is disabled cluster-wide (`max_parallel_workers_per_gather=0`). A
  parallel scan over an encrypted table crashes Postgres. After migrating to a plain
  database with `ENABLE_ENCRYPTION=false`, you can raise it again.

For a fresh plain database, set `ENABLE_ENCRYPTION=false` and use full-disk/volume
encryption at the OS level (LUKS, or your cloud provider's disk encryption).
On an existing encrypted installation, changing the flag does not decrypt tables or
reset the database's `tde_heap` default; startup refuses that mismatch. Keep it `true`
until completing the [TDE-to-plain database migration](docs/BACKUP-RESTORE.md#tde-to-plain-database-migration).

## Security updates

- How you learn of a fix: watch the public repository on GitHub (Watch -> Custom ->
  Releases and Security advisories). Security fixes ship only as new releases; their
  `CHANGELOG.md` entry has a `### Security` heading. For release bundles, automatic
  reconciliation installs a daily update check at 06:00. Availability and failures reach
  operator receipts, metrics and Grafana alerts, with details in the private
  state `reconcile.update.log`. `./chronicle update --check` exits `0` when current,
  `3` when a newer release exists, and any other status indicates a check failure.
  It refuses a superseded bundle. If reconciliation is disabled, schedule the check
  from the active bundle and alert on both `3` and failure statuses.
- Applying a fix: run `./chronicle update` from the directory you installed. It verifies the
  signed release, preserves data, and automatically rolls back failed verification. Apply critical fixes within 48 hours of publication, high-severity fixes within
  7 days, medium-severity fixes within 30 days, and low-severity fixes within 90 days.
  Record the advisory, deadline, installed version and verification evidence in the
  controlled operations register. If a deadline cannot be met, record the approver,
  temporary containment and revised date. Source installations update to the fixed
  default-branch revision and exact gitlinks; release installations update to the latest
  fixed release. Only pre-reset installations require fresh volumes.
- If you think you were affected: follow [docs/INCIDENT-RESPONSE.md](docs/INCIDENT-RESPONSE.md).

## Support

Only the latest post-reset release receives security and bug fixes. Update older post-reset
installations in place with `./chronicle update`; pre-reset installations require a fresh install.

- Install the reset baseline fresh with a new database and app install. Pre-reset releases
  and backups cannot cross this reset. Starting with this release, updates preserve all data in place.
  Restore backups into the same or a newer post-reset release. Security fixes ship in new releases; check with
  `./chronicle update --check`.
- Bugs: open an issue on the public repository's GitHub issue tracker. Include
  `./chronicle doctor --json` output; it contains no secrets.
- Vulnerabilities: report privately as described in `SECURITY.md` at the bundle root.
  Do not open a public issue.
- Out of scope: see [docs/DEPLOYMENT-COMPATIBILITY.md](docs/DEPLOYMENT-COMPATIBILITY.md).

## FAQ

Which database? Use the pinned Percona PostgreSQL 18 image from `.env.example`. The
Compose service preloads `pg_tde` in every mode, including when `ENABLE_ENCRYPTION=false`;
stock `postgres:18` is not a supported replacement.

I already run an older release. For a post-reset release, run `./chronicle update`; configuration,
volumes and data stay in place. For 2026.10.9 and earlier, install fresh with fresh volumes.
See [upgrade and rollback](docs/UPGRADE-ROLLBACK.md). Guarded restore accepts a reviewed backup
from the same or an older post-reset release and refuses newer-release or pre-reset backups.

Which languages does the Time Use Diary support? English, Spanish, German, Swedish and
Hebrew. The diary is fully translated; every string the diary asks for exists in each of
those languages, and participants get a language picker on the form itself. You can also fix
the language per study (the study's `language` setting) or per link by appending `&lang=es`
to a diary link. Hebrew additionally takes `&gender=male|female`, because the questions are
gendered in Hebrew.

The researcher dashboard and the daily app-usage survey are also available in Spanish: a
browser set to Spanish shows them in Spanish, any other browser in English. Questionnaire and study
text you write yourself is whatever language you type it in, so participant-facing content is
not limited to English even where the surrounding buttons are.

### Sizing

Measured at idle (one study, no devices enrolled): backend ~0.9 GB, Postgres ~0.1 GB,
Caddy ~40 MB, backup sidecar ~30 MB → ~1.1 GB resident.

Configured ceilings are much higher, and they sum to more than a 4 GB box has:

| Setting | Default |
|---|---|
| `BACKEND_MEM_LIMIT` | 3 GB |
| `POSTGRES_MEM_LIMIT` | 2 GB |
| `BACKUP_MEM_LIMIT` | 512 MB |
| `WEB_MEM_LIMIT` | 256 MB |
| total | 5.75 GB |

Setup budgets the selected service ceilings plus 512 MiB of host headroom before
publishing settings. The 4 GiB profile uses a 1.5 GiB backend/1 GiB heap, 1 GiB
PostgreSQL, 256 MiB backup, and 128 MiB Caddy. Monitoring defaults
off below 10 GiB and adds its exporters, receivers, Grafana, and one-shot helpers to the
same check. Limits are ceilings; these checks do not replace workload qualification.

Disk sizing must cover the actual Docker data-root, PostgreSQL volume, and state device.
`check` requires a 5 GiB byte reserve and 10,000 free inodes. Budget downloads, extraction,
and image pulls separately when preparing a fresh installation. PostgreSQL `max_wal_size=2GB` is a soft target;
`max_slot_wal_keep_size=4GB` bounds replication-slot retention. Doctor warns when
`pg_wal` exceeds twice the configured WAL target.

Backup verification needs additional scratch space equal to twice the larger of the live
database size and uncompressed dump size. Setup, check and doctor project retention from the
newest dump size and the daily/weekly/monthly counts chosen at setup, including the latest
copy, and warn when that would not fit above `MIN_FREE_DISK_GIB`. Each retained copy costs
about one compressed dump. Compression varies; size from measured dumps and ingestion growth.
Monitoring adds its separate metrics/log budgets (5 GiB each by default). Reserve space
for container logs as well. Twenty GiB before study data is only a starting
estimate, not a sustainable retention guarantee.

| Scenario | Suggested |
|---|---|
| Pilot, a few devices | 2 vCPU / 4 GB, with the limits above reduced to fit |
| Comfortable, small study | 4 vCPU / 8 GB (stock limits fit) |
| Sensor-heavy (high-rate accelerometer) or many devices | scale disk first, then RAM |

CPU load is driven by ingest rate. Disk is the variable to plan around, and it is
dominated almost entirely by whether hardware sensors are on.

If you give the box more RAM, raise the database settings with it. Every container is
capped (`POSTGRES_MEM_LIMIT`, `BACKEND_MEM_LIMIT`, `WEB_MEM_LIMIT`, `BACKUP_MEM_LIMIT`),
and Postgres is tuned to the 2 GB default; `POSTGRES_SHARED_BUFFERS=512MB` at ~25% and
`POSTGRES_EFFECTIVE_CACHE_SIZE=1536MB` at ~75%. Raising only `POSTGRES_MEM_LIMIT` leaves
the extra memory unused, because Postgres' own defaults are far smaller than either value.
Keep `shared_buffers + (max_connections × work_mem) + maintenance_work_mem` under the
limit, or the kernel OOM-kills the database rather than Postgres returning an error. The
JVM heap is separate: `BACKEND_XMX` must stay below `BACKEND_MEM_LIMIT`.

The request body ceiling is generated from `MAX_REQUEST_SIZE_BYTES` in
[`ontology/chronicle.linkml.yaml`](../ontology/chronicle.linkml.yaml). Android measures the
final sealed JSON bytes and retries smaller batches after transport timeouts or body-deadline failures.
The server caches whole bodies before parsing JSON. Include concurrent uploads when
sizing the JVM heap. See [upload deadlines](docs/CONFIGURATION.md#upload-body-deadlines).

Two defaults assume SSD/NVMe; `POSTGRES_RANDOM_PAGE_COST=1.1` and
`POSTGRES_EFFECTIVE_IO_CONCURRENCY=200`. On spinning disks set them to `4` and `2`, or the
planner will pick index scans that cost more than a sequential read.

Query parallelism is off (`max_parallel_workers_per_gather=0`) because a parallel scan over
an encrypted table crashes Postgres. Leave it off unless `ENABLE_ENCRYPTION=false`.

Container logs are capped at `LOG_MAX_SIZE=10m` × `LOG_MAX_FILES=5` per service. Docker
does not rotate logs by default, so removing these lets a chatty service fill the disk.

Measured on a test deployment (Android phones + tablets, on-disk including
indexes):

| Module set | Per device per day |
|---|---|
| Usage events only (no hardware sensors) | < 1 MB; ~200 rows/device/day |
| Hardware sensors at default rate | ~23 MB; ~63,000 rows/device/day |
| Hardware sensors, heaviest observed day | ~220 MB; ~570,000 rows/device/day |

Ten devices with continuous accelerometer use roughly 7 GB/month. Sampling rate and
duty cycle are per-study settings in the dashboard.

### Container limits

Every container has a CPU ceiling, a memory ceiling and a process (pid) limit. The CPU
ceiling is a CFS quota (`cpu_period`/`cpu_quota`), not `cpus`: Docker refuses `cpus` above
the host's CPU count when it creates the container, so `cpus: 4` would stop a 2-vCPU pilot
host, while a quota is accepted on any host and still binds on a large one. Thread pools
follow the ceiling, not the host: the JVM reads the quota (4 processors for the backend),
Go services set `GOMAXPROCS` to their ceiling, and HAProxy runs `nbthread 2`. Without that,
a 32-CPU host started one thread per host CPU in each of them and ran into the pid limits.

The pid column is the limit; the measured column is the highest count seen on a 32-CPU host
over 90 seconds of concurrent requests to the participant, internal and Grafana listeners
(`docker stats`, every 2 s), with the default mode and the backup and monitoring overlays.
Each limit is at least twice that peak. The one-shot jobs (config, certificate, secret and
database setup, migrations, restore) have the same kind of ceilings and are not listed.

| Service | CPUs | Memory | Pids | Measured peak |
|---|---|---|---|---|
| `backend` | 4 | `BACKEND_MEM_LIMIT` (3 GB) | 1024 | 187 |
| `postgres` | 4 | `POSTGRES_MEM_LIMIT` (2 GB) | 512 | 29 |
| `web` | 2 | `WEB_MEM_LIMIT` (256 MB) | 256 | 10 |
| `web-forward` | 2 | 64 MB | 64 | 5 |
| `db-backup` | 2 | `BACKUP_MEM_LIMIT` (512 MB) | 128 | 7 |
| `grafana` | 2 | `GRAFANA_MEM_LIMIT` (512 MB) | 512 | 28 |
| `victoriametrics` | 2 | `VICTORIAMETRICS_MEM_LIMIT` (512 MB) | 256 | 13 |
| `victorialogs` | 2 | `VICTORIALOGS_MEM_LIMIT` (512 MB) | 256 | 23 |
| `monitoring-forward` | 2 | 64 MB | 64 | 5 |
| `cadvisor` | 1 | `CADVISOR_MEM_LIMIT` (256 MB) | 256 | 21 |
| `fluent-bit` | 1 | `FLUENT_BIT_MEM_LIMIT` (128 MB) | 128 | 6 |
| `operational-probe` | 1 | `OPERATIONAL_PROBE_MEM_LIMIT` (192 MB) | 128 | 2 |
| `metrics-exporter` | 1 | 64 MB | 64 | 6 |
| `docker-socket-proxy` | 1 | 64 MB | 64 | 3 |
| `public-probe` | 1 | 64 MB | 64 | 2 |
| `egress-proxy` | 1 | 64 MB | 32 | 3 |

PostgreSQL starts one process per connection, so its pid limit also bounds connections;
keep `max_connections` well under 512 if you raise it.

### Scale in this order

1. Add disk when the Database and Storage dashboard shows capacity or predicted-growth
   pressure.
2. Add RAM for sustained PostgreSQL/backend memory or connection pressure; add CPU for
   measured ingestion saturation after ruling out disk I/O.
3. Tune the documented container, PostgreSQL and JVM values together and compare the same
   dashboard window before and after.
4. There is no multi-node or high-availability mode.

### Operator overrides

The bundle normally uses GitHub's signed release catalog, the host's memory probe, and
the configured Caddy image when hashing a dashboard password. Process-environment
overrides are unset by default: `CHRONICLE_RELEASES_URL` selects an HTTP(S) catalog that is
tried before GitHub (downloaded releases still require the installed signing key), `CHRONICLE_MEMINFO`
selects a Linux-format meminfo file for sizing fixtures, and `CADDY_SETUP_HASH_IMAGE`
selects the password-hash helper image. That image receives the dashboard password on
stdin; use only a trusted, digest-pinned Caddy image. These overrides are read from the
operator process environment, not deployment `.env` settings.
