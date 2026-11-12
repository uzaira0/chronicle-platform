# Network egress: what can leave the host

A self-host deployment holds participant data. If a dependency inside one of its containers
were hijacked, the damage it can do depends on where that container can send data. From
2026.11.12 every container that holds data or a credential sits only on internal networks: it
has no default route, so it cannot open a connection off the host, and it cannot resolve an
external name. The two things that must reach the internet go through one allowlisting proxy
that tunnels only to the hosts your own settings name. `./chronicle update` applies this
itself; there is nothing to configure, and a rollback restores the previous release's networks
with its Compose files.

## The networks

| Network | Internal | Who is on it | Why |
|---|---|---|---|
| `core` | yes | web, backend | Caddy to the backend. Docker gives an internal network no gateway, so nothing on it has a route off the host, and its resolver answers only Compose service names. |
| `database` | yes | postgres, backend, db-backup, db-init, migrate, restore | The database's users and nothing else. Web, the TLS edge that parses every request, cannot open `postgres:5432`. |
| `ingress` | yes | web-forward, web | The published ports' path into Caddy. |
| `default` | no | web-forward only | Published ports need a bridge Docker connects to the host. web-forward holds no data, credential or volume (below). The bridge is not masqueraded, as a second layer. |
| `database-probe` | yes | postgres, operational-probe | The probe's read-only database checks. |
| `monitoring` | yes | VictoriaMetrics, VictoriaLogs, cAdvisor, fluent-bit, Grafana, operational-probe, the exporter, web (scraped) | Metrics and logs stay on the host. |
| `monitoring-ingress` | yes | monitoring-forward, Grafana, fluent-bit | The published loopback ports' path to Grafana's dashboard and fluent-bit's log forward. |
| `monitoring-ports` | no | monitoring-forward only | The bridge for those loopback ports. Not masqueraded. |
| `docker-api` | yes | docker-socket-proxy, cAdvisor | The read-only Docker API. |
| `egress-clients` | yes | egress-proxy, public-probe; Grafana only when the alert webhook is off this host | The clients' only path out: to egress-proxy, which they reach by name. |
| `egress` | no | egress-proxy only | The one network with a route out (below). |

The one-shot jobs that only write files (config-guard, cert-init, caddy-storage-init,
secrets-init, monitoring-cert-init, monitoring-config, and ca-export in local-HTTPS mode) run
with `network_mode: none`. The one-shot jobs mount only the bundle files they read, read-only,
never the bundle directory: `.env` reaches none of them (config-guard, db-init, restore and
ca-export each list theirs in `docker-compose.yml`; a test follows every file each script
sources or names and fails if one is missing or if a job mounts the directory).

### The egress proxy

`egress-proxy` runs `chronicle-forward -connect 3128`, an HTTP CONNECT proxy in the same
standard-library Go binary as the forwarders. It tunnels only to the `host:port` pairs in
`/egress/allow`, which monitoring-config writes on every `up` from `.env`:

- the host and port of `PUBLIC_TLS_URL` and `PUBLIC_HEALTH_URL` when they are `https://`;
- the host of `CHRONICLE_ALERT_WEBHOOK_URL` when it is `https://` and off this host.

Any other target gets `403` before a name is resolved or a connection opened, and any method
but CONNECT gets `405`, so it is not a plain-HTTP forwarder either. The proxy holds no
credential, data or volume except its read-only allowlist, runs read-only as an unprivileged
user with every capability dropped, and logs each refusal. Its clients set `HTTPS_PROXY`
(curl, Grafana's webhook client, which honours the proxy environment) or pass `-proxy`
(`openssl s_client`, for the certificate check), and they cannot go around it: they sit only on
internal networks and resolve external names nowhere. A webhook URL that is plain `http://` or
carries credentials is not added (monitoring-config warns without printing it), and setup and
`guard-config.sh` refuse a plain-HTTP webhook off this host.

### The port forwarders

`masquerade off` alone is not isolation: a host or upstream router that routes the bridge's
private subnet would carry the traffic, and the container still has a default route. So no
service that holds data or a credential joins a network with a gateway. Two forwarders do:

- **web-forward** publishes web's ports (8080/8081 behind a proxy; 443, 80 and 8081 in the
  other modes) and copies each connection to web over `ingress`.
- **monitoring-forward** publishes Grafana's dashboard and fluent-bit's log port on loopback
  and copies each connection over `monitoring-ingress`.

Both run `chronicle-forward`, a TCP copier built from the Go standard library alone into the
Caddy image (`caddy/forward/`, built and tested in `Dockerfile.caddy`, which fails the build
if the binary links any module). They mount no volume, receive no credential, run read-only as
an unprivileged user with every capability dropped, and resolve external names nowhere. A
hijacked forwarder can see the TLS bytes passing through it, as any router on the path can, and
nothing else.

web-forward prefixes each connection to web with a PROXY protocol v2 header carrying the
client address. Caddy accepts that header only from web-forward's fixed address (`X.130`, see
below) and ignores one from anywhere else, so the access log and the backend's
`X-Forwarded-For` still show the real client and no other container can forge one.

### Web

In every mode web is on `core`, `ingress` and `monitoring` only and uses the blackhole
resolver: the container that holds the TLS key and sees decrypted traffic has no route out.
Caddy therefore staples no OCSP response (`ocsp_stapling off` in `Caddyfile.split.tls`); it
could not fetch one. Clients check revocation themselves, as they do for any server that does
not staple; since CA/Browser Forum ballot SC-063 (2024) OCSP is optional for CAs and CRLs are
required, and browsers use their own revocation lists. A certificate with the OCSP Must-Staple
extension (RFC 7633) needs a stapled response, and browsers that enforce it (Firefox) refuse
the site without one, so request a certificate without it, or terminate TLS on your own proxy
(`behind-proxy`).

### DNS

Every service that has a network but no reason to resolve external names sets
`dns: ["192.0.2.53"]` (one YAML anchor per file, `x-no-external-dns`). That address is in
TEST-NET-1 (RFC 5737), which nothing answers; Docker's embedded resolver still answers
Compose service names itself. Docker Engine before 25.0.5 forwarded external queries from
internal networks to the host's resolver (CVE-2024-29018), which a lookup can leak data
through; the blackhole resolver closes that on every engine.

### Enforced by

`chronicle_ops/services.py` owns the lists: the internal networks, the services allowed on a
network with a way out (web-forward, monitoring-forward and egress-proxy, each with its
reason), and the two services allowed to hold a credential in their environment.
`./chronicle verify` and `verify-config.sh` check the Compose files against it, and
`scripts/generate-egress-rego.py` writes the conftest data
(`tests/security/policies/egress_services.rego`, checked for drift with `--check`) that
`docker_compose.rego` reads. That policy also refuses a credential substituted from `.env`
into any other service's configuration.

## Addresses

`CHRONICLE_SUBNET` is the `default` network, as before. `CHRONICLE_CORE_PREFIX` (three octets,
e.g. `10.252.0`) is one /24, and `network-subnet.py` owns it and everything derived from it
(`core_layout`): `core` is `X.0/25` (Docker assigns from `X.64/26`), `ingress` is `X.128/26`
(Docker assigns from `X.160/27`), `database` is `X.192/26`, web holds `X.2` on core and web-forward `X.130` on ingress,
both outside the ranges Docker assigns from, so no other container can take either. The backend
trusts `X-Forwarded-For` only from `X.2` (`CHRONICLE_TRUSTED_PROXY_CIDRS`) and Caddy accepts a
PROXY protocol header only from `X.130`. `docker-compose.yml` spells these by interpolating the
prefix, which it requires (there is no default); a test renders it and compares it with
`core_layout`.

Setup and update pick a prefix whose whole /24 overlaps no Docker network, host route or
`CHRONICLE_SUBNET` (`network-subnet.py select-core`), so both derived subnets are clear; an
existing value is never moved. If the host's network table cannot be read, the update falls back
to the first /24 of the range and warns. `./chronicle up` warns when a derived subnet
overlaps something, and `./chronicle verify` compares the running `core` and `ingress` subnets
and web's and web-forward's addresses with what the prefix in `.env` derives.

## What still goes out, and why

Both go through egress-proxy, to the hosts its allowlist names.

- **public-probe** fetches `https://DOMAIN/health` and reads the served certificate, as an
  outside client would. It holds no password, no key and no data volume; operational-probe
  hands it only a copy of the public CA certificate.
- **Grafana** joins `egress-clients` only when `CHRONICLE_ALERT_WEBHOOK_URL` names a host other
  than this one (`chronicle_ops/egress.py`), and sends the alert through the proxy. `CHRONICLE_ALERT_EGRESS` records that decision in
  `.env` (`open` or `closed`); it is derived, not a setting: setup and `./chronicle update`
  write it, and every `./chronicle` run rewrites a value that no longer matches the webhook URL
  and says so. A plain `docker compose` therefore gives Grafana the same networks. Grafana's
  plugin preinstall and news feed are off either way.
- **Study webhooks are off.** The backend has no route out, so registering a webhook is
  refused with that reason (409) and no delivery is attempted (`chronicle.yaml`,
  `webhooks.enabled: false`). A study that needs webhooks needs a deliberate change to this
  design.

## Host destinations

The containers above are not the only thing that connects out: the host itself does, for
updates. If a firewall or proxy sits between the host and the internet, allow HTTPS (443) to:

| Host | Used by | For |
|---|---|---|
| `api.github.com` | `./chronicle update` (curl) | the release catalog |
| `github.com` | `./chronicle update` (curl) | the release feed, and release asset URLs before their redirect |
| `release-assets.githubusercontent.com` | `./chronicle update` (curl) | release assets after GitHub's redirect |
| `objects.githubusercontent.com` | `./chronicle update` (curl) | release assets after GitHub's older redirect |
| `ghcr.io` | Docker (image pull) | Chronicle's release images and cAdvisor |
| `pkg-containers.githubusercontent.com` | Docker (image pull) | `ghcr.io` image layers |
| `registry-1.docker.io` | Docker (image pull) | docker-socket-proxy, VictoriaMetrics and VictoriaLogs (monitoring overlay) |
| `auth.docker.io` | Docker (image pull) | Docker Hub pull tokens |
| `production.cloudflare.docker.com` | Docker (image pull) | Docker Hub image layers |

`./chronicle update` uses curl, which honours `https_proxy` and `no_proxy`; Docker pulls with
the daemon's own proxy settings. `CHRONICLE_RELEASES_URL`, when set, adds its host.
`./chronicle update --check` tries each host once (any HTTP answer counts) and names the first
one it cannot reach before it waits on any retry. The list lives in
`chronicle_ops/egress.py` (`HOST_DESTINATIONS`).

## Credentials

No container except the two that copy them from `.env` holds a credential in its Compose
configuration, so `docker inspect` of every other container shows none. `secrets-init`
(one-shot, no network) writes them on every `up` into one volume per consumer:

| Volume | Read by | Files |
|---|---|---|
| `postgres_secrets` | postgres | postgres-password |
| `backend_secrets` | backend | the database, JWT, metrics, web-marker and reviewer secrets |
| `web_secrets` | web | internal-web-secret (the web-marker secret) |
| `operator_secrets` | db-backup, operational-probe, restore | postgres-password |
| `database_init_secrets` | db-init | postgres-password, postgres-app-password |
| `migrate_secrets` | migrate | postgres-password |
| `guard_secrets` | config-guard | every credential it validates |

monitoring-config (one-shot, no network) writes Grafana's. The bash one-shots read their files
with `secret-files.sh`; the backend and migrate with `backend-entrypoint.sh`. config-guard
runs after secrets-init, so it validates exactly what the services will read; `./chronicle
check` and the update's preflight run secrets-init before it. When a value changes, Compose
restarts the long-running consumers (`depends_on: restart: true`); the launcher's `rotate-secret`
reruns `secrets-init` before it recreates services. Web's entrypoint reads its file and exports
the value only into Caddy's own process, which substitutes it when it loads the Caddyfile; the
container's configuration does not hold it.

Who can still read a credential:

- secrets-init's and monitoring-config's configurations hold the values they copy (those two
  containers exit after writing). Anyone who can use the Docker API (root, and members of the
  `docker` group) can read them with `docker inspect`, as they can read `.env`, the volumes and
  every container's memory. Treat Docker API access as root on this host.
- Grafana's configuration holds `CHRONICLE_ALERT_WEBHOOK_URL`, which may carry a token in its
  path; the same Docker API users can read it.
- No container can: cAdvisor no longer mounts Docker's storage directory (where each
  container's configuration is kept), and the socket proxy blanks `Env`.

The Docker socket proxy blanks `Env` in every container inspect it returns
(`monitoring/docker-api-strip-env.lua`); cAdvisor does not use it. A response it cannot strip
is refused (502), not passed through.

## Image listeners

`scripts/check-image-no-ssh-server.sh` finds an SSH server by its file name, which a Go or Rust
binary embedding one does not have. `scripts/check-image-listeners.sh` therefore starts every
image Chronicle builds as it ships, on `--network none`, reads `/proc/net/tcp` and
`/proc/net/tcp6` in its namespace for 20 seconds, and fails on a listening socket bound to a
non-loopback address on a port the image does not declare with `EXPOSE`. `publish-images.sh`
and `local-ci.sh` run it on every image before anything is pushed.

## Limits

- web-forward and monitoring-forward have a default route, as any container with a published
  port must. They hold nothing worth sending, and neither can resolve an external name.
- egress-proxy reaches the allowlisted hosts, so a hijacked public-probe or Grafana can send to
  those hosts and no other; neither holds participant data.
- cAdvisor runs unprivileged and mounts `/sys`, the host's `/proc`, Docker's layer-id files
  and the backups directory (for free space). It cannot read container configurations, volumes
  or the host root, so it reports host and backups filesystem usage but not each container's
  disk usage.
- fluent-bit's forward input (Docker's `fluentd` log driver delivers every container's log
  lines to it) is published on `127.0.0.1` only and has no authentication: Docker's driver
  cannot send a shared key or TLS. Any process on this host can therefore write records into
  VictoriaLogs; it cannot read them back through that port. Treat VictoriaLogs content as
  host-local input, not as authenticated evidence: the backend's audit table and log files
  (collected in [INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md)) are the record.
- The host itself, and anything you run on it outside this project, is not covered. Docker's
  published-port rules run before UFW and firewalld; see "Host firewalls and published ports"
  in the README.

## Checking a running deployment

`tests/security/selfhost-egress.sh PROJECT` probes a running project from inside each
container's network namespace and prints the Docker Engine and kernel versions it ran on. It
first proves its probes work: from Docker's default bridge, TCP to 1.1.1.1:443 and
`getent hosts example.com` must succeed, or the run fails. Then, for each running service,
either every network it is on is internal and it has no IPv4 or IPv6 default route, no TCP
connection out and no external DNS answer, or the service is one `services.py` lists with a
reason. A probe that cannot run fails the check rather than counting as blocked. It also
checks that egress-proxy refuses a host outside its allowlist and prints the allowlist, that web
cannot connect to `postgres:5432`, that the internal paths and scrapes work, logs reach
VictoriaLogs, the socket proxy strips `Env`, and no container's configuration other than
secrets-init's and monitoring-config's holds a credential.

Last run: Docker Engine 29.8.2, kernel 7.2.9 (OrbStack), behind-proxy mode with the backups and
monitoring overlays, the alert webhook both on this host and off it (Grafana then sent a test
alert to `example.org` through egress-proxy and got that host's HTTP answer): 81 checks passed,
none failed.
