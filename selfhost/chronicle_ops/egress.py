"""Which containers may open connections beyond the host, decided from settings at every Compose call.

Only public-probe always may. Grafana may only while the alert webhook points somewhere off this
host: CHRONICLE_ALERT_EGRESS selects monitoring/docker-compose.grafana-alerts-<value>.yml through `extends`, and
every Compose entry point (the launcher's need_env and release_command) derives it from .env, so
the operator never sets it. .env carries the derived value as well (setup, the update's settings
migration and every launcher run write it), so a plain `docker compose` renders the same networks.

The host itself reaches a fixed list of destinations (HOST_DESTINATIONS); `./chronicle update
--check` names the first one it cannot reach before anything waits on a retry.
"""
import ipaddress
import os
import subprocess
from urllib.parse import urlsplit

ALERT_EGRESS_ENV = "CHRONICLE_ALERT_EGRESS"
CLOSED, OPEN = "closed", "open"
# Same default as monitoring.yml: the closed discard port on loopback, alerts stay in Grafana.
DEFAULT_ALERT_WEBHOOK = "http://127.0.0.1:9/dashboard-only"
# Containers that publish ports cannot be on an internal network. Their Docker resolver is pointed
# at TEST-NET-1 (RFC 5737), which nothing answers, so external names never resolve: Compose
# service names are still answered by Docker's embedded resolver itself.
BLACKHOLE_RESOLVER = "192.0.2.53"


def webhook_host(url):
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def is_local(host):
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def alert_egress_for_url(url):
    """OPEN when the alert webhook URL names a host other than this container's loopback."""
    host = webhook_host(url.strip() or DEFAULT_ALERT_WEBHOOK)
    return OPEN if host and not is_local(host) else CLOSED


def alert_egress(settings):
    from .envfile import value
    return alert_egress_for_url(value(settings, "CHRONICLE_ALERT_WEBHOOK_URL"))


def sync_env_file(path=".env"):
    """CHRONICLE_ALERT_EGRESS as .env must hold it, written there when it differs.

    The value is derived from CHRONICLE_ALERT_WEBHOOK_URL, never configured. A stale or missing
    copy in .env is rewritten and reported; an .env this cannot rewrite keeps its copy, which is
    reported, and the caller still exports the derived value for its own Compose calls."""
    from pathlib import Path
    from .common import warn
    from .envfile import read_env, set_env_values, value
    from .receipts import write_text
    path = Path(path)
    derived = environment_alert_egress(path)
    if not path.is_file() or path.is_symlink():
        return derived
    try:
        recorded = value(read_env(path), ALERT_EGRESS_ENV)
        if recorded == derived:
            return derived
        write_text(path, set_env_values(path.read_text(encoding="utf-8"), {ALERT_EGRESS_ENV: derived},
                                        require_existing=False))
    except (OSError, ValueError) as error:
        warn(f"{path} disagrees with CHRONICLE_ALERT_WEBHOOK_URL about {ALERT_EGRESS_ENV} and could not be "
             f"rewritten ({error}); this run uses {derived}, a plain `docker compose` the value in {path}")
        return derived
    warn(f"{path} had {ALERT_EGRESS_ENV}={recorded or '(unset)'}, which CHRONICLE_ALERT_WEBHOOK_URL does not give; "
         f"it now has {derived} (the value is derived from the webhook URL, not a setting)")
    return derived


def environment_alert_egress(path=".env"):
    """The release commands' view: .env as Compose reads it.

    An .env this parser cannot read leaves Grafana without a route out and says so: alerts then
    stay in the dashboard, which loses nothing, while refusing would stop an update."""
    from pathlib import Path
    from .common import warn
    from .envfile import read_env
    path = Path(path)
    try:
        return alert_egress(read_env(path) if path.is_file() else {})
    except (OSError, ValueError) as error:
        warn(f"could not read CHRONICLE_ALERT_WEBHOOK_URL from {path} ({error}); "
             "Grafana gets no route out, so alerts stay in the dashboard")
        return CLOSED


# Every host the deployment's own commands connect to, all from the host and never from a
# container (docs/NETWORK-EGRESS.md, "Host destinations"). update.py's curl reaches the release
# catalog and assets through the operator's proxy; the Docker daemon pulls the images with its own.
HOST_DESTINATIONS = (
    ("api.github.com", "release catalog (GitHub REST API)"),
    ("github.com", "release feed, and the release asset URLs before their redirect"),
    ("release-assets.githubusercontent.com", "release assets after GitHub's redirect"),
    ("objects.githubusercontent.com", "release assets after GitHub's older redirect"),
    ("ghcr.io", "Chronicle's release images and cAdvisor"),
    ("pkg-containers.githubusercontent.com", "ghcr.io image layers"),
    ("registry-1.docker.io", "docker-socket-proxy, VictoriaMetrics and VictoriaLogs images"),
    ("auth.docker.io", "Docker Hub pull tokens"),
    ("production.cloudflare.docker.com", "Docker Hub image layers"),
)


def first_unreachable(destinations=None, seconds=10):
    """(host, purpose, curl exit) for the first destination one HTTPS request cannot reach, else None.

    Any HTTP answer, an error status included, means the network path works. One attempt each,
    bounded by `seconds` to connect; curl honours https_proxy and no_proxy as update.py's does.
    CHRONICLE_RELEASES_URL, when set, is checked first, as the update reads it first."""
    default = destinations is None
    destinations = list(HOST_DESTINATIONS if default else destinations)
    configured = urlsplit(os.environ.get("CHRONICLE_RELEASES_URL", "")).hostname
    if configured and default:
        destinations.insert(0, (configured, "CHRONICLE_RELEASES_URL"))
    for host, purpose in destinations:
        result = subprocess.run(
            ["curl", "--silent", "--output", "/dev/null", "--proto", "=https",
             "--connect-timeout", str(seconds), "--max-time", str(seconds * 2), f"https://{host}/"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if result.returncode != 0:
            return host, purpose, result.returncode
    return None


def report_first_unreachable():
    """Warn about the first unreachable host destination; True when every one answered."""
    from .common import warn
    unreachable = first_unreachable()
    if unreachable:
        host, purpose, code = unreachable
        warn(f"cannot reach https://{host}/ (curl exit {code}), needed for {purpose}; an update needs "
             "every host in docs/NETWORK-EGRESS.md, \"Host destinations\". Check DNS, the firewall and "
             "https_proxy before running ./chronicle update")
    return unreachable is None

