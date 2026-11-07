"""Firing Grafana alerts, read from the host: the zero-configuration alert receiver (PR-O3, PR-O11).

With no CHRONICLE_ALERT_WEBHOOK_URL, Grafana's contact point delivers to a discard port, so alerts
reached no one. The host can still read them: Grafana's Alertmanager API lists every alert that is
firing, over the loopback listener ./chronicle monitoring status already uses. The scheduled doctor
(reconcile.sh, every 15 minutes) writes each to the system log with `logger`, the path reconcile
already uses for its own failures; doctor and status list them. No container gains a route out.
"""

import base64
import datetime
import json
import os
import ssl
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import NamedTuple

from .envfile import read_env, value
from .receipts import write_json

# Set by reconcile.sh on its doctor run only; an operator's own doctor never writes to syslog.
SYSLOG_ENV = "CHRONICLE_ALERT_SYSLOG"
SYSLOG_RECORD = "alert-syslog.json"
# Grafana's notification policy repeats a firing alert every 24 h (grafana-alerting/notification-policies.yml).
REPEAT = datetime.timedelta(hours=24)
ALERTS_PATH = "/api/alertmanager/grafana/api/v2/alerts?active=true&silenced=false&inhibited=false"
TIMEOUT_SECONDS = 8


class Alert(NamedTuple):
    fingerprint: str
    name: str
    severity: str
    summary: str


def firing(rows):
    """The active alerts in an Alertmanager v2 /alerts response, sorted by name."""
    found = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or (row.get("status") or {}).get("state") != "active":
            continue
        labels, annotations = row.get("labels") or {}, row.get("annotations") or {}
        found.append(Alert(str(row.get("fingerprint", "")), str(labels.get("alertname", "unnamed")),
                           str(labels.get("severity", "unknown")), " ".join(str(annotations.get("summary", "")).split())))
    return sorted(found, key=lambda alert: (alert.name, alert.fingerprint))


def grafana_base(settings):
    """The private listener, as network-policy.sh grafana_base_url builds it."""
    host = value(settings, "GRAFANA_BIND", "127.0.0.1") or "127.0.0.1"
    host = "127.0.0.1" if host == "0.0.0.0" else host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"https://{host}:{value(settings, 'GRAFANA_PORT', '3000') or '3000'}"


def fetch(settings, state):
    """Firing alerts from Grafana, authenticated as its admin and verified against the monitoring CA."""
    context = ssl.create_default_context(cafile=str(Path(state) / "tls/monitoring.crt"))
    # Grafana is a private local listener: an inherited HTTPS_PROXY cannot reach it.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    token = base64.b64encode(f"admin:{value(settings, 'GRAFANA_ADMIN_PASSWORD')}".encode()).decode()
    request = urllib.request.Request(grafana_base(settings) + ALERTS_PATH, headers={"Authorization": "Basic " + token})
    with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
        return firing(json.loads(response.read(4 * 1024 * 1024)))


def doctor_row(alerts):
    if not alerts:
        return ("alerts-firing", "ok", "No alert is firing", "none")
    names = ", ".join(f"{alert.name} ({alert.severity})" for alert in alerts)
    return ("alerts-firing", "warn", f"{len(alerts)} alert(s) firing: {names}",
            "Open Grafana's Alerting page; each alert links its runbook (docs/MONITORING-RUNBOOK.md)")


def syslog(priority, message):
    subprocess.run(["logger", "-p", priority, "-t", "chronicle", message], check=False, timeout=10,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def log_to_syslog(alerts, state, now=None):
    """Write each firing alert to syslog once per REPEAT, and each resolution once."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    path = Path(state) / SYSLOG_RECORD
    try:
        logged = json.loads(path.read_text())
        if not isinstance(logged, dict):
            logged = {}
    except (OSError, ValueError):
        logged = {}
    current = {}
    for alert in alerts:
        previous = logged.get(alert.fingerprint) or {}
        try:
            last = datetime.datetime.fromisoformat(previous["at"])
        except (KeyError, TypeError, ValueError):
            last = None
        if last is None or now - last >= REPEAT:
            summary = f": {alert.summary}" if alert.summary else ""
            syslog("user.crit", f"Chronicle alert firing: {alert.name} ({alert.severity}){summary}. Run ./chronicle doctor")
            last = now
        current[alert.fingerprint] = {"name": alert.name, "at": last.isoformat()}
    for fingerprint, previous in logged.items():
        if fingerprint not in current and isinstance(previous, dict):
            syslog("user.notice", f"Chronicle alert resolved: {previous.get('name', 'unnamed')}")
    write_json(path, current)


def command(to_syslog):
    """Print the doctor row for the firing alerts; with to_syslog, also write them to syslog.
    Prints nothing when the monitoring overlay is off. Never fails: a missing answer is a warning."""
    settings = read_env(Path.cwd() / ".env")
    if "overlays/monitoring.yml" not in value(settings, "COMPOSE_FILE"):
        return 0
    state = os.environ["CHRONICLE_OPS_STATE"]
    try:
        alerts = fetch(settings, state)
    except (OSError, ValueError, urllib.error.URLError, ssl.SSLError) as error:
        reason = getattr(error, "reason", None) or error
        print("\x1f".join(("alerts-firing", "warn", f"Could not read alerts from Grafana: {reason}",
                           "Run ./chronicle monitoring status")))
        return 0
    if to_syslog:
        try:
            log_to_syslog(alerts, state)
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    print("\x1f".join(doctor_row(alerts)))
    return 0
