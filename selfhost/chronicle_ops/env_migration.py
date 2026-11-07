"""Deployment environment migration policy for setup and release handoffs."""

from enum import Enum
from pathlib import Path, PurePosixPath

from .common import DEFAULT_MIN_FREE_DISK_GIB, GIB, UPDATE_PEAK_BYTES, require
from .envfile import assignment, quote_env, value
from .receipts import write_text


class DeploymentMode(Enum):
    """The deployment mode is the mode overlay COMPOSE_FILE selects; every mode keeps the dashboard internal."""
    BEHIND_PROXY = "behind-proxy"
    OWN_TLS = "own-tls"
    LOCAL_HTTPS = "local-https"


MODE_OVERLAYS = {
    "overlays/mode-behind-proxy-internal.yml": DeploymentMode.BEHIND_PROXY,
    "overlays/mode-own-tls-internal.yml": DeploymentMode.OWN_TLS,
    "overlays/mode-local-https.yml": DeploymentMode.LOCAL_HTTPS,
}


def deployment_mode(compose_file, source=None):
    """The mode a COMPOSE_FILE selects, read with the same path rules as compose_names."""
    source = Path.cwd() if source is None else source
    names = [compose_name(token.strip(), source) for token in compose_file.split(":") if token.strip()]
    return next((MODE_OVERLAYS[name] for name in names if name in MODE_OVERLAYS), None)


def compose_name(token, source):
    """One COMPOSE_FILE entry as a release-relative name; an absolute entry must lie inside the release."""
    candidate = Path(token)
    if candidate.is_absolute():
        try:
            relative = candidate.resolve().relative_to(source)
        except ValueError:
            raise ValueError(f"previous COMPOSE_FILE references a file outside its release: {token}")
        return PurePosixPath(relative.as_posix()).as_posix()
    pure = PurePosixPath(token)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe previous COMPOSE_FILE path: {token}")
    return pure.as_posix()


SUPPORTED_COMPOSE_FILES = frozenset({"docker-compose.yml", *MODE_OVERLAYS, "overlays/backups.yml", "overlays/monitoring.yml"})


def compose_selection(values, source):
    """The supported Compose files COMPOSE_FILE selects, and the operator's own entries it drops.

    Empty entries and repeats are dropped silently; they select nothing. A file the release does
    not ship is dropped and returned, so the caller can keep a copy and name it."""
    values = {key: value(values, key) for key in values}
    raw_compose = values.get(
        "COMPOSE_FILE",
        "docker-compose.yml:overlays/mode-behind-proxy-internal.yml:overlays/backups.yml",
    )
    normalized, dropped = [], []
    for token in raw_compose.split(":"):
        token = token.strip()
        if not token:
            continue
        try:
            name = compose_name(token, source)
        except ValueError:
            dropped.append(token)  # an operator file outside the release
            continue
        if name not in SUPPORTED_COMPOSE_FILES:
            dropped.append(name)
        elif name not in normalized:
            normalized.append(name)

    if normalized.count("docker-compose.yml") != 1:
        raise ValueError("previous COMPOSE_FILE must contain docker-compose.yml exactly once")
    modes = [name for name in normalized if name in MODE_OVERLAYS]
    if len(modes) != 1:
        raise ValueError("previous COMPOSE_FILE must contain exactly one supported mode overlay")
    return normalized, dropped


def compose_names(values, source):
    return compose_selection(values, source)[0]


def running_selection(values, source):
    """The Compose files the release at source runs with, in COMPOSE_FILE order: the supported
    selection plus every operator file that still exists there. An update stops, dumps and removes
    the previous release, and a rollback restarts it, with exactly these; only the new release
    leaves the operator's files out (compose_selection)."""
    compose_selection(values, source)  # the same validity rules
    raw = {key: value(values, key) for key in values}.get(
        "COMPOSE_FILE", "docker-compose.yml:overlays/mode-behind-proxy-internal.yml:overlays/backups.yml")
    names = []
    for token in (token.strip() for token in raw.split(":")):
        if not token:
            continue
        try:
            name = compose_name(token, source)
        except ValueError:
            name = token  # outside the release; the previous release reads it from there
        path = Path(name) if Path(name).is_absolute() else Path(source) / name
        if (name in SUPPORTED_COMPOSE_FILES or path.is_file() and not path.is_symlink()) and name not in names:
            names.append(name)
    return names


# Keys a release renamed, old name to new; the value carries over unchanged (both in milliseconds).
RENAMED_KEYS = {
    "POSTGRES_STATEMENT_TIMEOUT": "POSTGRES_STATEMENT_TIMEOUT_MS",
    "POSTGRES_IDLE_IN_TRANSACTION_TIMEOUT": "POSTGRES_IDLE_IN_TRANSACTION_TIMEOUT_MS",
    "POSTGRES_LOCK_TIMEOUT": "POSTGRES_LOCK_TIMEOUT_MS",
    # An alert budget, never a cap (AF-P10); the value is the same number of bytes.
    "METRICS_MAX_DISK_BYTES": "METRICS_DISK_BUDGET_BYTES",
}

# Values an earlier release shipped in .env.example, which a later release changed. A value still
# equal to the old default was never chosen by the operator, so it follows the new one; any other
# value is kept. key: (old shipped value, new value, why).
RETIRED_DEFAULTS = {
    "METRICS_MIN_FREE_DISK_BYTES": (
        "2147483648", str(DEFAULT_MIN_FREE_DISK_GIB * GIB + UPDATE_PEAK_BYTES),
        "VictoriaMetrics now stops writing while an update still has room (MIN_FREE_DISK_GIB plus 3 GiB)"),
}


CORE_PREFIX_KEY = "CHRONICLE_CORE_PREFIX"


def migrate_settings(old, hash_password, select_core=None):
    """Every settings migration an update can derive by itself, as (settings, notes).

    Renamed keys move to their new name; a secret that only these services share is generated as
    setup would; a cleartext dashboard password is replaced by its bcrypt hash; a release from
    before the internal core network gets a free CHRONICLE_CORE_PREFIX from select_core(subnet).
    The database passwords must match the existing database, so a missing one is the one refusal."""
    import json
    from .credentials import GENERATION_DATES_KEY, GRAFANA, INTERNAL_WEB, JWT, METRICS, POSTGRES, POSTGRES_APP
    from .credentials import setup_credentials
    settings, notes = dict(old), []
    for retired, current in RENAMED_KEYS.items():
        if retired in settings:
            if current not in settings:
                settings[current] = settings[retired]
                notes.append(f"{retired} is now {current}; its value was moved")
            else:
                notes.append(f"{retired} is retired; {current} is kept")
            del settings[retired]
    for key, (shipped, current, reason) in RETIRED_DEFAULTS.items():
        if value(settings, key) == shipped:
            settings[key] = current
            notes.append(f"{key} was the old default {shipped}; it is now {current}: {reason}")
    for secret in (POSTGRES, POSTGRES_APP):
        require(value(settings, secret.env_key),
                f"{secret.env_key} is empty; it must match the existing database's password, so the update cannot "
                "generate it. Restore it in .env from your copy of the settings, then rerun ./chronicle update")
    regenerable = (JWT, METRICS, INTERNAL_WEB, GRAFANA)
    missing = [secret for secret in regenerable if not value(settings, secret.env_key)]
    if missing:
        preserved = {secret.env_key: value(settings, secret.env_key) for secret in (POSTGRES, POSTGRES_APP, *regenerable)}
        generated = setup_credentials(settings, preserved)
        for secret in missing:
            settings[secret.env_key] = quote_env(generated.values[secret.env_key])
            notes.append(f"{secret.env_key} was empty; a new random value was generated")
        settings[GENERATION_DATES_KEY] = quote_env(json.dumps(generated.generated_at, sort_keys=True))
    if select_core is not None and not value(settings, CORE_PREFIX_KEY):
        prefix = select_core(value(settings, "CHRONICLE_SUBNET", "172.28.0.0/16"))
        settings[CORE_PREFIX_KEY] = quote_env(prefix)
        notes.append(f"{CORE_PREFIX_KEY} was not set; the internal core and ingress networks use {prefix}.0/24")
    from .egress import ALERT_EGRESS_ENV, alert_egress
    derived = alert_egress(settings)
    if value(settings, ALERT_EGRESS_ENV) != derived:
        settings[ALERT_EGRESS_ENV] = derived
        notes.append(f"{ALERT_EGRESS_ENV} is now {derived}, derived from CHRONICLE_ALERT_WEBHOOK_URL")
    password = value(settings, "DASHBOARD_PASSWORD_HASH")
    if password and not password.startswith("$2"):
        hashed = hash_password(password)
        require(hashed.startswith("$2"), "could not bcrypt-hash the cleartext DASHBOARD_PASSWORD_HASH")
        settings["DASHBOARD_PASSWORD_HASH"] = quote_env(hashed)
        notes.append("DASHBOARD_PASSWORD_HASH held a cleartext password; it now holds its bcrypt hash")
    return settings, notes


def dashboard_login_settings(settings, names):
    if value(settings, "DASHBOARD_EXPOSURE") == "internal" or any(name in MODE_OVERLAYS for name in names):
        require(value(settings, "DASHBOARD_PASSWORD_HASH").startswith("$2"),
                "internal dashboard requires a bcrypt DASHBOARD_PASSWORD_HASH; run ./chronicle setup to choose a dashboard password before retrying")
        return {"TESTING_LOGIN_ENABLED": "false", "REQUIRE_MFA": "false"}
    return {}


def merge_env(old, template, destination, state, names, preserve_images=False):
    old = dict(old, CHRONICLE_STATE_DIR=quote_env(str(state)), COMPOSE_FILE=":".join(names))
    if not preserve_images:
        old.update(dashboard_login_settings(old, names))
    managed = {"RELEASE_VERSION", "POSTGRES_IMAGE", "COMPOSE_FILE", "CHRONICLE_STATE_DIR"}
    rendered, seen = [], set()
    for line in template.splitlines():
        match = assignment.match(line)
        if match:
            key = match[1]
            require(key not in seen, f"new .env.example contains duplicate assignment: {key}")
            seen.add(key)
            if key in {"CHRONICLE_STATE_DIR", "COMPOSE_FILE"} or (
                    key in old and (preserve_images or (key not in managed and not key.endswith("_IMAGE")))):
                line = f"{key}={old[key]}"
        rendered.append(line)
    unknown = sorted(key for key in old.keys() - seen - managed
                     if not key.startswith("COMPOSE_") and not key.endswith("_IMAGE"))
    if unknown:
        rendered.extend(["", "# Previous operator settings not present in this release template."])
        rendered.extend(f"{key}={old[key]}" for key in unknown)
    content = "\n".join(rendered) + "\n"
    require(preserve_images or "__CHRONICLE_" not in content,
            "new .env.example still contains unresolved release image placeholders")
    if destination is not None:
        write_text(destination, content)
    return content

