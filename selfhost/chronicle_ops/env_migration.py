"""Deployment environment migration policy for setup and release handoffs."""

from enum import Enum
from pathlib import Path, PurePosixPath

from .common import require
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


def compose_names(values, source):
    values = {key: value(values, key) for key in values}
    allowed = {"docker-compose.yml", *MODE_OVERLAYS, "overlays/backups.yml", "overlays/monitoring.yml"}
    raw_compose = values.get(
        "COMPOSE_FILE",
        "docker-compose.yml:overlays/mode-behind-proxy-internal.yml:overlays/backups.yml",
    )
    normalized = []
    for token in raw_compose.split(":"):
        token = token.strip()
        if not token:
            raise ValueError("previous COMPOSE_FILE contains an empty path")
        name = compose_name(token, source)
        if name not in allowed:
            raise ValueError(f"unsupported previous Compose file: {name}")
        if name in normalized:
            raise ValueError(f"duplicate previous Compose file: {name}")
        normalized.append(name)

    if normalized.count("docker-compose.yml") != 1:
        raise ValueError("previous COMPOSE_FILE must contain docker-compose.yml exactly once")
    modes = [name for name in normalized if name in MODE_OVERLAYS]
    if len(modes) != 1:
        raise ValueError("previous COMPOSE_FILE must contain exactly one supported mode overlay")
    return normalized


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

