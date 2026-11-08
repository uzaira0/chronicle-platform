"""Finite operator-selected startup waits."""

from gettext import gettext as _
from decimal import Decimal, localcontext
import re

DEFAULT_STARTUP_TIMEOUT_SECONDS = "3600"


def startup_timeout(raw, name):
    if not re.fullmatch(r"[1-9][0-9]*", raw):
        raise ValueError(_("%(name)s must be a positive integer") % {"name": name})
    return raw


def caddy_duration_nanoseconds(raw):
    """A positive Caddy duration within signed 64-bit nanoseconds, including days, in nanoseconds; else None."""
    if not raw or len(raw) > 128:
        return None
    duration = raw.removeprefix("+")
    units = {"ns": 1, "us": 1000, "µs": 1000, "μs": 1000, "ms": 1000000,
             "s": 1000000000, "m": 60000000000, "h": 3600000000000, "d": 86400000000000}
    component = re.compile(r"([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(ns|us|µs|μs|ms|s|m|h|d)")
    offset, nanoseconds = 0, 0
    with localcontext() as context:
        context.prec = 200
        for match in component.finditer(duration):
            if match.start() != offset:
                return None
            nanoseconds += int(Decimal(match.group(1)) * units[match.group(2)])
            if nanoseconds > 2**63 - 1:
                return None
            offset = match.end()
    return nanoseconds if offset == len(duration) and nanoseconds > 0 else None


def valid_caddy_duration(raw):
    """Accept positive Caddy durations within signed 64-bit nanoseconds, including days."""
    return caddy_duration_nanoseconds(raw) is not None
