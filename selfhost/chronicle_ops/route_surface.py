"""Public edge contract, including prefixes which must never reach a backend."""

from dataclasses import dataclass
from enum import Enum


class ProbeKind(Enum):
    SERVED = "served"
    DENIED = "denied"


@dataclass(frozen=True)
class RouteProbe:
    path: str
    statuses: tuple[str, ...]
    label: str
    served: bool = False
    kind: ProbeKind = ProbeKind.SERVED

    def __post_init__(self):
        if self.kind is ProbeKind.SERVED and any(not code.startswith('2') for code in self.statuses):
            raise ValueError('reachability requires a successful response')


RETIRED_PREFIXES = ("/chronicle/v1", "/chronicle/v2", "/chronicle/study")
BLOCKED_PREFIXES = ("/datastore", "/chronicle/datastore", "/chronicle/principal",
                    "/chronicle/compliance", "/chronicle/import", "/prometheus")
PUBLIC_ROUTES = (
    RouteProbe("/health", ("204",), "ready"),
    RouteProbe("/chronicle", ("200",), "dashboard", served=True),
    RouteProbe("/chronicle/", ("200",), "dashboard assets", served=True),
    RouteProbe("/chronicle/survey", ("200",), "participant form"),
)
DENIED_ROUTES = tuple(RouteProbe(prefix + "/x", ("404",), "retired API blocked", kind=ProbeKind.DENIED)
                      for prefix in RETIRED_PREFIXES) + tuple(
    RouteProbe(prefix + "/", ("404",), "direct backend route blocked", kind=ProbeKind.DENIED) for prefix in BLOCKED_PREFIXES)
DENIED_ROUTES += tuple(RouteProbe(path, ("404",), "private deployment file blocked", kind=ProbeKind.DENIED)
                       for path in ("/.env", "/.git/config", "/.env.local"))
PUBLIC_SURFACE = PUBLIC_ROUTES + DENIED_ROUTES
