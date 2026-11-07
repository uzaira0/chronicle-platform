#!/usr/bin/env python3
"""Select or check a Compose subnet against the host's Docker networks."""

import ipaddress
import json
import subprocess
import sys
import shutil


def docker_networks():
    ids = subprocess.run(
        ["docker", "network", "ls", "-q"],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    return json.loads(subprocess.run(
        ["docker", "network", "inspect", *ids],
        check=True, capture_output=True, text=True,
    ).stdout) if ids else []


# The one owner of the core network's range: select-core picks the first free /24 in it, so on
# a host with nothing there CHRONICLE_CORE_PREFIX is DEFAULT_CORE_PREFIX. Nothing else defaults it:
# setup and update write it to .env, and Compose refuses to start without it.
CORE_RANGE = "10.252"
DEFAULT_CORE_PREFIX = f"{CORE_RANGE}.0"
# Everything derived from that one /24 (docs/NETWORK-EGRESS.md, "Addresses"). `core` carries the
# web-to-backend path, `ingress` carries web-forward to web, and `database` carries PostgreSQL and
# its users (backend, backups, the database jobs), which web is not one of. core and ingress each
# have the ip_range Docker assigns from and one fixed address outside it that a trust rule names:
# the backend trusts X-Forwarded-For only from web, and Caddy accepts a PROXY protocol header only
# from web-forward.
# docker-compose.yml spells the same values by interpolating the prefix (Compose cannot run this
# file); the tests render it and compare with core_layout, and ./chronicle verify compares the
# running networks with it. Both subnets lie inside the /24, so select-core's overlap check and
# the update's fallback to DEFAULT_CORE_PREFIX cover them.
CORE_NETWORKS = {"core": ("0/25", "64/26"), "ingress": ("128/26", "160/27")}
# The database network has no fixed address (nothing trusts an address on it), so ./chronicle verify
# compares only CORE_NETWORKS; it is still ours for the overlap checks below.
DERIVED_NETWORKS = {**CORE_NETWORKS, "database": ("192/26", "192/26")}
FIXED_ADDRESSES = {"web": ("core", 2), "web-forward": ("ingress", 130)}
# Networks of ours that carry a fixed subnet: `default` (CHRONICLE_SUBNET) and the networks
# derived from CHRONICLE_CORE_PREFIX.
OWN_NETWORKS = ("default", *DERIVED_NETWORKS)
SUBNET_SETTINGS = {"default": "CHRONICLE_SUBNET", **{name: "CHRONICLE_CORE_PREFIX" for name in DERIVED_NETWORKS}}


def derived_subnets(prefix):
    """{network: (subnet, ip_range)} of every network derived from CHRONICLE_CORE_PREFIX."""
    return {name: (f"{prefix}.{subnet}", f"{prefix}.{ip_range}") for name, (subnet, ip_range) in DERIVED_NETWORKS.items()}


def core_layout(prefix):
    """{"networks": {name: {"subnet", "ip_range"}}, "addresses": {service: (network, address)}}
    for the three octets in CHRONICLE_CORE_PREFIX."""
    return {"networks": {name: {"subnet": f"{prefix}.{subnet}", "ip_range": f"{prefix}.{ip_range}"}
                         for name, (subnet, ip_range) in CORE_NETWORKS.items()},
            "addresses": {service: (network, f"{prefix}.{host}") for service, (network, host) in FIXED_ADDRESSES.items()}}


def is_own(other, project, names=OWN_NETWORKS):
    # Name alone is not ownership: a hand-made network can carry the same name, and Compose
    # refuses to adopt it. This project's Compose-created networks are excluded under any
    # name (a `name:` override in Compose renames them); Compose's labels are what mark them.
    labels = other.get("Labels") or {}
    return (labels.get("com.docker.compose.project") == project
            and labels.get("com.docker.compose.network") in names)


def overlap(wanted, existing, project):
    return next(iter(overlaps(wanted, existing, project)), None)


def overlaps(wanted, existing, project):
    found = []
    for other in existing:
        if is_own(other, project):
            continue
        for config in (other.get("IPAM") or {}).get("Config") or []:
            subnet = config.get("Subnet")
            if not subnet:
                continue
            held = ipaddress.ip_network(subnet, strict=False)
            for want in wanted:
                if held.version == want.version and held.overlaps(want):
                    found.append((want, other["Name"], held))
    return found


def host_networks(existing, project):
    own_bridges = {network.get("Options", {}).get("com.docker.network.bridge.name") or "br-" + network.get("Id", "")[:12]
                   for network in existing if is_own(network, project)}
    if shutil.which("ip"):
        routes = []
        for family in ("-4", "-6"):
            routes += json.loads(subprocess.run(["ip", family, "-j", "route", "show", "table", "all"],
                                               capture_output=True, text=True, check=True).stdout)
        return [{"Name": "host route " + route.get("dev", "unknown"), "IPAM": {"Config": [{"Subnet": route["dst"]}]}}
                for route in routes if route.get("dst", "default") != "default" and route.get("dev") not in own_bridges]
    if sys.platform != "darwin":
        raise ValueError("iproute2 is required to check institutional/VPN routes")
    routes = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, check=True).stdout
    result = []
    for line in routes.splitlines():
        fields = line.split()
        if not fields or fields[0] == "default":
            continue
        try:
            destination = fields[0]
            address, separator, prefix = destination.partition('/')
            if ':' not in address and all(part.isdigit() for part in address.split('.')):
                octets = address.split('.')
                destination = '.'.join(octets + ['0'] * (4 - len(octets))) + '/' + (prefix if separator else str(8 * len(octets)))
            subnet = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        result.append({"Name": "host route", "IPAM": {"Config": [{"Subnet": str(subnet)}]}})
    return result


def select(default, project):
    wanted = ipaddress.ip_network(default)
    try:
        existing = docker_networks()
    except (OSError, subprocess.CalledProcessError, ValueError):
        existing = []
    existing += host_networks(existing, project)
    if not overlap([wanted], existing, project):
        print(default)
        return
    # Avoid Docker's usual 172.16/12 and 192.168/16 address pools.
    for index in range(256):
        candidate = ipaddress.ip_network(f"10.253.{index}.0/24")
        if not overlap([candidate], existing, project):
            print(candidate)
            return
    sys.exit("no free subnet in 10.253.0.0/16; set CHRONICLE_SUBNET in .env to a free private range")


def select_core(edge, project):
    """Print the first free CHRONICLE_CORE_PREFIX: three octets of a /24 for the internal core
    network, clear of Docker networks, host routes and the edge subnet (CHRONICLE_SUBNET)."""
    try:
        existing = docker_networks()
    except (OSError, subprocess.CalledProcessError, ValueError):
        existing = []
    existing += host_networks(existing, project)
    if edge:
        existing.append({"Name": "CHRONICLE_SUBNET", "IPAM": {"Config": [{"Subnet": edge}]}})
    for index in range(256):
        candidate = ipaddress.ip_network(f"{CORE_RANGE}.{index}.0/24")
        if not overlap([candidate], existing, project):
            print(f"{CORE_RANGE}.{index}")
            return
    sys.exit(f"no free /24 in {CORE_RANGE}.0.0/16 for the internal core network; set CHRONICLE_CORE_PREFIX "
             "in .env to the first three octets of a free private /24")


def warn(message):
    print(f"warning: {message}", file=sys.stderr)


def check():
    config = json.load(sys.stdin)
    # The setting that chose each subnet, so the warning names what to change.
    settings = {}
    for key, network in (config.get("networks") or {}).items():
        for ipam in ((network or {}).get("ipam") or {}).get("config") or []:
            if ipam.get("subnet"):
                settings[ipaddress.ip_network(ipam["subnet"], strict=False)] = SUBNET_SETTINGS.get(key, f"the {key} network's subnet")
    wanted = list(settings)
    if not wanted:
        return
    existing = docker_networks()
    # Warn, never refuse: an overlap is an environment problem the operator fixes on their own
    # schedule. A Docker network overlap makes Compose refuse to create ours (its own error then
    # names it); a route overlap makes those hosts unreachable from the containers.
    for want, name, held in overlaps(wanted, existing + host_networks(existing, config.get("name")), config.get("name")):
        setting = settings[want]
        warn(f"{setting} {want} overlaps Docker network {name} ({held}); "
             f"set {setting} in .env to a free private range")


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["check"]:
            check()
        elif len(sys.argv) == 4 and sys.argv[1] == "select":
            select(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 4 and sys.argv[1] == "select-core":
            select_core(sys.argv[2], sys.argv[3])
        elif sys.argv[1:] == ["default-core"]:
            print(DEFAULT_CORE_PREFIX)
        elif len(sys.argv) == 3 and sys.argv[1] == "layout":
            print(json.dumps(core_layout(sys.argv[2]), sort_keys=True))
        else:
            sys.exit("usage: network-subnet.py check | select DEFAULT PROJECT | select-core CHRONICLE_SUBNET PROJECT"
                     " | default-core | layout CHRONICLE_CORE_PREFIX")
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        if sys.argv[1:] != ["check"]:
            sys.exit(f"could not check CHRONICLE_SUBNET against Docker networks: {error}")
        warn(f"could not check CHRONICLE_SUBNET against Docker networks: {error}")
