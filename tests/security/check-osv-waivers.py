#!/usr/bin/env python3
"""Fail unless every OSV waiver names a reason and expires within MAX_DAYS."""
import datetime
import sys
import tomllib

MAX_DAYS = 62


# Each waiver table and the key holding its expiry.
WAIVERS = (("IgnoredVulns", "ignoreUntil"), ("PackageOverrides", "effectiveUntil"))


def problems(config: dict, now: datetime.datetime) -> list[str]:
    found = []
    for table, expiry in WAIVERS:
        for entry in config.get(table, []):
            waived = entry.get("id") or " ".join(filter(None, (entry.get("name"), entry.get("version")))) or "<unnamed>"
            until = entry.get(expiry)
            if isinstance(until, datetime.date) and not isinstance(until, datetime.datetime):
                until = datetime.datetime.combine(until, datetime.time(), datetime.timezone.utc)
            if not str(entry.get("reason", "")).strip():
                found.append(f"{waived}: missing reason")
            if table == "PackageOverrides" and not entry.get("version"):
                found.append(f"{waived}: a package waiver must name one version")
            if not isinstance(until, datetime.datetime):
                found.append(f"{waived}: missing {expiry}")
            elif not now < until <= now + datetime.timedelta(days=MAX_DAYS):
                found.append(f"{waived}: {expiry} {until.isoformat()} must be in the next {MAX_DAYS} days")
    return found


def self_test() -> None:
    now = datetime.datetime(2026, 10, 8, tzinfo=datetime.timezone.utc)
    soon = now + datetime.timedelta(days=30)
    assert not problems({"IgnoredVulns": [{"id": "A", "reason": "unused", "ignoreUntil": soon}]}, now)
    assert problems({"IgnoredVulns": [{"id": "A", "ignoreUntil": soon}]}, now)
    assert problems({"IgnoredVulns": [{"id": "A", "reason": "unused"}]}, now)
    assert problems({"IgnoredVulns": [{"id": "A", "reason": "unused", "ignoreUntil": now}]}, now)
    assert problems({"IgnoredVulns": [{"id": "A", "reason": "unused",
                                       "ignoreUntil": now + datetime.timedelta(days=MAX_DAYS + 1)}]}, now)
    package = {"name": "io.netty:netty-codec", "version": "4.1.93.Final", "reason": "unused", "effectiveUntil": soon.date()}
    assert not problems({"PackageOverrides": [package]}, now)
    assert problems({"PackageOverrides": [dict(package, reason="")]}, now)
    assert problems({"PackageOverrides": [{k: v for k, v in package.items() if k != "effectiveUntil"}]}, now)
    assert problems({"PackageOverrides": [{k: v for k, v in package.items() if k != "version"}]}, now)
    assert problems({"PackageOverrides": [dict(package, effectiveUntil=(now + datetime.timedelta(days=MAX_DAYS + 1)).date())]}, now)


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        sys.exit(0)
    now = datetime.datetime.now(datetime.timezone.utc)
    failures = []
    for path in sys.argv[1:]:
        with open(path, "rb") as handle:
            failures += [f"{path}: {problem}" for problem in problems(tomllib.load(handle), now)]
    print("\n".join(failures))
    sys.exit(1 if failures else 0)
