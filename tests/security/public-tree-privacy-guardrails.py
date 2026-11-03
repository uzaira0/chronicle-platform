#!/usr/bin/env python3
"""Reject deployment-specific identifiers from the reusable public tree."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OPERATIONAL_PREFIXES = (
    ".github/workflows/",
    "deploy/",
    "scripts/",
    "selfhost/",
)
THIS_GUARD = "tests/security/public-tree-privacy-guardrails.py"
# Frozen until ported as selfhost overlays: no gate scans them.
FROZEN_PREFIXES = ("docker/", "k8s/")
PUBLIC_ANDROID_PACKAGE = re.compile(
    r"(?<![A-Za-z0-9_.])com\.bcm\.chronicle(?:\.debug)?(?![A-Za-z0-9_.])",
    re.IGNORECASE,
)
PUBLIC_ANDROID_PACKAGE_REGEX = re.compile(
    r"com\\\.bcm\\\.chronicle(?:\\\.debug)?",
    re.IGNORECASE,
)
UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
RULES = (
    (
        "absolute-account-path",
        re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+/"),
        lambda path: True,
    ),
    (
        "cloud-instance-identifier",
        re.compile(r"\bi-[0-9a-f]{8,17}\b", re.IGNORECASE),
        lambda path: path.startswith(OPERATIONAL_PREFIXES),
    ),
    (
        "institution-deployment-hostname",
        re.compile(
            r"(?:https?://|hostname:\s*|DOMAIN=['\"]?)[A-Za-z0-9.-]*(?:\.edu|\.research\.[A-Za-z0-9.-]+)\b",
            re.IGNORECASE,
        ),
        lambda path: path.startswith(OPERATIONAL_PREFIXES),
    ),
    (
        "institution-deployment-label",
        re.compile(
            "|".join(
                (
                    r"\b" + "BC" + r"M\b",
                    r"\b" + "Bay" + r"lor\b",
                    r"\b" + "CN" + r"RC\b",
                    r"\b" + "test" + r"prod\b",
                    r"\b" + "iie" + r"\.cl\b",
                    chr(70) + chr(53) + " VIP",
                    "FLASH" + "-TV",
                )
            ),
            re.IGNORECASE,
        ),
        lambda path: path != THIS_GUARD,
    ),
)


def repository_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    excluded = subprocess.run(
        ["git", "ls-files", "--cached", "--ignored", "--exclude-from=.publishignore", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    private_paths = set(excluded.stdout.split(b"\0"))
    return [path for item in result.stdout.split(b"\0") if item and item not in private_paths
            if not (path := item.decode("utf-8")).startswith(FROZEN_PREFIXES)]


def main() -> int:
    findings: list[tuple[str, int, str]] = []
    for relative in repository_files():
        path = ROOT / relative
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue

        for line_number, line in enumerate(text.splitlines(), 1):
            # The Play application ID is a required public product identifier, not a
            # deployment label. Remove only that exact token before checking the rest of
            # the line so nearby institution-specific prose cannot hide behind it. Tests
            # may express that same exact package as an escaped regular expression.
            privacy_line = PUBLIC_ANDROID_PACKAGE.sub("<public-android-package>", line)
            privacy_line = PUBLIC_ANDROID_PACKAGE_REGEX.sub(
                "<public-android-package-regex>", privacy_line
            )
            if relative.startswith(("scripts/", ".github/workflows/")) and UUID.search(line):
                findings.append((relative, line_number, "embedded-operational-uuid"))
            for category, pattern, applies in RULES:
                if applies(relative) and pattern.search(privacy_line):
                    findings.append((relative, line_number, category))

    if findings:
        print("Public-tree privacy guardrails failed:", file=sys.stderr)
        for relative, line_number, category in findings:
            print(f"{relative}:{line_number}: {category}", file=sys.stderr)
        return 1

    print("Public-tree privacy guardrails passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
