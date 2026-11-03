#!/usr/bin/env python3
"""Fail-closed Chronicle source ownership and dependency-boundary checker."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import sys
from typing import Any

SOURCE_SUFFIXES = {".java", ".kt", ".kts", ".swift", ".ts", ".tsx", ".js", ".jsx"}


def load_manifest(path: pathlib.Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    if manifest.get("version") != 1:
        raise ValueError("architecture manifest version must be 1")
    return manifest


def matching_owners(relative_path: str, manifest: dict[str, Any]) -> list[str]:
    matches: list[str] = []
    for rule in manifest["owners"]:
        included = any(relative_path.startswith(prefix) for prefix in rule["prefixes"])
        excluded = any(
            relative_path.startswith(prefix) for prefix in rule.get("exclude_prefixes", [])
        )
        if included and not excluded:
            matches.append(rule["name"])
    return matches


def active_exception(
    relative_path: str,
    token: str,
    manifest: dict[str, Any],
    today: dt.date,
) -> bool:
    for exception in manifest.get("exceptions", []):
        if exception["path"] != relative_path or exception["token"] != token:
            continue
        required = ("owner", "reason", "expires")
        if any(not exception.get(field) for field in required):
            raise ValueError(f"incomplete boundary exception for {relative_path}: {token}")
        expiry = dt.date.fromisoformat(exception["expires"])
        if expiry < today:
            raise ValueError(f"expired boundary exception for {relative_path}: {token}")
        return True
    return False


def source_errors(
    relative_path: str,
    source: str,
    manifest: dict[str, Any],
    today: dt.date,
) -> list[str]:
    owners = matching_owners(relative_path, manifest)
    if len(owners) != 1:
        return [f"{relative_path}: expected exactly one architecture owner, found {owners or 'none'}"]
    errors = []
    for rule in manifest["forbidden_dependencies"]:
        if "prefixes" in rule:
            if not any(relative_path.startswith(prefix) for prefix in rule["prefixes"]):
                continue
        elif rule["owner"] != owners[0]:
            continue
        for token in rule["tokens"]:
            if token in source and not active_exception(relative_path, token, manifest, today):
                errors.append(f"{relative_path}: {owners[0]} may not depend on {token}")
    for rule in manifest.get("forbidden_patterns", []):
        if not any(relative_path.startswith(prefix) for prefix in rule["prefixes"]):
            continue
        for match in re.finditer(rule["pattern"], source, re.DOTALL):
            token = f"{rule['name']}:{match['field']}"
            if not active_exception(relative_path, token, manifest, today):
                errors.append(f"{relative_path}: forbidden {token}")
    return errors


def check(
    root: pathlib.Path,
    manifest: dict[str, Any],
    today: dt.date,
    *,
    include_optional: bool = False,
) -> list[str]:
    errors: list[str] = []
    required_roots = set(manifest["source_roots"])
    optional_roots = set(manifest.get("optional_source_roots", []))
    discovered_roots = required_roots | (optional_roots if include_optional else set())
    android_root = root / "chronicle"
    if android_root.is_dir():
        discovered_roots.update(
            str(path.relative_to(root) / "src" / "main")
            for path in android_root.glob("collection-*")
            if (path / "src" / "main").is_dir()
        )

    files: list[pathlib.Path] = []
    for source_root in sorted(discovered_roots):
        absolute_root = root / source_root
        if not absolute_root.is_dir():
            if source_root in required_roots or source_root in optional_roots:
                kind = "production" if source_root in required_roots else "opted-in optional"
                errors.append(f"declared {kind} source root is missing: {source_root}")
            continue
        files.extend(
            path for path in absolute_root.rglob("*") if path.is_file() and path.suffix in SOURCE_SUFFIXES
        )

    for path in sorted(set(files)):
        relative_path = path.relative_to(root).as_posix()
        try:
            errors.extend(source_errors(relative_path, path.read_text(encoding="utf-8", errors="replace"), manifest, today))
        except ValueError as error:
            errors.append(str(error))

    known_exception_paths = {item["path"] for item in manifest.get("exceptions", [])}
    for exception_path in sorted(known_exception_paths):
        if not (root / exception_path).is_file():
            errors.append(f"boundary exception references missing file: {exception_path}")
    return errors


def dependency_self_test(manifest: dict[str, Any]) -> None:
    for rule in manifest["forbidden_dependencies"]:
        prefixes = rule.get("prefixes") or next(
            owner["prefixes"] for owner in manifest["owners"] if owner["name"] == rule["owner"]
        )
        for prefix in prefixes:
            for token in rule["tokens"]:
                for source in (f"import {token}Forbidden", f"val dependency: {token}Forbidden? = null"):
                    errors = source_errors(prefix + "Example.kt", source, manifest, dt.date.today())
                    if not any(f"may not depend on {token}" in error for error in errors):
                        raise AssertionError(f"manifest dependency fixture did not fire: {rule}")


def optional_root_self_test(fixture_root: pathlib.Path, manifest: dict[str, Any]) -> None:
    manifest = dict(manifest, source_roots=[], exceptions=[])
    manifest["owners"] = [owner for owner in manifest["owners"] if owner["name"] != "ios-runtime"]
    if check(fixture_root, manifest, dt.date.today()):
        raise AssertionError("present optional root must be skipped by default")
    errors = check(fixture_root, manifest, dt.date.today(), include_optional=True)
    if len(errors) != 1 or "exactly one architecture owner" not in errors[0]:
        raise AssertionError(f"opted-in optional root must be checked: {errors}")
    manifest["owners"].append({"name": "ios-runtime", "prefixes": ["chronicle-ios/chronicle/"]})
    if check(fixture_root, manifest, dt.date.today(), include_optional=True):
        raise AssertionError("opted-in optional root with an owner must pass")
    manifest["source_roots"] = ["missing/src/main"]
    if not any("production source root is missing" in error for error in check(fixture_root, manifest, dt.date.today())):
        raise AssertionError("missing required source root must fail closed")


def self_test() -> None:
    script_root = pathlib.Path(__file__).resolve().parents[1]
    manifest = load_manifest(script_root / "config/architecture-boundaries.json")
    manifest["exceptions"] = []
    fixture_root = script_root / "tests/architecture-boundaries"
    fixtures = json.loads((fixture_root / "fixtures.json").read_text(encoding="utf-8"))
    for fixture in fixtures:
        if "owner" in fixture and matching_owners(fixture["path"], manifest) != [fixture["owner"]]:
            raise AssertionError(f"{fixture['name']}: incorrect architecture owner")
        errors = source_errors(fixture["path"], fixture["source"], manifest, dt.date.today())
        if bool(errors) != fixture["forbidden"]:
            raise AssertionError(f"{fixture['name']}: unexpected boundary result: {errors}")
    dependency_self_test(manifest)
    optional_root_self_test(fixture_root / "optional", manifest)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument(
        "--include-optional",
        action="store_true",
        help="check optional source roots supplied by an explicit platform checkout",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("[ok] architecture boundary fixtures passed")
        return 0

    script_root = pathlib.Path(__file__).resolve().parents[1]
    root = (args.root or script_root).resolve()
    manifest_path = args.manifest or root / "config" / "architecture-boundaries.json"
    optional_environment = os.environ.get("CHRONICLE_INCLUDE_OPTIONAL_SOURCE_ROOTS")
    if optional_environment not in (None, "0", "1"):
        parser.error("CHRONICLE_INCLUDE_OPTIONAL_SOURCE_ROOTS must be 0 or 1")
    include_optional = args.include_optional or optional_environment == "1"
    try:
        manifest = load_manifest(manifest_path)
        errors = check(
            root,
            manifest,
            dt.date.today(),
            include_optional=include_optional,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"[fail] architecture boundary checker error: {error}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[fail] {error}", file=sys.stderr)
        print(f"[fail] architecture boundary check found {len(errors)} violation(s)", file=sys.stderr)
        return 1
    optional_note = "included" if include_optional else "skipped"
    print(
        "[ok] architecture ownership and dependency boundaries passed "
        f"(optional source roots {optional_note})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
