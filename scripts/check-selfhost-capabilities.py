#!/usr/bin/env python3
"""Validate and render the self-host backend-to-interface ownership contract."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contracts" / "selfhost-capabilities.json"
ARCHITECTURE_MANIFEST = ROOT / "config" / "architecture-boundaries.json"
VALID_OWNERS = {"researcher-web", "participant-web", "mobile-client", "operator-cli", "grafana", "api-only-by-design"}
REQUIRED = {
    "participant-export",
    "participant-enrollment-health",
    "verified-deletion",
    "failed-background-operations",
    "backup-visibility",
    "deployment-diagnostics",
}


def evidence_is_under(path_text: str, source_root: str) -> bool:
    path_parts = PurePosixPath(path_text).parts
    root_parts = PurePosixPath(source_root).parts
    return bool(root_parts) and path_parts[: len(root_parts)] == root_parts


def load_and_validate(
    root: Path = ROOT,
    manifest_path: Path = MANIFEST,
    architecture_manifest_path: Path = ARCHITECTURE_MANIFEST,
    *,
    include_optional: bool = False,
) -> dict:
    data = json.loads(manifest_path.read_text())
    architecture = json.loads(architecture_manifest_path.read_text())
    if architecture.get("version") != 1:
        raise ValueError("architecture manifest version must be 1")
    required_roots = architecture.get("source_roots")
    optional_roots = architecture.get("optional_source_roots", [])
    if not isinstance(required_roots, list) or not required_roots or not all(
        isinstance(item, str) and item for item in required_roots
    ):
        raise ValueError("architecture source_roots must be a non-empty string list")
    if not isinstance(optional_roots, list) or not all(
        isinstance(item, str) and item for item in optional_roots
    ):
        raise ValueError("architecture optional_source_roots must be a string list")

    errors: list[str] = []
    seen: set[str] = set()
    for capability in data.get("capabilities", []):
        capability_id = capability.get("id", "")
        if not capability_id or capability_id in seen:
            errors.append(f"invalid or duplicate capability id: {capability_id!r}")
        seen.add(capability_id)
        owners = set(capability.get("owners", []))
        if not owners or not owners <= VALID_OWNERS:
            errors.append(f"{capability_id}: owners must use declared interface categories")
        if "api-only-by-design" in owners and (len(owners) != 1 or not capability.get("rationale")):
            errors.append(f"{capability_id}: API-only ownership requires a rationale and no second owner")
        for item in capability.get("evidence", []):
            path_text, separator, needle = item.partition(":")
            if not separator or not needle:
                errors.append(f"{capability_id}: malformed evidence {item!r}")
                continue
            if not include_optional and any(
                evidence_is_under(path_text, source_root) for source_root in optional_roots
            ):
                continue
            path = root / path_text
            if not path.exists():
                errors.append(f"{capability_id}: evidence path missing: {path_text}")
            elif needle.casefold() not in path.read_text(errors="replace").casefold():
                errors.append(f"{capability_id}: evidence text missing from {path_text}: {needle!r}")
    missing = REQUIRED - seen
    if missing:
        errors.append(f"required self-host workflows have no declared owner: {', '.join(sorted(missing))}")
    if errors:
        raise SystemExit("capability ownership check failed:\n- " + "\n- ".join(errors))
    return data


def self_test() -> None:
    scratch_parent = ROOT / "build" / "selfhost-capability-self-test"
    scratch_parent_existed = scratch_parent.exists()
    scratch_parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(dir=scratch_parent) as directory:
            root = Path(directory)
            required_evidence = root / "required" / "src" / "Evidence.txt"
            required_evidence.parent.mkdir(parents=True)
            required_evidence.write_text("required marker\n", encoding="utf-8")

            capabilities = [
                {
                    "id": capability_id,
                    "backend": "fixture",
                    "owners": ["operator-cli"],
                    "evidence": ["required/src/Evidence.txt:required marker"],
                }
                for capability_id in sorted(REQUIRED)
            ]
            capabilities.append(
                {
                    "id": "optional-mobile-client",
                    "backend": "fixture",
                    "owners": ["mobile-client"],
                    "evidence": ["optional/src/Evidence.swift:optional marker"],
                }
            )
            manifest_path = root / "selfhost-capabilities.json"
            manifest_path.write_text(
                json.dumps({"schemaVersion": 1, "capabilities": capabilities}),
                encoding="utf-8",
            )
            architecture_manifest_path = root / "architecture-boundaries.json"
            architecture_manifest_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "source_roots": ["required/src"],
                        "optional_source_roots": ["optional/src"],
                    }
                ),
                encoding="utf-8",
            )

            load_and_validate(root, manifest_path, architecture_manifest_path)

            try:
                load_and_validate(
                    root,
                    manifest_path,
                    architecture_manifest_path,
                    include_optional=True,
                )
            except SystemExit as error:
                if "evidence path missing: optional/src/Evidence.swift" not in str(error):
                    raise AssertionError(f"unexpected optional-root failure: {error}") from error
            else:
                raise AssertionError("missing opted-in optional evidence did not fail closed")

            optional_evidence = root / "optional" / "src" / "Evidence.swift"
            optional_evidence.parent.mkdir(parents=True)
            optional_evidence.write_text("optional marker\n", encoding="utf-8")
            load_and_validate(
                root,
                manifest_path,
                architecture_manifest_path,
                include_optional=True,
            )

            optional_evidence.write_text("wrong text\n", encoding="utf-8")
            load_and_validate(root, manifest_path, architecture_manifest_path)
            try:
                load_and_validate(
                    root,
                    manifest_path,
                    architecture_manifest_path,
                    include_optional=True,
                )
            except SystemExit as error:
                if "evidence text missing from optional/src/Evidence.swift" not in str(error):
                    raise AssertionError(f"unexpected optional-text failure: {error}") from error
            else:
                raise AssertionError("invalid opted-in optional evidence did not fail closed")

            required_evidence.unlink()
            try:
                load_and_validate(root, manifest_path, architecture_manifest_path)
            except SystemExit as error:
                if "evidence path missing: required/src/Evidence.txt" not in str(error):
                    raise AssertionError(f"unexpected required-root failure: {error}") from error
            else:
                raise AssertionError("missing required evidence was skipped")
    finally:
        if not scratch_parent_existed:
            try:
                scratch_parent.rmdir()
            except OSError:
                pass


def render(data: dict) -> str:
    rows = [
        "# Capability ownership",
        "",
        "Generated from `contracts/selfhost-capabilities.json`; run `python3 scripts/check-selfhost-capabilities.py --write`.",
        "Infrastructure diagnostics intentionally belong to `./chronicle doctor` and Grafana, not the React application.",
        "",
        "| Capability | Backend operation | User-facing owner |",
        "|---|---|---|",
    ]
    for item in data["capabilities"]:
        owners = ", ".join(f"`{owner}`" for owner in item["owners"])
        rows.append(f"| `{item['id']}` | {item['backend']} | {owners} |")
    rows.append("")
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--architecture-manifest", type=Path)
    parser.add_argument(
        "--include-optional",
        action="store_true",
        help="check evidence under optional source roots supplied by an explicit platform checkout",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("[ok] self-host capability ownership fixtures passed")
        return 0

    root = (args.root or ROOT).resolve()
    manifest_path = args.manifest or root / "contracts" / "selfhost-capabilities.json"
    architecture_manifest_path = (
        args.architecture_manifest or root / "config" / "architecture-boundaries.json"
    )
    report_path = root / "docs" / "selfhost-capability-ownership.md"
    optional_environment = os.environ.get("CHRONICLE_INCLUDE_OPTIONAL_SOURCE_ROOTS")
    if optional_environment not in (None, "0", "1"):
        parser.error("CHRONICLE_INCLUDE_OPTIONAL_SOURCE_ROOTS must be 0 or 1")
    include_optional = args.include_optional or optional_environment == "1"

    rendered = render(
        load_and_validate(
            root,
            manifest_path,
            architecture_manifest_path,
            include_optional=include_optional,
        )
    )
    if args.write:
        report_path.write_text(rendered)
    elif not report_path.exists() or report_path.read_text() != rendered:
        raise SystemExit("capability report is stale; run: python3 scripts/check-selfhost-capabilities.py --write")
    optional_note = "included" if include_optional else "skipped"
    print(f"self-host capability ownership check passed (optional source roots {optional_note})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
