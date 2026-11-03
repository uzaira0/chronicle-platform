#!/usr/bin/env python3
"""Compare the fresh ontology projection with the Android open module registry."""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "chronicle/app/src/open/assets/approved-module-registry.json"


def check_registry(registry_path: Path) -> int:
    contract = json.loads((ROOT / "generated/domain-contracts/chronicle-domain-contracts.json").read_text())
    source = contract["sourceFiles"]["linkml"]
    if hashlib.sha256((ROOT / source["path"]).read_bytes()).hexdigest() != source["sha256"]:
        raise ValueError("Ontology projection is stale; run scripts/generate-chronicle-contracts.py")
    ontology_ids = set(contract["contracts"]["playStoreBuildCollectionModuleIds"])
    registry = json.loads(registry_path.read_text())
    registry_ids = {module["id"] for module in registry["modules"]}
    difference = ontology_ids ^ registry_ids
    if difference:
        print(f"FAIL: Play Store module symmetric difference: {sorted(difference)}", file=sys.stderr)
        return 1
    print(f"PASS: Ontology Play Store modules match the Android open registry ({len(ontology_ids)} ids)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    result = check_registry(args.registry)
    if result or not args.self_test:
        return result

    registry = json.loads(args.registry.read_text())
    removed = registry["modules"].pop()["id"]
    with tempfile.TemporaryDirectory(prefix="play-store-registry-") as directory:
        missing_id_registry = Path(directory) / "registry.json"
        missing_id_registry.write_text(json.dumps(registry))
        probe = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--registry", str(missing_id_registry)],
            capture_output=True,
            text=True,
            check=False,
        )
    if probe.returncode != 1 or removed not in probe.stderr:
        print(f"FAIL: Removing {removed} did not report registry drift", file=sys.stderr)
        return 1
    print(f"PASS: Negative self-test rejects a registry missing {removed}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
