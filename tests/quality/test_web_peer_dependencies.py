"""chronicle-web installs no peers (bunfig.toml `peer = false`), so every required peer of a direct
dependency must be installed some other way: as a direct dependency, or as an ordinary dependency of an
installed package. chronicle-web 503ed9aa set `peer = false`; @testing-library/dom, a peer of
@testing-library/react 16, was then missing from every clean install and the dependency gate's web job
failed typecheck with 222 errors (renovate/ast-grep-cli-0.x, 2026-11-08). Workstation checkouts still had
it in an older node_modules."""

import json
import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "chronicle-web"
# Peers deliberately left out, with the reason (bunfig.toml says why for each).
NOT_INSTALLED = {"bun": "bun-plugin-tailwind's peer; installed, its placeholder bin shadows the Bun runtime"}


def lockfile(text: str) -> dict:
    """bun.lock is JSON with trailing commas."""
    return json.loads(re.sub(r",(\s*[}\]])", r"\1", text))


def missing_peers(package: dict, lock: dict) -> list[str]:
    direct = {name for field in ("dependencies", "devDependencies", "optionalDependencies")
              for name in package.get(field, {})}
    entries = {name: entry[2] for name, entry in lock["packages"].items()
               if isinstance(entry, list) and len(entry) > 2 and isinstance(entry[2], dict)}
    ordinary = {dependency for meta in entries.values()
                for field in ("dependencies", "optionalDependencies") for dependency in meta.get(field, {})}
    missing = []
    for name in sorted(direct & entries.keys()):
        meta = entries[name]
        optional = set(meta.get("optionalPeers", []))
        for peer in meta.get("peerDependencies", {}):
            if peer not in direct | ordinary | optional | NOT_INSTALLED.keys():
                missing.append(f"{name} needs {peer}")
    return missing


class WebPeerDependencyTests(unittest.TestCase):
    def test_every_required_peer_of_a_direct_dependency_is_installed(self):
        bunfig = tomllib.loads((WEB / "bunfig.toml").read_text())
        if bunfig.get("install", {}).get("peer", True):
            self.skipTest("chronicle-web installs peers")
        package = json.loads((WEB / "package.json").read_text())
        self.assertEqual([], missing_peers(package, lockfile((WEB / "bun.lock").read_text())))

    def test_the_rule_names_a_peer_nothing_installs(self):
        lock = {"packages": {
            "@testing-library/react": ["@testing-library/react@16.3.3", "", {
                "peerDependencies": {"@testing-library/dom": "^10", "@types/react": "^19", "react": "^19"},
                "optionalPeers": ["@types/react"]}, ""],
            "@axe-core/playwright": ["@axe-core/playwright@4.11.1", "", {"peerDependencies": {"playwright-core": "*"}}, ""],
            "playwright": ["playwright@1.56.1", "", {"dependencies": {"playwright-core": "1.56.1"}}, ""],
            "bun-plugin-tailwind": ["bun-plugin-tailwind@0.1.2", "", {"peerDependencies": {"bun": "*"}}, ""],
        }}
        package = {"dependencies": {"react": "^19"},
                   "devDependencies": {"@testing-library/react": "^16", "@axe-core/playwright": "^4",
                                       "playwright": "^1", "bun-plugin-tailwind": "^0.1"}}
        self.assertEqual(["@testing-library/react needs @testing-library/dom"], missing_peers(package, lock))
        package["devDependencies"]["@testing-library/dom"] = "^10"
        self.assertEqual([], missing_peers(package, lock))


if __name__ == "__main__":
    unittest.main()
