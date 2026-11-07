"""The ast-grep proxy rules for operator Python agree with config_inventory.proxy_violations.

proxy_violations (run by verify-config.sh) owns the exceptions (PROXY_USERS): the release fetcher's curl
and egress.py's destination probe must honour HTTPS_PROXY, every other curl must pass --noproxy '*'. A curl
rule without those exceptions fails what verify-config.sh requires, so the two checks could never both pass."""

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
RULES = ("selfhost-http-ignores-proxy-environment", "selfhost-curl-ignores-proxy-environment")
PROXIED_CURL = 'run(["curl", "--fail", "--max-time", "10", url], check=True)\n'
BYPASSING_CURL = 'run(["curl", "--noproxy", "*", "--max-time", "10", url], check=True)\n'


def release_fetcher() -> str:
    source = (ROOT / "selfhost/chronicle_ops/config_inventory.py").read_text()
    return "selfhost/" + re.search(r"^RELEASE_FETCHER = '([^']+)'", source, re.M).group(1)


def proxy_users() -> list[str]:
    sys.path.insert(0, str(ROOT / "selfhost"))
    from chronicle_ops.config_inventory import PROXY_USERS
    return sorted("selfhost/" + path for path in PROXY_USERS)


class SelfhostPythonProxyRulesTest(unittest.TestCase):
    def scan(self, files: dict[str, str]) -> list[tuple[str, str]]:
        scratch = ROOT / "build/operator-test-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            project = Path(directory)
            shutil.copyfile(ROOT / "sgconfig.yml", project / "sgconfig.yml")
            rules = project / "tests/security/ast-grep"
            rules.mkdir(parents=True)
            for rule in RULES:
                shutil.copyfile(ROOT / "tests/security/ast-grep" / (rule + ".yml"), rules / (rule + ".yml"))
            for name, text in files.items():
                (project / name).parent.mkdir(parents=True, exist_ok=True)
                (project / name).write_text(text)
            result = subprocess.run(["ast-grep", "scan", "--config", str(project / "sgconfig.yml"),
                                     "--json=compact", "."], cwd=project,
                                    capture_output=True, text=True, check=False, timeout=30)
            self.assertTrue(result.stdout.strip(), result.stderr)
            return sorted((finding["file"], finding["ruleId"]) for finding in json.loads(result.stdout))

    def test_the_release_fetcher_may_use_the_proxy_and_every_other_curl_may_not(self):
        fetcher = release_fetcher()
        probe = "selfhost/chronicle_ops/verify.py"
        self.assertEqual([(probe, "selfhost-curl-ignores-proxy-environment")],
                         self.scan({fetcher: PROXIED_CURL, probe: PROXIED_CURL}))
        self.assertEqual([], self.scan({fetcher: PROXIED_CURL, probe: BYPASSING_CURL}))

    def test_the_egress_destination_probe_may_use_the_proxy(self):
        self.assertEqual([], self.scan({"selfhost/chronicle_ops/egress.py": PROXIED_CURL}))

    def test_the_release_fetcher_is_still_checked_for_urllib(self):
        fetcher = release_fetcher()
        self.assertEqual([(fetcher, "selfhost-http-ignores-proxy-environment")],
                         self.scan({fetcher: "from urllib.request import urlopen\nurlopen(request)\n"}))

    def test_the_exception_is_the_one_config_inventory_names(self):
        rules = {rule: yaml.safe_load((ROOT / "tests/security/ast-grep" / (rule + ".yml")).read_text())
                 for rule in RULES}
        self.assertIn(release_fetcher(), proxy_users())
        self.assertEqual(proxy_users(), sorted(rules["selfhost-curl-ignores-proxy-environment"]["ignores"]))
        self.assertNotIn("ignores", rules["selfhost-http-ignores-proxy-environment"])


if __name__ == "__main__":
    unittest.main()
