"""The host curl rule also scans the extensionless operator launcher."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULE = "selfhost-shell-http-ignores-proxy-environment"


class ProxyRuleDiscoveryTest(unittest.TestCase):
    def test_extensionless_launcher_is_scanned_with_the_real_project_configuration(self):
        scratch = ROOT / "build/operator-test-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            project = Path(directory)
            shutil.copyfile(ROOT / "sgconfig.yml", project / "sgconfig.yml")
            rules = project / "tests/security/ast-grep"
            rules.mkdir(parents=True)
            shutil.copyfile(ROOT / "tests/security/ast-grep" / (RULE + ".yml"), rules / (RULE + ".yml"))
            launcher = project / "selfhost/chronicle"
            launcher.parent.mkdir()
            for command, expected in (("curl --max-time 10 \"$url\"", 1),
                                      ("curl --noproxy '*' --max-time 10 \"$url\"", 0)):
                launcher.write_text("#!/usr/bin/env bash\n" + command + "\n")
                result = subprocess.run(["ast-grep", "scan", "--config", str(project / "sgconfig.yml"),
                                         "--json=compact", "."], cwd=project,
                                        capture_output=True, text=True, check=False, timeout=30)
                findings = json.loads(result.stdout)
                self.assertEqual(expected, len(findings), result.stderr)
                if expected:
                    self.assertEqual(RULE, findings[0]["ruleId"])


if __name__ == "__main__":
    unittest.main()
