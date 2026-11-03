import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PortableReleasePathTests(unittest.TestCase):
    def test_publish_commands_require_an_explicit_work_directory(self):
        environment = dict(os.environ)
        environment.pop("CHRONICLE_PUBLISH_WORK", None)
        for script, argument in (("publish.sh", "status"), ("changelog-draft.sh", "2026.11.1")):
            result = subprocess.run(["bash", str(ROOT / "scripts" / script), argument],
                                    env=environment, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("CHRONICLE_PUBLISH_WORK", result.stderr)


if __name__ == "__main__":
    unittest.main()
