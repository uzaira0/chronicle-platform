"""Exercise the shipped browser runner with isolated command failures."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WebE2ERunnerTests(unittest.TestCase):
    def test_backend_and_browser_failures_propagate_and_completion_always_closes_the_backend(self):
        for backend_status, browser_status in ((0, 0), (6, 0), (0, 17)):
            with self.subTest(backend=backend_status, browser=browser_status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "scripts").mkdir()
                (root / "chronicle-web").mkdir()
                commands = root / "commands"
                commands.mkdir()
                shutil.copyfile(ROOT / "scripts/run-web-e2e.sh", root / "scripts/run-web-e2e.sh")
                scripts = {
                    root / "gradlew": '''#!/usr/bin/env bash
set -eu
[[ -d "$GRADLE_USER_HOME" ]] || exit 19
[[ "$BACKEND_STATUS" == 0 ]] || exit "$BACKEND_STATUS"
for argument in "$@"; do
 case "$argument" in -Dchronicle.playwright.backend.doneFile=*) done_file="${argument#*=}";; esac
done
touch "$READY_PATH"
until [[ -f "$done_file" ]]; do sleep 0.25; done
touch "$FINISHED_PATH"
''',
                    commands / "curl": '#!/usr/bin/env bash\n[[ -f "$READY_PATH" ]]\n',
                    commands / "bunx": '#!/usr/bin/env bash\nexit "$BROWSER_STATUS"\n',
                }
                for path, script in scripts.items():
                    path.write_text(script)
                    path.chmod(0o755)
                result = subprocess.run(["bash", str(root / "scripts/run-web-e2e.sh")],
                    env=dict({key: value for key, value in os.environ.items() if key != "GRADLE_USER_HOME"}, PATH=str(commands) + os.pathsep + os.environ["PATH"],
                             TMPDIR=str(root),
                             BACKEND_STATUS=str(backend_status), BROWSER_STATUS=str(browser_status),
                             READY_PATH=str(root / "ready"), FINISHED_PATH=str(root / "finished")),
                    text=True, capture_output=True, timeout=10)
                self.assertEqual(backend_status or browser_status, result.returncode, result.stdout + result.stderr)
                self.assertEqual(backend_status == 0, (root / "finished").exists())


if __name__ == "__main__":
    unittest.main()
