"""Under `SHELL [... "-o", "pipefail" ...]`, `producer | grep -q pattern` fails the build at random:
grep -q exits at the first match, the producer gets SIGPIPE writing the rest (exit 141), and pipefail
reports the pipeline as failed. Seen 2026-11-05 on Dockerfile.grafana's `go version -m | grep -q`.
Use `grep pattern >/dev/null`, which reads all input."""

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PIPE_GREP_Q = re.compile(r"\|\s*grep\s+(?:-\w*q\w*|--quiet|--silent)\b")


def dockerfiles():
    for repository in [ROOT] + [path for path in ROOT.iterdir() if (path / ".git").exists()]:
        listed = subprocess.run(["git", "-C", str(repository), "ls-files", "-z"],
                                capture_output=True, text=True, check=True).stdout
        for name in filter(None, listed.split("\0")):
            if Path(name).name.startswith("Dockerfile") and (repository / name).is_file():
                yield repository / name


def findings(text):
    pipefail = False
    found = []
    for number, line in enumerate(text.replace("\\\n", " ").splitlines(), 1):
        if line.lstrip().upper().startswith("SHELL"):
            pipefail = "pipefail" in line
        elif pipefail and PIPE_GREP_Q.search(line):
            found.append((number, line.strip()))
    return found


class DockerfilePipeGrepTest(unittest.TestCase):
    def test_rule_flags_grep_q_after_a_pipe_only_under_pipefail(self):
        self.assertEqual(1, len(findings('SHELL ["/bin/ash", "-o", "pipefail", "-c"]\nRUN a | grep -q x\n')))
        self.assertEqual(1, len(findings('SHELL ["/bin/bash", "-o", "pipefail", "-c"]\nRUN a \\\n    | grep -qE x\n')))
        self.assertEqual([], findings('SHELL ["/bin/ash", "-o", "pipefail", "-c"]\nRUN a | grep x >/dev/null\n'))
        self.assertEqual([], findings('RUN a | grep -q x\n'))
        self.assertEqual([], findings('SHELL ["/bin/ash", "-o", "pipefail", "-c"]\nSHELL ["/bin/sh", "-c"]\n'
                                      'RUN a | grep -q x\n'))

    def test_no_dockerfile_pipes_into_grep_q_under_pipefail(self):
        offenders = [f"{path.relative_to(ROOT)}: {line}" for path in dockerfiles()
                     for _, line in findings(path.read_text(encoding="utf-8"))]
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
