"""No pipeline may feed a consumer that stops reading before the producer has finished writing.

Under pipefail (`set -o pipefail`, or `SHELL [... "-o", "pipefail" ...]` in a Dockerfile) the
producer of such a pipeline is killed by SIGPIPE while it writes the rest, and its status (141)
becomes the pipeline's: a correct answer is reported as a failure, at random. Seen 2026-11-05 on
Dockerfile.grafana's `go version -m | grep -q` and 2026-11-11 on the launcher's
`host_addrs | grep -qx`, which made `./chronicle up` refuse a healthy host.

The consumers: grep or rg with -q or -m, head, sed with a q command, awk with exit outside END,
and read. Each has a form that reads everything: `grep PATTERN >/dev/null`, `sed -n 1p`,
`sed -n 1,5p`, awk with a flag in place of exit.

The ast-grep rule pipeline-consumer-leaves-early-shell reads shell scripts with the bash grammar.
This test reads as text what that grammar cannot: Dockerfiles, shell blocks in YAML and in the
operator's Python, scripts held in here-documents, and the scripts the grammar gives up on
(selfhost/monitoring/probe.sh and tests/security/selfhost-secret-rotation.sh parse as one error
node in ast-grep 0.42.1)."""

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# One pipe (not ||, not >|), then optional VAR=value words and a directory before the command name.
PIPE = r"(?<![|>])\|(?!\|)&?\s*"
COMMAND = r"(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*(?:/\S*/)?"
CONSUMERS = (
    ("grep -q", re.compile(PIPE + COMMAND + r"(?:[efz]?grep|rg)\s+(?:-[A-Za-z0-9]+\s+)*"
                           r"(?:-[A-Za-z]*[qm][A-Za-z0-9]*|--quiet|--silent|--max-count)(?:[\s=;)]|$)")),
    ("head", re.compile(PIPE + COMMAND + r"head(?:\s|$|[;)])")),
    ("sed q", re.compile(PIPE + COMMAND + r"""g?sed\s[^|]*?(?:['"\s;{]|[0-9$/])q\s*[0-9]*\s*(?:['";}]|$)""")),
    ("awk exit", re.compile(PIPE + COMMAND + r"[gm]?awk\s(?:(?!END)[^|])*\bexit\b")),
    ("read", re.compile(PIPE + r"(?:[{(]\s*)?(?:IFS=\S*\s+)?read(?:\s|$)")),
)
# A producer that never ends by itself (docker logs -f) needs the early exit; its status is then
# tested in the same list.
HANDLED = re.compile(r"PIPESTATUS.*141|141.*PIPESTATUS")
# The ast-grep rule and its cases quote the pattern they describe.
QUOTED_EXAMPLES = ("tests/security/ast-grep/", "tests/security/ast-grep-tests/")
# A consumer that reads everything and keeps the first lines (`sed -n 1p`, `sed -n 1,5p`) or only
# asks whether there is any line (`grep . >/dev/null`). The producer in front of it then runs to
# its end, which costs with the size of what it reads: a directory tree, a log, a history. Such a
# producer stops by itself: `find ... -print -quit`, `git log --max-count=N`, `docker logs --tail N`,
# `grep -R -q`. (`head -n 5 < <(producer)` also stops it, outside any pipeline.)
KEEPS_THE_FIRST = re.compile(r"""\|\s*(?:(?:/\S*/)?g?sed\s+-n\s+["']?1(?:,[^p|"']+)?p|(?:/\S*/)?grep\s+\.\s*>\s*/dev/null)""")
# A stage in between that needs all of its input anyway.
NEEDS_EVERYTHING = re.compile(r"\|\s*(?:sort|tac|wc|tail|uniq -c)\b")
GROWING_PRODUCERS = (
    ("find without -quit", re.compile(r"(?<![\w./-])find\s+(?![^|;]*-quit\b)[^|;]*")),
    ("git log or rev-list without --max-count", re.compile(
        r"(?<![\w./-])git\s+(?:-C\s+\S+\s+)?(?:log|rev-list)\b(?![^|;]*(?:--max-count|\s-n\s*\d|\s-\d+\b))[^|;]*")),
    ("docker, compose or kubectl logs or journalctl without --tail or --since", re.compile(
        r"(?<![\w./-])(?:(?:docker|kubectl)\s+(?:compose\s+)?logs|journalctl)\b(?![^|;]*(?:--tail|--since|--lines|\s-n\s*\d))[^|;]*")),
    ("grep -r", re.compile(r"(?<![\w./-])[ef]?grep\s+(?:[^|;]*\s)?-[A-Za-z]*[rR][A-Za-z]*\s[^|;]*")),
)


def growing_producer_findings(text):
    """(line, producer, text) for a producer whose cost grows with what it reads and that feeds,
    in the same pipeline, a consumer that only keeps the first lines. Comment lines are skipped."""
    found = []
    for number, line in logical_lines(text):
        if line.lstrip().startswith("#"):
            continue
        # Not the end of a command: a quoted `;` or `)`, and the `\;` that ends find's -exec.
        bare = re.sub(r"'[^'|]*'", "''", line).replace("\\;", "  ")
        for name, pattern in GROWING_PRODUCERS:
            for match in pattern.finditer(bare):
                # The rest of this pipeline: up to a `;`, a closing `)` or a `&&`/`||`.
                rest = re.split(r";|\)|&&|\|\|", bare[match.end():], maxsplit=1)[0]
                consumer = KEEPS_THE_FIRST.search(rest)
                if consumer and not NEEDS_EVERYTHING.search(rest[:consumer.start()]):
                    found.append((number, name, line.strip()))
    return found


def logical_lines(text):
    """(first line number, text) with backslash continuations and a trailing `|` joined to the next line."""
    start, held = None, ""
    for number, line in enumerate(text.splitlines(), 1):
        start = start or number
        body = line.rstrip()
        if body.endswith("\\"):
            held += body[:-1] + " "
            continue
        held += body
        if body.endswith("|") and not body.endswith("||") and not body.lstrip().startswith("#"):
            held += " "
            continue
        yield start, held
        start, held = None, ""
    if held:
        yield start, held


def findings(text):
    """Every early-leaving consumer after a pipe: (line, consumer, text). Comment lines are skipped."""
    found = []
    for number, line in logical_lines(text):
        if line.lstrip().startswith("#") or HANDLED.search(line):
            continue
        # A `|` inside a single-quoted pattern is not a pipe: grep -oE '(get|head):'. sed and awk keep
        # their quoted programs, which is where q and exit are.
        bare = re.sub(r"'[^']*'", "''", line)
        for name, pattern in CONSUMERS:
            if pattern.search(line if name in ("sed q", "awk exit") else bare):
                found.append((number, name, line.strip()))
    return found


def dockerfile_findings(text):
    """findings() for the RUN lines under a SHELL that sets pipefail."""
    pipefail, found = False, []
    for number, line in logical_lines(text):
        if line.lstrip().upper().startswith("SHELL"):
            pipefail = "pipefail" in line
        elif pipefail:
            found += [(number, name, source) for _, name, source in findings(line)]
    return found


def tracked(repository=ROOT):
    listed = subprocess.run(["git", "-C", str(repository), "ls-files", "-z"], capture_output=True, text=True, check=True).stdout
    return [repository / name for name in filter(None, listed.split("\0"))
            if (repository / name).is_file() and not (repository / name).is_symlink()]


def is_shell_script(path):
    if path.suffix in (".sh", ".bash"):
        return True
    with path.open("rb") as handle:
        first = handle.readline(200)
    return first.startswith(b"#!") and re.search(rb"\b(?:ba|da|k)?sh\b", first) is not None


def repositories():
    return [ROOT] + [path for path in ROOT.iterdir() if (path / ".git").exists()]


class PipeConsumerTest(unittest.TestCase):
    def test_each_consumer_is_found_and_each_complete_reader_is_not(self):
        for line in ('a | grep -q x', 'a | grep -Eiq x && b', 'if ! a | LC_ALL=C grep -qx "$1"; then', 'a | /usr/bin/grep -q .',
                     'a | grep -E -q x', 'a | grep -m1 x', 'a | grep --quiet x', 'a | rg -qv x', 'x=$(a | head -1)',
                     'a | head -n "$n" | b', 'a | sed 5q', "a | sed -n '/x/{p;q}'", "a | awk '/v/ { print $2; exit }'",
                     'a | read -r v', 'a | { read -r first; }', 'a |\n  grep -q x', 'a \\\n  | grep -q x'):
            with self.subTest(line=line):
                self.assertEqual(1, len(findings(line)), findings(line))
        for line in ('a | grep x >/dev/null', 'a | grep -c x', 'a | sed -n 1p', 'a | sed -n "1,${n}p"', "a | sed 's/x/q/'",
                     "a | awk '{ bad = 1 } END { exit bad }'", 'a | while read -r line; do echo "$line"; done',
                     'grep -q x file', 'head -1 file | cut -f1', '# a | grep -q x', 'a || grep -q x file',
                     'docker logs -f c | grep -m1 ready || [[ "${PIPESTATUS[*]}" == "141 0" ]]'):
            with self.subTest(line=line):
                self.assertEqual([], findings(line))

    def test_a_dockerfile_is_read_only_under_a_pipefail_shell(self):
        self.assertEqual(1, len(dockerfile_findings('SHELL ["/bin/ash", "-o", "pipefail", "-c"]\nRUN a | grep -q x\n')))
        self.assertEqual(1, len(dockerfile_findings('SHELL ["/bin/bash", "-o", "pipefail", "-c"]\nRUN a \\\n    | grep -qE x\n')))
        self.assertEqual(1, len(dockerfile_findings('SHELL ["/bin/bash", "-o", "pipefail", "-c"]\nRUN a | head -1\n')))
        self.assertEqual([], dockerfile_findings('SHELL ["/bin/ash", "-o", "pipefail", "-c"]\nRUN a | grep x >/dev/null\n'))
        self.assertEqual([], dockerfile_findings('RUN a | grep -q x\n'))
        self.assertEqual([], dockerfile_findings('SHELL ["/bin/ash", "-o", "pipefail", "-c"]\nSHELL ["/bin/sh", "-c"]\n'
                                                 'RUN a | grep -q x\n'))

    def test_no_dockerfile_feeds_a_consumer_that_leaves_early_under_pipefail(self):
        offenders = [f"{path.relative_to(ROOT)}:{number}: {line}" for repository in repositories()
                     for path in tracked(repository) if path.name.startswith("Dockerfile")
                     for number, _, line in dockerfile_findings(path.read_text(encoding="utf-8"))]
        self.assertEqual([], offenders)

    def test_no_shell_script_feeds_a_consumer_that_leaves_early(self):
        # Every script, pipefail or not: a library is sourced under its caller's options.
        offenders = [f"{path.relative_to(ROOT)}:{number}: {name}: {line[:160]}" for path in tracked() if is_shell_script(path)
                     for number, name, line in findings(path.read_text(encoding="utf-8", errors="replace"))]
        self.assertEqual([], offenders)

    def test_no_embedded_shell_block_feeds_a_consumer_that_leaves_early_under_pipefail(self):
        # Shell held in YAML (Ansible tasks, Compose commands) and in the operator's own Python
        # (reconcile.py writes the scheduled script), in the files that set pipefail.
        offenders = []
        for path in tracked():
            name = path.relative_to(ROOT).as_posix()
            if name.startswith(QUOTED_EXAMPLES):
                continue
            if path.suffix not in (".yml", ".yaml") and not (path.suffix == ".py" and name.startswith("selfhost/")):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if "pipefail" in text:
                offenders += [f"{name}:{number}: {consumer}: {line[:160]}" for number, consumer, line in findings(text)]
        self.assertEqual([], offenders)

    def test_each_growing_producer_is_found_and_each_one_with_its_own_limit_is_not(self):
        for line in ('find /root /home -xdev -type f -print 2>/dev/null | sed -n 1,20p', 'x="$(find "$d" -type f -name "$n" | sed -n 1p)"',
                     'git -C "$wt" log --format="%h %s" "$tip..HEAD" 2>/dev/null | sed -n 1,50p', 'git rev-list HEAD | sed -n 1p',
                     'log_head=$(docker logs chronicle-falco 2>&1 | sed -n 1,10p || true)', 'docker compose logs backend | sed -n "1,${n}p"',
                     "grep -rn 'x' \"$ROOT/src\" --include='*.kt' 2>/dev/null | grep -v test | sed -n 1,5p",
                     "elif grep -R -E -l \"x\" overlays --exclude='a.yml' | grep . >/dev/null; then",
                     'if grep -rn x \\\n  src | sed -n 1,5p; then'):
            with self.subTest(line=line):
                self.assertEqual(1, len(growing_producer_findings(line)), growing_producer_findings(line))
        for line in ('find "$d" -type f -name "$n" -print -quit', 'find "$d" -name x -print -quit | grep . >/dev/null',
                     'find . -print 2>/dev/null | sort | sed -n 1,5p', 'git -C "$wt" log --max-count=50 --format="%h %s"',
                     'git log -1 --format=%H | sed -n 1p', 'docker logs --tail 10 chronicle-falco 2>&1 | sed -n 1p',
                     'hits="$(head -n 5 < <(grep -rn x src | grep -v test))"', 'grep -R -E -q "x" overlays',
                     'grep -E "^$1=" "$ENV_FILE" | sed -n 1p', 'printf "%s\\n" "$list" | sed -n 1p', '# find / | sed -n 1p',
                     'find . -type f; printf x | sed -n 1p'):
            with self.subTest(line=line):
                self.assertEqual([], growing_producer_findings(line))

    def test_no_reader_of_a_tree_a_log_or_a_history_runs_to_its_end_for_its_first_lines(self):
        # Three pipelines lost their early exit when their consumer was made to read everything
        # (`| head -20` became `| sed -n 1,20p`): `find /root /home`, `docker logs` and `git log`
        # then walked both trees, the whole log and the whole range for a few lines.
        offenders = []
        for path in tracked():
            name = path.relative_to(ROOT).as_posix()
            if name.startswith(QUOTED_EXAMPLES) or name == "tests/quality/test_pipe_consumers.py":
                continue
            if not (is_shell_script(path) or path.suffix in (".yml", ".yaml") or (path.suffix == ".py" and name.startswith("selfhost/"))):
                continue
            offenders += [f"{name}:{number}: {producer}: {line[:160]}" for number, producer, line
                          in growing_producer_findings(path.read_text(encoding="utf-8", errors="replace"))]
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
