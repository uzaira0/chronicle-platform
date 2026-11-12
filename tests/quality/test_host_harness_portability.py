"""Host-side test scripts must run on macOS as well as Linux.

The 2026.11.12 release smoke ran on a Mac and stopped at `setsid: command not found` (util-linux only);
the next steps used `ps --sid` (procps only) and `sed -i 's/…/' FILE`, which BSD sed reads as a backup
suffix followed by a script. The same forms sat in the topology, setup-secrets and backup self-check
suites. Use `python3 -c 'import os, sys; os.setsid(); os.execvp(...)'`, `ps -A -o pgid=`/`pgrep -P`,
and `perl -pi -e` (which also keeps the file's mode) instead.

The deploy security layer then ran on the same Mac and four more suites stopped on a host command:
`touch -d '40 days ago'` (BSD touch: illegal time specification), `env --default-signal=…` (BSD env:
illegal option), `/usr/bin/date`, `/usr/bin/ln` and `/usr/bin/mv` (macOS has them in /bin only), and
`stat -c '%a'` with no BSD form beside it. Use `python3 -c '… os.utime(…)'`, `perl -e '$SIG{…} =
"DEFAULT" …; exec …'`, `$(command -v ln)`, and `stat -c '%a' FILE 2>/dev/null || stat -f '%Lp' FILE`."""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN = {
    'util-linux setsid': re.compile(r'(?m)(?:^|[;&|(]|\bthen|\bdo)\s*setsid\s'),
    'procps ps --sid/--ppid/--pid': re.compile(r'\bps\b[^|\n]*\s--(?:sid|ppid|pid)\b'),
    'GNU sed -i without a suffix': re.compile(r'\bsed\s+-i\s+(?:-E\s+)?[\'"]'),
    'GNU touch -d with a relative date': re.compile(r'\btouch\s+(?:-[A-Za-z]+\s+)*-d\s+[\'"][^\'"\n]*\bago\b'),
    'GNU env signal options': re.compile(r'\benv\s+--(?:default|ignore|block)-signal\b'),
    # /bin on macOS, /usr/bin and /bin on Linux: name the tool through PATH or `command -v`.
    'a /usr/bin path for a tool macOS keeps in /bin': re.compile(
        r'/usr/bin/(?:cat|chmod|cp|date|dd|df|echo|expr|hostname|kill|ln|ls|mkdir|mv|ps|pwd|rm|rmdir|sleep|stty|'
        r'sync|test|bash|sh)\b'),
}
# The suites the deploy security layer runs on the host (tests/security/run-all-security.sh). Scripts
# that run inside a container, or `docker exec … stat -c`, are outside these globs.
HOST_HARNESSES = ('tests/security/selfhost-*.sh', 'tests/security/*-guardrails.sh', 'tests/security/lib/*.sh')
GNU_STAT = re.compile(r'\bstat\s+-c\b')
BSD_STAT = re.compile(r'\bstat\s+-f\b')


def findings(text):
    return [label for label, pattern in FORBIDDEN.items() if pattern.search(text)]


def stat_without_bsd_form(text):
    """Lines that read a file's attributes with GNU `stat -c` and offer no BSD `stat -f` on the same line."""
    return [line.strip() for line in text.splitlines() if GNU_STAT.search(line) and not BSD_STAT.search(line)]


def tracked(*patterns):
    names = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z', '--', *patterns],
                           capture_output=True, text=True, check=True).stdout.split('\0')
    return [name for name in names if name and (ROOT / name).is_file()]


class HostHarnessPortabilityTests(unittest.TestCase):
    def test_no_tracked_shell_script_uses_linux_only_host_commands(self):
        offenders = {}
        for name in tracked('*.sh'):
            found = findings((ROOT / name).read_text(errors='replace'))
            if found:
                offenders[name] = found
        self.assertEqual({}, offenders)

    def test_the_patterns_catch_the_2026_11_6_lines(self):
        # Negative control: each form that failed or would have failed on the Mac is reported.
        for line, label in (
                ('setsid ./chronicle up --no-reconcile >"$RUN_DIR/x.log" 2>&1 &', 'util-linux setsid'),
                ('until ! ps -o pid= --sid "$interrupted_up" >/dev/null; do', 'procps ps --sid/--ppid/--pid'),
                ('  for child in $(ps -o pid= --ppid "$1"); do kill_tree "$child"; done', 'procps ps --sid/--ppid/--pid'),
                ("sed -i 's/^RATE_LIMIT_GUARD_EVENTS=.*/RATE_LIMIT_GUARD_EVENTS=5/' .env", 'GNU sed -i without a suffix'),
                ('sed -i -E "s~^(A|B)=.*~\\1=x~" .env', 'GNU sed -i without a suffix'),
                ('  : >"${PRUNE_DIR}/${name}"; touch -d \'40 days ago\' "${PRUNE_DIR}/${name}"',
                 'GNU touch -d with a relative date'),
                ('    exec /usr/bin/env --default-signal=HUP,INT,TERM "$ROOT_DIR/scripts/flyway-migrate.sh" validate',
                 'GNU env signal options'),
                ('exec /usr/bin/date -u -d "@$FIXTURE_EPOCH" "$@"', 'a /usr/bin path for a tool macOS keeps in /bin'),
                ('exec /usr/bin/${tool} "\\$@"'.replace('${tool}', 'ln'), 'a /usr/bin path for a tool macOS keeps in /bin')):
            with self.subTest(line=line):
                self.assertIn(label, findings(line))
        self.assertEqual([], findings("python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])'"))
        self.assertEqual([], findings("perl -pi -e 's/^A=.*/A=5/' .env"))
        self.assertEqual([], findings('#!/usr/bin/env bash\ntouch -r "$reference" "$file"\n/usr/bin/mktemp -d "$parent/run.XXXXXX"\n'
                                      'exec /usr/bin/perl -e \'exec @ARGV\' "$script"\nexec $(command -v ln) "$@"\n'))

    def test_host_suites_read_file_modes_with_both_stat_forms(self):
        offenders = {}
        for name in tracked(*HOST_HARNESSES):
            found = stat_without_bsd_form((ROOT / name).read_text(errors='replace'))
            if found:
                offenders[name] = found
        self.assertEqual({}, offenders)

    def test_the_stat_check_catches_the_2026_11_6_line(self):
        self.assertEqual(["mode() { stat -c '%a' \"$1\"; }"], stat_without_bsd_form("mode() { stat -c '%a' \"$1\"; }\n"))
        self.assertEqual([], stat_without_bsd_form(
            "mode() { stat -c '%a' \"$1\" 2>/dev/null || stat -f '%Lp' \"$1\"; }\n"
            "[[ \"$(stat -f '%Lp' \"$file\" 2>/dev/null || stat -c '%a' \"$file\")\" == 600 ]]\n"))
        self.assertIn('tests/security/selfhost-cert-init.sh', tracked(*HOST_HARNESSES))


if __name__ == '__main__':
    unittest.main()
