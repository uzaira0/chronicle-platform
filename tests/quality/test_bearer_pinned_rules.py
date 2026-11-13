"""local-ci's bearer job scans with the pinned bearer-rules release and makes no network call.

The job scans twice: once for the SARIF report, with bearer.ignore's waivers, and once with no waiver
for scripts/check-bearer-waivers.py. Both scans use the pinned rules.

`bearer scan` with its default rules looks up the latest bearer-rules release through the unauthenticated
GitHub API on every run and downloads one archive per language without checking the response status. On
2026-11-08 the dependency gate failed on that download twice: renovate/minimatch-11.x with "error loading
remote rules: loading rules failed: gzip: invalid header", the temurin rerun with "0 rules found for
supported language, default rules could not be downloaded". With --disable-default-rules and the version
check off, bearer 2.0.2 skips both its version API and the GitHub lookup (GetScanVersionMeta)."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# local-ci's bearer job with the tool install replaced; the rules step runs with its download stubbed.
# The fake scanner reports no findings, so the comparison of waivers with findings is replaced too
# (tests/quality/test_bearer_waivers.py covers scripts/check-bearer-waivers.py).
DRIVER = '''source "$1"
ensure_bearer() { :; }
python3() { case "$1" in */check-bearer-waivers.py) return 0 ;; *) command python3 "$@" ;; esac; }
download_asset() { printf '%s\\n' "$1" >> "$FAKE_DOWNLOADS"; : > "$2"; }
sha256_check() { printf '%s\\n' "$1" >> "$FAKE_VERIFIED"; }
tar() { :; }
job_bearer
'''
# Records the arguments and the version-check setting of every call, and writes an empty SARIF report
# for the call that asks for one through BEARER_OUTPUT.
END_OF_CALL = '--end-of-call--'
FAKE_BEARER = '''#!/bin/sh
{ printf '%s\\n' "$@"; printf '%s\\n' ''' + END_OF_CALL + '''; } >> "$FAKE_BEARER_ARGS"
printf '%s\\n' "${BEARER_DISABLE_VERSION_CHECK:-unset}" >> "$FAKE_BEARER_VERSION_CHECK"
if [ -n "${BEARER_OUTPUT:-}" ]; then echo '{"runs": [{"results": null}]}' > "$BEARER_OUTPUT"; fi
'''


def manifest_rules() -> tuple[str, dict]:
    out = subprocess.run(['yq', '-o=json', '.gate_tools."bearer-rules"', str(ROOT / 'toolchain-manifest.yaml')],
                         capture_output=True, text=True, check=True).stdout
    pin = json.loads(out)
    return pin['version'], pin['sha256']


class BearerRulesTests(unittest.TestCase):
    def test_the_scan_uses_only_the_pinned_rules_and_no_version_check(self):
        version, digests = manifest_rules()
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'bin').mkdir()
            (base / 'bin/bearer').write_text(FAKE_BEARER)
            (base / 'bin/bearer').chmod(0o755)
            files = {name: base / name for name in ('args', 'version-check', 'downloads', 'verified')}
            environment = dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=str(base / 'bin'),
                               CHRONICLE_LOCAL_CI_REPORT_DIR=str(base / 'reports'),
                               FAKE_BEARER_ARGS=str(files['args']), FAKE_BEARER_VERSION_CHECK=str(files['version-check']),
                               FAKE_DOWNLOADS=str(files['downloads']), FAKE_VERIFIED=str(files['verified']))
            result = subprocess.run(['bash', '-s', str(ROOT / 'scripts/local-ci.sh')], input=DRIVER,
                                    capture_output=True, text=True, timeout=120, check=False, env=environment)
            self.assertEqual(0, result.returncode, result.stderr)
            calls = [call.strip().split('\n') for call in files['args'].read_text().split(END_OF_CALL) if call.strip()]
            rules = base / 'bin' / f'bearer-rules-{version}'
            self.assertEqual(2, len(calls), calls)
            for args in calls:
                self.assertIn('--disable-default-rules', args)
                self.assertEqual(str(rules), args[args.index('--external-rule-dir') + 1])
            self.assertEqual(['--ignore-file' in args for args in calls], [False, True], 'the second scan applies no waiver')
            self.assertEqual(['true', 'true'], files['version-check'].read_text().split())
            # Every language archive of the pinned release, each checked against its committed digest.
            self.assertEqual(sorted(f'https://github.com/Bearer/bearer-rules/releases/download/{version}/{language}.tar.gz'
                                    for language in digests), sorted(files['downloads'].read_text().split()))
            self.assertEqual(sorted(digests.values()), sorted(files['verified'].read_text().split()))
            self.assertTrue((rules / '.verified').is_file())

    def test_the_gate_sandbox_cannot_reach_the_github_api(self):
        # Bearer's rule lookup was the sandbox's only use of the GitHub API.
        allowlist = (ROOT / 'scripts/sandbox/egress-allowlist.txt').read_text().split()
        self.assertNotIn('api.github.com', allowlist)


if __name__ == '__main__':
    unittest.main()
