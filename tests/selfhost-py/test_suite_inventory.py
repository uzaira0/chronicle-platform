"""Exercise native suite and setting inventories with alternate identifier spellings."""
import importlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/security'))
suites = importlib.import_module('check-suite-inventory')
settings = importlib.import_module('check-setting-readers')


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


class SuiteInventoryTests(unittest.TestCase):
    def test_missing_dispatch_or_orphaned_files_fail_independently_of_iterator_names(self):
        for iterator in ('suite', 'candidate', 'script'):
            with self.subTest(iterator=iterator), tempfile.TemporaryDirectory() as directory:
                # check-suite-inventory runs on a resolved ROOT; macOS temp folders sit behind /var -> /private/var.
                root = Path(directory).resolve()
                ci = '''fast_jobs=(browser)
security_jobs=()
containers_jobs=()
all_jobs=(fast load)
job_browser() { bash "$ROOT_DIR/scripts/browser.sh"; }
job_deployed() { CHRONICLE_E2E_SELFHOST=1 bunx playwright test e2e/selfhost-journey.spec.ts; }
job_load() { for ITERATOR in "$ROOT_DIR"/tests/load/*.js; do k6 run "$ITERATOR"; done; }
dispatch_job() { case "$1" in
 browser) job_browser ;;
 deployed) job_deployed ;;
 load) job_load ;;
 esac; }
'''.replace('ITERATOR', iterator)
                ci_path = write(root, 'scripts/local-ci.sh', ci)
                write(root, 'scripts/browser.sh', 'bunx playwright test --project=desktop-chromium\n')
                write(root, 'tests/smoke/selfhost-release-smoke.sh', '"$ROOT_DIR/scripts/local-ci.sh" deployed\n')
                load = write(root, 'tests/load/probe.js', 'import http from "k6/http";\n')
                normal = write(root, 'chronicle-web/e2e/normal.spec.ts', '')
                write(root, 'chronicle-web/e2e/selfhost-journey.spec.ts', '')
                command = write(root, 'commands/bunx', '''#!/usr/bin/env python3
import json,os
name='selfhost-journey.spec.ts' if os.getenv('CHRONICLE_E2E_SELFHOST')=='1' else 'normal.spec.ts'
print(json.dumps({'suites':[{'file':name}]}))
''')
                command.chmod(0o755)
                with patch.dict(os.environ, PATH=str(command.parent) + os.pathsep + os.environ['PATH']):
                    self.assertEqual(set(), suites.coverage(root))
                    security_probe = write(root, 'tests/security/renamed-probe.js', 'import transport from "k6/http";\n')
                    self.assertEqual({security_probe}, suites.coverage(root))
                    load.write_text('export { default } from "../security/renamed-probe.js";\n')
                    self.assertEqual(set(), suites.coverage(root))
                    load.write_text('import http from "k6/http";\n')
                    security_probe.unlink()
                    for extension, source in (('mjs', 'const alias = require("k6\\x2fhttp");'),
                                              ('cjs', 'import("k6/crypto");')):
                        alternate = write(root, 'tests/security/other-probe.' + extension, source)
                        self.assertEqual({alternate}, suites.coverage(root))
                        alternate.unlink()
                    ci_path.write_text(ci.replace('k6 run "$' + iterator + '";', ': # k6 run "$' + iterator + '"\n'))
                    self.assertEqual({load}, suites.coverage(root))
                    ci_path.write_text(ci)
                    orphan = write(root, 'chronicle-web/e2e/alternate.spec.ts', '')
                    self.assertEqual({orphan}, suites.coverage(root))
                    orphan.unlink()
                    ci_path.write_text(ci.replace('all_jobs=(fast load)', 'all_jobs=(fast)'))
                    self.assertEqual({load}, suites.coverage(root))
                    ci_path.write_text(ci.replace('fast_jobs=(browser)', 'fast_jobs=()'))
                    self.assertIn(normal, suites.coverage(root))

    def test_unread_setting_detection_includes_property_references_and_safe_navigation(self):
        for field in ('deviceUsageThresholdInSeconds', 'otherThreshold', 'alternate_setting'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write(root, 'chronicle-models/src/main/kotlin/Settings.kt',
                      f'data class Settings(val {field}: Int = 1) : StudySetting')
                for relative in ('chronicle-server/src/main', 'chronicle/app/src/main', 'chronicle-web/src/modern'):
                    (root / relative).mkdir(parents=True)
                self.assertEqual([field], [name for _, name in settings.unread_settings(root)])
                source = write(root, 'chronicle-server/src/main/Read.kt', f'val reader = Settings::{field}')
                self.assertEqual([], settings.unread_settings(root))
                source.write_text(f'fun read(settings: Settings?) = settings?.{field}')
                self.assertEqual([], settings.unread_settings(root))


if __name__ == '__main__':
    unittest.main()
