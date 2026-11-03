"""Negative WAF evidence requires the same authenticated route to work first."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WafControlTests(unittest.TestCase):
    def test_authentication_and_throttling_cannot_satisfy_attack_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            script = work / 'test-waf.sh'
            shutil.copyfile(ROOT / 'tests/security/test-waf.sh', script)
            shutil.copytree(ROOT / 'tests/security/lib', work / 'lib')
            (work / 'docker').write_text('#!/bin/sh\nprintf "fixture-crowdsec\\n"\n')
            (work / 'curl').write_text('''#!/usr/bin/env python3
import os,sys
a=sys.argv[1:];url=a[-1];mode=os.environ['WAF_STATUS']
assert 'Authorization: Bearer fixture' in a
attack='?' in url or 'passwd' in url or '%00' in url or '-d' in a
print(('403' if attack else '200') if mode=='controlled' else mode,end='')
''')
            for command in ('docker', 'curl'):
                (work / command).chmod(0o755)
            for mode in ('controlled', '200', '401', '403', '429', '500'):
                with self.subTest(mode=mode):
                    result = subprocess.run(['bash', str(script)], text=True, capture_output=True, timeout=10,
                        env=dict(os.environ, PATH=str(work) + os.pathsep + os.environ['PATH'],
                                 BASE_URL='https://fixture.invalid', AUTH_TOKEN='fixture', WAF_STATUS=mode))
                    self.assertEqual(mode == 'controlled', result.returncode == 0, result.stdout + result.stderr)
                    if mode in ('401', '429'):
                        self.assertNotIn('[PASS]', result.stdout)


if __name__ == '__main__':
    unittest.main()
