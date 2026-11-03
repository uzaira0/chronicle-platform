"""Check declared healthcheck execution with an isolated Docker command boundary."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('healthcheck_executables', ROOT / 'tests/security/healthcheck-executables.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class HealthcheckExecutableTests(unittest.TestCase):
    def test_shell_commands_and_busybox_applets_must_exist(self):
        with tempfile.TemporaryDirectory() as folder:
            busybox = Path(folder) / 'busybox'
            busybox.write_text('#!/bin/sh\ncase "$1" in true|--help) exit 0;; *) exit 127;; esac\n')
            busybox.chmod(0o755)
            for test, fails in ((['CMD-SHELL', 'exit 1'], False),
                                (['CMD-SHELL', 'chronicle_missing_probe_executable'], True),
                                (['CMD', '/probe/busybox', 'true'], False),
                                (['CMD', '/probe/busybox', 'chronicle_missing_applet'], True)):
                with self.subTest(test=test):
                    execution = []
                    state = {}

                    def docker(arguments, **_options):
                        if arguments[:3] == ['docker', 'image', 'inspect']:
                            return subprocess.CompletedProcess(arguments, 0, json.dumps(['/bin/sh', '-c']) if 'Shell' in arguments[4] else 'sha256:fixture')
                        if arguments[:2] == ['docker', 'create']:
                            index = arguments.index('--entrypoint')
                            program = arguments[index + 1]
                            execution[:] = [str(busybox) if program == '/probe/busybox' else program, *arguments[index + 3:]]
                        if arguments[:2] == ['docker', 'start']:
                            result = subprocess.run(execution, capture_output=True, timeout=5, check=False)
                            state.update(Status='exited', Error='', ExitCode=result.returncode)
                        if arguments[:2] == ['docker', 'inspect']:
                            return subprocess.CompletedProcess(arguments, 0, json.dumps(state))
                        return ''

                    with patch.object(checker, 'run', side_effect=docker):
                        service = dict(image='fixture', healthcheck=dict(test=test))
                        if fails:
                            with self.assertRaises(ValueError):
                                checker.verify_program(service, (busybox, '/probe/busybox'))
                        else:
                            checker.verify_program(service, (busybox, '/probe/busybox'))
