"""Release image fixtures release every owned tag, including failed builds."""
import subprocess
import unittest
from unittest.mock import patch

import test_release_images as image_suite


class ReleaseImageCleanupTests(unittest.TestCase):
    def test_class_cleanup_removes_tags_after_success_and_partial_setup_failure(self):
        fixture = image_suite.ReleaseImageTests
        for fails in (False, True):
            calls = []
            built = []

            def command(arguments, **_options):
                if arguments[0] == 'git':
                    return b''
                arguments = tuple(arguments[1:])
                calls.append(arguments)
                if arguments[:2] == ('build', '-q'):
                    if fails and built:
                        raise subprocess.CalledProcessError(1, 'docker')
                    built.append(arguments[arguments.index('-t') + 1])
                return ''

            with self.subTest(fails=fails), patch.object(image_suite.subprocess, 'check_output', side_effect=command):
                try:
                    if fails:
                        with self.assertRaises(subprocess.CalledProcessError):
                            fixture.setUpClass()
                    else:
                        fixture.setUpClass()
                finally:
                    fixture.doClassCleanups()
                removed = {tag for command in calls if command[:2] == ('image', 'rm') for tag in command[2:]}
                self.assertEqual(set(built), removed)
                self.assertEqual(1 if fails else len(fixture.images), len(built))
