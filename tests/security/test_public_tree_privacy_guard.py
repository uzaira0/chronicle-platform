"""The public-tree privacy guard reads each line after removing two kinds of public identifier.

The 2026.11.12 gate run failed on two lines. One was a release note that gave the institution's
privacy page by its address, a real finding. The other was the rpm-md XML namespace in
scripts/os_packages.py, which the hostname rule read as a deployment host. The namespace is now
removed from a line as a whole token before the rules run; anything else on the line is still read."""
import importlib.util
import unittest
from pathlib import Path

GUARD = Path(__file__).with_name('public-tree-privacy-guardrails.py')
spec = importlib.util.spec_from_file_location('public_tree_privacy_guardrails', GUARD)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

HOSTNAME = 'institution-deployment-hostname'
LABEL = 'institution-deployment-label'
# Assembled here so that this file does not contain what the guard rejects.
INSTITUTION = 'b' + 'cm'
UNIVERSITY_HOST = 'study.research-university.' + 'edu'


class LineFindingsTests(unittest.TestCase):
    def test_the_rpm_metadata_namespaces_are_not_deployment_hosts(self):
        line = ("    namespace = {'r': 'http://linux.duke.edu/metadata/repo', "
                "'c': 'http://linux.duke.edu/metadata/common'}")
        self.assertEqual([], guard.line_findings('scripts/os_packages.py', line))
        self.assertEqual([], guard.line_findings('scripts/os_packages.py',
                                                 'xmlns:rpm="http://linux.duke.edu/metadata/rpm"'))

    def test_only_the_whole_namespace_is_removed(self):
        for line in ("get('http://linux.duke.edu/metadata/repository-mirror')",
                     "get('http://linux.duke.edu/downloads')",
                     "get('https://linux.duke.edu/metadata/repo')",
                     f"NS = 'http://linux.duke.edu/metadata/repo'; HOST = 'https://{UNIVERSITY_HOST}'"):
            with self.subTest(line=line):
                self.assertEqual([HOSTNAME], guard.line_findings('scripts/os_packages.py', line))

    def test_an_institution_address_in_release_notes_is_a_label_finding(self):
        # The line the 2026.11.12 run reported at CHANGELOG.md:384.
        line = f'- Privacy policy link: https://www.{INSTITUTION}.edu/privacy everywhere.'
        self.assertEqual([LABEL], guard.line_findings('CHANGELOG.md', line))
        self.assertEqual([HOSTNAME, LABEL], guard.line_findings('selfhost/README.md', line))

    def test_the_play_application_id_is_still_the_only_use_of_that_name_allowed(self):
        package = f'com.{INSTITUTION}.chronicle'
        self.assertEqual([], guard.line_findings('README.md', f'The application ID {package} is the one on Play.'))
        self.assertEqual([LABEL], guard.line_findings('README.md', f'{package} is published by {INSTITUTION.upper()}.'))

    def test_an_operational_uuid_is_reported_next_to_a_namespace(self):
        line = "ns = 'http://linux.duke.edu/metadata/repo'  # 11111111-2222-4333-8444-555555555555"
        self.assertEqual(['embedded-operational-uuid'], guard.line_findings('scripts/os_packages.py', line))


class TreeTests(unittest.TestCase):
    def test_the_tracked_tree_has_no_finding(self):
        self.assertEqual(0, guard.main())


if __name__ == '__main__':
    unittest.main()
