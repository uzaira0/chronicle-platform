"""Harnesses that write a self-host .env without setup supply every setting setup would write.

Compose refuses to start when a `${NAME:?...}` variable is unset, and .env.example leaves some of them
for setup to choose (retention, the operator UID/GID, the core network prefix). 5feb26e9 made
CHRONICLE_CORE_PREFIX one of them and updated the smoke, bundle, matrix and verify-secrets harnesses,
but not tests/deployment/selfhost-topology.sh; the 2026.11.12 release smoke then failed in its topology
layer with "required variable CHRONICLE_CORE_PREFIX is missing a value". The list is computed from the
Compose files and the template, so a new setup-chosen setting is caught the same way."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SELFHOST = ROOT / 'selfhost'
# Each writes .env from .env.example itself instead of running ./chronicle setup.
HARNESSES = ('tests/deployment/selfhost-topology.sh', 'tests/security/selfhost-release-bundle.sh',
             'tests/security/selfhost-combination-matrix.sh')


def setup_chosen_settings():
    required = set()
    for compose in [SELFHOST / 'docker-compose.yml', *sorted((SELFHOST / 'overlays').glob('*.yml'))]:
        required |= set(re.findall(r'\$\{([A-Z_][A-Z0-9_]*):\?', compose.read_text()))
    template = dict(re.findall(r'(?m)^([A-Z_][A-Z0-9_]*)=(.*)$', (SELFHOST / '.env.example').read_text()))
    return sorted(name for name in required if not template.get(name))


class HarnessRequiredSettingTests(unittest.TestCase):
    def test_the_template_leaves_the_core_prefix_to_setup(self):
        self.assertIn('CHRONICLE_CORE_PREFIX', setup_chosen_settings())

    def test_every_harness_that_writes_env_supplies_each_setup_chosen_setting(self):
        settings = setup_chosen_settings()
        missing = {name: [setting for setting in settings if setting not in (ROOT / name).read_text()]
                   for name in HARNESSES}
        self.assertEqual({}, {name: names for name, names in missing.items() if names})


if __name__ == '__main__':
    unittest.main()
