"""Caddy reads {$NAME} placeholders from its container environment, never from .env directly."""
import re
import unittest

import yaml

from test_restore_schemas import ROOT

SELFHOST = ROOT / 'selfhost'
PLACEHOLDER = re.compile(r'\{\$([A-Z0-9_]+)')


def web_environment(path):
    service = ((yaml.safe_load(path.read_text()) or {}).get('services') or {}).get('web') or {}
    environment = service.get('environment') or {}
    return set(environment) if isinstance(environment, dict) else {entry.split('=', 1)[0] for entry in environment}


def entrypoint_exports(path):
    """Variables web's entrypoint exports into Caddy's process environment (read from secret files)."""
    service = ((yaml.safe_load(path.read_text()) or {}).get('services') or {}).get('web') or {}
    script = ' '.join(service.get('entrypoint') or [])
    return set(re.findall(r'\bexport ([A-Z0-9_]+)', script))


class CaddyEnvironmentTests(unittest.TestCase):
    def test_every_caddy_placeholder_reaches_the_web_service(self):
        # A placeholder missing here silently takes its Caddyfile default: POOL_LISTENER_TLS=true
        # once served the pool listener in plain HTTP while every check reported TLS.
        provided = web_environment(SELFHOST / 'docker-compose.yml') | entrypoint_exports(SELFHOST / 'docker-compose.yml')
        for overlay in sorted((SELFHOST / 'overlays').glob('*.yml')):
            provided |= web_environment(overlay)
        sources = sorted(SELFHOST.glob('Caddyfile*')) + [SELFHOST / 'caddy/snippets.caddy']
        missing = {(name, path.name) for path in sources for name in PLACEHOLDER.findall(path.read_text())
                   if name not in provided}
        self.assertEqual(set(), missing)


if __name__ == '__main__':
    unittest.main()
