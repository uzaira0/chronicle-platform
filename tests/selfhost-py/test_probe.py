from pathlib import Path
import os
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SETTINGS = ('DASHBOARD_BASE_URL', 'INTERNAL_BIND', 'INTERNAL_PORT', 'INTERNAL_HEALTH_URL', 'DOMAIN')


def probe(script, *args, **settings):
    """Source probe.sh (functions and settings only) and run script the way collect() does."""
    environment = {key: value for key, value in os.environ.items() if key not in SETTINGS}
    environment.update(settings, POSTGRES_PASSWORD='fixture', PYTHONPATH=str(ROOT / 'selfhost'),
                       PROBE_SCRIPT=str(ROOT / 'selfhost/monitoring/probe.sh'))
    return subprocess.run(['bash', '-c', 'source "$PROBE_SCRIPT"\n' + script, 'probe', *args],
                          env=environment, capture_output=True, text=True, check=True).stdout


class ProbeTests(unittest.TestCase):
    def test_served_certificates_require_trust_identity_and_convert_expiry(self):
        stubs = '''
DOMAIN=configured
timeout() { shift; "$@"; }
openssl() {
  if [[ "$1" == s_client ]]; then
    shift
    [[ "$*" == "$EXPECTED_CONNECT" ]] || return 1
    printf 'served\\n'
  else
    read -r certificate
    [[ "$certificate" == served ]] || return 1
    printf 'notAfter=PUBLIC_EXPIRY\\n'
  fi
}
date() {
  case "$2" in
    PUBLIC_EXPIRY) printf 1900000000 ;;
    *) return 1 ;;
  esac
}
'''
        for url, connect in (
            ("https://host.test/path?q=1#fragment", "host.test:443 -servername host.test"),
            ("https://host.test:8443/study", "host.test:8443 -servername host.test"),
            ("https://192.168.0.1", "192.168.0.1:443 -noservername"),
            ("https://[fd00::1]", "[fd00::1]:443 -noservername"),
            ("https://[fd00::1]:8443", "[fd00::1]:8443 -noservername"),
        ):
            with self.subTest(url=url):
                script = stubs + 'EXPECTED_CONNECT="$2"; printf %s "$(public_tls_expiry "$1")"'
                self.assertEqual(probe(script, url, "-verify_return_error -connect " + connect + (" -verify_ip " if " -noservername" in connect else " -verify_hostname ") + ("fd00::1" if "fd00" in url else "192.168.0.1" if "192.168" in url else "host.test")),
                                 "1900000000")
        # No certificate measured prints nothing, so the sample is dropped rather than read as expiry 0.
        for command, expected in (("certificate_expiry </dev/null", ""),
                                  ("public_tls_expiry http://host.test", ""),
                                  ("DOMAIN=unknown; public_tls_expiry https://host.test", "")):
            with self.subTest(command=command):
                self.assertEqual(probe(stubs + f'printf %s "$({command})"'), expected)
        expected = '-verify_return_error -connect web:8081 -servername management.example.org -verify_hostname management.example.org -partial_chain -CAfile retained.crt'
        script = stubs + 'EXPECTED_CONNECT="$1"; printf %s "$(public_tls_expiry https://management.example.org:8443 retained.crt web:8081)"'
        self.assertEqual(probe(script, expected), '1900000000')

    def test_management_probe_keeps_configured_identity_and_maps_container_port(self):
        script = 'printf "%s\\n%s" "$INTERNAL_HEALTH_URL" "$INTERNAL_CONNECT"'
        for settings, expected in (({'DASHBOARD_BASE_URL': 'https://management.example.org:8443'},
                                    'https://management.example.org:8443/health\nmanagement.example.org:8443:web:8081'),
                                   ({'INTERNAL_BIND': 'fd42::1', 'INTERNAL_PORT': '8443'},
                                    'https://[fd42::1]:8443/health\n[fd42::1]:8443:web:8081')):
            self.assertEqual(probe(script, **settings), expected)
