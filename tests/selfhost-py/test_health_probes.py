"""Every long-lived service must have an executable readiness probe."""
from pathlib import Path
import re
import unittest
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[2]


def compose_services():
    paths = [ROOT / "selfhost/docker-compose.yml", *sorted((ROOT / "selfhost/overlays").glob("*.yml"))]
    for path in paths:
        for name, service in (yaml.load(path.read_text(), Loader=yaml.BaseLoader) or {}).get("services", {}).items():
            yield path, name, service


def caddy_blocks(text):
    """Top-level Caddyfile blocks as {address: body}, matched by brace depth (comments dropped)."""
    blocks, depth, name, body = {}, 0, None, []
    for line in (raw.split("#", 1)[0].rstrip() for raw in text.splitlines()):
        if depth == 0 and line.endswith("{"):
            name, body = line[:-1].strip(), []
        elif depth:
            body.append(line.strip())
        depth += line.count("{") - line.count("}")
        if depth == 0 and name is not None:
            blocks[name] = body[:-1]
            name = None
    return blocks


class HealthProbeTests(unittest.TestCase):
    def test_web_readiness_crosses_the_internal_tls_listener_to_backend_readiness(self):
        # The :80 listener answers an empty 200 for any host in own-tls and local-https; only the
        # port-only :8081 TLS listener reaches the backend's readiness endpoint in every variant.
        web = next(service for path, name, service in compose_services()
                   if path.name == "docker-compose.yml" and name == "web")
        url = urlsplit(web["healthcheck"]["test"][-1])
        self.assertEqual(("https", "127.0.0.1", 8081, "/health"), (url.scheme, url.hostname, url.port, url.path))
        snippets = caddy_blocks((ROOT / "selfhost/caddy/snippets.caddy").read_text())
        health = snippets["(chronicle_health)"]
        self.assertIn("rewrite * /chronicle/internal/health/ready", health)
        self.assertIn("reverse_proxy https://backend:8443 {", health)
        variants = sorted((ROOT / "selfhost").glob("Caddyfile.split*"))
        self.assertTrue(variants)
        for variant in variants:
            with self.subTest(variant=variant.name):
                internal = caddy_blocks(variant.read_text())[":8081"]
                self.assertTrue(any(re.fullmatch(r"tls \S+\.pem \S+\.pem", line) for line in internal))
                route = internal[internal.index("route {") + 1:]
                self.assertEqual("import chronicle_health", route[0])
        monitoring = (ROOT / "selfhost/monitoring/probe.sh").read_text()
        internal_probe = next(line for line in monitoring.splitlines() if '"$INTERNAL_HEALTH_URL"' in line)
        self.assertIn('--cacert "$internal_ca"', internal_probe)
        self.assertIn("== 204 ]]", internal_probe)
        self.assertNotIn(" -k", internal_probe)


    def test_no_prose_waivers_replace_readiness(self):
        for path, name, service in compose_services():
            with self.subTest(path=path.name, service=name):
                self.assertNotIn("x-no-healthcheck", service)

    def test_static_probes_are_initialized_and_mounted_read_only(self):
        found = 0
        for path, name, service in compose_services():
            test = service.get("healthcheck", {}).get("test", [])
            if test[:2] != ["CMD", "/probe/busybox"]:
                continue
            found += 1
            with self.subTest(path=path.name, service=name):
                self.assertEqual("service_completed_successfully",
                                 service["depends_on"]["health-probe"]["condition"])
                self.assertIn("health_probe:/probe:ro", service["volumes"])
                self.assertEqual("wget", test[2])
        self.assertGreater(found, 0)


if __name__ == "__main__":
    unittest.main()
