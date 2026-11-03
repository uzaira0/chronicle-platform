"""Run shipped edge route decisions against disposable, bounded proxy containers."""

from contextlib import contextmanager
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "selfhost"))
from chronicle_ops.route_surface import PUBLIC_SURFACE, RETIRED_PREFIXES
from test_caddy_body_limit import BODY_DEADLINE_SECONDS

CONFIG_PATH = "/fixture/config"
CADDY_IMAGE = os.environ.get("SELFHOST_CADDY_TEST_IMAGE", "chronicle-selfhost-caddy:test")


def docker(*args):
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True).stdout.strip()


def request(base, path, method="GET"):
    try:
        with urlopen(Request(base + path, method=method, headers={"Host": "localhost"}), timeout=3) as response:
            return response.status, response.read()
    except HTTPError as response:
        with response:
            return response.code, response.read()


def retired_paths():
    for prefix in RETIRED_PREFIXES:
        for suffix in ("", "/", "/x", "/app.js", "/style.css"):
            yield prefix + suffix
    yield RETIRED_PREFIXES[1].replace("v2", "%76%32") + "/x"
    for prefix in RETIRED_PREFIXES:
        yield prefix.replace("/chronicle/", "/chronicle%2f") + "/x"
        yield "/" + (prefix + "/x")[1:].replace("/", "%2F")


@contextmanager
def proxy(image, network, config, *command, aliases=(), started=None):
    name = "chronicle-route-test-" + uuid.uuid4().hex[:12]
    if started is not None:
        started.append(name)
    alias_args = [entry for alias in aliases for entry in ("--network-alias", alias)]
    try:
        docker("run", "-d", "--name", name, "--memory=512m", "--memory-swap=512m",
               "--network", network, *alias_args,
               "-p", "127.0.0.1::8080", "-v", f"{config}:{CONFIG_PATH}:ro",
               "-v", f"{config.parent}:/srv:ro", image, *command)
        ports = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Ports}}", name))
        base = "http://127.0.0.1:" + ports["8080/tcp"][0]["HostPort"]
        for _ in range(50):
            try:
                request(base, "/health")
                break
            except (OSError, URLError):
                time.sleep(0.1)
        else:
            raise AssertionError("proxy did not start")
        yield base
    finally:
        docker("rm", "-f", name)


def caddy_handlers(node, handler):
    if isinstance(node, dict) and node.get("handler") == handler:
        yield node
    for child in node.values() if isinstance(node, dict) else node if isinstance(node, list) else ():
        yield from caddy_handlers(child, handler)


def caddy_config(source, *environment):
    adapted = docker("run", "--rm", "--network", "none", "--memory=512m", "--memory-swap=512m",
        "-e", "DOMAIN=localhost", "-e", "DASHBOARD_ALLOWED_IPS=127.0.0.1/32",
        *[entry for setting in environment for entry in ("-e", setting)],
        "-v", f"{source}:/etc/caddy/Caddyfile:ro",
        "-v", f"{ROOT / 'selfhost/caddy/snippets.caddy'}:/etc/caddy/snippets.caddy:ro",
        CADDY_IMAGE, "caddy", "adapt", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
    return json.loads(adapted)


def caddy_public_config(source, *environment, upstream_port=40320):
    config = caddy_config(source, *environment)
    servers = config["apps"]["http"]["servers"]
    # Terminate test HTTP on one port; preserve every adapted public route/handler.
    public_port = ":443" if "tls" in source.name or "local" in source.name else ":8080"
    public = next(server for server in servers.values() if public_port in server["listen"])
    public["listen"] = [":8080"]
    # The shipped hop to the backend is verified TLS; the fixture upstream is plain HTTP.
    proxies = list(caddy_handlers(public, "reverse_proxy"))
    assert proxies, source.name
    for handler in proxies:
        assert handler["upstreams"] == [{"dial": "backend:8443"}], (source.name, handler["upstreams"])
        assert handler["transport"]["tls"]["ca"]["pem_files"] == ["/etc/caddy/backend-tls/backend.crt"], source.name
        handler["upstreams"] = [{"dial": f"backend:{upstream_port}"}]
        del handler["transport"]["tls"]
    public.pop("tls_connection_policies", None)
    public["automatic_https"] = {"disable": True}
    upstream = {"listen": [":40320", ":80"], "routes": [
        {"match": [{"path": ["/chronicle/internal/health/ready"]}], "handle": [{"handler": "static_response", "status_code": 204}]},
        {"handle": [
        {"handler": "static_response", "status_code": 200, "body": "upstream"}]}]}
    config["apps"] = {"http": {"servers": {"public": public, "upstream": upstream}}}
    config["admin"] = {"disabled": True}
    return config


class RouteSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="route-surface-")
        self.addCleanup(self.work.cleanup)
        self.folder = Path(self.work.name)
        self.folder.chmod(0o755)
        (self.folder / "index.html").write_text("frontend")
        self.network = "chronicle-sat-r1-route-test-" + uuid.uuid4().hex[:12]
        self.subnet = subprocess.run([sys.executable, str(ROOT / "selfhost/network-subnet.py"), "select",
                                     "10.251.0.0/24", self.network], check=True, capture_output=True, text=True).stdout.strip()
        docker("network", "create", "--subnet", self.subnet, self.network)
        self.addCleanup(docker, "network", "rm", self.network)

    def test_network_uses_the_selected_subnet(self):
        network = json.loads(docker("network", "inspect", self.network))[0]
        self.assertEqual(self.subnet, network["IPAM"]["Config"][0]["Subnet"])

    def test_every_caddy_variant_and_public_surface_entry(self):
        variants = sorted((ROOT / "selfhost").glob("Caddyfile*"))
        for source in variants:
            with self.subTest(variant=source.relative_to(ROOT)):
                config = self.folder / (source.name + ".json")
                config.write_text(json.dumps(caddy_public_config(source)))
                with proxy(CADDY_IMAGE, self.network, config, "caddy", "run", "--config", CONFIG_PATH, aliases=("backend",)) as base:
                    for route in PUBLIC_SURFACE:
                        status, _ = request(base, route.path)
                        self.assertIn(str(status), route.statuses, (source.name, route.path, status))
                    for path in retired_paths():
                        for method in ("GET", "POST"):
                            status, body = request(base, path, method)
                            self.assertEqual(404, status, (source.name, path, method))
                            self.assertNotIn(b"upstream", body)
                    self.assertEqual(200, request(base, "/chronicle/v3/survey/x/app-usage-frequency")[0])



class CaddyQuotaTests(unittest.TestCase):
    def test_only_pre_authentication_paths_have_edge_quotas(self):
        authenticated = (
            "/chronicle/v4/study/s/participant/p/usage-events",
            "/chronicle/v3/study/s/participant/p/status",
            "/chronicle/v3/study/s/settings/type/DataCollection",
            "/chronicle/v4/mobile/enrollments/current",
            "/chronicle/api/web/study",
            "/chronicle/limits/study/s",
            "/chronicle/v3/auth/session",
            "/chronicle/v3/auth/logout",
            "/chronicle/v3/participant-access/session",
            "/chronicle/v3/survey/s/participant/p/app-usage",
            "/chronicle/studies/s/participants",
        )
        for source in sorted((ROOT / "selfhost").glob("Caddyfile*")):
            config = caddy_config(source)
            for server in config['apps']['http']['servers'].values():
                zones = [zone for handler in caddy_handlers(server, 'rate_limit')
                         for zone in handler['rate_limits'].values()]
                if not zones:
                    self.assertFalse(list(caddy_handlers(server, 'reverse_proxy')),
                                     'application listeners must retain pre-authentication quotas')
                    continue  # Redirect-only listeners have no application traffic.
                paths = []
                for zone in zones:
                    for match in zone['match']:
                        with self.subTest(source=source.name, listen=server['listen'], match=match):
                            self.assertIn('path', match, 'every quota needs an explicit pre-auth route list')
                            paths.extend(match['path'])
                            for path in authenticated:
                                self.assertFalse(any(fnmatchcase(path, pattern) for pattern in match['path']), path)
                for path in ('/chronicle/v3/auth/dashboard-login', '/chronicle/v3/auth/testing-login',
                             '/chronicle/v3/auth/set-cookie', '/chronicle/v4/mobile/reviewer-enrollment',
                             '/chronicle/v4/study/s/participant/p/enroll',
                             '/chronicle/v4/study/s/participant/p/enrollment-preview',
                             '/chronicle/v3/participant-access/exchange'):
                    self.assertTrue(any(fnmatchcase(path, pattern) for pattern in paths), (source.name, path))
                if ':8081' in server['listen']:
                    self.assertIn('/chronicle/login', paths)
                else:
                    self.assertFalse(any(fnmatchcase('/chronicle/login', pattern) for pattern in paths),
                                     'public pages must not acquire a new aggregate quota')
                self.assertEqual(BODY_DEADLINE_SECONDS * 1_000_000_000, server['read_timeout'])


class CaddyLogRedactionTests(unittest.TestCase):
    """Raw Caddy output is what Docker keeps without monitoring; Fluent Bit only sanitizes a downstream copy."""

    def setUp(self):
        RouteSurfaceTests.setUp(self)

    @staticmethod
    def send(base, method, path, headers=(), declared_length=None):
        import http.client
        host, port = base.removeprefix("http://").split(":")
        connection = http.client.HTTPConnection(host, int(port), timeout=10)
        try:
            connection.putrequest(method, path, skip_host=True)
            connection.putheader("Host", "localhost")
            for name, value in headers:
                connection.putheader(name, value)
            if declared_length is not None:
                connection.putheader("Content-Length", str(declared_length))
            connection.endheaders()
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def fluent_bit(self, raw):
        """The shipped parser and Lua filters, fed the way Docker's fluentd driver wraps a line: {"log": line}."""
        import yaml
        # The vendor parent of selfhost/Dockerfile.fluentbit, which changes only libbrotli1.
        image = yaml.safe_load((ROOT / "toolchain-manifest.yaml").read_text())["selfhost_images"]["fluent_bit"]
        source = self.folder / "caddy-raw.log"
        source.write_text("".join(line + "\n" for line in raw))
        source.chmod(0o644)
        name = "chronicle-log-route-" + uuid.uuid4().hex[:12]
        try:
            docker("run", "-d", "--name", name, "--network", "none", "--memory=256m",
                   "-v", f"{source}:/in/caddy.log:ro",
                   "-v", f"{ROOT / 'selfhost/monitoring/sanitize.lua'}:/sanitize.lua:ro",
                   "-v", f"{ROOT / 'selfhost/monitoring/parsers.conf'}:/parsers.conf:ro",
                   image, "/fluent-bit/bin/fluent-bit", "-f", "1", "-R", "/parsers.conf",
                   "-i", "tail", "-p", "path=/in/caddy.log", "-p", "read_from_head=on", "-p", "tag=chronicle.web",
                   "-F", "parser", "-m", "chronicle.*", "-p", "key_name=log", "-p", "parser=chronicle_json",
                   "-p", "reserve_data=true", "-p", "preserve_key=false",
                   "-F", "lua", "-m", "chronicle.*", "-p", "script=/sanitize.lua", "-p", "call=sanitize",
                   "-o", "stdout", "-m", "chronicle.*", "-p", "format=json_lines")
            for _ in range(60):
                output = subprocess.run(["docker", "logs", name], capture_output=True, text=True).stdout
                rows = [json.loads(line) for line in output.splitlines()
                        if line.startswith("{") and '"service":"web"' in line]
                if len(rows) >= len(raw):
                    return output, rows
                time.sleep(0.5)
            raise AssertionError("Fluent Bit emitted %d of %d records:\n%s" % (len(rows), len(raw), output))
        finally:
            docker("rm", "-f", name)

    def test_credentials_and_participant_identifiers_never_reach_raw_or_shipped_logs(self):
        sentinel = {kind: kind + uuid.uuid4().hex[:16] for kind in
                    ("participant", "encoded", "query", "cookie", "bearer", "verifier", "apikey", "escaped")}
        encoded = "%" + format(ord(sentinel["encoded"][0]), "02X") + sentinel["encoded"][1:]
        secret_headers = (("authorization", "Bearer " + sentinel["bearer"]),
                          ("COOKIE", "chronicle_session=" + sentinel["cookie"] + '; quoted="\\' + sentinel["escaped"] + '"'),
                          ("X-Chronicle-Api-Key", sentinel["apikey"]))
        study = str(uuid.uuid4())
        statuses = []
        source = ROOT / "selfhost/Caddyfile.split"
        raw = []
        for upstream_port in (40320, 40399):  # the second dials a closed port: every proxied request is a 502
            config = self.folder / f"logging-{upstream_port}.json"
            config.write_text(json.dumps(caddy_public_config(source, "RATE_LIMIT_MOBILE_ABUSE_EVENTS=2",
                                                             "RATE_LIMIT_MOBILE_WINDOW=60s", upstream_port=upstream_port)))
            started = []
            with proxy(CADDY_IMAGE, self.network, config, "caddy", "run", "--config", CONFIG_PATH, aliases=("backend",),
                       started=started) as base:
                container = started[0]
                first_status = len(statuses)
                survey = "/chronicle/v3/survey/%s/app-usage-frequency?token=%s"
                if upstream_port == 40320:
                    statuses.append(self.send(base, "GET", survey % (sentinel["participant"], sentinel["query"]), secret_headers))
                    statuses.append(self.send(base, "GET", "/chronicle/v3/survey/%s/app-usage-frequency" % encoded, secret_headers))
                    statuses.append(self.send(base, "GET", RETIRED_PREFIXES[0] + "/" + sentinel["participant"] + "?token=" + sentinel["query"],
                                              secret_headers))
                    statuses.append(self.send(base, "POST", f"/chronicle/v4/study/{study}/participant/{sentinel['participant']}/usage-events",
                                              secret_headers, declared_length=67108865))
                    statuses.append(self.send(base, "GET", "/health", (("Authorization", "ChronicleUpdate " + sentinel["verifier"]),)))
                    for _ in range(4):
                        statuses.append(self.send(base, "POST", "/chronicle/v3/participant-access/exchange?code=" + sentinel["query"],
                                                  secret_headers, declared_length=0))
                else:
                    statuses.append(self.send(base, "GET", survey % (sentinel["participant"], sentinel["query"]), secret_headers))
                from collections import Counter
                wanted = Counter(status for status in statuses[first_status:] if status != 204)
                for _ in range(50):
                    logs = subprocess.run(["docker", "logs", container], capture_output=True, text=True)
                    lines = [line for line in (logs.stdout + logs.stderr).splitlines() if line.startswith("{")]
                    recorded = Counter(json.loads(line).get("status") for line in lines)
                    if all(recorded[status] >= count for status, count in wanted.items()):
                        break
                    time.sleep(0.1)
                else:
                    self.fail("Caddy did not flush its access records: " + logs.stdout + logs.stderr)
                raw += lines
        self.assertEqual([200, 200, 404, 413, 204, 200, 200, 429, 429, 502], statuses)
        text = "\n".join(raw)
        for kind, value in sentinel.items():
            self.assertNotIn(value, text, f"raw Caddy log kept the {kind} sentinel")
        self.assertNotIn(encoded, text)
        self.assertNotIn(study, text)
        access = [json.loads(line) for line in raw if '"status"' in line]
        for status in (200, 404, 413, 429, 502):
            self.assertTrue(any(row.get("status") == status for row in access), (status, text))
        self.assertTrue(any(json.loads(line).get("level") == "error" for line in raw), "the 502 left no error evidence")
        self.assertTrue(all(row.get("request", {}).get("method") for row in access), "access rows lost their method")
        output, rows = self.fluent_bit(raw)
        for kind, value in sentinel.items():
            self.assertNotIn(value, output, f"shipped log kept the {kind} sentinel")
        self.assertEqual({"200", "404", "413", "429", "502"}, {row["status"] for row in rows} & {"200", "404", "413", "429", "502"})


if __name__ == "__main__":
    unittest.main()
