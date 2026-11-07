"""Exercise first-party release images with no deployment credentials or outbound network."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid

import yaml

from selfhost_fixture import context_sources

ROOT = Path(__file__).resolve().parents[2]


class ReleaseImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix='release-images-')
        cls.addClassCleanup(cls.folder.cleanup)
        cls.work = Path(cls.folder.name)
        cls.images = {name: 'chronicle-u-selfhost-' + name + ':' + uuid.uuid4().hex
                      for name in ('frontend', 'caddy', 'grafana', 'backup')}
        frontend = cls.work / 'frontend'; frontend.mkdir()
        (frontend / 'chronicle-web').mkdir()
        files = subprocess.check_output(['git', '-C', str(ROOT / 'chronicle-web'), 'ls-files', '-z',
                                         '--cached', '--others', '--exclude-standard']).split(b'\0')
        for name in filter(None, files):
            relative = Path(os.fsdecode(name))
            if any(part.startswith('.env') for part in relative.parts) or relative.suffix in ('.key', '.pem', '.p12', '.jks', '.keystore'):
                continue
            source = ROOT / 'chronicle-web' / relative
            if not source.is_file() or source.is_symlink():
                continue
            target = frontend / 'chronicle-web' / relative
            target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(source, target)
        # The rest of what the Dockerfile reads from the root context (LICENSE, the OS-package helper).
        for relative in map(Path, context_sources(ROOT / 'selfhost/Dockerfile.frontend')):
            if relative.parts[0] != 'chronicle-web':
                (frontend / relative).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, frontend / relative)
        shutil.copy2(ROOT / 'selfhost/Dockerfile.frontend', frontend / 'Dockerfile')
        cls.docker('build', '-q', '-t', cls.images['frontend'], str(frontend))
        for name in ('caddy', 'grafana', 'backup'):
            cls.build_sidecar(name)

    @classmethod
    def build_sidecar(cls, name):
        from chronicle_ops.images import SOURCE_IMAGES
        image = next(image for image in SOURCE_IMAGES if image.component == name)
        source = (ROOT / 'selfhost' / image.context).resolve()
        context = cls.work / name; context.mkdir()
        dockerfile = ROOT / 'selfhost' / image.dockerfile
        inputs = [dockerfile.relative_to(source)]
        if name == 'caddy':
            inputs.append(Path('LICENSE'))
        elif name == 'backup':
            inputs += list(map(Path, ('backup-image', 'chronicle_ops', 'init-tde.sh')))
        # The release build sends the whole context (images.SourceImage.archive); include every
        # context file the Dockerfile copies or bind-mounts, so a new COPY (such as Caddy's patch) or a
        # new helper mount (selfhost/os-packages) cannot drift.
        for path in map(Path, context_sources(dockerfile)):
            if (source / path).exists() and not any(path == known or known in path.parents for known in inputs):
                inputs.append(path)
        for relative in inputs:
            target = context / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if (source / relative).is_dir():
                shutil.copytree(source / relative, target, ignore=shutil.ignore_patterns('__pycache__'))
            else:
                shutil.copy2(source / relative, target)
        arguments = ['--build-context', 'chronicle-selfhost-frontend:release=docker-image://' + cls.images['frontend']] if name == 'caddy' else []
        cls.docker('build', '-q', '-f', str(context / dockerfile.relative_to(source)),
                   '-t', cls.images[name], *arguments, str(context))

    @classmethod
    def docker(cls, *arguments):
        try:
            output = subprocess.check_output(['docker', *arguments], stderr=subprocess.STDOUT, text=True, timeout=600)
        except subprocess.CalledProcessError as error:
            # CalledProcessError's message omits the output, which is the only place Docker says why.
            error.add_note(f"docker {' '.join(arguments)} output:\n{(error.output or '')[-4000:]}")
            raise
        if arguments[0] == 'build':
            cls.addClassCleanup(cls.docker, 'image', 'rm', arguments[arguments.index('-t') + 1])
        return output

    def test_serving_image_contains_the_dashboard(self):
        self.docker('run', '--rm', '--network', 'none', '--entrypoint', '/bin/sh', self.images['caddy'],
                    '-ec', 'test -s /srv/index.html; test -s /srv/version.json; test -s /usr/share/doc/chronicle/LICENSE-chronicle-web')

    def test_grafana_registers_the_baked_plugin_without_egress(self):
        services = yaml.safe_load((ROOT / 'selfhost/overlays/monitoring.yml').read_text())['services']
        environment = services['grafana']['environment']
        name = 'chronicle-u-selfhost-grafana-' + uuid.uuid4().hex
        options = [item for key, value in environment.items() if key.startswith(('GF_PLUGINS_', 'GF_PATHS_', 'GF_ANALYTICS_'))
                   for item in ('-e', key + '=' + value)]
        self.docker('run', '-d', '--name', name, '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                    '--memory', '512m', '--tmpfs', '/var/lib/grafana:uid=472,gid=0', '--tmpfs', '/tmp',
                    *options, self.images['grafana'])
        self.addCleanup(self.docker, 'rm', '-fv', name)
        for _ in range(120):
            result = subprocess.run(['docker', 'exec', name, 'curl', '-fsS', 'http://127.0.0.1:3000/api/health'],
                                    capture_output=True, timeout=10)
            if result.returncode == 0:
                break
            time.sleep(0.5)
        self.assertEqual(0, result.returncode, 'Grafana did not start without egress')
        log = self.docker('logs', name)
        datasources = yaml.safe_load((ROOT / 'selfhost/monitoring/grafana-datasources.yml').read_text())['datasources']
        plugin = next(row['type'] for row in datasources if row['uid'] == 'chronicle-victorialogs')
        self.assertIn('pluginId=' + plugin, log)
        self.assertNotIn('Failed to download', log)

    def test_backup_image_runs_its_shipped_verifier_without_a_source_checkout(self):
        self.docker('run', '--rm', '--network', 'none', '--entrypoint', 'python3', self.images['backup'],
                    '-c', 'import chronicle_ops.dump; import selfcheck; assert selfcheck.main(["health"]) == 1')

    def test_final_css_names_and_cache_headers(self):
        css = self.docker('run', '--rm', '--network', 'none', '--entrypoint', '/bin/sh', self.images['frontend'],
                          '-ec', 'find /dist -maxdepth 1 -name "*.css"').strip().splitlines()[0]
        content = subprocess.check_output(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat',
                                           self.images['frontend'], css], timeout=30)
        filename = Path(css).name
        self.assertIn(hashlib.sha256(content).hexdigest()[:8], filename)
        caddyfile = self.work / 'Caddyfile'
        caddyfile.write_text('{\n admin off\n auto_https off\n}\nimport /snippets.caddy\n:8080 {\n import chronicle_security_headers\n import chronicle_spa\n}\n')
        name = 'chronicle-u-selfhost-css-' + uuid.uuid4().hex
        self.docker('run', '-d', '--name', name, '--network', 'none', '--memory', '256m',
                    '--entrypoint', 'caddy', '-v', str(caddyfile) + ':/fixture.caddy:ro',
                    '-v', str(ROOT / 'selfhost/caddy/snippets.caddy') + ':/snippets.caddy:ro',
                    self.images['caddy'], 'run', '--config', '/fixture.caddy', '--adapter', 'caddyfile')
        self.addCleanup(self.docker, 'rm', '-fv', name)
        url = 'http://127.0.0.1:8080/chronicle/' + filename
        for _ in range(50):
            result = subprocess.run(['docker', 'exec', name, 'wget', '-S', '-O', '-', url],
                                    capture_output=True, timeout=10)
            if result.returncode == 0:
                break
            time.sleep(0.1)
        self.assertEqual(0, result.returncode, self.docker('logs', name))
        self.assertEqual(content, result.stdout)
        headers = result.stderr.decode().lower()
        self.assertIn('cache-control:', headers)
        self.assertIn('immutable', headers)
        self.assertIn('content-security-policy:', headers)
        self.assertIn("default-src 'self'", headers)
        self.assertIn("frame-ancestors 'none'", headers)
        missing = subprocess.run(['docker', 'exec', name, 'wget', '-S', '-O', '-',
                                  'http://127.0.0.1:8080/chronicle/chunk-missing.css'],
                                 capture_output=True, timeout=10)
        self.assertEqual(0, missing.returncode, missing.stderr)
        self.assertNotIn('immutable', missing.stderr.decode().lower())

    def test_fresh_compose_creation_cannot_turn_certificate_files_into_directories(self):
        from chronicle_ops.images import bundle_config
        from selfhost_fixture import postgres_image
        source = bundle_config(ROOT / 'selfhost')['services']
        services = {name: source[name] for name in ('monitoring-cert-init', 'grafana')}
        directory = self.work / 'compose-create'; directory.mkdir()
        tls = directory / 'tls'; tls.mkdir()
        volumes = {}
        for name, service in services.items():
            service.pop('networks', None); service.pop('ports', None)
            service.pop('depends_on', None); service.pop('healthcheck', None)
            service['network_mode'] = 'none'
            for mount in service['volumes']:
                if mount['type'] == 'volume':
                    volumes[mount['source']] = {}
                elif mount['target'] == '/tls':
                    mount['source'] = str(tls)
                elif mount['target'].startswith('/etc/grafana/tls'):
                    mount['source'] = str(tls / Path(mount['source']).name)
        services['grafana']['image'] = self.images['grafana']
        services['monitoring-cert-init']['image'] = postgres_image()
        services['grafana']['entrypoint'] = ['/bin/sh', '-ec',
            'test -s /etc/grafana/tls/monitoring.crt; test -f /etc/grafana/tls/monitoring.key']
        project = 'chronicle-u-cert-' + uuid.uuid4().hex
        config = directory / 'compose.json'
        config.write_text(json.dumps(dict(services=services, volumes=volumes)))
        command = ['compose', '--env-file', '/dev/null', '-p', project, '-f', str(config)]
        try:
            self.docker(*command, 'create')
            for service in ('monitoring-cert-init', 'grafana'):
                container = self.docker(*command, 'ps', '--all', '-q', service).strip()
                self.docker('start', '-a', container)
                self.assertEqual('0', self.docker('inspect', '--format', '{{.State.ExitCode}}', container).strip(),
                                 self.docker('logs', container))
            self.assertTrue((tls / 'monitoring.crt').is_file())
            self.assertFalse((tls / 'monitoring.key').exists())
        finally:
            containers = self.docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project).split()
            if containers:
                self.docker('rm', '-fv', *containers)
            owned_volumes = self.docker('volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project).split()
            if owned_volumes:
                self.docker('volume', 'rm', *owned_volumes)
