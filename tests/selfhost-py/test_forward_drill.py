"""Signed bundle update drill: real pg_tde, Flyway, safety dump and guarded restore.

Owns a random disposable Compose project, including pg_tde, a real one-shot Flyway
migrate service, Caddy, and restore dependencies. Only external acceptance failure and
process death are injected. No existing deployment is addressed.
"""
from contextlib import ExitStack, contextmanager
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import runpy
import shutil
import shlex
import signal
import sys
import subprocess
import tempfile
import unittest
import threading
import uuid
import yaml
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from types import SimpleNamespace
from unittest.mock import patch

from chronicle_ops import release, upgrade
from chronicle_ops.ingress import VERIFY_HEADER, VERIFY_SCHEME, fence_path, RETRY_AFTER_SECONDS
from chronicle_ops.dump import file_sha256
from chronicle_ops.envfile import set_env_values, read_env
from chronicle_ops.migrations import migration_hashes
from selfhost_fixture import FIXTURE_POSTGRES_PASSWORD, bundle_fixture_files
import test_restore_deployment as deployed
import test_restore_schemas as schemas
from test_forward_update import next_version


class QuietHTTP(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


class ForwardUpgradeDrill(schemas.PgTdeFixture):
    database_user = 'testuser'
    network_options = ('-p', '127.0.0.1::5432')
    bootstrap_deployment = classmethod(deployed.DeploymentCatalogTests.bootstrap_deployment.__func__)
    apply_deployment_migrations = classmethod(deployed.DeploymentCatalogTests.apply_deployment_migrations.__func__)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.bootstrap_deployment()
        cls.java_image = cls.pull_image('eclipse-temurin:25-jdk')
        cls.edge_image = cls.pull_image('caddy:2.11.9-alpine')
        libraries = cls.work / 'classpath'
        libraries.mkdir()
        for index, entry in enumerate(cls.main_classpath.split(os.pathsep)):
            source = Path(entry)
            if not source.exists():
                continue  # Gradle classpaths include empty language output directories.
            target = libraries / str(index)
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                target = target.with_suffix('.jar')
                shutil.copy2(source, target)

    @classmethod
    def pull_image(cls, image):
        subprocess.run(['docker', 'pull', image], check=True, capture_output=True, timeout=300)
        return json.loads(cls.docker('image', 'inspect', image))[0]['RepoDigests'][0]

    @classmethod
    def start_database(cls, initialize_tde=True):
        cls.project = 'chronicle-sat-r1-fu2-drill-' + uuid.uuid4().hex
        cls.subnet = subprocess.run([sys.executable, str(schemas.ROOT / 'selfhost/network-subnet.py'), 'select',
                                     '10.251.2.0/24', cls.project], check=True, capture_output=True, text=True).stdout.strip()
        from selfhost_fixture import postgres_image
        cls.pg_image = postgres_image()
        cls.bootstrap = cls.work / 'bootstrap'
        cls.bootstrap.mkdir()
        (cls.bootstrap / 'docker-compose.yml').write_text(yaml.safe_dump(cls.database_compose()))
        cls.addClassCleanup(cls.dc_fixture, cls.bootstrap, 'down', '--volumes', '--remove-orphans')
        cls.dc_fixture(cls.bootstrap, 'up', '-d', '--wait', '--wait-timeout', '120', 'postgres')
        if initialize_tde:
            cls.docker('exec', '--user', '0', '-e', 'POSTGRES_HOST=127.0.0.1', cls.container,
                       'bash', '/selfhost/init-tde.sh')

    @classmethod
    def database_compose(cls):
        return dict(services={'postgres': dict(image=cls.pg_image, container_name=cls.container,
            environment=dict(POSTGRES_HOST_AUTH_METHOD='trust', POSTGRES_USER=cls.database_user,
                POSTGRES_DB='chronicle', POSTGRES_PASSWORD=FIXTURE_POSTGRES_PASSWORD,
                POSTGRES_INITDB_ARGS='--encoding=UTF8'),
            ports=['127.0.0.1::5432'], volumes=[f'{schemas.SELFHOST}:/selfhost:ro', f'{cls.work}:/work',
                'database:/data/db', 'keys:/var/lib/postgresql/tde-keyring'],
            command=['-c', 'shared_preload_libraries=pg_tde', '-c', 'max_parallel_workers_per_gather=0'],
            healthcheck=dict(test=['CMD', 'pg_isready', '-U', cls.database_user], interval='1s', timeout='5s', retries=60))},
            volumes=dict(database={}, keys={}),
            networks={'default': {'ipam': {'config': [{'subnet': cls.subnet}]}}})

    @classmethod
    def dc_fixture(cls, directory, *args):
        return subprocess.run(['docker', 'compose', '-p', cls.project, '-f', str(directory / 'docker-compose.yml'),
                               *args], capture_output=True, text=True, check=True, timeout=180)

    def configure_compose(self, host, version, future):
        config = self.database_compose()
        services = config['services']
        one_shot = dict(image=self.pg_image, entrypoint=['/bin/true'], restart='no',
                        depends_on=dict(postgres=dict(condition='service_healthy')))
        # The upgrade preflight runs secrets-init, then config-guard, on the candidate.
        services.update({'config-guard': dict(one_shot, profiles=['tools']), 'db-init': one_shot,
                         'secrets-init': dict(image=self.pg_image, entrypoint=['/bin/true'], restart='no',
                                              profiles=['tools'])})
        sources = self.sources[version] / 'chronicle-server/src/main/resources/db/migration'
        libraries = ':'.join('/work/classpath/' + path.name for path in (self.work / 'classpath').iterdir())
        services['migrate'] = dict(image=self.java_image, entrypoint=['java', '-Xmx256m', '-cp', libraries,
            '/work/ForwardMigration.java', 'jdbc:postgresql://postgres:5432/chronicle', self.database_user,
            FIXTURE_POSTGRES_PASSWORD, '/migrations'], volumes=[f'{self.work}:/work', f'{sources}:/migrations:ro'],
            restart='no', depends_on={'db-init': dict(condition='service_completed_successfully')})
        services['backend'] = dict(image=self.pg_image, entrypoint=['sleep', 'infinity'], init=True,
            stop_signal='SIGTERM', stop_grace_period='1s',
            depends_on={'migrate': dict(condition='service_completed_successfully')})
        services['web'] = dict(image=self.edge_image, ports=['127.0.0.1::8080'],
            environment=dict(CHRONICLE_INTERNAL_WEB_SECRET='drill-internal-capability'),
            volumes=['./caddy/snippets.caddy:/etc/caddy/snippets.caddy:ro',
                './Caddyfile.drill:/etc/caddy/Caddyfile:ro', f'{self.work}/state/tls:/etc/caddy/certs:ro'],
            healthcheck=dict(test=['CMD', 'wget', '-q', '-O', '/dev/null', 'http://127.0.0.1:8080/health'],
                             interval='1s', timeout='5s', retries=60),
            depends_on={'backend': dict(condition='service_started')})
        services['ca-export'] = dict(image=self.edge_image, entrypoint=['/bin/true'], restart='no',
                                    depends_on={'web': dict(condition='service_healthy')})
        services['restore'] = dict(image=self.pg_image, user='0:0', profiles=['restore'], entrypoint=['bash', '/selfhost/restore.sh'],
            environment=dict(POSTGRES_HOST='postgres', POSTGRES_USER=self.database_user, POSTGRES_DB='chronicle',
                POSTGRES_PASSWORD=FIXTURE_POSTGRES_PASSWORD, BACKUPS_DIR='/backups', RELEASE_VERSION=version),
            volumes=['./:/selfhost:ro', f'{self.backups}:/backups'],
            depends_on={'db-init': dict(condition='service_completed_successfully')})
        if future:
            services['future-writer'] = dict(image='${WORKER_IMAGE}', entrypoint=['sleep', 'infinity'], init=True,
                stop_signal='SIGTERM', stop_grace_period='1s',
                depends_on={'migrate': dict(condition='service_completed_successfully')})
        (host / 'docker-compose.yml').write_text(yaml.safe_dump(config))
        (host / 'overlays/mode-local-https.yml').write_text('services: {}\n')
        (host / 'Caddyfile.drill').write_text('{\n    admin off\n    auto_https off\n}\nimport /etc/caddy/snippets.caddy\n:8080 {\n    import chronicle_update_fence\n    respond /health 204\n    respond "accepted" 200\n}\n')
        if future:
            with (host / 'chronicle_ops/images.py').open('a') as output:
                output.write("\nSOURCE_IMAGES += (SourceImage('future-worker', 'WORKER_IMAGE', 'unused', 'unused'),)\n")
            with (host / '.env.example').open('a') as output:
                output.write('\nWORKER_IMAGE=' + self.java_image + '\n')

    def build_bundle(self, version, source, key):
        builder = runpy.run_path(str(schemas.ROOT / 'scripts/build-selfhost-release.py'))
        output = self.work / ('release-' + version)
        output.mkdir()
        name = 'chronicle-selfhost-' + version
        bundle = output / name
        args = SimpleNamespace(source_revision='a' * 40, public_revision=None,
                               inputs_tree='b' * 40, source_date_epoch=1700000000,
                               migrations=migration_hashes(source))
        tracked = builder['tracked_source_paths'](schemas.ROOT) | {
            'selfhost/' + name for name in bundle_fixture_files(builder)}
        builder['copy_bundle_inputs'](bundle, args, tracked)
        shutil.copy2(str(key) + '.pub', bundle / 'selfhost/release-signing.pub')
        (bundle / 'CHANGELOG.md').write_text('# Fixture release\n\n## [' + version + ']\n\nFixture migration drill.\n')
        images = {name: 'fixture/' + name + '@sha256:' + 'a' * 64
                  for name in builder['PLACEHOLDERS'].values()}
        builder['render_bundle'](bundle, args, images, version)
        future = version != release.UPGRADE_FROM_MINIMUM
        self.configure_compose(bundle / 'selfhost', version, future)
        manifest_path = bundle / 'release-manifest.json'
        manifest = json.loads(manifest_path.read_text())
        if future:
            manifest['images']['future-worker'] = self.java_image
            manifest['image_inputs']['future-worker'] = 'b' * 40
        manifest['files'] = {path.relative_to(bundle).as_posix(): file_sha256(path)
                             for path in bundle.rglob('*') if path.is_file() and path != manifest_path}
        manifest_path.write_text(json.dumps(manifest))
        builder['require_offline_links'](bundle)
        archive = output / (name + '.tar.gz')
        checksum = archive.with_name(archive.name + '.sha256')
        builder['publish_bundle'](bundle, args, self.http / name, self.http / archive.name,
                                  self.http / checksum.name)
        # publish_bundle removes its staging directory after the caller is finished.
        checksum = self.http / checksum.name
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-n', release.RELEASE_SIGNER,
                        '-f', str(key), str(checksum)], check=True, capture_output=True)
        return self.http / name

    def compose(self, directory, project, names, *args, **kwargs):
        directory = directory or Path.cwd()
        settings = read_env(directory / '.env')
        from chronicle_ops.env_migration import compose_names
        result = release.compose_release(directory, self.project,
                                         names or compose_names(settings, directory), *args, **kwargs)
        if 'up' in args and self.kill_after_migration:
            self.assert_fenced(directory)
            os.kill(os.getpid(), signal.SIGKILL)
        return result

    def schema_version(self):
        # Flyway stores versions as text; compare numerically.
        return int(self.sql('SELECT max(version::int) FROM flyway_schema_history;'))

    def assert_fenced(self, host):
        endpoint = self.dc_fixture(host, 'port', 'web', '8080').stdout.strip()
        for route in ('/chronicle/v4/study/x/upload', '/chronicle/v3/survey/x', '/chronicle/survey'):
            request = Request('http://' + endpoint + route, data=b'fixture')
            try:
                urlopen(request, timeout=10)
            except HTTPError as error:
                with error:
                    self.assertEqual(503, error.code)
                    self.assertEqual(str(RETRY_AFTER_SECONDS), error.headers['Retry-After'])
            else:
                self.fail('participant ingress opened before verification')
        return 'http://' + endpoint

    def command(self, args, **kwargs):
        if args[0] == 'python3' and 'network-subnet.py' in args[1]:
            return SimpleNamespace(returncode=0, stdout='')
        if Path(args[0]).name == 'chronicle' and args[-1] == 'verify' and kwargs.get('cwd'):
            # Upgrade.verify_previous: the previous release checks itself while it still serves,
            # before the fence closes, so participants are still accepted here.
            endpoint = self.dc_fixture(Path(kwargs['cwd']).resolve(), 'port', 'web', '8080').stdout.strip()
            with urlopen(Request('http://' + endpoint + '/chronicle/v4/study/x/upload', data=b'fixture'),
                         timeout=10) as response:
                self.assertEqual(200, response.status)
            return SimpleNamespace(returncode=0, stdout='internal verification passed')
        if Path(args[0]).name == 'chronicle' and args[-1] == 'verify':
            host = Path(args[0]).resolve().parent
            version = json.loads((host.parent / 'release-manifest.json').read_text())['release_version']
            origin = self.assert_fenced(host)
            request = Request(origin + '/chronicle/v4/study/x/upload', data=b'fixture',
                              headers={VERIFY_HEADER: VERIFY_SCHEME + ' drill-internal-capability'})
            with urlopen(request, timeout=10) as response:
                self.assertEqual(200, response.status)
            if version == self.fail_version:
                raise subprocess.CalledProcessError(1, args)
            return SimpleNamespace(returncode=0, stdout='internal verification passed')
        from chronicle_ops.common import run
        return run(args, **kwargs)

    def invoke(self, host, *arguments):
        os.chdir(host)
        request = self.work / 'driver.json'
        request.write_text(json.dumps(dict(work=str(self.work), http=str(self.http), backups=str(self.backups),
                                           container=self.container, classpath=self.classpath, project=self.project,
                                           sources={v: str(p) for v, p in self.sources.items()}, fail_version=self.fail_version,
                                           kill_after_migration=self.kill_after_migration,
                                           kill_rollback_phase=getattr(self, 'kill_rollback_phase', None))))
        environment = dict(os.environ, CHRONICLE_DRILL_STATE=str(request),
                           PATH=str(self.work / 'driver-bin') + os.pathsep + os.environ['PATH'])
        result = subprocess.run(['bash', str(host / 'chronicle'), 'update', *arguments],
                                env=environment, capture_output=True, text=True, timeout=180)
        print(result.stdout + result.stderr, flush=True)
        if result.returncode == 0:
            self.assertFalse((self.work / 'state' / upgrade.UPGRADE_LOCK).exists())
            self.assertEqual('retained', self.sql('SELECT value FROM public.forward_drill_data WHERE id=1;'))
        return result.returncode

    def test_signed_forward_repair_failure_and_interruption_keep_data(self):
        self.http = self.work / 'http'
        self.http.mkdir()
        self.backups = self.work / 'state/backups'
        self.backups.mkdir(parents=True)
        (self.work / 'state/tls').mkdir()
        shutil.copy2(Path(__file__).with_name('ForwardMigration.java'), self.work / 'ForwardMigration.java')
        self.environment, self.stopped, self.fail_version = [], False, None
        self.kill_after_migration = False
        commands = self.work / 'driver-bin'
        commands.mkdir()
        driver = Path(__file__).with_name('forward_drill_driver.py')
        python = commands / 'python3'
        python.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' ' + shlex.quote(str(driver)) + ' "$@"\n')
        python.chmod(0o755)
        first = release.UPGRADE_FROM_MINIMUM
        second = next_version(first)
        self.sources = {version: self.work / ('source-' + version) for version in (first, second)}
        for source in self.sources.values():
            target = source / 'chronicle-server/src/main/resources/db/migration'
            shutil.copytree(schemas.ROOT / 'chronicle-server/src/main/resources/db/migration', target)
        # The next release's migration follows every shipped one.
        shipped = self.sources[second] / 'chronicle-server/src/main/resources/db/migration'
        self.shipped_version = max(int(path.name[1:].split('__', 1)[0]) for path in shipped.glob('V*__*.sql'))
        self.forward_version = self.shipped_version + 1
        migration = shipped / f'V{self.forward_version}__forward_drill.sql'
        migration.write_text('ALTER TABLE public.forward_drill_data ADD COLUMN migrated boolean DEFAULT true;\n')
        key = self.work / 'drill-signing-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        bundles = {version: self.build_bundle(version, source, key) for version, source in self.sources.items()}
        host = bundles[first] / 'selfhost'
        env = set_env_values((host / '.env.example').read_text(), {
            'RELEASE_VERSION': first, 'COMPOSE_PROJECT_NAME': self.project, 'MIN_FREE_DISK_GIB': '0',
            'CHRONICLE_STATE_DIR': str(self.work / 'state'), 'CHRONICLE_RECONCILE_ENABLED': 'false',
            'COMPOSE_FILE': 'docker-compose.yml:overlays/mode-local-https.yml',
            'DASHBOARD_PASSWORD_HASH': '$2synthetic'}, require_existing=False)
        (host / '.env').write_text(env)
        (host / '.env').chmod(0o600)
        self.sql("CREATE TABLE public.forward_drill_data(id integer PRIMARY KEY, value text); "
                 "INSERT INTO public.forward_drill_data VALUES (1, 'retained');")
        self.addCleanup(self.sql, 'DROP TABLE public.forward_drill_data;')
        self.exercise_handoff(host, first, second)

    def exercise_handoff(self, host, first, second):
        handler = functools.partial(QuietHTTP, directory=str(self.http))
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = Path.cwd()
        url = f'http://127.0.0.1:{server.server_port}'
        assets = [dict(name=path.name, browser_download_url=url + '/' + path.name)
                  for path in self.http.glob('*.tar.gz*')]
        (self.http / 'catalog.json').write_text(json.dumps([
            dict(tag_name=version, draft=False, prerelease=False, assets=assets) for version in (first, second)]))
        try:
            with patch.dict(os.environ, CHRONICLE_RELEASES_URL=url + '/catalog.json',
                            CHRONICLE_RECONCILE_ENABLED='false'), self.service_adapters():
                self.assertEqual(0, self.invoke(host))
                active = Path((self.work / 'state' / release.OWNER_FILE).read_text().strip())
                self.assertEqual('t', self.sql('SELECT migrated FROM public.forward_drill_data;'))
                self.assertEqual(self.forward_version, self.schema_version())
                endpoint = self.dc_fixture(active, 'port', 'web', '8080').stdout.strip()
                with urlopen(Request('http://' + endpoint + '/chronicle/v4/study/x/upload', data=b'fixture')) as response:
                    self.assertEqual(200, response.status)
                self.assertIn('future-writer', self.dc_fixture(active, 'ps', '--services').stdout)
                self.assertEqual(0, self.invoke(active, second))  # same-version repair
                self.check_cross_version_restore(first)
                self.check_failure_and_interruption(host, first, second)
        finally:
            os.chdir(origin)
            server.shutdown()
            server.server_close()
            thread.join()

    @contextmanager
    def service_adapters(self):
        with ExitStack() as stack:
            stack.enter_context(patch('chronicle_ops.release.compose_projects', return_value=[]))
            stack.enter_context(patch('chronicle_ops.release.cleanup_releases'))
            stack.enter_context(patch('chronicle_ops.upgrade.compose_release', self.compose))
            stack.enter_context(patch('chronicle_ops.restore.compose', lambda *a, **k: self.compose(None, None, None, *a, **k)))
            stack.enter_context(patch('chronicle_ops.upgrade.run', self.command))
            docker_root = subprocess.run(['docker', 'info', '--format', '{{.DockerRootDir}}'],
                                         capture_output=True, text=True, check=True).stdout.strip()
            if not Path(docker_root).exists():
                # Docker Desktop keeps its data root inside its VM, so storage_report would measure it
                # by running the bundle's PostgreSQL image, which in this drill is an unpullable
                # fixture digest. test_storage_report covers that path; Linux hosts, where the data
                # root is a host directory, still run the real check here.
                def host_storage(state, project, floor_gib=5, peak_bytes=0, *, image=None):
                    disk = os.statvfs(state)
                    return [(name, True, disk.f_bavail * disk.f_frsize, disk.f_favail, 0)
                            for name in ('state', 'docker-data')]
                stack.enter_context(patch('chronicle_ops.common.storage_report', host_storage))

            for module in ('upgrade', 'restore'):
                stack.enter_context(patch('chronicle_ops.' + module + '.finish_operation'))
            stack.enter_context(patch('chronicle_ops.reconcile.uninstall'))
            stack.enter_context(patch('chronicle_ops.restore.Rollback.verify_previous', lambda operation: self.command([str(operation.previous / 'chronicle'), 'verify'], check=True)))
            from chronicle_ops.receipts import write_json
            def journal(path, data):
                write_json(path, data)
                if (data.get('phase') == getattr(self, 'kill_rollback_phase', None)
                        and (data['phase'] != upgrade.PREPARED or 'backup' in data)):
                    os.kill(os.getpid(), signal.SIGKILL)
            stack.enter_context(patch('chronicle_ops.restore.write_json', journal))
            stack.enter_context(patch('chronicle_ops.upgrade.write_json', journal))
            yield

    def check_cross_version_restore(self, first):
        from chronicle_ops.dump import file_sha256
        from chronicle_ops.restore import Restore
        active = Path((self.work / 'state' / release.OWNER_FILE).read_text().strip())
        os.chdir(active)
        older, newer = sorted(self.backups.glob('pre-upgrade-*.sql.gz'))[:2]
        operation = Restore(self.work / 'state', self.backups, '/backups/' + older.name,
                            file_sha256(older), '3600', False, True)
        self.assertEqual(0, operation.execute())
        self.assertEqual('t', self.sql('SELECT migrated FROM public.forward_drill_data;'))
        rejected = Restore(self.work / 'state', self.backups, '/backups/' + newer.name,
                           file_sha256(newer), '3600', False, True, target_version=first)
        with patch('chronicle_ops.restore.compose', side_effect=AssertionError('mutation before version guard')):
            self.assertEqual(1, rejected.execute())
        self.assertEqual('retained', self.sql('SELECT value FROM public.forward_drill_data WHERE id=1;'))

    def return_to_shipped(self, host, backup):
        """Guarded rollback from the release that owns the deployment back to N with a safety dump."""
        from chronicle_ops.restore import rollback
        from chronicle_ops.dump import file_sha256
        os.chdir(Path((self.work / 'state' / release.OWNER_FILE).read_text().strip()))
        self.assertEqual(0, rollback(host, '/backups/' + backup.name, file_sha256(backup), True))
        self.assertEqual(str(host.resolve()), (self.work / 'state' / release.OWNER_FILE).read_text().strip())
        self.assertEqual(self.shipped_version, self.schema_version())

    def assert_updated_by_one_rerun(self, host):
        # An interrupted update needs one rerun of ./chronicle update: it recovers, updates again and
        # exits 0 (invoke() also checks that the journal is gone and the data was kept).
        self.assertEqual(0, self.invoke(host))
        owner = (self.work / 'state' / release.OWNER_FILE).read_text().strip()
        self.assertNotEqual(str(host.resolve()), owner)
        self.assertEqual(self.forward_version, self.schema_version())
        self.assertEqual('t', self.sql('SELECT migrated FROM public.forward_drill_data;'))
        # Back to N with the dump this update took before it changed anything.
        self.return_to_shipped(host, sorted(self.backups.glob('pre-upgrade-*.sql.gz'))[-1])

    def check_failure_and_interruption(self, host, first, second):
        # Return to N using the first verified safety dump, then try a failing N+1.
        self.return_to_shipped(host, sorted(self.backups.glob('pre-upgrade-*.sql.gz'))[0])
        self.fail_version = second
        self.assertEqual(1, self.invoke(host, second))
        self.assertEqual(str(host.resolve()), (self.work / 'state' / release.OWNER_FILE).read_text().strip())
        self.assertEqual(self.shipped_version, self.schema_version())
        self.assertEqual('0', self.sql("SELECT count(*) FROM information_schema.columns WHERE "
                                       "table_name='forward_drill_data' AND column_name='migrated';"))
        self.fail_version = None
        marker = self.work / 'state' / upgrade.UPGRADE_LOCK
        self.kill_rollback_phase = upgrade.PREPARED
        self.assertNotEqual(0, self.invoke(host, second))
        self.assertEqual(self.shipped_version, self.schema_version())
        self.assertTrue(marker.exists())
        self.kill_rollback_phase = None
        # Real PREPARED recovery excludes ca-export from up --wait; the rerun then updates again.
        self.assert_updated_by_one_rerun(host)
        self.kill_after_migration = True
        self.assertNotEqual(0, self.invoke(host, second))
        self.kill_after_migration = False
        self.assertTrue(marker.is_dir())
        self.assertEqual(self.forward_version, self.schema_version())
        record = json.loads((marker / upgrade.RECOVERY_FILE).read_text())
        abandoned = Path(record['owner'])
        self.dc_fixture(abandoned, 'restart', 'web')
        self.assert_fenced(abandoned)  # Caddy restart after updater death still refuses participants.
        # SIGKILL left the durable fence and safety dump: the rerun restores it, then updates again.
        self.assert_updated_by_one_rerun(host)

        from chronicle_ops.restore import ROLLBACK_PHASES
        for phase in ROLLBACK_PHASES:
            with self.subTest(killed_phase=phase):
                self.fail_version = second
                self.kill_rollback_phase = phase
                self.assertNotEqual(0, self.invoke(host, second))
                self.assertTrue(marker.exists(), 'rollback journal disappeared before old verification')
                self.assertTrue(fence_path(self.work / 'state').exists())
                self.kill_rollback_phase = None
                self.fail_version = None
                # The update had failed (journal marked failed): the rerun only finishes the rollback.
                self.assertEqual(1, self.invoke(host))
                self.assertFalse(marker.exists())
                self.assertFalse(fence_path(self.work / 'state').exists())
                self.assertEqual(self.shipped_version, self.schema_version())

        # Once committed, even a crash before fence removal can never restore the old dump.
        from chronicle_ops.ingress import open_ingress
        self.kill_rollback_phase = upgrade.COMMITTED
        self.assertNotEqual(0, self.invoke(host, second))
        self.assertEqual(upgrade.COMMITTED, json.loads((marker / upgrade.RECOVERY_FILE).read_text())['phase'])
        open_ingress(self.work / 'state')
        self.sql("INSERT INTO public.forward_drill_data(id, value) VALUES (2, 'after-commit');")
        self.kill_rollback_phase = None
        active = Path((self.work / 'state' / release.OWNER_FILE).read_text().strip())
        self.assertEqual(0, self.invoke(active))
        self.assertEqual('after-commit', self.sql('SELECT value FROM public.forward_drill_data WHERE id=2;'))


class ForwardClasspathTests(unittest.TestCase):
    def test_container_migration_copies_only_production_runtime(self):
        with tempfile.TemporaryDirectory(prefix='forward-classpath-') as directory:
            folder = Path(directory)
            main, tests, work = (folder / name for name in ('main', 'tests', 'work'))
            for path in (main, tests, work):
                path.mkdir()
            (main / 'production.class').write_bytes(b'synthetic-main-runtime')
            (tests / 'forbidden-test-payload.class').write_bytes(b'synthetic-test-runtime')
            fixture = type('ForwardClasspathFixture', (ForwardUpgradeDrill,), {
                'work': work,
                'classpath': os.pathsep.join((str(main), str(tests))),
                'main_classpath': str(main),
                'bootstrap_deployment': classmethod(lambda cls: None),
                'pull_image': classmethod(lambda cls, image: image),
            })
            with patch.object(schemas.PgTdeFixture, 'setUpClass'):
                ForwardUpgradeDrill.setUpClass.__func__(fixture)
            copied = {path.name for path in (work / 'classpath').rglob('*.class')}
            self.assertEqual({'production.class'}, copied)
