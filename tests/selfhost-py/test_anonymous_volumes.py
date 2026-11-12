"""No operator Compose command and no harness teardown leaves an anonymous volume behind that
Docker made for a container, and none removes a volume a container asked for by name.

The release Postgres image is built on the Percona image, which declares six VOLUME paths
(/backrestrepo, /data/db, /pgconf, /pgdata, /pgwal, /sshd). Docker makes an anonymous volume for
each one a container mounts nothing over, so every container made from POSTGRES_IMAGE or
BACKUP_IMAGE has five or six. `docker compose down` leaves them when it removes the container;
`down --volumes` would also remove the named volumes, and leaves them anyway once `up` has
recreated the container. One Docker daemon held 17,973 of them on 2026-11-11.

Docker's anonymous label is also on a volume an operator made with `docker volume create` and no
name. Up to 7358dc83 the label and the mount path decided, and `./chronicle down` removed such a
volume when the operator's Compose file mounted it at /data/db: on Engine 29.8.2 the database
went with it (reproduced 2026-11-11). Now the container's own configuration decides.

These tests run real Docker against a disposable Compose project with no network and no ports.
Its `database` service keeps project volumes over /data/db and /pgconf and mounts three volumes
made by hand without a name: with the short and the long syntax at paths the image declares, and
at a path it does not. All five must survive every command with their contents. The bookkeeping
here asks Docker directly and does not use the code under test.
"""
from contextlib import contextmanager, redirect_stderr
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

import yaml

import chronicle_ops
from chronicle_ops import common, release, services, upgrade
from chronicle_ops.restore import Rollback
from selfhost_fixture import (ROOT, AnonymousVolumeWatch, anonymous_volumes_removed, disposable_project_volumes,
                              postgres_image)

# The package under test may be a built bundle (run_suite.py selects it through PYTHONPATH).
SELFHOST = Path(chronicle_ops.__file__).resolve().parents[1]
ANONYMOUS_LABEL = 'com.docker.volume.anonymous'
DECLARED = ['/backrestrepo', '/data/db', '/pgconf', '/pgdata', '/pgwal', '/sshd']
# Where the database service mounts a volume it asks for by name; the image's other two paths
# (/backrestrepo, /sshd) get a volume from Docker.
KEPT_PATHS = ['/data/db', '/pgconf', '/pgwal', '/pgdata', '/operator-data']
SENTINEL = 'kept-' + uuid.uuid4().hex


def docker(*args, check=True, **options):
    return subprocess.run(['docker', *args], capture_output=True, text=True, check=check, timeout=180, **options)


class ComposeProject(unittest.TestCase):
    """A disposable project: `database` (sleeps) and the one-shot `job`, both from the Postgres image."""

    def setUp(self):
        self.project = 'chronicle-anonymous-volumes-' + uuid.uuid4().hex
        self.folder = Path(tempfile.mkdtemp(prefix='anonymous-volumes-')).resolve()
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.image = postgres_image()
        self.assertEqual(DECLARED, sorted(json.loads(docker('image', 'inspect', '--format', '{{json .Config.Volumes}}',
                                                             self.image).stdout)))
        self.seen, self.extra, self.file, self.own, self.made = set(), [], 'docker-compose.yml', {}, set()
        self.addCleanup(self.remove_everything)
        self.prepare()
        (self.folder / '.env').write_text('')
        (self.folder / '.env').chmod(0o600)
        (self.folder / 'production.yml').write_text('services: {}\n')

    def prepare(self):
        """The operator's own volumes and the Compose files that mount them. Called again by a
        test that goes on to its next entry point after one of them removed such a volume."""
        # Made without a name: Docker labels them anonymous like the ones it makes for the image's paths.
        self.own = {key: docker('volume', 'create').stdout.strip() for key in ('short', 'long', 'elsewhere')}
        self.made.update(self.own.values())
        for name in self.own.values():
            self.assertIn(ANONYMOUS_LABEL, json.loads(docker('volume', 'inspect', name).stdout)[0]['Labels'] or {})
        self.write('docker-compose.yml', job=True)
        self.write('without-job.yml', job=False)
        # `sleep` as process 1 ignores the stop signal, so `down` waits out the grace period.
        self.write('slow-stop.yml', job=True, init=False, stop_grace_period='6s')
        # The same services with one more setting: Compose recreates the container by itself.
        self.write('changed.yml', job=True, environment=dict(CHANGED='yes'))
        # The same services in a Compose file that names its project.
        self.write('named.yml', job=True, project=self.project)

    def write(self, name, *, job, init=True, stop_grace_period='1s', environment=None, project=None):
        mounts = ['data:/data/db',                                              # project volume, short syntax
                  dict(type='volume', source='data_long', target='/pgconf'),   # project volume, long syntax
                  'own_short:/pgwal',                                           # made by hand, short syntax
                  dict(type='volume', source='own_long', target='/pgdata'),    # made by hand, long syntax
                  'own_elsewhere:/operator-data']                               # made by hand, not an image path
        database = dict(image=self.image, entrypoint=['sleep', 'infinity'], init=init, stop_grace_period=stop_grace_period,
                        network_mode='none', volumes=mounts, environment=environment or {})
        volumes = dict(data={}, data_long={},
                       **{'own_' + key: dict(external=True, name=volume) for key, volume in self.own.items()})
        configuration = dict(services=dict(database=database), volumes=volumes, **(dict(name=project) if project else {}))
        if job:
            configuration['services']['job'] = dict(image=self.image, entrypoint=['/bin/true'], network_mode='none',
                                                    restart='no', environment=environment or {})
            database['depends_on'] = dict(job=dict(condition='service_completed_successfully'))
        (self.folder / name).write_text(yaml.safe_dump(configuration))

    def raw(self, *args, check=True):
        """Plain Compose, not an operator entry point: the test's own setup."""
        return docker('compose', '-p', self.project, '-f', str(self.folder / self.file), *args, check=check)

    def containers(self):
        return docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + self.project).stdout.split()

    def mounted(self):
        """{anonymous volume Docker made: service} for every container of the project, as Docker reports it now."""
        found = {}
        ids = self.containers()
        for container in json.loads(docker('inspect', *ids).stdout) if ids else []:
            service = container['Config']['Labels'].get('com.docker.compose.service', container['Name'])
            for mount in container['Mounts']:
                if mount['Type'] == 'volume' and re.fullmatch(r'[0-9a-f]{64}', mount['Name']) and mount['Name'] not in self.made:
                    found[mount['Name']] = service
        self.seen.update(found)
        return found

    def existing(self, names):
        return sorted(name for name in names if docker('volume', 'inspect', name, check=False).returncode == 0)

    def start(self, recreate=False):
        """Start the project and return the anonymous volumes Docker made for it; recreate=True has
        plain Compose carry them over to a new container first, which mounts them by name."""
        self.raw('up', '-d')
        first = self.mounted()
        self.assertEqual({'database': 2, 'job': 6}, {service: list(first.values()).count(service) for service in set(first.values())})
        container = self.raw('ps', '-q', 'database').stdout.strip()
        docker('exec', '-u', '0', container, 'sh', '-c',
               'for path in "$@"; do echo "$0" > "$path/sentinel" || exit 1; done', SENTINEL, *KEPT_PATHS)
        if recreate:
            self.raw('up', '-d', '--force-recreate')
            self.assertEqual(first, self.mounted(), 'Compose carries anonymous volumes over to a recreated container')
        return first

    def kept_volumes(self):
        return [self.project + '_data', self.project + '_data_long', *self.own.values()]

    def assert_kept(self, volumes=None):
        """The project's named volumes and the operator's own volumes exist with their contents."""
        volumes = self.kept_volumes() if volumes is None else volumes
        self.assertEqual(volumes, [name for name in volumes if self.existing([name])], 'a volume asked for by name is gone')
        for volume in volumes:
            # `docker run --rm` removes the anonymous volumes of its own container.
            read = docker('run', '--rm', '--network', 'none', '-u', '0', '--entrypoint', 'cat', '-v', volume + ':/kept:ro',
                          self.image, '/kept/sentinel', check=False)
            self.assertEqual(SENTINEL, read.stdout.strip(), volume + ': ' + read.stderr)

    def remove_everything(self):
        for name in self.extra:
            docker('rm', '-f', '-v', name, check=False)
        self.mounted()
        self.raw('down', '--volumes', '--remove-orphans', check=False)
        for name in sorted(self.seen | self.made):
            docker('volume', 'rm', name, check=False)

    def reset(self):
        """The test's own reset between two cases: the project and every volume Docker made for it."""
        self.mounted()
        self.raw('down', '--remove-orphans', check=False)
        for volume in self.existing(self.seen):
            docker('volume', 'rm', volume, check=False)
        self.file = 'docker-compose.yml'

    @contextmanager
    def operator_environment(self):
        with patch.dict(os.environ, CHRONICLE_OPS_PROJECT=self.project, COMPOSE_FILE=self.file):
            origin = Path.cwd()
            os.chdir(self.folder)
            try:
                yield
            finally:
                os.chdir(origin)

    def shell(self, wrapper, *args, traps=''):
        """(command, environment) that runs one of SHELL_WRAPPERS against this project."""
        return wrapper_command(wrapper, args, self.folder, self.file, self.project, traps)

    def run_shell(self, wrapper, *args):
        command, environment = self.shell(wrapper, *args)
        return subprocess.run(command, cwd=self.folder, env=environment, capture_output=True, text=True, timeout=180)

    def entry_points(self):
        """{name: function(*compose arguments)} for every operator entry point; each returns the
        finished command with everything the entry point wrote to stderr in .stderr."""
        def python_compose(*args):
            with self.operator_environment(), redirect_stderr(io.StringIO()) as said:
                result = common.compose(*args, capture=True, stderr=subprocess.PIPE)
            result.stderr = (result.stderr or '') + said.getvalue()
            return result

        def python_release(*args):
            with redirect_stderr(io.StringIO()) as said:
                result = release.compose_release(self.folder, self.project, [self.file], *args, capture=True, stderr=subprocess.PIPE)
            result.stderr = (result.stderr or '') + said.getvalue()
            return result
        return {'chronicle_ops.common.compose': python_compose,
                'chronicle_ops.release.compose_release': python_release,
                **{wrapper: (lambda *args, wrapper=wrapper: self.run_shell(wrapper, *args)) for wrapper in SHELL_WRAPPERS}}


def wrapper_command(wrapper, args, folder, file, project, traps=''):
    """(command, environment) that runs one of SHELL_WRAPPERS: the Compose function of an operator
    script, as that script defines it, with the script's own variables set. traps is shell text
    run after those settings and before the function."""
    script_file, function_name, settings = SHELL_WRAPPERS[wrapper]
    function = '\n'.join(re.findall(rf'(?ms)^{function_name}\(\) \{{.*?^\}}', script_file.read_text()))
    if not function:
        raise AssertionError(f'{script_file} defines no {function_name}()')
    script = f'set -euo pipefail\n{settings}\n{traps}{function}\n{function_name} "$@"\n'
    environment = {key: value for key, value in os.environ.items() if not key.startswith('COMPOSE_')}
    environment.update(FIXTURE_FOLDER=str(folder), FIXTURE_FILE=file, FIXTURE_PROJECT=project,
                       FIXTURE_ROOT=str(ROOT), FIXTURE_SELFHOST=str(SELFHOST))
    return ['bash', '-c', script, 'fixture', *args], environment


# script, its function that passes arguments on to Compose, and the script's variables that function reads.
SELFHOST_SETTINGS = ('PROJECT="$FIXTURE_PROJECT"; SCRIPT_DIR="$FIXTURE_SELFHOST"; SCRIPT_PATH="$FIXTURE_SELFHOST/chronicle"\n'
                     'export COMPOSE_FILE="$FIXTURE_FILE"\nwarn() { printf "warning: %s\\n" "$*" >&2; }')
SHELL_WRAPPERS = {
    'selfhost/chronicle dc': (SELFHOST / 'chronicle', 'dc', SELFHOST_SETTINGS),
    'selfhost/rotate-secret.sh dc': (SELFHOST / 'rotate-secret.sh', 'dc', SELFHOST_SETTINGS),
    # The Traefik deployment's scripts call the same functions through their own wrapper.
    'scripts/deploy.sh compose_cmd': (
        ROOT / 'scripts/deploy.sh', 'compose_cmd',
        'PROJECT_ROOT="$FIXTURE_ROOT"; COMPOSE_BASE="$FIXTURE_FOLDER/$FIXTURE_FILE"\n'
        'COMPOSE_PROD="$FIXTURE_FOLDER/production.yml"; export COMPOSE_PROJECT_NAME="$FIXTURE_PROJECT"\n'
        'env_file_path() { printf \'%s\\n\' "$FIXTURE_FOLDER/.env"; }'),
    'scripts/rotate-secrets.sh dc': (
        ROOT / 'scripts/rotate-secrets.sh', 'dc',
        'REPO_ROOT="$FIXTURE_ROOT"; ENV_FILE="$FIXTURE_FOLDER/.env"; COMPOSE_FILE="$FIXTURE_FOLDER/$FIXTURE_FILE"\n'
        'export COMPOSE_PROJECT_NAME="$FIXTURE_PROJECT"'),
    'docker/restore-chronicle.sh compose_cmd': (
        ROOT / 'docker/restore-chronicle.sh', 'compose_cmd',
        'SCRIPT_DIR="$FIXTURE_ROOT/docker"; COMPOSE_FILE="$FIXTURE_FOLDER/$FIXTURE_FILE"\n'
        'COMPOSE_PROD_FILE="$FIXTURE_FOLDER/production.yml"; COMPOSE_PROJECT="$FIXTURE_PROJECT"\n'
        'CHRONICLE_RESTORE_ENV_FILE="$FIXTURE_FOLDER/.env"'),
}
# The two that pass no -p: Compose resolves the project name for them.
NAMED_BY_COMPOSE = ('scripts/deploy.sh compose_cmd', 'scripts/rotate-secrets.sh dc')


class EntryPointTests(ComposeProject):
    def test_down_through_every_entry_point_removes_dockers_own_and_keeps_every_volume_asked_for_by_name(self):
        # Up to 7358dc83 this lost the two volumes made by hand that the database mounts at
        # /pgwal and /pgdata, through every entry point: Docker's label and an image path decided.
        for name, compose in self.entry_points().items():
            with self.subTest(entry_point=name):
                if self.existing(self.own.values()) != sorted(self.own.values()):
                    self.prepare()  # the entry point before this one removed them
                volumes = self.start()
                result = compose('down', '--remove-orphans')
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual([], self.containers())
                self.assert_kept()
                self.assertEqual([], self.existing(volumes), f'{name}: anonymous volumes left by down')
                # The two it was asked for at image paths are reported, once, as left.
                self.assertIn('2 volumes without a name were left', result.stderr)

    def test_volumes_compose_carried_over_to_a_recreated_container_are_mounted_by_name_and_stay(self):
        # Compose mounts the anonymous volumes it carries over by name (HostConfig.Mounts), as it
        # mounts a volume an operator asked for (HostConfig.Binds here, HostConfig.Mounts with
        # Compose 2.17), so the container no longer says whose they are and they are not removed.
        for name, compose in self.entry_points().items():
            # Compose recreating by itself after a change, through the entry point; plain Compose.
            for carried_by in ('a changed configuration', 'plain Compose'):
                with self.subTest(entry_point=name, carried_by=carried_by):
                    try:
                        volumes = self.start(recreate=carried_by == 'plain Compose')
                        if carried_by == 'a changed configuration':
                            self.file = 'changed.yml'
                            result = compose('up', '-d')
                            self.assertEqual(0, result.returncode, result.stderr)
                            self.assertEqual(volumes, self.mounted(), 'Compose did not carry the volumes over')
                        result = compose('down', '--remove-orphans')
                        self.assertEqual(0, result.returncode, result.stderr)
                        self.assertEqual([], self.containers())
                        self.assert_kept()
                        self.assertEqual(sorted(volumes), self.existing(volumes))
                        self.assertIn('10 volumes without a name were left', result.stderr)  # the 8 and the operator's 2
                    finally:
                        self.reset()

    def test_a_forced_recreation_renews_them_so_that_none_is_left(self):
        # What every forced recreation in the operator code passes (FORCED_RECREATION): the new
        # container gets its own anonymous volumes, the old ones are removed with the old container.
        for name, compose in self.entry_points().items():
            for options in (common.FORCED_RECREATION, ('--renew-anon-volumes',)):
                with self.subTest(entry_point=name, options=options):
                    try:
                        volumes = self.start()
                        result = compose('up', '-d', *options)
                        self.assertEqual(0, result.returncode, result.stderr)
                        renewed = self.mounted()
                        self.assertEqual(8, len(renewed))
                        self.assertFalse(set(renewed) & set(volumes))
                        self.assertEqual([], self.existing(volumes), f'{name}: the replaced volumes were left')
                        result = compose('down', '--remove-orphans')
                        self.assertEqual(0, result.returncode, result.stderr)
                        self.assertEqual([], self.existing(renewed), f'{name}: anonymous volumes left by down')
                        self.assert_kept()
                    finally:
                        self.reset()

    def test_up_removing_an_orphan_leaves_none_of_its_volumes(self):
        for name, compose in self.entry_points().items():
            with self.subTest(entry_point=name):
                volumes = self.start()
                kept = sorted(volume for volume, service in volumes.items() if service == 'database')
                # The job is no longer configured: `up --remove-orphans` removes its container. The
                # database no longer depends on it, so Compose recreates that one and carries its two over.
                self.file = 'without-job.yml'
                try:
                    result = compose('up', '-d', '--remove-orphans')
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual(kept, self.existing(volumes),
                                     f'{name}: the removed orphan left volumes, or attached ones went')
                    self.assertEqual(kept, sorted(self.mounted()))
                    self.assert_kept()
                finally:
                    self.reset()

    def test_the_project_is_the_one_compose_resolves_for_the_same_command_line(self):
        # scripts/deploy.sh and scripts/rotate-secrets.sh pass no -p. Compose then takes the name
        # from the shell's COMPOSE_PROJECT_NAME, else from the file given with --env-file, else
        # from the Compose file's `name:`. Up to 7358dc83 both wrappers read the shell alone and
        # fell back to "chronicle": for the other two sources they listed that project's volumes
        # (none) and left the real project's without a word.
        other = f'COMPOSE_PROJECT_NAME={self.project}-other\n'
        sources = {'the shell': ('', '', 'docker-compose.yml'),
                   'the shell, over the name in the --env-file file': ('', other, 'docker-compose.yml'),
                   'the --env-file file': ('unset COMPOSE_PROJECT_NAME\n', f'COMPOSE_PROJECT_NAME={self.project}\n', 'docker-compose.yml'),
                   'the --env-file file, over the name in the Compose file': (
                       'unset COMPOSE_PROJECT_NAME\n', f'COMPOSE_PROJECT_NAME={self.project}\n', 'named-other.yml'),
                   "the Compose file's name": ('unset COMPOSE_PROJECT_NAME\n', '', 'named.yml')}
        self.write('named-other.yml', job=True, project=self.project + '-other')
        for wrapper in NAMED_BY_COMPOSE:
            for source, (unset, env_file, file) in sources.items():
                with self.subTest(wrapper=wrapper, name_from=source):
                    try:
                        self.file = file
                        (self.folder / '.env').write_text(env_file)
                        volumes = self.start()
                        command, environment = self.shell(wrapper, 'down', '--remove-orphans', traps=unset)
                        result = subprocess.run(command, cwd=self.folder, env=environment, capture_output=True, text=True, timeout=180)
                        self.assertEqual(0, result.returncode, result.stderr)
                        self.assertEqual([], self.containers(), result.stderr)
                        self.assertEqual([], self.existing(volumes), f'{wrapper}: anonymous volumes left by down')
                        self.assert_kept()
                    finally:
                        (self.folder / '.env').write_text('')
                        self.reset()

    def test_a_termination_signal_during_down_still_removes_them(self):
        # ./chronicle and docker/restore-chronicle.sh leave from a trap on HUP, INT and TERM. Bash
        # runs a trap when the command it is waiting for returns: without the subshell in the
        # wrapper that command is Compose, and the script left before the volumes of the
        # containers it removed were.
        for wrapper in SHELL_WRAPPERS:
            with self.subTest(wrapper=wrapper):
                self.file = 'slow-stop.yml'
                try:
                    volumes = self.start()
                    command, environment = self.shell(wrapper, 'down', '--remove-orphans', traps="trap 'exit 143' TERM\n")
                    with subprocess.Popen(command, cwd=self.folder, env=environment,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True) as process:
                        try:
                            progress = []
                            for line in process.stderr:
                                progress.append(line)
                                if 'Stopping' in line:  # Compose is now waiting for the database to stop
                                    process.send_signal(signal.SIGTERM)
                                    break
                            progress.append(process.stderr.read())
                            self.assertEqual(143, process.wait(timeout=180), ''.join(progress))
                        finally:
                            process.kill()
                    self.assertIn('Stopping', ''.join(progress))
                    self.assertEqual([], self.containers(), 'Compose itself was not interrupted')
                    self.assertEqual([], self.existing(volumes), f'{wrapper}: a signal during down left volumes')
                    self.assert_kept()
                finally:
                    self.reset()

    def test_a_volume_another_container_still_uses_is_kept(self):
        # A container outside the project that took the database container's volumes with
        # --volumes-from. `docker volume rm` refuses a volume only while Docker holds a reference
        # for a container, so the containers are asked (used_volumes).
        for state in ('created', 'exited'):
            with self.subTest(borrower=state):
                volumes = self.start()
                database = self.raw('ps', '-q', 'database').stdout.strip()
                borrower = 'chronicle-anonymous-volumes-borrower-' + uuid.uuid4().hex
                self.extra.append(borrower)
                docker('create' if state == 'created' else 'run', '--name', borrower, '--network', 'none',
                       '--volumes-from', database, '--entrypoint', '/bin/true', self.image)
                with self.operator_environment():
                    result = common.compose('down', '--remove-orphans', capture=True, stderr=subprocess.PIPE)
                self.assertEqual(0, result.returncode, result.stderr)
                still_used = sorted(volume for volume, service in volumes.items() if service == 'database')
                self.assertEqual(still_used, self.existing(volumes), 'only the volumes no container uses may go')
                self.assert_kept()
                docker('rm', '-f', '-v', borrower)
                docker('volume', 'rm', *still_used, check=False)

    def test_a_command_that_removes_no_container_removes_no_volume(self):
        volumes = self.start()
        for name, compose in self.entry_points().items():
            for args in (('ps', '-q'), ('stop', 'database'), ('start', 'database'), ('up', '-d'), ('up', '-d', '--force-recreate')):
                with self.subTest(entry_point=name, args=args):
                    result = compose(*args)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual(volumes, self.mounted())
                    self.assertEqual(sorted(volumes), self.existing(volumes))
        self.assert_kept()

    def test_a_placeholder_left_by_an_interrupted_recreate_takes_its_volumes_with_it(self):
        volumes = self.start()
        placeholder = 'a' * 12 + '_' + self.project + '-database-1'
        self.extra.append(placeholder)
        docker('create', '--name', placeholder, '--network', 'none', '--label', 'com.docker.compose.project=' + self.project,
               '--label', 'com.docker.compose.service=database', self.image)
        own = set(self.mounted()) - set(volumes)
        self.assertEqual(6, len(own))
        with self.operator_environment():
            result = common.compose('up', '-d', capture=True, stderr=subprocess.PIPE)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn(placeholder, docker('ps', '-a', '--format', '{{.Names}}').stdout.split())
        self.assertEqual([], self.existing(own), 'the placeholder left its anonymous volumes')
        self.assertEqual(sorted(volumes), self.existing(volumes))
        self.assert_kept()


class OperatorPathTests(ComposeProject):
    """The calls update, rollback and restore make, on real Docker: the participant data is in the
    named volumes, and these are the commands that remove and recreate the containers around them."""

    def test_rollback_shutdown_keeps_the_named_volumes_and_their_data(self):
        volumes = self.start()
        rollback = Rollback.__new__(Rollback)
        rollback.record = {}  # no volumes created by a candidate: nothing else is removed
        with self.operator_environment():
            rollback.stop_candidate()
        self.assertEqual([], self.containers())
        self.assertEqual([], self.existing(volumes), 'rollback left anonymous volumes')
        self.assert_kept()

    def test_rollback_shutdown_removes_only_the_volumes_the_candidate_created(self):
        volumes = self.start()
        created = self.project + '_candidate-secrets'
        docker('volume', 'create', created)
        self.seen.add(created)
        rollback = Rollback.__new__(Rollback)
        rollback.record = {'created_volumes': [created]}
        with self.operator_environment():
            rollback.stop_candidate()
        self.assertEqual([], self.existing([created, *volumes]))
        self.assert_kept()

    def test_update_shutdown_and_release_start_keep_the_named_volumes_and_their_data(self):
        volumes = self.start()
        names = ['docker-compose.yml']
        # Upgrade.start: stop and remove the previous release, then start the candidate.
        release.compose_release(self.folder, self.project, names, 'down', '--remove-orphans', check=True,
                                capture=True, stderr=subprocess.PIPE)
        self.assertEqual([], self.containers())
        self.assertEqual([], self.existing(volumes), 'the update left the previous release\'s anonymous volumes')
        self.assert_kept()
        upgrade.start_release(self.folder, self.project, names, '120')
        started = self.mounted()
        self.assertEqual(8, len(started))
        # A rerun recreates every container, each with its own new anonymous volumes.
        upgrade.start_release(self.folder, self.project, names, '120')
        renewed = self.mounted()
        self.assertEqual(8, len(renewed))
        self.assertFalse(set(renewed) & set(started))
        self.assertEqual([], self.existing(started), 'the rerun left the volumes of the containers it replaced')
        release.compose_release(self.folder, self.project, names, 'down', '--remove-orphans', check=True,
                                capture=True, stderr=subprocess.PIPE)
        self.assertEqual([], self.existing(renewed), 'a release started twice left anonymous volumes')
        self.assert_kept()

    def test_restore_restart_keeps_the_named_volumes_and_their_data(self):
        volumes = self.start()
        database = sorted(volume for volume, service in volumes.items() if service == 'database')
        with self.operator_environment():
            common.compose('stop', 'database', check=True, capture=True, stderr=subprocess.PIPE)
            # Restore.start, after the database has been restored.
            services.start_split(common.compose, ['database'], [], '120', ('--remove-orphans', *common.FORCED_RECREATION))
        renewed = self.mounted()
        self.assertEqual(8, len(renewed))
        self.assertFalse(set(renewed) & set(database), 'the recreated database kept the old container\'s volumes')
        self.assertEqual([], self.existing(database), 'the restart left the replaced container\'s volumes')
        self.assert_kept()


class HarnessTeardownTests(ComposeProject):
    """A harness removes its own disposable project for good, the volumes Compose carried over
    included (disposable_project_volumes); the operator code leaves those."""

    def kept_by_a_harness(self):
        # A volume the test made by hand stays when its container names it apart from the ones
        # Compose carried over: in HostConfig.Binds (Compose 5), or in HostConfig.Mounts with
        # VolumeOptions (short syntax, Compose 2.17). The long syntax of Compose 2.17 does not.
        kept = []
        for container in json.loads(docker('inspect', *self.containers()).stdout):
            host = container['HostConfig']
            sources = {bind.split(':')[0] for bind in host.get('Binds') or []}
            sources |= {mount['Source'] for mount in host.get('Mounts') or [] if 'VolumeOptions' in mount}
            kept += [volume for volume in self.own.values() if volume in sources]
        self.assertIn(self.own['short'], kept)
        self.assertIn(self.own['elsewhere'], kept)
        return [volume for volume in self.own.values() if volume in kept]

    def test_python_harness_teardown_removes_the_project_and_its_anonymous_volumes(self):
        volumes = self.start(recreate=True)
        kept = self.kept_by_a_harness()
        with anonymous_volumes_removed(self.project):
            self.raw('down', '--volumes', '--remove-orphans')
        self.assertEqual([], self.existing([*volumes, self.project + '_data', self.project + '_data_long']))
        self.assert_kept(kept)  # an external volume is not the project's to remove

    def test_shell_harness_teardown_removes_the_project_and_its_anonymous_volumes(self):
        volumes = self.start(recreate=True)
        kept = self.kept_by_a_harness()
        script = ('source "$1"\nROOT_DIR="$2"\nremove_compose_project "$3" -f "$4" -- -t 1\n')
        result = subprocess.run(['bash', '-eu', '-c', script, 'fixture', str(ROOT / 'tests/security/lib/selfhost-python.sh'),
                                 str(ROOT), self.project, str(self.folder / 'docker-compose.yml')],
                                env=dict(os.environ, SELFHOST_PYTHON_PACKAGE=str(SELFHOST)),
                                capture_output=True, text=True, timeout=180)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], self.containers())
        self.assertEqual([], self.existing([*volumes, self.project + '_data', self.project + '_data_long']))
        self.assert_kept(kept)

    def test_the_harness_list_is_wider_than_the_operators(self):
        volumes = self.start(recreate=True)
        self.assertEqual([], common.anonymous_volumes(self.project), 'every volume is mounted by name after a recreation')
        self.assertEqual(sorted(volumes), disposable_project_volumes(self.project))


class WatchTests(ComposeProject):
    """The watch test_forward_drill uses to assert that its operator commands left nothing."""

    def test_the_watch_names_exactly_what_plain_compose_down_leaves(self):
        watch = AnonymousVolumeWatch(self.project, self.folder)
        self.addCleanup(watch.stop)
        watch.start()
        volumes = self.start(recreate=True)
        # The watch sees names and Docker's label, not the Compose file: the fixture's own volumes,
        # made without a name, look like the image's to it. The drill has no such volume.
        seen = sorted([*volumes, *self.own.values()])
        self.assertEqual(seen, watch.mounted())
        self.assertEqual([], watch.unattached())
        self.raw('down', '--remove-orphans')  # plain Compose, no operator entry point: all of them stay
        self.assertEqual(seen, watch.unattached())
        docker('volume', 'rm', *volumes)
        self.assertEqual(sorted(self.own.values()), watch.unattached())
        self.assertEqual(seen, watch.mounted())


# A `docker` for the tests below. It answers the listing an entry point makes before Compose (one
# container that mounts one anonymous volume) and the project name; what it does for `compose
# down` and afterwards depends on FAKE_DOCKER_MODE:
#   unanswered   `compose down` returns, then every call hangs, as with a daemon that has stopped answering;
#   interrupted  `compose down` waits for SIGINT and exits 130 as Compose does; later calls succeed.
FAKE_DOCKER = r"""#!/usr/bin/env bash
state=$FAKE_DOCKER_STATE
printf '%s\n' "$*" >>"$state/calls"
if [[ $1 == compose ]]; then
  if [[ " $* " == *" config "* ]]; then
    printf 'name: %s\nservices: {}\n' "$FAKE_DOCKER_PROJECT"
    exit 0
  fi
  if [[ $FAKE_DOCKER_MODE == interrupted ]]; then
    trap ': >"$state/compose-interrupted"; exit 130' INT
    echo $$ >"$state/compose-waiting"
    for _ in $(seq 600); do sleep 0.1; done
    exit 0
  fi
  : >"$state/compose-done"
  exit 0
fi
if [[ -e $state/compose-done ]]; then
  echo $$ >>"$state/hung"
  exec sleep 600
fi
[[ -e $state/compose-interrupted ]] && exit 0
case "$1 $2" in
  'ps -a') echo c1 ;;
  'inspect c1') cat "$state/containers.json" ;;
  'volume inspect') cat "$state/volumes.json" ;;
esac
"""
PYTHON_ENTRY_POINT = ('import signal, sys\nfrom chronicle_ops import common\n'
                      'for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):\n    signal.signal(signum, common.interrupted)\n'
                      'try:\n    sys.exit(common.compose(*sys.argv[1:]).returncode)\n'
                      'except common.Interrupted as error:\n    sys.exit(error.status)\n')


class UnansweredDockerTests(unittest.TestCase):
    """What an operator at a terminal gets when Docker stops answering after `compose down`
    returned. No Docker needed: `docker` is FAKE_DOCKER.

    Up to 7358dc83 the shell wrappers ignored HUP, INT and TERM once Compose had returned and
    then made Docker calls limited to 120 seconds each, so Ctrl-C did nothing for minutes."""
    VOLUME = 'a' * 64
    # Above common.AFTER_COMPOSE_SECONDS, far below the 120 seconds one call was given before.
    BOUND = 30

    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix='anonymous-volumes-fake-')).resolve()
        self.addCleanup(shutil.rmtree, self.folder, True)
        (self.folder / 'bin').mkdir()
        (self.folder / 'bin/docker').write_text(FAKE_DOCKER)
        (self.folder / 'bin/docker').chmod(0o755)
        for name in ('.env', 'production.yml', 'docker-compose.yml'):
            (self.folder / name).write_text('')
        self.started = []
        self.addCleanup(self.stop_everything)

    def stop_everything(self):
        """The test's own processes, by pid: each wrapper's process group and each hung fake docker
        (the operator code starts those in a session of their own)."""
        for process, state in self.started:
            for pid in [-process.pid, *self.hung(state)]:
                try:
                    os.kill(pid, signal.SIGKILL) if pid > 0 else os.killpg(-pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            for stream in (process.stdout, process.stderr):
                if stream:
                    stream.close()

    def hung(self, state):
        return [int(pid) for pid in (state / 'hung').read_text().split()] if (state / 'hung').exists() else []

    def running(self, pids):
        alive = []
        for pid in pids:
            try:
                os.kill(pid, 0)
                alive.append(pid)
            except ProcessLookupError:
                pass
            except PermissionError:
                alive.append(pid)
        return alive

    def wait_for(self, condition, seconds, what):
        deadline = time.monotonic() + seconds
        while not condition():
            self.assertLess(time.monotonic(), deadline, 'still waiting for ' + what)
            time.sleep(0.05)

    def entry_points(self):
        return ['chronicle_ops.common.compose', *SHELL_WRAPPERS]

    def launch(self, entry_point, mode, traps=''):
        """Start `down --remove-orphans` through the entry point as a terminal starts a command:
        at the head of its own process group. Returns (process, state directory)."""
        project = 'chronicle-fake-' + uuid.uuid4().hex
        state = self.folder / uuid.uuid4().hex
        state.mkdir()
        container = {'Id': 'c1', 'Config': {'Volumes': {path: {} for path in DECLARED}},
                     'HostConfig': {'Binds': None, 'Mounts': None, 'VolumesFrom': None},
                     'Mounts': [{'Type': 'volume', 'Name': self.VOLUME, 'Destination': '/pgwal'}]}
        (state / 'containers.json').write_text(json.dumps([container]))
        (state / 'volumes.json').write_text(json.dumps([{'Name': self.VOLUME, 'Labels': {ANONYMOUS_LABEL: ''}}]))
        if entry_point in SHELL_WRAPPERS:
            command, environment = wrapper_command(entry_point, ('down', '--remove-orphans'), self.folder,
                                                   'docker-compose.yml', project, traps)
        else:
            command = [sys.executable, '-c', PYTHON_ENTRY_POINT, 'down', '--remove-orphans']
            environment = dict(os.environ, CHRONICLE_OPS_PROJECT=project, PYTHONPATH=str(SELFHOST), PYTHONDONTWRITEBYTECODE='1')
        environment.update(PATH=str(self.folder / 'bin') + os.pathsep + os.environ['PATH'], FAKE_DOCKER_STATE=str(state),
                           FAKE_DOCKER_PROJECT=project, FAKE_DOCKER_MODE=mode)
        process = subprocess.Popen(command, cwd=self.folder, env=environment, start_new_session=True,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        self.started.append((process, state))
        return process, state

    def test_an_interrupt_after_compose_returned_ends_the_command_at_once(self):
        shell_traps = "trap 'exit 129' HUP\ntrap 'exit 130' INT\ntrap 'exit 143' TERM\n"  # as ./chronicle sets them
        for entry_point in self.entry_points():
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                for traps in ('', shell_traps) if entry_point in SHELL_WRAPPERS else ('',):
                    with self.subTest(entry_point=entry_point, signal=signum.name, script_traps=bool(traps)):
                        process, state = self.launch(entry_point, 'unanswered', traps)
                        self.wait_for(lambda: self.hung(state), 30, 'the first Docker call after Compose')
                        os.killpg(process.pid, signum)  # Ctrl-C, or a terminal that closed: the whole foreground group
                        try:
                            status = process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            self.fail(f'{entry_point}: still running 10 seconds after {signum.name}')
                        self.assertIn(status, (128 + signum,) if traps or entry_point not in SHELL_WRAPPERS else (-signum, 128 + signum))
                        # The Docker call it was waiting for went with it.
                        self.wait_for(lambda: not self.running(self.hung(state)), 10, 'the hung docker to be stopped')
                        self.assertNotIn('volume rm', (state / 'calls').read_text())

    def test_the_step_after_compose_gives_up_within_a_short_total(self):
        # No signal at all. Each entry point returns Compose's own status, says that the volumes
        # may have stayed, and leaves no Docker call behind. All of them wait at the same time.
        began = time.monotonic()
        launched = {entry_point: self.launch(entry_point, 'unanswered') for entry_point in self.entry_points()}
        for entry_point, (process, state) in launched.items():
            with self.subTest(entry_point=entry_point):
                try:
                    status = process.wait(timeout=max(1, self.BOUND + 15 - (time.monotonic() - began)))
                except subprocess.TimeoutExpired:
                    self.fail(f'{entry_point}: still running {self.BOUND + 15} seconds after Compose returned')
                said = process.stderr.read()
                self.assertEqual(0, status, said)
                self.assertIn('could not remove the 1 anonymous volume that removed containers may have left', said)
                self.assertIn('Docker did not answer within', said)
                self.assertEqual([], self.running(self.hung(state)))
        self.assertLessEqual(common.AFTER_COMPOSE_SECONDS, self.BOUND)

    def test_the_total_covers_every_docker_call_of_the_step(self):
        state = self.folder / 'direct'
        state.mkdir()
        (state / 'compose-done').write_text('')
        environment = dict(PATH=str(self.folder / 'bin') + os.pathsep + os.environ['PATH'], FAKE_DOCKER_STATE=str(state))
        began = time.monotonic()
        with patch.dict(os.environ, environment), patch.object(common, 'warn') as warned:
            common.after_compose('pilot', [self.VOLUME], seconds=1)
        self.assertLess(time.monotonic() - began, 6)
        self.assertEqual(1, warned.call_count)
        self.assertIn('Docker did not answer within 1 second', warned.call_args.args[0])
        self.assertEqual(1, len(self.hung(state)), 'one call was given the whole second; none was started after it')
        self.assertEqual([], self.running(self.hung(state)))

    def test_one_interrupt_during_down_still_removes_the_volumes(self):
        # Ctrl-C while Compose is stopping containers: Compose ends, and the volumes of the
        # containers it removed are still removed before the command returns 130.
        for entry_point in SHELL_WRAPPERS:
            with self.subTest(entry_point=entry_point):
                process, state = self.launch(entry_point, 'interrupted')
                self.wait_for(lambda: (state / 'compose-waiting').exists(), 30, 'Compose to start')
                os.killpg(process.pid, signal.SIGINT)
                try:
                    status = process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    self.fail(f'{entry_point}: still running 20 seconds after SIGINT')
                self.assertIn(status, (130, -signal.SIGINT), process.stderr.read())
                self.assertIn('volume rm ' + self.VOLUME, (state / 'calls').read_text().splitlines())


class ProjectNameTests(unittest.TestCase):
    """The project of an entry point that passes no -p (no Docker needed)."""
    OPTIONS = ['--env-file', '/srv/chronicle/.env', '-f', 'docker-compose.traefik.yml']

    def compose_answering(self, stdout, status=0, stderr=''):
        calls = []

        def run(args, **_options):
            calls.append(args)
            return subprocess.CompletedProcess(args, status, stdout, stderr)
        return calls, run

    def test_the_name_is_read_from_composes_own_rendering_of_the_same_options(self):
        # Compose 2.17.0 has no "name" in `config --format json`; the YAML of 2.17.0 and 5.5.0
        # starts with `name:`, quoted when YAML would read the name as something else (2026-11-11).
        for rendered, name in (('name: pilot\nservices:\n  backend:\n    container_name: other\n', 'pilot'),
                               ('name: "123"\nservices: {}\n', '123'), ("name: 'on'\nservices: {}\n", 'on'),
                               ('services:\n  backend:\n    image: x\nname: last\n', 'last')):
            calls, run = self.compose_answering(rendered)
            with self.subTest(rendered=rendered), patch.object(common, 'run', side_effect=run):
                self.assertEqual(name, common.resolved_project(self.OPTIONS))
                self.assertEqual([['docker', 'compose', *self.OPTIONS, 'config']], calls)

    def test_a_project_compose_cannot_load_has_no_name(self):
        for rendered, status, stderr in (('', 1, 'required variable POSTGRES_PASSWORD is missing a value\n'),
                                         ('services:\n  backend:\n    name: nested\n', 0, '')):
            calls, run = self.compose_answering(rendered, status, stderr)
            with self.subTest(rendered=rendered), patch.object(common, 'run', side_effect=run):
                with self.assertRaises((ValueError, subprocess.SubprocessError)):
                    common.resolved_project(self.OPTIONS)

    def test_only_a_command_that_can_remove_a_container_asks_and_a_failure_is_said(self):
        with patch.object(common, 'resolved_project', return_value='pilot') as resolved, \
                patch.object(common, 'volume_ownership', return_value=(['a' * 64], ['b' * 64])) as listed:
            self.assertEqual([], common.project_volumes_before(self.OPTIONS, ['ps', '-q']))
            self.assertEqual((0, 0), (resolved.call_count, listed.call_count))
            self.assertEqual(['pilot', 'a' * 64, common.KEPT_VOLUME_PREFIX + 'b' * 64],
                             common.project_volumes_before(self.OPTIONS, ['down', '--remove-orphans']))
            listed.assert_called_once_with('pilot')
        # No volumes: nothing for the shell to do after the command, so not even the name.
        with patch.object(common, 'resolved_project', return_value='pilot'), \
                patch.object(common, 'volume_ownership', return_value=([], [])):
            self.assertEqual([], common.project_volumes_before(self.OPTIONS, ['down']))
        with patch.object(common, 'resolved_project', side_effect=subprocess.SubprocessError('no configuration file')), \
                patch.object(common, 'volume_ownership') as listed, patch.object(common, 'warn') as warned:
            self.assertEqual([], common.project_volumes_before(self.OPTIONS, ['down']))
            self.assertEqual((1, 0), (warned.call_count, listed.call_count))
            self.assertIn('no configuration file', warned.call_args.args[0])


class ForcedRecreationTests(unittest.TestCase):
    def test_every_forced_recreation_in_the_operator_code_renews_the_anonymous_volumes(self):
        # `up --force-recreate` alone has Compose carry the old container's anonymous volumes over,
        # mounted by name; those can no longer be told from an operator's and stay for good.
        files = [SELFHOST / 'chronicle', SELFHOST / 'rotate-secret.sh', *sorted((SELFHOST / 'chronicle_ops').glob('*.py')),
                 ROOT / 'scripts/deploy.sh', ROOT / 'scripts/rotate-secrets.sh', ROOT / 'docker/restore-chronicle.sh']
        found = 0
        for path in files:
            for number, line in enumerate(path.read_text().splitlines(), 1):
                # An option of chronicle_ops's own command line is not a Compose call.
                if '--force-recreate' in line and not line.lstrip().startswith('#') and 'add_argument(' not in line:
                    found += 1
                    self.assertIn('--renew-anon-volumes', line, f'{path}:{number}')
        self.assertGreaterEqual(found, 5)


class SelectionTests(unittest.TestCase):
    """What may be removed, decided from Docker's answers (no Docker needed)."""

    def answers(self, containers, volumes):
        calls = []

        def run(args, **_options):
            calls.append(args)
            if args[:2] == ['docker', 'ps']:
                return subprocess.CompletedProcess(args, 0, '\n'.join(container['Id'] for container in containers) + '\n', '')
            if args[:2] == ['docker', 'inspect']:
                return subprocess.CompletedProcess(args, 0, json.dumps([c for c in containers if c['Id'] in args]), '')
            if args[:3] == ['docker', 'volume', 'inspect']:
                return subprocess.CompletedProcess(args, 0, json.dumps([v for v in volumes if v['Name'] in args]), '')
            return subprocess.CompletedProcess(args, 0, '', '')
        return calls, run

    def container(self, identifier, mounts, declared=DECLARED, binds=None, requested=None, volumes_from=None):
        """mounts: (type, volume, path) as Docker lists them; binds, requested and volumes_from are
        the container's own configuration (HostConfig.Binds, .Mounts and .VolumesFrom)."""
        return {'Id': identifier, 'Config': {'Volumes': {path: {} for path in declared}},
                'HostConfig': {'Binds': binds, 'Mounts': requested, 'VolumesFrom': volumes_from},
                'Mounts': [{'Type': kind, 'Name': name, 'Destination': path} for kind, name, path in mounts]}

    def labelled(self, *names):
        return [{'Name': name, 'Labels': {ANONYMOUS_LABEL: ''}} for name in names]

    def test_only_labelled_volumes_at_declared_paths_are_listed(self):
        anonymous, named, own = 'a' * 64, 'pilot_postgres_data', 'b' * 64
        containers = [self.container('one', [('volume', anonymous, '/pgwal'), ('volume', named, '/data/db'),
                                             ('volume', own, '/operator-data'), ('bind', '', '/selfhost'),
                                             ('volume', 'c' * 64, '/pgconf')],
                                     binds=[named + ':/data/db:rw', own + ':/operator-data:rw', '/srv/selfhost:/selfhost:ro'])]
        volumes = [{'Name': anonymous, 'Labels': {ANONYMOUS_LABEL: ''}}, {'Name': named, 'Labels': {'com.docker.compose.volume': 'postgres_data'}},
                   {'Name': own, 'Labels': {ANONYMOUS_LABEL: ''}}, {'Name': 'c' * 64, 'Labels': None}]
        calls, run = self.answers(containers, volumes)
        with patch.object(common, 'run', side_effect=run):
            self.assertEqual([anonymous], common.anonymous_volumes('pilot'))
            self.assertEqual(([anonymous], []), common.volume_ownership('pilot'))
        self.assertNotIn(own, [arg for call in calls for arg in call], 'a volume at an undeclared path is not even asked about')

    def test_a_volume_the_container_asked_for_by_name_is_never_listed(self):
        # What `docker inspect` showed on Engine 29.8.2 with Compose 5.6.0 and on Engines 20.10.24,
        # 23.0.6 and 27.5.1 with Compose 2.17.0 (2026-11-11), for a volume made by hand without a
        # name and for one Compose carried over. Each of them carries Docker's anonymous label.
        implicit, short, long_, options, carried, key = ('a' * 64, 'b' * 64, 'c' * 64, 'd' * 64, 'e' * 64, 'f' * 64)
        for case, binds, requested in (
                ('short and long syntax, Compose 5: HostConfig.Binds', [short + ':/data/db:rw'], None),
                ('short syntax, Compose 2.17: HostConfig.Mounts with VolumeOptions', None,
                 [{'Type': 'volume', 'Source': short, 'Target': '/data/db', 'VolumeOptions': {}}]),
                ('long syntax, Compose 2.17: HostConfig.Mounts', None, [{'Type': 'volume', 'Source': long_, 'Target': '/data/db'}]),
                ('long syntax with nocopy', None,
                 [{'Type': 'volume', 'Source': options, 'Target': '/data/db', 'VolumeOptions': {'NoCopy': True}}]),
                ('carried over by Compose: HostConfig.Mounts', None, [{'Type': 'volume', 'Source': carried, 'Target': '/data/db'}]),
                ('a top-level key that is the volume\'s name', [key + ':/data/db'], None)):
            asked = (binds[0].split(':')[0] if binds else requested[0]['Source'])
            containers = [self.container('one', [('volume', asked, '/data/db'), ('volume', implicit, '/pgwal')],
                                         binds=binds, requested=requested)]
            calls, run = self.answers(containers, self.labelled(implicit, asked))
            with self.subTest(case=case), patch.object(common, 'run', side_effect=run):
                self.assertEqual(([implicit], [asked]), common.volume_ownership('pilot'))
                self.assertEqual([implicit, common.KEPT_VOLUME_PREFIX + asked], common.before_compose('pilot', ['down']))

    def test_a_volume_another_container_of_the_project_names_or_lends_is_never_listed(self):
        implicit, lent, named_elsewhere = 'a' * 64, 'b' * 64, 'c' * 64
        containers = [
            # Took the lender's volumes with --volumes-from: its configuration names none of them.
            self.container('borrower', [('volume', lent, '/data/db'), ('volume', 'd' * 64, '/pgwal')], volumes_from=['lender']),
            # Mounts at an image path, with nothing in its own configuration, what `two` asks for by name.
            self.container('one', [('volume', named_elsewhere, '/pgdata'), ('volume', implicit, '/pgwal')]),
            self.container('two', [('volume', named_elsewhere, '/operator-data')], binds=[named_elsewhere + ':/operator-data']),
        ]
        calls, run = self.answers(containers, self.labelled(implicit, lent, named_elsewhere, 'd' * 64))
        with patch.object(common, 'run', side_effect=run):
            self.assertEqual(([implicit], sorted([lent, named_elsewhere, 'd' * 64])), common.volume_ownership('pilot'))

    def test_without_dockers_label_nothing_is_listed_and_nothing_is_said(self):
        # Engine 20.10.24 sets no label on any volume (measured 2026-11-11); 23.0.6 and newer do.
        implicit, own = 'a' * 64, 'b' * 64
        containers = [self.container('one', [('volume', implicit, '/pgwal'), ('volume', own, '/data/db')], binds=[own + ':/data/db'])]
        calls, run = self.answers(containers, [{'Name': implicit, 'Labels': {}}, {'Name': own, 'Labels': None}])
        with patch.object(common, 'run', side_effect=run), patch.object(common, 'warn') as warned, \
                patch.object(common, 'note') as noted:
            self.assertEqual(([], []), common.volume_ownership('pilot'))
            listed = common.before_compose('pilot', ['down'])
            self.assertEqual([], listed)
            common.after_compose('pilot', listed)
        self.assertEqual([], [call for call in calls if call[:3] == ['docker', 'volume', 'rm']])
        self.assertEqual((0, 0), (warned.call_count, noted.call_count))

    def test_only_commands_that_can_remove_a_container_take_the_list(self):
        for args, expected in ((['down', '--remove-orphans'], True), (['--progress', 'quiet', 'up', '-d'], True),
                               (['-f', 'down.yml', 'rm', '-f'], True), (['--profile', 'restore', 'run', '--rm', 'restore'], False),
                               (['create', '--force-recreate'], True), (['run', '--rm', '--remove-orphans', 'job'], True),
                               (['ps', '-q', 'down'], False), (['exec', '-T', 'postgres', 'rm', '-f', 'x'], False),
                               (['stop', 'backend'], False), (['logs', '-f'], False), ([], False)):
            with self.subTest(args=args), patch.object(common, 'volume_ownership', return_value=(['a' * 64], ['b' * 64])) as listed, \
                    patch.object(common, 'clear_interrupted_recreates'):
                self.assertEqual(['a' * 64, common.KEPT_VOLUME_PREFIX + 'b' * 64] if expected else [],
                                 common.before_compose('pilot', args))
                self.assertEqual(expected, listed.called)

    def test_a_volume_still_mounted_is_not_removed_and_nothing_is_forced(self):
        gone, attached, borrowed, carried = 'a' * 64, 'b' * 64, 'c' * 64, 'd' * 64
        # `carried` was Docker's own before the command; Compose recreated its container and the
        # new one mounts it by name.
        containers = [self.container('one', [('volume', attached, '/pgwal'), ('volume', carried, '/pgdata')],
                                     requested=[{'Type': 'volume', 'Source': carried, 'Target': '/pgdata'}])]
        calls, run = self.answers(containers, self.labelled(attached, carried))

        def docker_answers(args, **options):
            if args[:4] == ['docker', 'ps', '-a', '-q'] and args[4:6] != ['--filter', 'label=com.docker.compose.project=pilot']:
                calls.append(args)
                # A container of another project lists `borrowed`.
                return subprocess.CompletedProcess(args, 0, 'foreign\n' if 'volume=' + borrowed in args else '', '')
            return run(args, **options)
        with patch.object(common, 'run', side_effect=docker_answers):
            common.after_compose('pilot', [gone, attached, borrowed, carried])
        removals = [call for call in calls if call[:3] == ['docker', 'volume', 'rm']]
        self.assertEqual([['docker', 'volume', 'rm', gone]], removals)
        asked = [argument for call in calls for argument in call if argument.startswith('volume=')]
        self.assertNotIn('volume=' + attached, asked)
        self.assertNotIn('volume=' + carried, asked)

    def test_a_kept_volume_is_reported_once_it_is_unused_and_is_never_removed(self):
        gone, kept_unused, kept_mounted, kept_elsewhere = 'a' * 64, 'b' * 64, 'c' * 64, 'd' * 64
        containers = [self.container('one', [('volume', kept_mounted, '/pgwal')], binds=[kept_mounted + ':/pgwal'])]
        calls, run = self.answers(containers, self.labelled(kept_mounted))

        def docker_answers(args, **options):
            if args[:4] == ['docker', 'ps', '-a', '-q'] and args[4:6] != ['--filter', 'label=com.docker.compose.project=pilot']:
                calls.append(args)
                return subprocess.CompletedProcess(args, 0, 'foreign\n' if 'volume=' + kept_elsewhere in args else '', '')
            return run(args, **options)
        listed = [gone, *(common.KEPT_VOLUME_PREFIX + name for name in (kept_unused, kept_mounted, kept_elsewhere))]
        with patch.object(common, 'run', side_effect=docker_answers), patch.object(common, 'note') as noted:
            common.after_compose('pilot', listed)
        self.assertEqual([['docker', 'volume', 'rm', gone]], [call for call in calls if call[:3] == ['docker', 'volume', 'rm']])
        self.assertEqual(1, noted.call_count)
        self.assertIn('1 volume without a name was left: the removed containers mounted it by name', noted.call_args.args[0])
        # Only kept volumes: nothing to remove, the report alone.
        calls.clear()
        with patch.object(common, 'run', side_effect=docker_answers), patch.object(common, 'note') as noted:
            common.after_compose('pilot', [common.KEPT_VOLUME_PREFIX + kept_unused, common.KEPT_VOLUME_PREFIX + 'e' * 64])
        self.assertEqual([], [call for call in calls if call[:3] == ['docker', 'volume', 'rm']])
        self.assertIn('2 volumes without a name were left: the removed containers mounted them by name', noted.call_args.args[0])

    def test_nothing_is_asked_or_removed_without_a_list_or_when_docker_fails(self):
        calls, run = self.answers([], [])
        with patch.object(common, 'run', side_effect=run):
            common.after_compose('pilot', [])
        self.assertEqual([], calls)

        def failing(args, **_options):
            raise subprocess.CalledProcessError(1, args)
        # Neither raises, neither removes on a guess, and each says that volumes may stay.
        with patch.object(common, 'run', side_effect=failing), patch.object(common, 'warn') as warned:
            self.assertEqual([], common.before_compose('pilot', ['down']))
            self.assertEqual(1, warned.call_count)
            common.after_compose('pilot', ['a' * 64])
            self.assertEqual(2, warned.call_count)
            self.assertEqual([], common.before_compose('pilot', ['ps']))  # not asked, so nothing to report
            self.assertEqual(2, warned.call_count)

    def test_a_failure_after_the_command_says_what_could_not_be_done(self):
        def failing(args, **_options):
            raise subprocess.CalledProcessError(1, args)
        kept = common.KEPT_VOLUME_PREFIX + 'c' * 64
        for listed, said in ((['a' * 64], 'could not remove the 1 anonymous volume that removed containers may have left'),
                             (['a' * 64, 'b' * 64, kept], 'could not remove the 2 anonymous volumes that removed containers may have left'),
                             # Nothing in the list may be removed: only the count of kept volumes is lost.
                             ([kept], 'could not see which volumes without a name the removed containers left unused')):
            with self.subTest(listed=len(listed)), patch.object(common, 'run', side_effect=failing), \
                    patch.object(common, 'warn') as warned:
                common.after_compose('pilot', listed)
                self.assertEqual(1, warned.call_count)
                self.assertIn(said, warned.call_args.args[0])
                self.assertNotIn(' 0 ', warned.call_args.args[0])
        # A removal Docker refused for a reason of its own is counted the same way.
        for refused, said in ((1, 'could not remove 1 anonymous volume that removed containers left'),
                              (2, 'could not remove 2 anonymous volumes that removed containers left')):
            def run(args, count=refused, **_options):
                if args[:3] == ['docker', 'volume', 'rm']:
                    return subprocess.CompletedProcess(args, 1, '', 'Error response from daemon: remove x: permission denied\n' * count)
                return subprocess.CompletedProcess(args, 0, '', '')
            with self.subTest(refused=refused), patch.object(common, 'run', side_effect=run), patch.object(common, 'warn') as warned:
                common.after_compose('pilot', ['a' * 64, 'b' * 64])
                self.assertIn(said, warned.call_args.args[0])

    def test_a_docker_error_is_a_failure_and_an_object_removed_meanwhile_is_not(self):
        anonymous = 'a' * 64
        containers = [self.container('one', [('volume', anonymous, '/pgwal')])]
        for stderr, listed in (('Error response from daemon: No such container: two\n', [anonymous]),
                               ('error: no such object: two\n', [anonymous]),
                               ('Error response from daemon: client version 1.99 is too new\n', None),
                               ('', None)):
            def run(args, refusal=stderr, **_options):
                if args[:2] == ['docker', 'ps']:
                    return subprocess.CompletedProcess(args, 0, 'one\ntwo\n', '')
                if args[:2] == ['docker', 'inspect']:
                    return subprocess.CompletedProcess(args, 1, json.dumps(containers), refusal)
                return subprocess.CompletedProcess(args, 0, json.dumps([{'Name': anonymous, 'Labels': {ANONYMOUS_LABEL: ''}}]), '')
            with self.subTest(stderr=stderr), patch.object(common, 'run', side_effect=run), \
                    patch.object(common, 'warn') as warned:
                if listed is None:
                    with self.assertRaises(subprocess.SubprocessError):
                        common.anonymous_volumes('pilot')
                    self.assertEqual([], common.before_compose('pilot', ['down']))
                    self.assertEqual(1, warned.call_count)
                else:
                    self.assertEqual(listed, common.anonymous_volumes('pilot'))
                    self.assertEqual(0, warned.call_count)

    def test_only_a_removal_docker_refused_for_another_reason_is_reported(self):
        for stderr, warnings in (('', 0), ('Error response from daemon: remove {0}: volume is in use - [1f2e]\n', 0),
                                 ('Error response from daemon: get {0}: no such volume\n', 0),
                                 ('Error response from daemon: remove {0}: permission denied\n', 1)):
            def run(args, refusal=stderr, **_options):
                if args[:2] == ['docker', 'ps']:
                    return subprocess.CompletedProcess(args, 0, '', '')
                return subprocess.CompletedProcess(args, 1 if refusal else 0, '', refusal.format('a' * 64))
            with self.subTest(stderr=stderr), patch.object(common, 'run', side_effect=run), \
                    patch.object(common, 'warn') as warned:
                common.after_compose('pilot', ['a' * 64])
                self.assertEqual(warnings, warned.call_count)


if __name__ == '__main__':
    unittest.main()
