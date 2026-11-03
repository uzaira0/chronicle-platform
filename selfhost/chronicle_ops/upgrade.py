"""Post-reset release handoff with a quiesced dump and automatic guarded rollback."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from .common import (Interrupted, PREPARATION_TIMEOUT_SECONDS, UPDATE_PEAK_BYTES, acquire_operation_lock,
                     application_services, compose_project, release_operation_lock, require, require_storage, run, warn)
from .envfile import read_env, value
from .ingress import close_ingress, open_ingress
from .env_migration import compose_names, merge_env
from .receipts import OPERATOR_RECEIPTS_DIR, durable_replace, finish_operation, json_text, publish_journal, write_json, write_text
from .reconcile import ENABLED_ENV, RECOVERY_FILE, RECOVERY_PHASE, UPGRADE_LOCK, check_mutations, preflight
from .release import (ROLLBACK_DUMP, certificate_digest, compose_release, free_disk_floor,
                      postgres_major, postgres_sql, read_manifest, record_applied_certificates,
                      release_command, require_current_owner, require_upgrade, rollback_dump)
from .startup import DEFAULT_STARTUP_TIMEOUT_SECONDS, startup_timeout

PREPARED = 'prepared'
COMMITTED = 'committed'
# Application log records below WARN; every other line (errors, stack traces, plain script output) is shown.
ROUTINE_LOG_LINE = re.compile(r'\S+ (TRACE|DEBUG|INFO) ')


def start_release(directory, project, names, timeout):
    timeout = startup_timeout(timeout, 'START_WAIT_TIMEOUT_SECONDS')
    configured = compose_release(directory, project, names, 'config', '--services',
                                 capture=True, check=True).stdout.splitlines()
    startup = [service for service in configured if service and service != 'ca-export']
    require(startup, 'release has no services to start')
    compose_release(directory, project, names, 'up', '-d', '--wait', '--wait-timeout', timeout,
                    '--remove-orphans', '--force-recreate', *startup, check=True)
    if 'ca-export' in configured:
        compose_release(directory, project, names, 'run', '--rm', '--no-deps', 'ca-export', check=True)


def save_failed_service_logs(directory, project, names, state):
    """Recovery recreates the containers, so keep and show each failed service's log before it does."""
    try:
        exited = compose_release(directory, project, names, 'ps', '-a', '--status', 'exited', '--format',
                                 '{{.Service}} {{.ExitCode}}', capture=True, check=True,
                                 timeout=PREPARATION_TIMEOUT_SECONDS).stdout.splitlines()
        failed = [row.split()[0] for row in exited if len(row.split()) == 2 and row.split()[1] != '0']
        folder = Path(state) / OPERATOR_RECEIPTS_DIR / 'failed-services'
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        for service in failed:
            log = compose_release(directory, project, names, 'logs', '--no-color', '--no-log-prefix', service,
                                  capture=True, timeout=PREPARATION_TIMEOUT_SECONDS).stdout
            path = folder / f'{stamp}-{service}.log'
            write_text(path, log)
            print(f'{service} failed:', *(line for line in log.splitlines() if not ROUTINE_LOG_LINE.match(line)),
                  f'Full {service} log: {path}', sep='\n')
        return failed
    except (OSError, subprocess.SubprocessError) as error:
        warn(f'could not save the failed services\' logs: {error}')
        return []


class Upgrade:
    def __init__(self, previous, candidate, state, settings):
        self.previous, self.candidate, self.state = previous, candidate, state
        self.settings = settings
        self.project = compose_project(settings)
        self.names = compose_names(settings, previous)
        # `./chronicle update` does not source .env, so read the update wait from the settings file too.
        # Unset or empty means the generic START_WAIT_TIMEOUT_SECONDS.
        override = os.environ.get('UPGRADE_WAIT_TIMEOUT_SECONDS') or value(settings, 'UPGRADE_WAIT_TIMEOUT_SECONDS')
        self.timeout = (startup_timeout(override, 'UPGRADE_WAIT_TIMEOUT_SECONDS') if override else startup_timeout(
            value(settings, 'START_WAIT_TIMEOUT_SECONDS', DEFAULT_STARTUP_TIMEOUT_SECONDS), 'START_WAIT_TIMEOUT_SECONDS'))
        self.marker = state / UPGRADE_LOCK
        self.recovery = dict(previous=str(previous), owner=str(candidate), phase=PREPARED)
        self.failed_services = []

    def dc(self, directory, *args, **kwargs):
        return compose_release(directory, self.project, self.names, *args, **kwargs)

    def save(self):
        write_json(self.marker / RECOVERY_FILE, self.recovery)

    def prepare(self):
        previous, _ = read_manifest(self.previous.parent / 'release-manifest.json', False, discovery=True)
        candidate, _ = read_manifest(self.candidate.parent / 'release-manifest.json', True)
        require_upgrade(previous['release_version'], candidate)
        from .update import show_changelog
        show_changelog(self.candidate.parent, previous['release_version'], candidate['release_version'])
        require(not os.path.lexists(self.candidate / '.env'), 'candidate already has deployment settings')
        check_mutations(self.state, self.candidate)
        require_storage(self.state, self.project, free_disk_floor(self.settings), UPDATE_PEAK_BYTES,
                        image=value(self.settings, "POSTGRES_IMAGE"))
        preflight()
        merge_env(self.settings, (self.candidate / '.env.example').read_text(),
                  self.candidate / '.env', self.state, self.names)
        for args in (('config', '--quiet'), ('pull', '--policy', 'missing'),
                     ('run', '--rm', '--no-deps', 'config-guard')):
            self.dc(self.candidate, *args, check=True)
        postgres = self.dc(self.previous, 'ps', '-q', 'postgres', capture=True, check=True).stdout.strip()
        require(postgres, 'previous PostgreSQL container is not running')
        health = run(['docker', 'inspect', '--format', '{{.State.Health.Status}}', postgres],
                     capture=True, check=True).stdout.strip()
        require(health == 'healthy', 'previous PostgreSQL is not healthy')
        old_major = postgres_sql(postgres, 'SHOW server_version_num')
        require(old_major.isdigit(), 'invalid PostgreSQL server_version_num')
        config = self.dc(self.candidate, 'config', '--format', 'json', capture=True, check=True).stdout
        image = json.loads(config)['services']['postgres']['image']
        version = run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                       '--entrypoint', 'postgres', image, '--version'], capture=True, check=True).stdout
        require(int(old_major) // 10000 == postgres_major(version, image),
                'automatic update refuses a PostgreSQL major change; see docs/UPGRADE-ROLLBACK.md')
        run(['python3', str(self.candidate / 'network-subnet.py'), 'check'], input=config, check=True)

    def snapshot(self):
        publish_journal(self.marker, {RECOVERY_FILE: json_text(self.recovery)})
        from .update import HANDOFF_FILE
        (self.state / HANDOFF_FILE).unlink(missing_ok=True)
        close_ingress(self.state)
        # The complete record is published atomically before the first stop.
        services = self.dc(self.previous, 'config', '--services', capture=True, check=True).stdout.splitlines()
        writers = application_services(services)
        self.dc(self.previous, 'stop', *writers, check=True)
        running = self.dc(self.previous, 'ps', '--status', 'running', '--services', capture=True,
                          check=True).stdout.splitlines()
        require('postgres' in running and not set(writers).intersection(running),
                'application writers did not stop; database dump was not started')
        backups = self.state / 'backups'
        require(backups.is_dir() and not backups.is_symlink(), 'unsafe or missing backups directory')
        backups.chmod(0o700)
        backup = backups / f'pre-upgrade-{time.time_ns()}.sql.gz'
        partial = backup.with_suffix(backup.suffix + '.partial')
        command, environment = release_command(self.previous, self.project, self.names)
        environment['RELEASE_VERSION'] = json.loads(
            (self.previous.parent / 'release-manifest.json').read_text())['release_version']
        try:
            digest = rollback_dump([*command, 'exec', '-T', 'postgres', '/bin/bash', '-ceu', ROLLBACK_DUMP],
                                   partial, cwd=self.previous, env=environment)
            durable_replace(partial, backup)
        finally:
            partial.unlink(missing_ok=True)
        self.recovery.update(backup=str(backup), sha256=digest)
        self.save()

    def start(self):
        self.dc(self.previous, 'stop', check=True)
        self.recovery['phase'] = RECOVERY_PHASE
        self.save()  # Never restart the old backend after this point without restoring.
        self.dc(self.previous, 'down', '--remove-orphans', check=True)
        os.chdir(self.candidate)
        os.environ['COMPOSE_FILE'] = ':'.join(self.names)
        try:
            start_release(self.candidate, self.project, self.names, self.timeout)
        except subprocess.CalledProcessError:
            self.failed_services = save_failed_service_logs(self.candidate, self.project, self.names, self.state)
            raise
        certificates = certificate_digest(self.state)
        run(['./chronicle', 'verify'], check=True)
        record_applied_certificates(self.state, certificates)
        from .reconcile import install
        install(self.candidate / 'chronicle', self.state, self.project)
        self.recovery['phase'] = COMMITTED
        self.save()  # After this durable commit, recovery must never restore the old dump.
        open_ingress(self.state)
        clear_recovery(self.marker)
        print(f'Update verified. Run future commands from: {self.candidate}')


def clear_recovery(marker):
    from .update import HANDOFF_FILE
    (marker.parent / HANDOFF_FILE).unlink(missing_ok=True)
    retired = marker.with_name(marker.name + '.completed')
    if retired.exists():
        shutil.rmtree(retired)
    durable_replace(marker, retired)
    shutil.rmtree(retired)


def recover_update(state):
    """Called under the operation lock, including after SIGKILL or host restart."""
    marker = Path(state) / UPGRADE_LOCK
    if not marker.exists():
        return False
    recovery = json.loads((marker / RECOVERY_FILE).read_text())
    previous, candidate = Path(recovery['previous']), Path(recovery['owner'])
    require(Path.cwd().resolve() in (previous, candidate),
            f'incomplete update; run update from {previous} or {candidate}')
    settings = read_env(previous / '.env')
    names = compose_names(settings, previous)
    project = compose_project(settings)
    close_ingress(state)
    if recovery['phase'] == PREPARED:
        start_release(previous, project, names, value(settings, 'START_WAIT_TIMEOUT_SECONDS', DEFAULT_STARTUP_TIMEOUT_SECONDS))
        run([str(previous / 'chronicle'), 'verify'], check=True)
        recovery['phase'] = COMMITTED
        recovery['owner'] = str(previous)
        write_json(marker / RECOVERY_FILE, recovery)
        open_ingress(state)
        clear_recovery(marker)
        (candidate / '.env').unlink(missing_ok=True)
    elif recovery['phase'] == COMMITTED:
        active = Path(recovery['owner'])
        os.chdir(active)
        run([str(active / 'chronicle'), 'verify'], check=True)
        open_ingress(state)
        if recovery.get('settings_archive'):
            from .reconcile import STOP_MARKER
            (Path(state) / STOP_MARKER).unlink(missing_ok=True)
        clear_recovery(marker)
        print(f'Committed release recovered: {active}')
        return True
    else:
        from .restore import ROLLBACK_PHASES, rollback
        require(recovery['phase'] in (RECOVERY_PHASE, *ROLLBACK_PHASES), 'unrecognized update recovery phase')
        os.chdir(candidate)
        require(rollback(previous, recovery.get('dump') or '/backups/' + Path(recovery['backup']).name,
                         recovery['sha256'], True) == 0, 'automatic rollback failed; retain recovery state')
    os.chdir(previous)
    os.environ['CHRONICLE_OPS_VERSION'] = value(settings, 'RELEASE_VERSION', 'unknown')
    print(f'Previous release recovered with its data: {previous}')
    return True


def upgrade(previous, candidate):
    previous, candidate = Path(previous).resolve(), Path(candidate).resolve()
    settings = read_env(previous / '.env')
    state = (previous / value(settings, 'CHRONICLE_STATE_DIR', '.')).resolve()
    descriptor = acquire_operation_lock(state)
    began, status, operation = time.monotonic(), 1, None
    origin = Path.cwd()
    try:
        require((previous / '.env').stat().st_mode & 0o777 == 0o600, 'previous .env must have mode 0600')
        settings = read_env(previous / '.env')
        require((previous / value(settings, 'CHRONICLE_STATE_DIR', '.')).resolve() == state,
                'state changed while acquiring the lock; retry update')
        os.environ.update(CHRONICLE_OPS_STATE=str(state), CHRONICLE_OPS_BACKUPS=str(state / 'backups'),
                          CHRONICLE_OPS_PROJECT=compose_project(settings),
                          CHRONICLE_OPS_VERSION=value(settings, 'RELEASE_VERSION', 'unknown'))
        os.environ.setdefault(ENABLED_ENV, value(settings, ENABLED_ENV, 'true'))
        require_current_owner(previous, state, os.environ['CHRONICLE_OPS_PROJECT'])
        operation = Upgrade(previous, candidate, state, settings)
        operation.prepare()
        operation.snapshot()
        operation.start()
        os.environ['CHRONICLE_OPS_VERSION'] = value(read_env(candidate / '.env'), 'RELEASE_VERSION', 'unknown')
        status = 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, Interrupted) as error:
        print(f'Update failed: {error}')
        status = error.status if isinstance(error, Interrupted) else 1
        if (state / UPGRADE_LOCK / RECOVERY_FILE).exists():
            try:
                os.chdir(previous)
                recover_update(state)
            except (OSError, ValueError, KeyError, subprocess.SubprocessError, Interrupted) as recovery_error:
                print(f'Automatic rollback incomplete: {recovery_error}. See docs/UPGRADE-ROLLBACK.md')
    finally:
        try:
            failed = operation.failed_services if operation else []
            finish_operation('upgrade', status, 'migration_failed' if 'migrate' in failed else 'upgrade_failed', began)
        finally:
            os.chdir(origin)
            release_operation_lock(descriptor)
    return status
