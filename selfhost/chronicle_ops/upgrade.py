"""Post-reset release handoff with a quiesced dump and automatic guarded rollback."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from .common import (FORCED_RECREATION, Interrupted, PREPARATION_TIMEOUT_SECONDS, UPDATE_PEAK_BYTES, acquire_operation_lock,
                     application_services, compose_project, release_operation_lock, require, require_storage, run, warn)
from .envfile import read_env, value
from .ingress import close_ingress, open_ingress
from .env_migration import compose_names, compose_selection, merge_env, migrate_settings, running_selection
from .receipts import OPERATOR_RECEIPTS_DIR, durable_replace, finish_operation, json_text, publish_journal, write_json, write_text
from .reconcile import ENABLED_ENV, RECOVERY_FILE, RECOVERY_PHASE, STOP_MARKER, UPGRADE_LOCK, check_mutations, preflight
from .release import (ROLLBACK_DUMP, certificate_digest, compose_release, free_disk_floor, front_door_target,
                      postgres_major, postgres_sql, LOCAL_EDITS_DIR, preserve_local_edits, read_manifest, record_applied_certificates,
                      release_command, require_current_owner, require_upgrade, rollback_dump, transfer_deployment)
from .host_versions import warn_architecture, warn_outdated
from .services import awaited_by_update, release_roles, report_unawaited, start_split
from .startup import DEFAULT_STARTUP_TIMEOUT_SECONDS, startup_timeout
from .verify import BASELINE_ENV, failed_checks, regressions
from .restore import RESTORED_STOP, Restore

PREPARED = 'prepared'
COMMITTED = 'committed'
# Application log records below WARN; every other line (errors, stack traces, plain script output) is shown.
ROUTINE_LOG_LINE = re.compile(r'\S+ (TRACE|DEBUG|INFO) ')


def start_release(directory, project, names, timeout):
    """Wait on the release's core services; db-backup (services.UNAWAITED_BY_UPDATE) and optional
    monitoring are started after them and only warn."""
    timeout = startup_timeout(timeout, 'START_WAIT_TIMEOUT_SECONDS')
    core, monitoring = release_roles(
        lambda selection, *args, **kwargs: compose_release(directory, project, selection, *args, **kwargs), names)
    startup, unawaited = awaited_by_update([service for service in core if service != 'ca-export'])
    require(startup, 'release has no services to start')
    start_split(lambda *args, **kwargs: compose_release(directory, project, names, *args, **kwargs),
                startup, monitoring, timeout, ('--remove-orphans', *FORCED_RECREATION), unawaited)
    if 'ca-export' in core:
        compose_release(directory, project, names, 'run', '--rm', '--no-deps', 'ca-export', check=True)


def report_release_readiness(directory, project, names):
    """After an update or rollback commits: the state of the services it did not wait on. Never raises."""
    def dc(*args, **kwargs):
        return compose_release(directory, project, names, *args, **kwargs)
    try:
        core, _ = release_roles(lambda selection, *args, **kwargs: compose_release(directory, project, selection, *args, **kwargs),
                                names)
        report_unawaited(dc, awaited_by_update(core)[1])
    except Exception as error:  # noqa: BLE001 - after the commit a report must never turn success into failure
        warn(f'could not report the state of the release\'s services ({error}); ./chronicle doctor reports it')


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


DATABASE_MOUNTS = ('/data/db', '/var/lib/postgresql/tde-keyring')


# verify_release runs right after a start. Some probes measure a warm stack: the edge rate-limit
# probe needs its burst to land inside one rate-limit window, which a backend still warming up
# answers too slowly for (2026.11.6 drill: a rollback's 2026.11.2 verify failed so, and the
# rollback stopped). A release's verifier cannot be changed after it ships, so a verification
# whose failures are new is rerun after a pause until VERIFY_SETTLE_SECONDS have passed; only a
# failure that persists counts.
VERIFY_SETTLE_SECONDS = 180
VERIFY_RETRY_DELAYS = (15, 30, 60)


def verify_release(launcher, baseline, **kwargs):
    """Run a release's ./chronicle verify (an older release's knows no baseline) and fail only on
    checks the update made fail. baseline lists the FAIL messages from before the update; None
    means the pre-update verification could not run, so every failure is reported, not fatal."""
    deadline, waited, delays = time.monotonic() + VERIFY_SETTLE_SECONDS, 0, iter(VERIFY_RETRY_DELAYS)
    while True:
        os.environ[BASELINE_ENV] = json.dumps(baseline or [])
        try:
            result = run([str(launcher), 'verify'], capture=True, **kwargs)
        finally:
            os.environ.pop(BASELINE_ENV, None)
        caused = regressions(result.returncode, result.stdout or '', baseline or [])
        delay = next(delays, VERIFY_RETRY_DELAYS[-1])
        if not caused or waited + delay > VERIFY_SETTLE_SECONDS or time.monotonic() + delay > deadline:
            break
        warn(f'verification right after the start failed ({"; ".join(caused)}); the services may still be '
             f'settling, so it runs again in {delay} s')
        time.sleep(delay)
        waited += delay
    print(result.stdout or '', end='', flush=True)
    if caused and baseline is None:
        warn(f'{len(caused)} verification check(s) fail after the update: ' + '; '.join(caused) + '. The pre-update '
             'verification could not run, so they are reported and do not roll the update back; ./chronicle verify lists them')
        return
    require(not caused, 'verification failed: ' + '; '.join(caused))
    if baseline:
        count = len(baseline)
        warn(f'{count} check{"s" if count != 1 else ""} already failed before this update and do not roll it back; '
             './chronicle verify lists them')


def default_core_prefix(release):
    """The core network's first /24, read from the release's network-subnet.py, which owns the range.
    Loaded, not run: it is the fallback for when running that script failed."""
    from .common import network_subnet
    return network_subnet(release).DEFAULT_CORE_PREFIX


def database_volumes(config):
    """Docker names of the volumes holding PostgreSQL's data directory and TDE keyring."""
    names = config.get('volumes') or {}
    return {(names.get(mount['source']) or {}).get('name', mount['source'])
            for mount in config['services']['postgres'].get('volumes') or []
            if mount.get('type') == 'volume' and mount.get('target') in DATABASE_MOUNTS}


def named_volumes(config):
    """Docker names of the volumes a rendered Compose configuration creates (not external ones)."""
    return {(spec or {}).get('name', key) for key, spec in (config.get('volumes') or {}).items()
            if not (spec or {}).get('external')}


def caddy_hash(image, password):
    """bcrypt through the release's Caddy image, as setup does; the password travels on stdin."""
    return run(['docker', 'run', '--rm', '-i', '--network', 'none', '--read-only', '--entrypoint', 'caddy',
                image, 'hash-password'], input=password + '\n', capture=True, check=True).stdout.strip()


class Upgrade:
    def __init__(self, previous, candidate, state, settings):
        self.previous, self.candidate, self.state = previous, candidate, state
        self.settings = settings
        self.project = compose_project(settings)
        # The previous release is stopped, dumped and restarted with the files it runs with,
        # operator overlays included; the candidate gets the supported selection.
        self.previous_names = running_selection(settings, previous)
        self.names = compose_names(settings, previous)
        # `./chronicle update` does not source .env, so read the update wait from the settings file too.
        # Unset or empty means the generic START_WAIT_TIMEOUT_SECONDS.
        override = os.environ.get('UPGRADE_WAIT_TIMEOUT_SECONDS') or value(settings, 'UPGRADE_WAIT_TIMEOUT_SECONDS')
        self.timeout = (startup_timeout(override, 'UPGRADE_WAIT_TIMEOUT_SECONDS') if override else startup_timeout(
            value(settings, 'START_WAIT_TIMEOUT_SECONDS', DEFAULT_STARTUP_TIMEOUT_SECONDS), 'START_WAIT_TIMEOUT_SECONDS'))
        self.marker = state / UPGRADE_LOCK
        self.recovery: dict = dict(previous=str(previous), owner=str(candidate), phase=PREPARED)
        self.failed_services = []
        self.baseline = None  # FAIL messages of the pre-update verify; None: it could not run

    def dc(self, directory, *args, **kwargs):
        names = self.previous_names if directory == self.previous else self.names
        return compose_release(directory, self.project, names, *args, **kwargs)

    def save(self):
        write_json(self.marker / RECOVERY_FILE, self.recovery)

    def prepare(self):
        # The directory the operator runs ./chronicle from; the commit step makes it forward.
        self.recovery['front_door'] = str(front_door_target(self.previous, self.state))
        leftover = self.candidate / '.env'
        if os.path.lexists(leftover):
            # upgrade() runs only without a journal, so the previous release never stopped and the
            # candidate never started: these are the settings an interrupted prepare derived.
            warn('an earlier update attempt was interrupted while preparing; its candidate settings are derived again')
            leftover.unlink()
        # Operator edits to the installed bundle never stop an update; they are kept with a diff.
        previous, _ = read_manifest(self.previous.parent / 'release-manifest.json', False, discovery=True, installed=True)
        self.recovery_version = previous['release_version']
        candidate, _ = read_manifest(self.candidate.parent / 'release-manifest.json', True)
        require_upgrade(previous['release_version'], candidate)
        preserve_local_edits(self.previous.parent, previous, self.candidate.parent, self.state)
        from .update import show_changelog
        show_changelog(self.candidate.parent, previous['release_version'], candidate['release_version'])
        check_mutations(self.state, self.candidate)
        require_storage(self.state, self.project, free_disk_floor(self.settings), UPDATE_PEAK_BYTES,
                        image=value(self.settings, "POSTGRES_IMAGE"))
        preflight()
        warn_outdated(run)  # Host versions only warn; they never stop an update.
        warn_architecture(run)  # So does a non-amd64 daemon: the deployment already runs.
        self.migrate_settings(previous['release_version'])
        merge_env(self.settings, (self.candidate / '.env.example').read_text(),
                  self.candidate / '.env', self.state, self.names)
        self.dc(self.candidate, 'config', '--quiet', check=True)
        self.pull_images()
        config = self.dc(self.candidate, 'config', '--format', 'json', capture=True, check=True).stdout
        previous_config = json.loads(self.dc(self.previous, 'config', '--format', 'json', capture=True, check=True).stdout)
        # Before secrets-init below creates the new release's credential volumes, so a rollback
        # of this update knows to remove them.
        self.record_created_volumes(previous_config, json.loads(config))
        # secrets-init first: config-guard checks the credential files it writes from the new .env.
        self.dc(self.candidate, 'run', '--rm', '--no-deps', 'secrets-init', check=True)
        self.dc(self.candidate, 'run', '--rm', '--no-deps', 'config-guard', check=True)
        postgres = self.dc(self.previous, 'ps', '-q', 'postgres', capture=True, check=True).stdout.strip()
        require(postgres, 'previous PostgreSQL container is not running')
        health = run(['docker', 'inspect', '--format', '{{.State.Health.Status}}', postgres],
                     capture=True, check=True).stdout.strip()
        require(health == 'healthy', 'previous PostgreSQL is not healthy')
        old_major = postgres_sql(postgres, 'SHOW server_version_num')
        require(old_major.isdigit(), 'invalid PostgreSQL server_version_num')
        image = json.loads(config)['services']['postgres']['image']
        version = run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                       '--entrypoint', 'postgres', image, '--version'], capture=True, check=True).stdout
        old, new = int(old_major) // 10000, postgres_major(version, image)
        if old != new:
            self.prepare_new_major(postgres, old, new, previous_config, json.loads(config))
        else:
            # An operator overlay the new release leaves out may have moved the database: starting
            # without it would serve another (empty) database, so this is the one refusal.
            kept, fresh = database_volumes(previous_config), database_volumes(json.loads(config))
            dropped = [name for name in self.previous_names if name not in self.names]
            require(kept == fresh, f'the running release keeps PostgreSQL in {", ".join(sorted(kept))}'
                    f'{" (set by " + ", ".join(dropped) + ")" if dropped else ""}, but the new release would start it on '
                    f'{", ".join(sorted(fresh))}; nothing was stopped. Move that volume selection out of the operator '
                    'Compose file before updating (docs/UPGRADE-ROLLBACK.md)')
        run(['python3', str(self.candidate / 'network-subnet.py'), 'check'], input=config)  # warns only
        self.baseline = self.verify_previous()
        # Every verification of this update, including a resumed recovery's, judges against it.
        self.recovery['baseline'] = self.baseline

    def pull_images(self):
        """Chronicle's own images must be present; monitoring's are optional like the services, so
        a registry that cannot serve one of them only warns and the update goes on without it."""
        core, monitoring = release_roles(
            lambda selection, *args, **kwargs: compose_release(self.candidate, self.project, selection, *args, **kwargs),
            self.names)
        self.dc(self.candidate, 'pull', '--policy', 'missing', *core, check=True)
        if monitoring:
            try:
                self.dc(self.candidate, 'pull', '--policy', 'missing', *monitoring, check=True)
            except (OSError, subprocess.SubprocessError) as error:
                warn(f'could not pull the monitoring images ({error}); the update continues, and monitoring '
                     'starts once its images can be pulled (./chronicle doctor reports it)')

    def record_created_volumes(self, previous_config, candidate_config):
        """The volumes the candidate will create (its secrets, a new major's database): a rollback of
        this update removes exactly these, so a retry finds the host as the first attempt did."""
        try:
            existing = set(run(['docker', 'volume', 'ls', '--quiet'], capture=True, check=True).stdout.split())
        except (OSError, subprocess.SubprocessError) as error:
            warn(f'could not list Docker volumes ({error}); a rollback will leave the new release\'s volumes in place')
            existing = None
        self.recovery['created_volumes'] = ([] if existing is None else
                                            sorted(named_volumes(candidate_config) - named_volumes(previous_config) - existing))

    def prepare_new_major(self, postgres, old, new, previous_config, candidate_config):
        """A new PostgreSQL major cannot open the old data directory. The new release names new
        database volumes; the update restores its safety dump into them and keeps the old ones,
        which the previous release still names, so a rollback simply starts it on them again."""
        kept, fresh = database_volumes(previous_config), database_volumes(candidate_config)
        require(kept and fresh and not kept & fresh,
                f'PostgreSQL {old} to {new} needs new database volumes, but the new release reuses '
                f'{", ".join(sorted(kept & fresh)) or "unnamed volumes"}; this release cannot update this server')
        size = postgres_sql(postgres, 'SELECT pg_database_size(current_database())')
        require(size.isdigit(), 'could not measure the database before the PostgreSQL major update')
        # The new volumes hold a second copy of the database next to the kept one.
        require_storage(self.state, self.project, free_disk_floor(self.settings), UPDATE_PEAK_BYTES + int(size),
                        image=value(self.settings, "POSTGRES_IMAGE"))
        self.recovery['fresh_database'] = True
        warn(f'PostgreSQL {old} to {new}: the update restores its safety dump into new volumes '
             f'({", ".join(sorted(fresh))}); the {old} volumes ({", ".join(sorted(kept))}) are kept for rollback. '
             'Remove them with docker volume rm only after the new release has run long enough to trust it.')

    def restore_into_new_major(self):
        """Start only the new PostgreSQL on its empty volumes and load the safety dump before any
        migration or application service runs against it."""
        start_split(lambda *args, **kwargs: self.dc(self.candidate, *args, **kwargs), ['postgres'], [], self.timeout)
        operation = Restore(self.state, str(self.state / 'backups'), '/backups/' + Path(self.recovery['backup']).name,
                            self.recovery['sha256'], self.timeout, True, True, recovery_owner=str(self.candidate),
                            target_version=self.recovery_version, rollback=False)
        require(operation.execute() == 0, 'could not restore the safety dump into the new PostgreSQL major')
        stop = self.state / STOP_MARKER
        if stop.is_file() and stop.read_text() == RESTORED_STOP:
            stop.unlink()  # the update itself starts the application next

    def verify_previous(self):
        """The previous release's own verification while it still serves: the FAIL messages, or
        None when it could not run or failed without naming a check ("could not run" is not
        "nothing failed")."""
        unavailable = ('; a check that fails after the update is then reported as a warning and does not '
                       'roll it back')
        try:
            result = run(['./chronicle', 'verify'], cwd=self.previous, capture=True, timeout=PREPARATION_TIMEOUT_SECONDS)
        except (OSError, subprocess.SubprocessError) as error:
            warn(f'could not run the pre-update verification ({error})' + unavailable)
            return None
        failed = failed_checks(result.stdout or '')
        if result.returncode and not failed:
            warn(f'the pre-update verification exited {result.returncode} without naming a check' + unavailable)
            return None
        if failed:
            warn(f'{len(failed)} verification check(s) fail before the update; they will not roll it back')
        return failed

    def migrate_settings(self, version):
        """Apply every settings migration the update can derive; only an underivable value refuses."""
        image = value(read_env(self.candidate / '.env.example'), 'CADDY_IMAGE')
        self.settings, notes = migrate_settings(self.settings, lambda password: caddy_hash(image, password),
                                                select_core=self.select_core)
        _, dropped = compose_selection(self.settings, self.previous)
        kept = self.state / LOCAL_EDITS_DIR / version
        for name in dropped:
            source = Path(name) if Path(name).is_absolute() else self.previous / name
            if source.is_file() and not source.is_symlink():
                target = kept / 'selfhost' / Path(name).name if Path(name).is_absolute() else kept / 'selfhost' / name
                target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                write_text(target, source.read_text(errors='replace'))
                notes.append(f'COMPOSE_FILE entry {name} is not part of the release and was left out; a copy is in {target}')
            else:
                notes.append(f'COMPOSE_FILE entry {name} is not part of the release and was left out')
        for note in notes:
            warn(f'settings migration: {note}')

    def select_core(self, subnet):
        """A free /24 for the candidate's internal core network, chosen as setup chooses one. The
        host's network table is environment: unreadable, it warns and takes the shipped default."""
        try:
            prefix = run(['python3', str(self.candidate / 'network-subnet.py'), 'select-core', subnet, self.project],
                         capture=True, check=True).stdout.strip()
        except (OSError, subprocess.SubprocessError) as error:
            prefix = f'unavailable ({error})'
        if not re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}', prefix):
            fallback = default_core_prefix(self.candidate)
            warn(f'could not check the host\'s networks for the internal core network ({prefix}); using {fallback}.0/24. '
                 'If that range is in use here, set CHRONICLE_CORE_PREFIX in .env to three octets of a free private /24')
            prefix = fallback
        return prefix

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
            if self.recovery.get('fresh_database'):
                self.restore_into_new_major()
            start_release(self.candidate, self.project, self.names, self.timeout)
        except subprocess.CalledProcessError:
            self.failed_services = save_failed_service_logs(self.candidate, self.project, self.names, self.state)
            raise
        certificates = certificate_digest(self.state)
        verify_release('./chronicle', self.baseline)  # only a check the update made fail rolls it back
        record_applied_certificates(self.state, certificates)
        # Ownership and the front door belong to the transaction: written before the durable commit,
        # so a failure here rolls the update back and an interruption after the commit finds them
        # in place (a resumed COMMITTED recovery writes them again).
        transfer_deployment(self.candidate, Path(self.recovery['front_door']), self.state)
        from .reconcile import install_after_transfer
        # Only the schedule is optional: ownership was written and checked above.
        install_after_transfer(self.candidate / 'chronicle', self.state, self.project)
        self.recovery['phase'] = COMMITTED
        self.save()  # After this durable commit, recovery must never restore the old dump.
        open_ingress(self.state)
        clear_recovery(self.marker)
        print(f'Update verified. This deployment now runs from: {self.candidate}')
        report_release_readiness(self.candidate, self.project, self.names)


def clear_recovery(marker):
    from .update import HANDOFF_FILE
    (marker.parent / HANDOFF_FILE).unlink(missing_ok=True)
    retired = marker.with_name(marker.name + '.completed')
    if retired.exists():
        shutil.rmtree(retired)
    durable_replace(marker, retired)
    shutil.rmtree(retired)


ROLLBACK_STOP = 'rollback in progress\n'
# Journal phases whose resumption restores the safety dump again; anything accepted meanwhile is lost.
RESTORE_PENDING = (RECOVERY_PHASE, 'rollback-restore')


def settle_failed_recovery(state):
    """Leave a failed update recovery or rollback in a state cron and the operator can act on.

    The journal stays, so `./chronicle update` resumes it. Reconciliation resumes: its `up` refuses
    the journal and logs the failure on every run instead of pausing silently. Ingress reopens,
    as before the update, unless resuming would restore the safety dump and discard what
    participants upload in between; then it stays closed until the recovery completes."""
    state = Path(state)
    try:
        phase = json.loads((state / UPGRADE_LOCK / RECOVERY_FILE).read_text()).get('phase')
    except (OSError, ValueError, AttributeError):
        phase = None
    stop = state / STOP_MARKER
    try:
        if stop.is_file() and not stop.is_symlink() and stop.read_text() == ROLLBACK_STOP:
            stop.unlink()
    except OSError as error:
        warn(f'could not resume periodic reconciliation ({error}); run ./chronicle doctor')
    if phase is None or phase in RESTORE_PENDING:
        warn('participant ingress stays closed (503): resuming this recovery restores the safety dump, '
             'which would discard uploads accepted now. Resolve the failure above, then run ./chronicle update')
        return
    try:
        open_ingress(state)
    except OSError as error:
        warn(f'could not reopen participant ingress ({error}); run ./chronicle doctor')
        return
    warn('recovery did not complete; participant ingress was reopened with the data already in place. '
         'Resolve the failure above, then run ./chronicle update to finish it')


def mark_failed(state):
    """Record on the journal that the update itself failed, before its rollback starts. A rerun that
    finds a journal without this mark is finishing an interrupted update (killed process, host
    restart, a recovery that was itself interrupted): after recovering it updates again. With the
    mark it only finishes the rollback and reports the failure. rollback() keeps the key."""
    path = Path(state) / UPGRADE_LOCK / RECOVERY_FILE
    record = json.loads(path.read_text())
    record['failed'] = True
    write_json(path, record)


def recover_update(state):
    """Called under the operation lock, including after SIGKILL or host restart. Returns False when
    no update was pending, else the release directory that serves afterwards: the candidate when the
    recovered update had committed, the previous release after a rollback."""
    marker = Path(state) / UPGRADE_LOCK
    if not marker.exists():
        return False
    recovery = json.loads((marker / RECOVERY_FILE).read_text())
    previous, candidate = Path(recovery['previous']), Path(recovery['owner'])
    require(Path.cwd().resolve() in (previous, candidate),
            f'incomplete update; run update from {previous} or {candidate}')
    settings = read_env(previous / '.env')
    names = running_selection(settings, previous)
    project = compose_project(settings)
    close_ingress(state)
    try:
        return resume_recovery(state, marker, recovery, previous, candidate, settings, names, project)
    except BaseException:
        settle_failed_recovery(state)
        raise


def resume_recovery(state, marker, recovery, previous, candidate, settings, names, project):
    if recovery['phase'] == PREPARED:
        start_release(previous, project, names, value(settings, 'START_WAIT_TIMEOUT_SECONDS', DEFAULT_STARTUP_TIMEOUT_SECONDS))
        verify_release(previous / 'chronicle', recovery.get('baseline', []))
        recovery['phase'] = COMMITTED
        recovery['owner'] = str(previous)
        write_json(marker / RECOVERY_FILE, recovery)
        open_ingress(state)
        clear_recovery(marker)
        (candidate / '.env').unlink(missing_ok=True)
    elif recovery['phase'] == COMMITTED:
        active = Path(recovery['owner'])
        os.chdir(active)
        verify_release(active / 'chronicle', recovery.get('baseline', []))
        if recovery.get('front_door') and active.resolve() != previous.resolve():
            transfer_deployment(active, Path(recovery['front_door']), state)
        open_ingress(state)
        if recovery.get('settings_archive'):
            (Path(state) / STOP_MARKER).unlink(missing_ok=True)
        clear_recovery(marker)
        print(f'Committed release recovered: {active}')
        return active
    else:
        from .restore import ROLLBACK_PHASES, rollback
        require(recovery['phase'] in (RECOVERY_PHASE, *ROLLBACK_PHASES), 'unrecognized update recovery phase')
        os.chdir(candidate)
        require(rollback(previous, recovery.get('dump') or '/backups/' + Path(recovery['backup']).name,
                         recovery['sha256'], True) == 0, 'automatic rollback failed; retain recovery state')
    os.chdir(previous)
    os.environ['CHRONICLE_OPS_VERSION'] = value(settings, 'RELEASE_VERSION', 'unknown')
    print(f'Previous release recovered with its data: {previous}')
    return previous


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
                if not isinstance(error, Interrupted):
                    try:
                        mark_failed(state)
                    except (OSError, ValueError, KeyError) as mark_error:  # never in the way of the rollback
                        warn(f'could not record the failure in the update journal ({mark_error}); '
                             'if this rollback is interrupted, the next update retries the release')
                # A failure after the durable commit is finished forward: the candidate serves.
                if Path(recover_update(state) or previous).resolve() == candidate:
                    status = 0
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
