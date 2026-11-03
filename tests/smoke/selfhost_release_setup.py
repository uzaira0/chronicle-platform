"""Drive each release's shipped setup without duplicating deployment policy."""

import argparse
from enum import Enum
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'selfhost'))
from chronicle_ops.envfile import set_env_values
from chronicle_ops.receipts import write_text


class SetupMode(Enum):
    BEHIND_PROXY = '1'
    OWN_TLS = '2'
    LOCAL_HTTPS = '3'


NETWORK_DEFAULT_PROMPTS = {SetupMode.BEHIND_PROXY: 12, SetupMode.OWN_TLS: 8, SetupMode.LOCAL_HTTPS: 0}
BACKUP_WAIVER_KEY = 'BACKUP_STORAGE_ENCRYPTION_WAIVER'
COMMAND_TIMEOUT_SECONDS = 120
STARTUP_WAIT_SECONDS = 300
# Daily, weekly, monthly and safety-dump retention. Fixtures keep everything: no number is chosen here.
BACKUP_RETENTION = ('all', 'all', 'all', 'all')


def setup_answers(*, mode, public_host, password, monitoring, overwrite=False, reuse_hash=False,
                  alert_webhook='', keep_retention=False, backup_storage_encryption_waiver=None):
    answers = ['y'] if overwrite else []
    answers += [mode.value, public_host] + [''] * NETWORK_DEFAULT_PROMPTS[mode]
    if not reuse_hash:
        answers += [password, password]
    answers += ['y' if monitoring else 'n']
    if monitoring:
        answers += ['', '', '', alert_webhook]  # Grafana bind, metrics retention, log retention, webhook.
    answers += [''] * len(BACKUP_RETENTION) if keep_retention else BACKUP_RETENTION  # Blank keeps saved values.
    if backup_storage_encryption_waiver is not None:
        answers += [backup_storage_encryption_waiver]
    return '\n'.join(answers) + '\n'


def release_environment(environment):
    environment = dict(environment, HTTP_BIND='127.0.0.1', INTERNAL_BIND='127.0.0.1', GRAFANA_BIND='127.0.0.1')
    for key in ('CADDY_TRUSTED_PROXIES', 'POOL_ALLOWED_IPS', 'DASHBOARD_ALLOWED_IPS',
                'DASHBOARD_BASE_URL', 'PUBLIC_HTTP_ENABLED', BACKUP_WAIVER_KEY):
        environment.pop(key, None)
    return environment


def setup_release(bundle, *, mode, public_host, password, monitoring, environment,
                  backup_storage_encryption_waiver=None, capture=False):
    if (bundle / '.env').exists():
        raise ValueError('release smoke setup requires a clean installation')
    environment = release_environment(environment)
    answers = setup_answers(mode=mode, public_host=public_host, password=password, monitoring=monitoring,
                            backup_storage_encryption_waiver=backup_storage_encryption_waiver)
    result = subprocess.run(['./chronicle', 'setup'], cwd=bundle, env=environment,
                            input=answers, text=True, check=True, timeout=COMMAND_TIMEOUT_SECONDS,
                            capture_output=capture)
    if backup_storage_encryption_waiver is not None:
        settings = bundle / '.env'
        write_text(settings, set_env_values(settings.read_text(),
                   {BACKUP_WAIVER_KEY: backup_storage_encryption_waiver}, require_existing=False))
    print(f'Fixture backup storage waiver: {"explicit" if backup_storage_encryption_waiver else "none"}', flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path, nargs='?')
    parser.add_argument('--mode', type=SetupMode, default=SetupMode.BEHIND_PROXY)
    parser.add_argument('--backup-storage-encryption-waiver')
    parser.add_argument('--answers-only', action='store_true')
    parser.add_argument('--overwrite', action='store_true')
    parser.add_argument('--reuse-hash', action='store_true')
    parser.add_argument('--keep-retention', action='store_true')
    parser.add_argument('--alert-webhook', default='')
    parser.add_argument('--public-host', default=os.environ.get('DOMAIN'))
    parser.add_argument('--monitoring', action='store_true')
    parser.add_argument('--install', action='store_true')
    args = parser.parse_args()
    choices = dict(mode=args.mode, public_host=args.public_host, password=os.environ['SMOKE_PASSWORD'],
                   monitoring=args.monitoring or os.environ.get('ENABLE_MONITORING') == 'true')
    if args.answers_only:
        print(setup_answers(**choices, overwrite=args.overwrite, reuse_hash=args.reuse_hash,
                            alert_webhook=args.alert_webhook, keep_retention=args.keep_retention,
                            backup_storage_encryption_waiver=args.backup_storage_encryption_waiver), end='')
    else:
        if args.bundle is None:
            parser.error('bundle is required unless --answers-only is used')
        setup_release(args.bundle, **choices, environment=os.environ,
                      backup_storage_encryption_waiver=args.backup_storage_encryption_waiver)
        if args.install:
            environment = release_environment(os.environ)
            subprocess.run(['./chronicle', 'up'], cwd=args.bundle,
                           env=dict(environment, START_WAIT_TIMEOUT_SECONDS=str(STARTUP_WAIT_SECONDS)),
                           check=True, timeout=STARTUP_WAIT_SECONDS + COMMAND_TIMEOUT_SECONDS)
            subprocess.run(['./chronicle', 'verify', '--dashboard-password'], cwd=args.bundle,
                           env=environment, input=choices['password'] + '\n', text=True,
                           check=True, timeout=COMMAND_TIMEOUT_SECONDS)
