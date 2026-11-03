"""Validate the named setup handoff and atomically publish deployment settings."""

import ipaddress
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from .common import compose_project
from .credentials import GENERATION_DATES_KEY, SETUP_SECRETS, setup_credentials
from .env_migration import merge_env
from .envfile import parse_env_text, read_env, set_env_values, value
from .host_memory import SMALL_HOST_LIMITS, SMALL_HOST_MEMORY_KIB, require_memory, total_memory_kib
from .receipts import write_text

SETUP_FIELDS = (
    *(secret.env_key for secret in SETUP_SECRETS),
    'DOMAIN',
    'COMPOSE_FILE',
    'INTERNAL_BIND',
    'TESTING_LOGIN_ENABLED',
    'DASHBOARD_PASSWORD_HASH',
    'HTTP_BIND',
    'POOL_LISTENER_TLS',
    'REQUIRE_MFA',
    'CHRONICLE_STATE_DIR',
    'GRAFANA_BIND',
    'METRICS_RETENTION',
    'LOGS_RETENTION',
    'BACKUP_KEEP_DAYS',
    'BACKUP_KEEP_WEEKS',
    'BACKUP_KEEP_MONTHS',
    'PRE_OP_BACKUP_KEEP_DAYS',
    'COMPOSE_PROJECT_NAME',
    'HTTP_PORT',
    'INTERNAL_PORT',
    'CHRONICLE_REVIEWER_ACCESS_ENABLED',
    'CHRONICLE_REVIEWER_ACCESS_SECRET',
    'CHRONICLE_REVIEWER_STUDY_ID',
    'CHRONICLE_REVIEWER_PARTICIPANT_ID',
    'CHRONICLE_PUBLIC_BASE_URL',
    'LOCAL_HTTPS_PORT',
    'LOCAL_HTTP_PORT',
    'GRAFANA_PORT',
    'CHRONICLE_SUBNET',
    'CHRONICLE_ALERT_WEBHOOK_URL',
    'CADDY_TRUSTED_PROXIES',
    'POOL_ALLOWED_IPS',
    'DASHBOARD_ALLOWED_IPS',
    'DASHBOARD_BASE_URL',
    'PUBLIC_HTTP_ENABLED',
    'LB_MAX_BODY_BYTES',
    'LB_IDLE_TIMEOUT_SECONDS',
    'LB_MAX_HEADER_BYTES',
)


def parse_setup_fields(raw):
    if not raw.endswith(b'\0'):
        raise ValueError('setup records must be NUL terminated')
    values = {}
    for record in raw[:-1].split(b'\0'):
        name, separator, encoded = record.partition(b'=')
        if not separator or name.decode('utf-8') not in SETUP_FIELDS:
            raise ValueError('unknown or malformed setup field')
        key = name.decode('utf-8')
        if key in values:
            raise ValueError('duplicate setup field: ' + key)
        values[key] = encoded.decode('utf-8')
    missing = set(SETUP_FIELDS) - values.keys()
    if missing:
        raise ValueError('missing setup fields: ' + ', '.join(sorted(missing)))
    return values


def validate_alert_webhook(alert_webhook):
    if alert_webhook:
        parsed = urlsplit(alert_webhook)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or any(
            char in alert_webhook for char in "'\"\\\r\n"
        ):
            raise ValueError('alert webhook must be an HTTPS URL without credentials, quotes or line breaks')


def append_unique_list_setting(text, existing, key, item, separator):
    items = [entry for entry in value(existing, key).split(separator) if entry]
    if item not in items:
        items.append(item)
    return set_env_values(text, {key: (separator or ' ').join(items)}, require_existing=False)


def add_management_origin(s, existing, management_url):
    if management_url:
        parsed = urlsplit(management_url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username:
            raise ValueError('researcher URL must be an HTTPS origin')
        try:
            ipaddress.ip_address(parsed.hostname)
            san = 'IP:' + parsed.hostname
        except ValueError:
            san = 'DNS:' + parsed.hostname
        s = append_unique_list_setting(s, existing, 'INTERNAL_CERT_SANS', san, ',')
        s = append_unique_list_setting(s, existing, 'DASHBOARD_ORIGINS', management_url, None)
    return s


def apply_setup_memory(s, existing, compose_file):
    # The shipped ceilings (6.25 GB) assume an 8 GB host. On a smaller Linux host, size them to
    # the documented 4 GB pilot minimum so load cannot push the stack into the OOM killer.
    mem_kb = total_memory_kib()
    if not existing and mem_kb is not None and mem_kb < SMALL_HOST_MEMORY_KIB:
        s = set_env_values(s, SMALL_HOST_LIMITS, require_existing=False)
        print(f"Host has {mem_kb // 1024} MiB of memory; sized backend/Postgres limits for a 4 GB host (see README Sizing).")
    if mem_kb is not None:
        proposed = parse_env_text(s)
        require_memory(proposed, mem_kb, 'overlays/monitoring.yml' in compose_file)
    return s


def write_setup_environment():
    fields = parse_setup_fields(sys.stdin.buffer.read())
    validate_alert_webhook(fields['CHRONICLE_ALERT_WEBHOOK_URL'])
    existing = read_env('.env') if Path('.env').exists() else {}
    compose_file = fields['COMPOSE_FILE']
    text = merge_env(existing, Path('.env.example').read_text(), None, fields['CHRONICLE_STATE_DIR'],
                     compose_file.split(':'), preserve_images=True)
    credentials = setup_credentials(existing, fields)
    fields.update(credentials.values)
    fields[GENERATION_DATES_KEY] = json.dumps(credentials.generated_at, sort_keys=True)
    text = set_env_values(text, fields, require_existing=False)
    text = add_management_origin(text, existing, fields['DASHBOARD_BASE_URL'])
    text = apply_setup_memory(text, existing, compose_file)
    write_text('.env', text)


def confirm_storage_encryption():
    from .verify import STORAGE_ENCRYPTION_WAIVER, reviewed_storage_waiver, verify_backup_storage, verify_database_storage
    root = Path.cwd()
    settings_path = root / '.env'
    settings = read_env(settings_path)
    waiver = value(settings, STORAGE_ENCRYPTION_WAIVER)
    if reviewed_storage_waiver(waiver):
        return
    project = os.environ.get('CHRONICLE_OPS_PROJECT') or compose_project(settings)
    database_confirmed = verify_database_storage(project, waiver) == 0
    backup_confirmed = verify_backup_storage(os.environ.get('CHRONICLE_OPS_BACKUPS', root / 'backups'), waiver) == 0
    if database_confirmed and backup_confirmed:
        return
    required = 'confirmed encryption or a reviewed storage-encryption waiver is required'
    try:
        waiver = input('Storage encryption is unconfirmed. Enter a reviewed storage-encryption waiver reference (blank stops setup): ').strip()
    except EOFError:
        raise ValueError(required) from None
    if not reviewed_storage_waiver(waiver):
        raise ValueError(required)
    write_text(settings_path, set_env_values(settings_path.read_text(), {STORAGE_ENCRYPTION_WAIVER: waiver}, require_existing=False))
