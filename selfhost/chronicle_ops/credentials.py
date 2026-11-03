"""Setup credential catalog, generation metadata, secret ages and rotation configuration validation."""

import base64
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .envfile import value
from .receipts import OPERATOR_RECEIPTS_DIR

GENERATION_DATES_KEY = 'CHRONICLE_SECRET_GENERATED_AT'
GENERATION_TIMESTAMP = re.compile(
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)'
)


# rotate-secret.sh writes one receipt per completed rotation here.
ROTATION_RECEIPTS_DIR = Path(OPERATOR_RECEIPTS_DIR) / 'secret-rotations'
# A forward recovery completes the interrupted rotation; a rollback keeps the old secret.
ROTATION_ACTIONS = ('rotate', 'recover-forward')


@dataclass(frozen=True)
class SetupSecret:
    """name is the rotate-secret.sh argument for the same secret."""
    name: str
    env_key: str


POSTGRES = SetupSecret(name='postgres', env_key='POSTGRES_PASSWORD')
POSTGRES_APP = SetupSecret(name='postgres-app', env_key='POSTGRES_APP_PASSWORD')
JWT = SetupSecret(name='jwt', env_key='JWT_SECRET')
METRICS = SetupSecret(name='metrics', env_key='METRICS_PASSWORD')
INTERNAL_WEB = SetupSecret(name='internal-web', env_key='CHRONICLE_INTERNAL_WEB_SECRET')
GRAFANA = SetupSecret(name='grafana', env_key='GRAFANA_ADMIN_PASSWORD')
SETUP_SECRETS = (POSTGRES, POSTGRES_APP, JWT, METRICS, INTERNAL_WEB, GRAFANA)


@dataclass(frozen=True)
class SetupCredentials:
    values: dict[str, str] = field(repr=False)
    generated_at: dict[str, str]


def setup_credentials(existing, preserved: dict[str, str]):
    dates = json.loads(value(existing, GENERATION_DATES_KEY) or '{}')
    if not isinstance(dates, dict):
        raise ValueError('secret generation dates must be a JSON object')
    credentials = {}
    for secret in SETUP_SECRETS:
        credential = preserved[secret.env_key]
        if not credential:
            credential = base64.b64encode(secrets.token_bytes(32)).decode('ascii')
            dates[secret.name] = datetime.now(timezone.utc).isoformat()
        credentials[secret.env_key] = credential
    return SetupCredentials(values=credentials, generated_at=dates)


def parse_timestamp(date):
    """ISO 8601 with any fraction width: Python 3.9 (RHEL 9) `fromisoformat` takes only 3 or 6 digits."""
    return datetime.fromisoformat(re.sub(r'\.\d+', '', date).replace('Z', '+00:00'))


def valid_generation_dates(dates):
    if not isinstance(dates, dict):
        return False
    try:
        return all(isinstance(date, str) and GENERATION_TIMESTAMP.fullmatch(date)
                   and parse_timestamp(date).tzinfo is not None for date in dates.values())
    except (TypeError, ValueError):
        return False


def secret_dates(settings, state):
    """When each secret was last set: its newest completed rotation receipt, else its setup generation date."""
    dates = {name: parse_timestamp(date) for name, date in json.loads(value(settings, GENERATION_DATES_KEY) or '{}').items()}
    for path in (Path(state) / ROTATION_RECEIPTS_DIR).glob('*.json'):
        receipt = json.loads(path.read_text())
        if receipt.get('status') == 'completed' and receipt.get('action') in ROTATION_ACTIONS:
            done = datetime.strptime(receipt['completed_at_utc'], '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
            dates[receipt['secret']] = max(done, dates.get(receipt['secret'], done))
    return dates


def validate_mobile_signing_configuration(settings):
    retired = dict(MOBILE_SIGNING_ENABLED='false', MOBILE_SIGNING_REQUIRED='false',
                   MOBILE_SIGNING_SECRET='', MOBILE_SIGNING_SECRET_PREVIOUS='')
    for key, disabled in retired.items():
        if value(settings, key, disabled) != disabled:
            raise ValueError(f'{key} is unsupported; use per-device enrollment on a fresh installation')


def validate_rotation_configuration(settings):
    if value(settings, 'ENABLE_ENCRYPTION', 'true') not in ('true', 'false'):
        raise ValueError('ENABLE_ENCRYPTION must be exactly true or false')
    try:
        dates = json.loads(value(settings, GENERATION_DATES_KEY) or '{}')
    except (TypeError, ValueError):
        dates = None
    if not valid_generation_dates(dates):
        raise ValueError('CHRONICLE_SECRET_GENERATED_AT must be a JSON object of ISO timestamps with time zones') from None
