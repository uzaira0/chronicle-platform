"""Host memory probes, setup sizing and service budget policy."""

import os
import re
import subprocess
from pathlib import Path

from .common import GIB, require
from .envfile import value

# A 4 GB VM reports less than 4 GiB after kernel reservations.
MIN_MEMORY_KIB = 3_670_016
MONITORING_MIN_MEMORY_KIB = 10 * 1024 * 1024
SMALL_HOST_MEMORY_KIB = 7_500_000
SMALL_HOST_LIMITS = {
    'POSTGRES_MEM_LIMIT': '1g', 'POSTGRES_SHARED_BUFFERS': '256MB',
    'POSTGRES_EFFECTIVE_CACHE_SIZE': '768MB', 'BACKEND_MEM_LIMIT': '1536m',
    'BACKEND_XMX': '-Xmx1g',
    'BACKUP_MEM_LIMIT': '256m', 'WEB_MEM_LIMIT': '128m',
}
MEMORY_HEADROOM_BYTES = GIB // 2
# Conservative Docker log-message allocation estimate for the async pending channel.
LOG_EVENT_ESTIMATE_BYTES = 32 * 1024
# Fluent Bit documents a soft 2 MiB limit for each chunk.
FLUENT_BIT_CHUNK_SOFT_LIMIT_BYTES = 2 * 1024 ** 2


def memory_bytes(raw):
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([kmgt]?)(?:b)?", str(raw).lower())
    if match is None:
        raise ValueError("invalid memory ceiling")
    return int(float(match[1]) * 1024 ** ("kmgt".index(match[2]) + 1 if match[2] else 0))


def memory_ceilings(services):
    """Bytes the rendered Compose services may hold at once (AF-P7): the mem_limit of every service
    Compose keeps running. Read from `docker compose config`, so web-forward, monitoring-forward and
    any service a later release adds count without a list kept here. One-shot jobs (restart "no")
    are left out: each finishes before the services that wait on it start
    (depends_on service_completed_successfully), and the largest, migrate, shares the backend's
    ceiling and runs before it."""
    return sum(memory_bytes(service['mem_limit']) for service in services.values()
               if service.get('mem_limit') not in (None, '', 0, '0')
               and str(service.get('restart', 'no')) in ('always', 'unless-stopped', 'on-failure'))


def require_memory(services, available_kib):
    required = MEMORY_HEADROOM_BYTES + memory_ceilings(services)
    require(required <= available_kib * 1024, f"selected service ceilings plus host headroom need {required // 1024 ** 2} MiB; host has {available_kib // 1024}. Disable monitoring or review memory ceilings before setup")
    return required


def rendered_services(settings, compose_file):
    """The services Compose would run with settings (not yet written to .env) and compose_file."""
    import json

    from .common import run
    environment = {key: value(settings, key) for key in settings}
    environment.update(COMPOSE_FILE=compose_file)
    files = [argument for name in compose_file.split(':') if name for argument in ('-f', name)]
    result = run(['docker', 'compose', '--env-file', os.devnull, *files, 'config', '--format', 'json'],
                 capture=True, stderr=subprocess.PIPE, timeout=30, env=dict(os.environ, **environment))
    try:
        return None if result.returncode else json.loads(result.stdout)['services']
    except (ValueError, KeyError, TypeError):
        return None


def total_memory_kib(*, native_fallback=False):
    try:
        text = Path(os.environ.get('CHRONICLE_MEMINFO', '/proc/meminfo')).read_text(encoding='utf-8')
        return next(int(line.split()[1]) for line in text.splitlines() if line.startswith('MemTotal:'))
    except (OSError, StopIteration, ValueError, IndexError):
        if not native_fallback or 'CHRONICLE_MEMINFO' in os.environ:
            return None
    try:
        result = subprocess.run(['sysctl', '-n', 'hw.memsize'], check=True, capture_output=True, text=True)
        return int(result.stdout) // 1024
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def host_memory(action):
    if action in ('logging', 'ceilings'):
        import json

        from .common import compose
        services = json.loads(compose('config', '--format', 'json', capture=True, timeout=30, check=True).stdout)['services']
        try:
            if action == 'logging':
                require_logging_budget(services)
            else:
                # Warn only: up and update never refuse on sizing; setup refuses a new install.
                available_kib = total_memory_kib(native_fallback=True)
                if available_kib is not None:
                    require_memory(services, available_kib)
        except ValueError as error:
            print(str(error).replace(' before setup', ''))
        return 0
    available_kib = total_memory_kib(native_fallback=action == 'check')
    if action == 'monitoring-default':
        print('Y' if available_kib is not None and available_kib >= MONITORING_MIN_MEMORY_KIB else 'N')
    elif available_kib is not None and available_kib < MIN_MEMORY_KIB:
        print(f'{available_kib // 1048576} GiB of memory; below the 4 GB minimum the stack is sized for '
              '(README Sizing), so containers may be OOM-killed. Use a host with 4 GB or more')
    return 0


def require_logging_budget(services):
    queued_events = 0
    for service in services.values():
        logging = service.get('logging', {})
        if logging.get('driver') != 'fluentd':
            continue
        options = logging.get('options', {})
        if str(options.get('fluentd-async', 'false')).lower() != 'true':
            continue
        count = int(options['fluentd-buffer-limit'])
        require(count > 0, 'fluentd pending-channel limit must be a positive event count')
        queued_events += count
    queued_bytes = queued_events * LOG_EVENT_ESTIMATE_BYTES
    require(queued_bytes <= MEMORY_HEADROOM_BYTES,
            f'Docker pending log messages need an estimated {queued_bytes} bytes; host headroom is {MEMORY_HEADROOM_BYTES}')
    return queued_bytes
