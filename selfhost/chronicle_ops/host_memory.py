"""Host memory probes, setup sizing and service budget policy."""

import os
from pathlib import Path
import re
import subprocess

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
    require(match, "invalid memory ceiling")
    return int(float(match[1]) * 1024 ** ("kmgt".index(match[2]) + 1 if match[2] else 0))


def require_memory(settings, available_kib, monitoring=False):
    keys = ["POSTGRES", "BACKEND", "WEB", "BACKUP"]
    fixed = 0
    if monitoring:
        keys += ["CADVISOR", "VICTORIAMETRICS", "VICTORIALOGS", "FLUENT_BIT", "OPERATIONAL_PROBE", "METRICS_EXPORTER", "GRAFANA"]
        fixed = (128 + 64) * 1024 ** 2  # Monitoring config and Docker API proxy.
    required = MEMORY_HEADROOM_BYTES + fixed
    for key in keys:
        required += memory_bytes(value(settings, key + "_MEM_LIMIT"))
    require(required <= available_kib * 1024, f"selected service ceilings plus host headroom need {required // 1024 ** 2} MiB; host has {available_kib // 1024}. Disable monitoring or review memory ceilings before setup")
    return required


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
    if action == 'logging':
        import json
        from .common import compose
        services = json.loads(compose('config', '--format', 'json', capture=True, timeout=30, check=True).stdout)['services']
        try:
            require_logging_budget(services)
        except ValueError as error:
            print(error)
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
