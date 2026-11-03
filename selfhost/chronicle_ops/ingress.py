"""Durable edge fence and the operator-only verification capability."""
from pathlib import Path

from .common import require
from .receipts import sync_directory, write_text

FENCE_NAME = '.chronicle-ingress-closed'
VERIFY_HEADER = 'Authorization'
VERIFY_SCHEME = 'ChronicleUpdate'
RETRY_AFTER_SECONDS = 1


def fence_path(state):
    return Path(state) / 'tls' / FENCE_NAME


def close_ingress(state):
    path = fence_path(state)
    require(not path.parent.is_symlink(), 'unsafe TLS state directory')
    path.parent.mkdir(mode=0o755, exist_ok=True)
    write_text(path, 'Update in progress\n')
    path.chmod(0o644)  # Public status, read by the unprivileged edge on every request.
    sync_directory(path.parent)


def open_ingress(state):
    path = fence_path(state)
    path.unlink(missing_ok=True)
    sync_directory(path.parent)


def caddy_fence():
    return f'''# BEGIN GENERATED UPDATE FENCE (chronicle_ops.ingress)
(chronicle_update_fence) {{
    @updateClosed {{
        not path /health
        file {{
            root /etc/caddy/certs
            try_files /{FENCE_NAME}
        }}
        not header {VERIFY_HEADER} "{VERIFY_SCHEME} {{$CHRONICLE_INTERNAL_WEB_SECRET}}"
    }}
    @updateVerifier header {VERIFY_HEADER} "{VERIFY_SCHEME} {{$CHRONICLE_INTERNAL_WEB_SECRET}}"
    route {{
        header @updateClosed Retry-After {RETRY_AFTER_SECONDS}
        respond @updateClosed "Update in progress" 503
        request_header @updateVerifier -{VERIFY_HEADER}
    }}
}}
# END GENERATED UPDATE FENCE'''


def render_caddy_fence(path):
    path = Path(path)
    text = path.read_text()
    start = text.index('# BEGIN GENERATED UPDATE FENCE')
    end = text.index('# END GENERATED UPDATE FENCE') + len('# END GENERATED UPDATE FENCE')
    path.write_text(text[:start] + caddy_fence() + text[end:])
