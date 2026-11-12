"""A disposable self-host project for runtime network checks (test_egress_runtime.py).

Copies one source tree's selfhost/ bundle into a run directory, writes a synthetic .env
(generated secrets, free loopback ports, subnets chosen by network-subnet.py), and starts it
with plain `docker compose up --wait`, the path `./chronicle up` wraps. Images come from
images(): the local first-party builds this checkout produces, built when missing.

    python3 egress_stack.py up RUN_DIR SOURCE_ROOT PROJECT     # prints the project name
    python3 egress_stack.py down RUN_DIR PROJECT
"""
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'selfhost'))

from chronicle_ops.envfile import set_env_values  # noqa: E402
from chronicle_ops.images import SOURCE_IMAGES  # noqa: E402
from selfhost_fixture import anonymous_volumes_removed, context_sources  # noqa: E402

OVERLAYS = 'docker-compose.yml:overlays/mode-behind-proxy-internal.yml:overlays/backups.yml:overlays/monitoring.yml'
TAG = 'egress-test'
DASHBOARD_PASSWORD = 'egress-fixture-dashboard-password'  # synthetic, this disposable project only


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def image_exists(tag):
    return subprocess.run(['docker', 'image', 'inspect', tag], capture_output=True).returncode == 0


# What each first-party image is built from, relative to the source root: its Dockerfile, the paths
# it copies, and the submodules (by commit and local changes) whose sources it compiles.
IMAGE_INPUTS = {
    'backend': (('docker/Dockerfile.backend', 'selfhost/backend-entrypoint.sh', 'gradle', 'gradles', 'gradlew',
                 'build.gradle.kts', 'settings.gradle.kts', 'gradle.properties', 'LICENSE'),
                ('chronicle-models', 'chronicle-api', 'chronicle-server', 'rhizome', 'rhizome-client')),
    'frontend': (('selfhost/Dockerfile.frontend', 'LICENSE'), ('chronicle-web',)),
    'caddy': (('selfhost/Dockerfile.caddy', 'selfhost/caddy', 'LICENSE'), ()),
    'backup': (('selfhost/Dockerfile.backup', 'selfhost/backup-image', 'selfhost/chronicle_ops', 'selfhost/init-tde.sh'), ()),
    'grafana': (('selfhost/Dockerfile.grafana',), ()),
    'fluentbit': (('selfhost/Dockerfile.fluentbit',), ()),
    'postgres': (('selfhost/Dockerfile.postgres', 'selfhost/backup-image/emudhra-distrusted-2026-10.pem'), ()),
}


def release_platform(source_root=ROOT):
    """toolchain-manifest.yaml release_platform: the only platform release images are built for (the
    backend builder's apt pins exist only in the amd64 Ubuntu snapshot; Dockerfile.fluentbit unpacks
    amd64 libraries), so the proof runs those images, emulated on another host architecture."""
    import re
    manifest = (Path(source_root) / 'toolchain-manifest.yaml').read_text()
    return re.search(r'^release_platform: "([^"]+)"', manifest, re.MULTILINE).group(1)


def inputs_digest(source_root, component, *extra):
    """A digest of one image's build inputs, so a tag names exactly what it was built from: the listed
    paths, every context path its Dockerfile copies or bind-mounts (an OS-package helper included),
    the submodules it compiles and the release platform."""
    import hashlib
    paths, submodules = IMAGE_INPUTS[component]
    image = next(image for image in SOURCE_IMAGES if image.component == component)
    context = os.path.normpath('selfhost/' + image.context)
    dockerfile = Path(source_root) / 'selfhost' / image.dockerfile
    # Submodule sources count by commit and local diff below, not file by file (chronicle-web holds
    # node_modules and dist).
    compiled = {name for _, names in IMAGE_INPUTS.values() for name in names}
    read = [path for path in (os.path.normpath(os.path.join(context, source)) for source in context_sources(dockerfile)
                              if source != '.') if path.split(os.sep, 1)[0] not in compiled] if dockerfile.is_file() else []
    digest = hashlib.sha256(component.encode() + release_platform(source_root).encode())
    for relative in sorted(set(paths) | set(read)):
        root = Path(source_root) / relative
        files = sorted(root.rglob('*')) if root.is_dir() else [root]
        for path in files:
            if path.is_file() and '__pycache__' not in path.parts:
                digest.update(str(path.relative_to(source_root)).encode() + b'\0' + path.read_bytes() + b'\0')
    for name in submodules:
        for arguments in (['rev-parse', 'HEAD'], ['diff', 'HEAD']):
            digest.update(subprocess.run(['git', '-C', str(Path(source_root) / name), *arguments], check=True,
                                         capture_output=True, timeout=120).stdout)
    for value in extra:
        digest.update(value.encode())
    return digest.hexdigest()[:16]


def images(source_root=ROOT, log=None, only=None):
    """{IMAGE_VARIABLE: tag} for every first-party image (or the components in only, plus the
    frontend Caddy embeds), building from source_root what is missing.

    Each tag carries the digest of that image's inputs (IMAGE_INPUTS), so a changed Dockerfile or
    source builds a new image and an unchanged one is reused. CHRONICLE_EGRESS_REBUILD=1 forces a
    rebuild."""
    values = {}
    wanted = None if only is None else set(only) | ({'frontend'} if 'caddy' in only else set())
    for image in SOURCE_IMAGES:
        if wanted is not None and image.component not in wanted:
            continue
        extra = (values['SELFHOST_FRONTEND_IMAGE'],) if image.component == 'caddy' else ()
        tag = f'chronicle-selfhost-{image.component}:{TAG}-{inputs_digest(source_root, image.component, *extra)}'
        if os.environ.get('CHRONICLE_EGRESS_REBUILD') == '1' or not image_exists(tag):
            context = (source_root / 'selfhost' / image.context).resolve()
            dockerfile = (source_root / 'selfhost' / image.dockerfile).resolve()
            command = ['docker', 'build', '-q', '--platform', release_platform(source_root), '-f', str(dockerfile), '-t', tag]
            if image.revision_argument:
                command += ['--build-arg', f'{image.revision_argument}=egress-test']
            if image.component == 'caddy':
                command += ['--build-context', 'chronicle-selfhost-frontend:release=docker-image://' +
                            values['SELFHOST_FRONTEND_IMAGE']]
            subprocess.run([*command, str(context)], check=True, stdout=log, stderr=log, timeout=3600)
        values[image.variable] = tag
    return values


def settings(bundle, project, image_tags):
    """The .env for this project: .env.example with generated secrets and non-colliding host resources."""
    def select(*arguments):
        return subprocess.run([sys.executable, str(bundle / 'network-subnet.py'), *arguments], check=True,
                              capture_output=True, text=True, timeout=60).stdout.strip()
    subnet = select('select', '172.28.0.0/16', project)
    core = select('select-core', subnet, project)
    gateway = subnet.split('/')[0].rsplit('.', 1)[0] + '.1'
    password_hash = subprocess.run(
        ['docker', 'run', '--rm', '-i', '--network', 'none', '--read-only', '--entrypoint', 'caddy',
         image_tags['CADDY_IMAGE'], 'hash-password'], input=DASHBOARD_PASSWORD + '\n', capture_output=True,
        text=True, check=True, timeout=120).stdout.strip()
    values = dict(image_tags,
                  COMPOSE_PROJECT_NAME=project, COMPOSE_FILE=OVERLAYS, DOMAIN='egress-fixture.chronicle-selfhost.net',
                  CHRONICLE_SUBNET=subnet, CHRONICLE_CORE_PREFIX=core,
                  CADDY_TRUSTED_PROXIES=gateway + '/32', DASHBOARD_ALLOWED_IPS=f'{gateway}/32 127.0.0.1/32 ::1/128',
                  CHRONICLE_RECONCILE_ENABLED='false', START_WAIT_TIMEOUT_SECONDS='600',
                  HTTP_PORT=str(free_port()), INTERNAL_PORT=str(free_port()), GRAFANA_PORT=str(free_port()),
                  FLUENT_BIT_FORWARD_PORT=str(free_port()), DASHBOARD_PASSWORD_HASH=password_hash,
                  POSTGRES_PASSWORD=secrets.token_urlsafe(32), POSTGRES_APP_PASSWORD=secrets.token_urlsafe(32),
                  JWT_SECRET=secrets.token_urlsafe(48), CHRONICLE_INTERNAL_WEB_SECRET=secrets.token_urlsafe(48),
                  METRICS_PASSWORD=secrets.token_urlsafe(48), GRAFANA_ADMIN_PASSWORD=secrets.token_urlsafe(48),
                  BACKUP_KEEP_DAYS='7', BACKUP_KEEP_WEEKS='4', BACKUP_KEEP_MONTHS='6', PRE_OP_BACKUP_KEEP_DAYS='7',
                  MIN_FREE_DISK_GIB='0', BACKUP_STORAGE_ENCRYPTION_WAIVER='synthetic-egress-fixture-no-study-data')
    return set_env_values((bundle / '.env.example').read_text(), values, require_existing=False)


def compose(bundle, project, *arguments, log=None, timeout=900):
    environment = {key: val for key, val in os.environ.items() if not key.startswith('COMPOSE_')}
    environment.update(CHRONICLE_HOST_UID=str(os.getuid()), CHRONICLE_HOST_GID=str(os.getgid()))
    return subprocess.run(['docker', 'compose', '-p', project, *arguments], cwd=bundle, env=environment,
                          stdout=log, stderr=log, timeout=timeout)


def up(run_dir, source_root, project, log=None):
    run_dir, source_root = Path(run_dir), Path(source_root)
    bundle = run_dir / 'selfhost'
    shutil.copytree(source_root / 'selfhost', bundle, ignore=shutil.ignore_patterns('__pycache__', '.env', 'backups', 'tls'))
    (run_dir / 'docker').mkdir(exist_ok=True)
    shutil.copy2(source_root / 'docker/init-db-roles.sql', run_dir / 'docker/init-db-roles.sql')
    for folder in ('backups', 'tls'):
        (bundle / folder).mkdir(mode=0o700, exist_ok=True)
    env = bundle / '.env'
    env.write_text(settings(bundle, project, images(source_root, log)))
    env.chmod(0o600)
    result = compose(bundle, project, 'up', '-d', '--wait', '--wait-timeout', '600', log=log)
    return result.returncode


def down(run_dir, project, log=None):
    bundle = Path(run_dir) / 'selfhost'
    # `down -v` leaves the anonymous volumes of every container `up` recreated; this removes them too.
    with anonymous_volumes_removed(project):
        return compose(bundle, project, 'down', '-v', '--remove-orphans', '-t', '5', log=log).returncode


if __name__ == '__main__':
    action, *rest = sys.argv[1:]
    if action == 'up':
        sys.exit(up(*rest))
    if action == 'down':
        sys.exit(down(*rest))
    sys.exit('usage: egress_stack.py up RUN_DIR SOURCE_ROOT PROJECT | down RUN_DIR PROJECT')
