"""One source-build inventory for first-party self-host images."""
from dataclasses import dataclass
import os
import re
import tempfile
from pathlib import Path

from .common import run
from .release import record_source_images


SOURCE_TAG_PREFIX = "chronicle-selfhost"
INPUTS_TREE_LABEL = "io.chronicle.source.inputs-tree"
IMAGE_INPUTS_KEY = "image_inputs"


@dataclass(frozen=True)
class SourceImage:
    component: str
    variable: str
    dockerfile: str
    placeholder: str
    context: str = '..'
    revision_argument: str = 'SOURCE_REF'
    overlay: str = ''
    submodules: tuple = ()  # gitlinks the build reads; no other submodule needs to be checked out

    def tag(self, revision):
        return f'{SOURCE_TAG_PREFIX}-{self.component}:source-{revision[:16]}'

    def archive(self, repository, revision, output):
        archive_source(repository, revision, os.path.normpath('selfhost/' + self.context), output, self.submodules)

    def managed(self):
        value = os.environ.get(self.variable, self.placeholder)
        return value == self.placeholder or bool(re.fullmatch(rf'{SOURCE_TAG_PREFIX}-{self.component}:source(?:-[0-9a-f]{{16}})?', value))


SOURCE_IMAGES = (
    SourceImage(component='backend', variable='BACKEND_IMAGE', dockerfile='../docker/Dockerfile.backend',
                placeholder='__CHRONICLE_BACKEND_IMAGE__', revision_argument='VCS_REF',
                submodules=('chronicle-models', 'chronicle-api', 'chronicle-server', 'rhizome', 'rhizome-client')),
    SourceImage(component='frontend', variable='SELFHOST_FRONTEND_IMAGE', dockerfile='Dockerfile.frontend',
                placeholder='__CHRONICLE_SELFHOST_FRONTEND_IMAGE__', revision_argument='GIT_SHA',
                submodules=('chronicle-web',)),
    SourceImage(component='caddy', variable='CADDY_IMAGE', dockerfile='Dockerfile.caddy',
                placeholder='__CHRONICLE_SELFHOST_CADDY_IMAGE__'),
    SourceImage(component='backup', variable='BACKUP_IMAGE', dockerfile='Dockerfile.backup',
                placeholder='__CHRONICLE_BACKUP_IMAGE__', context='.', overlay='overlays/backups.yml'),
    SourceImage(component='grafana', variable='GRAFANA_IMAGE', dockerfile='Dockerfile.grafana',
                placeholder='__CHRONICLE_GRAFANA_IMAGE__', context='.', overlay='overlays/monitoring.yml'),
    SourceImage(component='fluentbit', variable='FLUENT_BIT_IMAGE', dockerfile='Dockerfile.fluentbit',
                placeholder='__CHRONICLE_SELFHOST_FLUENT_BIT_IMAGE__', context='.', overlay='overlays/monitoring.yml'),
    SourceImage(component='postgres', variable='POSTGRES_IMAGE', dockerfile='Dockerfile.postgres',
                placeholder='__CHRONICLE_SELFHOST_POSTGRES_IMAGE__', context='.'),
)


def requested_images(compose_file):
    return [image for image in SOURCE_IMAGES if not image.overlay or image.overlay in compose_file]


def build_source_images(revision, compose_file):
    values: dict[str, str] = {}
    inputs_tree = source_inputs_tree(Path.cwd().parent, revision)
    for image in requested_images(compose_file):
        if not image.managed():
            continue
        tag = image.tag(revision)
        cached = run(['docker', 'image', 'inspect', '--format', '{{index .Config.Labels "' + INPUTS_TREE_LABEL + '"}}', tag],
                     capture=True, quiet=True)
        if cached.returncode or cached.stdout.strip() != inputs_tree:
            arguments = ['docker', 'build', '-q', '-f', image.dockerfile, '-t', tag,
                         '--build-arg', f'{image.revision_argument}={revision}']
            if image.component == 'caddy':
                frontend = next(owner for owner in SOURCE_IMAGES if owner.component == 'frontend')
                serving = values.get(frontend.variable, os.environ.get(frontend.variable, ''))
                arguments += ['--build-context', 'chronicle-selfhost-frontend:release=docker-image://' + serving]
            dockerfile = Path(image.dockerfile).resolve().relative_to(Path(image.context).resolve())
            arguments[arguments.index('-f') + 1] = dockerfile.as_posix()
            with tempfile.TemporaryFile() as archive:
                image.archive(Path.cwd().parent, revision, archive)
                archive.seek(0)
                run([*arguments, '--label', 'org.opencontainers.image.revision=' + revision,
                     '--label', INPUTS_TREE_LABEL + '=' + inputs_tree, '-'], stdin=archive, check=True)
        values[image.variable] = tag
    record_source_images(values)


def source_inputs_tree(repository, revision):
    return run(['git', '-C', str(repository), 'rev-parse', revision + '^{tree}'], capture=True, check=True).stdout.strip()


def archive_source(repository, revision, context, output, submodules=None):
    """Read immutable tree objects, including each gitlink at its recorded revision.

    submodules names the top-level gitlinks to include; None includes every one."""
    import tarfile
    context = Path(context)
    if context.is_absolute() or '..' in context.parts:
        raise ValueError('build context must be within the revision')
    context = '' if context.as_posix() == '.' else context.as_posix()
    # GNU headers: git's per-commit PAX comment in every member makes `docker build -` read stdin as a Dockerfile.
    with tarfile.open(fileobj=output, mode='w|', format=tarfile.GNU_FORMAT) as destination:
        _archive_tree(Path(repository), revision, '', context, destination, submodules)


def _archive_tree(repository, revision, prefix, context, destination, submodules=None):
    import io
    import tarfile
    raw = run(['git', '-C', str(repository), 'archive', '--format=tar', revision], capture=True,
              check=True, text=False).stdout
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for member in archive:
            full = prefix + member.name
            if context and not full.startswith(context + '/'):
                continue
            member.name = full[len(context) + 1:] if context else full
            if member.name:
                destination.addfile(member, archive.extractfile(member) if member.isfile() else None)
    entries = run(['git', '-C', str(repository), 'ls-tree', '-rz', revision], capture=True,
                  check=True, text=False).stdout
    for entry in entries.split(b'\0'):
        if entry.startswith(b'160000 '):
            metadata, name = entry.split(b'\t', 1)
            path = os.fsdecode(name)
            if submodules is None or path in submodules:
                _archive_tree(repository / path, metadata.split()[2].decode(), prefix + path + '/', context, destination)


def bundle_config(directory):
    """Render every shipped overlay; use no saved operator environment or live secrets."""
    import re
    from .envfile import read_env, value
    directory = Path(directory)
    settings = read_env(directory / '.env.example')
    files = [directory / 'docker-compose.yml', *sorted((directory / 'overlays').glob('*.yml'))]
    environment = {key: value(settings, key) for key in settings}
    for path in files:
        for key in re.findall(r'\$\{([A-Z][A-Z0-9_]*)\s*:\?', path.read_text()):
            if not environment.get(key):
                environment[key] = 'image-inventory-only'
    environment['PATH'] = os.environ.get('PATH', os.defpath)
    result = run(['docker', 'compose', '--env-file', '/dev/null',
                  *[argument for path in files for argument in ('-f', str(path))],
                  '--profile', '*', 'config', '--no-consistency', '--format', 'json'],
                 env=environment, capture=True, check=True)
    import json
    return json.loads(result.stdout)


def bundle_images(directory):
    return {service['image'] for service in bundle_config(directory)['services'].values() if 'image' in service}
