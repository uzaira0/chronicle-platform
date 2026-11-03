#!/usr/bin/env bash
# Bind runtime and frontend lockfile SPDX assets to the immutable publication revision.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=scripts/local-ci.sh
source "$root/scripts/local-ci.sh"
ensure_syft
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 - "$root" "$@" <<'PY_SBOMS'
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

from chronicle_ops.common import run
from chronicle_ops.dump import file_sha256
from chronicle_ops.images import SOURCE_IMAGES


def frontend_source(root, revision, staging):
    web_revision = run(['git', '-C', str(root), 'rev-parse', revision + ':chronicle-web'], capture=True, check=True).stdout.strip()
    directory = staging / 'frontend-source'; directory.mkdir()
    with (directory / 'bun.lock').open('w') as output:
        run(['git', '-C', str(root / 'chronicle-web'), 'show', web_revision + ':bun.lock'], stdout=output, check=True)
    return directory


def write_sbom(target, path):
    with path.open('w') as output:
        run(['syft', target, '-o', 'spdx-json'], stdout=output, check=True)
    document = json.loads(path.read_text())
    if not str(document.get('spdxVersion', '')).startswith('SPDX-'):
        raise ValueError('Syft did not produce an SPDX document')
    return document


def generate_sboms(references, release, staging, source):
    assets = []
    for image, reference in zip(SOURCE_IMAGES, references):
        name = f'chronicle-{image.component}-{release.removeprefix("v")}.spdx.json'
        path = staging / name
        write_sbom(reference, path)
        asset = dict(image=reference, asset=name, sha256=file_sha256(path))
        if image.component == 'frontend':
            inventory_name = name.replace('.spdx.json', '-npm.spdx.json')
            inventory_path = staging / inventory_name
            document = write_sbom('dir:' + str(source), inventory_path)
            if not any(ref.get('referenceLocator', '').startswith('pkg:npm/')
                       for package in document.get('packages', []) for ref in package.get('externalRefs', [])):
                raise ValueError('frontend SBOM has no lockfile npm dependency inventory')
            asset['inventories'] = [dict(asset=inventory_name, sha256=file_sha256(inventory_path))]
        assets.append(asset)
    return assets


def main():
    if len(sys.argv) != len(SOURCE_IMAGES) + 4:
        raise ValueError('usage: write-image-sboms.sh RELEASE OUTPUT_DIR ' + ' '.join(image.component.upper() + '_REF' for image in SOURCE_IMAGES))
    root, release, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]).resolve()
    references = sys.argv[4:]
    if not re.fullmatch(r'v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?', release):
        raise ValueError('release must be a Docker-tag-compatible semantic version')
    if shutil.which('syft') is None:
        raise ValueError('syft is required to produce release SBOMs')
    if any(not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', ref) for ref in references):
        raise ValueError('SBOM input must be an immutable name@sha256 image reference')
    output.mkdir(parents=True, exist_ok=True)
    revision = os.environ.get('CHRONICLE_SBOM_SOURCE_REVISION') or run(['git', '-C', str(root), 'rev-parse', 'HEAD'], capture=True, check=True).stdout.strip()
    version = release.removeprefix('v')
    manifest_name = f'chronicle-image-sboms-{version}.json'
    checksums_name = f'chronicle-image-sboms-{version}.sha256'
    with tempfile.TemporaryDirectory(prefix='.image-sboms.', dir=output) as folder:
        staging = Path(folder)
        source = frontend_source(root, revision, staging)
        assets = generate_sboms(references, release, staging, source)
        manifest = dict(schemaVersion=1, release=release, sourceRevision=revision, sboms=assets)
        (staging / manifest_name).write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
        digests = {document['asset']: document['sha256'] for asset in assets
                   for document in [asset, *asset.get('inventories', [])]}
        digests[manifest_name] = file_sha256(staging / manifest_name)
        (staging / checksums_name).write_text(''.join(f'{digest}  {name}\n' for name, digest in digests.items()))
        names = [*digests, checksums_name]
        if any(os.path.lexists(output / name) for name in names):
            raise ValueError('refusing to replace an existing SBOM release asset')
        for name in names:
            os.link(staging / name, output / name)
            print(output / name)


try:
    main()
except (OSError, ValueError) as error:
    sys.exit('error: ' + str(error))
PY_SBOMS
