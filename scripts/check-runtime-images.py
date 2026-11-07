#!/usr/bin/env python3
"""Run the image checks on the third-party images the release bundle runs.

    scripts/check-runtime-images.py [--inventory SELFHOST_DIR]

The checks publish-images.sh runs on the images it builds (no SSH server, no undeclared listener,
scripts/check-image-policy.py) apply to every shipped image, so they also run here on cAdvisor, the
Docker socket proxy, VictoriaMetrics, VictoriaLogs and the health-probe busybox (container-infra
checklist I2 and I3). Each pin is resolved to its linux/amd64 manifest (the release platform) and
pulled by that digest: the index digest could name a copy of another platform already on this daemon.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = ('linux', 'amd64')


def repository(reference):
    name = reference.split('@', 1)[0]
    head, _, tail = name.rpartition('/')
    return (head + '/' if head else '') + tail.split(':', 1)[0]


def inventory(selfhost):
    sys.path.insert(0, str(ROOT / 'selfhost'))
    from chronicle_ops.images import SOURCE_IMAGES, bundle_images
    images = sorted(bundle_images(selfhost) - {image.placeholder for image in SOURCE_IMAGES})
    for image in images:
        if not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', image):
            raise SystemExit(f'error: runtime image inventory contains a mutable image: {image}')
    return images


def platform_reference(image):
    """repository@digest of the linux/amd64 manifest, or the image itself if it is not an index."""
    raw = subprocess.run(['docker', 'buildx', 'imagetools', 'inspect', '--raw', image],
                         check=True, capture_output=True, text=True).stdout
    manifests = json.loads(raw).get('manifests')
    if not manifests:
        return image
    for manifest in manifests:
        platform = manifest.get('platform') or {}
        if (platform.get('os'), platform.get('architecture')) == PLATFORM:
            return f"{repository(image)}@{manifest['digest']}"
    raise SystemExit(f'error: {image} has no {"/".join(PLATFORM)} manifest')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--inventory', type=Path, default=ROOT / 'selfhost')
    args = parser.parse_args(argv)
    pulled = []
    for image in inventory(args.inventory):
        reference = platform_reference(image)
        print(f'pulling {image} as {reference}', file=sys.stderr, flush=True)
        subprocess.run(['docker', 'pull', '--quiet', '--platform', '/'.join(PLATFORM), reference],
                       check=True, stdout=subprocess.DEVNULL)
        pulled.append((repository(image), reference))
    references = [reference for _, reference in pulled]
    status = 0
    for command in (['bash', str(ROOT / 'scripts/check-image-no-ssh-server.sh'), *references],
                    ['bash', str(ROOT / 'scripts/check-image-listeners.sh'), *references],
                    [sys.executable, str(ROOT / 'scripts/check-image-policy.py'),
                     *(f'{key}={reference}' for key, reference in pulled)]):
        status = subprocess.run(command, env=os.environ).returncode or status
    return status


if __name__ == '__main__':
    sys.exit(main())
