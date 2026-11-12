"""Verify the cosign signature and SLSA provenance a release ships for each first-party image.

scripts/publish-images.sh signs every pushed image digest with the image-signing key (`cosign sign`) and
attests its BuildKit provenance (`cosign attest --type slsaprovenance02`), both without a transparency
log, and puts the two Sigstore bundles of each image into the release under selfhost/image-signatures/.
The manifest names them and the public key (selfhost/image-signing.pub), and the SSH-signed checksum
covers all of it. Anyone can check the registry copies with
`cosign verify --key selfhost/image-signing.pub --insecure-ignore-tlog IMAGE@DIGEST`.

`./chronicle update` checks the candidate's bundles here, offline, before it pulls anything: each bundle's
DSSE envelope must be signed by the pinned key (ECDSA P-256, verified with the host's openssl, which the
launcher already requires), carry the right in-toto predicate, and name the exact digest the manifest pins.
A release from before 2026.11.12 has no image_signatures entry and is accepted as before: its digests are
bound by the SSH-signed manifest alone.
"""
import base64
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile

from .common import warn

SIGNATURES_KEY = 'image_signatures'
BUNDLE_MEDIA_TYPES = ('application/vnd.dev.sigstore.bundle.v0.3+json',)
PAYLOAD_TYPE = 'application/vnd.in-toto+json'
SIGNATURE_PREDICATE = 'https://sigstore.dev/cosign/sign/v1'
PROVENANCE_PREDICATE = 'https://slsa.dev/provenance/v0.2'
KINDS = {'signature': SIGNATURE_PREDICATE, 'provenance': PROVENANCE_PREDICATE}


def pae(payload_type, payload):
    """DSSE pre-authentication encoding: what the signature covers."""
    return b'DSSEv1 %d %s %d %s' % (len(payload_type), payload_type, len(payload), payload)


def bundle_file(bundle, relative):
    path = PurePosixPath(str(relative))
    if not str(relative) or path.is_absolute() or '..' in path.parts:
        raise ValueError(f'unsafe image signature path in the release manifest: {relative!r}')
    resolved = Path(bundle) / path
    if resolved.is_symlink() or not resolved.is_file():
        raise ValueError(f'image signature file is missing: {relative}')
    return resolved


def openssl_verifies(public_key, signature, message):
    with tempfile.TemporaryDirectory(prefix='chronicle-image-signature-') as folder:
        signature_path, message_path = Path(folder) / 'signature', Path(folder) / 'message'
        signature_path.write_bytes(signature)
        message_path.write_bytes(message)
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(public_key), '-signature',
                                 str(signature_path), str(message_path)], capture_output=True, check=False)
        return result.returncode == 0


def verify_bundle(path, public_key, digest, predicate_type, label):
    try:
        bundle = json.loads(path.read_text(encoding='utf-8'))
        envelope = bundle['dsseEnvelope']
        payload = base64.b64decode(envelope['payload'], validate=True)
        signatures = [base64.b64decode(item['sig'], validate=True) for item in envelope['signatures']]
        statement = json.loads(payload)
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise ValueError(f'{label}: unreadable Sigstore bundle {path.name} ({error})') from None
    if bundle.get('mediaType') not in BUNDLE_MEDIA_TYPES or envelope.get('payloadType') != PAYLOAD_TYPE:
        raise ValueError(f'{label}: {path.name} is not a Sigstore DSSE bundle of an in-toto statement')
    message = pae(PAYLOAD_TYPE.encode(), payload)
    if not any(openssl_verifies(public_key, signature, message) for signature in signatures):
        raise ValueError(f'{label}: the signature does not verify with the release image-signing key')
    if statement.get('predicateType') != predicate_type:
        raise ValueError(f'{label}: {path.name} carries predicate {statement.get("predicateType")!r}, '
                         f'not {predicate_type}')
    subjects = {(subject.get('digest') or {}).get('sha256') for subject in statement.get('subject') or []}
    if subjects != {digest}:
        raise ValueError(f'{label}: the signed statement does not name exactly the pinned digest sha256:{digest}')


def verify_release_images(bundle, manifest):
    """Components whose signature and provenance verified; [] for a release that ships none."""
    from .images import SOURCE_IMAGES
    spec = manifest.get(SIGNATURES_KEY)
    if spec is None:
        return []
    if not isinstance(spec, dict) or not isinstance(spec.get('bundles'), dict):
        raise ValueError('malformed image_signatures entry in the release manifest')
    public_key = bundle_file(bundle, spec.get('public_key', ''))
    expected = {image.component for image in SOURCE_IMAGES}
    if set(spec['bundles']) != expected:
        missing = ', '.join(sorted(expected ^ set(spec['bundles'])))
        raise ValueError(f'image signatures do not cover exactly the first-party images: {missing}')
    files = {component: {kind: bundle_file(bundle, (entry or {}).get(kind, '')) for kind in KINDS}
             for component, entry in spec['bundles'].items()}
    if shutil.which('openssl') is None:
        warn('openssl is not installed, so the image signatures in this release were not checked; the image '
             'digests are still the ones the signed release manifest pins. Install openssl to check them.')
        return []
    verified = []
    for component in sorted(expected):
        pin = manifest['images'][component]
        digest = pin.rpartition('@sha256:')[2]
        for kind, predicate in KINDS.items():
            verify_bundle(files[component][kind], public_key, digest, predicate, f'{component} image {kind}')
        verified.append(component)
    return verified
