"""A release's first-party images are verified against the pinned image-signing key before an update pulls them.

The fixtures under fixtures/cosign are real cosign v3.1.4 output (`cosign sign --key ... --bundle` and
`cosign attest --type slsaprovenance02 ... --bundle`, no transparency log) for one image digest; the
negative cases re-sign with a different key through openssl, which is what the verifier itself uses.
"""
import base64
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from chronicle_ops import image_signatures
from chronicle_ops.images import SOURCE_IMAGES

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'cosign'
DIGEST = '36ddee97b4f569fdb60d7f0c627b68d44da895ad6d6970ab93eecf927e214296'


@unittest.skipUnless(shutil.which('openssl'), 'needs openssl')
class ImageSignatureTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='image-signatures-')
        self.addCleanup(self.folder.cleanup)
        self.bundle = Path(self.folder.name)
        (self.bundle / 'selfhost/image-signatures').mkdir(parents=True)
        shutil.copy(FIXTURES / 'image-signing.pub', self.bundle / 'selfhost/image-signing.pub')
        signatures = {}
        for image in SOURCE_IMAGES:
            for kind in ('signature', 'provenance'):
                relative = f'selfhost/image-signatures/{image.component}.{kind}.sigstore.json'
                shutil.copy(FIXTURES / f'{kind}.sigstore.json', self.bundle / relative)
                signatures.setdefault(image.component, {})[kind] = relative
        self.manifest = {
            'images': {image.component: f'ghcr.io/example/{image.component}@sha256:{DIGEST}' for image in SOURCE_IMAGES},
            image_signatures.SIGNATURES_KEY: {'public_key': 'selfhost/image-signing.pub', 'bundles': signatures},
        }

    def verify(self, manifest=None):
        return image_signatures.verify_release_images(self.bundle, manifest or self.manifest)

    def test_real_cosign_bundles_verify_for_every_first_party_image(self):
        self.assertEqual(sorted(image.component for image in SOURCE_IMAGES), sorted(self.verify()))

    def test_a_release_without_signatures_is_accepted_unchanged(self):
        # Every release before 2026.11.12: their digests are bound by the SSH-signed manifest alone.
        manifest = dict(self.manifest)
        del manifest[image_signatures.SIGNATURES_KEY]
        self.assertEqual([], self.verify(manifest))

    def test_a_signature_for_another_digest_is_refused(self):
        manifest = json.loads(json.dumps(self.manifest))
        manifest['images']['backend'] = 'ghcr.io/example/backend@sha256:' + 'f' * 64
        with self.assertRaisesRegex(ValueError, 'backend.*does not name'):
            self.verify(manifest)

    def test_another_key_is_refused(self):
        other = self.bundle / 'other.pem'
        subprocess.run(['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(other)], check=True)
        public = subprocess.run(['openssl', 'ec', '-in', str(other), '-pubout'], check=True, capture_output=True).stdout
        (self.bundle / 'selfhost/image-signing.pub').write_bytes(public)
        with self.assertRaisesRegex(ValueError, 'signature does not verify'):
            self.verify()

    def resign(self, path, statement, key):
        bundle = json.loads(path.read_text())
        payload = json.dumps(statement).encode()
        envelope = bundle['dsseEnvelope']
        envelope['payload'] = base64.b64encode(payload).decode()
        message = image_signatures.pae(envelope['payloadType'].encode(), payload)
        (self.bundle / 'message').write_bytes(message)
        signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key), str(self.bundle / 'message')],
                                   check=True, capture_output=True).stdout
        envelope['signatures'] = [{'sig': base64.b64encode(signature).decode()}]
        path.write_text(json.dumps(bundle))

    def test_a_tampered_payload_or_wrong_predicate_is_refused(self):
        key = self.bundle / 'signer.pem'
        subprocess.run(['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(key)], check=True)
        (self.bundle / 'selfhost/image-signing.pub').write_bytes(
            subprocess.run(['openssl', 'ec', '-in', str(key), '-pubout'], check=True, capture_output=True).stdout)
        statement = {'_type': 'https://in-toto.io/Statement/v1', 'subject': [{'digest': {'sha256': DIGEST}}],
                     'predicateType': image_signatures.SIGNATURE_PREDICATE, 'predicate': {}}
        provenance = dict(statement, predicateType=image_signatures.PROVENANCE_PREDICATE)
        for image in SOURCE_IMAGES:
            self.resign(self.bundle / f'selfhost/image-signatures/{image.component}.signature.sigstore.json', statement, key)
            self.resign(self.bundle / f'selfhost/image-signatures/{image.component}.provenance.sigstore.json', provenance, key)
        self.assertEqual(len(SOURCE_IMAGES), len(self.verify()))
        # The provenance attestation cannot stand in for the signature, nor the other way round.
        self.resign(self.bundle / 'selfhost/image-signatures/caddy.signature.sigstore.json', provenance, key)
        with self.assertRaisesRegex(ValueError, 'caddy.*predicate'):
            self.verify()
        self.resign(self.bundle / 'selfhost/image-signatures/caddy.signature.sigstore.json', statement, key)
        path = self.bundle / 'selfhost/image-signatures/caddy.signature.sigstore.json'
        bundle = json.loads(path.read_text())
        tampered = dict(statement, subject=[{'digest': {'sha256': 'e' * 64}}, {'digest': {'sha256': DIGEST}}])
        bundle['dsseEnvelope']['payload'] = base64.b64encode(json.dumps(tampered).encode()).decode()
        path.write_text(json.dumps(bundle))
        with self.assertRaisesRegex(ValueError, 'signature does not verify'):
            self.verify()

    def test_missing_or_escaping_bundle_paths_are_refused(self):
        for component, path, message in (('frontend', None, 'frontend'),
                                         ('frontend', '../outside.json', 'unsafe'),
                                         ('frontend', 'selfhost/image-signatures/absent.json', 'missing')):
            manifest = json.loads(json.dumps(self.manifest))
            if path is None:
                del manifest[image_signatures.SIGNATURES_KEY]['bundles'][component]
            else:
                manifest[image_signatures.SIGNATURES_KEY]['bundles'][component]['signature'] = path
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, message):
                self.verify(manifest)

    def test_without_openssl_the_update_warns_and_relies_on_the_signed_manifest(self):
        warnings = []
        with patch.object(image_signatures.shutil, 'which', return_value=None), \
                patch.object(image_signatures, 'warn', warnings.append):
            self.assertEqual([], self.verify())
        self.assertTrue(any('openssl' in line for line in warnings), warnings)


@unittest.skipUnless(shutil.which('openssl'), 'needs openssl')
class BuilderTests(unittest.TestCase):
    def test_the_builder_ships_every_bundle_and_refuses_an_incomplete_set(self):
        import runpy
        builder = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'scripts/build-selfhost-release.py'))
        with tempfile.TemporaryDirectory(prefix='image-signature-build-') as folder:
            source, bundle = Path(folder) / 'signed', Path(folder) / 'bundle'
            source.mkdir()
            (bundle / 'selfhost').mkdir(parents=True)
            shutil.copy(FIXTURES / 'image-signing.pub', bundle / 'selfhost/image-signing.pub')
            for image in SOURCE_IMAGES:
                for kind in ('signature', 'provenance'):
                    shutil.copy(FIXTURES / f'{kind}.sigstore.json', source / f'{image.component}.{kind}.sigstore.json')
            entry = builder['copy_image_signatures'](bundle, source)
            self.assertEqual('selfhost/image-signing.pub', entry['public_key'])
            manifest = {'images': {image.component: f'ghcr.io/example/{image.component}@sha256:{DIGEST}' for image in SOURCE_IMAGES},
                        image_signatures.SIGNATURES_KEY: entry}
            self.assertEqual(len(SOURCE_IMAGES), len(image_signatures.verify_release_images(bundle, manifest)))
            (source / 'grafana.provenance.sigstore.json').unlink()
            (Path(folder) / 'second/selfhost').mkdir(parents=True)
            with self.assertRaisesRegex(SystemExit, 'grafana.provenance.sigstore.json'):
                builder['copy_image_signatures'](Path(folder) / 'second', source)


class ReadManifestHookTests(unittest.TestCase):
    def test_the_update_candidate_is_verified_before_its_images_are_pulled(self):
        """upgrade.py reads the candidate with read_manifest(..., True) and pulls only afterwards."""
        from pathlib import Path as P
        release = (P(image_signatures.__file__).parent / 'release.py').read_text()
        body = release[release.index('def read_manifest('):]
        body = body[:body.index('\ndef ', 1)]
        self.assertIn('verify_release_images(bundle, manifest)', body)
        self.assertLess(body.index('if discovery:'), body.index('verify_release_images(bundle, manifest)'))
        upgrade = (P(image_signatures.__file__).parent / 'upgrade.py').read_text()
        self.assertLess(upgrade.index("read_manifest(self.candidate.parent / 'release-manifest.json', True)"),
                        upgrade.index('self.pull_images()'))


if __name__ == '__main__':
    unittest.main()
