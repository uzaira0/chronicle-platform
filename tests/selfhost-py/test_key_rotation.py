"""CI-U7 / SO-U7: a release signed by a new key installs with `./chronicle update` alone.

A rotation release carries two extra assets: release-signing.pub (the new public key) and
release-signing.pub.sig, an SSH signature over that key by the key the server already trusts,
in its own namespace (chronicle-release-key, so a checksum signature can never stand in for it).
The updater accepts the new key only through that endorsement, verifies the checksum with it,
and requires the bundle to ship the same key, so the next update trusts it. Real ssh-keygen keys.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from chronicle_ops import update
from chronicle_ops.release import RELEASE_SIGNER

ARCHIVE = 'chronicle-selfhost-2026.11.9.tar.gz'


class KeyRotationTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.folder)
        self.keys = {name: self.key(name) for name in ('installed', 'rotated', 'stranger')}
        (self.folder / ARCHIVE).write_bytes(b'fixture release archive\n')
        digest = subprocess.run(['shasum', '-a', '256', ARCHIVE], cwd=self.folder, capture_output=True, text=True,
                                check=True).stdout.split()[0]
        (self.folder / (ARCHIVE + '.sha256')).write_text(f'{digest}  {ARCHIVE}\n')

    def key(self, name):
        path = self.folder / name
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', name, '-f', str(path)], check=True,
                       capture_output=True, timeout=30)
        return path

    def public(self, name):
        return (self.keys[name].with_suffix('.pub')).read_text().strip()

    def sign(self, signer, path, namespace, output):
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-q', '-n', namespace, '-f', str(self.keys[signer]), str(path)],
                       check=True, capture_output=True, timeout=30)
        Path(str(path) + '.sig').replace(output)

    def assets(self, *, checksum_signer, endorsement_signer=None, namespace=update.KEY_ROTATION_NAMESPACE):
        self.sign(checksum_signer, self.folder / (ARCHIVE + '.sha256'), RELEASE_SIGNER,
                  self.folder / (ARCHIVE + '.sha256.sig'))
        names = [ARCHIVE, ARCHIVE + '.sha256', ARCHIVE + '.sha256.sig']
        if endorsement_signer:
            endorsed = self.folder / update.ROTATED_KEY_ASSET
            endorsed.write_text(self.public('rotated') + '\n')
            # Sign a copy: ssh-keygen writes <file>.sig next to the file it signs.
            copy = self.folder / 'endorse-copy'
            shutil.copy(endorsed, copy)
            self.sign(endorsement_signer, copy, namespace, self.folder / update.ROTATION_ENDORSEMENT_ASSET)
            names += [update.ROTATED_KEY_ASSET, update.ROTATION_ENDORSEMENT_ASSET]
        release = {'assets': [{'name': name, 'browser_download_url': 'https://example.invalid/' + name} for name in names]}
        return update.release_assets(release, ARCHIVE)

    def verify(self, assets):
        return update.verify_download(self.folder, assets, self.public('installed'), directory=self.folder)

    def test_a_release_signed_by_the_installed_key_needs_no_endorsement(self):
        assets = self.assets(checksum_signer='installed')
        self.assertIsNone(assets.rotated_key)
        self.assertEqual(self.public('installed'), self.verify(assets))

    def test_a_new_key_endorsed_by_the_installed_key_is_accepted(self):
        assets = self.assets(checksum_signer='rotated', endorsement_signer='installed')
        self.assertEqual(update.ROTATED_KEY_ASSET, assets.rotated_key.name)
        self.assertEqual(self.public('rotated'), self.verify(assets))

    def test_a_new_key_without_an_endorsement_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'invalid release signature'):
            self.verify(self.assets(checksum_signer='rotated'))

    def test_an_endorsement_by_any_other_key_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'not endorsed by the installed release key'):
            self.verify(self.assets(checksum_signer='rotated', endorsement_signer='stranger'))

    def test_a_checksum_signature_cannot_serve_as_an_endorsement(self):
        # Same signer, release namespace: a signature made for a checksum file must not endorse a key.
        with self.assertRaisesRegex(ValueError, 'not endorsed by the installed release key'):
            self.verify(self.assets(checksum_signer='rotated', endorsement_signer='installed', namespace=RELEASE_SIGNER))

    def test_the_maintainer_script_writes_an_endorsement_the_updater_accepts(self):
        self.sign('rotated', self.folder / (ARCHIVE + '.sha256'), RELEASE_SIGNER, self.folder / (ARCHIVE + '.sha256.sig'))
        output = self.folder / 'endorsement'
        root = Path(__file__).resolve().parents[2]
        subprocess.run(['bash', str(root / 'scripts/endorse-release-key.sh'), str(self.keys['installed']),
                        str(self.keys['rotated'].with_suffix('.pub')), str(output)], check=True, capture_output=True, timeout=60)
        for name in (update.ROTATED_KEY_ASSET, update.ROTATION_ENDORSEMENT_ASSET):
            shutil.copy(output / name, self.folder / name)
        self.assertEqual([update.ROTATED_KEY_ASSET, update.ROTATION_ENDORSEMENT_ASSET], sorted(os.listdir(output)))
        names = [ARCHIVE, ARCHIVE + '.sha256', ARCHIVE + '.sha256.sig', update.ROTATED_KEY_ASSET, update.ROTATION_ENDORSEMENT_ASSET]
        release = {'assets': [{'name': name, 'browser_download_url': 'https://example.invalid/' + name} for name in names]}
        self.assertEqual(self.public('rotated'), self.verify(update.release_assets(release, ARCHIVE)))

    def test_a_rotated_key_without_its_endorsement_asset_is_refused_before_download(self):
        names = [ARCHIVE, ARCHIVE + '.sha256', ARCHIVE + '.sha256.sig', update.ROTATED_KEY_ASSET]
        release = {'assets': [{'name': name, 'browser_download_url': 'https://example.invalid/' + name} for name in names]}
        with self.assertRaisesRegex(ValueError, 'needs both'):
            update.release_assets(release, ARCHIVE)

    def test_the_bundle_must_ship_the_key_that_signed_it(self):
        bundle = self.folder / 'bundle'
        (bundle / 'selfhost').mkdir(parents=True)
        (bundle / 'selfhost/release-signing.pub').write_text(self.public('rotated') + '\n')
        update.require_bundled_key(bundle, self.public('rotated'))
        with self.assertRaisesRegex(ValueError, 'does not ship the key that signed it'):
            update.require_bundled_key(bundle, self.public('installed'))


if __name__ == '__main__':
    unittest.main()
