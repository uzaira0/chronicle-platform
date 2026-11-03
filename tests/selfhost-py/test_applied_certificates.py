import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from chronicle_ops.release import CERTIFICATE_MARKER, certificate_digest, certificates_changed, record_applied_certificates


class AppliedCertificatesTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        tls = self.state / "tls"
        (tls / "monitoring").mkdir(parents=True)
        (tls / "internal-cert.pem").write_text("cert")
        (tls / "monitoring" / "monitoring.crt").write_text("crt")
        (tls / "service-certificates.sha256").write_text("sums")
        (tls / "internal-key.pem").write_text("key")

    def test_recorded_digest_is_unchanged_and_missing_or_unreadable_record_is_changed(self):
        digest = certificate_digest(self.state)
        self.assertTrue(certificates_changed(self.state, digest))
        record_applied_certificates(self.state, digest)
        self.assertFalse(certificates_changed(self.state, digest))
        # cert-init rewrites, re-owns and re-modes unchanged files on every start: no content change, no recreate.
        certificate = self.state / "tls" / "internal-cert.pem"
        replacement = certificate.with_name("internal-cert.pem.new")
        replacement.write_text(certificate.read_text())
        replacement.replace(certificate)
        certificate.chmod(0o640)
        os.utime(certificate, (1, 1))
        self.assertFalse(certificates_changed(self.state, certificate_digest(self.state)))
        certificate.write_text("renewed cert")
        self.assertTrue(certificates_changed(self.state, certificate_digest(self.state)))
        if os.geteuid() != 0:
            (self.state / CERTIFICATE_MARKER).chmod(0)
            self.assertTrue(certificates_changed(self.state, digest))

    def test_marker_written_by_earlier_releases_still_matches(self):
        # 2026.9-2026.10.9 wrote `find … -exec sha256sum {} + | sort`, under the shell's own path spelling.
        legacy = subprocess.run(["bash", "-c", "find \"$1/tls\" -type f \\( -name '*cert.pem' -o -name '*.crt' -o -name '*.sha256' \\) -exec sha256sum {} + | sort",
                                 "legacy", str(self.state) + "/."], capture_output=True, text=True, check=True).stdout.rstrip("\n")
        self.assertEqual(sorted(legacy.split()[0::2]), sorted(certificate_digest(self.state).split()[0::2]))
        (self.state / CERTIFICATE_MARKER).write_text(legacy)
        self.assertFalse(certificates_changed(self.state, certificate_digest(self.state)))

    def test_certificate_changes_are_detected_and_keys_are_not_read(self):
        before = certificate_digest(self.state)
        record_applied_certificates(self.state, before)
        self.assertNotIn("internal-key.pem", before)
        self.assertIn("monitoring/monitoring.crt", before)
        (self.state / "tls" / "internal-key.pem").write_text("rotated key")
        self.assertFalse(certificates_changed(self.state, certificate_digest(self.state)))
        (self.state / "tls" / "service-certificates.sha256").write_text("new sums")
        self.assertTrue(certificates_changed(self.state, certificate_digest(self.state)))


if __name__ == "__main__":
    unittest.main()
