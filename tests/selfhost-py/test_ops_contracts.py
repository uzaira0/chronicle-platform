"""Restore phase order, credential repr, deployment-mode parsing and backup probe transport."""
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "selfhost"))
from chronicle_ops.credentials import SetupCredentials
from chronicle_ops.env_migration import DeploymentMode, compose_names, dashboard_login_settings, deployment_mode
from chronicle_ops.restore import Restore, RestoreError, RestorePhase

ROOT = Path(__file__).resolve().parents[2]


class RestorePhaseTests(unittest.TestCase):
    def restore(self):
        restore = Restore.__new__(Restore)
        restore.phase = None
        restore.written = []
        restore.write_lock = lambda name, text: restore.written.append((name, text))
        return restore

    def test_phases_are_entered_only_in_order(self):
        restore = self.restore()
        for phase in RestorePhase:
            restore.enter(phase)
        self.assertEqual(restore.written, [("phase", phase.value) for phase in RestorePhase])

    def test_skipping_repeating_or_passing_the_last_phase_is_refused(self):
        restore = self.restore()
        with self.assertRaises(RestoreError):
            restore.enter(RestorePhase.RESTORING)
        restore.enter(RestorePhase.PREPARED)
        with self.assertRaises(RestoreError):
            restore.enter(RestorePhase.PREPARED)
        for phase in list(RestorePhase)[1:]:
            restore.enter(phase)
        with self.assertRaises(RestoreError):
            restore.enter(RestorePhase.VERIFIED)
        self.assertEqual(len(restore.written), len(RestorePhase))


class CredentialReprTests(unittest.TestCase):
    def test_repr_never_contains_secret_values(self):
        credentials = SetupCredentials({"JWT_SECRET": "fixture-secret-value"}, {"JWT_SECRET": "2026-10-22"})
        self.assertNotIn("fixture-secret-value", repr(credentials))
        self.assertIn("2026-10-22", repr(credentials))


class DeploymentModeTests(unittest.TestCase):
    def test_each_mode_overlay_names_one_mode(self):
        for overlay, mode in (("overlays/mode-behind-proxy-internal.yml", DeploymentMode.BEHIND_PROXY),
                              ("overlays/mode-own-tls-internal.yml", DeploymentMode.OWN_TLS),
                              ("overlays/mode-local-https.yml", DeploymentMode.LOCAL_HTTPS)):
            with self.subTest(overlay=overlay):
                self.assertIs(deployment_mode(f"docker-compose.yml:{overlay}:overlays/backups.yml"), mode)
                names = compose_names({"COMPOSE_FILE": f"docker-compose.yml:{overlay}"}, Path("/release"))
                self.assertEqual(dashboard_login_settings({"DASHBOARD_PASSWORD_HASH": "$2b$fixture"}, names),
                                 {"TESTING_LOGIN_ENABLED": "false", "REQUIRE_MFA": "false"})
        self.assertIsNone(deployment_mode("docker-compose.yml:overlays/backups.yml"))

    def test_absolute_mode_overlay_inside_the_release_selects_its_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            release = Path(folder).resolve()
            selection = f"{release}/docker-compose.yml:{release}/overlays/mode-local-https.yml"
            self.assertEqual(compose_names({"COMPOSE_FILE": selection}, release),
                             ["docker-compose.yml", "overlays/mode-local-https.yml"])
            self.assertIs(deployment_mode(selection, release), DeploymentMode.LOCAL_HTTPS)
            with patch.object(Path, "cwd", return_value=release):
                self.assertIs(deployment_mode(selection), DeploymentMode.LOCAL_HTTPS)

    def test_update_drops_an_operator_file_outside_the_release_and_refuses_a_missing_base_file(self):
        from chronicle_ops.env_migration import compose_selection
        with tempfile.TemporaryDirectory() as folder:
            release = Path(folder).resolve()
            # An operator's own Compose file is left out (the update keeps a copy and names it).
            selection = f"{release}/docker-compose.yml:{release}/overlays/mode-local-https.yml:/etc/chronicle/custom.yml"
            self.assertEqual((["docker-compose.yml", "overlays/mode-local-https.yml"], ["/etc/chronicle/custom.yml"]),
                             compose_selection({"COMPOSE_FILE": selection}, release))
            # Without the base file there is nothing to derive the deployment from.
            message = "previous COMPOSE_FILE must contain docker-compose.yml exactly once"
            with self.assertRaisesRegex(ValueError, "^" + re.escape(message) + "$"):
                compose_names({"COMPOSE_FILE": "overlays/mode-local-https.yml:overlays/backups.yml"}, release)

    def test_compose_selection_needs_exactly_one_known_mode(self):
        for selection in ("docker-compose.yml",
                          "docker-compose.yml:overlays/mode-own-tls-internal.yml:overlays/mode-local-https.yml",
                          "docker-compose.yml:overlays/mode-behind-proxy-public.yml"):
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                compose_names({"COMPOSE_FILE": selection}, Path("/release"))


class BackupProbeTransportTests(unittest.TestCase):
    def test_backup_readiness_probe_uses_verified_https(self):
        import yaml
        service = yaml.safe_load((ROOT / "selfhost/overlays/backups.yml").read_text())["services"]["db-backup"]
        environment = service["environment"]
        self.assertTrue(environment["BACKUP_BACKEND_URL"].startswith("https://backend:8443/"))
        self.assertIn("backend_tls:" + str(Path(environment["BACKUP_BACKEND_CA"]).parent) + ":ro", service["volumes"])


if __name__ == "__main__":
    unittest.main()
