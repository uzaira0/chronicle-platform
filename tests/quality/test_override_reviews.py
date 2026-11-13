import datetime
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


class OverrideReviewTests(unittest.TestCase):
    def test_every_override_has_a_current_removal_review(self):
        spec = importlib.util.spec_from_file_location("overrides", ROOT / "scripts/check-dependency-overrides.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual([], module.problems(ROOT))

    def test_an_unrecorded_changed_or_expired_override_fails(self):
        spec = importlib.util.spec_from_file_location("overrides", ROOT / "scripts/check-dependency-overrides.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        record = {"pin": "1.2.3", "reason": "CVE fixture", "remove_when": "Upstream resolves 1.2.3",
                  "reviewed_on": "2026-11-01", "review_after": "2026-12-01"}
        today = datetime.date(2026, 11, 1)
        self.assertEqual([], module.review_problems({"a": "1.2.3"}, {"a": record}, today))
        self.assertTrue(module.review_problems({"a": "1.2.3", "b": "4"}, {"a": record}, today))
        self.assertTrue(module.review_problems({"a": "2"}, {"a": record}, today))
        self.assertTrue(module.review_problems({"a": "1.2.3"}, {"a": record}, datetime.date(2026, 12, 1)))
        for field in ("reason", "remove_when", "reviewed_on", "review_after"):
            with self.subTest(field=field):
                self.assertTrue(module.review_problems({"a": "1.2.3"}, {"a": {**record, field: ""}}, today))


class PatchOverrideReviewTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("patch_overrides", ROOT / "scripts/check-dependency-overrides.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.work_root = ROOT / "build" / "override-patch-tests"
        self.work_root.mkdir(parents=True, exist_ok=True)

    def fixture(self, directory):
        root = Path(directory)
        for name in ("gradles", "chronicle-web/vendor/patches", "selfhost"):
            (root / name).mkdir(parents=True)
        (root / "gradles/chronicle.gradle").write_text("")
        (root / "selfhost/Dockerfile.caddy").write_text("")
        # inventory() also reads the Grafana image's go-work replaces (59abc18).
        (root / "selfhost/Dockerfile.grafana").write_text("")
        (root / "selfhost/Dockerfile.backup").write_text("# Commit: " + "a" * 40 + "\n")
        (root / "selfhost/Dockerfile.postgres").write_text("")
        package = {"patchedDependencies": {"@redocly/openapi-core@1.34.22": "vendor/patches/redocly.patch"}}
        (root / "chronicle-web/package.json").write_text(json.dumps(package))
        patch = root / "chronicle-web/vendor/patches/redocly.patch"
        patch.write_text("-legacy callable\n+named export\n")
        return root, package, patch

    def inventory(self, root):
        with mock.patch.object(self.module.subprocess, "run", return_value=mock.Mock(stdout="")):
            return self.module.inventory(root)

    def test_grafana_replace_reads_its_arg_version(self):
        # Since 2026-11-07 Dockerfile.grafana quotes the replace and takes the version from an annotated ARG.
        with tempfile.TemporaryDirectory(dir=self.work_root) as directory:
            root, _, _ = self.fixture(directory)
            key = "selfhost/Dockerfile.grafana::github.com/go-jose/go-jose/v4"
            grafana = root / "selfhost/Dockerfile.grafana"
            replace = 'RUN go work edit -replace="github.com/go-jose/go-jose/v4=github.com/go-jose/go-jose/v4@${V}" && go build ./x\n'
            for text, pin in (("FROM golang\nARG V=v4.1.8\n" + replace, "v4.1.8"),
                              ("FROM golang\nRUN go work edit -replace=github.com/go-jose/go-jose/v4=github.com/go-jose/go-jose/v4@v4.1.8\n", "v4.1.8"),
                              ("FROM golang\n" + replace, "${V}")):
                with self.subTest(text=text):
                    grafana.write_text(text)
                    found = {name: value for name, value in self.inventory(root).items() if "Dockerfile.grafana" in name}
                    self.assertEqual({key: pin}, found)

    def test_patch_bytes_have_the_same_dated_removal_review(self):
        with tempfile.TemporaryDirectory(dir=self.work_root) as directory:
            root, _, patch = self.fixture(directory)
            key = "chronicle-web/package.json::patch:@redocly/openapi-core@1.34.22"
            digest = "sha256:" + hashlib.sha256(patch.read_bytes()).hexdigest()
            self.assertEqual(digest, self.inventory(root)[key])
            record = {"pin": digest, "reason": "Named export compatibility", "remove_when": "Parent supports the named export",
                      "reviewed_on": "2026-11-01", "review_after": "2026-12-01"}
            today = datetime.date(2026, 11, 1)
            self.assertEqual([], self.module.review_problems({key: digest}, {key: record}, today))
            patch.write_text("different patch bytes\n")
            self.assertTrue(self.module.review_problems({key: self.inventory(root)[key]}, {key: record}, today))

    def test_missing_patch_fails_before_hashing_any_file(self):
        with tempfile.TemporaryDirectory(dir=self.work_root) as directory:
            root, package, _ = self.fixture(directory)
            package["patchedDependencies"]["@redocly/openapi-core@1.34.22"] = "vendor/patches/missing.patch"
            (root / "chronicle-web/package.json").write_text(json.dumps(package))
            with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("must not read a missing patch")), self.assertRaises(ValueError):
                self.inventory(root)

    def test_invalid_paths_and_symlinks_fail_before_hashing_any_file(self):
        with tempfile.TemporaryDirectory(dir=self.work_root) as directory:
            root, package, _ = self.fixture(directory)
            outside = root / "outside.patch"
            outside.write_text("outside the web checkout\n")
            (root / "chronicle-web/vendor/link.patch").symlink_to(outside)
            (root / "chronicle-web/linked").symlink_to(root, target_is_directory=True)
            (root / "chronicle-web/vendor/directory.patch").mkdir()
            for path in (str(outside), "../outside.patch", "vendor/../outside.patch", "C:\\outside.patch",
                         "package.json", "vendor/link.patch", "linked/outside.patch", "vendor/directory.patch"):
                with self.subTest(path=path):
                    package["patchedDependencies"]["@redocly/openapi-core@1.34.22"] = path
                    (root / "chronicle-web/package.json").write_text(json.dumps(package))
                    with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("must not read an invalid patch path")), self.assertRaises(ValueError):
                        self.inventory(root)


    def test_named_security_classpath_floors_use_the_existing_dated_review(self):
        with tempfile.TemporaryDirectory(dir=self.work_root) as directory:
            root, _, _ = self.fixture(directory)
            (root / "chronicle-api").mkdir()
            build = root / "chronicle-api/build.gradle"
            build.write_text("""buildscript {
    dependencies {
        classpath('io.swagger.codegen.v3:swagger-codegen:3.0.82')
        def securityClasspathFloors = [
            'ch.qos.logback:logback-classic:1.6.6',
            'com.github.jknack:handlebars:4.5.8',
            'com.fasterxml.jackson.core:jackson-databind:2.22.3',
        ]
        securityClasspathFloors.each { classpath it }
    }
}
""")
            expected = {"chronicle-api/build.gradle::ch.qos.logback:logback-classic": "1.6.6",
                        "chronicle-api/build.gradle::com.github.jknack:handlebars": "4.5.8",
                        "chronicle-api/build.gradle::com.fasterxml.jackson.core:jackson-databind": "2.22.3"}
            with mock.patch.object(self.module.subprocess, "run", return_value=mock.Mock(stdout="chronicle-api/build.gradle\0")):
                found = self.module.inventory(root)
                self.assertEqual(expected, {name: pin for name, pin in found.items() if name in expected})
                self.assertNotIn("chronicle-api/build.gradle::io.swagger.codegen.v3:swagger-codegen", found)
                records = {name: {"pin": pin, "reason": "Published security fix", "remove_when": "Parent resolves the patched version",
                                  "reviewed_on": "2026-11-01", "review_after": "2026-12-01"}
                           for name, pin in expected.items()}
                today = datetime.date(2026, 11, 1)
                self.assertEqual([], self.module.review_problems(expected, records, today))
                build.write_text(build.read_text().replace("1.6.6", "1.6.7"))
                changed = self.module.inventory(root)
                self.assertTrue(self.module.review_problems({name: changed[name] for name in expected}, records, today))


    def test_kotlin_security_classpath_list_is_reviewed_without_plain_or_unused_classpaths(self):
        with tempfile.TemporaryDirectory(dir=self.work_root) as directory:
            root, _, _ = self.fixture(directory)
            build = root / "build.gradle.kts"
            build.write_text("""buildscript {
    dependencies {
        val securityClasspathFloors = listOf(
            "com.fasterxml.jackson.core:jackson-databind:2.22.3",
            "org.jsoup:jsoup:1.23.2",
        )
        securityClasspathFloors.forEach { classpath(it) }
        classpath("org.owasp:dependency-check-gradle:13.0.0")
        val unused = listOf("example:unconsumed:1.0")
    }
}
""")
            expected = {"build.gradle.kts::com.fasterxml.jackson.core:jackson-databind": "2.22.3",
                        "build.gradle.kts::org.jsoup:jsoup": "1.23.2"}
            with mock.patch.object(self.module.subprocess, "run", return_value=mock.Mock(stdout="build.gradle.kts\0")):
                found = self.module.inventory(root)
                self.assertEqual(expected, {name: pin for name, pin in found.items() if name in expected})
                self.assertNotIn("build.gradle.kts::org.owasp:dependency-check-gradle", found)
                self.assertNotIn("build.gradle.kts::example:unconsumed", found)
                build.write_text(build.read_text().replace("val securityClasspathFloors =", "val otherName ="))
                with self.assertRaisesRegex(ValueError, "cannot inventory classpath list securityClasspathFloors"):
                    self.module.inventory(root)


if __name__ == "__main__":
    unittest.main()
