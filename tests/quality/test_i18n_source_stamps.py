"""docs/i18n-source-es.tsv records the English each Spanish line translates; `i18n-sheet.py check`
fails when that English changes, and `stamp` records English a person has reviewed."""

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SHEET = ROOT / "scripts/i18n-sheet.py"
WEB_EN = "chronicle-web/src/modern/i18n/en/translation.json"
WEB_ES = "chronicle-web/src/modern/i18n/es/translation.json"
SERVER_ES = "chronicle-server/src/main/resources/messages_es.properties"
COPIED = [
    "chronicle/app/build.gradle",
    "chronicle/app/src/main/res",
    "chronicle/app/src/googleServices/res",
    "chronicle/app/src/research/res",
    "chronicle/app/src/amazon/res",
    "chronicle/app/src/debug/res",
    WEB_EN,
    WEB_ES,
    "chronicle-server/src/main/resources/messages.properties",
    SERVER_ES,
    "docs/i18n-source-es.tsv",
]


def run(root, *args):
    return subprocess.run([sys.executable, str(SHEET), "--root", str(root), *args],
                          capture_output=True, text=True, check=False)


class I18nSourceStampsTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / "build/operator-test-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=scratch)
        self.root = Path(self.directory.name)
        for name in COPIED:
            source, target = ROOT / name, self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                def resource_values_only(folder, names, res=source):
                    return [name for name in names if Path(folder) == res and not name.startswith("values")]
                shutil.copytree(source, target, ignore=resource_values_only)
            else:
                shutil.copyfile(source, target)

    def tearDown(self):
        self.directory.cleanup()

    def edit_web(self, name, change):
        path = self.root / name
        data = json.loads(path.read_text(encoding="utf-8"))
        change(data)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def test_committed_spanish_matches_the_recorded_english(self):
        result = run(ROOT, "check", "--lang", "es")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(" 0 stale, 0 unstamped, 0 orphan records", result.stdout)

    def test_changed_english_marks_the_spanish_line_stale_until_stamped(self):
        self.assertEqual(0, run(self.root, "check", "--lang", "es").returncode)

        def reword(data):
            data["common"]["try_again"] = "Retry now"
        self.edit_web(WEB_EN, reword)
        result = run(self.root, "check", "--lang", "es")
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn(f"stale: {WEB_ES} common.try_again", result.stdout)
        self.assertIn("English now: Retry now", result.stdout)
        self.assertIn(" 1 stale,", result.stdout)

        stamped = run(self.root, "stamp", "--lang", "es", "common.try_again")
        self.assertEqual(0, stamped.returncode, stamped.stdout + stamped.stderr)
        self.assertEqual(0, run(self.root, "check", "--lang", "es").returncode)

    def test_api_level_folders_follow_the_english_android_shows_at_that_level(self):
        # values-es-v35 and values-es-v36 both translate values-v35 (there is no values-v36).
        english = self.root / "chronicle/app/src/main/res/values-v35/strings.xml"
        text = english.read_text(encoding="utf-8")
        english.write_text(text.replace("App battery usage", "Battery use by app", 1), encoding="utf-8")
        result = run(self.root, "check", "--lang", "es")
        self.assertEqual(1, result.returncode, result.stdout)
        for folder in ("values-es-v35", "values-es-v36"):
            self.assertIn(f"stale: chronicle/app/src/main/res/{folder}/strings.xml battery_optimization_exemption",
                          result.stdout)

    def test_a_new_line_needs_a_record_and_a_removed_line_drops_its_record(self):
        self.edit_web(WEB_EN, lambda data: data["common"].update(new_label="New label"))
        self.edit_web(WEB_ES, lambda data: data["common"].update(new_label="Etiqueta nueva"))
        self.edit_web(WEB_ES, lambda data: data["common"].pop("try_again"))
        server = self.root / SERVER_ES
        lines = server.read_text(encoding="utf-8").splitlines()
        server.write_text("\n".join(line for line in lines if not line.startswith("error.generic=")) + "\n",
                          encoding="utf-8")
        result = run(self.root, "check", "--lang", "es")
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn(f"unstamped: {WEB_ES} common.new_label", result.stdout)
        self.assertIn(f"orphan record: {WEB_ES} common.try_again", result.stdout)
        self.assertIn(f"orphan record: {SERVER_ES} error.generic", result.stdout)

        stamped = run(self.root, "stamp", "--lang", "es", f"{WEB_ES}:common.new_label")
        self.assertEqual(0, stamped.returncode, stamped.stdout + stamped.stderr)
        self.assertIn("Stamped 1 lines; removed 2 orphan records.", stamped.stdout)
        self.assertEqual(0, run(self.root, "check", "--lang", "es").returncode)

    def test_import_writes_web_catalogs_in_the_layout_biome_enforces(self):
        # chronicle-web's `biome:check` formats these files; an import must not leave a reformatting diff.
        spec = importlib.util.spec_from_file_location("i18n_sheet", SHEET)
        sheet = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sheet)
        for name in (WEB_EN, WEB_ES):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertEqual(text, sheet.web_json(json.loads(text)) + "\n", name)

    def test_stamp_refuses_a_key_that_is_not_one_translated_line(self):
        result = run(self.root, "stamp", "--lang", "es", "no.such.key")
        self.assertEqual(1, result.returncode)
        self.assertIn("no translated line; use FILE:KEY", result.stderr)


if __name__ == "__main__":
    unittest.main()
