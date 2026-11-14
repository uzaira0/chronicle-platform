"""Every English string an Android build variant shows has the Spanish that build would show.

Android merges a variant's resources from its source sets, lowest priority first: main, the
product flavor (with any extra `res.srcDir` it declares in chronicle/app/build.gradle, such as
src/googleServices/res for research and open), the build type, then the flavor+build-type set.
For each string the highest-priority `values` folder supplies the English and the
highest-priority `values-es` folder the Spanish. The Spanish is missing when no `values-es`
defines the name, and wrong when it comes from a lower-priority source set than the English:
it then translates English this variant overrides (a flavor's own privacy policy, say).

The model here is deliberately independent of scripts/i18n-sheet.py; the second test checks
that `i18n-sheet.py check` reports the same two failures."""

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "chronicle/app"
SHEET = ROOT / "scripts/i18n-sheet.py"
RESOURCE_TAGS = {"string", "string-array", "plurals"}


def block_children(text, header):
    """Names of the `name { ... }` blocks directly inside the Groovy block `header { ... }`."""
    start = text.index(header + " {") + len(header) + 2
    depth, names = 1, []
    for match in re.finditer(r"(\w+)\s*\{|\{|\}", text[start:]):
        if match[0] == "}":
            depth -= 1
            if depth == 0:
                return names
        else:
            if depth == 1 and match[1]:
                names.append(match[1])
            depth += 1
    raise ValueError(f"unterminated {header} block")


def variants(app):
    gradle = (app / "build.gradle").read_text(encoding="utf-8")
    flavors = block_children(gradle, "productFlavors")
    build_types = block_children(gradle, "buildTypes")
    extra = {}
    res_dirs = re.findall(r"^\s*(\w+)\.res\.srcDirs?\s*\(?\s*['\"]([^'\"]+)['\"]", gradle, re.MULTILINE)
    for source_set, folder in res_dirs:
        extra.setdefault(source_set, []).append(app / folder)
    for flavor in flavors:
        for build_type in build_types:
            names = ("main", flavor, build_type, flavor + build_type[0].upper() + build_type[1:])
            yield f"{flavor}/{build_type}", [[app / "src" / name / "res", *extra.get(name, [])] for name in names]


def translatable(folder):
    found = {}
    for path in sorted(folder.glob("*.xml")) if folder.is_dir() else []:
        for element in ET.parse(path).getroot():
            if element.tag in RESOURCE_TAGS and element.get("translatable") != "false":
                found[element.get("name")] = path
    return found


def coverage_failures(app, lang="es"):
    failures = set()
    for variant, source_sets in variants(app):
        english, translated = {}, {}
        for priority, folders in enumerate(source_sets):
            for res in folders:
                for name, path in translatable(res / "values").items():
                    english[name] = (priority, path)
                for name, path in translatable(res / f"values-{lang}").items():
                    translated[name] = (priority, path)
        for name, (priority, path) in english.items():
            source = path.relative_to(app.parent.parent).as_posix()
            if name not in translated:
                failures.add(("untranslated", source, name))
            elif translated[name][0] < priority:
                failures.add(("shadowed", source, name))
    return failures


class I18nFlavorCoverageTest(unittest.TestCase):
    def test_every_variant_shows_spanish_for_every_english_string_it_shows(self):
        failures = sorted(coverage_failures(APP))
        self.assertEqual([], failures, "\n".join(" ".join(failure) for failure in failures))

    def test_check_reports_flavor_strings_without_their_own_spanish(self):
        scratch = ROOT / "build/operator-test-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            for name in ("chronicle/app/build.gradle", "chronicle/app/src",
                         "chronicle-web/src/modern/i18n", "chronicle-server/src/main/resources",
                         "docs/i18n-source-es.tsv"):
                source, target = ROOT / name, root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                if source.is_dir():
                    shutil.copytree(source, target, ignore=shutil.ignore_patterns("java", "kotlin", "assets"))
                else:
                    shutil.copyfile(source, target)

            def check():
                return subprocess.run([sys.executable, str(SHEET), "--root", str(root), "check", "--lang", "es"],
                                      capture_output=True, text=True, check=False)

            clean = check()
            self.assertEqual(0, clean.returncode, clean.stdout + clean.stderr)

            research_es = root / "chronicle/app/src/research/res/values-es/strings.xml"
            text = research_es.read_text(encoding="utf-8")
            research_es.write_text(re.sub(r'\s*<string name="accessibility_disclosure_title">.*?</string>', "",
                                          text, flags=re.DOTALL), encoding="utf-8")
            (root / "chronicle/app/src/amazon/res/values-es/strings.xml").unlink()
            self.assertEqual(
                {("untranslated", "chronicle/app/src/research/res/values/strings.xml", "accessibility_disclosure_title"),
                 ("shadowed", "chronicle/app/src/amazon/res/values/strings.xml", "platform_privacy_policy_full")},
                coverage_failures(root / "chronicle/app"))
            result = check()
            self.assertEqual(1, result.returncode, result.stdout)
            self.assertIn("untranslated: chronicle/app/src/research/res/values/strings.xml "
                          "accessibility_disclosure_title", result.stdout)
            self.assertIn("shadowed: chronicle/app/src/amazon/res/values/strings.xml "
                          "platform_privacy_policy_full", result.stdout)


if __name__ == "__main__":
    unittest.main()
