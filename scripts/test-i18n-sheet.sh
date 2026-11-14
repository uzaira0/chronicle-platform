#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p "$HOME/tmp"
sheet_tmp=$(mktemp -d -p "$HOME/tmp" i18n-sheet-test.XXXXXX)
trap 'rm -rf "$sheet_tmp"' EXIT

translated=(
  chronicle/app/src/main/res/values-es/strings.xml
  chronicle/app/src/main/res/values-es/consent_copy.xml
  chronicle/app/src/googleServices/res/values-es/strings.xml
  chronicle/app/src/googleServices/res/values-es/consent_copy.xml
  chronicle/app/src/research/res/values-es/strings.xml
  chronicle/app/src/research/res/values-es/platform_policy.xml
  chronicle/app/src/amazon/res/values-es/strings.xml
  chronicle/app/src/debug/res/values-es/strings.xml
  chronicle-web/src/modern/i18n/es/translation.json
  chronicle-server/src/main/resources/messages_es.properties
  docs/i18n-source-es.tsv
)
# build.gradle names the flavors, build types and extra res folders each variant merges.
sources=(
  "${translated[@]}"
  chronicle/app/build.gradle
  chronicle/app/src/research/res/values/strings.xml
  chronicle/app/src/research/res/values/platform_policy.xml
  chronicle/app/src/amazon/res/values/strings.xml
  chronicle/app/src/debug/res/values/strings.xml
  chronicle/app/src/main/res/values/strings.xml
  chronicle/app/src/main/res/values/consent_copy.xml
  chronicle/app/src/googleServices/res/values/strings.xml
  chronicle/app/src/googleServices/res/values/consent_copy.xml
  chronicle-web/src/modern/i18n/en/translation.json
  chronicle-server/src/main/resources/messages.properties
)
# API-level folders: check pairs values-es-vN with the English Android shows at level N.
for file in chronicle/app/src/main/res/values-v*/strings.xml chronicle/app/src/main/res/values-es-v*/strings.xml; do
  sources+=("$file")
done
for source in "${sources[@]}"; do
  mkdir -p "$sheet_tmp/$(dirname "$source")"
  cp "$source" "$sheet_tmp/$source"
done

# An unchanged export/import must leave every translated file and the English records byte-identical.
python3 scripts/i18n-sheet.py export --root "$sheet_tmp" --lang es --out "$sheet_tmp/sheet.xlsx"
python3 scripts/i18n-sheet.py import --root "$sheet_tmp" --lang es --in "$sheet_tmp/sheet.xlsx" >/dev/null
for file in "${translated[@]}"; do
  cmp "$file" "$sheet_tmp/$file"
done
python3 scripts/i18n-sheet.py check --root "$sheet_tmp" --lang es >/dev/null
echo "PASS: unchanged round trip keeps all ${#translated[@]} translated files byte-identical and check passes"
python3 - "$sheet_tmp" <<'PY'
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

from openpyxl import load_workbook

root = Path(sys.argv[1])
workbook = load_workbook(root / "sheet.xlsx")
sheet = workbook["Strings"]
assert tuple(cell.value for cell in sheet[1]) == (
    "surface", "file", "key", "english", "spanish", "notes",
)
assert sheet.max_row - 1 >= 1700, sheet.max_row - 1
print(f"PASS: export header and {sheet.max_row - 1} data rows")

android_file = "chronicle/app/src/main/res/values/strings.xml"
string_keys = {element.attrib["name"] for element in ET.parse(root / android_file).findall("string")}
tokens = re.compile(r"(%%|%(?:\d+\$)?[sd]|\{\{[^{}]+\}\}|\{\d+\}|\\n)")
selected = {}
for cells in sheet.iter_rows(min_row=2):
    surface, file, key, english, _, _ = (cell.value for cell in cells)
    cells[4].value = None
    kind = None
    if file == android_file and key in string_keys:
        if not tokens.search(english):
            kind = "plain"
        elif "%1$s" in english:
            kind = "android-placeholder"
    elif surface == "web" and "{{" in english:
        kind = "web-placeholder"
    elif surface == "server" and "{0}" in english:
        kind = "server-placeholder"
    if kind is None or kind in selected:
        continue
    # Reverse the text as a whole, treating placeholders and literal newlines as atoms.
    spanish = "".join(
        part if tokens.fullmatch(part) else part[::-1]
        for part in reversed(tokens.split(english))
    )
    assert spanish != english, key
    cells[4].value = spanish
    cells[4].data_type = "s"
    selected[kind] = {"row": cells[0].row, "file": file, "key": key, "spanish": spanish}

assert set(selected) == {"plain", "android-placeholder", "web-placeholder", "server-placeholder"}, selected
workbook.save(root / "sheet.xlsx")
workbook.close()
(root / "expected.json").write_text(json.dumps(selected), encoding="utf-8")
PY

python3 scripts/i18n-sheet.py import --root "$sheet_tmp" --lang es --in "$sheet_tmp/sheet.xlsx"
python3 - "$sheet_tmp" <<'PY'
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

from openpyxl import load_workbook

root = Path(sys.argv[1])
selected = json.loads((root / "expected.json").read_text(encoding="utf-8"))
for kind, expected in selected.items():
    if kind == "server-placeholder":
        path = root / "chronicle-server/src/main/resources/messages_es.properties"
        lines = dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines()
                     if line and not line.startswith("#"))
        actual = lines[expected["key"]].replace("''", "'")
    elif kind == "web-placeholder":
        path = root / "chronicle-web/src/modern/i18n/es/translation.json"
        actual = json.loads(path.read_text(encoding="utf-8"))
        for key in expected["key"].split("."):
            actual = actual[int(key)] if isinstance(actual, list) else actual[key]
    else:
        path = root / expected["file"].replace("/values/", "/values-es/")
        element = ET.parse(path).find(f"string[@name='{expected['key']}']")
        assert element is not None, expected["key"]
        actual = re.sub(r"\\(['\"])", r"\1", "".join(element.itertext()))
    assert actual == expected["spanish"], (kind, expected["key"], actual)
print("PASS: plain, Android placeholder, web interpolation and server MessageFormat values round-trip")

workbook = load_workbook(root / "sheet.xlsx")
sheet = workbook["Strings"]
bad = selected["android-placeholder"]
sheet.cell(bad["row"], 5).value = bad["spanish"].replace("%1$s", "")
# A valid changed row makes any premature write observable in the checksum check.
plain = selected["plain"]
sheet.cell(plain["row"], 5).value = plain["spanish"] + " changed"
workbook.save(root / "sheet.xlsx")
workbook.close()
PY

# The import recorded the English of the four rows it changed, so nothing is stale or unstamped.
# (check still fails: the workbook left every other Android line untranslated.)
check_out=$(python3 scripts/i18n-sheet.py check --root "$sheet_tmp" --lang es || true)
grep -q " 0 stale, 0 unstamped, 0 orphan records; [1-9][0-9]* untranslated" <<<"$check_out"
echo "PASS: import stamped the rows it changed"

outputs=(
  "$sheet_tmp/chronicle/app/src/main/res/values-es/strings.xml"
  "$sheet_tmp/chronicle/app/src/main/res/values-es/consent_copy.xml"
  "$sheet_tmp/chronicle/app/src/googleServices/res/values-es/strings.xml"
  "$sheet_tmp/chronicle/app/src/googleServices/res/values-es/consent_copy.xml"
  "$sheet_tmp/chronicle/app/src/research/res/values-es/strings.xml"
  "$sheet_tmp/chronicle/app/src/research/res/values-es/platform_policy.xml"
  "$sheet_tmp/chronicle/app/src/amazon/res/values-es/strings.xml"
  "$sheet_tmp/chronicle/app/src/debug/res/values-es/strings.xml"
  "$sheet_tmp/chronicle-web/src/modern/i18n/es/translation.json"
  "$sheet_tmp/chronicle-server/src/main/resources/messages_es.properties"
  "$sheet_tmp/docs/i18n-source-es.tsv"
)
sha256sum "${outputs[@]}" > "$sheet_tmp/before.sha256"
if python3 scripts/i18n-sheet.py import --root "$sheet_tmp" --lang es --in "$sheet_tmp/sheet.xlsx"; then
  echo "FAIL: import accepted a missing placeholder" >&2
  exit 1
fi
sha256sum "${outputs[@]}" > "$sheet_tmp/after.sha256"
cmp "$sheet_tmp/before.sha256" "$sheet_tmp/after.sha256"
echo "PASS: invalid placeholder rejected and all ${#outputs[@]} output checksums unchanged"

# Changed English makes its Spanish line stale: check fails and the workbook tells the translator.
python3 - "$sheet_tmp" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1]) / "chronicle-web/src/modern/i18n/en/translation.json"
english = json.loads(path.read_text(encoding="utf-8"))
english["common"]["try_again"] = "Retry now"
path.write_text(json.dumps(english, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
check_out=$(python3 scripts/i18n-sheet.py check --root "$sheet_tmp" --lang es || true)
if ! grep -q "^stale: chronicle-web/src/modern/i18n/es/translation.json common.try_again$" <<<"$check_out" \
    || ! grep -q " 1 stale," <<<"$check_out"; then
  echo "FAIL: check accepted a Spanish line whose English changed" >&2
  exit 1
fi
python3 scripts/i18n-sheet.py export --root "$sheet_tmp" --lang es --out "$sheet_tmp/stale.xlsx" >/dev/null
python3 - "$sheet_tmp" <<'PY'
from pathlib import Path
import sys

from openpyxl import load_workbook

workbook = load_workbook(Path(sys.argv[1]) / "stale.xlsx", read_only=True)
notes = {row[2]: row[5] or "" for row in workbook["Strings"].iter_rows(min_row=2, values_only=True)}
workbook.close()
assert notes["common.try_again"].startswith("English changed since this was translated"), notes["common.try_again"]
assert sum(note.startswith("English changed") for note in notes.values()) == 1
PY
echo "PASS: changed English fails check and is flagged in the exported workbook"
