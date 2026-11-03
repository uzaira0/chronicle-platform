#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p "$HOME/tmp"
sheet_tmp=$(mktemp -d -p "$HOME/tmp" i18n-sheet-test.XXXXXX)
trap 'rm -rf "$sheet_tmp"' EXIT

sources=(
  chronicle/app/src/main/res/values/strings.xml
  chronicle/app/src/main/res/values/consent_copy.xml
  chronicle/app/src/googleServices/res/values/strings.xml
  chronicle/app/src/googleServices/res/values/consent_copy.xml
  chronicle-web/src/modern/i18n/en/translation.json
  chronicle-web/src/modern/i18n/es/translation.json
  chronicle-server/src/main/resources/messages.properties
  chronicle-server/src/main/resources/messages_es.properties
)
for source in "${sources[@]}"; do
  mkdir -p "$sheet_tmp/$(dirname "$source")"
  cp "$source" "$sheet_tmp/$source"
done

# An unchanged export/import must leave the server table byte-identical.
python3 scripts/i18n-sheet.py export --root "$sheet_tmp" --lang es --out "$sheet_tmp/sheet.xlsx"
python3 scripts/i18n-sheet.py import --root "$sheet_tmp" --lang es --in "$sheet_tmp/sheet.xlsx" >/dev/null
cmp chronicle-server/src/main/resources/messages_es.properties \
  "$sheet_tmp/chronicle-server/src/main/resources/messages_es.properties"
echo "PASS: unchanged round trip keeps messages_es.properties byte-identical"
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

outputs=(
  "$sheet_tmp/chronicle/app/src/main/res/values-es/strings.xml"
  "$sheet_tmp/chronicle/app/src/main/res/values-es/consent_copy.xml"
  "$sheet_tmp/chronicle/app/src/googleServices/res/values-es/strings.xml"
  "$sheet_tmp/chronicle/app/src/googleServices/res/values-es/consent_copy.xml"
  "$sheet_tmp/chronicle-web/src/modern/i18n/es/translation.json"
  "$sheet_tmp/chronicle-server/src/main/resources/messages_es.properties"
)
sha256sum "${outputs[@]}" > "$sheet_tmp/before.sha256"
if python3 scripts/i18n-sheet.py import --root "$sheet_tmp" --lang es --in "$sheet_tmp/sheet.xlsx"; then
  echo "FAIL: import accepted a missing placeholder" >&2
  exit 1
fi
sha256sum "${outputs[@]}" > "$sheet_tmp/after.sha256"
cmp "$sheet_tmp/before.sha256" "$sheet_tmp/after.sha256"
echo "PASS: invalid placeholder rejected and all six output checksums unchanged"
