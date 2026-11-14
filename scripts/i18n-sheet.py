#!/usr/bin/env python3
"""Exchange Chronicle's Android, web and server translations with a human-filled XLSX, and track
which English text each translation was made from.

`docs/i18n-source-<lang>.tsv` records, for every translated line, a hash of the English it
translates. `check` fails when the English has changed since (the translation is stale) or a
translated line has no record; `stamp` records the current English for lines a person has
reviewed; `import` stamps the rows whose translation it changes.

Android tables come from every source set some build variant merges (main, each product flavor
and its extra `res.srcDir` folders, each build type), read from chronicle/app/build.gradle. `check`
also fails when a variant would show a string's English to a user of the language, or a
translation made for other English (a flavor overriding main's English while only main has the
translation)."""

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from copy import deepcopy
from pathlib import Path

APP = Path("chronicle/app")
# Workbook surface per source set folder; any other folder X is "android-X". main and
# googleServices keep the names earlier workbooks and docs/i18n-provenance-*.tsv use.
ANDROID_SURFACES = {"main": "android-play", "googleServices": "android-research",
                    "research": "android-research-flavor"}
WEB = Path("chronicle-web/src/modern/i18n/en/translation.json")
SERVER = Path("chronicle-server/src/main/resources/messages.properties")
HEADERS = ("surface", "file", "key", "english", "spanish", "notes")
TOKENS = re.compile(r"%%|%(?:\d+\$)?[sd]|\{\{[^{}]+\}\}|\{\d+\}")
STAMP_HEADER = ("file", "key", "english_sha256")
STALE_NOTE = "English changed since this was translated"


def placeholders(text):
    return set(TOKENS.findall(text)) - {"%%"}


def android_text(element):
    return re.sub(r"\\(['\"])", r"\1", "".join(element.itertext()))


def resources(tree):
    return [element for element in tree
            if element.tag in {"string", "string-array", "plurals"}
            and element.get("translatable") != "false"]


def items(element):
    name = element.attrib["name"]
    if element.tag == "string":
        return [(name, element)]
    return [(f"{name}[{item.get('quantity') if element.tag == 'plurals' else index}]", item)
            for index, item in enumerate(element.findall("item"))]


def gradle_children(text, header):
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
    raise ValueError(f"{APP / 'build.gradle'}: unterminated {header} block")


def android_variants(root):
    """Every build variant's resource folders, one list per source set from lowest to highest
    merge priority (main, flavor, build type, flavor+build type), read from the app's
    build.gradle: product flavors, build types and extra `res.srcDir` folders."""
    gradle = (root / APP / "build.gradle").read_text(encoding="utf-8")
    extra = {}
    res_dirs = re.findall(r"^\s*(\w+)\.res\.srcDirs?\s*\(?\s*['\"]([^'\"]+)['\"]", gradle, re.MULTILINE)
    for source_set, folder in res_dirs:
        extra.setdefault(source_set, []).append(APP / folder)
    variants = {}
    for flavor in gradle_children(gradle, "productFlavors"):
        for build_type in gradle_children(gradle, "buildTypes"):
            names = ("main", flavor, build_type, flavor + build_type[0].upper() + build_type[1:])
            variants[f"{flavor}{build_type[0].upper()}{build_type[1:]}"] = [
                [APP / "src" / name / "res", *extra.get(name, [])] for name in names]
    return variants


def android_res_folders(root):
    """Every existing res folder some variant merges, main first."""
    folders = []
    for source_sets in android_variants(root).values():
        for res in (res for folders_of_set in source_sets for res in folders_of_set):
            if res not in folders and (root / res).is_dir():
                folders.append(res)
    return folders


def android_files(root):
    """(surface, English file) for every `values/*.xml` holding translatable strings."""
    files = []
    for res in android_res_folders(root):
        for path in sorted((root / res / "values").glob("*.xml")):
            if resources(ET.parse(path).getroot()):
                files.append((ANDROID_SURFACES.get(res.parent.name, f"android-{res.parent.name}"),
                              path.relative_to(root)))
    return files


def android_coverage(root, lang):
    """(untranslated, shadowed) English lines, as (English file, resource name, variants), that
    some variant shows to `lang` users in English (no `values-<lang>` defines the name) or in a
    translation of other English (the `values-<lang>` that wins comes from a lower-priority
    source set than the English, e.g. main's Spanish under a flavor's own English text)."""
    found = {"untranslated": {}, "shadowed": {}}
    for variant, source_sets in android_variants(root).items():
        english, translated = {}, {}
        for priority, folders in enumerate(source_sets):
            for res in folders:
                for folder, table in ((res / "values", english), (res / f"values-{lang}", translated)):
                    for path in sorted((root / folder).glob("*.xml")):
                        for element in resources(ET.parse(path).getroot()):
                            table[element.get("name")] = (priority, path.relative_to(root).as_posix())
        for name, (priority, path) in english.items():
            kind = ("untranslated" if name not in translated
                    else "shadowed" if translated[name][0] < priority else None)
            if kind:
                found[kind].setdefault((path, name), []).append(variant)
    return tuple(sorted((*line, variants) for line, variants in found[kind].items())
                 for kind in ("untranslated", "shadowed"))


def flatten(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from flatten(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from flatten(child, (*path, index))
    elif isinstance(value, str):
        yield ".".join(map(str, path)), value, path


def target_path(path, lang):
    if path == WEB:
        return WEB.parent.parent / lang / WEB.name
    if path == SERVER:
        return SERVER.with_name(f"messages_{lang.replace('-r', '_')}.properties")
    return path.parent.parent / f"values-{lang}" / path.name


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_properties(path):
    return parse_properties(path.read_text(encoding="utf-8"), path)


def parse_properties(text, path):
    """The `key=value` lines of a Java message table. MessageFormat's doubled apostrophe on a
    `{0}` line is shown to translators as a single one and restored by `properties_line`."""
    entries = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        if line.endswith("\\") or "\\u" in line or "=" not in line:
            raise ValueError(f"{path}: unsupported properties line: {line}")
        key, value = line.split("=", 1)
        value = re.sub(r"\\(.)", lambda match: {"n": "\n", "t": "\t"}.get(match[1], match[1]), value.lstrip())
        entries[key.strip()] = value.replace("''", "'") if placeholders(value) else value
    return entries


def properties_line(key, value):
    if placeholders(value):
        value = value.replace("'", "''")
    value = value.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")
    return f"{key}={value}"


def catalog(root, lang):
    rows = {}
    trees = {}
    for surface, path in android_files(root):
        tree = ET.parse(root / path).getroot()
        trees[path] = tree
        translated = root / target_path(path, lang)
        existing = {}
        if translated.exists():
            existing = {key: android_text(item)
                        for element in resources(ET.parse(translated).getroot())
                        for key, item in items(element)}
        for element in resources(tree):
            for key, item in items(element):
                if item.get("translatable") != "false":
                    rows[(surface, path.as_posix(), key)] = (android_text(item), existing.get(key, ""))
    english = read_json(root / WEB)
    translated = root / target_path(WEB, lang)
    existing = {key: value for key, value, _ in flatten(read_json(translated))} if translated.exists() else {}
    for key, value, _ in flatten(english):
        rows[("web", WEB.as_posix(), key)] = (value, existing.get(key, ""))
    translated = root / target_path(SERVER, lang)
    existing = read_properties(translated) if translated.exists() else {}
    for key, value in read_properties(root / SERVER).items():
        rows[("server", SERVER.as_posix(), key)] = (value, existing.get(key, ""))
    return rows, trees, english


def android_entries(path):
    return {key: android_text(item)
            for element in resources(ET.parse(path).getroot())
            for key, item in items(element)
            if item.get("translatable") != "false"}


def versioned_android(root, lang):
    """Translated lines in API-qualified folders (`values-es-v35`), each paired with the English
    Android shows at that API level: the highest `values-vK` (K <= the folder's level) defining the
    key, else `values`. These are the Settings labels quoted from AOSP, not workbook rows."""
    def levels(res, prefix):
        return {int(match[1]): path for path in res.glob(f"{prefix}-v*")
                if (match := re.fullmatch(rf"{re.escape(prefix)}-v(\d+)", path.name))}

    lines = {}
    for res in android_res_folders(root):
        res = root / res
        english_levels = levels(res, "values")
        for level, folder in sorted(levels(res, f"values-{lang}").items()):
            english_folders = [english_levels[k] for k in sorted(english_levels, reverse=True) if k <= level]
            english_folders.append(res / "values")
            for translated_file in sorted(folder.glob("*.xml")):
                sources = [android_entries(path / translated_file.name) for path in english_folders
                           if (path / translated_file.name).exists()]
                for key, text in android_entries(translated_file).items():
                    english = next((source[key] for source in sources if key in source), None)
                    if english is not None:
                        lines[(translated_file.relative_to(root).as_posix(), key)] = (english, text)
    return lines


def translated_lines(root, lang):
    """Every translated line keyed by (translated file, key), with the English it translates."""
    rows, _, _ = catalog(root, lang)
    lines = {(target_path(Path(file), lang).as_posix(), key): (english, translated)
             for (_, file, key), (english, translated) in rows.items() if translated}
    lines.update(versioned_android(root, lang))
    return lines


def english_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def stamp_path(root, lang):
    return root / f"docs/i18n-source-{lang}.tsv"


def read_stamps(root, lang):
    path = stamp_path(root, lang)
    if not path.exists():
        return {}
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or tuple(lines[0].split("\t")) != STAMP_HEADER:
        raise ValueError(f"{path}: expected header {' '.join(STAMP_HEADER)}")
    stamps = {}
    for number, line in enumerate(lines[1:], 2):
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError(f"{path}:{number}: expected 3 tab-separated fields")
        stamps[(fields[0], fields[1])] = fields[2]
    return stamps


def write_stamps(root, lang, stamps):
    body = "".join(f"{file}\t{key}\t{digest}\n" for (file, key), digest in sorted(stamps.items()))
    stamp_path(root, lang).write_text("\t".join(STAMP_HEADER) + "\n" + body, encoding="utf-8")


def source_status(root, lang):
    """(lines, stamps, stale, unstamped, orphans): stale lines have a record of different English,
    unstamped ones have none, orphans are records for lines that no longer exist."""
    lines = translated_lines(root, lang)
    stamps = read_stamps(root, lang)
    stale = sorted(identity for identity, (english, _) in lines.items()
                   if identity in stamps and stamps[identity] != english_hash(english))
    unstamped = sorted(identity for identity in lines if identity not in stamps)
    orphans = sorted(identity for identity in stamps if identity not in lines)
    return lines, stamps, stale, unstamped, orphans


def check_sources(root, lang):
    lines, _, stale, unstamped, orphans = source_status(root, lang)
    for label, identities in (("stale", stale), ("unstamped", unstamped)):
        for file, key in identities:
            english, translated = lines[(file, key)]
            print(f"{label}: {file} {key}\n  English now: {english}\n  {lang} now:     {translated}")
    for file, key in orphans:
        print(f"orphan record: {file} {key} (the line no longer exists)")
    untranslated, shadowed = android_coverage(root, lang)
    for file, key, variants in untranslated:
        print(f"untranslated: {file} {key}\n  {', '.join(variants)} show this English to {lang} users")
    for file, key, variants in shadowed:
        print(f"shadowed: {file} {key}\n  {', '.join(variants)} show {lang} users a {lang} line made for "
              f"other English; add it to {target_path(Path(file), lang).as_posix()}")
    print(f"{len(lines)} translated lines: {len(stale)} stale, {len(unstamped)} unstamped, "
          f"{len(orphans)} orphan records; {len(untranslated)} untranslated and {len(shadowed)} "
          "shadowed Android lines")
    if untranslated or shadowed:
        print(f"Translate each untranslated or shadowed Android line into the {lang} folder of the source set "
              "that defines its English, then stamp it.")
    if stale or unstamped or orphans or untranslated or shadowed:
        print(f"Update each listed {lang} line (or confirm it still fits the English), then run\n"
              f"  python3 scripts/i18n-sheet.py stamp --lang {lang} KEY ...\n"
              "A translator workbook import stamps the rows whose translation it changes.")
        return 1
    return 0


def stamp_sources(root, lang, keys):
    """Record the current English for the named lines; drop records of lines that no longer exist."""
    lines, stamps, _, _, orphans = source_status(root, lang)
    chosen = set()
    for wanted in keys:
        file, _, key = wanted.rpartition(":")
        matches = [identity for identity in lines if identity[1] == key and file in ("", identity[0])]
        if len(matches) != 1:
            found = ", ".join(f"{f}:{k}" for f, k in matches) or "no translated line"
            raise ValueError(f"{wanted}: expected one translated line, found {found}; use FILE:KEY")
        chosen.add(matches[0])
    for identity in orphans:
        del stamps[identity]
    for identity in chosen:
        stamps[identity] = english_hash(lines[identity][0])
    write_stamps(root, lang, stamps)
    print(f"Stamped {len(chosen)} lines; removed {len(orphans)} orphan records.")


def export_sheet(root, lang, output):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font

    rows, _, _ = catalog(root, lang)
    stale = set(source_status(root, lang)[2])
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Strings"
    sheet.append(HEADERS)
    sheet.freeze_panes = "A2"
    for identity, (english, spanish) in rows.items():
        notes = sorted(placeholders(english))
        if r"\n" in english:
            notes.append(r"\n")
        notes.extend(re.findall(r"\$t\([^)]*\)", english))
        if (target_path(Path(identity[1]), lang).as_posix(), identity[2]) in stale:
            notes.insert(0, STALE_NOTE)
        sheet.append((*identity, english, spanish, ", ".join(notes)))
    for row in sheet:
        for cell in row:
            cell.data_type = "s"  # Strings beginning with '=' must stay text.
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            if cell.row == 1:
                cell.font = Font(bold=True)
    for column, width in zip("ABCDEF", (22, 58, 48, 80, 80, 32)):
        sheet.column_dimensions[column].width = width
    sheet.auto_filter.ref = sheet.dimensions
    output.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(output)
    workbook.close()
    for surface in dict.fromkeys(identity[0] for identity in rows):
        print(f"{surface}: {sum(identity[0] == surface for identity in rows)} rows")
    print(f"Exported {len(rows)} rows to {output}")


def read_sheet(source, rows):
    from openpyxl import load_workbook

    workbook = load_workbook(source, read_only=True, data_only=False)
    translations = {}
    rejected = []
    try:
        if "Strings" not in workbook.sheetnames:
            raise ValueError("Workbook has no Strings sheet")
        sheet = workbook["Strings"]
        if tuple(cell.value for cell in next(sheet.iter_rows(max_row=1, max_col=len(HEADERS)))) != HEADERS:
            raise ValueError(f"Expected columns: {', '.join(HEADERS)}")
        seen = set()
        for number, cells in enumerate(sheet.iter_rows(min_row=2, max_col=6), 2):
            surface, file, key, english, spanish, _ = (cell.value for cell in cells)
            if spanish is None or spanish == "":
                continue
            identity = (surface, file, key)
            reason = None
            if identity not in rows:
                reason = "unknown surface/file/key"
            elif identity in seen:
                reason = "duplicate row"
            elif english != rows[identity][0]:
                reason = "English differs from the current source; export again"
            elif not isinstance(spanish, str) or cells[4].data_type == "f":
                reason = "spanish must be text, not a number or formula"
            elif placeholders(spanish) != placeholders(english):
                reason = (f"placeholder mismatch: expected {sorted(placeholders(english))}, "
                          f"got {sorted(placeholders(spanish))}")
            elif r"\n" in english and r"\n" not in spanish:
                reason = r"missing literal \n"
            seen.add(identity)
            if reason:
                rejected.append(f"Row {number} ({key}) rejected: {reason}")
            else:
                translations[identity] = spanish
    finally:
        workbook.close()
    if rejected:
        raise ValueError("\n".join(rejected) + "\nImport aborted; no files written.")
    return translations


def merge_web(existing, english, translations, path=()):
    """Keep existing data, including JSON array positions."""
    if path in translations:
        return translations[path]
    if not any(key[:len(path)] == path for key in translations):
        return existing
    if isinstance(english, dict):
        result = dict(existing) if isinstance(existing, dict) else {}
        for key, child in english.items():
            child_path = (*path, key)
            if any(target[:len(child_path)] == child_path for target in translations):
                result[key] = merge_web(result.get(key), child, translations, child_path)
        return result
    if isinstance(english, list):
        result = list(existing) if isinstance(existing, list) else []
        for index, child in enumerate(english):
            child_path = (*path, index)
            if any(target[:len(child_path)] == child_path for target in translations):
                # Missing earlier indices fall back to English, keeping array positions.
                while len(result) <= index:
                    result.append(deepcopy(english[len(result)]))
                result[index] = merge_web(result[index], child, translations, child_path)
        return result
    return existing


def english_order(value, english):
    if isinstance(value, dict) and isinstance(english, dict):
        keys = [key for key in english if key in value]
        keys.extend(key for key in value if key not in english)
        return {key: english_order(value[key], english.get(key)) for key in keys}
    if isinstance(value, list) and isinstance(english, list):
        return [english_order(child, english[index] if index < len(english) else None)
                for index, child in enumerate(value)]
    return value


def web_json(value, indent=0, column=0):
    """JSON laid out as chronicle-web's Biome formatter writes it (2-space indent, 120 columns):
    objects one key per line, an array of plain values on one line when it fits."""
    pad = "  " * indent
    inner = "  " * (indent + 1)
    if isinstance(value, dict) and value:
        fields = []
        for key, child in value.items():
            prefix = inner + json.dumps(key, ensure_ascii=False) + ": "
            fields.append(prefix + web_json(child, indent + 1, len(prefix)))
        return "{\n" + ",\n".join(fields) + "\n" + pad + "}"
    if isinstance(value, list) and value:
        line = "[" + ", ".join(json.dumps(child, ensure_ascii=False) for child in value) + "]"
        if not any(isinstance(child, (dict, list)) for child in value) and column + len(line) + 1 <= 120:
            return line
        return "[\n" + ",\n".join(inner + web_json(child, indent + 1, len(inner)) for child in value) + "\n" + pad + "]"
    return json.dumps(value, ensure_ascii=False)


def same_entries(path, content):
    """True when `content` holds exactly the entries already in `path`, so rewriting would only
    reorder or reformat it."""
    if not path.exists():
        return False
    if path.suffix == ".json":
        return read_json(path) == json.loads(content)
    if path.suffix == ".xml":
        return android_entries(path) == {key: android_text(item)
                                         for element in resources(ET.fromstring(content))
                                         for key, item in items(element)}
    return read_properties(path) == parse_properties(content, path)


def import_sheet(root, lang, source):
    rows, trees, english = catalog(root, lang)
    translations = read_sheet(source, rows)
    outputs = {}
    for surface, path in android_files(root):
        output = ET.Element("resources")
        for element in resources(trees[path]):
            entries = items(element)
            values = [translations.get((surface, path.as_posix(), key)) for key, _ in entries]
            if not entries or any(value is None for value in values):
                if element.tag != "string":
                    print(f"Warning: omitted incomplete {element.tag} {path}:{element.get('name')}", file=sys.stderr)
                continue
            translated = ET.SubElement(output, element.tag, element.attrib)
            for (_, original), value in zip(entries, values):
                item = translated if element.tag == "string" else ET.SubElement(translated, "item", original.attrib)
                item.text = value.replace("'", r"\'").replace('"', r'\"')
        if not len(output) and not (root / target_path(path, lang)).exists():
            continue  # Nothing translated in this file yet: no empty values-<lang> table.
        ET.indent(output, space="    ")
        outputs[root / target_path(path, lang)] = ET.tostring(output, encoding="unicode", xml_declaration=True) + "\n"
    web_path = root / target_path(WEB, lang)
    existing = read_json(web_path) if web_path.exists() else {}
    web_translations = {path: translations[("web", WEB.as_posix(), key)]
                        for key, _, path in flatten(english)
                        if ("web", WEB.as_posix(), key) in translations}
    merged = english_order(merge_web(existing, english, web_translations), english)
    outputs[web_path] = web_json(merged) + "\n"
    server_path = root / target_path(SERVER, lang)
    server_lines = [properties_line(identity[2], translations[identity]) for identity in rows
                    if identity[0] == "server" and identity in translations]
    outputs[server_path] = (
        f"# Chronicle server message table for {lang}, written by scripts/i18n-sheet.py import.\n"
        "# Keys and {0} placeholders match messages.properties; a missing key falls back to English.\n"
        + "".join(f"{line}\n" for line in server_lines))
    stamps = read_stamps(root, lang)
    for path, content in outputs.items():
        if same_entries(path, content):
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"Wrote {path}")
    # A row whose text the translator changed was written against the English in the workbook,
    # which read_sheet checked is the current English. An unchanged row keeps its old record, so a
    # stale translation stays stale until someone edits it or confirms it with `stamp`.
    still_stale = []
    for identity, translated in translations.items():
        english, before = rows[identity]
        line = (target_path(Path(identity[1]), lang).as_posix(), identity[2])
        if translated != before:
            stamps[line] = english_hash(english)
        elif line in stamps and stamps[line] != english_hash(english):
            still_stale.append(line)
    # Import rewrites whole tables, so lines left empty in the workbook are gone; so are their records.
    remaining = translated_lines(root, lang)
    write_stamps(root, lang, {line: digest for line, digest in stamps.items() if line in remaining})
    print(f"Imported {len(translations)} filled rows (incomplete Android groups omitted).")
    for file, key in sorted(still_stale):
        print(f"Still stale (text unchanged): {file} {key}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default_root = Path(__file__).resolve().parent.parent
    parser.add_argument("--root", type=Path, default=default_root)
    commands = parser.add_subparsers(dest="command", required=True)
    for command, flag in (("export", "--out"), ("import", "--in"), ("check", None), ("stamp", None)):
        sub = commands.add_parser(command)
        sub.add_argument("--lang", required=True)
        sub.add_argument("--root", type=Path, default=argparse.SUPPRESS)
        if flag:
            sub.add_argument(flag, dest="sheet", type=Path, required=True)
        if command == "stamp":
            sub.add_argument("keys", nargs="+", metavar="[FILE:]KEY",
                             help="translated line whose English a person has reviewed")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z]{2,3}(?:-r[A-Z]{2})?", args.lang) or args.lang == "en":
        parser.error("--lang must be a non-English Android language qualifier, e.g. es or pt-rBR")
    try:
        if args.command == "export":
            export_sheet(args.root, args.lang, args.sheet)
        elif args.command == "import":
            import_sheet(args.root, args.lang, args.sheet)
        elif args.command == "check":
            sys.exit(check_sources(args.root, args.lang))
        else:
            stamp_sources(args.root, args.lang, args.keys)
    except (OSError, ValueError, ET.ParseError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
