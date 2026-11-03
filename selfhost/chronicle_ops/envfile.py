"""Literal deployment environment parsing, quoting and assignment updates."""

from pathlib import Path
import re
import shlex

from .common import require

assignment = re.compile(r"^(?:export\s+)?([A-Z][A-Z0-9_]*)=(.*)$")
environment_value = re.compile(r'''(?:'[^']*'|"[^"$`\\]*"|[A-Za-z0-9_@%+=:,./-]*)(?:\s+\#.*)?''')


def read_env(path):
    return parse_env_text(Path(path).read_text())


def parse_env_text(text):
    values = {}
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = assignment.fullmatch(line)
        require(match and match[1] not in values, f"invalid or duplicate environment assignment on line {number}")
        raw = match[2]
        require(environment_value.fullmatch(raw),
                f"unsupported environment value on line {number}; use a literal quoted value, not shell syntax")
        _require_single_token(match[1], raw)
        values[match[1]] = raw
    return values


def value(values, key, default=""):
    if key not in values:
        return default
    return _require_single_token(key, values[key])


def _require_single_token(key, raw):
    if raw.lstrip().startswith("#"):
        return ""
    tokens = shlex.split(raw, comments=True)
    require(len(tokens) <= 1, f"invalid environment value for {key}")
    return tokens[0] if tokens else ""


def quote_env(text):
    require(not any(character in text for character in "\r\n"), "environment value cannot contain a line break")
    if "'" not in text:
        return shlex.quote(text) if text else ""
    require(not any(character in text for character in '"$`\\'), "environment value cannot combine apostrophes with shell escapes or expansion")
    return '"' + text + '"'


def set_env_values(text, values, *, require_existing):
    replacements = {}
    for key, raw in values.items():
        require(assignment.fullmatch(key + '='), 'invalid environment key')
        replacements[key] = f'{key}={quote_env(raw)}'
    seen = set()
    lines = []
    for line in text.splitlines():
        match = assignment.fullmatch(line)
        if match and match[1] in replacements:
            key = match[1]
            require(key not in seen, f'duplicate environment key: {key}')
            seen.add(key)
            line = replacements[key]
        lines.append(line)
    missing = replacements.keys() - seen
    require(not require_existing or not missing, 'missing environment keys: ' + ', '.join(sorted(missing)))
    lines.extend(replacements[key] for key in replacements if key in missing)
    return '\n'.join(lines) + '\n'
