"""Derive disposable authorization-probe inputs from the actual OpenAPI contract."""
from __future__ import annotations

import base64
import json
import re


class UnsupportedSchema(ValueError):
    """The contract or seeded fixture cannot supply a valid request."""


_MISSING = object()


def request_inputs(document, path, method, fixtures):
    def fail(location, reason):
        raise UnsupportedSchema(f"{method} {path}: {location}: {reason}")

    def resolve(schema, depth=0):
        if depth > 16 or not isinstance(schema, dict):
            fail('schema', 'unsupported or recursive schema')
        if '$ref' in schema:
            reference = schema['$ref']
            if not reference.startswith('#/'):
                fail('schema', 'external reference is unsupported')
            node = document
            try:
                for token in reference[2:].split('/'):
                    node = node[token.replace('~1', '/').replace('~0', '~')]
            except (KeyError, TypeError):
                fail('schema', 'unresolved reference')
            schema = resolve(node, depth + 1) | {key: value for key, value in schema.items() if key != '$ref'}
        merged = {key: value for key, value in schema.items() if key != 'allOf'}
        for part in schema.get('allOf', []):
            for key, value in resolve(part, depth + 1).items():
                if key == 'properties':
                    merged[key] = value | merged.get(key, {})
                elif key == 'required':
                    merged[key] = list(dict.fromkeys(merged.get(key, []) + value))
                else:
                    merged.setdefault(key, value)
        return merged

    def sample(schema, location, supplied=_MISSING, depth=0, seeded=False):
        if depth > 16:
            fail(location, 'recursive request input')
        schema = resolve(schema)
        for union in ('oneOf', 'anyOf'):
            if union in schema:
                for variant in schema[union]:
                    try:
                        return sample(variant, location, supplied, depth + 1, seeded)
                    except UnsupportedSchema:
                        continue
                fail(location, 'no supported union alternative')
        if not seeded:
            binding = fixtures.get(location, fixtures.get(location.rsplit('.', 1)[-1], _MISSING))
            if binding is not _MISSING:
                supplied, seeded = binding, True
        if not seeded and schema.get('format') == 'uuid':
            fail(location, 'a seeded uuid fixture is required')
        value = supplied
        if value is _MISSING:
            for key in ('example', 'default'):
                if key in schema:
                    value = schema[key]
                    break
        if value is _MISSING and schema.get('enum'):
            value = schema['enum'][0]
        if value is _MISSING and schema.get('nullable'):
            value = None
        if value is None:
            if schema.get('nullable') or schema.get('type') == 'null':
                return None
            fail(location, 'null fixture is not permitted')
        kind = schema.get('type', 'object' if 'properties' in schema or 'additionalProperties' in schema else None)
        if kind == 'object':
            if value is not _MISSING and not isinstance(value, dict):
                fail(location, 'object fixture required')
            properties = schema.get('properties', {})
            required = set(schema.get('required', []))
            if required - properties.keys():
                fail(location, 'required property has no declared schema')
            supplied_object = {} if value is _MISSING else value
            if schema.get('additionalProperties') is False and supplied_object.keys() - properties.keys():
                fail(location, 'fixture has undeclared properties')
            output = dict(supplied_object)
            additional = schema.get('additionalProperties')
            if isinstance(additional, dict):
                for name in supplied_object.keys() - properties.keys():
                    output[name] = sample(additional, f'{location}.{name}', supplied_object[name], depth + 1, seeded)
            for name, field in properties.items():
                if name in supplied_object or name in required and not resolve(field).get('readOnly'):
                    output[name] = sample(field, f'{location}.{name}', supplied_object.get(name, _MISSING), depth + 1, seeded and name in supplied_object)
            if not schema.get('minProperties', 0) <= len(output) <= schema.get('maxProperties', 10000):
                fail(location, 'a seeded map fixture is required')
            return output
        if kind == 'array':
            minimum = schema.get('minItems', 0)
            if minimum > 128:
                fail(location, 'required array exceeds the probe input budget')
            if value is _MISSING:
                count = min(max(minimum, 1), schema.get('maxItems', 128))
                value = [sample(schema.get('items', {}), location + '[]', depth=depth + 1) for _ in range(count)]
            elif not isinstance(value, list):
                value = [value]
            if not minimum <= len(value) <= schema.get('maxItems', 128):
                fail(location, 'array fixture violates item bounds')
            value = [sample(schema.get('items', {}), location + '[]', item, depth + 1, seeded) for item in value]
            if schema.get('uniqueItems') and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
                fail(location, 'distinct seeded array values are required')
            return value
        if kind == 'string':
            if value is _MISSING:
                formats = {'date': '2026-01-01', 'date-time': '2026-01-01T00:00:00Z',
                           'email': 'probe@example.invalid', 'uri': 'https://example.invalid/probe',
                           'byte': base64.b64encode(b'probe').decode()}
                format_name = schema.get('format')
                if format_name and format_name not in formats:
                    fail(location, f'a seeded {format_name} fixture is required')
                minimum = max(schema.get('minLength', 0), schema.get('x-minLengthUtf16', 0))
                if minimum > 4096:
                    fail(location, 'required text exceeds the probe input budget')
                maximum = min(schema.get('maxLength', 4096), schema.get('x-maxLengthUtf16', 4096))
                length = min(max(5, minimum), maximum)
                value = formats[format_name] if format_name else ('probe' * ((length + 4) // 5))[:length]
            if not isinstance(value, str) or not schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', 4096):
                fail(location, 'string fixture violates length/type constraints')
            utf16_units = len(value.encode('utf-16-le', errors='surrogatepass')) // 2
            if not schema.get('x-minLengthUtf16', 0) <= utf16_units <= schema.get('x-maxLengthUtf16', 2**31 - 1):
                fail(location, 'string fixture violates UTF-16 length constraints')
            try:
                if 'pattern' in schema and re.search(schema['pattern'], value) is None:
                    fail(location, 'a fixture matching the declared pattern is required')
            except re.error:
                fail(location, 'unsupported pattern')
        elif kind in ('integer', 'number'):
            if value is _MISSING:
                value = schema.get('minimum', 0) + (1 if schema.get('exclusiveMinimum') else 0)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or kind == 'integer' and not isinstance(value, int):
                fail(location, 'numeric fixture required')
            if value < schema.get('minimum', float('-inf')) or value > schema.get('maximum', float('inf')):
                fail(location, 'numeric fixture violates bounds')
        elif kind == 'boolean':
            if value is _MISSING:
                value = False
            if not isinstance(value, bool):
                fail(location, 'boolean fixture required')
        else:
            fail(location, 'unsupported schema type')
        if 'enum' in schema and value not in schema['enum']:
            fail(location, 'fixture is outside the declared enum')
        return value

    def canonical(value):
        value = re.sub(r'^/v3(?=/|$)', '', value.removeprefix('/chronicle'))
        return re.sub(r'\{[^}]+\}', '{}', value).rstrip('/')

    def example(node):
        if 'example' in node:
            return node['example']
        for candidate in node.get('examples', {}).values():
            candidate = resolve(candidate)
            if 'value' in candidate:
                return candidate['value']
        return _MISSING
    candidates = [(template, operations) for template, operations in document.get('paths', {}).items()
                  if canonical(template) == canonical(path)]
    operation = next((operations[method.lower()] for _, operations in candidates if method.lower() in operations), None)
    if operation is None:
        fail('operation', 'published operation is missing')
    for name in re.findall(r'\{([^}]+)\}', path):
        if name not in fixtures:
            fail(name, 'seeded path fixture is required')
    path_item = candidates[0][1]
    result = {'query': [], 'headers': {}}
    parameters = { (resolve(parameter)['in'], resolve(parameter)['name']): resolve(parameter)
                  for parameter in path_item.get('parameters', []) + operation.get('parameters', []) }
    for (where, name), parameter in parameters.items():
        if where == 'path':
            continue
        overrides = fixtures.get('headers' if where == 'header' else 'query', {})
        supplied = next((value for key, value in overrides.items() if key.lower() == name.lower()), fixtures.get(name, _MISSING))
        if not parameter.get('required') and supplied is _MISSING:
            continue
        if where == 'header' and supplied is _MISSING:
            fail(name, 'an exact seeded header fixture is required')
        value = sample(parameter.get('schema', {}), name, example(parameter) if supplied is _MISSING else supplied, seeded=supplied is not _MISSING)
        if value is None:
            fail(name, 'null parameter serialization is unsupported')
        if where == 'query':
            if isinstance(value, dict) or parameter.get('style', 'form') != 'form':
                fail(name, 'unsupported query serialization')
            if isinstance(value, list) and not parameter.get('explode', True):
                value = ','.join(str(item) for item in value)
            values = value if isinstance(value, list) else [value]
            result['query'].extend((name, str(item).lower() if isinstance(item, bool) else str(item)) for item in values)
        elif where == 'header':
            result['headers'][name] = str(value)
        else:
            fail(name, 'unsupported parameter location')
    if 'requestBody' in operation:
        body = resolve(operation['requestBody'])
        content = body.get('content', {})
        media = next((name for name in ('application/json', 'application/x-www-form-urlencoded') if name in content), None)
        if media is None:
            fail('body', 'unsupported request media type')
        selected = content[media]
        value = fixtures.get('body', example(selected))
        result['json' if media == 'application/json' else 'form'] = sample(selected.get('schema', {}), 'body', value, seeded='body' in fixtures)
    if len(json.dumps(result)) > 262144:
        fail('body', 'request exceeds the probe input budget')
    return result
