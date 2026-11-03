#!/usr/bin/env python3
"""Find StudySetting and reloadable configuration properties with no production reader."""

import argparse
import tempfile
import json
from pathlib import Path
import re
import sys
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def ast_nodes(root, language, rule, paths):
    config = {'id': 'setting-readers', 'language': language, 'rule': rule}
    result = subprocess.run(['ast-grep', 'scan', '--inline-rules', json.dumps(config), '--json=compact',
                             '--globs', '!**/*.generated.ts', *map(str, paths)],
                            cwd=root, text=True, capture_output=True, timeout=300)
    if result.returncode not in (0, 1):
        result.check_returncode()
    return json.loads(result.stdout)


def unread_settings(root):
    setting_class = {'kind': 'class_declaration', 'any': [
        {'regex': r'^[^{]*\)\s*:\s*StudySetting\b'},
        {'regex': r'^[^{]*@ReloadableConfiguration\b'},
    ], 'stopBy': 'end'}
    declaration = {'all': [{'kind': 'class_parameter'}, {'inside': setting_class}]}
    properties = [(node['file'], match[1]) for node in ast_nodes(root, 'Kotlin', declaration,
                  [root / 'chronicle-models/src/main/kotlin', root / 'chronicle-server/src/main'])
                  if (match := re.search(r'\b(?:val|var)\s+(\w+)', node['text']))]
    readers = set()
    sources = {'Kotlin': (['navigation_expression', 'callable_reference'],
                          ['chronicle-server/src/main', 'chronicle/app/src/main', 'chronicle-models/src/main/kotlin']),
               'TypeScript': (['member_expression', 'shorthand_property_identifier_pattern'], ['chronicle-web/src/modern']),
               'Tsx': (['member_expression', 'shorthand_property_identifier_pattern'], ['chronicle-web/src/modern']),
               'Java': (['field_access', 'method_invocation'], ['chronicle-server/src/main', 'chronicle/app/src/main'])}
    for language, (kinds, paths) in sources.items():
        nodes = ast_nodes(root, language, {'any': [{'kind': kind} for kind in kinds]},
                          [root / path for path in paths])
        for node in nodes:
            match = re.search(r'(\w+)\s*(?:\(\))?$', node['text'])
            if match:
                name = match[1]
                readers.add(name)
                if name.startswith('get') and len(name) > 3:
                    readers.add(name[3].lower() + name[4:])
    # Model methods also read their own properties without a receiver, including string interpolation.
    references = {'all': [{'any': [{'kind': 'simple_identifier'}, {'kind': 'interpolated_identifier'}]},
                          {'inside': {'kind': 'function_body', 'stopBy': 'end'}},
                          {'inside': setting_class}]}
    readers.update(node['text'] for node in ast_nodes(root, 'Kotlin', references,
                   [root / 'chronicle-models/src/main/kotlin', root / 'chronicle-server/src/main']))
    return [(path, name) for path, name in properties if name not in readers]


def self_test():
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        for directory in ('chronicle-models/src/main/kotlin', 'chronicle-server/src/main',
                          'chronicle/app/src/main', 'chronicle-web/src/modern'):
            (root / directory).mkdir(parents=True)
        model = root / 'chronicle-models/src/main/kotlin/DisplaySetting.kt'
        model.write_text("""class DisplaySetting(val labFriendlyName: String, val studyFriendlyName: String) : StudySetting {
    fun label() = labFriendlyName + this.studyFriendlyName
}
""")
        # Bare self-references are also real readers in model implementations.
        assert not unread_settings(root), 'Model implementations must count as readers'
        model.write_text('''class DisplaySetting(val studyFriendlyName: String) : StudySetting {
    fun label() = "You've been invited to $studyFriendlyName."
}''')
        assert not unread_settings(root), 'Model string interpolation must count as a reader'
        model.write_text('class DisplaySetting(val studyFriendlyName: String) : StudySetting {}')
        assert len(unread_settings(root)) == 1, 'An unused constructor property must fail'
        model.write_text('class DisplaySetting(val studyFriendlyName: String) : StudySetting { fun name() = studyFriendlyName }')
        configuration = root / 'chronicle-server/src/main/UnusedConfiguration.kt'
        configuration.write_text('@ReloadableConfiguration(uri = "unused.yaml")\ndata class UnusedConfiguration(val obsoleteOption: String)')
        assert any(name == 'obsoleteOption' for _, name in unread_settings(root)), 'Reloadable configuration fields need readers too'
        configuration.write_text('@ReloadableConfiguration(uri = "unused.yaml")\ndata class UnusedConfiguration(val activeOption: String)\nfun read(configuration: UnusedConfiguration) = configuration.activeOption')
        assert not unread_settings(root), 'Consumed reloadable configuration fields must pass'
    print('PASS setting reader model and unused-property fixtures')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        sys.exit(0)
    unread = unread_settings(ROOT)
    if unread:
        sys.exit('\n'.join(f'Unread setting: {Path(path).relative_to(ROOT)}: {name}' for path, name in unread))
    print('Every StudySetting and reloadable configuration property has a production reader')
