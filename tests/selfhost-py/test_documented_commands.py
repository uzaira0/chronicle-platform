"""Pass documented command examples through the shipped command validators."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import unittest
from unittest.mock import patch

from test_secret_generation import SelfhostSetupFixture

ROOT = Path(__file__).resolve().parents[2]


def concrete(argument):
    return (argument.replace('${TRUSTED_SHA256}', 'a' * 64).replace('STUDY_UUID', '00000000-0000-0000-0000-000000000001')
            .replace('OPERATION_UUID', '00000000-0000-0000-0000-000000000002'))


def documented_commands(document):
    for line in document.read_text().replace('\\\n', ' ').splitlines():
        for span in line.split('`'):
            tokens = shlex.shlex(span, posix=True, punctuation_chars=';&|')
            tokens.whitespace_split = True
            tokens.commenters = '#'
            if './chronicle ' not in span:
                continue
            words = list(tokens)
            for index, word in enumerate(words):
                if word != './chronicle':
                    continue
                command = []
                for argument in words[index + 1:]:
                    if argument in (';', '&&', '|', '||') or argument.startswith(('>', '2>')):
                        break
                    argument = concrete(argument)
                    if argument == '--trusted-sha256=...':
                        argument = '--trusted-sha256=' + 'a' * 64
                    command.append(argument)
                yield command


OPERATOR_DOCS = (ROOT / 'README.md', *sorted((ROOT / 'selfhost').rglob('*.md')),
                 ROOT / 'docs/PILOT-DATA.md')
# Guarded restore and the backup self-check own file/stdin replay, including psql's include command.
# Shell operators count outside quotes only, so quoted SQL such as `count(*) < 1` stays a query.
QUOTED = re.compile(r""""[^"\n]*"|'[^'\n]*'""")
SHELL_REPLAY = re.compile(r'[|<][^|\n]*\bpsql\b|\bpsql\b[^\n]*(?:<|\s--file(?:[=\s]|$)|\s-[^\s-]*f)|\bpg_restore\b')
QUOTED_REPLAY = re.compile(r"""\bpsql\b[^\n]*(?:\$\(|\s(?:-c|--command(?:=|\s))\s*["']?`)|"""
                           r'\\(?:ir?|include(?:_relative)?)\b')


def replays_dump(line):
    return bool(QUOTED_REPLAY.search(line) or SHELL_REPLAY.search(QUOTED.sub("''", line)))


def documented_lines(document):
    # Scan all Markdown so indentation, fence style and unformatted commands cannot hide replay.
    text = document.read_text().replace('\\\n', ' ')
    # A pipeline continues over a trailing comment and over comment-only lines.
    yield from re.sub(r'\|[ \t]*(?:#[^\n]*)?\n(?:[ \t]*#[^\n]*\n)*[ \t]*', '| ', text).splitlines()


class DocumentedCommandTests(unittest.TestCase):
    def validate(self, arguments):
        if arguments and arguments[0] in ('help', '-h', '--help'):
            # The launcher answers help before validate_command_arguments (selfhost/chronicle, "help"
            # branch), so run that entry; COMMAND in `./chronicle help COMMAND` stands for any command.
            return subprocess.run(['bash', str(ROOT / 'selfhost/chronicle'),
                                   *('update' if argument == 'COMMAND' else argument for argument in arguments)],
                                  env=dict(os.environ), capture_output=True, text=True, timeout=10)
        return subprocess.run(['bash', '-c', 'source "$1"; validate_command_arguments "${@:2}"; printf parsed',
                               'fixture', str(ROOT / 'selfhost/chronicle'), *arguments],
                              env=dict(os.environ), capture_output=True, text=True, timeout=10)

    def test_every_documented_command_parses_without_a_refused_handoff(self):
        documents = [ROOT / 'selfhost/README.md', *sorted((ROOT / 'selfhost/docs').glob('*.md'))]
        count = 0
        for document in documents:
            for arguments in documented_commands(document):
                with self.subTest(document=document.name, arguments=arguments):
                    result = self.validate(arguments)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual('parsed', result.stdout)
                count += 1
        self.assertGreater(count, 0)

    def test_operator_docs_replay_dumps_only_through_the_guarded_restore(self):
        count = 0
        for document in OPERATOR_DOCS:
            for line in documented_lines(document):
                with self.subTest(document=document.name, line=line):
                    self.assertFalse(replays_dump(line))
                count += 1
        self.assertGreater(count, 0)

    def test_dump_replay_check_covers_every_operator_document_and_shell_spelling(self):
        replays = (
            'gunzip -c dump.sql.gz | docker exec -i db psql -q -U chronicle',
            'psql -U chronicle -d chronicle < dump.sql',
            'psql -U chronicle -f dump.sql',
            'psql --file=dump.sql',
            'psql --file dump.sql',
            'psql -Xfdump.sql',
            "psql -c '\\i dump.sql'",
            "psql -c '\\include dump.sql'",
            'psql -U chronicle\n\\include_relative dump.sql',
            '< dump.sql psql -U chronicle',
            'psql -c "$(zcat dump.sql.gz)"',
            'psql -c "`zcat dump.sql.gz`"',
            'pg_restore -d chronicle dump',
            'zcat dump.sql.gz | sed s/tde_heap/heap/g |\n  docker exec -i db psql',
            'gunzip -c dump.sql.gz |\n  cat |\n  psql -U chronicle',
            'psql <<SQL\n\\i dump.sql\nSQL',
            'gunzip -c dump.sql.gz | # restore\n  docker exec -i db psql -U chronicle',
            'gunzip -c dump.sql.gz |\n  # into the scratch database\n  psql -U chronicle',
        )
        for document in OPERATOR_DOCS:
            for replay in replays:
                for example in (f'```bash\n{replay}\n```', f'  ~~~sh\n{replay}\n  ~~~',
                                f'    {replay}', f'`{replay}`', replay):
                    with self.subTest(document=document.relative_to(ROOT), example=example), \
                         patch.object(Path, 'read_text', return_value=example):
                        self.assertTrue(any(replays_dump(line) for line in documented_lines(document)))

    def test_dump_replay_check_allows_queries_and_guarded_restore(self):
        for command in ('psql -c "SELECT count(*) FROM studies"',
                        'psql -c "SELECT count(*) < 1 FROM studies"',
                        "psql -c '\\copy (SELECT * FROM audit) TO STDOUT WITH CSV HEADER' > audit.csv",
                        './chronicle restore --file dump.sql.gz --trusted-sha256=...',
                        'Do not replay with psql. Dumps leave out `pgcrypto` and `pg_tde`.'):
            with self.subTest(command=command):
                self.assertFalse(replays_dump(command))

    def test_every_advertised_command_has_working_help(self):
        help_result = subprocess.run(['bash', str(ROOT / 'selfhost/chronicle'), 'help'],
                                     capture_output=True, text=True, timeout=10)
        self.assertEqual(0, help_result.returncode, help_result.stderr)
        advertised = {line.split()[1] for line in help_result.stdout.splitlines()
                      if line.strip().startswith('./chronicle ')}
        self.assertTrue(advertised)
        for command in advertised:
            with self.subTest(command=command):
                result = subprocess.run(['bash', str(ROOT / 'selfhost/chronicle'), command, '--help'],
                                         capture_output=True, text=True, timeout=10)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn('usage:', result.stdout)
        result = subprocess.run(['bash', str(ROOT / 'selfhost/chronicle'), 'stauts'],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(2, result.returncode)
        self.assertFalse(result.stdout)

    def test_invalid_examples_fail_the_production_parser(self):
        for arguments in (['up', '--wrong'], ['restore', '--wrong'], ['upgrade', '--from', '/fixture'],
                          ['adopt', '--from', '/fixture'], ['update', '--wrong'], ['cleanup-releases']):
            with self.subTest(arguments=arguments):
                self.assertNotEqual(0, self.validate(arguments).returncode)

    def test_retired_implementations_are_not_importable(self):
        import importlib.util
        for name in ('adopt',):
            with self.subTest(name=name):
                self.assertIsNone(importlib.util.find_spec('chronicle_ops.' + name))


def section(text, heading):
    """Body under an exact Markdown heading, up to the next heading of the same or a higher level, whitespace-joined."""
    lines = text.splitlines()
    level = len(heading) - len(heading.lstrip('#'))
    body = []
    for line in lines[lines.index(heading) + 1:]:
        if line.startswith('#') and len(line) - len(line.lstrip('#')) <= level:
            break
        body.append(line)
    return ' '.join(' '.join(body).split())


def joined(path):
    return ' '.join((ROOT / path).read_text().split())


def chronicle_commands(text, pattern=r'`(\./chronicle [^`]+)`'):
    return [[concrete(argument) for argument in shlex.split(code)[1:]] for code in re.findall(pattern, text)]


class OperatorDocTruthTests(unittest.TestCase):
    """Operator guides compared with the CLI, settings and code they describe."""

    validate = DocumentedCommandTests.validate

    def test_supported_release_versions_are_explicit_and_the_security_policy_links_them(self):
        support = section((ROOT / 'selfhost/README.md').read_text(), '## Support')
        self.assertIn('Only the latest post-reset release receives security and bug fixes.', support)
        security = section((ROOT / 'SECURITY.md').read_text(), '## Supported versions')
        self.assertIn('selfhost/README.md#support', security)

    def launcher(self, script, **environment):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            return subprocess.run(['bash', '-c', 'fixture="$PWD"; source "$1"; cd "$fixture"; ' + script, 'fixture', str(ROOT / 'selfhost/chronicle')],
                                  cwd=folder, env=dict(os.environ, **environment), capture_output=True, text=True, timeout=20)

    def test_requirements_name_every_tool_and_minimum_the_launcher_enforces(self):
        requirements = section((ROOT / 'selfhost/README.md').read_text(), '## Requirements')
        compose = re.search(r'Docker Compose plugin \*\*(\d+)\.(\d+) or newer\*\*', requirements)
        python = re.search(r'\*\*Python (\d+)\.(\d+) or newer\*\*', requirements)
        self.assertTrue(compose and python, requirements)
        stubs = ('ops_python() { :; }; docker() { printf "%s\\n" "$FIXTURE_COMPOSE"; }; '
                 'command() { [[ "$1" == -v && "$2" == "$FIXTURE_MISSING" ]] && return 1; builtin command "$@"; }; ')
        major, minor = map(int, compose.groups())
        accepted = self.launcher(stubs + 'preflight_resources', FIXTURE_COMPOSE=f'{major}.{minor}.0', FIXTURE_MISSING='')
        self.assertIn(f'docker compose {major}.{minor}.0', accepted.stdout)
        self.assertNotIn('FAIL', accepted.stdout)
        older = self.launcher(stubs + 'preflight_resources', FIXTURE_COMPOSE=f'{major}.{minor - 1}.99', FIXTURE_MISSING='')
        self.assertIn('older than', older.stdout)
        major, minor = map(int, python.groups())
        fake = ('python3() { builtin command python3 -c "import sys; sys.version_info = tuple(map(int, sys.argv[1].split(\'.\'))); '
                'exec(sys.argv[2])" "$FIXTURE_PYTHON" "$2"; }; ops_require_python && printf accepted')
        self.assertEqual('accepted', self.launcher(fake, FIXTURE_PYTHON=f'{major}.{minor}.0').stdout)
        self.assertNotEqual('accepted', self.launcher(fake, FIXTURE_PYTHON=f'{major}.{minor - 1}.0').stdout)
        names = {'python3': 'Python', 'openssl': 'OpenSSL', 'ssh-keygen': '`ssh-keygen -Y`'}
        required = []
        for tool in ('curl', 'openssl', 'python3', 'ssh-keygen', 'gzip', 'tar', 'ip', 'ss'):
            preflight = self.launcher(stubs + 'preflight_resources', FIXTURE_COMPOSE='9.0.0', FIXTURE_MISSING=tool)
            update = self.launcher(stubs + 'cmd_update update', FIXTURE_COMPOSE='9.0.0', FIXTURE_MISSING=tool)
            if 'missing host tools' in preflight.stdout or 'update requires missing tool' in update.stderr:
                required.append(tool)
        self.assertTrue(required)
        for tool in required:
            with self.subTest(tool=tool):
                self.assertIn(names.get(tool, tool), requirements)

    def test_quick_start_sign_in_names_no_account_and_the_backend_reads_only_a_password(self):
        quick = joined('README.md')
        instruction = re.search(r'Then open `https://<[^>]+>/chronicle/` and ([^.]+)\.', quick)
        self.assertTrue(instruction)
        self.assertNotIn('`', instruction.group(1))
        self.assertIn('dashboard password chosen during setup', instruction.group(1))
        login = (ROOT / 'chronicle-server/src/main/kotlin/com/openlattice/chronicle/controllers/AuthTokenController.kt').read_text()
        handler = login[login.index('fun dashboardLogin('):]
        handler = handler[:handler.index('\n    }\n')]
        # Kotlin source as text, deliberately: the handler reads an untyped map, so no model class or
        # OpenAPI contract (DashboardLoginRequest is hand-written) binds the field the README names.
        self.assertEqual(['password'], re.findall(r'body\?\.get\("(\w+)"\)', handler))


    def test_operations_index_names_only_rotations_the_cli_offers(self):
        usage = subprocess.run(['bash', str(ROOT / 'selfhost/chronicle'), 'rotate-secret', '--help'],
                               capture_output=True, text=True, timeout=10).stdout
        kinds = set(re.search(r'rotate-secret \[--yes\] (\S+)', usage).group(1).split('|'))
        listed = re.search(r'Secret rotation and crash recovery: \S+; guarded (.+?) procedures with automatic rollback',
                           joined('selfhost/README.md')).group(1)
        names = [name for name in re.split(r',\s*(?:and\s+)?|\s+and\s+', listed) if name]
        mapping = {'JWT': 'jwt', 'internal': 'internal-web', 'PostgreSQL': 'postgres', 'Grafana': 'grafana', 'TDE': 'tde'}
        named = {mapping.get(name, name.lower().replace(' ', '-')) for name in names}
        self.assertLessEqual(named, kinds, listed)
        for kind in named:
            self.assertEqual(0, self.validate(['rotate-secret', kind]).returncode)
        self.assertTrue(all(any(kind == name or kind.startswith(name + '-') for name in named) for kind in kinds), listed)

    def test_incident_jwt_rotation_revokes_the_exposed_key_without_an_overlap(self):
        for document, heading in (
                ('INCIDENT-RESPONSE.md', '## 3. Rotate'),
                ('UNINSTALL-DATA-DELETION.md', '## Researcher access and "account deletion"')):
            procedure = section((ROOT / 'selfhost/docs' / document).read_text(), heading)
            commands = [arguments for arguments in chronicle_commands(procedure) if arguments[:2] == ['rotate-secret', 'jwt']]
            self.assertTrue(commands, 'The revocation guide must name the JWT rotation command')
            for arguments in commands:
                with self.subTest(document=document, arguments=arguments):
                    self.assertIn('--revoke-sessions', arguments,
                                  'Routine rotation retains the previous signing key and cannot revoke access')
                    self.assertEqual(0, self.validate(arguments).returncode)

    def test_served_runbooks_use_parseable_commands_and_the_in_place_update(self):
        import html
        from chronicle_ops.release import UPDATE_AVAILABLE_EXIT
        page = html.unescape((ROOT / 'selfhost/monitoring/runbooks.html').read_text())
        commands = chronicle_commands(page, r'<code>(\./chronicle [^<]+)</code>')
        self.assertTrue(commands)
        for arguments in commands:
            with self.subTest(arguments=arguments):
                self.assertEqual(0, self.validate(arguments).returncode)
        update = re.search(r'<h2 id="update-available">.*?</section>', page, re.S).group(0)
        steps = chronicle_commands(update, r'<code>(\./chronicle [^<]+)</code>')
        self.assertEqual(['update', '--check'], steps[0])
        self.assertLess(steps.index(['backup']), steps.index(['update']))
        self.assertEqual(str(UPDATE_AVAILABLE_EXIT), re.search(r'exit (\d+) means a release is available', update).group(1))

    def test_play_build_section_matches_the_open_flavor(self):
        import json
        build = section((ROOT / 'selfhost/README.md').read_text(), '### Which Android build')
        registry = {module['id'] for module in json.loads(
            (ROOT / 'chronicle/app/src/open/assets/approved-module-registry.json').read_text())['modules']}
        supported = re.search(r"supports the pilot's (.+?) modules\.", build)
        self.assertTrue(supported, build)
        ids = {'app-usage': 'usage_events', 'activity-class': 'in_app_activity_class', 'upload': 'upload_telemetry'}
        for name in re.split(r',\s*(?:and\s+)?|\s+and\s+', supported.group(1)):
            with self.subTest(module=name):
                self.assertIn(ids.get(name, name.replace('-', '_').replace(' ', '_')), registry)
        excluded = re.search(r'(.+?) collectors are excluded', build.split('modules.', 1)[1]).group(1)
        for name in ('interaction', 'notification', 'audio'):
            self.assertIn(name, excluded.lower())
            self.assertFalse([module for module in registry if name in module])
        gradle = (ROOT / 'chronicle/app/build.gradle').read_text()
        flavor = gradle[gradle.index('        open {'):]
        direct = re.search(r'"DIRECT_BATTERY_EXEMPTION_REQUEST", "(true|false)"', flavor).group(1)
        self.assertEqual('false', direct)  # Play policy: the open build only opens the settings list.
        self.assertNotIn('one-tap', build)
        self.assertIn("select **Don't optimize**", build)
        self.assertIn("select **Unrestricted**", build)  # Android 15+ App battery usage

    def test_rate_limit_section_describes_only_the_shipped_pre_authentication_quotas(self):
        import yaml
        text = section((ROOT / 'selfhost/README.md').read_text(), '## Rate limiting')
        caddy = (ROOT / 'selfhost/caddy/snippets.caddy').read_text()
        zones = {}
        for name, body in re.findall(r'zone (\w+) \{(.*?)\n\t\t\}', caddy, re.S):
            events = re.search(r'events (?:\{\$(\w+):(\d+)\}|(\d+))', body)
            window = re.search(r'window \{\$(\w+):(\w+)\}', body)
            zones[name] = (events.group(1), int(events.group(2) or events.group(3)), window.group(1), window.group(2))
        units = {'1s': 'second', '1m': 'minute'}
        owned, documented = set(), set()
        for row in re.findall(r'\| ([^|]+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \|', text)[1:]:
            settings = re.findall(r'`(\w+)`', row[3])
            with self.subTest(zone=row[0]):
                matching = [name for name, zone in zones.items() if zone[2] in settings and (zone[0] in settings or zone[0] is None)
                            and (zone[0] is None) == ('fixed ceiling' in row[3])]
                self.assertEqual(1, len(matching), row)
                documented.add(matching[0])
                events, count, _, window = zones[matching[0]]
                number = int(re.match(r'([\d,]+)', row[2]).group(1).replace(',', ''))
                self.assertEqual(count, number)
                if events:
                    self.assertIn(f'requests/{units[window]}', row[2])
                owned.add(number)
        self.assertEqual(set(zones), documented)
        limits = yaml.safe_load((ROOT / 'chronicle-server/src/main/resources/rate-limit.yaml').read_text())
        auth, multiplier = limits['auth-requests-per-minute'], limits['burst-capacity-multiplier']
        self.assertIn(f'{auth} requests/minute with burst capacity {int(auth * multiplier)} (the configured {multiplier} multiplier)', text)
        self.assertIn(f"tiers of {limits['read-requests-per-minute']} and {limits['write-requests-per-minute']} requests/minute", text)
        login = re.search(r'DASHBOARD_LOGIN_PER_MINUTE = (\d+)L', (ROOT / 'chronicle-server/src/main/kotlin/com/openlattice/'
                          'chronicle/controllers/AuthTokenController.kt').read_text()).group(1)
        self.assertIn(f'limits dashboard login to {login} requests/minute', text)
        owned |= {auth, int(auth * multiplier), limits['read-requests-per-minute'], limits['write-requests-per-minute'], int(login)}
        for number in re.findall(r'(\d[\d,]*)(?:[ -]requests?\b| per mobile window|-request)', text):
            self.assertIn(int(number.replace(',', '')), owned, 'quota without a shipped owner: ' + number)

    def test_alert_destination_guide_matches_the_provisioned_contact_point_and_update(self):
        import json
        from chronicle_ops.env_migration import merge_env
        from chronicle_ops.envfile import parse_env_text, value
        from chronicle_ops.release import require_release_files
        from chronicle_ops.dump import file_sha256
        guide = section((ROOT / 'selfhost/docs/MONITORING-RUNBOOK.md').read_text(), '## Attach a notification channel')
        key = re.search(r'In `\.env`, add `(\w+)=', guide).group(1)
        contact = ROOT / 'selfhost/monitoring/grafana-alerting/contactpoints.yml'
        receiver = json.loads(contact.read_text())['contactPoints'][0]['receivers'][0]['settings']
        self.assertEqual('$' + key, receiver['url'])
        self.assertIn(key + ': ${' + key, (ROOT / 'selfhost/overlays/monitoring.yml').read_text())
        rendered = merge_env({key: "'https://hooks.example.org/fixture'"}, (ROOT / 'selfhost/.env.example').read_text(),
                             None, '/state', ['docker-compose.yml', 'overlays/monitoring.yml'], preserve_images=True)
        self.assertEqual('https://hooks.example.org/fixture', value(parse_env_text(rendered), key))
        # The contact point is a signed bundle file: an edited copy fails update's checksum validation.
        relative = 'selfhost/monitoring/grafana-alerting/contactpoints.yml'
        require_release_files(ROOT, ROOT / 'release-manifest.json', {relative: file_sha256(contact)})
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            require_release_files(ROOT, ROOT / 'release-manifest.json', {relative: '0' * 64})
        for sentence in re.split(r'(?<=\.) ', guide):
            if 'contactpoints.yml' in sentence and re.search(r'\b(?:change|edit|modify)', sentence, re.I):
                with self.subTest(sentence=sentence):
                    self.assertRegex(sentence, r'Do not edit|unchanged')

    def test_emergency_access_procedure_records_custody_with_real_settings(self):
        procedure = section((ROOT / 'selfhost/docs/INCIDENT-RESPONSE.md').read_text(), '### Emergency dashboard access')
        commands = chronicle_commands(procedure)
        self.assertEqual(['rotate-secret', 'dashboard'], commands[0])
        for arguments in commands:
            self.assertEqual(0, self.validate(arguments).returncode)
        template = (ROOT / 'selfhost/.env.example').read_text()
        for setting in re.findall(r'`([A-Z][A-Z0-9_]+)(?:=\w+)?`', procedure):
            with self.subTest(setting=setting):
                self.assertRegex(template, rf'(?m)^#? ?{setting}=')
        self.assertIn('out of band, and writes in the incident record who received it, when, and why', procedure)
        self.assertRegex(procedure, r'removes the temporary source range and rotates the dashboard password again')

    def test_export_guides_match_the_participant_download_contract(self):
        import yaml
        api = yaml.safe_load((ROOT / 'chronicle-api/chronicle.yaml').read_text())
        download = api['paths']['/chronicle/v3/study/{studyId}/participants/data']['get']
        parameters = {parameter['name']: parameter for parameter in download['parameters'] if 'name' in parameter}
        formats = parameters['responseType']['schema']['enum']
        self.assertEqual('string', parameters['dataType']['schema']['type'])  # one dataset per request
        self.assertEqual(1, parameters['participantId']['schema']['minItems'])
        self.assertFalse([path for path in api['paths'] if 'export' in path.lower() and 'job' in path.lower()])
        readme = section((ROOT / 'selfhost/README.md').read_text(), '## Managing studies, participants, export, and deletion')
        guide = joined('docs/PILOT-DATA.md')
        default = parameters['responseType']['schema']['default'].upper()
        self.assertIn(f'Each download is one data type as {default}', readme)  # the dashboard sends no responseType
        self.assertIn('from the Participants tab: tick participants', readme)
        self.assertIn('runs no export jobs', readme)
        self.assertIn('one dataset per download, streamed straight to the browser: '
                      f'{default} from the dashboard, ' + ' or '.join(name.upper() for name in formats), guide)
        self.assertIn('a request with none is refused', guide)
        for retired in ('Excel', 'xlsx', 'background job'):
            self.assertNotIn(retired, readme + guide)

    def test_pilot_guide_lists_every_app_usage_survey_export_column_and_answer(self):
        storage = ROOT / 'chronicle-server/src/main/kotlin/com/openlattice/chronicle/storage'
        tables = (storage / 'ChroniclePostgresTables.kt').read_text()
        body = re.search(r'val APP_USAGE_SURVEY: PostgresTableDefinition = PostgresTableDefinition\("app_usage_survey"\)'
                         r'\s*\.addColumns\((.*?)\)\s*\.primaryKey', tables, re.S).group(1)
        constants = re.findall(r'(?:PostgresEventColumns\.)?([A-Z_]+)\s*,', re.sub(r'//[^\n]*', '', body))
        definitions = (storage / 'PostgresColumns.kt').read_text() + (storage / 'PostgresEventColumns.kt').read_text()
        columns = {re.search(rf'val {name} = PostgresColumnDefinition\("(\w+)"', definitions).group(1) for name in constants}
        service = (ROOT / 'chronicle-server/src/main/kotlin/com/openlattice/chronicle/services/download/DataDownloadService.kt').read_text()
        columns.add(re.search(r'ANSWER_LAG_SECONDS = "(\w+)"', service).group(1))
        guide = (ROOT / 'docs/PILOT-DATA.md').read_text()
        self.assertIn('All datasets include `study_id` (study UUID) and `participant_id`', guide)
        row = next(line for line in guide.splitlines() if line.startswith('| AppUsageSurvey |'))
        self.assertEqual(set(), columns - {'study_id', 'participant_id'} - set(re.findall(r'`(\w+)`', row)))
        answer = re.search(r'APP_USAGE_NONE_OPTION = "([^"]+)"',
                           (ROOT / 'chronicle-web/src/modern/components/participant-survey-form.tsx').read_text()).group(1)
        self.assertIn(f'"{answer}" is stored in `users`', guide)
        self.assertIn('nothing to review is one row at the start of the day with an empty `app_package_name`',
                      ' '.join(guide.split()))

    def test_free_disk_floor_names_every_filesystem_startup_checks(self):
        import tempfile
        from chronicle_ops import common
        from chronicle_ops.release import free_disk_floor
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, clear=True):
            info = subprocess.CompletedProcess([], 0, folder + '\n')
            with patch('chronicle_ops.common.run', return_value=info), \
                 patch('chronicle_ops.common.database_volume_path', return_value=Path(folder)):
                rows = [row[0] for row in common.storage_report(folder, 'fixture')]
            floor = free_disk_floor({})
        readme = joined('selfhost/README.md')
        rule = re.search(r'Free disk floor: (.+?)\. `\./chronicle doctor`', readme).group(1)
        self.assertIn(f'`MIN_FREE_DISK_GIB` (default {floor})', rule)
        self.assertIn(f'fewer than {common.MIN_FREE_INODES:,} inodes', rule)
        names = {'state': 'state directory', 'docker-data': 'Docker data root', 'database-volume': 'database volume'}
        self.assertEqual(set(names), set(rows))
        for row in rows:
            self.assertIn(names[row], rule)

    def test_release_notes_match_removed_settings_formats_and_recovery_commands(self):
        import yaml
        notes = (ROOT / 'CHANGELOG.md').read_text()
        # The release that removed xlsx, wherever the release cut moved it (Unreleased or a dated heading).
        release = next(' '.join(section.split()) for section in re.split(r'\n(?=## \[)', notes)
                       if 'Excel (xlsx) format' in section)
        removed = release[release.index('### Removed'):]
        removed = removed[:removed.index('### ', 4)] if '### ' in removed[4:] else removed
        api = yaml.safe_load((ROOT / 'chronicle-api/chronicle.yaml').read_text())
        formats = api['paths']['/chronicle/v3/study/{studyId}/participants/data']['get']['parameters']
        formats = next(parameter for parameter in formats if parameter.get('name') == 'responseType')['schema']['enum']
        self.assertNotIn('xlsx', formats)
        self.assertIn('Excel (xlsx) format', removed)
        self.assertIn('as CSV (dashboard) or CSV/JSON (API), one data type per download', removed)
        shipped = ''.join((ROOT / path).read_text() for path in ('selfhost/.env.example', 'selfhost/docker-compose.yml'))
        for setting in re.findall(r'`([A-Z][A-Z0-9_]{3,})`', removed):
            with self.subTest(setting=setting):
                self.assertNotIn(setting, shipped)
        for arguments in chronicle_commands(release):
            with self.subTest(arguments=arguments):
                self.assertEqual(0, self.validate(arguments).returncode)

    def test_backup_guide_names_the_extensions_restore_and_the_self_check_create(self):
        from chronicle_ops.dump import RESTORE_EXTENSIONS_SQL
        created = set(re.findall(r'CREATE EXTENSION IF NOT EXISTS "(\w+)"', RESTORE_EXTENSIONS_SQL))
        guide = joined('selfhost/docs/BACKUP-RESTORE.md')
        named = re.search(r'Restore creates (.+?) before replay when the database lacks it', guide).group(1)
        self.assertEqual(created, set(re.findall(r'`(\w+)`', named)))
        self.assertIn('the backup self-check restores into scratch the same way', guide)


SHELL_FENCE = re.compile(r'^[ \t]*(```|~~~)(?:bash|sh|shell)[^\n]*\n(.*?)^[ \t]*\1', re.M | re.S)
# Multi-command blocks whose commands do not depend on one another's success, with the reason.
INDEPENDENT_SHELL_BLOCKS = {
    ('README.md', './chronicle monitoring status'): 'separate viewer commands, one per task',
    ('README.md', 'PUB=https://<public-host> # your CHRONICLE_PUBLIC_BASE_URL'):
        'read-only probes that print each answer; a failed probe is the reported result',
    ('README.md', 'PUB=https://<public-host>; INT=https://<internal-ip>:8081'):
        'read-only probes that print each answer; a failed probe is the reported result',
    ('BACKUP-RESTORE.md', './chronicle check'): './chronicle up reruns every check and refuses to start on a failure',
    ('SECRET-ROTATION.md', './chronicle verify'): 'two independent verifications, each with its own verdict',
    ('SECRET-ROTATION.md', 'docker compose ps --all'): 'read-only inspection',
    ('SECRET-ROTATION.md', './chronicle rotate-secret recover --forward'): 'two alternatives; the operator runs exactly one',
    ('UNINSTALL-DATA-DELETION.md', "grep -E '^[[:space:]]*(export[[:space:]]+)?(COMPOSE_PROJECT_NAME|CHRONICLE_STATE_DIR)=' .env"):
        'read-only inspection',
    ('UNINSTALL-DATA-DELETION.md', 'realpath /ABSOLUTE/CHRONICLE_STATE_DIR'): 'read-only inspection',
    ('UNINSTALL-DATA-DELETION.md', "docker ps -a --filter 'label=com.docker.compose.project=EXACT_PROJECT_NAME' --format '{{.Names}}'"):
        'read-only inspection',
}


def shell_blocks(document):
    """(first command, commands, body) for each fenced shell block; continuation lines are joined."""
    for match in SHELL_FENCE.finditer(document.read_text()):
        commands = [' '.join(line.split()) for line in match[2].replace('\\\n', ' ').splitlines()
                    if line.strip() and not line.strip().startswith('#')]
        yield (commands[0] if commands else ''), commands, match[2]


def run_documented_block(body, directory, commands):
    """Run a copied block as an operator would paste it into a Bash shell, with stub commands first on PATH."""
    return subprocess.run(['bash', '-c', body], cwd=directory, capture_output=True, text=True, timeout=20,
                          env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH']))


class OperatorShellBlockTests(unittest.TestCase):
    documents = [ROOT / 'selfhost/README.md', *sorted((ROOT / 'selfhost/docs').glob('*.md'))]

    def test_every_multi_step_operator_block_stops_at_its_first_failure(self):
        listed, checked = set(), 0
        for document in self.documents:
            for first, commands, _ in shell_blocks(document):
                if len(commands) < 2:
                    continue
                checked += 1
                key = (document.name, first)
                with self.subTest(document=document.name, first=first):
                    if key in INDEPENDENT_SHELL_BLOCKS:
                        listed.add(key)
                    else:
                        self.assertEqual(['(', 'set -euo pipefail'], commands[:2])
                        self.assertEqual(')', commands[-1])
        self.assertGreater(checked, len(INDEPENDENT_SHELL_BLOCKS))
        self.assertEqual(set(INDEPENDENT_SHELL_BLOCKS), listed, 'a listed block no longer exists')

    def test_strict_blocks_leave_the_operators_shell_alive_on_failure(self):
        for document in self.documents:
            for first, commands, body in shell_blocks(document):
                if len(commands) < 2 or (document.name, first) in INDEPENDENT_SHELL_BLOCKS:
                    continue
                with self.subTest(document=document.name, body=body[:100]):
                    lines = commands
                    self.assertEqual('(', lines[0])
                    self.assertEqual(')', lines[-1])
                    # Exercise the documented shell boundary without running operator commands.
                    failed = '\n'.join([*lines[:2], 'false', 'printf "continued after failure\\n"', lines[-1]])
                    result = subprocess.run(['bash', '-c', failed + '\nprintf "session alive\\n"'],
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual('session alive\n', result.stdout)

    def test_upgrade_recipe_continues_when_a_release_is_available_and_stops_on_update_failure(self):
        import tempfile
        guide = ROOT / 'selfhost/docs/UPGRADE-ROLLBACK.md'
        (body,) = [body for _, _, body in shell_blocks(guide) if './chronicle update' in [line.strip() for line in body.splitlines()]]
        for update_status in (0, 1):
            with self.subTest(update_status=update_status), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                launcher = root / 'chronicle'
                launcher.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >>calls\n'
                                    '[ "$*" = "update --check" ] && exit 3\n'
                                    f'[ "$*" = update ] && exit {update_status}\nexit 0\n')
                launcher.chmod(0o755)
                result = run_documented_block(body, root, root)
                self.assertEqual(update_status, result.returncode, result.stdout + result.stderr)
                self.assertEqual(['update', *([] if update_status else ['verify', 'doctor --json'])],
                                 [line for line in (root / 'calls').read_text().splitlines() if line != 'update --check'])

    def offhost_blocks(self):
        guide = (ROOT / 'selfhost/docs/BACKUP-RESTORE.md').read_text()
        section = guide.split('## Verify off-host copies\n', 1)[1].split('\n## ', 1)[0]
        return [match[2] for match in SHELL_FENCE.finditer(section)]

    def test_off_host_check_never_vouches_for_a_stale_archive_or_a_failed_decrypt(self):
        import gzip as gzip_module
        import io
        import tarfile
        import tempfile
        (decrypt,) = [body for body in self.offhost_blocks() if 'gpg --decrypt' in body]
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:gz') as tar:
            member = tarfile.TarInfo('last/chronicle-latest.sql.gz'); payload = gzip_module.compress(b'fixture')
            member.size = len(payload); tar.addfile(member, io.BytesIO(payload))
        for case, copy_exit, decrypt_exit, succeeds in (('rclone copy fails, stale archive remains', 1, 0, False),
                                                         ('decryptor emits a tar stream, then fails', 0, 2, False),
                                                         ('fresh copy decrypts', 0, 0, True)):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); commands = root / 'bin'; commands.mkdir()
                (root / 'check').mkdir()
                (root / 'check/chronicle-backups.tar.gz.gpg').write_bytes(b'stale archive from the last exercise')
                (root / 'archive.tar.gz').write_bytes(archive.getvalue())
                (commands / 'rclone').write_text(f'#!/bin/sh\n[ "$1" = copy ] && exit {copy_exit}\nexit 0\n')
                # Decryption is the fixture's identity transform over the archive the copy would have fetched.
                (commands / 'gpg').write_text(f'#!/bin/sh\ncat "{root}/archive.tar.gz"\nexit {decrypt_exit}\n')
                for stub in commands.iterdir():
                    stub.chmod(0o755)
                result = run_documented_block(decrypt, root, commands)
                self.assertEqual(succeeds, result.returncode == 0, result.stdout + result.stderr)
                self.assertEqual(succeeds, 'decrypts and is intact' in result.stdout, result.stdout)

    def test_off_host_comparison_reports_a_failed_check(self):
        import tempfile
        (compare,) = [body for body in self.offhost_blocks() if 'rclone check' in body]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); commands = root / 'bin'; commands.mkdir()
            (commands / 'rclone').write_text('#!/bin/sh\nexit 1\n'); (commands / 'rclone').chmod(0o755)
            result = run_documented_block(compare, root, commands)
            self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)


class SetupSignInMessageTests(SelfhostSetupFixture):
    def test_setup_tells_the_operator_to_sign_in_with_the_password_they_chose(self):
        result = self.run_setup()
        self.assertIn('use the shared dashboard password you just chose.', result.stdout)
