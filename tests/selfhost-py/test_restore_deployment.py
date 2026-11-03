"""Catalog guard and overwrite restore for an actual migrated, encrypted deployment."""

import csv
from datetime import date, datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
import uuid
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from chronicle_ops.dump import SESSION_STATE_TABLE, CATALOG_GATE_SQL, CATALOG_SQL, EXIT_REJECTED_BEFORE_MUTATION, RestoreSource, DUMP_EXCLUDE_OPTIONS, UNCLASSIFIED_OBJECTS, backup_marker
from selfhost_fixture import FIXTURE_POSTGRES_PASSWORD, rotation_fixture
from test_restore_schemas import PgTdeFixture, ROOT, SELFHOST, KEY_EVIDENCE_SQL, ACTIVE_KEY_SQL
from chronicle_ops.release import ROLLBACK_DUMP

CLASSPATH_TASK = "restoreDeploymentClasspath"
CLASSPATH_OUTPUT_PROPERTY = "chronicle.restore.classpath.output"
PARTICIPANT_TOKEN_SQL = "SELECT public.chronicle_participant_block_token('00000000-0000-0000-0000-000000000001', 'P1');"

SANTIAGO = ZoneInfo("America/Santiago")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
PILOT_STUDY = "5a1e0000-0000-4000-8000-000000000001"
PILOT_MODULES = ("usage_events", "in_app_activity_class", "device_lifecycle", "user_identification",
                 "upload_telemetry", "sensor_availability", "battery_telemetry")
# Column kinds decide how a value is written to COPY csv and how it is read back as JSON.
PILOT_TABLES = {
    "studies": "study_id title settings:json modules:json lifecycle_status",
    "data_collection_settings_revisions": "study_id settings_version:int setting:json study_modules:json",
    "candidates": "candidate_id",
    "study_participants": "study_id participant_id candidate_id participation_status participant_notes participant_tags:array",
    "devices": "study_id random_device_id participant_id device_type source_device:json",
    "participant_collection_acknowledgment": "id study_id participant_id source_random_device_id acknowledged_modules:json "
                                             "acknowledged_at:ts recorded_at:ts app_version settings_version:int disclosure_version "
                                             "manifest_digest declined_modules:json unavailable_modules:json collection_trigger decision_seq:int",
    "chronicle_usage_events": "study_id participant_id app_package_name activity_class interaction_type event_type:int "
                              "event_timestamp:ts timezone username application_label uploaded_at:ts client_event_id",
    "chronicle_usage_stats": "study_id participant_id app_package_name interaction_type start_time:ts end_time:ts duration:int "
                             "event_timestamp:ts timezone application_label",
    "upload_buffer": "study_id participant_id data:json uploaded_at:ts upload_type random_device_id",
    "battery_telemetry": "study_id participant_id sample_id sample_timestamp:ts timezone level_percent:int charging_state plug_type "
                         "health temperature_deci_c:int voltage_millivolts:int uploaded_at:ts low_power_mode:bool",
    "android_device_sensor_availability": "study_id participant_id random_device_id available_sensors:array screen_width_pixels:int "
                                          "screen_height_pixels:int screen_density_dpi:int display_rotation:int "
                                          "interaction_pointer_capture_capability reported_at:ts",
    "upload_diagnostics": "study_id participant_id random_device_id event_id diagnostic_day:date module_family issue_code "
                          "occurrence_count:int first_occurred_at:ts last_occurred_at:ts http_status:int error_type uploaded_at:ts",
    "app_usage_survey": "study_id participant_id submission_date:ts application_label app_package_name event_timestamp:ts "
                        "timezone users:array survey_date:date",
    "participant_stats": "study_id participant_id android_last_ping:ts android_first_date:ts android_last_date:ts "
                         "android_unique_dates:array",
}
PILOT_COLUMNS = {table: [tuple((column + ":text").split(":")[:2]) for column in spec.split()] for table, spec in PILOT_TABLES.items()}


def millis(moment):
    return (moment - EPOCH) // timedelta(milliseconds=1)


def pilot_settings(version):
    return {"DataCollection": {"settingsVersion": version, "modules": list(PILOT_MODULES),
                               "requiredModules": ["usage_events"], "timezone": "America/Santiago",
                               "uploadIntervalMinutes": 15 * version}}


def pilot_dataset():
    """25 participants x 30 Santiago days of the seven pilot modules; half the cohort spans each 2026 DST change."""
    rng = random.Random(1030)
    apps = (("cl.mineduc.aprendoenlinea", "Aprendo en línea"), ("com.whatsapp", "WhatsApp"),
            ("com.spotify.music", 'Música "Spotify", Ñandú'), ("com.android.chrome", "Chrome"),
            ("com.google.android.youtube", "YouTube"))
    lifecycle = ((1, "Move to Foreground"), (2, "Move to Background"), (15, "Screen Interactive"),
                 (16, "Screen Non-Interactive"), (17, "Keyguard Shown"), (18, "Keyguard Hidden"),
                 (26, "Device Shutdown"), (27, "Device Startup"))
    rows = {table: [] for table in PILOT_TABLES}
    modules = {"chronicle": {"modules": list(PILOT_MODULES)}}
    rows["studies"].append([PILOT_STUDY, "Estudio piloto", pilot_settings(3), modules, "ACTIVE"])
    # The settings trigger keeps one immutable revision per researcher save (versions 1, 2, 3).
    rows["data_collection_settings_revisions"] = [
        [PILOT_STUDY, version, pilot_settings(version)["DataCollection"], modules] for version in (1, 2, 3)]
    for number in range(1, 26):
        participant = f"CL-{number:03d}"
        autumn = number <= 13
        first_day = date(2026, 3, 22) if autumn else date(2026, 8, 23)
        devices = [str(uuid.UUID(int=rng.getrandbits(128), version=4)) for _ in range(2 if number in (1, 14) else 1)]
        shared = number % 4 == 0
        candidate = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        rows["candidates"].append([candidate])
        rows["study_participants"].append([PILOT_STUDY, participant, candidate,
                                           "ENROLLED", "Hogar compartido: sí" if shared else None,
                                           ["santiago", "otoño" if autumn else "primavera"]])
        for index, device in enumerate(devices):
            reported = datetime(first_day.year, first_day.month, first_day.day, 9, tzinfo=SANTIAGO) + timedelta(days=15 * index)
            rows["devices"].append([PILOT_STUDY, device, participant, "Android",
                                    {"model": "Galaxy A14", "manufacturer": "samsung", "osVersion": "14", "sdk": 34 + index}])
            rows["android_device_sensor_availability"].append([
                PILOT_STUDY, participant, device, ["accelerometer", "light", "proximity"][:2 + index],
                1080, 2408 - index, 400 + index, index, "UNSUPPORTED" if index else None, millis(reported)])
        for sequence, (trigger, declined) in enumerate((("ENROLLMENT", []), ("SETTINGS_CHANGE", ["in_app_activity_class"] if shared else [])), 1):
            moment = datetime(first_day.year, first_day.month, first_day.day, 10, tzinfo=SANTIAGO) + timedelta(days=10 * (sequence - 1))
            accepted = [module for module in PILOT_MODULES if module not in declined]
            rows["participant_collection_acknowledgment"].append([
                str(uuid.UUID(int=rng.getrandbits(128), version=4)), PILOT_STUDY, participant, devices[0], accepted,
                millis(moment), millis(moment + timedelta(seconds=3)), "2026.10.29", sequence + 1, "es-CL-2026-10",
                "%064x" % rng.getrandbits(256), declined, [], trigger, sequence])
        dates = []
        for offset in range(30):
            day = first_day + timedelta(days=offset)
            dates.append(day.isoformat())
            # A Santiago day lasts 25 hours on 2026-04-04 and 23 hours on 2026-09-06 (midnight is skipped).
            start = datetime.combine(day, datetime.min.time(), SANTIAGO).astimezone(timezone.utc)
            length = datetime.combine(day + timedelta(days=1), datetime.min.time(), SANTIAGO).astimezone(timezone.utc) - start
            device = devices[-1] if offset >= 15 else devices[0]
            user = ("Someone else" if offset % 3 == 0 else "Study participant") if shared else "Study participant"
            moments = [start + length * step / 80 for step in range(80)]
            if day == date(2026, 4, 4):
                # Both instants of the repeated 23:30 wall-clock time survive as distinct observations.
                moments += [datetime(2026, 4, 4, 23, 30, fold=fold, tzinfo=SANTIAGO).astimezone(timezone.utc) for fold in (0, 1)]
            for step, moment in enumerate(moments):
                package, label = apps[step % len(apps)]
                event_type, interaction = lifecycle[step % len(lifecycle)]
                rows["chronicle_usage_events"].append([
                    PILOT_STUDY, participant, package, package + ".MainActivity" if event_type in (1, 2) else None, interaction,
                    event_type, millis(moment), "America/Santiago", user, label, millis(moment + timedelta(minutes=5)),
                    f"{participant}-{day.isoformat()}-{step}"])
            for package, label in apps:
                rows["chronicle_usage_stats"].append([PILOT_STUDY, participant, package, "Usage Stat", millis(start),
                                                      millis(start + length), rng.randrange(1, 3_600_000),
                                                      millis(start + length), "America/Santiago", label])
            for step in range(48):
                moment = start + length * step / 48
                rows["battery_telemetry"].append([
                    PILOT_STUDY, participant, f"{participant}-{day.isoformat()}-{step}", millis(moment), "America/Santiago",
                    rng.randrange(0, 101), ("CHARGING", "DISCHARGING", "FULL", "NOT_CHARGING")[step % 4],
                    "AC" if step % 4 == 0 else None, "GOOD", rng.randrange(200, 420), rng.randrange(3500, 4400),
                    millis(moment + timedelta(minutes=1)), (None, True, False)[step % 3]])
            failure = ("TIMEOUT", "HTTP_SERVER_ERROR", "LOCAL_WRITE_FAILED", "DNS_FAILURE")[offset % 4]
            rows["upload_diagnostics"].append([
                PILOT_STUDY, participant, device, str(uuid.UUID(int=rng.getrandbits(128), version=4)), day.isoformat(),
                ("USAGE_LIFECYCLE", "BATTERY", "DEVICE_TELEMETRY", "LOCAL_STORE")[offset % 4], failure, rng.randrange(1, 6),
                millis(start + timedelta(hours=2)), millis(start + timedelta(hours=3)),
                503 if failure == "HTTP_SERVER_ERROR" else None, "SocketTimeoutException" if failure == "TIMEOUT" else None,
                millis(start + timedelta(hours=4))])
            for step in range(3):
                package, label = apps[(offset + step) % len(apps)]
                rows["app_usage_survey"].append([
                    PILOT_STUDY, participant, millis(start + timedelta(hours=20)), label, package,
                    millis(start + length * (step + 1) / 4), "America/Santiago",
                    ["Study participant", "Someone else"] if shared and step else ["Study participant"], day.isoformat()])
        for step in range(3):
            moment = datetime.combine(first_day + timedelta(days=30), datetime.min.time(), SANTIAGO) + timedelta(minutes=step)
            rows["upload_buffer"].append([PILOT_STUDY, participant, {"usage": [{
                "packageName": apps[step][0], "eventType": 1, "timestamp": moment.isoformat(), "user": "Study participant"}]},
                millis(moment.astimezone(timezone.utc)), "Android", devices[-1]])
        last = datetime.combine(first_day + timedelta(days=29), datetime.min.time(), SANTIAGO)
        rows["participant_stats"].append([PILOT_STUDY, participant, millis(last + timedelta(hours=23)),
                                          millis(datetime.combine(first_day, datetime.min.time(), SANTIAGO)), millis(last), dates])
    return rows


def copy_value(kind, value):
    if value is None:
        return None
    if kind == "ts":
        return (EPOCH + timedelta(milliseconds=value)).astimezone(SANTIAGO).isoformat()
    if kind == "json":
        return json.dumps(value, ensure_ascii=False)
    if kind == "array":
        return "{" + ",".join('"' + element + '"' for element in value) + "}"
    if kind == "bool":
        return "true" if value else "false"
    return str(value)


def pilot_copy_sql(rows):
    script = ["SET client_encoding = 'UTF8';"]
    for table in PILOT_TABLES:
        if table in ("studies", "data_collection_settings_revisions"):
            continue  # Written by the study insert and its settings trigger.
        columns = PILOT_COLUMNS[table]
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        for row in rows[table]:
            writer.writerow([copy_value(kind, value) for (_, kind), value in zip(columns, row)])
        script.append(f"COPY public.{table} ({', '.join(name for name, _ in columns)}) FROM STDIN WITH (FORMAT csv);\n"
                      + buffer.getvalue() + "\\.")
    return "\n".join(script) + "\n"


def pilot_read_sql(table):
    expressions = []
    for name, kind in PILOT_COLUMNS[table]:
        expressions.append({"ts": f"(extract(epoch FROM {name}) * 1000)::bigint", "text": f"{name}::text",
                            "date": f"{name}::text"}.get(kind, name))
    scope = f"study_id::text = '{PILOT_STUDY}'"
    if table == "candidates":
        scope = f"candidate_id IN (SELECT candidate_id FROM public.study_participants WHERE {scope})"
    return (f"SELECT coalesce(json_agg(json_build_array({', '.join(expressions)})), '[]') FROM public.{table} "
            f"WHERE {scope};")


class DeploymentCatalogTests(PgTdeFixture):
    database_user = "testuser"
    network_options = ("-p", "127.0.0.1::5432")

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.bootstrap_deployment()
        cls.initial_application_tables = cls.public_tables()
        if cls.sql("SELECT am.amname FROM pg_class c JOIN pg_am am ON am.oid = c.relam "
                   "WHERE c.oid = 'public.data_deletion_tombstones'::regclass;") != "tde_heap":
            raise AssertionError("Fresh migrations must preserve the deployment's encrypted table default")
        # Sweep the framework tables too, just as db-init does after migrations.
        cls.docker("exec", "--user", "0", "-e", "POSTGRES_HOST=127.0.0.1", cls.container,
                   "bash", "/selfhost/init-tde.sh")
        cls.rotate_deployment_key()

    @classmethod
    def bootstrap_deployment(cls):
        classpath_file = cls.work / "test-classpath"
        init = cls.work / "restore-deployment.init.gradle"
        init.write_text(f'''allprojects {{
    plugins.withId('java') {{
        tasks.register('{CLASSPATH_TASK}') {{
            dependsOn testClasses
            doLast {{
                def output = System.getProperty('{CLASSPATH_OUTPUT_PROPERTY}')
                file(output).text = sourceSets.test.runtimeClasspath.asPath
                file(output + '.main').text = sourceSets.main.runtimeClasspath.asPath
            }}
        }}
    }}
}}
''')
        environment = dict(os.environ)
        environment["JAVA_TOOL_OPTIONS"] = environment.get("JAVA_TOOL_OPTIONS", "") + " -Djava.io.tmpdir=" + str(cls.work)
        result = subprocess.run(["./gradlew", "--no-daemon", "--no-configuration-cache", "-q", "-I", str(init),
                                 "-D" + CLASSPATH_OUTPUT_PROPERTY + "=" + str(classpath_file), ":" + CLASSPATH_TASK],
                                cwd=ROOT / "chronicle-server", env=environment, capture_output=True, text=True, timeout=600)
        (cls.work / "gradle.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        cls.classpath = classpath_file.read_text()
        cls.main_classpath = classpath_file.with_name(classpath_file.name + ".main").read_text()
        cls.apply_deployment_migrations()

    @classmethod
    def apply_deployment_migrations(cls):
        fixture = Path(__file__).parent
        environment = dict(os.environ)
        port = cls.docker("port", cls.container, "5432/tcp").decode().strip().split(":")[-1]
        result = subprocess.run(["java", "-cp", cls.classpath, str(fixture / "RestoreDeployment.java"),
                                 "jdbc:postgresql://127.0.0.1:" + port + "/chronicle",
                                 cls.database_user, FIXTURE_POSTGRES_PASSWORD],
                                cwd=ROOT, env=environment, capture_output=True, text=True, timeout=240)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        migrations = list((ROOT / "chronicle-server/src/main/resources/db/migration").glob("V*__*.sql"))
        if str(len(migrations)) not in result.stdout.splitlines():
            raise AssertionError(result.stdout + result.stderr)
        print("Full deployment: applied", len(migrations), "Flyway migrations", flush=True)

    def researcher_session_probe(self, token, issued_at):
        port = self.docker('port', self.container, '5432/tcp').decode().strip().split(':')[-1]
        request = dict(jdbcUrl='jdbc:postgresql://127.0.0.1:' + port + '/chronicle', username=self.database_user,
                       password=FIXTURE_POSTGRES_PASSWORD, tokenValue=token, issuedAtEpoch=issued_at)
        result = subprocess.run(['java', '-Xmx256m', '-cp', self.classpath,
                                 str(Path(__file__).with_name('ResearcherSessionProbe.java'))],
                                input=json.dumps(request), capture_output=True, text=True, timeout=120)
        self.assertEqual(0, result.returncode, result.stderr)
        return SimpleNamespace(**json.loads(result.stdout.splitlines()[-1]))

    def test_logged_out_researcher_cannot_replay_after_real_restore(self):
        self.environment = []
        self.sql('TRUNCATE ' + SESSION_STATE_TABLE + ';')
        token = 'synthetic-' + uuid.uuid4().hex
        issued_at = int(self.sql('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint;'))
        path = self.dump('researcher-logout.sql.gz', *DUMP_EXCLUDE_OPTIONS)
        logged_out = self.researcher_session_probe(token, issued_at)
        self.assertTrue(logged_out.beforeLogout)
        self.assertFalse(logged_out.afterLogout)
        result = self.restore(path)
        self.assertEqual(0, result.returncode, result.stderr)
        replay = self.researcher_session_probe(token, issued_at)
        self.assertFalse(replay.beforeLogout, 'a fresh backend accepted the logged-out pre-restore session')
        self.assertFalse(replay.afterLogout)

    def test_pre_rotation_backup_restores_database_privilege_restrictions(self):
        from chronicle_ops.verify import DATABASE_PRIVILEGES_SQL
        self.environment = []
        fixture = self.real_rotation_fixture()
        rotated = self.run_rotation(fixture, 'tde')
        self.assertEqual(0, rotated.returncode, rotated.stdout + rotated.stderr)
        backup, = (fixture.host / 'backups/secret-rotation').glob('*.sql.gz')
        restored = self.restore(backup)
        self.assertEqual(0, restored.returncode, restored.stderr)
        self.assertEqual('t', self.sql(DATABASE_PRIVILEGES_SQL))

    def test_quarantine_is_worker_only_and_restore_carries_it_in_the_continuity_checkpoint(self):
        self.environment = []
        study, candidate, operation, receipt = (str(uuid.uuid4()) for _ in range(4))
        participant = 'restore-withdrawal'
        scope = f"study_id = '{study}'"
        # Earlier restores in this shared container leave their checkpoint unconsumed (no backend runs here),
        # and restore.sh then reuses it instead of capturing this test's withdrawal. Consume it as the backend would.
        self.sql("DROP SCHEMA IF EXISTS chronicle_restore_continuity CASCADE;")
        self.addCleanup(self.sql,
                        f"DELETE FROM public.data_deletion_operations WHERE {scope}; "
                        f"DELETE FROM public.study_participants WHERE {scope}; "
                        f"DELETE FROM public.candidates WHERE candidate_id = '{candidate}'; "
                        f"DELETE FROM public.studies WHERE {scope};")
        self.sql(f"INSERT INTO public.studies(study_id, title, settings, modules, lifecycle_status) "
                 f"VALUES ('{study}', 'Restore withdrawal fixture', '{{}}', '{{}}', 'ACTIVE'); "
                 f"INSERT INTO public.candidates(candidate_id) VALUES ('{candidate}'); "
                 f"INSERT INTO public.study_participants(study_id, participant_id, candidate_id, participation_status) "
                 f"VALUES ('{study}', '{participant}', '{candidate}', 'ENROLLED');")
        backup = self.dump('before-quarantined-withdrawal.sql.gz', *DUMP_EXCLUDE_OPTIONS)
        self.sql("BEGIN; SET LOCAL app.is_admin = 'true'; SET LOCAL app.is_deletion_worker = 'true'; "
                 f"INSERT INTO public.data_deletion_operations(operation_id, study_id, participant_id, mode, status, "
                 f"requested_by, idempotency_key, registry_version) VALUES ('{operation}', '{study}', '{participant}', "
                 f"'WITHDRAW_AND_ERASE', 'QUARANTINED', 'restore-fixture', '{receipt}', 1); "
                 f"UPDATE public.study_participants SET participation_status = 'NOT_ENROLLED' WHERE {scope}; COMMIT;")
        context = ("BEGIN; SET LOCAL ROLE chronicle_app; SET LOCAL app.is_admin = 'true'; "
                   "SET LOCAL app.current_user_id = 'chronicle-deletion-worker'; ")
        query = f"SELECT count(*) FROM public.study_participants WHERE {scope}; COMMIT;"
        self.assertEqual('0', self.sql(context + "SET LOCAL app.is_deletion_worker = 'false'; " + query),
                         'an ordinary admin whose subject equals the worker marker read quarantined data')
        self.assertEqual('1', self.sql(context + "SET LOCAL app.is_deletion_worker = 'true'; " + query),
                         'the explicit trusted worker context could not read its quarantined participant')
        restored = self.restore(backup)
        self.assertEqual(0, restored.returncode, restored.stderr)
        self.assertEqual('NOT_ENROLLED', self.sql(
            f"SELECT participation_status FROM public.study_participants WHERE {scope};"))
        # restore.sh contains the withdrawal; the backend's reconciler replays the operation from the checkpoint.
        self.assertEqual('QUARANTINED', self.sql(
            f"SELECT status FROM chronicle_restore_continuity.deletion_operations WHERE operation_id = '{operation}';"))

    def test_receipt_owner_kinds_and_legacy_default_survive_same_schema_restore(self):
        self.environment = []
        owner = 'restore-receipt-' + uuid.uuid4().hex
        scope = f"principal_id = '{owner}'"
        self.addCleanup(self.sql, f"DELETE FROM public.researcher_create_receipts WHERE {scope};")
        # Explicit old column lists import into the current schema; they do not replace its DDL.
        self.sql("INSERT INTO public.researcher_create_receipts "
                 "(principal_id, route, idempotency_key, request_hash, response_status, sealed_response) "
                 f"VALUES ('{owner}', 'restore-fixture', 'legacy', decode(repeat('ab', 32), 'hex'), 201, 'opaque-legacy'); "
                 "INSERT INTO public.researcher_create_receipts "
                 "(principal_id, owner_kind, route, idempotency_key, request_hash, response_status, sealed_response) "
                 f"VALUES ('{owner}', 'USER', 'restore-fixture', 'user', decode(repeat('ab', 32), 'hex'), 201, 'opaque-user'), "
                 f"('{owner}', 'API_KEY', 'restore-fixture', 'key', decode(repeat('ab', 32), 'hex'), 201, 'opaque-key');")
        snapshot = ("SELECT string_agg(idempotency_key || '|' || owner_kind || '|' || response_status || '|' || "
                    f"sealed_response || '|' || encode(request_hash, 'hex'), ',' ORDER BY idempotency_key) "
                    f"FROM public.researcher_create_receipts WHERE {scope};")
        before = self.sql(snapshot)
        self.assertIn('legacy|LEGACY|201|opaque-legacy', before)
        backup = self.dump('receipt-owner-domains.sql.gz', *DUMP_EXCLUDE_OPTIONS)
        self.sql(f"UPDATE public.researcher_create_receipts SET owner_kind = 'LEGACY', response_status = 418, "
                 f"sealed_response = 'live-only' WHERE {scope};")
        restored = self.restore(backup)
        self.assertEqual(0, restored.returncode, restored.stderr)
        self.assertEqual(before, self.sql(snapshot))
        context = ("BEGIN; SET LOCAL ROLE chronicle_app; SET LOCAL app.is_admin = 'true'; "
                   f"SET LOCAL app.current_user_id = '{owner}'; ")
        query = (f"SELECT coalesce(string_agg(idempotency_key, ',' ORDER BY idempotency_key), '') "
                 f"FROM public.researcher_create_receipts WHERE {scope}; COMMIT;")
        for kind, expected in (('USER', 'user'), ('API_KEY', 'key'), ('LEGACY', ''), ('', '')):
            with self.subTest(kind=kind):
                self.assertEqual(expected, self.sql(context + "SET LOCAL app.is_deletion_worker = 'false'; "
                                 f"SET LOCAL app.receipt_owner_kind = '{kind}'; " + query))
        self.assertEqual('key,legacy,user', self.sql(context + "SET LOCAL app.is_deletion_worker = 'true'; "
                                                   "SET LOCAL app.receipt_owner_kind = ''; " + query))

    @classmethod
    def real_rotation_fixture(cls):
        """The rotation fixture wired to this database: its postgres exec and db-init run for real."""
        from chronicle_ops.envfile import set_env_values
        rotation = Path(tempfile.mkdtemp(prefix="rotation-", dir=cls.work))
        fixture = rotation_fixture(rotation)
        settings = fixture.host / '.env'
        settings.write_text(set_env_values(settings.read_text(), {'POSTGRES_USER': cls.database_user},
                                           require_existing=False))
        adapter = fixture.commands / "docker"
        adapter.rename(fixture.commands / "docker-original")
        # A `kill-after` file names text in one real command; once it succeeds the whole rotation is killed.
        adapter.write_text('''#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import subprocess
import sys
args = sys.argv[1:]
if 'exec' in args and 'postgres' in args:
    command = [{real_docker!r}, 'exec', '-i', {container!r},
               *args[args.index('postgres') + 1:]]
elif 'run' in args and args[-1:] == ['db-init']:
    # The shipped db-init against the live keyring and this installation's ./backups.
    command = [{real_docker!r}, 'exec', '-i', '--user', '0', '-e', 'POSTGRES_HOST=127.0.0.1', {container!r}, 'bash', '-c',
               'ln -sfn "$1" /backups && exec bash /selfhost/db-init.sh', 'db-init', {backups!r}]
else:
    os.execv(str(Path(__file__).with_name('docker-original')), [sys.argv[0], *args])
data = sys.stdin.buffer.read()
status = subprocess.run(command, input=data).returncode
marker = Path(__file__).with_name('kill-after')
if status == 0 and marker.exists() and (marker.read_bytes() in data or marker.read_text() in args):
    sys.stdout.flush()
    os.killpg(0, signal.SIGKILL)
sys.exit(status)
'''.format(real_docker=shutil.which("docker"), container=cls.container,
           backups=cls.container_work + "/" + (fixture.host / "backups").relative_to(cls.work).as_posix()))
        adapter.chmod(0o755)
        return fixture

    @classmethod
    def run_rotation(cls, fixture, *arguments):
        return subprocess.run(["bash", str(fixture.host / "rotate-secret.sh"), "--yes", *arguments], env=fixture.environment,
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300, start_new_session=True)

    @classmethod
    def rotate_deployment_key(cls):
        result = cls.run_rotation(cls.real_rotation_fixture(), "tde")
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        if cls.sql(ACTIVE_KEY_SQL) == "chronicle_key":
            raise AssertionError("rotation did not change the real principal key")

    KEYRING = "/var/lib/postgresql/tde-keyring/chronicle-keyring.per"

    def wait_ready(self, container):
        for _ in range(60):
            if subprocess.run(["docker", "exec", container, "psql", "-XqAt", "-h", "127.0.0.1", "-U", self.database_user,
                               "-d", "chronicle", "-c", "SELECT 1;"], capture_output=True, timeout=10).returncode == 0:
                return
            if self.docker("inspect", "-f", "{{.State.Running}}", container).decode().strip() != "true":
                raise AssertionError("PostgreSQL exited: " + subprocess.run(
                    ["docker", "logs", "--tail", "20", container], capture_output=True, text=True).stderr)
            time.sleep(0.5)
        raise AssertionError("PostgreSQL did not become ready")

    def volume_rows_with_keyring(self, keyring):
        """Copies the stopped data volume onto a fresh one beside only this keyring file and reads every row."""
        from chronicle_ops.images import bundle_config
        fresh = self.container + "-fresh-" + uuid.uuid4().hex[:8]
        self.addCleanup(self.docker, "rm", "-fv", fresh)
        self.docker("create", "--name", fresh, "--network", "none", "--memory", "1g",
                    bundle_config(SELFHOST)['services']['postgres']['image'],
                    "-c", "shared_preload_libraries=pg_tde", "-c", "max_parallel_workers_per_gather=0")
        self.docker("stop", self.container)
        try:
            volume = subprocess.run(["docker", "cp", self.container + ":/data/db", "-"], capture_output=True, timeout=300)
            self.assertEqual(0, volume.returncode, volume.stderr)
        finally:
            self.docker("start", self.container)
            self.wait_ready(self.container)
        self.docker("cp", "-a", "-", fresh + ":/data/", data=volume.stdout)
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            for name, mode, content in (("tde-keyring", 0o700, None), ("tde-keyring/chronicle-keyring.per", 0o600, keyring)):
                entry = tarfile.TarInfo(name)
                entry.uid = entry.gid = 26
                entry.mode = mode
                if content is None:
                    entry.type = tarfile.DIRTYPE
                else:
                    entry.size = len(content)
                tar.addfile(entry, None if content is None else io.BytesIO(content))
        self.docker("cp", "-a", "-", fresh + ":/var/lib/postgresql/", data=archive.getvalue())
        self.docker("start", fresh)
        self.wait_ready(fresh)
        return self.dump_data(fresh)

    def test_interrupted_tde_rotation_recovers_with_readable_rows_and_keyring(self):
        self.environment = []
        stale_keyring = self.docker("exec", self.container, "cat", self.KEYRING)
        # Each kill lands right after one real step: key activation, the db-init keyring copy, and the
        # last verification before the receipt is published.
        cases = (("activate", "pg_tde_set_key_using_database_key_provider", "forward"),
                 ("activate", "pg_tde_set_key_using_database_key_provider", "rollback"),
                 ("keyring", "db-init", "forward"),
                 ("keyring", "db-init", "rollback"),
                 ("receipt", "count(*) FILTER (WHERE a.amname <> 'tde_heap')", "forward"),
                 ("receipt", "count(*) FILTER (WHERE a.amname <> 'tde_heap')", "rollback"))
        for step, marker, direction in cases:
            with self.subTest(step=step, direction=direction):
                expected = self.dump_data()
                fixture = self.real_rotation_fixture()
                # The copy the deployment's last `up` left in ./backups, from before this rotation.
                previous_copy = fixture.host / "backups/keyring/chronicle-keyring.per"
                previous_copy.parent.mkdir(parents=True)
                previous_copy.write_bytes(self.docker("exec", self.container, "cat", self.KEYRING))
                previous_copy.chmod(0o600)
                (fixture.commands / "kill-after").write_text(marker)
                killed = self.run_rotation(fixture, "tde")
                self.assertEqual(-9, killed.returncode, killed.stdout + killed.stderr)
                transaction = fixture.host / ".chronicle-secret-rotation"
                old_key, new_key = ((transaction / name).read_text().strip() for name in ("old-tde-key", "new-tde-key"))
                self.assertFalse(list((fixture.host / "operator-receipts").rglob("*.json")), "a killed rotation published a receipt")
                self.docker("restart", self.container)
                self.wait_ready(self.container)
                self.assertEqual(expected, self.dump_data(), "rows unreadable after the crash and restart")
                (fixture.commands / "kill-after").unlink()
                recovered = self.run_rotation(fixture, "recover", "--" + direction)
                self.assertEqual(0, recovered.returncode, recovered.stdout + recovered.stderr)
                self.assertEqual(new_key if direction == "forward" else old_key, self.sql(ACTIVE_KEY_SQL))
                self.assertFalse(transaction.exists())
                receipt, = (fixture.host / "operator-receipts/secret-rotations").glob("*-tde-recover-" + direction + "-*.json")
                verification = json.loads(receipt.read_text())["verification"]
                self.assertIn("original_phase=" + ("tde-metadata-ready" if step == "activate" else "tde-updated"), verification)
                self.assertIn("keyring_backup=verified", verification)
                live_keyring = self.docker("exec", self.container, "cat", self.KEYRING)
                retained = (fixture.host / "backups/keyring/chronicle-keyring.per").read_bytes()
                self.assertEqual(live_keyring, retained, "the backup set keeps a stale keyring")
                self.assertEqual(expected, self.dump_data())
                self.assertEqual(expected, self.volume_rows_with_keyring(retained),
                                 "the retained keyring cannot open the data volume")
                if (step, direction) == ("activate", "forward"):
                    # Negative control: the keyring from before any of these rotations cannot open the volume.
                    with self.assertRaises(AssertionError):
                        self.volume_rows_with_keyring(stale_keyring)

    @classmethod
    def public_tables(cls):
        return set(json.loads(cls.sql("SELECT json_agg(table_schema || '.' || table_name) "
                                      "FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';")))

    def test_every_public_table_has_a_reviewed_restore_policy(self):
        from chronicle_ops.dump import APPLICATION_TABLE_POLICIES
        expected = set(APPLICATION_TABLE_POLICIES)
        self.assertEqual(expected, self.initial_application_tables)
        for alternate in ('future_credentials', 'renamed_authority', 'arbitrary_state'):
            previous_unclassified = self.public_tables() - expected
            self.sql('CREATE TABLE public.' + alternate + ' (id integer);')
            try:
                self.assertEqual(previous_unclassified | {'public.' + alternate}, self.public_tables() - expected)
            finally:
                self.sql('DROP TABLE public.' + alternate + ';')

    def test_catalog_producer_guard_rejects_unknown_objects(self):
        cases = (
            ("CREATE SCHEMA unclassified_migration;", "DROP SCHEMA unclassified_migration;"),
            ("CREATE EXTENSION hstore;", "DROP EXTENSION hstore;"),
            ("CREATE ROLE unclassified_owner; CREATE TABLE public.unknown_owner (value integer); "
             "ALTER TABLE public.unknown_owner OWNER TO unclassified_owner;",
             "DROP TABLE public.unknown_owner; DROP ROLE unclassified_owner;"),
            ("CREATE COLLATION public.unknown_kind (provider = libc, locale = 'C');",
             "DROP COLLATION public.unknown_kind;"),
            ("CREATE FOREIGN DATA WRAPPER unknown_global;", "DROP FOREIGN DATA WRAPPER unknown_global;"),
            ("CREATE ACCESS METHOD unknown_method TYPE TABLE HANDLER heap_tableam_handler;",
             "DROP ACCESS METHOD unknown_method;"),
            ("ALTER DEFAULT PRIVILEGES FOR ROLE chronicle_admin IN SCHEMA public GRANT SELECT ON TABLES TO chronicle_app;",
             "ALTER DEFAULT PRIVILEGES FOR ROLE chronicle_admin IN SCHEMA public REVOKE SELECT ON TABLES FROM chronicle_app;"),
        )
        for create, cleanup in cases:
            with self.subTest(create=create):
                self.sql(CATALOG_GATE_SQL)
                self.sql(create)
                try:
                    with self.assertRaisesRegex(AssertionError, UNCLASSIFIED_OBJECTS):
                        self.sql(CATALOG_GATE_SQL)
                finally:
                    self.sql(cleanup)
        self.sql("CREATE TABLE public.extension_probe (id integer); ALTER EXTENSION pg_tde ADD TABLE public.extension_probe;")
        try:
            self.sql(CATALOG_GATE_SQL)
            self.sql("CREATE SEQUENCE public.extension_probe_sequence OWNED BY public.extension_probe.id;")
            with self.assertRaisesRegex(AssertionError, UNCLASSIFIED_OBJECTS):
                self.sql(CATALOG_GATE_SQL)
        finally:
            self.sql("DROP SEQUENCE IF EXISTS public.extension_probe_sequence; "
                     "ALTER EXTENSION pg_tde DROP TABLE public.extension_probe; DROP TABLE public.extension_probe;")

    def catalog(self):
        rows = json.loads(self.sql("""
SELECT json_agg(snapshot ORDER BY kind, identity) FROM (
  SELECT c.*, CASE WHEN t.tgisinternal AND t.tgconstraint <> 0 THEN
    format('%s/%s/%s/%s', (pg_identify_object('pg_constraint'::regclass, t.tgconstraint, 0)).identity,
           t.tgrelid::regclass, t.tgfoid::regprocedure, t.tgtype)
    ELSE c.identity END AS comparison_identity
  FROM (""" + CATALOG_SQL + """) c
  LEFT JOIN pg_trigger t ON c.classid = 'pg_trigger'::regclass AND c.objid = t.oid
) snapshot;
"""))
        self.assertTrue(rows)
        self.assertTrue(all(row["source"] is not None for row in rows))
        counts = {}
        for row in rows:
            counts[row["kind"]] = counts.get(row["kind"], 0) + 1
        print("Classified catalog:", json.dumps(counts, sort_keys=True), flush=True)
        objects = {(row["classid"], row["kind"], row["comparison_identity"]): row for row in rows}
        self.assertEqual(len(rows), len(objects))
        return objects

    def dump_data(self, container=None):
        return self.docker("exec", container or self.container, "pg_dump", "-U", self.database_user, "-d", "chronicle",
                           "--data-only", "--no-owner", "--restrict-key=AQRestoreState", "--exclude-table-data=" + SESSION_STATE_TABLE,
                           "--exclude-table-data=public.chronicle_participant_token_key", *DUMP_EXCLUDE_OPTIONS)

    def pilot_rows(self, table):
        return sorted(json.dumps(row, sort_keys=True, ensure_ascii=False) for row in json.loads(self.sql(pilot_read_sql(table))))

    def assert_pilot_table(self, expected, table):
        wanted = sorted(json.dumps(row, sort_keys=True, ensure_ascii=False) for row in expected[table])
        actual = self.pilot_rows(table)
        if actual != wanted:
            missing, extra = sorted(set(wanted) - set(actual)), sorted(set(actual) - set(wanted))
            self.fail(f"{table}: {len(actual)} rows, expected {len(wanted)}; missing {missing[:3]}; unexpected {extra[:3]}")

    def test_pilot_dataset_survives_shipped_backup_and_restore(self):
        self.environment = []
        expected = pilot_dataset()
        modules = json.dumps(expected["studies"][0][3])
        self.sql(f"INSERT INTO public.studies (study_id, title, settings, modules) VALUES ('{PILOT_STUDY}', "
                 f"'Estudio piloto', '{json.dumps(pilot_settings(1))}', '{modules}');" +
                 "".join(f"UPDATE public.studies SET settings = '{json.dumps(pilot_settings(version))}' "
                         f"WHERE study_id = '{PILOT_STUDY}';" for version in (2, 3)))
        self.sql(pilot_copy_sql(expected))
        for table in PILOT_COLUMNS:
            self.assert_pilot_table(expected, table)
        dump_path = backup_marker(self.work, "chronicle").parent / "chronicle-pilot.sql.gz"
        dump_path.parent.mkdir()
        # The next restore test publishes into the same backup folder.
        self.addCleanup(dump_path.parent.rename, self.work / "pilot-backups")
        self.docker("exec", "--user", "0", "-e", "PGUSER=" + self.database_user,
                    "-e", "PGHOST=127.0.0.1", self.container, "python3", "/selfhost/backup-image/selfcheck.py",
                    "dump", "chronicle", self.container_path(dump_path), "-Z1", "--no-owner")
        self.assertGreater(dump_path.stat().st_size, 1024 * 1024, "the pilot dump must be materially larger than catalog probes")
        # Damage after the backup, across every snapshot-restored pilot table, including the repeated DST hour.
        fold_hour = "event_timestamp >= '2026-04-05 02:00Z' AND event_timestamp < '2026-04-05 04:00Z'"
        self.sql(f"DELETE FROM public.chronicle_usage_events WHERE participant_id = 'CL-004'; "
                 f"DELETE FROM public.chronicle_usage_events WHERE participant_id = 'CL-001' AND {fold_hour}; "
                 "INSERT INTO public.chronicle_usage_events SELECT study_id, participant_id, app_package_name, activity_class, "
                 "interaction_type, event_type, event_timestamp, timezone, username, application_label, uploaded_at + interval '1 day', "
                 "client_event_id || '-late' FROM public.chronicle_usage_events WHERE participant_id = 'CL-008'; "
                 "UPDATE public.chronicle_usage_events SET username = 'Someone else', activity_class = NULL "
                 "WHERE participant_id = 'CL-016' AND event_timestamp >= '2026-09-06 03:00Z' AND event_timestamp < '2026-09-06 05:00Z'; "
                 "DELETE FROM public.chronicle_usage_stats WHERE participant_id = 'CL-010'; "
                 "DELETE FROM public.upload_buffer; "
                 "UPDATE public.battery_telemetry SET level_percent = 0 WHERE participant_id = 'CL-006'; "
                 "DELETE FROM public.android_device_sensor_availability WHERE participant_id = 'CL-014'; "
                 "UPDATE public.upload_diagnostics SET occurrence_count = 99 WHERE participant_id = 'CL-020'; "
                 "UPDATE public.app_usage_survey SET users = '{}' WHERE participant_id = 'CL-012'; "
                 "UPDATE public.devices SET source_device = '{}' WHERE participant_id = 'CL-001'; "
                 "DELETE FROM public.participant_stats WHERE participant_id = 'CL-025';")
        for table in ("chronicle_usage_events", "chronicle_usage_stats", "upload_buffer", "battery_telemetry", "devices",
                      "android_device_sensor_availability", "upload_diagnostics", "app_usage_survey", "participant_stats"):
            with self.assertRaises(AssertionError, msg=table):
                self.assert_pilot_table(expected, table)
        result = self.restore(dump_path)
        self.assertEqual(0, result.returncode, result.stderr)
        for table in PILOT_COLUMNS:
            with self.subTest(table=table):
                self.assert_pilot_table(expected, table)

    def test_deployment_dump_restores_all_classes_and_keeps_live_evidence(self):
        self.environment = []
        self.addCleanup(self.sql,
                        "DROP MATERIALIZED VIEW IF EXISTS public.restore_materialized; "
                        "DROP VIEW IF EXISTS public.restore_probe_view; "
                        "DROP TABLE IF EXISTS public.restore_probe, public.restore_partitioned, public.restore_live_only CASCADE; "
                        "DROP PROCEDURE IF EXISTS public.restore_procedure(); "
                        "DROP FUNCTION IF EXISTS public.restore_probe_function(); "
                        "DROP TYPE IF EXISTS public.restore_composite, public.restore_value CASCADE; "
                        "DROP DOMAIN IF EXISTS public.restore_positive;")
        self.sql("CREATE TYPE public.restore_value AS ENUM ('dump', 'live-only'); "
                 "CREATE DOMAIN public.restore_positive AS integer CHECK (VALUE > 0); "
                 "CREATE TYPE public.restore_composite AS (value public.restore_value); "
                 "CREATE TABLE public.restore_probe (id bigint GENERATED ALWAYS AS IDENTITY, "
                 "value public.restore_value, positive public.restore_positive DEFAULT 1); "
                 "INSERT INTO public.restore_probe(value) VALUES ('dump'); "
                 "CREATE TABLE public.restore_partitioned (id integer PRIMARY KEY) PARTITION BY RANGE (id); "
                 "CREATE TABLE public.restore_partitioned_child PARTITION OF public.restore_partitioned FOR VALUES FROM (0) TO (10); "
                 "INSERT INTO public.restore_partitioned VALUES (5); "
                 "ALTER TABLE public.restore_probe OWNER TO chronicle_admin; "
                 "CREATE VIEW public.restore_probe_view AS SELECT * FROM public.restore_probe; "
                 "CREATE MATERIALIZED VIEW public.restore_materialized AS SELECT * FROM public.restore_probe; "
                 "CREATE PROCEDURE public.restore_procedure() LANGUAGE plpgsql AS $$BEGIN NULL; END$$; "
                 "CREATE FUNCTION public.restore_probe_function() RETURNS text LANGUAGE sql AS $$SELECT 'dump'::text$$;")
        initial = self.dump("initial.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        self.assertEqual(0, self.restore(initial).returncode)
        self.sql("CREATE SEQUENCE chronicle_restore_continuity.probe_sequence; "
                 "CREATE TABLE chronicle_restore_continuity.probe (value text); "
                 "INSERT INTO chronicle_restore_continuity.probe VALUES ('live'); "
                 "CREATE FUNCTION chronicle_restore_continuity.probe_function() RETURNS text "
                 "LANGUAGE sql AS $$SELECT 'live'::text$$; "
                 "SELECT nextval('chronicle_restore_continuity.probe_sequence'); "
                 "ALTER TABLE public.restore_probe OWNER TO chronicle_admin;")
        before = self.catalog()
        expected_data = self.dump_data()
        participant_token = self.sql(PARTICIPANT_TOKEN_SQL)
        key, active_key = self.sql(KEY_EVIDENCE_SQL), self.sql(ACTIVE_KEY_SQL)
        # The shipped backup self-check exercises its snapshot gate and TDE scratch bootstrap.
        dump_path = backup_marker(self.work, "chronicle").parent / "chronicle-deployment.sql.gz"
        dump_path.parent.mkdir()
        self.docker("exec", "--user", "0", "-e", "PGUSER=" + self.database_user,
                    "-e", "PGHOST=127.0.0.1", self.container, "python3", "/selfhost/backup-image/selfcheck.py",
                    "dump", "chronicle", self.container_path(dump_path), "-Z1", "--no-owner")
        self.sql("UPDATE public.restore_probe SET value = 'live-only'; "
                 "CREATE TABLE public.restore_live_only (id serial PRIMARY KEY); "
                 "INSERT INTO public.restore_partitioned VALUES (6); "
                 "SELECT nextval('public.restore_probe_id_seq'); "
                 "CREATE OR REPLACE FUNCTION public.restore_probe_function() RETURNS text "
                 "LANGUAGE sql AS $$SELECT 'live-only'::text$$; "
                 "UPDATE chronicle_restore_continuity.probe SET value = 'live-after-backup'; "
                 "SELECT nextval('chronicle_restore_continuity.probe_sequence');")
        result = self.restore(dump_path)
        self.assertEqual(0, result.returncode, result.stderr)
        after = self.catalog()
        self.assertEqual({key: row["source"] for key, row in before.items()},
                         {key: row["source"] for key, row in after.items()})
        for identity, row in before.items():
            if row["source"] == RestoreSource.LIVE:
                self.assertEqual(row["objid"], after[identity]["objid"], identity)
                self.assertEqual(row["objsubid"], after[identity]["objsubid"], identity)
        self.assertEqual(expected_data, self.dump_data())
        self.assertEqual(participant_token, self.sql(PARTICIPANT_TOKEN_SQL))
        self.assertEqual(self.database_user, self.sql("SELECT tableowner FROM pg_tables "
                                                      "WHERE schemaname = 'public' AND tablename = 'restore_probe';"))
        self.assertEqual("1|dump|1", self.sql("SELECT * FROM public.restore_probe_view;"))
        self.assertEqual("1|dump|1", self.sql("SELECT * FROM public.restore_materialized;"))
        self.assertEqual("dump", self.sql("SELECT public.restore_probe_function();"))
        self.assertEqual("1|t", self.sql("SELECT last_value, is_called FROM public.restore_probe_id_seq;"))
        self.assertEqual("live-after-backup", self.sql("SELECT value FROM chronicle_restore_continuity.probe;"))
        self.assertEqual("live", self.sql("SELECT chronicle_restore_continuity.probe_function();"))
        self.assertEqual("2|t", self.sql("SELECT last_value, is_called FROM chronicle_restore_continuity.probe_sequence;"))
        self.assertEqual(key, self.sql(KEY_EVIDENCE_SQL))
        self.assertEqual(active_key, self.sql(ACTIVE_KEY_SQL))
        self.assertEqual("0", self.sql("SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'chronicle_restore_saved_%';"))
        self.assertEqual("3", self.sql("SELECT count(*) FROM pg_roles WHERE rolname IN "
                                       "('chronicle', 'chronicle_app', 'chronicle_admin');"))

    def test_writers_and_restore_refuse_unknown_producer_schema(self):
        self.environment = []
        path = self.dump("writer-guard.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        active_key = self.sql(ACTIVE_KEY_SQL)
        self.sql("CREATE SCHEMA unknown_producer;")
        try:
            with self.assertRaisesRegex(AssertionError, UNCLASSIFIED_OBJECTS):
                self.docker("exec", self.container, "bash", "-ceu", ROLLBACK_DUMP)
            with self.assertRaisesRegex(AssertionError, UNCLASSIFIED_OBJECTS):
                self.docker("exec", "--user", "0", "-e", "PGUSER=" + self.database_user,
                            "-e", "PGHOST=127.0.0.1", self.container, "python3", "/selfhost/backup-image/selfcheck.py",
                            "dump", "chronicle", self.container_path(self.work / "refused.sql.gz"), "-Z1", "--no-owner")
            with self.assertRaisesRegex(AssertionError, UNCLASSIFIED_OBJECTS):
                self.rotate_deployment_key()
            self.assertEqual(EXIT_REJECTED_BEFORE_MUTATION, self.restore(path).returncode)
            self.assertEqual(active_key, self.sql(ACTIVE_KEY_SQL))
        finally:
            self.sql("DROP SCHEMA unknown_producer;")


if __name__ == "__main__":
    unittest.main()
