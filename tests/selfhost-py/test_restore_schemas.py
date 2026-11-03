"""Execute the shipped restore service against the release-pinned pg_tde image."""

import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "selfhost"))
import chronicle_ops
from chronicle_ops.dump import RESTORE_MUTATION_MARKER, COMPLETE, validate_dump, EXIT_REJECTED_BEFORE_MUTATION, EXIT_RESTORE_TRANSACTION_ROLLED_BACK, LIVE_OBJECTS_CHANGED, PRESERVED_EXTENSIONS, PRESERVED_SCHEMAS, DUMP_EXCLUDE_OPTIONS, TDE_GENERATION_SCHEMA as KEY_SCHEMA, UNCLASSIFIED_OBJECTS
from chronicle_ops import release
from chronicle_ops.release import ROLLBACK_DUMP
from chronicle_ops.verify import DATABASE_PRIVILEGES_SQL
from selfhost_fixture import FIXTURE_POSTGRES_APP_PASSWORD, FIXTURE_POSTGRES_PASSWORD, postgres_image, rotation_fixture
from test_restore import DUMP


ROOT = Path(__file__).resolve().parents[2]
SELFHOST = Path(chronicle_ops.__file__).resolve().parents[1]
KEY_EVIDENCE_SQL = f"SELECT row_to_json(k) FROM {KEY_SCHEMA}.chronicle_generated_key k;"
KEY_SCHEMA_OID_SQL = f"SELECT '{KEY_SCHEMA}'::regnamespace::oid;"
ACTIVE_KEY_SQL = "SELECT key_name FROM pg_tde_key_info();"
AUDIT_ROWS_SQL = "SELECT event FROM public.audit;"
AUDIT_COUNT_SQL = "SELECT count(*) FROM public.audit;"
INSERT_LIVE_AUDIT_SQL = "INSERT INTO public.audit VALUES ('live-only');"


class PgTdeFixture(unittest.TestCase):
    database_user = "chronicle"
    network_options = ("--network", "none")
    container_work = "/work"
    postgres_options = ()

    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix="restore-schemas-")
        cls.addClassCleanup(cls.folder.cleanup)
        cls.work = Path(cls.folder.name)
        (cls.work / "commands").mkdir()
        cls.container = "chronicle-restore-schema-test-" + uuid.uuid4().hex
        cls.start_database()
        cls.addClassCleanup(cls.docker, "rm", "-fv", cls.container)

    @classmethod
    def start_database(cls, initialize_tde=True):
        image = postgres_image()
        cls.docker("run", "-d", "--name", cls.container, *cls.network_options, "--memory", "1g",
                   "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-e", "POSTGRES_USER=" + cls.database_user,
                   "-e", "POSTGRES_INITDB_ARGS=--encoding=UTF8",
                   "-e", "POSTGRES_DB=chronicle", "-e", "POSTGRES_PASSWORD=" + FIXTURE_POSTGRES_PASSWORD,
                   "-e", "POSTGRES_APP_PASSWORD=" + FIXTURE_POSTGRES_APP_PASSWORD,
                   "-v", f"{SELFHOST}:/selfhost:ro", "-v", f"{cls.work}:{cls.container_work}",
                   image, "-c", "shared_preload_libraries=pg_tde", "-c", "max_parallel_workers_per_gather=0", *cls.postgres_options)
        for _ in range(60):
            probe = subprocess.run(["docker", "exec", cls.container, "psql", "-XqAt", "-h", "127.0.0.1",
                                    "-U", cls.database_user, "-d", "chronicle", "-c", "SELECT 1;"],
                                   capture_output=True, timeout=10)
            if probe.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise AssertionError("isolated PostgreSQL did not become ready")
        if initialize_tde:
            cls.docker("exec", "--user", "0", "-e", "POSTGRES_HOST=127.0.0.1", cls.container,
                       "bash", "/selfhost/init-tde.sh")

    @classmethod
    def load_application_fixture(cls):
        cls.sql((Path(__file__).with_name("restore_schema_fixture.sql")).read_text())

    @classmethod
    def docker(cls, *args, data=None):
        result = subprocess.run(["docker", *args], input=data, capture_output=True, timeout=120)
        if result.returncode:
            raise AssertionError((result.stdout + result.stderr).decode(errors="replace"))
        return result.stdout

    @classmethod
    def sql(cls, query):
        return cls.docker("exec", "-i", cls.container, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1",
                          "-U", cls.database_user, "-d", "chronicle",
                          data=("SET max_parallel_workers_per_gather=0; " + query).encode()).decode().strip()


    def dump(self, name, *options):
        data = self.docker("exec", self.container, "pg_dump", "-U", self.database_user, "-d", "chronicle",
                           "--no-owner", *options)
        path = self.work / name
        path.write_bytes(gzip.compress(data))
        return path

    def container_path(self, path):
        return self.container_work + "/" + path.relative_to(self.work).as_posix()

    def restore(self, path, backups=None):
        restore_file = self.container_path(path)
        digest = self.docker("exec", "--user", "0", self.container, "sha256sum", restore_file).decode().split()[0]
        result = subprocess.run([
            "docker", "exec", "--user", "0", "-e", "POSTGRES_HOST=127.0.0.1", "-e", "CHRONICLE_RESTORE_ORCHESTRATED=true",
            "-e", "POSTGRES_USER=" + self.database_user,
            "-e", f"PATH={self.container_work}/commands:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "-e", "BACKUPS_DIR=" + (self.container_path(backups) if backups else self.container_work), "-e", "RESTORE_FILE=" + restore_file,
            "-e", "CHRONICLE_RESTORE_TRUSTED_SHA256=" + digest,
            *self.environment, self.container, "bash", "/selfhost/restore.sh"], capture_output=True, text=True, timeout=120)
        print(result.stdout + result.stderr, flush=True)
        return result


class RestoreSchemaTests(PgTdeFixture):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.load_application_fixture()
        cls.key_before = cls.sql(KEY_EVIDENCE_SQL)
        cls.key_schema_oid = cls.sql(KEY_SCHEMA_OID_SQL)
        cls.active_key = cls.sql(ACTIVE_KEY_SQL)

    def setUp(self):
        (self.work / RESTORE_MUTATION_MARKER).unlink(missing_ok=True)
        self.environment = []
        self.sql("DROP SCHEMA IF EXISTS chronicle_restore_continuity CASCADE; "
                 "DROP SCHEMA IF EXISTS restore_extra CASCADE; DROP SCHEMA IF EXISTS live_only CASCADE; "
                 "TRUNCATE public.audit; INSERT INTO public.audit VALUES ('backup-row');")

    def assert_live_key_preserved(self):
        self.assertEqual(self.key_before, self.sql(KEY_EVIDENCE_SQL))
        self.assertEqual(self.active_key, self.sql(ACTIVE_KEY_SQL))
        self.assertEqual(self.key_schema_oid, self.sql(KEY_SCHEMA_OID_SQL))
        self.assertEqual("t", self.sql("SELECT pg_tde_is_encrypted('public.audit'::regclass);"))

    def test_pre_mutation_failures_restore_the_previous_service_state(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from chronicle_ops.restore import Restore
        path = self.dump("pre-mutation.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        for command in ("gzip", "pg_dump", "psql"):
            with self.subTest(command=command):
                adapter = self.work / "commands" / command
                adapter.write_text("#!/bin/bash\nexit 1\n")
                adapter.chmod(0o755)
                calls = []
                def compose(*args, **kwargs):
                    calls.append(args)
                    output = "postgres\nbackend\nweb\nrestore"
                    if "ps" in args:
                        output = "postgres\nbackend\nweb" if len(calls) == 2 else "postgres"
                    if "run" in args:
                        result = self.restore(path)
                        return SimpleNamespace(returncode=result.returncode, stdout=result.stdout)
                    return SimpleNamespace(returncode=0, stdout=output)
                state = self.work / ("state-" + command); state.mkdir()
                operation = Restore(state, self.work, "/backups/" + path.name,
                                    hashlib.sha256(path.read_bytes()).hexdigest(), "17", False, True)
                try:
                    with patch("chronicle_ops.restore.compose", compose), patch("chronicle_ops.restore.finish_operation"):
                        self.assertEqual(1, operation.execute())
                    self.assertFalse(operation.lock.exists(), "pre-mutation failure stranded the restore lock")
                    self.assertTrue(any("--no-deps" in args for args in calls), "running services were not recovered")
                    self.assertEqual("backup-row", self.sql(AUDIT_ROWS_SQL))
                finally:
                    adapter.unlink()

    def test_restore_onto_an_empty_application_database(self):
        from chronicle_ops.dump import RESTORE_PREPARE_SQL, RESTORE_RECOVER_SCHEMAS_SQL, CATALOG_CAPTURE_SQL
        path = self.dump("fresh-volume.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        self.sql("BEGIN; " + CATALOG_CAPTURE_SQL + RESTORE_PREPARE_SQL + RESTORE_RECOVER_SCHEMAS_SQL + "COMMIT;")
        result = self.restore(path)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("backup-row", self.sql(AUDIT_ROWS_SQL))
        self.assertEqual("", self.sql("SELECT to_regnamespace('chronicle_restore_continuity');"))
        self.assert_live_key_preserved()

    def test_restore_invalidates_pre_restore_researcher_sessions(self):
        self.sql("TRUNCATE public.jwt_session_state;")
        path = self.dump("researcher-session.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        before = self.sql("SELECT extract(epoch FROM now())::bigint;")
        result = self.restore(path)
        self.assertEqual(0, result.returncode, result.stderr)
        cutoff = self.sql("SELECT max(state_value) FROM public.jwt_session_state WHERE expires_at IS NULL;")
        self.assertTrue(cutoff, "restore retained signing authority without a session cutoff")
        self.assertGreaterEqual(int(cutoff), int(before))

    def test_restore_clears_bootstrap_defaults_and_rolls_back_forbidden_grants(self):
        path = self.dump('acl-preserved.sql.gz', *DUMP_EXCLUDE_OPTIONS)
        self.sql('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO chronicle_app, chronicle_admin; '
                 'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO chronicle_app, chronicle_admin; '
                 'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO chronicle_app, chronicle_admin;')
        restored = self.restore(path)
        self.assertEqual(0, restored.returncode, restored.stderr)
        self.assertEqual('t', self.sql(DATABASE_PRIVILEGES_SQL))
        self.assertEqual('t', self.sql("""SELECT NOT EXISTS (
            SELECT 1 FROM pg_default_acl defaults CROSS JOIN LATERAL aclexplode(defaults.defaclacl) acl
            WHERE defaults.defaclrole = current_user::regrole AND defaults.defaclnamespace = 'public'::regnamespace
              AND acl.grantee IN ('chronicle_app'::regrole, 'chronicle_admin'::regrole));"""))
        hostile = self.work / 'acl-escalation.sql.gz'
        hostile.write_bytes(gzip.compress(gzip.decompress(path.read_bytes()).replace(
            COMPLETE, b'GRANT UPDATE ON public.audit TO chronicle_app;\n' + COMPLETE)))
        self.sql(INSERT_LIVE_AUDIT_SQL)
        rejected = self.restore(hostile)
        self.assertEqual(EXIT_RESTORE_TRANSACTION_ROLLED_BACK, rejected.returncode, rejected.stderr)
        self.assertIn('violates audit/restore least privilege', rejected.stderr)
        self.assertEqual('2', self.sql(AUDIT_COUNT_SQL))
        self.assertEqual('t', self.sql(DATABASE_PRIVILEGES_SQL))
        self.assert_live_key_preserved()

    def test_participant_token_key_generation_mismatch_rolls_back_restore(self):
        path = self.dump("participant-token-key.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        try:
            self.sql("UPDATE public.chronicle_participant_token_key SET key_bytes = decode(repeat('cd', 32), 'hex');")
            result = self.restore(path)
            self.assertEqual(EXIT_RESTORE_TRANSACTION_ROLLED_BACK, result.returncode, result.stderr)
            self.assertIn("Participant token key differs from protected restore checkpoint", result.stderr)
            self.assertEqual("t", self.sql("SELECT key_bytes = decode(repeat('cd', 32), 'hex') "
                                         "FROM public.chronicle_participant_token_key;"))
            self.assert_live_key_preserved()
        finally:
            self.sql("UPDATE public.chronicle_participant_token_key SET key_bytes = decode(repeat('ab', 32), 'hex');")

    def test_collection_features_survive_real_restore_checkpoint(self):
        study_id = str(uuid.uuid4())
        setting = {"settingsVersion": 1}
        features = {"CHRONICLE_DATA_COLLECTION": {}}
        self.sql(f"INSERT INTO studies (study_id, settings, modules) VALUES ('{study_id}', "
                 f"'{json.dumps({'DataCollection': setting})}', '{json.dumps(features)}'); "
                 f"INSERT INTO data_collection_settings_revisions VALUES ('{study_id}', 1, "
                 f"'{json.dumps(setting)}', '{json.dumps(features)}', now());")
        path = self.dump("collection-features.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        setting["settingsVersion"] = 2
        self.sql(f"UPDATE studies SET settings = '{json.dumps({'DataCollection': setting})}', modules = '{{}}' "
                 f"WHERE study_id = '{study_id}'; "
                 f"INSERT INTO data_collection_settings_revisions VALUES ('{study_id}', 2, "
                 f"'{json.dumps(setting)}', '{{}}', now());")
        current_backup = self.work / "collection-current.sql.gz"
        conflicting_backup = self.work / "collection-conflicting.sql.gz"
        for candidate, modules in {conflicting_backup: features, current_backup: {}}.items():
            self.sql(f"UPDATE data_collection_settings_revisions SET study_modules = '{json.dumps(modules)}' "
                     f"WHERE study_id = '{study_id}' AND settings_version = 2;")
            self.dump(candidate.name, *DUMP_EXCLUDE_OPTIONS)
        try:
            result = self.restore(path)
            self.assertEqual(0, result.returncode, result.stderr)
            rows = json.loads(self.sql("SELECT json_agg(row_to_json(r) ORDER BY settings_version) FROM "
                              "chronicle_restore_continuity.data_collection_settings_revisions r;"))
            revisions = [row for row in rows if row["study_id"] == study_id]
            self.assertEqual([features, {}], [row["study_modules"] for row in revisions])
            published = json.loads(self.sql("SELECT row_to_json(p) FROM "
                                   "chronicle_restore_continuity.published_data_collection_settings p "
                                   f"WHERE study_id = '{study_id}';"))
            self.assertEqual({}, published["study_modules"])
            self.assertEqual(2, published["settings_version"])
            self.assertEqual("2|1", self.sql("SELECT collection_revision_count, published_collection_settings_count "
                                           "FROM chronicle_restore_continuity.checkpoint;"))
            digest_sql = (SELFHOST / "restore-continuity-digest.sql").read_text() + "SELECT value FROM digest;"
            before = self.sql(digest_sql)
            for modules in (features, {}):
                self.sql("UPDATE chronicle_restore_continuity.published_data_collection_settings "
                         f"SET study_modules = '{json.dumps(modules)}' WHERE study_id = '{study_id}';")
                self.assertEqual(bool(modules), before != self.sql(digest_sql))
            self.environment = ["-e", "CHRONICLE_RESTORE_ROLLBACK=true"]
            rejected = self.restore(conflicting_backup)
            self.assertEqual(EXIT_RESTORE_TRANSACTION_ROLLED_BACK, rejected.returncode, rejected.stderr)
            self.assertEqual("1", self.sql("SELECT count(*) FROM chronicle_restore_continuity.checkpoint;"))
            accepted = self.restore(current_backup)
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            self.assertEqual("", self.sql("SELECT to_regnamespace('chronicle_restore_continuity');"))
            self.assert_live_key_preserved()
        finally:
            self.sql(f"DELETE FROM studies WHERE study_id = '{study_id}'; "
                     f"DELETE FROM data_collection_settings_revisions WHERE study_id = '{study_id}';")

    def test_candidate_dump_over_existing_key_evidence(self):
        # Give the source evidence a different generation date for the same key name.
        self.sql(f"UPDATE {KEY_SCHEMA}.chronicle_generated_key SET generated_at = '2000-01-01Z';")
        path = self.dump("candidate.sql.gz")
        self.sql(f"UPDATE {KEY_SCHEMA}.chronicle_generated_key SET generated_at = "
                 f"('{self.key_before}'::json->>'generated_at')::timestamptz;")
        self.sql(INSERT_LIVE_AUDIT_SQL)
        result = self.restore(path)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("backup-row", self.sql(AUDIT_ROWS_SQL))
        self.assert_live_key_preserved()

    def test_older_dump_without_key_evidence(self):
        path = self.dump("older.sql.gz", "--exclude-schema=" + KEY_SCHEMA)
        self.sql(INSERT_LIVE_AUDIT_SQL)
        result = self.restore(path)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("backup-row", self.sql(AUDIT_ROWS_SQL))
        self.assert_live_key_preserved()

    def test_failed_restore_preserves_live_schema_and_key(self):
        path = self.dump("invalid.sql.gz")
        data = gzip.decompress(path.read_bytes()).replace(
            COMPLETE, b"SELECT pg_catalog.setval('public.missing_seq', 1, false);\n" + COMPLETE)
        path.write_bytes(gzip.compress(data))
        self.sql(INSERT_LIVE_AUDIT_SQL)
        result = self.restore(path)
        self.assertEqual(EXIT_RESTORE_TRANSACTION_ROLLED_BACK, result.returncode, result.stderr)
        self.assertIn('relation "public.missing_seq" does not exist', result.stderr)
        self.assertEqual("2", self.sql(AUDIT_COUNT_SQL))
        self.assert_live_key_preserved()

    def test_unknown_live_schema_is_rejected_before_mutation(self):
        path = self.dump("unknown-schema.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        self.sql("CREATE SCHEMA live_only; CREATE TABLE live_only.marker (value integer); "
                 "INSERT INTO live_only.marker VALUES (42);")
        result = self.restore(path)
        self.assertEqual(EXIT_REJECTED_BEFORE_MUTATION, result.returncode, result.stderr)
        self.assertEqual("42", self.sql("SELECT value FROM live_only.marker;"))
        self.assertEqual("", self.sql("SELECT to_regnamespace('chronicle_restore_continuity');"))
        self.assert_live_key_preserved()

    def test_unknown_dump_schema_rolls_back(self):
        self.sql("CREATE SCHEMA restore_extra; CREATE TABLE restore_extra.marker (value integer);")
        path = self.dump("unknown-dump-schema.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        self.sql("DROP SCHEMA restore_extra CASCADE;")
        self.sql(INSERT_LIVE_AUDIT_SQL)
        result = self.restore(path)
        self.assertEqual(EXIT_RESTORE_TRANSACTION_ROLLED_BACK, result.returncode, result.stderr)
        self.assertIn(UNCLASSIFIED_OBJECTS, result.stderr)
        self.assertEqual("2", self.sql(AUDIT_COUNT_SQL))
        self.assertEqual("", self.sql("SELECT to_regnamespace('restore_extra');"))
        self.assert_live_key_preserved()

    def test_preserved_dependency_cannot_be_silently_dropped(self):
        self.sql("CREATE TABLE public.restore_anchor (id integer PRIMARY KEY); "
                 f"CREATE TABLE {KEY_SCHEMA}.restore_reference (id integer REFERENCES public.restore_anchor) USING heap;")
        self.addCleanup(self.sql, f"DROP TABLE IF EXISTS {KEY_SCHEMA}.restore_reference; "
                                 "DROP TABLE IF EXISTS public.restore_anchor;")
        constraint = self.sql(f"SELECT oid FROM pg_constraint WHERE conrelid = '{KEY_SCHEMA}.restore_reference'::regclass;")
        path = self.dump("cross-schema-dependency.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        self.sql(INSERT_LIVE_AUDIT_SQL)
        result = self.restore(path)
        self.assertEqual(EXIT_RESTORE_TRANSACTION_ROLLED_BACK, result.returncode, result.stderr)
        self.assertIn(LIVE_OBJECTS_CHANGED, result.stderr)
        self.assertEqual(constraint, self.sql(f"SELECT oid FROM pg_constraint "
                                             f"WHERE conrelid = '{KEY_SCHEMA}.restore_reference'::regclass;"))
        self.assertEqual("2", self.sql(AUDIT_COUNT_SQL))
        self.assert_live_key_preserved()

    def test_real_dump_passes_and_server_access_statements_are_refused_before_mutation(self):
        path = self.dump("server-access.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        self.assertGreater(validate_dump(path), 0)
        self.sql(INSERT_LIVE_AUDIT_SQL)
        specimens = (b"SELECT lo_export(lo_import('/etc/passwd'), '/tmp/chronicle-exported');",
                     b"SELECT length(pg_read_file('/etc/passwd'));",
                     b"ALTER ROLE chronicle_app SUPERUSER;",
                     b"COPY public.audit (event) FROM '/etc/passwd';",
                     b"CREATE ROLE imported_live_role;")
        for specimen in specimens:
            with self.subTest(specimen=specimen):
                hostile = self.work / "hostile.sql.gz"
                hostile.write_bytes(gzip.compress(gzip.decompress(path.read_bytes()).replace(COMPLETE, specimen + b"\n" + COMPLETE)))
                result = self.restore(hostile)
                self.assertEqual(EXIT_REJECTED_BEFORE_MUTATION, result.returncode, result.stderr)
                self.assertIn("contains executable commands", result.stderr)
                self.assertEqual("2", self.sql(AUDIT_COUNT_SQL))
                self.assertEqual("f", self.sql("SELECT rolsuper FROM pg_roles WHERE rolname = 'chronicle_app';"))
        self.assertEqual("0", self.sql("SELECT count(*) FROM pg_roles WHERE rolname = 'imported_live_role';"))
        self.assert_live_key_preserved()

    def test_withdrawal_after_backup_stays_contained_after_restore(self):
        study_id, key_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.sql(f"INSERT INTO study_participants VALUES ('{study_id}', 'withdrawn-later', 'ENROLLED', NULL, now()); "
                 f"INSERT INTO api_keys VALUES ('{key_id}', '{study_id}', 'withdrawn-later', NULL, false);")
        self.addCleanup(self.sql, f"DELETE FROM study_participants WHERE study_id = '{study_id}'; "
                                  f"DELETE FROM api_keys WHERE study_id = '{study_id}';")
        path = self.dump("before-withdrawal.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        self.sql(f"UPDATE study_participants SET participation_status = 'NOT_ENROLLED' WHERE study_id = '{study_id}'; "
                 f"UPDATE api_keys SET revoked = true WHERE key_id = '{key_id}';")
        backups = self.work / "withdrawal-backups"
        backups.mkdir(mode=0o777)
        backups.chmod(0o777)
        result = self.restore(path, backups)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("NOT_ENROLLED|true", self.sql(
            "SELECT p.participation_status || '|' || k.revoked FROM study_participants p "
            f"JOIN api_keys k USING (study_id, participant_id) WHERE p.study_id = '{study_id}';"))
        columns = self.sql("SELECT string_agg(column_name, ',') FROM information_schema.columns "
                           "WHERE table_schema = 'chronicle_restore_continuity';").split(",")
        self.assertIn("participant_block_token", columns)
        self.assertFalse(set(columns) & {"api_key", "token", "secret", "password"}, columns)
        companion, = backups.glob("pre-restore-*.continuity.sql.gz")
        self.assertEqual(0o600, companion.stat().st_mode & 0o777)

    def test_dump_toc_matches_replaced_schemas_including_nonpublic(self):
        self.sql("CREATE TABLE public.restore_extra (value integer); "
                 "INSERT INTO public.restore_extra VALUES (1);")
        self.addCleanup(self.sql, "DROP TABLE IF EXISTS public.restore_extra;")
        archive = self.docker("exec", self.container, "pg_dump", "-U", "chronicle", "-d", "chronicle",
                              "-Fc", *DUMP_EXCLUDE_OPTIONS)
        toc = self.docker("exec", "-i", self.container, "pg_restore", "-l", data=archive).decode()
        schemas = set(re.findall(r"^\d+;\s+\d+\s+\d+ SCHEMA - (.+) \S+$", toc, re.M))
        schemas.update(re.findall(r"^\d+;\s+\d+\s+\d+ TABLE (?!DATA )(\S+) ", toc, re.M))
        extensions = set(re.findall(r"^\d+;\s+\d+\s+\d+ EXTENSION - (\S+)", toc, re.M))
        self.assertFalse(extensions.intersection(PRESERVED_EXTENSIONS))
        self.assertIn("public", schemas)
        self.assertFalse(schemas.intersection(PRESERVED_SCHEMAS))
        self.assertNotEqual("", self.sql(KEY_SCHEMA_OID_SQL))
        print("pg_restore TOC application schemas:", sorted(schemas), flush=True)
        # Exercise the upgrade/adoption dump command, rather than reimplement its flags.
        data = self.docker("exec", self.container, "bash", "-ceu", ROLLBACK_DUMP)
        path = self.work / "policy.sql.gz"
        path.write_bytes(gzip.compress(data))
        self.sql("UPDATE public.restore_extra SET value = 2;")
        result = self.restore(path)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("1", self.sql("SELECT value FROM public.restore_extra;"))
        self.assertEqual('t', self.sql(DATABASE_PRIVILEGES_SQL))
        restored = set(self.sql("SELECT nspname FROM pg_namespace WHERE nspname !~ '^pg_' "
                                "AND nspname <> 'information_schema';").splitlines())
        self.assertEqual(schemas, restored.difference(PRESERVED_SCHEMAS))
        safety = max((p for p in self.work.glob("pre-restore-*.sql.gz")
                      if not p.name.endswith(".continuity.sql.gz")), key=lambda p: p.stat().st_mtime)
        from chronicle_ops.dump import backup_release_header, installed_backup_version
        version = installed_backup_version(SELFHOST)
        for produced in (safety, safety.with_name(safety.name.removesuffix('.sql.gz') + '.continuity.sql.gz')):
            header = self.docker('exec', '--user', '0', '-e', 'PYTHONPATH=/selfhost', self.container,
                                 'python3', '-c', '''import gzip, sys
from chronicle_ops.dump import require_restore_version
require_restore_version(sys.argv[1], sys.argv[2])
with gzip.open(sys.argv[1], 'rb') as stream:
    sys.stdout.buffer.write(stream.readline())
''', self.container_path(produced), version)
            self.assertEqual(backup_release_header(version), header)
        # Replaying a shipped safety dump must obey the same schema policy too.
        self.assertEqual(0, self.restore(safety).returncode)
        self.assertEqual("2", self.sql("SELECT value FROM public.restore_extra;"))
        self.assertEqual('t', self.sql(DATABASE_PRIVILEGES_SQL))
        self.assert_live_key_preserved()

    def test_producer_failure_cannot_commit_and_rollback_consumes_checkpoint(self):
        path = self.dump("producer.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        self.sql(INSERT_LIVE_AUDIT_SQL)
        producer = self.work / "commands/gzip"
        producer.write_text('#!/bin/bash\n/usr/bin/gzip "$@"\n[[ "${1:-}" != -dc ]]\n')
        producer.chmod(0o755)
        self.addCleanup(producer.unlink, missing_ok=True)
        self.environment = ["-e", "CHRONICLE_RESTORE_ROLLBACK=true"]
        result = self.restore(path)
        self.assertEqual(EXIT_RESTORE_TRANSACTION_ROLLED_BACK, result.returncode, result.stderr)
        self.assertEqual("2", self.sql(AUDIT_COUNT_SQL))
        self.assertEqual("1", self.sql("SELECT count(*) FROM chronicle_restore_continuity.checkpoint;"))
        self.assert_live_key_preserved()
        producer.unlink()
        result = self.restore(path)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", self.sql("SELECT to_regnamespace('chronicle_restore_continuity');"))
        self.assertEqual("backup-row", self.sql(AUDIT_ROWS_SQL))
        self.assert_live_key_preserved()


class FreshVolumeRestoreTests(PgTdeFixture):
    def test_guarded_service_recovers_after_data_and_keyring_volume_loss(self):
        import yaml
        self.environment = []
        self.load_application_fixture()
        # V1 creates pgcrypto and Flyway never re-runs V1 over a restored history; plpgsql callers of
        # public.hmac (chronicle_participant_block_token) restore without error and fail at call time.
        self.sql("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public; "
                 "CREATE FUNCTION public.fixture_block_token(value text) RETURNS text LANGUAGE plpgsql AS "
                 "$$BEGIN RETURN encode(public.hmac(value, 'fixture', 'sha256'), 'hex'); END$$;")
        path = self.dump("fresh-volumes.sql.gz", *DUMP_EXCLUDE_OPTIONS)
        self.docker("rm", "-fv", self.container)
        self.start_database(initialize_tde=False)
        self.sql((ROOT / "docker/init-db-roles.sql").read_text())
        self.assertEqual("0", self.sql("SELECT count(*) FROM pg_extension WHERE extname = 'pg_tde';"))
        services = yaml.safe_load((SELFHOST / "docker-compose.yml").read_text())["services"]
        for name in services["restore"]["depends_on"]:
            if name != "postgres":
                self.docker("exec", "--user", "0", "-e", "POSTGRES_HOST=127.0.0.1", self.container,
                            *services[name]["entrypoint"])
        result = self.restore(path)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("backup-row", self.sql(AUDIT_ROWS_SQL))
        self.assertEqual("t", self.sql("SELECT pg_tde_is_encrypted('public.audit'::regclass);"))
        self.assertEqual("", self.sql("SELECT to_regnamespace('chronicle_restore_continuity');"))
        self.assertEqual(64, len(self.sql("SELECT public.fixture_block_token('participant');")))


class RotationBackupTests(unittest.TestCase):
    def test_upgrade_and_tde_dump_writers_lock_fragments_until_compression_finishes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            probe = root / 'probe.py'
            probe.write_text('''import fcntl
import os
from pathlib import Path
import sys
path = Path(sys.argv[1]) if len(sys.argv) > 1 else next(
    (Path(os.environ['STATE_ROOT']) / 'backups/secret-rotation').glob('*.partial'))
with path.open('rb') as fragment:
    try:
        fcntl.flock(fragment, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        pass
    else:
        raise SystemExit('dump writer did not protect its active fragment')
sys.stdout.buffer.write(Path(os.environ['DUMP_FIXTURE']).read_bytes())
''')
            (root / 'dump.sql').write_bytes(DUMP)
            environment = dict(os.environ, STATE_ROOT=folder, PROBE=str(probe), DUMP_FIXTURE=str(root / 'dump.sql'),
                               RELEASE_VERSION=release.UPGRADE_FROM_MINIMUM)
            path = root / 'pre-upgrade-locked.sql.gz.partial'
            self.assertEqual(len(release.rollback_dump([sys.executable, str(probe), str(path)], path, env=environment)), 64)
            fixture = rotation_fixture(root)
            host, commands = fixture.host, fixture.commands
            (commands / 'docker').rename(commands / 'docker-original')
            (commands / 'docker').write_text('''#!/bin/bash
if [[ "$*" == *pg_dump* ]]; then
  printf '%s\\n' "$@" >"$DUMP_ARGS"
  exec "$SELFHOST_ROTATION_TEST_REAL_PYTHON" "$PROBE"
fi
exec "$(dirname "$0")/docker-original" "$@" 2>>"$DUMP_ARGS"
''')
            (commands / 'docker').chmod(0o755)
            environment.update(fixture.environment, DUMP_ARGS=str(root / 'dump-args'))
            result = subprocess.run(['bash', str(host / 'rotate-secret.sh'), '--yes', 'tde'],
                                    env=environment, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr + (root / 'dump-args').read_bytes())
            produced = list((host / 'backups/secret-rotation').glob('*.sql.gz'))
            self.assertEqual(len(produced), 1)
            from chronicle_ops.dump import backup_release_header
            for backup in (path, produced[0]):
                with gzip.open(backup, 'rb') as stream:
                    self.assertEqual(backup_release_header(release.UPGRADE_FROM_MINIMUM), stream.readline())
            self.assertTrue(set(DUMP_EXCLUDE_OPTIONS).issubset((root / 'dump-args').read_text().splitlines()))


if __name__ == "__main__":
    unittest.main()
