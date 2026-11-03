"""Logical restore policy, catalog ownership and restricted pg_dump validation (Python 3.9)."""

from dataclasses import dataclass
import configparser
from enum import Enum
import gzip
import shutil
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import zlib

from . import cron

COMPLETE = b"-- PostgreSQL database dump complete"
_SESSION_CONTRACT = configparser.ConfigParser()
_SESSION_CONTRACT.read_string("[session]\n" + (Path(__file__).resolve().parent / "restore-session.properties").read_text())
_SESSION_VALUES = _SESSION_CONTRACT["session"]
class TableRestorePolicy(str, Enum):
    SNAPSHOT = "snapshot"
    LIVE_AUTHORITY = "merge-live"
    SESSION_CUTOFF = "revoke-sessions"


APPLICATION_TABLE_POLICIES = {
    name: TableRestorePolicy(policy) for name, policy in json.loads(
        (Path(__file__).resolve().parent / "restore-table-policy.json").read_text()).items()
}
SESSION_STATE_TABLE, = (name for name, policy in APPLICATION_TABLE_POLICIES.items()
                        if policy == TableRestorePolicy.SESSION_CUTOFF)
SESSION_CUTOFF_SQL = """
INSERT INTO {table} (state_group, state_key, state_value, expires_at)
VALUES ('{}', '{}', floor(extract(epoch FROM clock_timestamp()))::bigint, NULL)
ON CONFLICT (state_group, state_key) DO UPDATE
SET state_value = GREATEST({table}.state_value, EXCLUDED.state_value), expires_at = NULL;
""".format(*(_SESSION_VALUES[key].replace("'", "''") for key in ("blocklistMap", "revokeAllBeforeKey")), table=SESSION_STATE_TABLE)
RESTORE_MUTATION_MARKER = ".chronicle-restore-mutation-started"
EXIT_REJECTED_BEFORE_MUTATION = 46
EXIT_RESTORE_TRANSACTION_ROLLED_BACK = 47
# overlays/backups.yml hands go-cron this when BACKUP_SCHEDULE is empty.
DEFAULT_BACKUP_SCHEDULE = "@daily"
# Grace after a missed run: today's 36 h window for the default daily schedule, less its 24 h.
BACKUP_OVERDUE_MARGIN_SECONDS = 12 * 60 * 60
BACKUP_SCRATCH_FACTOR = 2
BACKUP_VERIFICATION_CACHE = ".backup-verification.json"
class RestoreSource(str, Enum):
    DUMP = "restored from dump"
    LIVE = "preserved from live"


TDE_GENERATION_SCHEMA = "chronicle_secret_generation"
SCHEMA_SOURCES = {
    "public": RestoreSource.DUMP,
    "chronicle_restore_continuity": RestoreSource.LIVE,
    TDE_GENERATION_SCHEMA: RestoreSource.LIVE,
}
# Extension members (including access methods) follow their extension, not their schema.
EXTENSION_SOURCES = {"plpgsql": RestoreSource.LIVE, "pg_tde": RestoreSource.LIVE, "pgcrypto": RestoreSource.LIVE}
GLOBAL_SOURCES = dict.fromkeys(("pg_authid", "pg_database", "pg_tablespace"), RestoreSource.LIVE)
PLATFORM_SOURCES = {
    "pg_am": dict.fromkeys(("heap", "btree", "hash", "gist", "spgist", "gin", "brin"), RestoreSource.LIVE),
    "pg_language": dict.fromkeys(("internal", "c", "sql"), RestoreSource.LIVE),
}
RELATION_DROP_TYPES = {"r": "TABLE", "p": "TABLE", "v": "VIEW", "m": "MATERIALIZED VIEW", "S": "SEQUENCE"}
ROUTINE_DROP_TYPES = {"f": "FUNCTION", "w": "FUNCTION", "p": "PROCEDURE"}
TYPE_DROP_TYPES = {"c": "TYPE", "d": "DOMAIN", "e": "TYPE"}
UNCLASSIFIED_OBJECTS = "Unclassified database object; review the restore policy before continuing"
LIVE_OBJECTS_CHANGED = "Live database objects changed during restore"
_POLICY_SQL = "'" + json.dumps(dict(schemas=SCHEMA_SOURCES, extensions=EXTENSION_SOURCES, globals=GLOBAL_SOURCES, platform=PLATFORM_SOURCES,
                                   relations=RELATION_DROP_TYPES, routines=ROUTINE_DROP_TYPES,
                                   types=TYPE_DROP_TYPES,
                                   messages=dict(unclassified=UNCLASSIFIED_OBJECTS, live_changed=LIVE_OBJECTS_CHANGED))).replace("'", "''") + "'"
PRESERVED_SCHEMAS = tuple(name for name, source in SCHEMA_SOURCES.items() if source == RestoreSource.LIVE)
PRESERVED_EXTENSIONS = tuple(name for name, source in EXTENSION_SOURCES.items() if source == RestoreSource.LIVE)
DUMP_EXCLUDE_OPTIONS = (tuple("--exclude-schema=" + name for name in PRESERVED_SCHEMAS) +
                        tuple("--exclude-extension=" + name for name in PRESERVED_EXTENSIONS))
# Dumps carry no CREATE EXTENSION for live extensions, and Flyway never re-runs V1 over a restored
# history: a fresh volume lacks pgcrypto unless restore creates it, and plpgsql callers of
# public.hmac then fail only when called. PostgreSQL ships plpgsql; init-tde.sh owns pg_tde.
RESTORE_EXTENSIONS_SQL = "".join(f'CREATE EXTENSION IF NOT EXISTS "{name}" WITH SCHEMA public;\n'
                                 for name in PRESERVED_EXTENSIONS if name not in ("plpgsql", "pg_tde"))

# pg_shdepend catches role-owned objects outside the enumerated catalogs too. Unsupported
# global objects or object kinds fail closed; their restore/drop semantics need review first.
CATALOG_SQL = """
WITH RECURSIVE extension_members(classid, objid, extension) AS (
  SELECT d.classid, d.objid, e.extname FROM pg_depend d
    JOIN pg_extension e ON d.refclassid = 'pg_extension'::regclass AND d.refobjid = e.oid
    WHERE d.deptype = 'e'
  UNION
  SELECT d.classid, d.objid, m.extension FROM pg_depend d
    JOIN extension_members m ON d.refclassid = m.classid AND d.refobjid = m.objid
    WHERE d.deptype = 'i'
), extension_dependents(classid, objid) AS (
  SELECT classid, objid FROM extension_members
  UNION
  SELECT d.classid, d.objid FROM pg_depend d
    JOIN extension_dependents p ON d.refclassid = p.classid AND d.refobjid = p.objid
    WHERE d.deptype IN ('i', 'a')
), objects(classid, objid, objsubid) AS (
  SELECT classid, objid, objsubid FROM pg_shdepend
    WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) AND deptype = 'o'
  UNION SELECT 'pg_namespace'::regclass, oid, 0 FROM pg_namespace
  UNION SELECT 'pg_extension'::regclass, oid, 0 FROM pg_extension
  UNION SELECT 'pg_class'::regclass, oid, 0 FROM pg_class
  UNION SELECT 'pg_class'::regclass, a.attrelid, a.attnum FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p', 'v', 'm', 'c', 'f')
  UNION SELECT 'pg_proc'::regclass, oid, 0 FROM pg_proc
  UNION SELECT 'pg_type'::regclass, oid, 0 FROM pg_type
  UNION SELECT 'pg_am'::regclass, oid, 0 FROM pg_am
  UNION SELECT 'pg_language'::regclass, oid, 0 FROM pg_language
  UNION SELECT 'pg_authid'::regclass, oid, 0 FROM pg_roles
  UNION SELECT 'pg_database'::regclass, oid, 0 FROM pg_database WHERE datname = current_database()
  UNION SELECT 'pg_tablespace'::regclass, oid, 0 FROM pg_tablespace
  UNION SELECT 'pg_foreign_data_wrapper'::regclass, oid, 0 FROM pg_foreign_data_wrapper
  UNION SELECT 'pg_foreign_server'::regclass, oid, 0 FROM pg_foreign_server
  UNION SELECT 'pg_event_trigger'::regclass, oid, 0 FROM pg_event_trigger
  UNION SELECT 'pg_publication'::regclass, oid, 0 FROM pg_publication
  UNION SELECT 'pg_subscription'::regclass, oid, 0 FROM pg_subscription
    WHERE subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())
  UNION SELECT 'pg_largeobject_metadata'::regclass, oid, 0 FROM pg_largeobject_metadata
  UNION SELECT classid, objid, objsubid FROM pg_depend
  UNION SELECT classid, objid, 0 FROM extension_members
), details AS (
  SELECT o.*, i.type AS kind, i.identity,
    CASE WHEN o.classid = 'pg_namespace'::regclass THEN n.nspname
         WHEN o.classid = 'pg_default_acl'::regclass THEN dn.nspname
         ELSE coalesce(i.schema, cn.nspname, pn.nspname, rn.nspname) END AS schema,
    coalesce(e.extname, m.extension) AS extension, dependent.objid IS NOT NULL AS extension_dependent,
    pg_get_userbyid(coalesce(s.refobjid, c.relowner, p.proowner, t.typowner,
                            n.nspowner, e.extowner, a.defaclrole, parent.relowner)) AS owner,
    c.relkind, p.prokind, t.typtype, coalesce(am.amname, lang.lanname) AS platform_name,
    EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid
            AND d.refclassid = 'pg_type'::regclass AND d.deptype = 'i') AS automatic_type
  FROM objects o CROSS JOIN LATERAL pg_identify_object(o.classid, o.objid, o.objsubid) i
  LEFT JOIN pg_namespace n ON o.classid = 'pg_namespace'::regclass AND n.oid = o.objid
  LEFT JOIN pg_extension e ON o.classid = 'pg_extension'::regclass AND e.oid = o.objid
  LEFT JOIN extension_members m ON m.classid = o.classid AND m.objid = o.objid
  LEFT JOIN extension_dependents dependent ON dependent.classid = o.classid AND dependent.objid = o.objid
  LEFT JOIN pg_shdepend s ON s.dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
    AND s.classid = o.classid AND s.objid = o.objid AND s.deptype = 'o'
  LEFT JOIN pg_class c ON o.classid = 'pg_class'::regclass AND c.oid = o.objid
  LEFT JOIN pg_namespace rn ON rn.oid = c.relnamespace
  LEFT JOIN pg_proc p ON o.classid = 'pg_proc'::regclass AND p.oid = o.objid
  LEFT JOIN pg_type t ON o.classid = 'pg_type'::regclass AND t.oid = o.objid
  LEFT JOIN pg_default_acl a ON o.classid = 'pg_default_acl'::regclass AND a.oid = o.objid
  LEFT JOIN pg_namespace dn ON dn.oid = a.defaclnamespace
  LEFT JOIN pg_constraint k ON o.classid = 'pg_constraint'::regclass AND k.oid = o.objid
  LEFT JOIN pg_namespace cn ON cn.oid = k.connamespace
  LEFT JOIN pg_attrdef ad ON o.classid = 'pg_attrdef'::regclass AND ad.oid = o.objid
  LEFT JOIN pg_trigger tr ON o.classid = 'pg_trigger'::regclass AND tr.oid = o.objid
  LEFT JOIN pg_rewrite rw ON o.classid = 'pg_rewrite'::regclass AND rw.oid = o.objid
  LEFT JOIN pg_policy pol ON o.classid = 'pg_policy'::regclass AND pol.oid = o.objid
  LEFT JOIN pg_class parent ON parent.oid = coalesce(k.conrelid, ad.adrelid, tr.tgrelid, rw.ev_class, pol.polrelid)
  LEFT JOIN pg_namespace pn ON pn.oid = parent.relnamespace
  LEFT JOIN pg_am am ON o.classid = 'pg_am'::regclass AND am.oid = o.objid
  LEFT JOIN pg_language lang ON o.classid = 'pg_language'::regclass AND lang.oid = o.objid
), classified AS (
  SELECT *, CASE
    WHEN owner IS NOT NULL AND owner NOT IN (current_user, 'chronicle', 'chronicle_app',
                                            'chronicle_admin', 'pg_database_owner') THEN NULL
    WHEN extension IS NOT NULL THEN (__POLICY__::jsonb -> 'extensions' ->> extension)
    -- Auto-dependency allows user-created objects too; it is not extension membership.
    WHEN extension_dependent THEN NULL
    WHEN (__POLICY__::jsonb -> 'globals') ? classid::regclass::text
      THEN (__POLICY__::jsonb -> 'globals' ->> classid::regclass::text)
    WHEN classid IN ('pg_am'::regclass, 'pg_language'::regclass)
      THEN (__POLICY__::jsonb -> 'platform' -> classid::regclass::text ->> platform_name)
    WHEN classid IN ('pg_namespace'::regclass, 'pg_constraint'::regclass,
                    'pg_attrdef'::regclass, 'pg_trigger'::regclass, 'pg_rewrite'::regclass, 'pg_policy'::regclass)
      OR (classid = 'pg_default_acl'::regclass AND owner = current_user)
      OR (classid = 'pg_class'::regclass AND (relkind IN ('i', 'I', 'c', 't')
          OR (__POLICY__::jsonb -> 'relations') ? relkind::text))
      OR (classid = 'pg_proc'::regclass AND (__POLICY__::jsonb -> 'routines') ? prokind::text)
      OR (classid = 'pg_type'::regclass AND (automatic_type OR (__POLICY__::jsonb -> 'types') ? typtype::text))
    THEN (__POLICY__::jsonb -> 'schemas' ->> schema)
    END AS source
  FROM details
  WHERE extension IS NOT NULL OR schema IS NULL OR (schema <> 'information_schema' AND schema !~ '^pg_')
)
SELECT * FROM classified
""".replace("__POLICY__", _POLICY_SQL)
CATALOG_GATE_SQL = "DO $catalog_gate$ BEGIN IF EXISTS (" + CATALOG_SQL + """
 WHERE source IS NULL) THEN
 RAISE EXCEPTION '%', """ + _POLICY_SQL + """::jsonb -> 'messages' ->> 'unclassified';
 END IF; END $catalog_gate$;
"""
LIVE_CATALOG_TABLE = "chronicle_restore_live_objects"
PRESERVED_SCHEMA_TABLE = "chronicle_preserved_schemas"
_LIVE_SOURCE_SQL = "'" + RestoreSource.LIVE.value + "'"
_LIVE_OBJECTS_SQL = "SELECT classid, objid, objsubid FROM (" + CATALOG_SQL + ") c WHERE source = " + _LIVE_SOURCE_SQL
CATALOG_CAPTURE_SQL = (CATALOG_GATE_SQL + "\nCREATE TEMP TABLE " + LIVE_CATALOG_TABLE +
                       " USING heap ON COMMIT DROP AS " + _LIVE_OBJECTS_SQL + ";")
CATALOG_VERIFY_LIVE_SQL = (CATALOG_GATE_SQL + "\nDO $live_catalog$ BEGIN IF EXISTS (WITH expected AS (" +
                         "SELECT classid, objid, objsubid FROM pg_temp." + LIVE_CATALOG_TABLE +
                         "), observed AS (" + _LIVE_OBJECTS_SQL + """
) (SELECT * FROM expected EXCEPT SELECT * FROM observed)
UNION ALL (SELECT * FROM observed EXCEPT SELECT * FROM expected)
) THEN RAISE EXCEPTION '%', """ + _POLICY_SQL + """::jsonb -> 'messages' ->> 'live_changed';
END IF; END $live_catalog$;
""")

# The same classification drives replacement: extension members and their internal
# children stay live. Identity sequences must be removed through their owning tables.
RESTORE_PREPARE_SQL = f"""
CREATE TEMP TABLE {PRESERVED_SCHEMA_TABLE} (original_name name, saved_name name) USING heap ON COMMIT DROP;
INSERT INTO {PRESERVED_SCHEMA_TABLE}
SELECT policy.name, 'chronicle_restore_saved_' || n.oid
FROM (
  SELECT key AS name FROM jsonb_each_text({_POLICY_SQL}::jsonb -> 'schemas') WHERE value = {_LIVE_SOURCE_SQL}
  UNION
  SELECT n.nspname FROM pg_namespace n JOIN pg_temp.{LIVE_CATALOG_TABLE} live
    ON live.classid = 'pg_namespace'::regclass AND live.objid = n.oid AND live.objsubid = 0
    WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_'
) policy LEFT JOIN pg_namespace n ON n.nspname = policy.name;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT * FROM pg_temp.{PRESERVED_SCHEMA_TABLE} WHERE saved_name IS NOT NULL LOOP
    EXECUTE format('ALTER SCHEMA %I RENAME TO %I', r.original_name, r.saved_name);
  END LOOP;
  FOR r IN SELECT oid, nspname FROM pg_namespace
    WHERE nspname <> 'public' AND nspname <> 'information_schema' AND nspname !~ '^pg_'
      AND nspname NOT IN (SELECT saved_name FROM pg_temp.{PRESERVED_SCHEMA_TABLE} WHERE saved_name IS NOT NULL)
  LOOP
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extnamespace = r.oid) THEN
      RAISE EXCEPTION 'Cannot replace extension schema safely';
    END IF;
    EXECUTE format('DROP SCHEMA %I CASCADE', r.nspname);
  END LOOP;
  FOR r IN SELECT c.oid, format('%I.%I', n.nspname, c.relname) AS ident, c.relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND ({_POLICY_SQL}::jsonb -> 'relations') ? c.relkind::text
      AND NOT EXISTS (SELECT 1 FROM pg_temp.{LIVE_CATALOG_TABLE} live
        WHERE live.classid = 'pg_class'::regclass AND live.objid = c.oid AND live.objsubid = 0)
    ORDER BY c.relkind = 'S'
  LOOP
    EXECUTE format('DROP %s IF EXISTS %s CASCADE', {_POLICY_SQL}::jsonb -> 'relations' ->> r.relkind::text, r.ident);
  END LOOP;
  FOR r IN SELECT p.oid, format('%I.%I(%s)', n.nspname, p.proname,
                               pg_get_function_identity_arguments(p.oid)) AS ident, p.prokind
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
      AND ({_POLICY_SQL}::jsonb -> 'routines') ? p.prokind::text
      AND NOT EXISTS (SELECT 1 FROM pg_temp.{LIVE_CATALOG_TABLE} live
        WHERE live.classid = 'pg_proc'::regclass AND live.objid = p.oid AND live.objsubid = 0)
  LOOP
    EXECUTE format('DROP %s IF EXISTS %s CASCADE', {_POLICY_SQL}::jsonb -> 'routines' ->> r.prokind::text, r.ident);
  END LOOP;
  FOR r IN SELECT t.oid, format('%I.%I', n.nspname, t.typname) AS ident, t.typtype
    FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public'
      AND ({_POLICY_SQL}::jsonb -> 'types') ? t.typtype::text
      AND NOT EXISTS (SELECT 1 FROM pg_depend d
        WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'i')
      AND NOT EXISTS (SELECT 1 FROM pg_temp.{LIVE_CATALOG_TABLE} live
        WHERE live.classid = 'pg_type'::regclass AND live.objid = t.oid AND live.objsubid = 0)
  LOOP
    EXECUTE format('DROP %s IF EXISTS %s CASCADE', {_POLICY_SQL}::jsonb -> 'types' ->> r.typtype::text, r.ident);
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
      AND NOT EXISTS (SELECT 1 FROM pg_temp.{LIVE_CATALOG_TABLE} live
        WHERE live.classid = 'pg_class'::regclass AND live.objid = c.oid AND live.objsubid = 0)) THEN
    RAISE EXCEPTION 'Application tables survived replacement';
  END IF;
END $$;
"""
RESTORE_RECOVER_SCHEMAS_SQL = f"""
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT * FROM pg_temp.{PRESERVED_SCHEMA_TABLE} LOOP
    EXECUTE format('DROP SCHEMA IF EXISTS %I CASCADE', r.original_name);
    IF r.saved_name IS NOT NULL THEN
      EXECUTE format('ALTER SCHEMA %I RENAME TO %I', r.saved_name, r.original_name);
    END IF;
  END LOOP;
END $$;
"""


def backup_marker(backups, database):
    if not database or any(c in database for c in "/\\\r\n\0"):
        raise DumpError("unsafe backup database name")
    return Path(backups) / "last" / f"{database}-verified.json"


@dataclass(frozen=True)
class VerifiedBackup:
    path: Path
    marker: dict
    uncompressed_bytes: int


BACKUP_RELEASE_PREFIX = b"-- Chronicle release: "


def backup_release_header(version):
    from .release import parse_version
    parse_version(version, "backup release")
    return BACKUP_RELEASE_PREFIX + version.encode("ascii") + b"\n"


def stamp_backup(path, version):
    """Prepend a gzip member so pg_dump bytes stay streaming and psql sees a comment."""
    from .receipts import durable_replace
    path = Path(path)
    temporary = path.with_name(path.name + '.release.partial')
    try:
        with temporary.open('xb') as output, path.open('rb') as source:
            os.chmod(temporary, 0o600)
            output.write(gzip.compress(backup_release_header(version), mtime=0))
            shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
        durable_replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def installed_backup_version(selfhost):
    """Resolve provenance at the dump producer, including source-clone operation."""
    from .envfile import read_env, value
    from .release import UPGRADE_FROM_MINIMUM
    selfhost = Path(selfhost)
    manifest = selfhost.parent / 'release-manifest.json'
    version = os.environ.get('RELEASE_VERSION')
    if not version and manifest.is_file():
        version = json.loads(manifest.read_text())['release_version']
    if not version:
        version = value(read_env(selfhost / '.env.example'), 'RELEASE_VERSION')
    return UPGRADE_FROM_MINIMUM + '+development' if version in ('development', '') else version


def stamp_installed_backup(path, selfhost):
    stamp_backup(path, installed_backup_version(selfhost))


def require_restore_version(path, current):
    from .release import FRESH_INSTALL_REQUIRED, UPGRADE_FROM_MINIMUM, parse_version
    with gzip.open(path, 'rb') as stream:
        header = stream.readline()
    if not header.startswith(BACKUP_RELEASE_PREFIX):
        raise DumpError(FRESH_INSTALL_REQUIRED)  # Every post-reset producer stamps its release.
    version = header[len(BACKUP_RELEASE_PREFIX):].decode('ascii').strip()
    if parse_version(version, path) < parse_version(UPGRADE_FROM_MINIMUM, 'reset floor'):
        raise DumpError(FRESH_INSTALL_REQUIRED)
    if parse_version(version, path) > parse_version(current, 'restore target'):
        raise DumpError('backup comes from a newer release; restore into that release or a newer one')


def publish_backup(path, database, source, *, pending=None):
    path = Path(path)
    stamp_installed_backup(pending or path, Path(__file__).resolve().parents[1])
    if pending is not None:
        os.replace(pending, path)
    marker = backup_marker(path.parent.parent, database)
    temporary = marker.with_name(marker.name + ".partial")
    try:
        with temporary.open("w") as output:
            os.chmod(temporary, 0o600)
            json.dump(dict(source, database=database, file=path.name, sha256=file_sha256(path), verified_at=time.time(), uncompressed_bytes=validate_dump(path)), output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, marker)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def backup_max_age_seconds(schedule):
    """Age at which the newest verified backup is overdue under BACKUP_SCHEDULE: the longest gap
    go-cron leaves between runs plus BACKUP_OVERDUE_MARGIN_SECONDS. Verification, doctor and the
    monitoring alert all read it, so a schedule go-cron runs never fails them early."""
    schedule = schedule or DEFAULT_BACKUP_SCHEDULE
    try:
        return cron.longest_gap_seconds(schedule) + BACKUP_OVERDUE_MARGIN_SECONDS
    except ValueError as error:
        raise ValueError(f"BACKUP_SCHEDULE is not a schedule the backup sidecar can run: {error} "
                         f"(received '{schedule}'; use a cron line such as 0 3 * * *, @daily or @every 6h)") from None


def verified_backup(backups, database, schedule):
    marker = backup_marker(backups, database)
    data = json.loads(marker.read_text())
    if data.get("database") != database or not 0 <= time.time() - data["verified_at"] <= backup_max_age_seconds(schedule):
        raise DumpError("verified backup belongs to another database or is stale")
    name = data["file"]
    if Path(name).name != name or not name.startswith(database + "-") or not name.endswith(".sql.gz"):
        raise DumpError("invalid verified backup path")
    path = marker.parent / name
    size = validate_dump(path, data["sha256"])
    if size != data["uncompressed_bytes"]:
        raise DumpError("verified backup size does not match its marker")
    return VerifiedBackup(path, data, size)


def file_identity(path):
    stat = path.stat()
    return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]


def cached_verified_backup(backups, database, cache, schedule):
    from .receipts import write_json
    marker_text = backup_marker(backups, database).read_text()
    data = json.loads(marker_text)
    cache = Path(cache)
    try:
        previous = json.loads(cache.read_text())
        path = Path(previous['path'])
        unchanged = previous['marker'] == marker_text and previous['identity'] == file_identity(path)
    except (OSError, ValueError, KeyError, TypeError):
        unchanged = False
    if unchanged:
        if not 0 <= time.time() - data['verified_at'] <= backup_max_age_seconds(schedule):
            raise DumpError('stale verified backup')
        return VerifiedBackup(path, data, data['uncompressed_bytes'])
    backup = verified_backup(backups, database, schedule)
    write_json(cache, dict(path=str(backup.path), marker=marker_text, identity=file_identity(backup.path)))
    return backup


class DumpError(ValueError):
    pass


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class DumpSqlLexer:
    quote: str = ""
    comment: int = 0  # PostgreSQL block comments nest.
    failed: bool = False

    def code(self, line):
        code, i = "", 0
        while i < len(line):
            c, nextc = line[i], line[i + 1:i + 2]
            if self.comment:
                if c == "*" and nextc == "/":
                    self.comment -= 1
                    i += 1
                elif c == "/" and nextc == "*":
                    self.comment += 1
                    i += 1
            elif self.quote in ("single", "double"):
                mark = "'" if self.quote == "single" else '"'
                if c == mark:
                    if nextc == mark:
                        i += 1
                    else:
                        self.quote = ""
                # A backslash escapes the quote only in E'' strings or with standard_conforming_strings
                # off, which a dump could switch. pg_dump's DDL has none, so refuse rather than guess.
                elif self.quote == "single" and c == "\\":
                    self.failed = True
            elif self.quote:
                if line[i:i + len(self.quote)] == self.quote:
                    i += len(self.quote) - 1
                    self.quote = ""
            elif c == "-" and nextc == "-":
                break
            elif c == "/" and nextc == "*":
                self.comment = 1
                code += " "  # A comment separates tokens, as whitespace does.
                i += 1
            elif c in ("'", '"'):
                self.quote = "single" if c == "'" else "double"
            elif c == "$" and (tag := re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$", line[i:])):
                # psql reads foo$tag$ as one identifier; pg_dump quotes identifiers containing $.
                self.failed |= i > 0 and bool(re.match(r"[A-Za-z0-9_$\x80-\xff]", line[i - 1]))
                self.quote = tag[0]
                i += len(self.quote) - 1
            else:
                code += c
            i += 1
        return code


# Allowlist of the statements pg_dump emits for Chronicle's schema, matched on lexer-stripped
# code (quoted text removed, whitespace collapsed, upper case). Anything else is refused,
# including role, system, large-object and transaction-control statements and any extension
# other than the two the schema uses (pg_tde for encryption at rest, pgcrypto from V1).
_IDENT = r'(?:[a-z_][a-z0-9_$]*|"(?:[^"]|"")+")'
_DUMP_STATEMENT = re.compile(r"""
    SET\ (STATEMENT_TIMEOUT|LOCK_TIMEOUT|IDLE_IN_TRANSACTION_SESSION_TIMEOUT|TRANSACTION_TIMEOUT
         |CHECK_FUNCTION_BODIES|XMLOPTION|CLIENT_MIN_MESSAGES|ROW_SECURITY|DEFAULT_TABLESPACE
         |DEFAULT_TABLE_ACCESS_METHOD)\ =(\ [A-Z0-9_]+)?
  | SET\ STANDARD_CONFORMING_STRINGS\ =\ ON
  | CREATE\ EXTENSION\ IF\ NOT\ EXISTS\ (PG_TDE|PGCRYPTO)\ WITH\ SCHEMA\ PUBLIC
  | CREATE\ (UNLOGGED\ TABLE|TABLE|SEQUENCE|(UNIQUE\ )?INDEX|VIEW|MATERIALIZED\ VIEW|FUNCTION|PROCEDURE|AGGREGATE
            |(CONSTRAINT\ )?TRIGGER|POLICY|TYPE|DOMAIN|SCHEMA)\ .*
  | ALTER\ (TABLE|SEQUENCE|FUNCTION|PROCEDURE|AGGREGATE|TYPE|DOMAIN|VIEW|MATERIALIZED\ VIEW|INDEX|SCHEMA|POLICY
           |TRIGGER|DEFAULT\ PRIVILEGES)\ .*
  | (GRANT|REVOKE)\ .*\bON\b.*
  | COMMENT\ ON\ .*
  | REFRESH\ MATERIALIZED\ VIEW\ .*
""", re.X)
# Statements whose quoted arguments decide their effect are matched on the raw text instead.
_DUMP_LITERAL_STATEMENT = re.compile(r"SET client_encoding = '[A-Z0-9_]+'"
                                     r"|SELECT pg_catalog\.set_config\('search_path', '', false\)"
                                     r"|SELECT pg_catalog\.setval\('(?:[^']|'')+', -?[0-9]+, (?:true|false)\)")
_DUMP_COPY = re.compile(rf"COPY {_IDENT}\.{_IDENT} \({_IDENT}(?:, {_IDENT})*\) FROM stdin;")
# Server-side file, network and large-object access has no place in a schema dump, including
# inside function bodies that a CHECK, DEFAULT or index expression could run during the restore.
# Known limit: a name scan; plpgsql dynamic SQL that assembles these names at run time evades it.
_DUMP_SERVER_ACCESS = re.compile(r"\b(lo_import|lo_export|pg_read_file|pg_read_binary_file|pg_ls_\w*dir|"
                                 r"pg_stat_file|pg_file_\w+|dblink\w*|copy|program)\b|\bu&[\"']", re.I)


def safe_dump(lines):
    restricted = finished = copying = header = failed = complete = False
    lexer = DumpSqlLexer()
    token = code_statement = raw_statement = ""
    for raw in lines:
        line = raw.decode("latin1").rstrip("\n")
        # pg_dump writes neither NUL nor CR (COPY escapes both). psql drops a line's text after
        # NUL and ends a -- comment at CR, so either would split what psql runs from what we lex.
        failed |= "\0" in line or "\r" in line
        if copying:
            if line == "\\.":
                copying = False
            continue
        match = None if lexer.quote or lexer.comment else re.fullmatch(r"\\restrict ([A-Za-z0-9]+)", line)
        if match:
            failed |= restricted or finished
            restricted, token = True, match[1]
            continue
        match = None if lexer.quote or lexer.comment else re.fullmatch(r"\\unrestrict ([A-Za-z0-9]+)", line)
        if match:
            failed |= not restricted or finished or match[1] != token
            finished = True
            continue
        if not lexer.quote and not lexer.comment and re.match(r"\s*\\", line, re.ASCII):
            failed = True
            continue
        if not lexer.quote and not lexer.comment:
            if line == "-- PostgreSQL database dump":
                failed |= header or restricted or finished
                header = True
                continue
            if line == COMPLETE.decode("ascii"):
                failed |= complete or not header or not restricted
                complete = True
                continue
            if re.fullmatch(r"\s*(--.*)?", line, re.ASCII):
                continue
        failed |= complete
        failed |= not restricted or finished
        if not (lexer.quote or lexer.comment or code_statement.strip()) and _DUMP_COPY.fullmatch(line):
            copying = True
            continue
        failed |= bool(_DUMP_SERVER_ACCESS.search(line))
        code = lexer.code(line)
        # pg_dump quotes every identifier that is not plain ASCII, so unquoted high-bit bytes (which
        # psql reads as identifier or dollar-tag characters) are not its output.
        failed |= "\\" in code or bool(re.search(r"[\x80-\xff]", code))
        # psql runs a statement at each unquoted semicolon; classify every complete statement.
        code_statement += code + " "
        raw_statement += line + "\n"
        while ";" in code_statement:
            statement, code_statement = code_statement.split(";", 1)
            normalized = " ".join(statement.split()).upper()
            failed |= not (_DUMP_STATEMENT.fullmatch(normalized)
                           or _DUMP_LITERAL_STATEMENT.fullmatch(raw_statement.strip().rstrip(";")))
            raw_statement = ""
    return not (failed or code_statement.strip() or not header or not restricted or not finished or not complete
                or copying or lexer.quote or lexer.comment or lexer.failed)


def canonical_digest(text):
    digest = text.lower()
    if not re.fullmatch("[0-9a-f]{64}", digest):
        raise ValueError("requires a 64-character hexadecimal SHA-256 digest")
    return digest


def validate_dump(path, expected=None):
    if expected is not None:
        try:
            expected = canonical_digest(expected)
        except ValueError as error:
            raise DumpError(str(error)) from None
        if file_sha256(path) != expected:
            raise DumpError("provenance digest mismatch")
    try:
        with gzip.open(path, "rb") as stream:
            safe = safe_dump(stream)  # Read to EOF so gzip checks the CRC and trailer too.
            size = stream.tell()
    except (OSError, EOFError, zlib.error):
        raise DumpError("failed gzip integrity verification (truncated or corrupt)") from None
    if not safe:
        raise DumpError("lacks safe pg_dump restricted framing or contains executable commands or lacks the final PostgreSQL database dump complete marker")

    return size


if __name__ == "__main__":
    try:
        outputs = {"--dump-excludes": "\n".join(DUMP_EXCLUDE_OPTIONS),
                   "--preserved-schemas": json.dumps(PRESERVED_SCHEMAS),
                   "--session-cutoff": SESSION_CUTOFF_SQL,
                   "--catalog-gate": CATALOG_GATE_SQL, "--capture-catalog": CATALOG_CAPTURE_SQL,
                   "--verify-live-catalog": CATALOG_VERIFY_LIVE_SQL,
                   "--prepare-restore": RESTORE_PREPARE_SQL, "--recover-schemas": RESTORE_RECOVER_SCHEMAS_SQL,
                   "--restore-extensions": RESTORE_EXTENSIONS_SQL}
        if len(sys.argv) == 2 and sys.argv[1] in outputs:
            print(outputs[sys.argv[1]])
        elif sys.argv[1] == "--stamp":
            stamp_backup(sys.argv[3], sys.argv[2])
        elif sys.argv[1] == "--stamp-installed":
            stamp_installed_backup(sys.argv[2], sys.argv[3])
        else:
            validate_dump(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    except (OSError, DumpError) as error:
        print("FAIL restore " + str(error), file=sys.stderr)
        sys.exit(EXIT_REJECTED_BEFORE_MUTATION)
