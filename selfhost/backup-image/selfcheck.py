#!/usr/bin/env python3
"""Restore the scheduled dump into a reserved scratch database before publication."""

import gzip
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys


SCRATCH = "chronicle_restore_selfcheck"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from chronicle_ops.dump import APPLICATION_TABLE_POLICIES, BACKUP_SCRATCH_FACTOR, CATALOG_GATE_SQL, DUMP_EXCLUDE_OPTIONS, RESTORE_EXTENSIONS_SQL, publish_backup, validate_dump

MANIFEST_SQL = """
SELECT json_build_object(
  'database_bytes', pg_database_size(current_database()),
  'version', coalesce((SELECT max(version) FROM public.flyway_schema_history), ''),
  'extensions', (SELECT json_agg(extname ORDER BY extname) FROM pg_extension),
  'tables', (SELECT coalesce(json_agg(c.relname ORDER BY c.relname), '[]'::json)
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')))
"""


def row_counts_sql(tables):
    # Use restore's reviewed table inventory, counting only tables present in this schema version.
    counts = " UNION ALL ".join(f"SELECT '{table}' AS name, count(*) AS rows FROM {table}"
                                for table in APPLICATION_TABLE_POLICIES if table.removeprefix("public.") in tables)
    # A parallel count over a pg_tde table segfaults the backend; compose turns parallelism off, an override must not.
    return ("SET max_parallel_workers_per_gather = 0;\n"
            "SELECT coalesce(json_object_agg(name, rows), '{}'::json) FROM (" + counts + ") counts;"
            if counts else "SELECT '{}'::json;")


def psql(database, sql, capture=True, timeout=None):
    result = subprocess.run(
        ["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-d", database],
        input=sql, text=True, check=True, timeout=timeout,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
    )
    return result.stdout.strip() if capture else ""


def drop_scratch():
    psql("postgres", f"DROP DATABASE IF EXISTS {SCRATCH} WITH (FORCE);", False, timeout=15)


def dump_snapshot(database, dump_file, options):
    # Keep the exporting transaction alive until pg_dump has consumed this exact snapshot.
    environment = os.environ.copy()
    environment["PGOPTIONS"] = environment.get("PGOPTIONS", "") + " -c idle_in_transaction_session_timeout=0"
    owner = subprocess.Popen(
        ["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-d", database],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=environment,
    )
    try:
        owner.stdin.write("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n")
        owner.stdin.write(CATALOG_GATE_SQL + "\nSELECT pg_export_snapshot();\n" + MANIFEST_SQL + ";\n")
        owner.stdin.flush()
        snapshot = owner.stdout.readline().strip()
        if not re.fullmatch(r"[0-9A-Fa-f]+-[0-9A-Fa-f]+-[0-9]+", snapshot):
            raise RuntimeError("source snapshot unavailable")
        manifest = json.loads(owner.stdout.readline())
        owner.stdin.write(row_counts_sql(manifest["tables"]) + "\n")
        owner.stdin.flush()
        manifest["row_counts"] = json.loads(owner.stdout.readline())
        command = ["pg_dump", "-d", database, *options, *DUMP_EXCLUDE_OPTIONS, "--snapshot=" + snapshot]
        # Keep pg_dump's existing output/options, including its compression and table AMs.
        with open(dump_file, "xb") as output:
            subprocess.run(command, stdout=output, check=True)
            output.flush()
            os.fsync(output.fileno())
        owner.stdin.write("ROLLBACK;\n\\q\n")
        owner.stdin.flush()
        owner.stdin.close()
        if owner.wait() != 0:
            raise RuntimeError("source snapshot failed")
        return manifest
    finally:
        if owner.poll() is None:
            owner.terminate()
        owner.wait()
        owner.stdout.close()
        if not owner.stdin.closed:
            owner.stdin.close()


def check_dump(database, dump_file, source):
    size = validate_dump(dump_file)

    # PostgreSQL has no free-space SQL API; server-side df measures its volume, not the sidecar.
    try:
        disk = psql(database, """
CREATE TEMP TABLE backup_selfcheck_disk (line text);
COPY backup_selfcheck_disk FROM PROGRAM 'df -Pk -- "$PGDATA"';
SELECT line FROM backup_selfcheck_disk;
""")
        available = int(disk.splitlines()[-1].split()[3]) * 1024
        if available < BACKUP_SCRATCH_FACTOR * max(size, source["database_bytes"]):
            raise ValueError("too small")
    except (subprocess.CalledProcessError, ValueError, IndexError):
        raise RuntimeError("insufficient space") from None

    drop_scratch()
    psql("postgres", f"CREATE DATABASE {SCRATCH} TEMPLATE template0;", False)
    encryption = os.environ.get("ENABLE_ENCRYPTION", "true")
    if encryption not in ("true", "false"):
        raise ValueError("ENABLE_ENCRYPTION must be true or false")
    method = "tde_heap" if encryption == "true" else "heap"
    if encryption == "true":
        init_tde = Path(__file__).with_name("init-tde.sh")
        if not init_tde.is_file():
            init_tde = Path(__file__).resolve().parents[1] / "init-tde.sh"
        bootstrap = subprocess.run(["bash", str(init_tde), "--database-sql", SCRATCH],
                                   text=True, capture_output=True, check=True).stdout
        psql(SCRATCH, bootstrap, False)
        ready = psql(SCRATCH, """
SELECT current_setting('default_table_access_method') = 'tde_heap'
   AND (SELECT key_name IS NOT NULL FROM pg_tde_key_info());
""")
        if ready != "t":
            raise RuntimeError("scratch database lacks TDE key or tde_heap default")
    # Exactly what restore.sh creates on a fresh volume, so a missing extension fails here too.
    psql(SCRATCH, RESTORE_EXTENSIONS_SQL, False)
    restore = subprocess.Popen(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", SCRATCH],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
    )
    try:
        with gzip.open(dump_file, "rb") as stream:
            while chunk := stream.read(1024 * 1024):
                restore.stdin.write(chunk)
        restore.stdin.close()
        if restore.wait() != 0:
            raise RuntimeError("restore failed")
    except BrokenPipeError:
        raise RuntimeError("restore failed") from None
    finally:
        if not restore.stdin.closed:
            try:
                restore.stdin.close()
            except BrokenPipeError:
                pass
        restore.wait()
    restored = json.loads(psql(SCRATCH, CATALOG_GATE_SQL + "\n" + MANIFEST_SQL + ";"))
    missing = set(source["extensions"]) - set(restored["extensions"]) - ({"pg_tde"} if encryption == "false" else set())
    if missing:
        raise RuntimeError("restored database lacks extensions: " + ", ".join(sorted(missing)))
    if restored["version"] != source["version"]:
        raise RuntimeError("schema version mismatch")
    if not set(source["tables"]).issubset(restored["tables"]):
        raise RuntimeError("missing public tables")
    restored_counts = json.loads(psql(SCRATCH, row_counts_sql(restored["tables"])))
    for table, count in source["row_counts"].items():
        if restored_counts.get(table) != count:
            raise RuntimeError(f"{table.removeprefix('public.')} row count mismatch")
    wrong_method = psql(SCRATCH, f"""
SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 JOIN pg_am a ON a.oid = c.relam
 WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.amname <> '{method}';
""")
    if wrong_method != "0":
        raise RuntimeError(f"restored tables do not use {method}")


def main(args=None):
    args = sys.argv[1:] if args is None else args
    if args == ["health"]:
        try:
            published = Path(os.environ["BACKUP_SUCCESS_MARKER"]).read_text().splitlines()
            if not published:
                return 1
            for filename in published:
                if Path(filename).stat().st_size == 0:
                    return 1
            return 0
        except (OSError, ValueError, KeyError):
            return 1
    mode, database, filename, *options = args
    if database == SCRATCH:
        print("Restore self-check FAIL: scratch database cannot be the source", file=sys.stderr)
        return 1  # Do not let cleanup drop the configured source.
    dump_file = Path(filename)
    partial = dump_file.with_name(dump_file.name + ".partial")
    status = 1
    descriptor = os.open(dump_file.parent / ".backup-verification.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    try:
        if mode != "dump":
            raise ValueError("unknown self-check mode")
        # A killed run leaves its dump fragment or publish_backup's release-stamp copy; both hold full data.
        for pattern in ("-*.sql.gz.partial", "-*.sql.gz*.release.partial"):
            for abandoned in dump_file.parent.glob(database + pattern):
                abandoned.unlink()
        source = dump_snapshot(database, partial, options)
        check_dump(database, partial, source)
        status = 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("Restore self-check FAIL: " + str(error), file=sys.stderr, flush=True)
    finally:
        try:
            drop_scratch()
        except (OSError, subprocess.SubprocessError):
            print("Restore self-check FAIL: scratch cleanup failed", file=sys.stderr, flush=True)
            status = 1
        if status == 0:
            try:
                publish_backup(dump_file, database, source, pending=partial)
                print("Restore self-check OK: restore verified", flush=True)
            except (OSError, ValueError) as error:
                print("Restore self-check FAIL: " + str(error), file=sys.stderr, flush=True)
                if not partial.exists():
                    dump_file.unlink(missing_ok=True)
                status = 1
        try:
            partial.unlink(missing_ok=True)
        finally:
            os.close(descriptor)
    return status


def interrupted(signum, _frame):
    raise RuntimeError(f"self-check interrupted by signal {signum}")


if __name__ == "__main__":
    for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    sys.exit(main())
