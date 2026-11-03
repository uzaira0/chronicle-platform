"""Probe the configured public and internal exposure boundaries."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from enum import Enum
from gettext import gettext as _
import getpass
from http.cookiejar import MozillaCookieJar
import ipaddress
import json
import os
import plistlib
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from typing import NamedTuple
from urllib.parse import urlsplit

from .common import BLD, GIB, GRN, RED, RST, YEL, LOW_FREE_PERCENT, MIN_FREE_INODES, compose, compose_project, dashboard_ca, dashboard_origin, database_volume_path, run, require, storage_report
from .mobile_canary import CANARY_FILE_SETTING
from .credentials import parse_timestamp, secret_dates
from .dump import BACKUP_SCRATCH_FACTOR, BACKUP_VERIFICATION_CACHE, TDE_GENERATION_SCHEMA, DumpError, cached_verified_backup, validate_dump, verified_backup
from .release import free_disk_floor, postgres_sql
from .env_migration import DeploymentMode, deployment_mode
from .envfile import read_env, value
from .route_surface import PUBLIC_SURFACE

BACKUP_COMPRESSION_ESTIMATE = 0.20
BACKUP_RETENTION_KEYS = ("BACKUP_KEEP_DAYS", "BACKUP_KEEP_WEEKS", "BACKUP_KEEP_MONTHS")
# Doctor warns below this share of free space; only the MIN_FREE_DISK_GIB startup reserve fails.
WAL_WARNING_FACTOR = 2
METRICS_MAX_AGE_SECONDS = 120
RATE_LIMIT_PROBE_WORKERS = 32
RATE_LIMIT_PROBE_MAX_REQUESTS = 400
MONITORING_JOBS = {"chronicle-backend", "chronicle-containers", "chronicle-host", "chronicle-operational",
                   "chronicle-log-forwarder", "chronicle-operations", "chronicle-configuration"}
DATABASE_PRIVILEGES_VIOLATION = 1
DATABASE_PRIVILEGES_UNAVAILABLE = 2
DATABASE_PRIVILEGES_RECOVERY = "Recover a reviewed backup that preserves ACLs"
DATABASE_PRIVILEGES_RETRY = "Restore database connectivity and rerun doctor"

DATABASE_PRIVILEGES_SQL = """
SELECT NOT EXISTS (
    SELECT 1 FROM (VALUES
        ('chronicle_app', 'audit', 'SELECT,UPDATE,DELETE,TRUNCATE'),
        ('chronicle_app', 'audit_buffer', 'SELECT,UPDATE,DELETE,TRUNCATE'),
        ('chronicle_admin', 'audit', 'UPDATE,DELETE,TRUNCATE'),
        ('chronicle_admin', 'audit_buffer', 'UPDATE,DELETE,TRUNCATE'),
        ('chronicle_app', 'data_deletion_audit_outbox', 'DELETE,TRUNCATE'),
        ('chronicle_app', 'restore_continuity_reconciliations', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'),
        ('chronicle_admin', 'restore_continuity_reconciliations', 'INSERT,UPDATE,DELETE,TRUNCATE')
    ) AS forbidden(role_name, table_name, privileges)
    WHERE to_regclass('public.' || table_name) IS NULL
       OR has_table_privilege(role_name, to_regclass('public.' || table_name), privileges)
) AND NOT EXISTS (
    SELECT 1 FROM (VALUES
        ('chronicle_app', 'studies', 'SELECT'),
        ('chronicle_app', 'audit', 'INSERT')
    ) AS required(role_name, table_name, privilege)
    WHERE to_regclass('public.' || table_name) IS NULL
       OR NOT has_table_privilege(role_name, to_regclass('public.' || table_name), privilege)
)
""".strip()


class CheckResult(NamedTuple):
    status: int
    message: str


class SessionResult(NamedTuple):
    authenticated: bool
    http_code: str


def verify_database_privileges():
    try:
        container = compose("ps", "-q", "postgres", capture=True, check=True).stdout.strip()
        require(container, "PostgreSQL container is unavailable")
        answer = postgres_sql(container, DATABASE_PRIVILEGES_SQL)
        require(answer in ("t", "f"), "invalid database privileges query result")
    except (OSError, ValueError, subprocess.SubprocessError):
        return CheckResult(DATABASE_PRIVILEGES_UNAVAILABLE, f"Could not check database privileges. {DATABASE_PRIVILEGES_RETRY}.")
    if answer == "f":
        return CheckResult(DATABASE_PRIVILEGES_VIOLATION, f"Database runtime privileges violate audit/restore least privilege. {DATABASE_PRIVILEGES_RECOVERY}.")
    return CheckResult(0, "Database runtime roles retain audit and restore privilege restrictions")


def free_space_row(name, subject, free_percent, free):
    """A low percentage is advice. Failure belongs to storage_report's startup reserve, which
    ./chronicle up enforces, so doctor never fails a filesystem that startup accepts. free_percent
    is None when the filesystem reports no block counts (df prints "-")."""
    if free_percent is None:
        return (name, "warn", _("{subject} capacity could not be read").format(subject=subject),
                _("Run df -h on the Chronicle state and database filesystems"))
    if free_percent >= LOW_FREE_PERCENT:
        return (name, "ok", _("{subject} has {percent}% free ({gib} GiB)").format(
            subject=subject, percent=free_percent, gib=free // GIB), "none")
    return (name, "warn", _("{subject} has only {percent}% free ({gib} GiB)").format(
        subject=subject, percent=free_percent, gib=free // GIB),
            _("Plan more capacity before free space reaches MIN_FREE_DISK_GIB, where ./chronicle up refuses to start"))


def disk_rows(settings, state):
    """Doctor's host filesystem rows; they need Docker but not the database."""
    disk = os.statvfs(state)
    # df's rounding: the used share rounds up, so the free share rounds down.
    usable = disk.f_blocks - disk.f_bfree + disk.f_bavail
    free_percent = 100 * disk.f_bavail // usable if usable > 0 else None
    rows = [free_space_row("disk", "Host filesystem", free_percent, disk.f_bavail * disk.f_frsize)]
    try:
        report = storage_report(state, os.environ.get("CHRONICLE_OPS_PROJECT", compose_project(settings)),
                                free_disk_floor(settings))
    except (OSError, ValueError, subprocess.SubprocessError):
        # The reserve covers Docker's and the database's filesystems, which only Docker can name.
        return rows + [("storage-reserve", "fail", _("Startup disk reserve could not be measured"),
                        _("Check Docker connectivity, then rerun ./chronicle doctor"))]
    for name, enough, available, inodes, required in report:
        rows.append((name + "-reserve", "ok" if enough else "fail",
                     _("{name}: {available} bytes and {inodes} inodes free; startup requires {required} bytes and {minimum_inodes} inodes").format(
                         name=name, available=available, inodes=inodes, required=required, minimum_inodes=MIN_FREE_INODES),
                     "none" if enough else _("Add filesystem capacity before restarting Chronicle")))
    return rows


def capacity_checks(settings, backups):
    command = ('df -Pk "$PGDATA"; '
               'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -qAt -h 127.0.0.1 '
               '-U "${POSTGRES_USER:-chronicle}" -d "${POSTGRES_DB:-chronicle}" -c '
               "\"SELECT json_build_object('database_bytes',pg_database_size(current_database()),"
               "'wal_bytes',(SELECT coalesce(sum(size),0) FROM pg_ls_waldir()),"
               "'max_wal_bytes',pg_size_bytes(current_setting('max_wal_size')))\"")
    result = compose("exec", "-T", "postgres", "/bin/bash", "-ceu", command, capture=True, timeout=15, check=True)
    lines = result.stdout.splitlines()
    data = json.loads(lines[-1])
    free = int(lines[-2].split()[3]) * 1024
    used = lines[-2].split()[4].rstrip("%")
    free_percent = 100 - int(used) if used.isdigit() else None
    rows = [free_space_row("database-disk", "Database volume", free_percent, free)]
    database = value(settings, "POSTGRES_DB", "chronicle")
    dump_size = int(data["database_bytes"] * BACKUP_COMPRESSION_ESTIMATE)
    uncompressed = data["database_bytes"]
    backup_valid = False
    if "overlays/backups.yml" in value(settings, "COMPOSE_FILE"):
        try:
            backup = cached_verified_backup(backups, database, Path(backups) / BACKUP_VERIFICATION_CACHE,
                                            value(settings, "BACKUP_SCHEDULE"))
            dump_size = backup.path.stat().st_size
            uncompressed = max(uncompressed, backup.uncompressed_bytes)
            backup_valid = True
        except (OSError, ValueError, KeyError):
            pass
    reserve = BACKUP_SCRATCH_FACTOR * uncompressed
    wal = ("postgres-wal", "warn" if data["wal_bytes"] > WAL_WARNING_FACTOR * data["max_wal_bytes"] else "ok",
           f"pg_wal uses {data['wal_bytes']} bytes; soft max_wal_size is {data['max_wal_bytes']}", "Inspect replication slots and long transactions; never delete WAL files")
    if "overlays/backups.yml" not in value(settings, "COMPOSE_FILE"):
        return rows + [wal]
    rows.append(("backup", "ok" if backup_valid else "fail",
                 "Active database has a fresh restore-verified backup" if backup_valid else "Active database has no fresh verified backup",
                 "none" if backup_valid else "Inspect db-backup logs and available scratch capacity"))
    rows.append(("backup-reserve", "ok" if free >= reserve else "fail",
                 f"Next restore-check needs {reserve} additional bytes; database filesystem has {free}", "Add database capacity before the next backup"))
    rows.append(backup_footprint(settings, backups, dump_size))
    rows.append(wal)
    return rows


def backup_footprint(settings, backups, dump_size=None):
    """Whether the backup filesystem holds the operator's chosen retention and still keeps
    MIN_FREE_DISK_GIB free. Setup, check and doctor share this estimate; dump_size defaults
    to the newest dump on disk."""
    row, action = "backup-footprint", "Choose a shorter backup retention with ./chronicle setup, or add backup capacity"
    keep = [value(settings, key) for key in BACKUP_RETENTION_KEYS]
    if not all(keep):
        return (row, "warn", "Backup retention has not been chosen",
                "Run ./chronicle setup and answer the backup retention questions")
    dumps = {}
    for directory in ("last", "daily", "weekly", "monthly"):
        for path in (Path(backups) / directory).glob(value(settings, "POSTGRES_DB", "chronicle") + "-*.sql.gz"):
            if not path.is_symlink():
                info = path.stat()
                dumps[info.st_dev, info.st_ino] = (info.st_mtime, info.st_size)
    if dump_size is None:
        if not dumps:
            return (row, "ok", "No backup yet; the disk estimate appears after the first backup", "none")
        dump_size = max(dumps.values())[1]
    disk = os.statvfs(backups)
    free, floor_gib = disk.f_bavail * disk.f_frsize, int(free_disk_floor(settings))
    usable = free - floor_gib * 1024 ** 3
    kept = f"the backup filesystem has {free} bytes free and keeps MIN_FREE_DISK_GIB={floor_gib} GiB in reserve"
    if "all" in keep:
        return (row, "ok" if usable >= dump_size else "warn",
                f"Retention keeps every backup in at least one tier, so each dump adds about {dump_size} bytes; {kept}", action)
    count = sum(int(days) for days in keep) + 1
    additional = max(0, count * dump_size - sum(size for _, size in dumps.values()))
    return (row, "ok" if usable >= additional else "warn",
            f"Retention projects {count * dump_size} bytes ({count} dumps), {additional} more than on disk; {kept}", action)


def tde_key_generated_at():
    """Creation date init-tde.sh recorded for the active TDE key; None once a rotation replaced that key."""
    container = compose("ps", "-q", "postgres", capture=True, check=True).stdout.strip()
    require(container, "PostgreSQL container is unavailable")
    answer = postgres_sql(container, f"SELECT to_char(generated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') "
                                     f"FROM {TDE_GENERATION_SCHEMA}.chronicle_generated_key "
                                     "WHERE key_name = (SELECT key_name FROM pg_tde_key_info());")
    return parse_timestamp(answer) if answer else None


def secret_age_rows(settings, state, tde_generated_at=None, now=None):
    """Days since each secret was generated or last rotated. A report only: the age limit is the operator's policy."""
    dates = secret_dates(settings, state)
    if tde_generated_at is not None:
        dates['tde'] = max(tde_generated_at, dates.get('tde', tde_generated_at))
    now = now or datetime.now(timezone.utc)
    ages = ', '.join(f'{name} {(now - date).days} d' for name, date in sorted(dates.items()))
    return [('secret-ages', 'ok', 'Days since each secret was generated or rotated: ' + (ages or 'none recorded'), 'none')]


def healthy_targets(payload, now=None):
    targets = payload.get("data", {}).get("activeTargets", [])
    now = time.time() if now is None else now
    jobs = set()
    for target in targets:
        job = target.get("labels", {}).get("job")
        if job not in MONITORING_JOBS:
            continue
        try:
            age = now - parse_timestamp(target["lastScrape"]).timestamp()
        except (ValueError, KeyError):
            return False
        if target.get("health") != "up" or not 0 <= age <= METRICS_MAX_AGE_SECONDS:
            return False
        jobs.add(job)
    return jobs == MONITORING_JOBS


def monitoring_checks():
    result = compose("exec", "-T", "grafana", "wget", "-T", "8", "-qO-", "http://victoriametrics:8428/api/v1/targets", capture=True, timeout=15)
    metrics_ok = result.returncode == 0 and healthy_targets(json.loads(result.stdout))
    daemons_ready = all(compose("exec", "-T", "grafana", "wget", "-T", "8", "-q", "--spider", endpoint,
                               quiet=True, timeout=15).returncode == 0 for endpoint in
                        ("http://victoriametrics:8428/-/healthy", "http://victorialogs:9428/health", "http://fluent-bit:2020/api/v1/health"))
    metrics_ok &= daemons_ready
    # The existing operator-event tail path exercises Fluent Bit's redaction and delivery.
    category = "doctor_" + secrets.token_hex(8)
    compose("exec", "-T", "operational-probe", "/monitoring/record-operation.sh", "doctor", "success", category, check=True, timeout=15)
    deadline, delivered = time.monotonic() + 30, False
    while time.monotonic() < deadline:
        result = compose("exec", "-T", "grafana", "wget", "-T", "8", "-qO-",
                         "http://victorialogs:9428/select/logsql/query?query=failure_category%3A" + category,
                         capture=True, timeout=15)
        if result.returncode == 0 and category in result.stdout:
            delivered = True
            break
        time.sleep(2)
    return [("metrics-pipeline", "ok" if metrics_ok else "fail", "All required scrape targets and daemons are healthy and fresh" if metrics_ok else "A required target/daemon is missing, stale or unhealthy", "Inspect failed or missing VictoriaMetrics targets"),
            ("logs-pipeline", "ok" if delivered else "fail", "Redacted doctor canary traverses Fluent Bit to VictoriaLogs" if delivered else "Redacted canary was not delivered", "Inspect Fluent Bit tail input and delivery")]


STORAGE_ENCRYPTION_WAIVER = "BACKUP_STORAGE_ENCRYPTION_WAIVER"


def reviewed_storage_waiver(waiver):
    return bool(waiver.strip()) and "CHANGE_ME" not in waiver and not any(c in waiver for c in "\r\n")


def verify_backup_storage(backups, waiver="", subject="backup"):
    path = Path(backups).resolve()
    while not path.exists() and path != path.parent:
        path = path.parent
    encrypted = False
    try:
        if sys.platform == "darwin":
            device = run(["df", "-P", str(path)], capture=True)
            if device.returncode == 0:
                info = run(["diskutil", "info", "-plist", device.stdout.splitlines()[-1].split()[0]], capture=True)
                if info.returncode == 0:
                    data = plistlib.loads(info.stdout.encode())
                    encrypted = data.get("FileVault") is True or data.get("Encrypted") is True
        else:
            mount = run(["findmnt", "-n", "-o", "SOURCE", "-T", str(path)], capture=True)
            if mount.returncode == 0:
                device = mount.stdout.strip().split("[", 1)[0]
                devices = run(["lsblk", "--inverse", "--tree", "--json", "--output", "TYPE", device], capture=True)
                if devices.returncode == 0:
                    roots = json.loads(devices.stdout)["blockdevices"]
                    encrypted = bool(roots)
                    pending = [(entry, False) for entry in roots]
                    while pending:
                        entry, covered = pending.pop()
                        covered |= entry["type"] == "crypt"
                        children = entry.get("children", [])
                        if children:
                            pending.extend((child, covered) for child in children)
                        elif not covered:
                            encrypted = False
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        pass
    if encrypted:
        print(f"  {GRN}ok{RST}   {subject} backing device is encrypted")
        return 0
    if reviewed_storage_waiver(waiver):
        print(f"  {YEL}warn{RST} {subject} encryption uses a reviewed waiver; consult BACKUP_STORAGE_ENCRYPTION_WAIVER in the controlled register")
        return 0
    print(f"  {YEL}warn{RST} {subject} backing-device encryption is unconfirmed; enable it or record a reviewed BACKUP_STORAGE_ENCRYPTION_WAIVER")
    return 1


def verify_database_storage(project, waiver=""):
    """PostgreSQL WAL and pg_tde's keyring sit on this volume in plain form; only disk encryption covers them."""
    try:
        path = database_volume_path(project)
        if path is None:
            # Before the named volume exists, Docker's data root is its backing storage.
            info = run(["docker", "info", "--format", "{{.DockerRootDir}}"], capture=True, check=True).stdout.strip()
            path = Path(info) if info and Path(info).is_absolute() else None
    except (OSError, ValueError, subprocess.SubprocessError):
        path = None
    if path is None:
        if reviewed_storage_waiver(waiver):
            print(f"  {YEL}warn{RST} database storage uses a reviewed encryption waiver")
            return 0
        print(f"  {YEL}warn{RST} database volume was not found; its backing-device encryption is unconfirmed")
        return 1
    return verify_backup_storage(path, waiver, "database volume")


def verify_backup(backups, database=None, schedule=None):
    if database is not None:
        try:
            verified_backup(backups, database, schedule)
            print(f"  {GRN}ok{RST}   active database has a fresh restore-verified dump")
            return 0
        except (OSError, ValueError, KeyError, TypeError) as error:
            print(f"  {RED}FAIL{RST} verified backup unavailable: {error}")
            return 1
    candidates = sorted((Path(backups) / "last").glob("*.sql.gz"))
    if not candidates:
        print(f"  {RED}FAIL{RST} no SQL dump yet — nothing recoverable if the keyring is lost")
        return 1
    for path in candidates:
        try:
            validate_dump(path)
        except (OSError, DumpError) as error:
            print(f"  {RED}FAIL{RST} SQL dump {error}: {path}")
            return 1
    print(f"  {GRN}ok{RST}   a key-free SQL dump exists; recover with ./chronicle restore")
    return 0


def curl_config(name, text):
    if "\n" in text or "\r" in text:
        raise ValueError("credential must not contain a line break")
    return '{} = "{}"\n'.format(name, text.replace("\\", "\\\\").replace('"', '\\"'))


def curl(url, *args, config=None, timeout=10):
    parsed = urlsplit(url)
    settings = read_env(Path.cwd() / ".env") if (Path.cwd() / ".env").is_file() else {}
    from .ingress import VERIFY_HEADER, VERIFY_SCHEME, fence_path
    state = Path(os.environ.get('CHRONICLE_OPS_STATE', '.'))
    if fence_path(state).exists():
        secret = value(settings, 'CHRONICLE_INTERNAL_WEB_SECRET')
        require(secret, 'closed-ingress verification requires the internal web credential')
        config = (config or '') + curl_config('header', VERIFY_HEADER + ': ' + VERIFY_SCHEME + ' ' + secret)
    management = dashboard_origin(settings)
    trust = []
    if parsed.scheme == "https" and (url.startswith(management + "/") or deployment_mode(value(settings, "COMPOSE_FILE")) is DeploymentMode.LOCAL_HTTPS):
        tls = Path(os.environ.get("CHRONICLE_OPS_STATE", ".")) / "tls"
        certificate = dashboard_ca(tls) if url.startswith(management + "/") else tls / "local-ca.crt"
        trust = ["--cacert", str(certificate)]
    result = run(["curl", *trust, *(["--config", "-"] if config is not None else []),
                  "--noproxy", "*", "--silent", "--show-error", "--max-time", str(timeout), *args, url],
                 capture=True, input=config)
    return result.returncode, (result.stdout or "").rstrip("\n")


class ProbeStatus(Enum):
    """What one anonymous probe's HTTP answer proves about the boundary it tests."""
    REFUSED = "refused"
    FORBIDDEN = "forbidden"
    RATE_LIMITED = "rate-limited"
    SERVER_ERROR = "server error"
    UNREACHABLE = "unreachable"
    ACCEPTED = "accepted"


def probe_status(code, refused):
    if code in refused:
        return ProbeStatus.REFUSED
    if code == "403":
        # The internal listener's source allowlist answered before the boundary under test could.
        return ProbeStatus.FORBIDDEN
    if code == "429":
        return ProbeStatus.RATE_LIMITED
    if code in ("", "000"):
        return ProbeStatus.UNREACHABLE
    if code.startswith("5"):
        return ProbeStatus.SERVER_ERROR
    return ProbeStatus.ACCEPTED


def anonymous_request(url, *args):
    """One anonymous request: its HTTP status ("000" when nothing answered) and Retry-After header."""
    _, response = curl(url, "-o", "/dev/null", "-D", "-", "-w", "\n%{http_code}", *args)
    headers, _, code = response.rpartition("\n")
    retry_after = re.search(r"(?im)^retry-after:[ \t]*([^\r\n]+)", headers)
    return code or "000", retry_after.group(1).strip() if retry_after else None


def rerun_action(retry_after):
    # A 429 from the edge (caddy rate_limit) or the backend (RateLimitFilter) carries Retry-After.
    if retry_after:
        if retry_after.isascii() and retry_after.isdigit():
            return f"rerun ./chronicle verify after {retry_after} s (the server's Retry-After)"
        try:
            retry_at = parsedate_to_datetime(retry_after)
            if retry_at.tzinfo is not None:
                return f"rerun ./chronicle verify after {retry_at.astimezone(timezone.utc).isoformat()} (the server's Retry-After)"
        except (TypeError, ValueError, OverflowError):
            pass
    return "wait for the rate-limit window to pass, then rerun ./chronicle verify"


def report_refusal(report, subject, code, retry_after, refused, refused_text, accepted_text):
    status = probe_status(code, refused)
    text = {ProbeStatus.REFUSED: refused_text,
            ProbeStatus.FORBIDDEN: "was refused by the source allowlist before the app session check",
            ProbeStatus.RATE_LIMITED: "was rate limited, so the refusal is unproven; " + rerun_action(retry_after),
            ProbeStatus.SERVER_ERROR: "returned a server error",
            ProbeStatus.UNREACHABLE: "did not answer",
            ProbeStatus.ACCEPTED: accepted_text}[status]
    report(status is ProbeStatus.REFUSED, f"{subject} {text} ({code})")


def verify_public_origin(origin):
    if urlsplit(origin).scheme != "https":
        print("public acceptance requires an HTTPS origin", file=sys.stderr)
        return 1
    for path, expected in (("/health", "204"), ("/chronicle/", "200")):
        status, response = curl(origin.rstrip("/") + path, "-o", "/dev/null", "-w", "%{http_code}")
        if status or response != expected:
            if status:
                message = f"Could not complete public HTTPS {path} (curl exit {status}); check DNS, LB routing and released-client TLS trust."
            elif path == "/health" and response == "503":
                message = "HTTPS responded, but Chronicle is not ready (503). Inspect backend, database and encryption health."
            else:
                message = f"Public HTTPS {path} responded with HTTP {response} (expected {expected}). Inspect routing and the application response."
            print(message, file=sys.stderr)
            return 1
    return 0


def check_proxy_http_redirect(http_url, expected_location):
    status, response = curl(http_url, "--connect-timeout", "5", "--dump-header", "-",
                            "-o", "/dev/null", "-w", "\n%{http_code}")
    lines = response.replace("\r", "").splitlines()
    code = lines[-1] if lines else ""
    locations = [line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("location:")]
    return code if status == 0 and code in ("301", "302", "307", "308") and locations and locations[-1] == expected_location else None


def dashboard_session(origin, password):
    config = ""
    with tempfile.TemporaryDirectory(prefix="chronicle-session-") as folder:
        cookies = str(Path(folder) / "session")
        status, response = curl(origin + "/chronicle/v3/auth/dashboard-login", "--cookie-jar", cookies,
                                "-H", "Content-Type: application/json", "-H", "Origin: " + origin,
                                "-w", "\n%{http_code}", timeout=15,
                                config=config + curl_config("data-binary", json.dumps({"password": password})))
        body, _, code = response.rpartition("\n")
        try:
            login = json.loads(body)
            if status or code != "200" or login.get("authenticated") is not True or not login.get("csrfToken"):
                return SessionResult(False, code)
            status, response = curl(origin + "/chronicle/v3/auth/session", "--cookie", cookies, "--cookie-jar", cookies,
                                    "-H", "Origin: " + origin, "-w", "\n%{http_code}", config=config)
            body, _, code = response.rpartition("\n")
            session = json.loads(body)
            # /session reissues the CSRF cookie; the token it returns must be the one it set.
            jar = MozillaCookieJar(cookies)
            jar.load(ignore_discard=True, ignore_expires=True)
            issued = next((cookie.value for cookie in jar if cookie.name == "ol_csrf_token"), None)
            return SessionResult(status == 0 and code == "200" and session.get("authenticated") is True
                                 and bool(issued) and session.get("csrfToken") == issued, code)
        except (OSError, ValueError, AttributeError):
            return SessionResult(False, code)


def verification_password(args):
    dashboard_password = os.environ.pop("DASHBOARD_PASSWORD", "")
    if args:
        if dashboard_password:
            raise ValueError("use either --dashboard-password or DASHBOARD_PASSWORD, not both")
        if sys.stdin.isatty():
            dashboard_password = getpass.getpass("Dashboard password: ")
        else:
            line = sys.stdin.readline()
            if not line:
                raise ValueError("--dashboard-password expected one password line on stdin")
            dashboard_password = line.rstrip("\n")
        if not dashboard_password:
            raise ValueError("dashboard password must not be empty")
    return dashboard_password


def surface_probe(pub, retry_sleep, report):
    def hit(origin, path, served=False):
        code = "000"
        for _attempt in range(4):
            _output, code = curl(origin + path, *(["-L"] if served else []), "-o", "/dev/null", "-w",
                           "%{http_code} %{size_download}" if served else "%{http_code}")
            if code.split(" ")[0] != "429":
                break
            time.sleep(retry_sleep)
        return code

    def probe(path, expected, label="", origin=pub, served=False):
        response = hit(origin, path, served)
        code, _, size = response.partition(" ")
        ok = code in expected and (not served or (size.isdigit() and int(size) > 0))
        wanted = "reachable" if len(expected) == 3 else " or ".join(expected)
        detail = "" if ok else (f"was rate limited, so the answer is unproven; {rerun_action(None)} "
                                if probe_status(code, expected) is ProbeStatus.RATE_LIMITED else
                                f"served {size or '0'} bytes (expected 200 and a page) "
                                if served else f"(expected {wanted}) ")
        report(ok, f"{code:<3} {path} " + detail + label)


    return probe


def verify_public_surface(pub, probe):
    print(f"{BLD}Public surface{RST} ({pub})")
    for route in PUBLIC_SURFACE:
        probe(route.path, route.statuses, route.label, served=route.served)


def verify_internal_surface(settings, dashboard_password, report, probe):
    print(f"\n{BLD}Public surface must NOT expose the dashboard{RST}")
    for path in ("/chronicle/v3/auth/testing-login", "/chronicle/v3/auth/session", "/chronicle/v3/auth/oidc/login",
                 "/chronicle/api/web/study", "/chronicle/v3/time-use-diary/S/data", "/chronicle/v3/survey/S/questionnaire/Q/responses"):
        probe(path, ("404",))
    internal = dashboard_origin({key: value(settings, key) for key in ("DASHBOARD_BASE_URL", "INTERNAL_BIND", "INTERNAL_PORT")})
    print(f"\n{BLD}Internal surface{RST} ({internal})")
    status, _ = curl(internal + "/health", "-o", "/dev/null")
    report(status == 0, "internal listener is HTTPS (credentials are not sent in clear)" if not status else "internal listener did not answer over HTTPS")
    code, retry_after = anonymous_request(internal + "/chronicle/api/web/study")
    loopback_management = ipaddress.ip_address(value(settings, "INTERNAL_BIND", "127.0.0.1").strip("[]")).is_loopback
    source_rejected = probe_status(code, ("401",)) is ProbeStatus.FORBIDDEN and not loopback_management
    if source_rejected:
        print(f"  {YEL}--{RST} host is outside the researcher ACL; remote researcher acceptance is required")
        report(True, f"dashboard API requires an app session ({code})")
    else:
        report_refusal(report, "dashboard API", code, retry_after, ("401",),
                       "requires an app session", "answered without an app session")
        authenticated, code = dashboard_session(internal,
                                                "not-the-" + secrets.token_hex(4) + "-password")
        report_refusal(report, "wrong dashboard password", "200" if authenticated else code, None, ("401",),
                       "is rejected", "was not rejected")
    cors = compose("exec", "-T", "backend", "grep", "-qF", '"' + internal + '"', "/server/rendered-config/cors.yaml", quiet=True)
    report(cors.returncode == 0, "the dashboard origin is on the API allowlist" if not cors.returncode else f"the dashboard origin {internal} is not on the API allowlist — sign-in cannot complete.\n       Add it to DASHBOARD_ORIGINS in .env and run ./chronicle up again.")
    if dashboard_password and not source_rejected:
        deadline = time.monotonic() + 75
        while True:
            authenticated, code = dashboard_session(internal, dashboard_password)
            if code != "429" or time.monotonic() >= deadline:
                break
            time.sleep(15)
        report(authenticated, "backend issued an authenticated dashboard session and accepted its cookie" if authenticated else f"dashboard session contract failed ({code})")
    else:
        print(f"  {YEL}--{RST}   rerun with --dashboard-password to also check the correct password")


def verify_mobile_bootstrap(settings, pub, report):
    print(f"\n{BLD}Public mobile bootstrap{RST}")
    settings_path = "/chronicle/v3/study/00000000-0000-0000-0000-000000000000/settings/type/DataCollection"
    enrollment_path = "/chronicle/v4/study/00000000-0000-0000-0000-000000000000/participant/reviewer/enroll"
    reviewer_path = "/chronicle/v4/mobile/reviewer-enrollment"
    settings_code, settings_retry = anonymous_request(pub + settings_path)
    device = {"@class": "com.openlattice.chronicle.sources.AndroidDevice",
              **dict.fromkeys(("device", "model", "codename", "brand", "product", "randomDeviceId"), "selfhost-verifier"),
              "osVersion": "1", "sdkVersion": "1"}
    enrollment_code, enrollment_retry = anonymous_request(
        pub + enrollment_path, "-X", "POST", "-H", "Content-Type: application/json",
        "-H", "X-Chronicle-Random-Device-Id: selfhost-verifier", "--data", json.dumps(device, separators=(",", ":")))
    reviewer_code, reviewer_retry = anonymous_request(pub + reviewer_path, "-X", "POST")
    _, page = curl(pub + "/reviewer", "-L", "-o", "/dev/null", "-w", "%{http_code}|%{url_effective}|%{size_download}")
    parts = page.split("|")
    page_ok = len(parts) == 3 and parts[:2] == ["200", pub + "/chronicle/reviewer"] and parts[2].isdigit() and int(parts[2]) > 0
    report(page_ok, f"/reviewer reaches the anonymous Chronicle page ({pub}/chronicle/reviewer)" if page_ok else f"/reviewer did not reach a nonempty anonymous Chronicle page ({page})")
    reachable = settings_code.startswith("2") or settings_code in ("400", "404", "409", "422")
    if settings_code in ("000", "401", "403"):
        reason = "public collection settings are unavailable without a global app secret"
    elif settings_code.startswith("5"):
        reason = "public collection settings returned a server error"
    elif settings_code == "429":
        reason = "public collection settings were rate limited, so reachability is unproven; " + rerun_action(settings_retry)
    else:
        reason = "public collection settings are reachable" if reachable else "public collection settings returned an unexpected status"
    report(reachable, f"{reason} ({settings_code})")
    report_refusal(report, "enrollment without a one-time code", enrollment_code, enrollment_retry, ("401", "403"),
                   "is refused", "was not refused")
    report_refusal(report, "exact reviewer route", reviewer_code, reviewer_retry, ("401", "403", "404"),
                   "refuses requests without its credential", "accepted an unauthenticated request")

    recipe = value(settings, CANARY_FILE_SETTING, os.environ.get(CANARY_FILE_SETTING, ""))
    state = "configured for release smoke only" if recipe else "not configured"
    print(f"  {YEL}--{RST}   mobile canary {state}; enrollment and upload probes run in the disposable release smoke")


def send_canary(request):
    config = ''.join(curl_config('header', key + ': ' + val) for key, val in request.headers.items())
    config += curl_config('data-binary', json.dumps(request.body))
    status, response = curl(request.url, '-X', 'POST', '-H', 'Content-Type: application/json',
                            '-w', '\n%{http_code}', config=config)
    body, _, code = response.rpartition('\n')
    if status or not code.startswith('2'):
        raise ValueError('synthetic mobile POST failed')
    return json.loads(body) if body else None


# Edge quotas cover only pre-authentication routes (caddy/snippets.caddy chronicle_mobile_rate_match).
MOBILE_RATE_PROBE = "/chronicle/v4/study/x/participant/x/enrollment-preview"


def verify_mobile_rate_limit(settings, pub, report):
    print(f"\n{BLD}Rate limiting{RST}")
    events = int(value(settings, "RATE_LIMIT_MOBILE_ABUSE_EVENTS", "200"))
    require(events > 0, "RATE_LIMIT_MOBILE_ABUSE_EVENTS must be positive")
    # Trusted SNAT has a fleet-sized edge ceiling; the backend still limits anonymous traffic.
    burst = min(events * 2, RATE_LIMIT_PROBE_MAX_REQUESTS)
    with ThreadPoolExecutor(max_workers=min(RATE_LIMIT_PROBE_WORKERS, burst)) as pool:
        codes = list(pool.map(lambda _: curl(pub + MOBILE_RATE_PROBE, "-o", "/dev/null", "-w", "%{http_code}")[1], range(burst)))
    report("429" in codes, "mobile enrollment abuse is rate limited by the edge" if "429" in codes else f"{burst} requests to mobile enrollment were never rate limited")


def verify_configured_backups(settings, report) -> None:
    backups = Path(os.environ["CHRONICLE_OPS_BACKUPS"])
    if "overlays/backups.yml" in value(settings, "COMPOSE_FILE"):
        report(verify_backup_storage(backups, value(settings, STORAGE_ENCRYPTION_WAIVER)) == 0,
               "Backup storage encryption check")
    if "overlays/backups.yml" in value(settings, "COMPOSE_FILE") and backups.is_dir():
        print(f"\n{BLD}Database dumps{RST}")
        mode_bits = stat.S_IMODE(backups.stat().st_mode)
        report(mode_bits == 0o700, f"{backups} is 0700 — dumps are not readable by other local accounts" if mode_bits == 0o700 else f"{backups} is {mode_bits:o} — every local account can read the full database (want 0700)")
        unwritable = sum(not os.access(directory, os.W_OK) for directory in [backups, *backups.iterdir()] if directory.is_dir())
        report(unwritable == 0, "dumps belong to this account — they can be pruned and copied without sudo" if not unwritable else f"{unwritable} director(y/ies) under {backups} are not writable by this account — backups cannot be pruned without sudo")
    if "overlays/backups.yml" in value(settings, "COMPOSE_FILE"):
        report(verify_backup(backups, value(settings, "POSTGRES_DB", "chronicle"), value(settings, "BACKUP_SCHEDULE")) == 0,
               "Backup restore verification")


def verify_encryption(settings, report):
    backups = Path(os.environ["CHRONICLE_OPS_BACKUPS"])
    if value(settings, "ENABLE_ENCRYPTION", "true") == "true":
        print(f"\n{BLD}Encryption at rest{RST}")
        counts = []
        for operator in ("=", "<>"):
            sql = "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_am a ON a.oid=c.relam WHERE n.nspname='public' AND c.relkind='r' AND a.amname" + operator + "'tde_heap';"
            try:
                result = compose("exec", "-T", "postgres", "/bin/bash", "-euc",
                                 'IFS= read -r -d "" PGPASSWORD\nexport PGPASSWORD\n'
                                 'exec psql -X -qAt -v ON_ERROR_STOP=1 -h 127.0.0.1 '
                                 '-U "${POSTGRES_USER:-chronicle}" -d "${POSTGRES_DB:-chronicle}" -f -',
                                 capture=True, input=value(settings, "POSTGRES_PASSWORD") + "\0" + sql + "\n")
                count = result.stdout.strip()
                require(result.returncode == 0 and count.isdigit(), "invalid encryption query result")
            except (OSError, ValueError, subprocess.SubprocessError):
                break
            counts.append(int(count))
        if len(counts) != 2:
            report(False, "Could not verify table encryption. Check the PostgreSQL query failure.")
        else:
            enc, plain = counts
            report(plain == 0 and enc > 0, f"all {enc} tables are encrypted (tde_heap)" if plain == 0 and enc > 0 else
                   f"{plain} table(s) still on plain heap" if plain else "No encrypted public tables were found. Check database initialization.")
        keyring = backups / "keyring" / "chronicle-keyring.per"
        report(keyring.is_file() and keyring.stat().st_size > 0,
               f"keyring copied into {backups}/keyring" if keyring.is_file() and keyring.stat().st_size > 0 else "The backup keyring copy is missing or empty. Check keyring backup creation before relying on these backups.")



def verify_proxy_surface(settings, mode, external, probe, report):
    if mode is DeploymentMode.BEHIND_PROXY:
        probe("/health", ("204",), "public HTTPS through the LB (strict certificate validation)", origin=external)
        probe("/chronicle/", ("200",), "public HTTPS assets through the LB", origin=external, served=True)
    if mode is DeploymentMode.BEHIND_PROXY and value(settings, "PUBLIC_HTTP_ENABLED", "false") == "true":
        external = external.rstrip("/")
        host = urlsplit(external).hostname
        http_authority = f"[{host}]" if host and ":" in host else host or ""
        http = "http://" + http_authority
        print(f"\n{BLD}External HTTP redirect{RST} ({http}/health)")
        code = check_proxy_http_redirect(http + "/health", external + "/health") if http_authority else None
        ok = code is not None
        report(ok, f"{code} redirects to the canonical HTTPS health URL ({external}/health)" if ok else f"HTTP /health must redirect with 301, 302, 307 or 308 to exactly {external}/health")


def verify(args):
    dashboard_password = verification_password(args)
    settings = read_env(Path.cwd() / ".env")
    def setting(key, default=""):
        return value(settings, key, default)
    if "CHRONICLE_OPS_STATE" in os.environ:
        require((Path.cwd() / (setting("CHRONICLE_STATE_DIR") or ".")).resolve() ==
                Path(os.environ["CHRONICLE_OPS_STATE"]).resolve(),
                "state directory changed while acquiring the lock; retry verification")
        require(compose_project(settings) == os.environ["CHRONICLE_OPS_PROJECT"],
                "Compose project changed while acquiring the lock; retry verification")
    os.environ["COMPOSE_FILE"] = setting("COMPOSE_FILE")
    dashboard_password = value(settings, "DASHBOARD_PASSWORD") or dashboard_password
    mode = deployment_mode(setting("COMPOSE_FILE"))
    exposure = "internal" if mode else ""
    external = setting("CHRONICLE_PUBLIC_BASE_URL") or "https://" + setting("DOMAIN")
    pub = external
    retry_sleep = float(setting("RATE_LIMIT_RETRY_SLEEP", "1.2"))
    failed = False

    def report(ok, message, *, warning=False):
        nonlocal failed
        status = "ok" if ok else "warn" if warning else "FAIL"
        color = GRN if ok else YEL if warning else RED
        print(f"  {color}{status}{RST}   {message}")
        failed |= not ok and not warning

    probe = surface_probe(pub, retry_sleep, report)
    verify_public_surface(pub, probe)
    if exposure == "internal":
        verify_internal_surface(settings, dashboard_password, report, probe)
    verify_mobile_bootstrap(settings, pub, report)
    verify_mobile_rate_limit(settings, pub, report)
    time.sleep(retry_sleep)
    privileges_status, privileges_message = verify_database_privileges()
    report(privileges_status == 0, privileges_message)
    verify_configured_backups(settings, report)
    verify_encryption(settings, report)
    report(verify_database_storage(compose_project(settings),
                                   setting(STORAGE_ENCRYPTION_WAIVER)) == 0,
           "Database volume storage encryption check")
    verify_proxy_surface(settings, mode, external, probe, report)
    print()
    if failed:
        print(f"{RED}Verification failed.{RST} Resolve the failed checks listed above.")
        return 1
    print(f"{GRN}Verified{RST} — exposure matches DASHBOARD_EXPOSURE={exposure}")
    if mode is DeploymentMode.BEHIND_PROXY:
        print("Public HTTPS passed from this host. Confirm phone enrollment and dashboard sign-in from their intended networks.")
    return 0


def service_contract_violations(paths):
    """Validate rendered service definitions and overlays without contacting Docker."""
    from .common import WRITABLE_ROOT_REASON_LABEL
    try:
        import yaml
    except ImportError:  # PyYAML is not an operator-host requirement; source CI has it.
        return "__NO_YAML__"

    base = {}
    defined = {}
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            document = yaml.safe_load(handle) or {}
        for name, service in (document.get("services") or {}).items():
            if path.endswith("docker-compose.yml"):
                base[name] = service
            if "image" in service:
                defined[(path, name)] = service
    problems = []
    for (path, name), service in sorted(defined.items()):
        label = f"{path}:{name}"
        labels = service.get("labels") or {}
        if isinstance(labels, list):
            labels = dict(entry.split("=", 1) for entry in labels if "=" in entry)
        if service.get("read_only") is not True and not str(labels.get(WRITABLE_ROOT_REASON_LABEL, "")).strip():
            problems.append(f"{label} root filesystem is writable without a justified exemption")
        if "logging" not in service:
            problems.append(f"{label} has no logging cap")
        if "no-new-privileges:true" not in (service.get("security_opt") or []):
            problems.append(f"{label} lacks no-new-privileges")
        if "ALL" not in (service.get("cap_drop") or []):
            problems.append(f"{label} does not drop all capabilities")
        if "pids_limit" not in service or "mem_limit" not in service:
            problems.append(f"{label} has no pid or memory limit")
        uid = str(service.get("user", "")).split(":")[0]
        if service.get("restart") not in (None, "no") and (uid == "root" or uid.isdecimal() and int(uid) == 0):
            if name == "docker-socket-proxy":
                if service.get("entrypoint") != ["haproxy"] or service.get("networks") != ["docker-api"] or service.get("cap_add"):
                    problems.append(f"{label} violates the documented socket-proxy root exception")
            elif name == "cadvisor":
                if service.get("networks") != ["monitoring", "docker-api"] or service.get("cap_add") or \
                        "--docker=tcp://docker-socket-proxy:2375" not in service.get("command", []) or \
                        any(not isinstance(volume, str) for volume in service.get("volumes", [])) or \
                        set(service.get("volumes", [])) != {"/:/rootfs:ro", "/sys:/sys:ro", "/var/lib/docker/:/var/lib/docker:ro"}:
                    problems.append(f"{label} violates the documented cAdvisor root exception")
            else:
                problems.append(f"{label} is long-running as root without a reviewed exception")
        for volume in service.get("volumes") or []:
            source = volume.split(":", 1)[0] if isinstance(volume, str) else volume.get("source", "")
            if source in ("/var/run", "/var/run/docker.sock", "/run", "/run/docker.sock"):
                # Only the GET-only proxy on its internal network may hold the socket.
                environment = service.get("environment") or {}
                if name != "docker-socket-proxy" or source != "/var/run/docker.sock" or str(environment.get("POST")) != "0" \
                        or service.get("networks") != ["docker-api"]:
                    problems.append(f"{label} mounts the Docker socket directory {source}")
        if service.get("restart") not in (None, "no") and "healthcheck" not in service and name not in {"victoriametrics", "victorialogs", "fluent-bit"}:
            problems.append(f"{label} is long-running with no healthcheck")
    networks = {}
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            networks.update((yaml.safe_load(handle) or {}).get("networks") or {})
    if "docker-api" in networks and (networks["docker-api"] or {}).get("internal") is not True:
        problems.append("the docker-api network that carries the Docker API proxy is not internal")
    return "\n".join(problems)
