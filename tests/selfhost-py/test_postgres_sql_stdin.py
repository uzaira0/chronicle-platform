"""release.postgres_sql passes SQL to psql verbatim on stdin, never through a shell string."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "selfhost"))
from chronicle_ops import release


class PostgresSqlTests(unittest.TestCase):
    def test_sql_with_quotes_and_dollars_reaches_psql_verbatim(self):
        with tempfile.TemporaryDirectory() as folder:
            bin_dir = Path(folder)
            (bin_dir / "docker").write_text('#!/bin/bash\nshift\n[[ "$1" == -i ]] && shift\nshift\nexec "$@"\n')
            (bin_dir / "psql").write_text('#!/bin/bash\nif [[ " $* " == *" -f - "* ]]; then cat; else for a; do [[ "$prev" == -tAqc ]] && printf "%s" "$a"; prev="$a"; done; fi\n')
            for name in ("docker", "psql"):
                (bin_dir / name).chmod(0o700)
            query = """SELECT '$HOME "quoted"' AS "x"; -- `id`"""
            with patch.dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", POSTGRES_PASSWORD="fixture"):
                self.assertEqual(release.postgres_sql("fixture-postgres", query), query)


if __name__ == "__main__":
    unittest.main()


class BoundIdentifierTests(unittest.TestCase):
    """AF-P11: deletion-status and doctor's reviewer check pass identifiers to psql as variables.

    The in-container script runs here with a psql that records its arguments and the SQL it reads.
    Bound values leave the SQL text identical whatever the identifiers are."""

    ROOT = Path(__file__).resolve().parents[2]
    SCRIPT = '''set -eu
fixture_host="$PWD"
source "$OPS_PACKAGE/chronicle"
source "$OPS_PACKAGE/doctor.sh"
cd "$fixture_host"
die() { echo "$*" >&2; exit 1; }
need_env() { :; }
begin_operation() { :; }
operation_succeeded() { :; }
# dc exec -T postgres /bin/bash -euc SCRIPT [ARGS]: run SCRIPT here, as the container would.
dc() { shift 3; POSTGRES_PASSWORD=fixture "$@"; }
case "$1" in
  deletion-status) shift; cmd_deletion_status deletion-status "$@" ;;
  reviewer) shift; reviewer_scope_state "$@" ;;
esac
'''

    def run_case(self, *args):
        with tempfile.TemporaryDirectory() as folder:
            tools = Path(folder)
            (tools / 'psql').write_text('#!/bin/bash\nprintf "%s\\n" "$@" >"$RECORD.args"\ncat >"$RECORD.sql"\n')
            (tools / 'psql').chmod(0o700)
            record = tools / 'record'
            result = subprocess.run(['bash', '-c', self.SCRIPT, 'fixture', *args], cwd=folder, capture_output=True,
                                    text=True, timeout=20, check=False,
                                    env=dict(os.environ, OPS_PACKAGE=str(self.ROOT / 'selfhost'), RECORD=str(record),
                                             PATH=f"{tools}:{os.environ['PATH']}"))
            self.assertEqual(0, result.returncode, result.stderr)
            return (tools / 'record.args').read_text().splitlines(), (tools / 'record.sql').read_text()

    def test_deletion_status_binds_both_identifiers(self):
        first, second = '0b7d3a2e-6f4c-4e0a-9d1e-2b3c4d5e6f70', '9f8e7d6c-5b4a-4321-8fed-cba987654321'
        operation = '11111111-2222-4333-8444-555555555555'
        arguments, sql = self.run_case('deletion-status', first, operation)
        self.assertIn(f'study_id={first}', arguments)
        self.assertIn(f'operation_id={operation}', arguments)
        self.assertNotIn(first, sql)
        self.assertNotIn(operation, sql)
        self.assertEqual(sql, self.run_case('deletion-status', second)[1])
        self.assertIn('operation_id=', self.run_case('deletion-status', second)[0])

    def test_reviewer_scope_binds_study_and_participant(self):
        study = '0b7d3a2e-6f4c-4e0a-9d1e-2b3c4d5e6f70'
        arguments, sql = self.run_case('reviewer', study, 'synthetic.reviewer-1')
        self.assertIn(f'study_id={study}', arguments)
        self.assertIn('participant_id=synthetic.reviewer-1', arguments)
        self.assertNotIn(study, sql)
        self.assertEqual(sql, self.run_case('reviewer', '9f8e7d6c-5b4a-4321-8fed-cba987654321', 'other')[1])
