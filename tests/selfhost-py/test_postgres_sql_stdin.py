"""release.postgres_sql passes SQL to psql verbatim on stdin, never through a shell string."""
import os
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
