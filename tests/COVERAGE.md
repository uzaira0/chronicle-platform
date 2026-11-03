# Coverage map

Line coverage is measured for Kotlin only: JaCoCo runs in the `jvm-smoke` job. The areas below
produce no line coverage, so each one is listed with the suite that executes it.

| Blind area | Executed by | Gate |
|---|---|---|
| Flyway migrations (`chronicle-server/src/main/resources/db/migration`) | `FlywayMigrationCorpusTest`, `tests/security/migration-safety.sh`, `scripts/check-migrations-safe.sh` | `jvm-smoke`, `migration-safety` |
| Row-level security policies | `chronicle-server/src/test/resources/pgtap/rls_matrix.sql` via `PgTapSuiteTest`; `tests/security/run-rls-guardrails.sh` | `jvm-smoke`, `security-layers` |
| SQL functions and triggers | `chronicle-server/src/test/resources/pgtap/*.sql` via `PgTapSuiteTest` | `jvm-smoke` |
| `selfhost/restore.sh` | `tests/security/selfhost-restore-failclosed.sh`, `selfhost-restore-orchestration.sh`, `tests/selfhost-py/test_restore.py` | `security-layers` (deploy) |
| `selfhost/restore-*.sql` templates | `tests/selfhost-py/test_restore_schemas.py` | `security-layers` (deploy) |
| `selfhost/Caddyfile.split*` | `tests/security/selfhost-combination-matrix.sh` | `security-layers` (deploy) |

`diff-coverage` (fast group) requires 80% of changed executable lines covered in the two repositories
whose reports the group produces: `chronicle-server` (JaCoCo from `jvm-smoke`) and `chronicle-web`
(lcov from `web`). Changed lines in other repositories, and Python and Bash everywhere, are not
measured; the suites in the table above execute them.
