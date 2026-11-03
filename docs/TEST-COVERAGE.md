# Test coverage

The local gate measures server and Android JVM sources with JaCoCo, the web application
with Bun's lcov reporter, and selfhost Python with coverage.py 7.6.1. `diff-coverage`
requires those reports for changed production sources and rejects reports older than the
changed source. Android reports include the Open, Research and Amazon test variants and
the tested collection libraries. The existing changed-line floor remains 80%.

`selfhost-python` runs the same strict unittest runner as the operator checks: failures
and skipped required checks fail the job. The coverage report measures the Python code
executed in that process. The web config property corpus uses a fixed seed and bounded
inputs; the security group runs the server's duration-bounded Jazzer targets.

## Code without a line-coverage report

| Code | Behavioral proof in the gate |
|---|---|
| Bash launchers, operator scripts and Python child processes | `engineering` runs ShellCheck and the cached workstation-path check. `selfhost-python`, `selfhost-restore` and the security shell fixtures execute launcher, failure and restore behavior. |
| SQL migrations and stored SQL | `migration-safety` checks migration safety; `jvm-smoke` runs the server database tests, including `PgTapSuiteTest` and `SchemaInvariantsTest`, against PostgreSQL. |
| PostgreSQL RLS policies and role/context behavior | `jvm-smoke` runs `RlsCoverageTest`, the policy-specific `*RlsTest` classes and `RLSRequestContextTest`; `selfhost-restore` checks preserved restore/session behavior. |
| Android native/device behavior | JVM migration tests verify released Room identities and preserved rows. The release's device upgrade and journey checks supply the platform proof. |

Execution results, failures and source revisions belong in the local gate report. A missing
required environment or an unexecuted device check remains a verification gap in that report.
