#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
for cmd in git diff-cover python3; do
  command -v "$cmd" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$cmd" >&2; exit 127; }
done
mkdir -p "$ROOT_DIR/build/quality-selftest"
TEST_DIR="$(mktemp -d "$ROOT_DIR/build/quality-selftest/diff-coverage.XXXXXX")"
trap 'rm -rf "$TEST_DIR"' EXIT
cd "$TEST_DIR"
git init --quiet
mkdir -p src coverage
printf 'export const value = 1;\n' > src/tiny.ts
git add src/tiny.ts
git -c user.name=QualitySelftest -c user.email=quality-selftest@example.invalid commit --quiet -m baseline
BASE="$(git rev-parse HEAD)"
printf 'export const value = 2;\n' > src/tiny.ts

report() {
  printf 'TN:\nSF:src/tiny.ts\nDA:1,%s\nLF:1\nLH:%s\nend_of_record\n' "$1" "$1" > coverage/lcov.info
}

expect_failure() {
  local label="$1" message="$2"
  if "$ROOT_DIR/scripts/diff-coverage.py" --base "$BASE" --require .=lcov > result.log 2>&1; then
    printf 'FAIL: %s unexpectedly passed\n' "$label" >&2
    cat result.log >&2
    exit 1
  fi
  if ! rg -q -- "$message" result.log; then
    printf 'FAIL: %s failed for the wrong reason\n' "$label" >&2
    cat result.log >&2
    exit 1
  fi
  printf 'PASS: %s\n' "$label"
}

command -v rg >/dev/null 2>&1 || { printf 'missing command: rg\n' >&2; exit 127; }
report 0
expect_failure 'uncovered changed line' 'Coverage: 0%|diff coverage is below|Failure'
report 1
"$ROOT_DIR/scripts/diff-coverage.py" --base "$BASE" --require .=lcov > result.log 2>&1 || { cat result.log >&2; exit 1; }
printf 'PASS: covered changed line\n'
# Portable mtime one hour back (GNU touch -d and BSD touch -v differ; python3 is required above).
python3 -c 'import os, sys, time; t = time.time() - 3600; os.utime(sys.argv[1], (t, t))' coverage/lcov.info
expect_failure 'report older than the change' 'ignoring reports that predate the changed sources'
"$ROOT_DIR/scripts/diff-coverage.py" --base "$BASE" > result.log 2>&1 || { cat result.log >&2; exit 1; }
rg -q 'ignoring reports that predate' result.log || { cat result.log >&2; exit 1; }
printf 'PASS: an old report where no gate job requires one is ignored, not measured\n'
report 1
printf 'src/tiny.ts\n' > .diff-coverage-waivers
expect_failure 'waiver without reason' 'waiver requires a path glob and a reason'
rm .diff-coverage-waivers
rm coverage/lcov.info
"$ROOT_DIR/scripts/diff-coverage.py" --base "$BASE" > result.log 2>&1 || { cat result.log >&2; exit 1; }
printf 'PASS: a repository no gate job measures needs no report\n'
expect_failure 'missing report' 'changed web sources require coverage/lcov.info.*bun test --coverage'

report 0
printf 'src/tiny.ts deliberate selftest exception\n' > .diff-coverage-waivers
"$ROOT_DIR/scripts/diff-coverage.py" --base "$BASE" --require .=lcov > result.log 2>&1 || { cat result.log >&2; exit 1; }
printf 'PASS: reasoned waiver excludes the path\n'

rm .diff-coverage-waivers
git add -A && git -c user.name=QualitySelftest -c user.email=quality-selftest@example.invalid commit --quiet -m web
BASE="$(git rev-parse HEAD)"
rm -f coverage/lcov.info
printf 'print("changed Python")\n' > src/operator.py
printf '#!/usr/bin/env bash\necho "changed Bash"\n' > src/operator.sh
"$ROOT_DIR/scripts/diff-coverage.py" --base "$BASE" --require .=lcov > result.log 2>&1 || { cat result.log >&2; exit 1; }
printf 'PASS: Python and Bash, which no gate job measures, do not need a report\n'

printf 'export const a = 1;\nexport const b = 2;\n' > src/helper.ts
git add -A && git -c user.name=QualitySelftest -c user.email=quality-selftest@example.invalid commit --quiet -m helper
BASE="$(git rev-parse HEAD)"
printf 'export const a = 1;\nexport const c = 3;\n' > src/helper.ts
report 1
expect_failure 'added line in a source no report lists' 'changed source src/helper.ts is absent from coverage reports'
printf 'export const a = 1;\n' > src/helper.ts
report 1
"$ROOT_DIR/scripts/diff-coverage.py" --base "$BASE" --require .=lcov > result.log 2>&1 || { cat result.log >&2; exit 1; }
printf 'PASS: a deletion-only change leaves no line to measure\n'
mkdir -p e2e/dsl
printf 'export const step = 1;\n' > e2e/dsl/helper.ts
report 1
"$ROOT_DIR/scripts/diff-coverage.py" --base "$BASE" --require .=lcov > result.log 2>&1 || { cat result.log >&2; exit 1; }
printf 'PASS: Playwright helpers under e2e/ are test code\n'

git add -A && git -c user.name=QualitySelftest -c user.email=quality-selftest@example.invalid commit --quiet -m modules
rm -f coverage/lcov.info
jacoco() { # module, class: one covered line 2 in package p
  mkdir -p "$1/build/reports/jacoco/test"
  printf '<report name="%s"><package name="p"><sourcefile name="%s.kt"><line nr="2" mi="0" ci="1" mb="0" cb="0"/></sourcefile></package></report>\n' \
    "$1" "$2" > "$1/build/reports/jacoco/test/jacocoTestReport.xml"
}
for module in a b; do mkdir -p "$module/src/main/kotlin/p"; printf 'package p\nval x = 1\n' > "$module/src/main/kotlin/p/${module^^}.kt"; done
git add -A && git -c user.name=QualitySelftest -c user.email=quality-selftest@example.invalid commit --quiet -m jvm
BASE="$(git rev-parse HEAD)"
printf 'package p\nval x = 2\n' > a/src/main/kotlin/p/A.kt
jacoco a A
python3 -c 'import os, sys, time; t = time.time() - 7200; os.utime(sys.argv[1], (t, t)); t += 3600; os.utime(sys.argv[2], (t, t))' \
  a/src/main/kotlin/p/A.kt a/build/reports/jacoco/test/jacocoTestReport.xml
printf 'package p\nval x = 2\n' > b/src/main/kotlin/p/B.kt
jacoco b B
"$ROOT_DIR/scripts/diff-coverage.py" --base "$BASE" --require .=jacoco > result.log 2>&1 || { cat result.log >&2; exit 1; }
if rg -q 'predate' result.log; then cat result.log >&2; exit 1; fi
printf 'PASS: a newer change in another module leaves a module report current\n'
python3 -c 'import os, sys, time; t = time.time() - 3600; os.utime(sys.argv[1], (t, t))' b/build/reports/jacoco/test/jacocoTestReport.xml
"$ROOT_DIR/scripts/diff-coverage.py" --base "$BASE" --require .=jacoco > result.log 2>&1 && { cat result.log >&2; exit 1; }
rg -q 'predate the changed sources: b/build' result.log || { cat result.log >&2; exit 1; }
printf 'PASS: a report older than a change in its own module is ignored\n'
jacoco b B
mkdir -p tests/fixtures/rule/src/main/kotlin/p
printf 'package p\nval fixture = 1\n' > tests/fixtures/rule/src/main/kotlin/p/Fixture.kt
"$ROOT_DIR/scripts/diff-coverage.py" --base "$BASE" --require .=jacoco > result.log 2>&1 || { cat result.log >&2; exit 1; }
printf 'PASS: Kotlin rule fixtures under the root tests/ tree are not production sources\n'
