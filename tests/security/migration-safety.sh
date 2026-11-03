#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="$ROOT_DIR/scripts/check-migrations-safe.sh"
RUNS="${TMPDIR:-$ROOT_DIR/build/operator-test-runs}"
mkdir -p "$RUNS"
FIXTURE=$(mktemp -d "$RUNS/migration-safety.XXXXXX")
trap 'rm -rf -- "$FIXTURE"' EXIT
REPO="$FIXTURE/server"
MIGRATIONS="$REPO/src/main/resources/db/migration"
mkdir -p "$MIGRATIONS"
for version in 1 2 10; do
  printf 'CREATE TABLE fixture_%s (id INTEGER);\n' "$version" > "$MIGRATIONS/V${version}__fixture.sql"
done

assert_gate() {
  local expected=$1 label=$2 pattern=$3 result=0
  shift 3
  bash "$GATE" --server-dir "$REPO" "$@" > "$FIXTURE/output" 2>&1 || result=$?
  if { [[ "$expected" == pass ]] && ((result != 0)); } ||
     { [[ "$expected" == fail ]] && ((result == 0)); } ||
     ! grep -Eq "$pattern" "$FIXTURE/output"; then
    printf 'FAIL fixture: %s (exit %s)\n' "$label" "$result" >&2
    cat "$FIXTURE/output" >&2
    exit 1
  fi
  printf 'PASS fixture: %s\n' "$label"
}

NEW="$MIGRATIONS/V11__additive.sql"
cat > "$NEW" <<'SQL'
-- DROP TABLE fixture_1;
/* DROP COLUMN id;
   /* nested comment */ TRUNCATE fixture_2; */
ALTER TABLE fixture_1
    ADD COLUMN note TEXT;
DELETE FROM fixture_1
    WHERE id = 1;
SQL
assert_gate pass 'untracked additive SQL and comments' '^PASS additive-only \(b\)$'
printf '\n-- baseline may be rewritten before the reset release\n' >> "$MIGRATIONS/V1__fixture.sql"
assert_gate pass 'fresh baseline has no published-history dependency' '^PASS numbering \(c\)$'
mv "$MIGRATIONS/V2__fixture.sql" "$MIGRATIONS/V4__renamed.sql"
assert_gate pass 'fresh baseline may rename unpublished migrations' '^PASS numbering \(c\)$'

DANGEROUS="$MIGRATIONS/V12__destructive.sql"
printf 'ALTER TABLE fixture_1\n  DROP COLUMN note;\n' > "$DANGEROUS"
assert_gate fail 'DROP COLUMN with exact line (b)' '^FAIL additive-only: .*V12__destructive.sql:2: DROP COLUMN$'
printf '%s\n' '-- chronicle:destructive-approved Reviewed removal of the obsolete note.' \
  'ALTER TABLE fixture_1 DROP COLUMN note;' > "$DANGEROUS"
assert_gate pass 'recorded destructive approval (b)' '^PASS additive-only: .*approved: Reviewed removal'
printf '%s\n' '-- chronicle:destructive-approved   ' 'DROP TABLE fixture_1;' > "$DANGEROUS"
assert_gate fail 'empty approval rejected' '^FAIL additive-only \(b\)$'
printf '%s\n' 'SELECT 1;' '-- chronicle:destructive-approved Too late' 'DROP TABLE fixture_1;' > "$DANGEROUS"
assert_gate fail 'approval after SQL rejected' '^FAIL additive-only \(b\)$'
printf '%s\n' '/*' '-- chronicle:destructive-approved Hidden in a block' '*/' 'DROP TABLE fixture_1;' > "$DANGEROUS"
assert_gate fail 'marker inside block comment rejected' '^FAIL additive-only \(b\)$'

for sql in \
  'dRoP /* comment */ TaBlE fixture_1;' \
  'DROP SCHEMA chronicle CASCADE;' \
  'DROP MATERIALIZED VIEW fixture_view;' \
  'DROP EXTENSION pg_tde CASCADE;' \
  'DROP TYPE fixture_type CASCADE;' \
  'DROP SEQUENCE fixture_sequence;' \
  'DROP OWNED BY fixture_role;' \
  'ALTER TABLE fixture_1 DROP CONSTRAINT old_constraint;' \
  'ALTER TABLE fixture_1 ALTER COLUMN id TYPE BIGINT;' \
  'ALTER TABLE fixture_1 RENAME TO renamed;' \
  'ALTER TABLE fixture_1 RENAME COLUMN id TO renamed;' \
  'TRUNCATE fixture_1;' \
  'DELETE FROM fixture_1; SELECT 1 WHERE true;' \
  'DELETE FROM fixture_1 /* WHERE id = 1 */;' \
  'DELETE FROM fixture_1 USING (SELECT 1 WHERE true) AS ignored;' \
  'DO $$ BEGIN DELETE FROM fixture_1; END $$;' \
  "DO \$\$ BEGIN EXECUTE 'DROP TABLE fixture_1'; END \$\$;" \
  "DELETE FROM fixture_1 RETURNING 'WHERE';"; do
  printf '%s\n' "$sql" > "$DANGEROUS"
  assert_gate fail "$sql" '^FAIL additive-only \(b\)$'
done
printf '%s\n' "DELETE FROM fixture_1 WHERE note = '-- /* text */';" > "$DANGEROUS"
assert_gate pass 'comment syntax inside SQL string' '^PASS additive-only \(b\)$'
rm "$DANGEROUS"

printf 'CREATE TABLE backfill (id INTEGER);\n' > "$MIGRATIONS/V3__backfill.sql"
assert_gate pass 'version need not exceed a pre-reset release' '^PASS numbering \(c\)$'
rm "$MIGRATIONS/V3__backfill.sql"
printf 'CREATE TABLE duplicate (id INTEGER);\n' > "$MIGRATIONS/V010__duplicate.sql"
assert_gate fail 'normalized duplicate version' '^FAIL numbering: duplicate version V10'
rm "$MIGRATIONS/V010__duplicate.sql"
printf 'CREATE TABLE duplicate (id INTEGER);\n' > "$MIGRATIONS/V1.0__duplicate.sql"
assert_gate fail 'trailing zero is the same Flyway version' '^FAIL numbering: duplicate version V1 among'
rm "$MIGRATIONS/V1.0__duplicate.sql"
printf 'CREATE TABLE invalid (id INTEGER);\n' > "$MIGRATIONS/Vbad__invalid.sql"
assert_gate fail 'invalid version name' '^FAIL numbering: .*invalid versioned migration name'
rm "$MIGRATIONS/Vbad__invalid.sql"
printf "SELECT 'unterminated;\n" > "$MIGRATIONS/V12__invalid.sql"
assert_gate fail 'unterminated SQL quote' 'unterminated SQL comment or quote'
rm "$MIGRATIONS/V12__invalid.sql"
ln -s V1__fixture.sql "$MIGRATIONS/V12__link.sql"
assert_gate fail 'symlink migration' 'migration must be a regular SQL file'
rm "$MIGRATIONS/V12__link.sql"
assert_gate pass 'fresh baseline validated' '^PASS additive-only \(b\)$'
rm "$MIGRATIONS"/*.sql
assert_gate fail 'empty migration directory fails closed' '^FAIL setup: no SQL migrations$'
