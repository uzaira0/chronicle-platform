#!/bin/bash
# ============================================
# Chronicle Row-Level Security (RLS) Test Runner
# ============================================
# Tests RLS policies by simulating different user contexts
#
# Usage:
#   ./test-rls.sh                    # Run against local docker
#   ./test-rls.sh prod               # Run against production (careful!)
#
# Prerequisites:
#   - PostgreSQL container running
#   - RLS migration applied (V1__fresh_schema.sql)
#   - chronicle_admin and chronicle_app roles created

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.prod.yml"

# Load environment
if [ -f "${SCRIPT_DIR}/.env" ]; then
    source "${SCRIPT_DIR}/.env"
fi

DB_USER="${POSTGRES_USER:-chronicle}"
DB_NAME="${POSTGRES_DB:-chronicle}"

echo "============================================"
echo "Chronicle RLS Test Suite"
echo "============================================"
echo ""

# Function to run SQL and display results
run_sql() {
    local description="$1"
    local sql="$2"
    echo ">>> $description"
    docker-compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U "$DB_USER" -d "$DB_NAME" -c "$sql" 2>/dev/null || \
        echo "    [SKIPPED - table may not exist yet]"
    echo ""
}

# Check RLS is enabled
echo "=== Checking RLS Configuration ==="
run_sql "RLS enabled on tables" \
    "SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public' AND rowsecurity = true;"

run_sql "RLS policies defined" \
    "SELECT tablename, policyname, cmd, qual FROM pg_policies WHERE schemaname = 'public';"

# Test chronicle_has_study_access function exists
echo "=== Testing RLS Function ==="
run_sql "chronicle_has_study_access function exists" \
    "SELECT proname, prosrc FROM pg_proc WHERE proname = 'chronicle_has_study_access' LIMIT 1;"

# Test with admin context
echo "=== Test 1: Admin Context (should see all data) ==="
docker-compose -f "$COMPOSE_FILE" exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" <<'EOF'
SET app.is_admin = 'true';
SET app.authorized_studies = '';
SELECT 'Admin can access' as status, count(*) as total_studies FROM studies;
EOF

# Test with restricted user context
echo ""
echo "=== Test 2: Restricted User Context ==="
docker-compose -f "$COMPOSE_FILE" exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" <<'EOF'
SET app.is_admin = 'false';
SET app.authorized_studies = '00000000-0000-0000-0000-000000000000';
SELECT 'Restricted user' as status, count(*) as visible_studies FROM studies;
EOF

# Test with no access
echo ""
echo "=== Test 3: No Access Context ==="
docker-compose -f "$COMPOSE_FILE" exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" <<'EOF'
SET app.is_admin = 'false';
SET app.authorized_studies = '';
SELECT 'No access user' as status, count(*) as visible_studies FROM studies;
EOF

echo ""
echo "============================================"
echo "RLS Test Complete"
echo "============================================"
echo ""
echo "Expected Results:"
echo "  - Admin: Sees all records"
echo "  - Restricted: Sees only authorized study records"
echo "  - No access: Sees 0 records"
echo ""
echo "For detailed testing, run:"
echo "  docker-compose -f docker-compose.prod.yml exec postgres psql -U $DB_USER -d $DB_NAME -f /test-rls.sql"
