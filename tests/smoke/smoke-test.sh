#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:40320}"
JWT_TOKEN="${2:-}"

echo "=== Chronicle Smoke Tests ==="
echo "Target: $BASE_URL"
echo ""

# Test 1: Backend is responding
echo -n "1. Backend health... "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/chronicle/v3/study" \
  ${JWT_TOKEN:+-H "Authorization: Bearer $JWT_TOKEN"} \
  --connect-timeout 5 --max-time 10 2>/dev/null || echo "000")

if echo "$STATUS" | grep -E "^(200|401|403)$" >/dev/null; then
  echo "OK (HTTP $STATUS)"
else
  echo "FAIL (HTTP $STATUS -- backend unreachable)"
  exit 1
fi

# Test 2: OpenAPI spec accessible
echo -n "2. API spec... "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/chronicle/v3/api-docs" \
  --connect-timeout 5 --max-time 10 2>/dev/null || echo "000")
if [ "$STATUS" = "200" ]; then
  echo "OK (HTTP $STATUS)"
elif [ "$STATUS" = "404" ]; then
  echo "OK (HTTP $STATUS -- spec endpoint not configured, non-critical)"
else
  echo "FAIL (HTTP $STATUS -- backend returned unexpected status)"
  exit 1
fi

# Test 3: Frontend assets
FRONTEND_URL="${FRONTEND_URL:-http://127.0.0.1:8080}"
echo -n "3. Frontend assets... "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$FRONTEND_URL/chronicle/" \
  --connect-timeout 5 --max-time 10 2>/dev/null || echo "000")
if [ "$STATUS" = "200" ]; then
  echo "OK"
else
  echo "FAIL (HTTP $STATUS -- frontend not responding)"
  exit 1
fi

# Test 4: Study list endpoint (with auth)
if [ -n "$JWT_TOKEN" ]; then
  echo -n "4. Study list API... "
  BODY=$(curl -s "$BASE_URL/chronicle/v3/study" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -H "Content-Type: application/json" \
    --connect-timeout 5 --max-time 10 2>/dev/null)
  if echo "$BODY" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    echo "OK (valid JSON)"
  else
    echo "FAIL (invalid response)"
    exit 1
  fi
else
  echo "4. Study list API... SKIP (no JWT_TOKEN provided)"
fi

echo ""
echo "=== Smoke tests passed ==="
