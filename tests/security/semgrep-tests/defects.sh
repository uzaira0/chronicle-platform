# ruleid: create-route-without-idempotency-key
curl --silent --fail -X POST "$backend/chronicle/v3/study" \
  -H 'Content-Type: application/json' --data '{}'

# ok: create-route-without-idempotency-key
curl --silent --fail -X POST "$backend/chronicle/v3/study" -H "$(idempotency_key_header)" \
  -H 'Content-Type: application/json' --data '{}'

# ruleid: create-route-without-idempotency-key
status=$(http_status POST "${BASE_URL}/chronicle/v3/study/${STUDY}/api-keys" --data '{}')

# ok: create-route-without-idempotency-key
status=$(auth_http_status POST "${BASE_URL}/chronicle/v3/study/${STUDY}/participants/purge" --data '{}')

# ok: create-route-without-idempotency-key
status=$(http_status GET "${BASE_URL}/chronicle/v3/study")
