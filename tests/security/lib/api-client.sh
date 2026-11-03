#!/usr/bin/env bash
# Researcher create routes answer 428 without an Idempotency-Key (chronicle-api/chronicle.yaml).
# Shell clients send a fresh key per create intent: curl ... -H "$(idempotency_key_header)"
idempotency_key_header() {
  printf 'Idempotency-Key: %s' "$(python3 -c 'import uuid; print(uuid.uuid4())')"
}
