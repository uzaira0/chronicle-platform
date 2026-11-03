#!/usr/bin/env bash
# rotate-secret accepts exactly one kind (or recover with a direction); help lists the real forms.
set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$ROOT_DIR/selfhost" || exit 1
fail() { echo "FAIL: $*" >&2; exit 1; }

bash rotate-secret.sh --validate jwt >/dev/null 2>&1 || fail "single kind rejected"
bash rotate-secret.sh --validate --yes dashboard >/dev/null 2>&1 || fail "--yes kind rejected"
bash rotate-secret.sh --validate recover --forward >/dev/null 2>&1 || fail "recover --forward rejected"
! bash rotate-secret.sh --validate jwt rotate >/dev/null 2>&1 || fail "trailing action argument accepted"
! bash rotate-secret.sh --validate recover >/dev/null 2>&1 || fail "recover without direction accepted"
help="$(bash chronicle help rotate-secret 2>&1)"
[[ "$help" == *"rotate-secret recover --forward|--rollback"* ]] || fail "help omits the recover form: $help"
[[ "$help" != *"smtp"* ]] || fail "help lists a removed kind"
echo "PASS: rotate-secret CLI forms"
