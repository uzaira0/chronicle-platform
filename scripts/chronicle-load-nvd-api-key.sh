#!/usr/bin/env bash
# Source this helper before running OWASP Dependency-Check.
#
# It exports NVD_API_KEY from a private local source when the variable is not
# already set. The key is never printed.
#
# It can also be executed directly as a redacted availability check:
#
#   scripts/chronicle-load-nvd-api-key.sh
#
# Direct execution prints only whether a key is available and exits nonzero
# when no approved local source produced a key.

_chronicle_nvd_direct=0
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  _chronicle_nvd_direct=1
fi

_chronicle_nvd_root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
_chronicle_nvd_file_rejected=0

_chronicle_nvd_reject_file() {
  local path="$1"
  if [[ -z "$path" ]]; then
    return 0
  fi
  if [[ "$path" != /* ]]; then
    path="$PWD/$path"
  fi
  if [[ -L "$path" ]]; then
    printf 'refusing to read NVD API key through symlink: %s\n' "$path" >&2
    return 1
  fi
  case "$path" in
    "$_chronicle_nvd_root_dir"| "$_chronicle_nvd_root_dir"/*)
      printf 'refusing to read NVD API key from inside Git checkout: %s\n' "$path" >&2
      return 1
      ;;
  esac
  return 0
}

_chronicle_nvd_user="${USER:-}"
if [[ -z "$_chronicle_nvd_user" ]] && command -v id >/dev/null 2>&1; then
  _chronicle_nvd_user="$(id -un 2>/dev/null || true)"
fi

if [[ -z "${NVD_API_KEY:-}" && -n "${CHRONICLE_NVD_API_KEY_FILE:-}" ]]; then
  if _chronicle_nvd_reject_file "$CHRONICLE_NVD_API_KEY_FILE" && [[ -r "$CHRONICLE_NVD_API_KEY_FILE" ]]; then
    IFS= read -r NVD_API_KEY < "$CHRONICLE_NVD_API_KEY_FILE" || true
    NVD_API_KEY="${NVD_API_KEY%$'\r'}"
    if [[ -n "$NVD_API_KEY" ]]; then
      export NVD_API_KEY
    fi
  else
    _chronicle_nvd_file_rejected=1
  fi
fi

_chronicle_nvd_keychain_service="${CHRONICLE_NVD_KEYCHAIN_SERVICE:-chronicle-nvd-api-key}"
_chronicle_nvd_keychain_account="${CHRONICLE_NVD_KEYCHAIN_ACCOUNT:-$_chronicle_nvd_user}"

if [[ "$_chronicle_nvd_file_rejected" == "0" && -z "${NVD_API_KEY:-}" ]] \
  && command -v security >/dev/null 2>&1 \
  && [[ -n "$_chronicle_nvd_keychain_account" ]]; then
  NVD_API_KEY="$(security find-generic-password \
    -a "$_chronicle_nvd_keychain_account" \
    -s "$_chronicle_nvd_keychain_service" \
    -w 2>/dev/null || true)"
  if [[ -n "$NVD_API_KEY" ]]; then
    export NVD_API_KEY
  else
    unset NVD_API_KEY
  fi
fi

# pass decrypts with gpg, which asks gpg-agent for the passphrase and opens pinentry (a GUI dialog on
# macOS, even from a terminal) when it is not cached. This helper runs from scripts and agents, so gpg
# gets --batch --pinentry-mode error: a cached passphrase works, anything else fails without a prompt.
if [[ "$_chronicle_nvd_file_rejected" == "0" && -z "${NVD_API_KEY:-}" ]] && command -v pass >/dev/null 2>&1; then
  _chronicle_nvd_pass_name="${CHRONICLE_NVD_PASS_NAME:-chronicle/nvd-api-key}"
  NVD_API_KEY="$(PASSWORD_STORE_GPG_OPTS="${PASSWORD_STORE_GPG_OPTS:+$PASSWORD_STORE_GPG_OPTS }--batch --pinentry-mode error" \
    pass show "$_chronicle_nvd_pass_name" 2>/dev/null | sed -n '1p' || true)"
  NVD_API_KEY="${NVD_API_KEY%$'\r'}"
  if [[ -n "$NVD_API_KEY" ]]; then
    export NVD_API_KEY
  else
    unset NVD_API_KEY
  fi
fi

unset _chronicle_nvd_user
unset -f _chronicle_nvd_reject_file
unset _chronicle_nvd_root_dir
unset _chronicle_nvd_file_rejected
unset _chronicle_nvd_keychain_service
unset _chronicle_nvd_keychain_account
unset _chronicle_nvd_pass_name

if [[ "$_chronicle_nvd_direct" == "1" ]]; then
  if [[ -n "${NVD_API_KEY:-}" ]]; then
    printf 'NVD_API_KEY=present\n'
    unset _chronicle_nvd_direct
    exit 0
  fi
  printf 'NVD_API_KEY=absent\n' >&2
  unset _chronicle_nvd_direct
  exit 2
fi

unset _chronicle_nvd_direct
