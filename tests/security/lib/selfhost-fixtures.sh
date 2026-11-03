#!/usr/bin/env bash

export CHRONICLE_RECONCILE_ENABLED=false
# shellcheck source=tests/security/lib/selfhost-python.sh
source "$(dirname "${BASH_SOURCE[0]}")/selfhost-python.sh"

copy_selfhost_setup_fixture() {
  selfhost_python "$ROOT_DIR/tests/selfhost-py/selfhost_fixture.py" "$1"
}

write_encrypted_storage_fixture() {
  local command_dir="$1"
  cat >"${command_dir}/findmnt" <<'SH'
#!/usr/bin/env bash
printf '%s\n' /dev/mapper/synthetic-encrypted
SH
  cat >"${command_dir}/lsblk" <<'SH'
#!/usr/bin/env bash
printf '%s\n' '{"blockdevices":[{"type":"crypt"}]}'
SH
  cat >"${command_dir}/df" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == '-P '* ]]; then
  printf '%s\n' 'Filesystem 512-blocks Used Available Capacity Mounted on' \
    '/dev/fixture-encrypted 100000000 1 99999999 1% /'
else
  exec /bin/df "$@"
fi
SH
  cat >"${command_dir}/diskutil" <<'SH'
#!/usr/bin/env bash
[[ "$*" == 'info -plist /dev/fixture-encrypted' ]] || exit 93
printf '%s\n' '<?xml version="1.0"?><plist version="1.0"><dict><key>Encrypted</key><true/></dict></plist>'
SH
  chmod 0755 "${command_dir}/findmnt" "${command_dir}/lsblk" "${command_dir}/df" "${command_dir}/diskutil"
}

make_selfhost_setup_fixture() {
  local case_dir="$1"
  copy_selfhost_setup_fixture "${case_dir}/selfhost"
  mkdir -p "${case_dir}/bin"
  cat >"${case_dir}/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == 'compose ls --all --format json' ]]; then
  printf '[]\n'
elif [[ "$*" == 'info --format {{.DockerRootDir}}' ]]; then
  printf '%s\n' /fixture/docker
elif [[ "${1:-}" == run ]]; then
  cat >/dev/null
  printf '%s\n' "${SELFHOST_FIXTURE_BCRYPT:-\$2a\$14\$syntheticbcryptvalueabcdefghijklmnopqrstuv0123456789ABCDE}"
fi
exit 0
SH
  write_encrypted_storage_fixture "${case_dir}/bin"
  cat >"${case_dir}/bin/crontab" <<'SH'
#!/usr/bin/env bash
if [[ "$1" == -l ]]; then echo "no crontab for fixture" >&2; exit 1; fi
cat >/dev/null
SH
  cat >"${case_dir}/bin/openssl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'rand -base64 32' ]] || exit 91
printf '%s\n' "${SELFHOST_FIXTURE_GENERATED:-synthetic-generated-value-for-operator-test-only}"
SH
  cat >"${case_dir}/bin/ip" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  '-4 -o addr show') printf '%s\n' '1: lo inet 127.0.0.1/8 scope host lo' ;;
  '-4 -j route show table all'|'-6 -j route show table all') printf '[]\n' ;;
  *) exit 92 ;;
esac
SH
  cat >"${case_dir}/bin/ss" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == '-lnt' ]] || exit 93
printf '%s\n' 'State Recv-Q Send-Q Local Address:Port Peer Address:Port'
SH
  chmod 0755 "${case_dir}/bin/"*
}

write_restore_sql_fixture() {
  printf '%s\n' '-- PostgreSQL database dump' '\restrict fixturetoken' 'SET statement_timeout = 0;' \
    '-- PostgreSQL database dump complete' '\unrestrict fixturetoken'
}

write_trusted_restore_fixture() {
  write_restore_sql_fixture | /usr/bin/gzip -c >"$1"
  chmod 0600 "$1"
  sha256sum "$1" | cut -d ' ' -f1
}

write_update_curl_fixture() {
  mkdir -p "$1"
  cat >"$1/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == info ]]; then printf '%s\n' "${DOCKER_FIXTURE_ROOT:-$PWD}"; fi
SH
  chmod 0755 "$1/docker"
  cat >"$1/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
url="${!#}"
name="${url##*/}"
if [[ -n "${CURL_FIXTURE_INTERRUPT_NAME:-}" && "$name" == "$CURL_FIXTURE_INTERRUPT_NAME" ]]; then
  printf 'partial archive'
  kill -INT "$PPID"
  sleep 5
  exit 130
fi
case "$url" in
  https://updates.invalid/latest.json|https://updates.invalid/*.sha256|https://updates.invalid/*.sig|https://updates.invalid/*.tar.gz)
    output=""
    while (($#)); do
      case "$1" in -o|--output) output="$2"; break ;; esac
      shift
    done
    if [[ -n "$output" && "$output" != - ]]; then
      cat "${CURL_FIXTURE_DIR:?}/$name" >"$output"
    else
      cat "${CURL_FIXTURE_DIR:?}/$name"
    fi ;;
  *) echo "unexpected synthetic update URL: $url" >&2; exit 22 ;;
esac
SH
  chmod 0755 "$1/curl"
}

write_update_fixture() {
  python3 - "$1" "$2" "$3" "${4:-valid}" "${5:-}" "${6:-}" \
    "${7:-### Security
- BREAKING: fixture release note}" <<'PY'
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

root = Path(sys.argv[1])
current, latest = sys.argv[2:4]
mode, revision, notes_path, body = sys.argv[4:]
version = latest.removeprefix("v")
name = "chronicle-selfhost-" + version
root.mkdir(parents=True, exist_ok=True)
archive_path = root / (name + ".tar.gz")
stub = (b'#!/usr/bin/env bash\nset -euo pipefail\nprintf "HANDOFF EXECUTED\\n"\n'
        b'printf "%s\\n" "$0" "$@" > "$UPDATE_EXEC_RECORD"\n')
changelog = Path(notes_path).read_bytes() if notes_path else (
    f"# Changelog\n\n## [{version}]\n- Synthetic release notes.\n\n"
    f"## [{current}]\n- Existing release notes.\n"
).encode()
manifest = {"release_version": version}
if revision:
    manifest["source_revision"] = revision
with tarfile.open(archive_path, "w:gz") as archive:
    files = [(name + "/selfhost/chronicle", stub, 0o755), (name + "/CHANGELOG.md", changelog, 0o644)]
    if mode != "missing-manifest":
        files.append((name + "/release-manifest.json", json.dumps(manifest).encode(), 0o644))
    if mode == "traversal":
        files.append((name + "/../escaped", b"must not extract", 0o644))
    if mode == "too-many-members":
        files.extend((f"{name}/filler/{i}", b"", 0o644) for i in range(20001))
    for path, data, permissions in files:
        member = tarfile.TarInfo(path)
        member.size = len(data)
        member.mode = permissions
        archive.addfile(member, io.BytesIO(data))
digest = hashlib.sha256(archive_path.read_bytes()).hexdigest() if mode != "corrupt" else "0" * 64
archive_path.with_suffix(".gz.sha256").write_text(f"{digest}  {archive_path.name}\n", encoding="ascii")
assets = [{"name": filename, "browser_download_url": f"https://updates.invalid/{filename}"}
          for filename in (archive_path.name, archive_path.name + ".sha256", archive_path.name + ".sha256.sig")]
(root / "latest.json").write_text(json.dumps([{"tag_name": latest, "assets": assets, "body": body, "draft": False, "prerelease": False}]))
PY
}

prepare_update_signer() {
  local run_dir="$1" installed_selfhost="$2"
  ssh-keygen -q -t ed25519 -N '' -f "$run_dir/fixture-signing-key"
  cp "$run_dir/fixture-signing-key.pub" "$installed_selfhost/release-signing.pub"
}

sign_update_fixture() {
  local run_dir="$1" version="$2" mode="${3:-valid}" checksum release_signer
  if [[ "$mode" == valid ]]; then
    selfhost_python - "$run_dir" "$version" <<'PY'
import sys
from test_release import complete_update_fixture
complete_update_fixture(sys.argv[1], sys.argv[2])
PY
  fi
  release_signer=$(selfhost_python -c \
    'from chronicle_ops.release import RELEASE_SIGNER; print(RELEASE_SIGNER)')
  checksum="$run_dir/http/chronicle-selfhost-$version.tar.gz.sha256"
  rm -f -- "$checksum.sig"
  ssh-keygen -q -Y sign -n "$release_signer" -f "$run_dir/fixture-signing-key" "$checksum"
}

write_selfhost_setup_answers() {
  local password="$1" overwrite="${2:-false}" reuse_hash="${3:-false}"
  local -a options=(--public-host chronicle.study-host.org)
  [[ "$overwrite" != true ]] || options+=(--overwrite)
  [[ "$reuse_hash" != true ]] || options+=(--reuse-hash)
  [[ "${SELFHOST_SETUP_MONITORING:-n}" != [yY] ]] || options+=(--monitoring)
  SMOKE_PASSWORD="$password" ENABLE_MONITORING=false \
    selfhost_python "$ROOT_DIR/tests/smoke/selfhost_release_setup.py" --answers-only \
      "${options[@]}" "${@:4}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -euo pipefail
  ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)
  case "${1:-}" in
    setup-fixture) make_selfhost_setup_fixture "${2:?fixture directory required}" ;;
    run-setup)
      write_selfhost_setup_answers synthetic-dashboard-password "${3:-false}" "${3:-false}" |
        bash "${2:?selfhost directory required}/chronicle" setup
      ;;
    update-fixture)
      write_update_curl_fixture "$2/bin"
      write_update_fixture "$2/http" 1.2.3 "$3"
      ;;
    *) echo 'Unknown selfhost fixture command' >&2; exit 2 ;;
  esac
fi
