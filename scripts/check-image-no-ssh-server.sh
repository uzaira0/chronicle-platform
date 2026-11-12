#!/usr/bin/env bash
# Fail if any given image contains an SSH server binary (OpenSSH sshd/sshd-session/sshd-auth, Dropbear).
#
# No Chronicle image needs one: operators reach a container with `docker exec` from the host, over the
# host's own SSH. An sshd inside an image is a second, unmanaged login path; on our Alpine (musl) images,
# with password authentication on and no PAM, it would match the setup of the OpenSSH root-login bug
# reported in November 2026. The check reads the image filesystem through
# `docker export`, so it needs no shell inside the image and works on distroless and scratch images.
set -euo pipefail

[[ $# -gt 0 ]] || { echo 'usage: check-image-no-ssh-server.sh IMAGE [IMAGE ...]' >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo 'error: docker is required to inspect image filesystems' >&2; exit 127; }

SSH_SERVER_PATH='(^|/)(sshd|sshd-session|sshd-auth|dropbear|dropbearmulti)$'
status=0
for image in "$@"; do
  [[ -n "$image" && "$image" != -* && "$image" != *[[:space:]]* ]] || {
    echo 'error: expected an image reference without whitespace or a leading hyphen' >&2
    exit 2
  }
  # The command is never run; `create` only needs one for images without CMD/ENTRYPOINT (scratch).
  container=$(docker create "$image" /chronicle-ssh-check)
  found=$(docker export "$container" | tar -tf - | grep -E "$SSH_SERVER_PATH" || true)
  docker container rm --volumes "$container" >/dev/null
  if [[ -n "$found" ]]; then
    printf 'error: %s contains an SSH server; remove it (use docker exec from the host instead):\n%s\n' \
      "$image" "$found" >&2
    status=1
  else
    printf 'no SSH server in %s\n' "$image" >&2
  fi
done
exit "$status"
