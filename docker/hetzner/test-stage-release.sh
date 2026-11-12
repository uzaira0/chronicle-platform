#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=stage-release.sh
source "$script_dir/stage-release.sh"

scratch_root=${CHRONICLE_TEST_SCRATCH_ROOT:-${XDG_RUNTIME_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}}}
mkdir -p "$scratch_root"
work=$(mktemp -d "$scratch_root/chronicle-stage-release-test.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
base=$work/base
release=$work/release
mkdir -p "$base/docker/hetzner" "$release/docker/hetzner" "$work/staged"

cat > "$base/docker/hetzner/compose.yml" <<'EOF'
services:
  crowdsec:
    logging:
      driver: journald
EOF
cat > "$base/docker/hetzner/verify-stack.sh" <<'EOF'
#!/usr/bin/env bash
echo old-verifier
EOF
cp "$script_dir/compose.yml" "$release/docker/hetzner/compose.yml"
cp "$script_dir/verify-stack.sh" "$release/docker/hetzner/verify-stack.sh"

cat > "$base/docker/hetzner/source-manifest.env" <<'EOF'
CHRONICLE_ROOT_BASE=cbe4557527d325259a8a4e113c8c3d1aacf12395
CHRONICLE_API=5ab5de79cdcc81b3c789ef03ef5fa2d0594630b1 # gitleaks:allow -- Git commit, not a credential
CHRONICLE_MODELS=09f50f4dd798339d4d97acc5f1c5576ee2e27ece
CHRONICLE_SERVER=a1a45720aff335665b7811b47453a9ad52e2cae1
RHIZOME=72f85b81231d5c8368b48fa9e2a6eef59ec2fb24
RHIZOME_CLIENT=b8525ed03443f6831f3286e9c6e675a5b9dfa6e3
BACKEND_PATCH_SHA256=c54fbf4ae98f0f3ccdef81147729297acb1de1ad0ebbfa00d1681c4a40f58764
RLS_BACKGROUND_PATCH_SHA256=45539b2976232defa956eb1f17765379566603f540131d4ad905c7ef64275728
DEPLOYMENT_REVISION=cbe4557-a1a4572-hzn4
SCREEN_TIME_DELTA_PATCH_SHA256=b7344f41142a38dd1df0c20f1f491071a9997fcd5a51c87be4554e54c097bcea
EOF

compose_sha=$(sha256_file "$release/docker/hetzner/compose.yml")
verify_sha=$(sha256_file "$release/docker/hetzner/verify-stack.sh")
sed \
  -e 's/hzn4$/hzn5/' \
  "$base/docker/hetzner/source-manifest.env" \
  > "$release/docker/hetzner/source-manifest.env"
printf 'HETZNER_COMPOSE_SHA256=%s\nHETZNER_VERIFY_STACK_SHA256=%s\n' \
  "$compose_sha" "$verify_sha" \
  >> "$release/docker/hetzner/source-manifest.env"

destination=$work/staged/cbe4557-a1a4572-hzn5
result=$(stage_release "$release" "$base" "$destination")
grep -Fxq 'deployment_revision=cbe4557-a1a4572-hzn5' <<<"$result"
grep -Fxq "staged_path=$destination" <<<"$result"
cmp -s "$release/docker/hetzner/compose.yml" "$destination/docker/hetzner/compose.yml"
cmp -s "$release/docker/hetzner/verify-stack.sh" "$destination/docker/hetzner/verify-stack.sh"
cmp -s "$release/docker/hetzner/source-manifest.env" "$destination/docker/hetzner/source-manifest.env"

if stage_release "$release" "$base" "$destination" >/dev/null 2>&1; then
  echo "existing destination was overwritten" >&2
  exit 1
fi

bad_release=$work/bad-release
cp -a "$release" "$bad_release"
sed -e 's/hzn5$/hzn6/' "$release/docker/hetzner/source-manifest.env" \
  > "$bad_release/docker/hetzner/source-manifest.env"
if stage_release "$bad_release" "$base" "$work/staged/cbe4557-a1a4572-hzn6" >/dev/null 2>&1; then
  echo "skipped release sequence was accepted" >&2
  exit 1
fi

if find "$work/staged" -maxdepth 1 -name '*.partial.*' -print -quit | grep . >/dev/null; then
  echo "failed staging left a partial directory" >&2
  exit 1
fi

echo "fail-closed hzn4-to-hzn5 release staging verified"
