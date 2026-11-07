# Security policy

Chronicle handles research participant data.

## Self-host release signing key

The public key ships in the bundle at `selfhost/release-signing.pub`.
The Ed25519 release key has fingerprint
`SHA256:PuOdejZ2d1CQgrWEF/tf95asMPC5RnsbCidg1PB6VSo`.
Only the fingerprint must come separately from the maintainer, by email or message from
your study's Chronicle contact. Replace `<version>` with the release version in the file name.
Extract only the key and show its fingerprint:

```bash
set -e
tar -xzOf chronicle-selfhost-<version>.tar.gz chronicle-selfhost-<version>/selfhost/release-signing.pub > release-signing.pub
ssh-keygen -lf release-signing.pub -E sha256
```

Compare it with the fingerprint the maintainer sent separately.
If it differs, stop. Do not install. If it matches, follow the signature and checksum steps
in [Quick start](selfhost/README.md#quick-start) before extracting the rest of the bundle.
Setup also prints the installed fingerprint.

The maintainer rotates the key with `scripts/endorse-release-key.sh`, which signs the new public
key with the old one (namespace `chronicle-release-key`); both files are uploaded with each release
the new key signs. An installed server (2026.11.6 or later) follows the rotation in
`./chronicle update` with no step of its own; see
[upgrade and rollback](selfhost/docs/UPGRADE-ROLLBACK.md). A first installation still compares
the fingerprint of the key in the bundle with the one the maintainer sent separately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on the affected repository
(**Security → Report a vulnerability**). It reaches the maintainers without creating a
public issue. Include the component, steps to reproduce, and the impact. For a source
checkout, include the commit from `git rev-parse --short HEAD`. For a self-host release
bundle, include `release_version`, `source_revision`, and `public_revision` when present in
the bundle-root `release-manifest.json`; the archive may not contain Git metadata.

Do not open a public issue or pull request for a security problem, and do not test against
deployments you do not operate.

## What to expect

- Acknowledgement of the report, and a first assessment of severity.
- A fix on the default branch, with credit in the changelog unless you prefer to stay anonymous.
- Coordinated disclosure: we ask that you hold details until the fix has shipped.

## Supported versions

Only the tip of each repository's default branch receives security fixes in the source
repositories. Only the latest post-reset self-host release bundle receives security and
bug fixes. See the [release support policy](selfhost/README.md#support) and update guidance.
