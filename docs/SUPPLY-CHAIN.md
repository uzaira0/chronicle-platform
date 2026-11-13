# Dependency intake and supply-chain policy

Chronicle takes dependency updates automatically, but never a version that is new enough to be a
hijacked release nobody has noticed yet. Carrying a known CVE for a few days is the accepted cost;
taking a malicious release is not.

## The waits

A version may enter only after it has been public for:

| Update | Wait | Where it is enforced |
|---|---|---|
| Routine (patch, minor, digest) | 7 days | `renovate.json` `minimumReleaseAge`, `chronicle-web/bunfig.toml` `minimumReleaseAge = 604800`, `scripts/check-dependency-age.py` |
| Major | 14 days | `renovate.json` packageRule on `matchUpdateTypes: major`, `check-dependency-age.py` |
| Security fix (the old version has an OSV advisory the new one lacks) | 3 days | `renovate.json` `vulnerabilityAlerts.minimumReleaseAge`, `check-dependency-age.py` |

Publish times come from the registry, not from the package: npm `time`, Maven Central, PyPI upload
time, GitHub release `published_at`, services.gradle.org, Quay `start_ts` for the pinned digest, and
Docker Hub `tag_last_pushed` only while that tag still holds the pinned digest (its index digest or
one platform's); a tag that has moved says nothing about an older digest, so such a pin falls to
the publisher's own `created`, which needs an exception. A version with no registry timestamp is not
proposed (Renovate `minimumReleaseAgeBehaviour: timestamp-required`) and not admitted.

Go is different: proxy.golang.org's `.info` `Time` is the commit time
(https://go.dev/ref/mod#version-info), so a tag pushed today on an old commit would look old, and
deps.dev's `publishedAt` is the same value (checked 2026-11-06: equal to `.info` `Time` for caddy
v2.11.2, golang.org/x/net v0.47.0, gopkg.in/yaml.v2 v2.2.2 and go-cron v0.0.11). The gate dates a Go
version by its `Timestamp` in index.golang.org, "the time it was first cached by proxy.golang.org"
(https://index.golang.org/). The index is a feed ordered by that time and read with `since`; it
cannot be asked for one version, and a version can be first cached weeks after its commit (cel.dev/expr
v0.25.3: committed 2026-07-29, first cached 2026-08-13). `sum.golang.org/lookup` gives the version's
record number in the checksum log, which grows as the proxy takes in versions, so the gate searches the
feed by time on the record number of the first row at each probe, between the commit time and now
(interpolating where the numbers grow evenly, bisecting where they do not, as in the April 2019
backfill), then reads the page around that point for the version's own row. That is 9 to 50 requests a
version; Go versions are dated on 4 threads that share one spacing between index requests, which
an HTTP 429 doubles. Only that row's `Timestamp` is used. A version whose row is not there, or a
proxy, checksum database or index that does not answer, is indeterminate and fails the run (exit 2).
Found times are cached; a cached Go time from the earlier sources (the commit time, or the
sum.golang.org witness the gate used briefly) is looked up again.

Any OSV `MAL-` advisory on any npm, Maven, Go or PyPI version the candidate holds fails every gate,
changed or not, and no exception admits it. OSV results are read to the last page
(`next_page_token`). A malicious version that the change removes does not block its replacement.

`scripts/check-dependency-age.py` owns these numbers (`--print-policy`); every other copy (this
table, `renovate.json`, `chronicle-web/bunfig.toml`, `dependency-exceptions.toml`, the intake,
publish and local-ci comments, `supply-chain-guardrails.sh`) is parsed by
`tests/quality/test_check_dependency_age.py` and must agree.

## Versions that RUN lines fetch

A Dockerfile that downloads a release, clones a tag, fetches `module@version` or installs `name==version`
keeps that version in an `ARG` (or `ENV`) under a Renovate annotation, never inside the RUN line:

    # renovate: datasource=github-releases depName=gitleaks/gitleaks
    ARG GITLEAKS_TAG=v8.30.1
    RUN curl ... "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_TAG}/gitleaks_${GITLEAKS_TAG#v}_linux_${arch}.tar.gz"

The value is the datasource's own version or tag (`v8.30.1` for a `v`-tagged GitHub release, `curl-8_21_0`
for curl, with `versioning=regex:...`). renovate.json's Dockerfile custom manager proposes new versions
(depType `dockerfile_pin`, labelled `manual-digests`: the checksum, commit or buildstamp beside the ARG is
refreshed by hand, and `sha256sum -c` or the commit check fails the image build until it is).
`scripts/check-dependency-age.py` reads the same annotations and dates each version by its registry:
`github-releases` by GitHub `published_at`, `go` by index.golang.org, `pypi` by PyPI upload time and
`custom.debian-source` by snapshot.debian.org's first `first_seen` of the source files. An annotation
naming any other datasource fails the gate closed. `# age-gate-only:` in place of `# renovate:` keeps a pin
from Renovate and still ages it: go-jose v3 in `selfhost/Dockerfile.caddy` has no fixed release, and
Renovate's OSV alert proposes v4.0.0, a different module path that cannot build there (seen in the
2026-11-07 dry run). `tests/quality/test_dockerfile_pins.py` fails on a
version written into a RUN line and holds Renovate's reading and the gate's reading of every Dockerfile
equal.

## New package names

A name that was not in a lockfile or pin file before needs a reviewed entry in
`dependency-additions.toml` (`ecosystem`, `name`, `reviewer`, `reason`). A newly committed lockfile
can be approved as a whole with `lockfile` and `revision` (the commit that was reviewed): it admits
only the names that file held at that revision, so a name added later needs its own row. An npm
package from anywhere but the npm registry (git, github, a tarball URL, another registry, `link:`,
a `file:` path leaving the repository) has no registry publish time and is never aged; it needs a
row with `ecosystem = "npm-source"`, the `name`, and `source` = the exact source string bun.lock
records, after someone has read that source. A different commit or URL is a new source. Entries
stay as the record of who let each name in and why. Pins present at the adoption revision
(`[policy] adopted_at`) were reviewed under the earlier process and are not aged again.

## Exceptions

An exploited and reachable vulnerability whose fix is younger than its wait goes through a person,
never through automation:

1. Read the fix's diff and confirm the vulnerable code is reachable in Chronicle.
2. Add the exact version to `dependency-exceptions.toml`:
   ```toml
   [[exception]]
   ecosystem = "npm"
   name = "example"
   version = "1.2.3"
   reviewer = "who reviewed it"
   note = "CVE id, why it is reachable, what in the diff was read"
   expires = 2026-12-01   # at most 30 days ahead
   ```
3. Commit the bump and the exception together on a branch; local CI's `dependency-age` job accepts it.

An expired entry fails the gate, so remove it once the version is past its normal wait. A `MAL-`
advisory cannot be excepted.

## How updates flow

```
Renovate (scripts/renovate-run.sh)  ->  renovate/* branches against deps/auto
gate runner (scripts/dependency-gate-runner.py)  ->  fast-forwards deps/auto with the ones that pass
the user  ->  merges deps/auto onward, cuts and publishes releases
```

- **Renovate** runs self-hosted from a digest-pinned image, once per repository (the root
  `uzaira0/methodic-dev` and `uzaira0/chronicle-web-dev`). Renovate can only commit to the repository
  it runs on, and `cloneSubmodules` only clones, so chronicle-web's `package.json` and `bun.lock` get
  their own run. This checkout's `renovate.json` is passed as the global config with
  `requireConfig: ignored`, so a stale `renovate.json` on another branch never applies. Renovate holds
  the GitHub token (from `gh auth token`, passed to the container by name, never printed), so it
  runs no package manager at all: `skipArtifactsUpdate: true` means it edits only manifests and pins
  and leaves every lockfile, `go.sum` and checksum to the gate runner's sandboxed
  `deps-regenerate.py`; there are no `postUpdateOptions`, and `allowedCommands` and
  `allowedUnsafeExecutions` are empty. `automerge` is off: a Renovate branch moves forward only by the
  gate runner's push. `internalChecksFilter: strict` and `internalChecksAsSuccess: false` mean
  Renovate's own checks never make a branch mergeable.
- **The gate runner** (`scripts/dependency-gate-runner.py`; its docstring has the full sequence)
  decides with this checkout's code only. The candidate is data: it is cloned (`git clone --local`,
  hooks and fsmonitor off) into the work directory and none of its code runs on the host. For each
  `renovate/*` branch that has not passed and contains the trusted `deps/auto`:
  1. fails at once if the candidate changes a gate input: `scripts/`, `tests/`, `.github/`,
     `.gitmodules`, `lefthook.yml`, `renovate.json`, `dependency-exceptions.toml`,
     `dependency-additions.toml`, the scanner configs (`.trivyignore.yaml`, `.grype.yaml`,
     `osv-scanner.toml`, `bearer.*`, `sgconfig.yml`, `detekt*`, the dependency-check suppressions),
     `chronicle-web/bunfig.toml`, or any `package.json` field other than the dependency fields. The
     one allowed change inside these paths is swapping one digest-pinned image reference for another
     (Renovate's updates to `scripts/sandbox/Dockerfile.*`, `scripts/flyway-migrate.sh`,
     `scripts/renovate-run.sh`); the age gate checks the new image;
  2. runs this checkout's `check-dependency-age.py` on the candidate before any dependency code runs;
  3. completes the change with this checkout's `scripts/deps-regenerate.py`: derived pins (Bun in
     `package.json`, Postgres in the pgTAP Dockerfile and contract tests, the Gradle wrapper and its
     checksum in every JVM submodule), `bun.lock`, Gradle lockfiles,
     `gradle/verification-metadata.xml` and `go mod tidy` for the Go modules. Every step that runs Bun,
     Gradle or Go runs in `scripts/deps-sandbox.sh` on a copy of the tree, and only the files that step
     may produce are copied back (regular files only; a symlink or a symlinked directory is refused).
     The protected-path check runs again on the result;
  4. runs the gates. On the host only this checkout's code runs: the age gate again;
     `local-ci.sh image-gate` for each release image whose Dockerfile or `COPY` sources changed
     (BuildKit builds the image for linux/amd64 from the committed candidate tree as
     `publish-images.sh` builds it; container-structure-test, the SSH-server check and trivy follow),
     plus the runtime image scan of the candidate's compose inventory when it changed; and
     `deps-freshness.sh --fetch-github`, the GitHub release lookups for repositories named in that
     script, made with the runner's gh login and handed to the sandbox as files. The image-gate host
     environment is built from nothing: an empty `HOME`, a Docker configuration with no credentials,
     no `GH_TOKEN`, `GHCR_TOKEN`, `SSH_AUTH_SOCK` or signing key. Everything else runs in the gate
     sandbox, each step on a fresh APFS clone of the candidate (nothing one step's dependency code
     writes reaches the next) with this checkout's `scripts/` and `tests/` mounted read-only over the
     candidate's. A `scripts/` file the candidate changed only by swapping digest-pinned image
     references carries the candidate's pins in that copy (`gate_scripts`), so a test comparing the JDK
     builder in `scripts/sandbox/Dockerfile.gate` with `docker/Dockerfile.backend` sees both new digests:
     - `python`: the candidate's `requirements-dev.txt`, wheels only, every hash checked, into a
       directory the later steps mount read-only (registries);
     - `tools`: `local-ci.sh gate-tools` downloads every checksum-pinned security tool and grype's
       database into a directory only this step writes, mounted read-only everywhere else (registries);
     - `toolchain`: `verify-toolchain.sh` (no network);
     - `scan`: the jobs that query a live database and run only tools and this checkout's scripts:
       `bun-audit`, `deps-freshness`, `bearer`, `osv` (registries);
     - `gradle`: Gradle downloads every resolvable configuration (registries); the offline builds
       verify each artifact against the candidate's `verification-metadata.xml`;
     - `security`: every other security job with no network, the scanners first and the jobs that
       build or test (`engineering`, `gradle-depcheck`) last. `gradle-depcheck` runs there with
       `SKIP_NVD_UPDATE=1` on a copy of the workstation's NVD database (the sandbox has no NVD key), so
       it is only as current as the workstation's last keyed `local-ci.sh gradle-depcheck`: that run
       records its time in `chronicle-nvd-updated-utc` next to the database, and the cache-only run
       prints the database's age and fails (status 2) when the record is missing or older than
       `CHRONICLE_DEPCHECK_MAX_AGE_HOURS` (default 168);
     - `fuzz`: the fuzz job as linux/amd64 (Jazzer has no linux/aarch64 library), no network;
     - `web`, when chronicle-web changed: `bun install` (registries), the candidate's Playwright
       Chromium headless shell into `/cache/ms-playwright` (`--network browsers`: registries plus
       `scripts/sandbox/egress-allowlist-browsers.txt`, where storage.googleapis.com is admitted for
       this command alone), then `local-ci.sh web` (none), whose browser tests use it;
  5. on green pushes `deps/auto` as a fast-forward (moved submodules first, then the root), records
     that commit as the trusted base, and posts the status; on red posts the failing gates. Logs are
     under `~/Library/Caches/chronicle-dependency-gate/logs/`.

  `deps/auto` itself is not trusted, since Renovate's token can write to it: the runner gates
  against the last `deps/auto` it pushed (state in
  `~/Library/Application Support/chronicle-dependency-gate/state.json`) or a `deps/auto` the
  runner's own checkout already contains, so anything that reached `deps/auto` another way is gated
  along with the candidate. A failed candidate is gated again only when it could now pass: always
  for an age failure (the wait runs out) or an indeterminate lookup, otherwise when the trusted
  base or this checkout's gate inputs changed, at most three times per fingerprint.

  It pushes only `refs/heads/deps/auto` with an explicit refspec to a URL it validated against
  `https://github.com/uzaira0/*-dev.git`, from a bare repository of its own with no system or global
  Git configuration (only the gh credential helper), `push.followTags` off and no submodule
  recursion, so no `pushurl`, `pushInsteadOf`, tag or hook in a checkout's configuration can send
  anything elsewhere. Never with force. It never merges into `main`, never tags and never publishes.
- **Publishing** (`scripts/publish-images.sh`) always needs the user. It runs the same age gate
  against the last `published-*` tag before any build.
- **Servers never auto-install.** A self-host server changes only when its operator runs
  `./chronicle update`.

## OS packages in images

Distribution packages are dependencies too: `apk upgrade` in a Dockerfile used to install whatever
Alpine had published that hour. On 2026-11-06 the grafana base would have taken `apk-tools` and
`libapk` 3.0.9-r0 and `tzdata` 2026f-r0, each one day old, and `alpine-release` 3.24.4-r0 built the
same day. Release images now install, upgrade and download OS packages only at exact versions older
than the same waits as every other dependency, through three helpers in `selfhost/os-packages/`,
bind-mounted into the `RUN` that uses them:

| Helper | Used by | What it pins | Publish time the age gate reads |
|---|---|---|---|
| `apk-install-aged.sh BRANCH [--add N...] [--pin N=V...] [--upgrade N=V...]` | backend, frontend, caddy, grafana runtime stages | `--pin`: each added package and each dependency the base lacks; `--upgrade`: newer versions of base packages | the APK index build time `t:` (`dl-cdn.alpinelinux.org/alpine/<branch>/{main,community}/x86_64/APKINDEX.tar.gz`) |
| `apt-install-aged.sh DISTRO SNAPSHOT [--https] [--download] [--add N...] [--pin N=V...] [--upgrade N=V...]` | backend builder (Ubuntu), backup builder (Debian), fluentbit's Debian stage (`--download`); the dependency sandbox images `scripts/sandbox/Dockerfile.{deps,gate}` (Debian) and `Dockerfile.jdk` (Ubuntu) | the full resolved closure, exact versions | Debian: `first_seen` of the amd64 (or all) binary from `snapshot.debian.org/mr/binary/<pkg>/<ver>/binfiles?fileinfo=1`; Ubuntu: `date_published` from Launchpad `getPublishedBinaries` (amd64) |
| `dnf-upgrade-aged.sh RELEASE --upgrade N=V-R...` | backup and postgres (Percona/UBI 9) | the five fixed RHEL builds, exact | UBI 9 `repodata/*-primary.xml.gz` `<time file= build=>`: the later of the two |

`scripts/check-dependency-age.py` reads these pins from every Dockerfile (module `scripts/os_packages.py`)
as `apk:v3.24/<name>`, `deb:debian/<name>` / `deb:ubuntu/<name>` and `rpm:el9/<name>` entries and
applies the usual rules: a changed pin younger than 7 days (14 for a major version change) fails, a
new `--pin` name needs `dependency-additions.toml`, a lookup it cannot answer is indeterminate. An
`--upgrade` replaces a package the base image already has, so it counts as a change of a known name,
never a new one; the helpers refuse an `--upgrade` of a name the base lacks and a `--pin` of one it has,
at build time, so that marker cannot be used to skip the review. OS packages get no 3-day security
path (OSV's Alpine, Debian and Red Hat data are not queried): a distribution security fix waits 7 days.

`scripts/os-package-pins.py --root DIR --write` proposes the pins and rewrites the calls in place
(`scripts/deps-regenerate.py` runs it for every Dockerfile whose `FROM` lines a candidate changed,
since a new base image carries its own package versions; to move pins forward without a base change,
run it by hand and commit the result through the same gate): for Alpine it reads the base image's package database
(`docker create` + `docker cp` of the linux/amd64 image, nothing started) and the branch's index;
for Debian and Ubuntu it resolves the `--add` packages inside the base image (run by
`scripts/deps-sandbox.sh --base-image` with `--network registries`: root with only the capabilities apt
needs, no cache volume, and no route out but the allowlisting egress proxy, which reaches
`snapshot.debian.org` and `snapshot.ubuntu.com` over HTTPS with this host's CA bundle) against the
distribution snapshot taken 14 days ago at midnight UTC, so nothing it pins can be younger than any wait, never
moves a pin back to an older version (the 14-day snapshot predates the libbrotli1 1.1.0-2+deb13u1
security build, first seen 2026-10-23 21:07 UTC, and would otherwise resolve the vulnerable +b7), refuses
to resolve when any snapshot pocket failed to update, and writes today's snapshot as the fallback
source; for RPM
it moves each pinned build to the UBI repository's current build once that is older than the wait.
It prints each changed file; exit 1 means some image has no aged version to install (its build
fails until one ages), exit 2 that a lookup failed and that call was left as it was.

The dependency sandbox images take OS packages the same way: their build context is `scripts/sandbox`,
so `deps-sandbox.sh` passes `selfhost/os-packages` as the `os-packages` build context and hashes the
helpers into each image tag. `Dockerfile.deps` uses the Debian Bun image rather than the Alpine one
because Alpine's index keeps only the newest build: on 2026-11-06 the only libexpat in v3.24
(2.10.0-r0, under python3 and git) was four days old, so no aged version existed to pin. The JDK
images resolve against `ARG JDK_IMAGE`'s default, which `deps-sandbox.sh` requires to be
`docker/Dockerfile.backend`'s builder. `snapshot.ubuntu.com` serves every architecture under
`/ubuntu/<timestamp>/` (there is no `/ubuntu-ports/` path; it answers 401), so on an arm64 host an Ubuntu
build has the same two sources as on amd64: the live ports mirror while a pin is current, the snapshot
once ports has replaced it. The pins are resolved for the amd64 release images; a test resolves the
backend builder's against the arm64 index of the same snapshot and requires the same closure.

### Why these mechanisms (measured 2026-11-06)

- **Alpine keeps one version per package.** The v3.24 `main` x86_64 APKINDEX lists 5961 packages
  and none of them twice; `community` lists 22699, five of them more than once, and those five are
  .NET subpackages built by three different .NET versions side by side, not older releases. A plain `name=version` pin stops installing the
  moment Alpine replaces that version, and there is no Alpine snapshot service. So an `--upgrade`
  whose version has left the index is skipped and the base version stays (it is as old as the
  base image digest, which the age gate checks); only an added package (`--pin`) has no fallback,
  and its image fails to build until `os-package-pins.py` proposes a replacement that has aged.
  The trade: a distribution fix can be absent for up to its wait, and the trivy gate then fails
  instead of shipping an unaged package.
- **UBI keeps one build per package too.** The UBI 9 baseos `primary.xml` lists exactly one
  `python3` build (3.9.25-7.el9_8.6), so the RPM helper has the same skip-and-keep-the-base rule.
  The file times of the five pinned builds are 2026-10-20 to 2026-10-23; the build times are up to
  two days earlier. The build time is the builder's own header, so the gate takes the later file time.
- **Debian and Ubuntu keep every version in their snapshots, but snapshot.debian.org is not always
  up.** It answered HTTP 503/504 to every request between 07:18 and 07:31 UTC on 2026-11-06, while
  `snapshot.ubuntu.com` answered at once. So builds do not depend on a snapshot alone: the apt
  helper configures the live mirror and the snapshot at SNAPSHOT side by side and installs exact
  versions, so a pin installs from the live mirror while it is current and from the snapshot after;
  only a pin that neither has fails. A Debian pin change whose `first_seen` cannot be read while
  snapshot.debian.org is down is indeterminate and is retried by the next gate run.
- **Every helper fails closed after installing.** Each compares the package database before and
  after and fails the build if any package is at a version that is neither the base image's nor
  pinned (an unpinned dependency at the repository's newest version, for instance).

Not covered: `scripts/sandbox/Dockerfile.deps`, `Dockerfile.jdk` and `Dockerfile.gate` (sandbox
images built on the workstation, never released; their build context is `scripts/sandbox/`, so they
cannot bind the helpers) still `apk add`/`apt-get install` unpinned from their digest-pinned bases. `.hadolint.yaml` keeps DL3008/DL3018 ignored for them;
`tests/quality/test_os_package_pins.py` is what holds the release Dockerfiles to the helpers.

## Build isolation

Dependency installs, regeneration, scans and the gate's tests run in `scripts/deps-sandbox.sh`: a
container with only the source mounted, no inherited environment, no Docker socket, no SSH agent, no
host home directory, uid 1000, all capabilities dropped and `no-new-privileges`; it refuses `--env`
names that look like credentials or proxies and `--mount`s of the Docker socket, `~`, `~/.docker`,
`~/.ssh` and `~/.config`. Images: `deps` (Bun, Python, the scan tools), `jdk` (the backend's JDK, for
Gradle), `go` (the backup image's Go builder, for `go mod tidy`) and `gate`
(`scripts/sandbox/Dockerfile.gate`: the backend JDK, Bun, semgrep, ruff, shellcheck, gitleaks, yq,
each release binary checked against its published sha256). `--platform linux/amd64` builds and runs
an image for that platform instead of the host's. Network is one of two:

- `none` (the default): no network at all. Tests, builds, the offline security jobs,
  `verify-toolchain.sh`, `local-ci.sh web`.
- `registries`: the container joins an internal Docker network with no gateway whose only other
  member is `scripts/sandbox/egress-proxy.py`. The proxy accepts `CONNECT name:443` for the names in
  `scripts/sandbox/egress-allowlist.txt` (npm, PyPI, Maven Central and the Gradle and Google
  repositories, the Go proxy and checksum database, OSV, deps.dev, the grype database, Docker Hub,
  GitHub release downloads and API) and refuses everything else, IP literals and plain HTTP
  included; DNS resolves only container names. Installs, lockfile regeneration, tool downloads and
  the scanners that query a live database. When a sandboxed command fails, the refused destinations
  are printed with its log. These hosts accept uploads too (a package that brought its own
  publishing token could send the source tree it was given to its own account). Installs, lockfile
  regeneration and Gradle's download execute build plugins with this network; that is the remaining
  exposure, bounded by the age gate on every plugin. Builds and tests have no network.

`tests/quality/test_build_isolation.py` proves this by running it: a canary planted in the host
environment and home directory never reaches a sandboxed gate step, a sandbox on `none` reaches
nothing, one on `registries` reaches the npm registry and gets 403 for any other name, and
`publish-images.sh --dry-run` with `GHCR_TOKEN` set starts no process that can see the token.

Every `bun install` in
Dockerfiles, scripts and CI is `--frozen-lockfile --ignore-scripts` (checked by
`tests/security/supply-chain-guardrails.sh`). Go stages build from committed `go.mod`/`go.sum` with
`-mod=readonly`.

In `publish-images.sh` the GHCR token is read once and unset from the environment; `docker login`
happens just before the first push and `docker logout` right after the images are signed, so no build
or scan step runs with registry credentials.

## Image signing and provenance

`publish-images.sh` builds each first-party image with BuildKit's provenance in the metadata file
(`BUILDX_METADATA_PROVENANCE=max`: Dockerfile, build arguments, base image digests; the daemon's
`docker` driver cannot attach attestations to the image itself). After the push it signs every digest
(`cosign sign`) and attests its provenance (`cosign attest --type slsaprovenance02`) with the
image-signing key, then verifies the registry copies with the public key. The key pair comes from
`scripts/create-image-signing-key.sh`: private half beside the release-signing key
(`~/.config/chronicle/image-signing.key`, or `CHRONICLE_IMAGE_SIGNING_KEY`), public half committed as
`selfhost/image-signing.pub`. No transparency log is used (`scripts/cosign-signing-config.json`): the
pinned key is the trust anchor, as for the SSH release signature.

The two Sigstore bundles per image ship in the release under `selfhost/image-signatures/`, named in
`release-manifest.json` (`image_signatures`) and covered by the signed checksum. `./chronicle update`
checks them offline before it pulls (`selfhost/chronicle_ops/image_signatures.py`: the DSSE signature
verifies with the shipped key through openssl, the predicate is the right one, and the statement names
exactly the pinned digest); a release from before 2026.11.12 ships none and updates as before. Anyone can
check a registry copy:

    cosign verify --key selfhost/image-signing.pub --insecure-ignore-tlog IMAGE@DIGEST
    cosign verify-attestation --key selfhost/image-signing.pub --insecure-ignore-tlog --type slsaprovenance02 IMAGE@DIGEST

SLSA Build level 1: the provenance exists and is signed, but it is produced on the maintainer's
workstation, not a hosted build platform (level 2). Third-party runtime images (cAdvisor, the socket
proxy, VictoriaMetrics, VictoriaLogs, busybox) are not signed by Chronicle; the signed manifest pins
their digests, and `scripts/check-runtime-images.py` checks them at publish.

## Running it

- One pass by hand: `scripts/dependency-intake.sh` (Renovate, then the gate runner).
- Preview without writing anything: `scripts/renovate-run.sh --dry-run=full [--base-branch NAME]`
  and `scripts/dependency-gate-runner.py --dry-run`; to gate a local commit the same way,
  `scripts/dependency-gate-runner.py --candidate REF --base-ref BASE`.
- First use, once this policy is on the branch that should seed it:
  `scripts/dependency-gate-runner.py --init-base <ref>` creates `deps/auto` in both repositories.
  If `deps/auto` already exists and is not contained in the runner's checkout, review it and record
  it with `scripts/dependency-gate-runner.py --trust-base <ref>`; until then every candidate is gated
  together with everything on `deps/auto` since the last trusted commit.
- Daily schedule: `scripts/launchd/install-dependency-intake.sh [--ref REF]` writes
  `~/Library/LaunchAgents/com.chronicle.dependency-intake.plist` (04:17 daily) for the runner checkout
  `~/chronicle/dependency-intake`, which it creates as a detached worktree at REF when missing. That
  checkout's code decides every gate, so it is never a task or release worktree, and it refuses a
  checkout with a branch checked out. Moving the runner to newer policy is a reviewed
  `git -C ~/chronicle/dependency-intake checkout --detach <commit>`. The script prints the
  `launchctl bootstrap` command and does not load the job itself.

## What stays manual

- Gate tools pinned by digest in `scripts/local-ci.sh` (`depType gate_tool`): Renovate labels them
  `manual-digests` and does not automerge, because the checksum table needs the new release's
  digests.
- Versions RUN lines fetch (`depType dockerfile_pin`, above): Renovate labels them `manual-digests`;
  the checksum beside each is refreshed by hand. debianutils in `selfhost/Dockerfile.backup` follows
  the upstream backup image and is disabled in `renovate.json`; go-jose v3 has no fixed release and is
  `age-gate-only`. The age gate still dates both.
- The Android app repository (`chronicle-dev`) is not in the Renovate run.
- Postgres/Percona major versions are disabled in `renovate.json`: they need a data migration.
- A version forced by a Gradle override (`config/dependency-overrides.json`: jackson, netty, log4j,
  commons-lang3, bouncycastle and the rest) carries a removal review with its pinned version. Renovate
  may bump it, but `deps-freshness` and the override-review test fail the branch until a person
  updates that review; the gate runner never writes one.
- Docker base-image digest refreshes: Renovate has no release timestamp for a digest. The age gate
  ages one by Docker Hub's `tag_last_pushed` only while the tag still holds that digest; once the tag
  has moved on, the pin needs an exception or a newer digest that the tag holds.
