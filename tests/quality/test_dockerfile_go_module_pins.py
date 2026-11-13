"""Self-host image builds must not choose Go module versions at build time.

`go install pkg@version`, `go get` and `xcaddy build` (which generates a module and runs `go get`) pick the
whole dependency graph when the image is built, with no go.sum in the repository to compare against: the same
Dockerfile can link different module versions on different days. Until 2026-11-06 Dockerfile.backup built
go-cron with `go install ...@v0.0.11` and Dockerfile.caddy built Caddy with `xcaddy build`. A `go build` or
`go install` of a local package is allowed only in a stage that copies a go.sum from the repository (the build
context) or clones an upstream source checked against a full commit hash, and never with `-mod=mod`."""

import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SELFHOST = ROOT / "selfhost"

RESOLVES = (
    (re.compile(r"\bgo\s+install\b[^;&|]*\s[\w.~/-]+@[\w.+-]+"), "go install <pkg>@<version>"),
    (re.compile(r"\bgo\s+get\b"), "go get"),
    (re.compile(r"\bxcaddy\s+build\b"), "xcaddy build"),
    (re.compile(r"-mod=mod\b"), "-mod=mod"),
)
GO_BUILD = re.compile(r"\bgo\s+(?:build|install)\b")
PINNED_CLONE = re.compile(r"\bgit\s+clone\b.*\brev-parse\s+HEAD\b.*=\s*[\"']?[0-9a-f]{40}\b", re.DOTALL)

# scripts/os_packages.py resolves ARG defaults with Docker's stage scoping.
sys.path.insert(0, str(ROOT / "scripts"))
from os_packages import expand_stage_args


def logical_lines(text):
    return [line.strip() for line in text.replace("\\\n", " ").splitlines() if line.strip()
            and not line.lstrip().startswith("#")]


def copy_sources(line):
    """Context paths named by a COPY/ADD that does not read another stage or image."""
    words = line.split()[1:]
    if any(word.startswith("--from=") for word in words):
        return []
    words = [word for word in words if not word.startswith("--")]
    return [word.strip('"[],') for word in words[:-1]]


def findings(text, go_sums):
    """go_sums: paths of repository go.sum files, relative to the image's build context."""
    found = []
    stage_has_go_sum = False
    for line in logical_lines(expand_stage_args(text)):
        keyword = line.split()[0].upper()
        if keyword == "FROM":
            stage_has_go_sum = False
        elif keyword in ("COPY", "ADD"):
            for source in copy_sources(line):
                source = source.rstrip("/").removeprefix("./")
                if source in go_sums or f"{source}/go.sum" in go_sums:
                    stage_has_go_sum = True
        elif keyword in ("RUN", "ENV", "ARG"):
            if keyword == "RUN" and PINNED_CLONE.search(line):
                stage_has_go_sum = True
            for pattern, name in RESOLVES:
                if pattern.search(line):
                    found.append(f"{name}: {line}")
            if keyword == "RUN" and GO_BUILD.search(line) and not stage_has_go_sum and not any(
                    pattern.search(line) for pattern, _ in RESOLVES):
                found.append(f"go build without a repository go.sum in the stage: {line}")
    return found


def build_contexts():
    """Each self-host Dockerfile with its build context, from the one source-image inventory."""
    sys.path.insert(0, str(SELFHOST))
    try:
        from chronicle_ops.images import SOURCE_IMAGES
    finally:
        sys.path.remove(str(SELFHOST))
    return {(SELFHOST / image.dockerfile).resolve(): (SELFHOST / image.context).resolve() for image in SOURCE_IMAGES}


def repository_go_sums(context):
    # Tracked or not yet committed (but not ignored), so a new module can be tested before its commit; the
    # release archive (chronicle_ops.images.archive_source) reads committed files only.
    listed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                            capture_output=True, text=True, check=True).stdout
    prefix = context.relative_to(ROOT).as_posix()
    prefix = "" if prefix == "." else prefix + "/"
    return {name[len(prefix):] for name in filter(None, listed.split("\0"))
            if name.startswith(prefix) and Path(name).name == "go.sum"}


class DockerfileGoModulePinTest(unittest.TestCase):
    def test_rule_flags_build_time_resolution(self):
        self.assertEqual(1, len(findings("FROM golang\nRUN go install -trimpath example.com/x@v1.0.0\n", set())))
        self.assertEqual(1, len(findings("FROM golang\nRUN CGO_ENABLED=0 go install \\\n    example.com/x@v1\n", set())))
        self.assertEqual(1, len(findings("FROM golang\nRUN go get example.com/x@v1\n", {"m/go.sum"})))
        self.assertEqual(1, len(findings("FROM caddy-builder\nRUN xcaddy build v2.11.9 --with a/b@v0.1.0\n", set())))
        self.assertEqual(1, len(findings("FROM golang\nCOPY m /m\nENV GOFLAGS=-mod=mod\n", {"m/go.sum"})))

    def test_rule_requires_a_repository_go_sum_in_the_building_stage(self):
        self.assertEqual(1, len(findings("FROM golang\nCOPY m /m\nRUN go build ./...\n", set())))
        self.assertEqual([], findings("FROM golang\nCOPY m/ /m\nRUN go build -mod=readonly ./...\n", {"m/go.sum"}))
        self.assertEqual([], findings("FROM golang\nCOPY m/go.mod m/go.sum /m/\nRUN go build .\n", {"m/go.sum"}))
        self.assertEqual(1, len(findings("FROM golang AS a\nCOPY m /m\nFROM golang\nRUN go build .\n", {"m/go.sum"})))
        self.assertEqual(1, len(findings("FROM golang\nCOPY --from=a /m /m\nRUN go build .\n", {"m/go.sum"})))
        self.assertEqual([], findings("FROM golang\nRUN git clone --depth 1 --branch v1 https://x/y /src && \\\n"
                                      f"    test \"$(git -C /src rev-parse HEAD)\" = {'a' * 40}\n"
                                      "RUN go build ./cmd/y\n", set()))
        self.assertEqual(1, len(findings("FROM golang\nRUN git clone --branch v1 https://x/y /src\n"
                                         "RUN go build ./cmd/y\n", set())))
        self.assertEqual([], findings("FROM golang\nRUN go version -m /bin/x && go mod download -json a/b@v1\n", set()))

    def test_a_clone_checked_against_an_arg_commit_counts_as_pinned(self):
        # Since 2026-11-07 Dockerfile.grafana keeps its tag and commit in Renovate-annotated ARGs.
        clone = ("RUN git clone --depth 1 --branch \"${TAG}\" https://x/y /src && \\\n"
                 "    test \"$(git -C /src rev-parse HEAD)\" = \"${COMMIT}\"\nRUN go build ./cmd/y\n")
        commit = "a" * 40
        self.assertEqual([], findings(f"FROM golang\nARG TAG=v1\nARG COMMIT={commit}\n{clone}", set()))
        # Not a full commit, an ARG of an earlier stage, an ARG declared after the check: not pinned.
        self.assertEqual(1, len(findings(f"FROM golang\nARG TAG=v1\nARG COMMIT=v1\n{clone}", set())))
        self.assertEqual(1, len(findings(f"FROM golang AS a\nARG COMMIT={commit}\nFROM golang\n{clone}", set())))
        self.assertEqual(1, len(findings(f"FROM golang\n{clone}ARG COMMIT={commit}\n", set())))
        # A global ARG reaches a stage only when the stage redeclares it.
        self.assertEqual(1, len(findings(f"ARG COMMIT={commit}\nFROM golang\n{clone}", set())))
        self.assertEqual([], findings(f"ARG COMMIT={commit}\nFROM golang\nARG COMMIT\n{clone}", set()))

    def test_selfhost_dockerfiles_pin_their_go_modules(self):
        contexts = build_contexts()
        offenders = []
        for dockerfile in sorted(SELFHOST.glob("Dockerfile*")):
            context = contexts.get(dockerfile.resolve())
            if context is None:
                offenders.append(f"{dockerfile.name}: not in chronicle_ops.images.SOURCE_IMAGES, build context unknown")
                continue
            offenders += [f"{dockerfile.name}: {finding}"
                          for finding in findings(dockerfile.read_text(encoding="utf-8"), repository_go_sums(context))]
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
