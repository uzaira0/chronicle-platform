#!/usr/bin/env python3
"""Refuse to publish a release catalog that an installed server's own updater would reject.

An installed server finds updates with its own, older chronicle_ops/update.py, which cannot be
changed after it ships. 2026.11.2's discovery fails as a whole on one catalog row it cannot parse
(a non-version tag, a missing draft or prerelease flag; update.py:216-219 at the tag), so a single
bad row published next to a good release blocks every 2026.11.2 server from updating.

Usage (scripts/publish-images.sh --promote, before the draft is published):
    gh api --paginate --slurp repos/<owner>/<repo>/releases | scripts/check-release-discovery.py <release>

The catalog an unauthenticated server sees after promotion is the authenticated one without
other drafts and with this release's draft published. It is served over loopback HTTP with the
GitHub API's paging, and each supported installed release (stable git tags from the upgrade
floor up to this release) plus this tree runs its own catalog fetch, select_release and
release_assets from its tag; each must select this release. Exit 1 names every one that did not.
"""

import argparse
import http.server
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]

# Runs inside the installed release's package. 2026.11.2 reads CHRONICLE_RELEASES_URL in
# fetch_published_releases; later releases read it first through catalog_releases (and only then
# fall back to the internet, which this check must not reach).
DISCOVER = '''
import json, os, sys
sys.path.insert(0, sys.argv[1])
from chronicle_ops import update
url = os.environ["CHRONICLE_RELEASES_URL"]
read = getattr(update, "catalog_releases", None)
releases = read(url) if read else update.fetch_published_releases()
chosen = update.select_release(releases)
assets = update.release_assets(chosen, "chronicle-selfhost-" + sys.argv[2] + ".tar.gz")
print(json.dumps([chosen["tag_name"], [asset.url for asset in assets.all()]]))
'''
GITHUB_DEFAULT_PAGE, GITHUB_MAX_PAGE = 30, 100


def catalog_rows(document):
    """Release rows from `gh api --paginate --slurp` (a list of pages) or a plain list."""
    if not isinstance(document, list):
        raise TypeError("release catalog must be a JSON array")
    if document and all(isinstance(page, list) for page in document):
        return [row for page in document for row in page]
    return list(document)


def anonymous_catalog(rows, version):
    """The rows an unauthenticated server reads once `version`'s draft is published."""
    visible, found = [], False
    for row in rows:
        if isinstance(row, dict) and str(row.get("tag_name", "")).removeprefix("v") == version.removeprefix("v"):
            row, found = dict(row, draft=False), True
        elif isinstance(row, dict) and row.get("draft") is True:
            continue  # GitHub lists drafts only to accounts with push access.
        visible.append(row)
    if not found:
        raise ValueError(f"release {version} is not in the catalog; create its draft first")
    return visible


def serve(rows):
    """Serve rows like GET /repos/{owner}/{repo}/releases: per_page (default 30, at most 100) and page."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            query = parse_qs(urlsplit(self.path).query)
            size = min(int(query.get("per_page", [GITHUB_DEFAULT_PAGE])[0]), GITHUB_MAX_PAGE)
            page = int(query.get("page", ["1"])[0])
            body = json.dumps(rows[(page - 1) * size:page * size]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def supported_tags(root, version):
    """Stable release tags at or above the upgrade floor and below `version`."""
    sys.path.insert(0, str(root / "selfhost"))
    from chronicle_ops.release import UPGRADE_FROM_MINIMUM, parse_version
    tags = subprocess.run(["git", "-C", str(root), "tag", "--list"], capture_output=True, text=True, check=True).stdout.split()
    floor, target = parse_version(UPGRADE_FROM_MINIMUM, "floor"), parse_version(version, "release")
    supported = []
    for tag in tags:
        try:
            key = parse_version(tag.removeprefix("v"), "tag")
        except ValueError:
            continue
        if floor <= key < target and key[3][0] == 1:
            supported.append(tag)
    return supported


def discovered(package_root, url, version):
    """(tag, [archive, checksum, signature URLs]) the release whose chronicle_ops is under
    package_root selects from the catalog at url; ValueError with its last error line if it fails."""
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CHRONICLE_RELEASES_URL": url,
                   "HOME": os.environ.get("HOME", "/")}
    result = subprocess.run([sys.executable, "-I", "-c", DISCOVER, str(package_root), version],
                            env=environment, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        lines = result.stderr.strip().splitlines()
        raise ValueError(lines[-1] if lines else f"exit {result.returncode}")
    tag, urls = json.loads(result.stdout)
    return tag, urls


def discover(package_root, url, version):
    """None when that release selects `version`, else what went wrong."""
    try:
        tag, _urls = discovered(package_root, url, version)
    except ValueError as error:
        return str(error)
    if tag.removeprefix("v") != version.removeprefix("v"):
        return f"selected {tag}, not {version}"
    return None


def check(root, rows, version):
    """[(installed release, problem or None)] for every supported release and this tree."""
    root = Path(root)
    server = serve(rows)
    url = f"http://127.0.0.1:{server.server_address[1]}/repos/fixture/releases?per_page={GITHUB_MAX_PAGE}"
    results = []
    try:
        for tag in supported_tags(root, version):
            with tempfile.TemporaryDirectory(prefix="release-discovery-") as folder:
                archive = subprocess.run(["git", "-C", str(root), "archive", "--format=tar", tag, "selfhost/chronicle_ops"],
                                         capture_output=True, check=True).stdout
                with tarfile.open(fileobj=io.BytesIO(archive)) as members:
                    members.extractall(folder, filter="data")
                results.append((tag, discover(Path(folder) / "selfhost", url, version)))
        results.append(("this tree", discover(root / "selfhost", url, version)))
    finally:
        server.shutdown()
        server.server_close()
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("release")
    parser.add_argument("--catalog", type=Path, help="gh api --slurp output (default: standard input)")
    options = parser.parse_args()
    document = json.loads(options.catalog.read_text() if options.catalog else sys.stdin.read())
    version = options.release.removeprefix("v")
    try:
        results = check(ROOT, anonymous_catalog(catalog_rows(document), version), version)
    except (TypeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    failed = [(installed, problem) for installed, problem in results if problem]
    for installed, problem in results:
        print(f"{installed}: {'FAILS: ' + problem if problem else 'selects ' + version}")
    if failed:
        print(f"error: {len(failed)} installed release(s) would not discover {version}; fix the catalog rows "
              "they reject before publishing", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
