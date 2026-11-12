#!/usr/bin/env python3
"""Refuse to publish a release catalog that an installed server's own updater would reject.

An installed server finds updates with its own, older chronicle_ops/update.py, which cannot be
changed after it ships. 2026.11.2's discovery fails as a whole on one catalog row it cannot parse
(a non-version tag, a missing draft or prerelease flag; update.py:216-219 at the tag), so a single
bad row published next to a good release blocks every 2026.11.2 server from updating.

Usage (scripts/publish-images.sh --promote, before the draft is published):
    gh api --paginate --slurp repos/<owner>/<repo>/releases |
        scripts/check-release-discovery.py <release> --bundle chronicle-selfhost-<release>.tar.gz

The catalog an unauthenticated server sees after promotion is the authenticated one without
other drafts and with this release's draft published. It is served over loopback HTTP with the
GitHub API's paging, and each supported installed release (stable git tags from the upgrade
floor up to this release) plus the release being promoted runs its own catalog fetch,
select_release and release_assets; each must select this release. Exit 1 names every one that
did not. The release being promoted is the code in its bundle when --bundle names the archive
(promotion passes the one it downloaded from the draft), else this tree.

The release being promoted is also checked on its second source, GitHub's releases feed, which
its updater reads when the API refuses it. Nothing in this repository decides what that feed
holds: uzaira0/methodic was renamed on 2026-11-10, GitHub redirected the old feed URL, and every
link in the answer carried the new name. A candidate bundle built before the rename looked
for the old name in those links and listed no release. So the feed is read from GitHub at
promotion (one GET without credentials by the release's own curl call on the release's own feed
URL, as an installed server makes it), not from a copy saved here, which would still show the
names of the day it was saved; --feed takes a saved copy for tests. This release is still a
draft and the feed lists git tags, which a draft does not have yet, so its entry is added as a
copy of the feed's own first entry. The release must list every entry of that feed and select
this release.

Each supported installed release is also asked where it looks. 2026.11.2 finds releases only at
https://api.github.com/repos/uzaira0/methodic/releases, the repository's name before 2026-11-10;
it finds this release only while GitHub answers that old address with this repository, which
stops the day anything else takes the name (docs/GIT-WORKFLOW.md, "The public repository's former
name"). So the first request the release's own discovery makes with no CHRONICLE_RELEASES_URL is
made by its own curl call to the URL its own code builds, and the answer must be this
repository's published releases: the catalog on standard input without drafts, compared by
release id and tag. --release-list takes a saved answer for tests.

That request and the feed request go to GitHub from this machine without credentials, so they can
come back with nothing to judge: GitHub allows 60 such API requests an hour from one address and
refuses the next with 403 or 429 and x-ratelimit-remaining: 0 until the time in x-ratelimit-reset
(docs.github.com, "Rate limits for the REST API"), a connection can fail, a server can answer 5xx.
None of those says anything about the address or the release. Each is reported as what it is (the
limit and its reset time, curl's own error, the status), a failed connection or a 5xx is asked
again with backoff inside one deadline (120 seconds, or CHRONICLE_TRANSFER_TIMEOUT_SECONDS when
that is shorter), and when nothing else failed the exit status is 75 (EX_TEMPFAIL): nothing was
decided and the promotion can be run again. Only a 404, or a list that holds none of this
repository's releases, means the address no longer reaches this repository. A list with some of
this repository's releases and no other is an earlier state of the same list (GitHub caches
answers to requests without credentials); it passes and the releases it lacks are printed.
"""

import argparse
import base64
import datetime
import http.server
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path, PurePosixPath
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
# The release's feed source (update.feed_releases, in releases from 2026.11.12) on the feed at argv[3].
# The assets are asked for only when it selected this release, so another choice is reported as that.
# Before it selects a feed row the updater asks GitHub whether the tag has a release
# (update.asset_missing). This release is a draft until promotion and its assets are not public
# before that, so the question is answered here as it will be once the draft is published, and
# nothing reaches beyond the loopback server.
DISCOVER_FEED = '''
import json, sys
sys.path.insert(0, sys.argv[1])
from chronicle_ops import update
update.asset_missing = lambda url: False
releases = update.feed_releases(sys.argv[3])
chosen = update.select_release(releases)
if chosen["tag_name"].removeprefix("v") == sys.argv[2]:
    update.release_assets(chosen, "chronicle-selfhost-" + sys.argv[2] + ".tar.gz")
print(json.dumps([chosen["tag_name"], [release["tag_name"] for release in releases]]))
'''
# The GET an installed server makes when the API refuses it: the release's own curl call (no
# credentials, redirects followed, size and time bounded, retried) on its own feed URL.
FETCH_FEED = '''
import sys
sys.path.insert(0, sys.argv[1])
from chronicle_ops import update
sys.stdout.buffer.write(update.curl(update.FEED_RELEASES_URL, max_bytes=update.MAX_CATALOG_BYTES))
'''
FEED_FETCH_SECONDS = 60
# The first request an installed release's own discovery makes when CHRONICLE_RELEASES_URL is unset:
# the URL as that release's code builds it (2026.11.2 builds it inside fetch_published_releases, so
# it is read from the call, not from a name), fetched by that release's own curl command, or answered
# from the file at argv[3] when one is given. The release's command is run once and changed in two
# places: the response headers are written to the file at argv[2], and --fail is taken out, so a
# refusal comes back with its status, headers and body instead of curl's exit 22 and nothing else.
# A second page, another source after a refusal and the release's own retry are not made: asking
# again is decided by the caller, which knows the deadline. Prints {"url", "body" (base64),
# "exit" (curl's), "error", "said" (curl's stderr when the release captured it)}.
INSTALLED_LIST = '''
import base64, json, os, subprocess, sys
sys.path.insert(0, sys.argv[1])
from chronicle_ops import update
headers, saved = sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None
real, launch, answer, launched = update.curl, subprocess.Popen, {}, []
class OneRequest(launch):
    def __init__(self, command, *arguments, **options):
        if isinstance(command, (list, tuple)) and command and os.path.basename(str(command[0])) == "curl":
            if launched:
                raise RuntimeError("only the first request is made")
            launched.append(self)
            command = [command[0], "--dump-header", headers,
                       *(part for part in command[1:] if part not in ("--fail", "--fail-with-body"))]
        super().__init__(command, *arguments, **options)
def first(url, *arguments, **options):
    if "url" in answer:
        raise RuntimeError("only the first request is made")
    answer["url"] = url
    if saved:
        with open(saved, "rb") as source:
            body = source.read()
    else:
        body = real(url, *arguments, **options)
    answer["body"] = base64.b64encode(body).decode()
    return body
update.curl = first
subprocess.Popen = OneRequest
os.environ.pop("CHRONICLE_RELEASES_URL", None)
try:
    update.fetch_published_releases()
except Exception as error:
    answer["error"] = type(error).__name__ + ": " + str(error)
    while error is not None:
        said = getattr(error, "stderr", None)
        if said:
            answer["said"] = said.decode(errors="replace") if isinstance(said, bytes) else str(said)
            break
        error = error.__context__
if launched:
    answer["exit"] = getattr(launched[0], "returncode", None)
print(json.dumps(answer))
'''
# One list request may take this long; all of them, with the waits between, LIST_DEADLINE_SECONDS.
LIST_ATTEMPT_SECONDS = 60
LIST_DEADLINE_SECONDS = 120
LIST_RETRY_DELAYS = (2, 5, 10, 20, 30)
RATE_LIMIT_HEADERS = ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after")
CURL_SAID = re.compile(r"^curl: \(\d+\) .*$", re.MULTILINE)
CURL_HTTP_ERROR = re.compile(r"^curl: \(22\) The requested URL returned error: (\d+)", re.MULTILINE)
# sysexits.h EX_TEMPFAIL: GitHub could not be asked, so nothing was decided; the same command can be run again.
EX_TEMPFAIL = 75
CATALOG_ADVICE = ("for an installed release, fix the catalog row it rejects; when the release being promoted fails, "
                  "rebuild it from source that reads the catalog and the releases feed as GitHub serves them")
REDIRECT_ADVICE = ("when an installed release's release list does not return this repository's published releases, "
                   "GitHub no longer answers the address that release asks with this repository, and no release "
                   "reaches servers on it until it does (docs/GIT-WORKFLOW.md, \"The public repository's former name\")")
RERUN_ADVICE = ("a refusal by GitHub's rate limit, a connection that failed and an answer that is no release list say "
                "nothing about the address or this release; nothing was published, and the promotion can be run again "
                "(after the reset time, when one is named)")
GITHUB_DEFAULT_PAGE, GITHUB_MAX_PAGE = 30, 100
# The checker's own reading of the feed, to compare a release's reading with: one entry per
# release, whose link ends in the tag under whatever repository name GitHub serves.
FEED_ENTRY = re.compile(r"<entry>.*?</entry>", re.DOTALL)
FEED_ENTRY_TAG = re.compile(r'<link\b[^>]*\bhref="[^"]*/releases/tag/([^"/?#]+)"')


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


def published_feed(feed, tag):
    """(feed, tags): the feed an unauthenticated server reads once the release tagged `tag` is
    published, and the tag of each of its entries in order. The new entry goes first and is a
    copy of the feed's own first entry with that entry's tag replaced, so its link carries the
    repository name GitHub serves today. A feed that already lists `tag` is returned as it is."""
    text = feed.decode("utf-8", errors="replace")
    entries = FEED_ENTRY.findall(text)
    links = [FEED_ENTRY_TAG.search(entry) for entry in entries]
    if not entries or None in links:
        raise ValueError("the releases feed holds no entries with a release link, so it is not the feed an "
                         "installed server reads; look at what GitHub returned before publishing")
    tags = [link[1] for link in links]
    if tag not in tags:
        text = text.replace(entries[0], entries[0].replace(tags[0], tag) + "\n  " + entries[0], 1)
        tags.insert(0, tag)
    return text.encode(), tags


def serve(rows, feed=b""):
    """Serve rows like GET /repos/{owner}/{repo}/releases: per_page (default 30, at most 100) and
    page; and feed, the releases Atom feed, at any path ending in .atom."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            request = urlsplit(self.path)
            if request.path.endswith(".atom"):
                body, kind = feed, "application/atom+xml; charset=utf-8"
            else:
                query = parse_qs(request.query)
                size = min(int(query.get("per_page", [GITHUB_DEFAULT_PAGE])[0]), GITHUB_MAX_PAGE)
                page = int(query.get("page", ["1"])[0])
                body, kind = json.dumps(rows[(page - 1) * size:page * size]).encode(), "application/json"
            self.send_response(200)
            self.send_header("Content-Type", kind)
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


def release_python(script, package_root, *arguments, environment):
    """stdout (bytes) of script run by the release whose chronicle_ops is under package_root;
    ValueError with its last error line if it fails."""
    result = subprocess.run([sys.executable, "-I", "-c", script, str(package_root), *arguments],
                            env=environment, capture_output=True, timeout=120, check=False)
    if result.returncode:
        lines = result.stderr.decode(errors="replace").strip().splitlines()
        raise ValueError(lines[-1] if lines else f"exit {result.returncode}")
    return result.stdout


def loopback_environment(**extra):
    """No proxy and no token: the release under test must reach nothing but the loopback server."""
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/"), **extra}


def discovered(package_root, url, version):
    """(tag, [archive, checksum, signature URLs]) the release whose chronicle_ops is under
    package_root selects from the catalog at url; ValueError with its last error line if it fails."""
    tag, urls = json.loads(release_python(DISCOVER, package_root, version,
                                          environment=loopback_environment(CHRONICLE_RELEASES_URL=url)))
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


def discover_feed(package_root, url, version, tags):
    """None when that release's feed source lists every entry (tags, in order) of the feed at url
    and selects `version`, else what went wrong."""
    try:
        chosen, listed = json.loads(release_python(DISCOVER_FEED, package_root, version, url,
                                                   environment=loopback_environment()))
    except ValueError as error:
        return str(error)
    if listed != tags:
        return f"lists {len(listed)} of the feed's {len(tags)} releases ({', '.join(listed) or 'none'})"
    if chosen.removeprefix("v") != version.removeprefix("v"):
        return f"selected {chosen}, not {version}"
    return None


class Failure(str):
    """What one check found wrong, and `advice`: what the person promoting does about it."""

    advice = CATALOG_ADVICE

    def __new__(cls, text, advice):
        self = super().__new__(cls, text)
        self.advice = advice
        return self


class Unread(ValueError):
    """GitHub was not reached, or refused the request for now: nothing is known about its answer."""


def within(seconds):
    """`seconds`, or the caller's CHRONICLE_TRANSFER_TIMEOUT_SECONDS when that is shorter."""
    try:
        return max(1, min(seconds, int(os.environ["CHRONICLE_TRANSFER_TIMEOUT_SECONDS"])))
    except (KeyError, ValueError):
        return seconds


def live_feed(package_root):
    """The releases feed as GitHub serves it now to the release whose chronicle_ops is under
    package_root. The caller's environment is passed on, so the GET uses the same proxy an update
    on this host would; the release's curl call sends no credentials and retries inside its own
    deadline. Unread when GitHub was not reached or refused for now; ValueError when the feed
    address answers 404 or 410, or the release's code could not fetch at all."""
    seconds = within(FEED_FETCH_SECONDS)
    environment = dict(os.environ, CHRONICLE_TRANSFER_TIMEOUT_SECONDS=str(seconds))
    try:
        result = subprocess.run([sys.executable, "-I", "-c", FETCH_FEED, str(package_root)],
                                env=environment, capture_output=True, timeout=seconds + 60, check=False)
    except subprocess.TimeoutExpired:
        raise Unread(f"the releases feed was not read: no answer in {seconds + 60} seconds") from None
    if not result.returncode:
        return result.stdout
    said = result.stderr.decode(errors="replace")
    refused, curl_said = CURL_HTTP_ERROR.findall(said), CURL_SAID.findall(said)
    if refused and refused[-1] in ("404", "410"):
        raise ValueError(f"the releases feed address the release being promoted reads answers {refused[-1]}, so "
                         "its second source of releases finds nothing")
    if curl_said:
        raise Unread(f"the releases feed was not read: {curl_said[-1][:300]}")
    lines = said.strip().splitlines()
    raise ValueError("could not read the releases feed as an installed server would: "
                     + (lines[-1] if lines else f"exit {result.returncode}"))


def published_now(rows):
    """The rows of the authenticated catalog that are published: what GitHub lists without credentials."""
    return [row for row in rows if isinstance(row, dict) and row.get("draft") is False]


def list_problem(url, body, published, note=None):
    """None when body, the answer to the release-list URL an installed release asks, is this
    repository's published releases (the release ids and tags of `published`), else a Failure.
    One page is compared. Release ids are GitHub-wide, so one shared row proves the repository:

    - the same rows, or a full page of this repository's rows: the list as it is now;
    - some of this repository's rows and no other: the list as it was before a publish, which
      GitHub's cache serves to requests without credentials; passes, and `note` is called with
      what is missing;
    - this repository's rows and rows the catalog does not hold: the catalog on standard input
      is the older of the two, so the check is run again with a fresh one;
    - none of this repository's rows: another repository's list."""
    def identity(row):
        return row.get("id"), str(row.get("tag_name"))

    def some(tags):
        return ", ".join(tags[:5]) + (f" and {len(tags) - 5} more" if len(tags) > 5 else "")
    try:
        rows = json.loads(body)
    except ValueError:
        return Failure(f"{url} did not answer with JSON", RERUN_ADVICE)
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        return Failure(f"{url} did not answer with a list of releases", RERUN_ADVICE)
    expected, answered = {identity(row) for row in published}, {identity(row) for row in rows}
    size = min(int(parse_qs(urlsplit(url).query).get("per_page", [GITHUB_DEFAULT_PAGE])[0]), GITHUB_MAX_PAGE)
    if answered <= expected and (answered == expected or len(rows) >= size):
        return None
    counts = f"it lists {len(rows)} ({len(answered & expected)} of this repository's {len(expected)}"
    if not answered & expected:
        return Failure(f"{url} does not return this repository's published releases: {counts}; others: "
                       f"{some(sorted(tag for _, tag in answered)) or 'none'})", REDIRECT_ADVICE)
    if answered - expected:
        return Failure(f"{url} lists releases that the catalog this check was given does not hold: {counts}; others: "
                       f"{some(sorted(tag for _, tag in answered - expected))})", RERUN_ADVICE)
    if note:
        missing = [str(row.get("tag_name")) for row in published if identity(row) not in answered]
        note(f"{len(answered)} of this repository's {len(expected)} published releases (not listed: {some(missing)}); "
             "every row is this repository's, and GitHub serves requests without credentials from a cache that can "
             "be older than a publish")
    return None


def answer_problem(url, answer, published, note=None, now=None):
    """None when `answer` (from installed_list or asked_list) is this repository's published
    releases, else a Failure that says what came back instead."""
    status, headers, body = answer.get("status"), answer.get("headers", {}), answer.get("body") or b""
    tries = (f"{answer['attempts']} attempt{'s' if answer['attempts'] != 1 else ''} inside the deadline of "
             f"{answer['deadline']} seconds" if "attempts" in answer else "one attempt")
    if status is None:
        code = answer.get("exit")
        said = answer.get("error") or "no answer"
        return Failure(f"{url} was not reached: {said} ({'' if code is None else f'curl exit {code}; '}{tries})", RERUN_ADVICE)
    if status == 200:
        return list_problem(url, body, published, note)
    try:
        document = json.loads(body)
    except ValueError:
        document = None
    message = document.get("message") if isinstance(document, dict) else None
    message = " ".join(str(message if message else body.decode(errors="replace")).split())[:300]
    if status in (403, 429) and headers.get("x-ratelimit-remaining") == "0":
        allowed = headers.get("x-ratelimit-limit", "")
        used = f"all {allowed} requests an hour from this address are used" if allowed.isdigit() else \
            "the requests allowed from this address are used"
        try:
            reset = int(headers.get("x-ratelimit-reset", ""))
            at = "it resets at " + datetime.datetime.fromtimestamp(reset, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            minutes = -(-(reset - (time.time() if now is None else now)) // 60)
            if 0 < minutes <= 120:
                at += f", {int(minutes)} minute{'s' if minutes != 1 else ''} from now"
        except (ValueError, OverflowError, OSError):
            at = "GitHub did not say when it resets"
        return Failure(f"{url} was refused by GitHub's rate limit for requests without credentials (HTTP {status}): "
                       f"{used}, and {at}", RERUN_ADVICE)
    if status in (403, 429) and ("retry-after" in headers or "secondary rate limit" in message.lower()):
        wait = f", retry-after {headers['retry-after']} seconds" if "retry-after" in headers else ""
        return Failure(f"{url} was refused by GitHub's secondary rate limit (HTTP {status}{wait}): {message}", RERUN_ADVICE)
    if status in (404, 410):
        return Failure(f"{url} answers {status}; it does not return this repository's published releases", REDIRECT_ADVICE)
    return Failure(f"{url} was answered with HTTP {status} by GitHub ({tries}): {message}", RERUN_ADVICE)


def installed_list(package_root, saved=None, seconds=LIST_ATTEMPT_SECONDS):
    """What the first request of the discovery of the release whose chronicle_ops is under
    package_root came back with, as a dict: "url" (the release-list URL its code builds; absent
    when its discovery asked for none), "status" and "headers" (the HTTP answer; absent when
    there was none), "body", "exit" (curl's exit status) and "error". Asked of GitHub once by
    the release's own curl command, bounded by `seconds` (the caller's environment is passed
    on, as for the feed), or answered from the file `saved`, with nothing fetched."""
    environment = loopback_environment() if saved else dict(os.environ, CHRONICLE_TRANSFER_TIMEOUT_SECONDS=str(seconds))
    with tempfile.TemporaryDirectory(prefix="release-discovery-") as folder:
        dumped = Path(folder) / "headers"
        try:
            result = subprocess.run([sys.executable, "-I", "-c", INSTALLED_LIST, str(package_root), str(dumped),
                                     *([str(saved)] if saved else [])],
                                    env=environment, capture_output=True, timeout=seconds + 30, check=False)
            answer = json.loads(result.stdout)
        except subprocess.TimeoutExpired:
            return dict(error=f"its discovery did not finish in {seconds + 30} seconds")
        except ValueError as error:
            return dict(error=f"its discovery could not be run ({error})")
        blocks = [block for block in dumped.read_text(errors="replace").replace("\r\n", "\n").split("\n\n")
                  if block.strip()] if dumped.exists() else []
    if "body" in answer:
        answer["body"] = base64.b64decode(answer["body"])
    if saved:
        return dict(answer, status=200)
    if answer.get("exit") == 0 and blocks:
        # --location: one block of headers for each answer on the way; the last is the one with the body.
        first, *lines = blocks[-1].strip().split("\n")
        parts = first.split()
        if len(parts) > 1 and parts[0].startswith("HTTP/") and parts[1].isdigit():
            fields = {name.strip().lower(): value.strip() for name, _, value in (line.partition(":") for line in lines)}
            return dict(answer, status=int(parts[1]), headers={name: fields[name] for name in RATE_LIMIT_HEADERS if name in fields})
    said = CURL_SAID.findall(result.stderr.decode(errors="replace") + "\n" + answer.get("said", ""))
    if said:
        answer["error"] = said[-1][:300]
    elif answer.get("exit") == 0:
        answer["error"] = "curl reported no HTTP status line"
    return answer


def asked_list(package_root, deadline):
    """installed_list from GitHub, asked again with backoff while there is no HTTP answer or the
    answer is a 5xx, for at most `deadline` seconds in all. An answer below 500, a rate-limit
    refusal included, is final: asking again cannot change it and spends the limit. The dict
    also holds "attempts" and "deadline"."""
    started, attempts, delays = time.monotonic(), 0, iter(LIST_RETRY_DELAYS)
    while True:
        remaining = deadline - (time.monotonic() - started)
        answer = installed_list(package_root, seconds=max(1, min(LIST_ATTEMPT_SECONDS, int(remaining))))
        attempts += 1
        answer.update(attempts=attempts, deadline=deadline)
        status = answer.get("status")
        delay = next(delays, LIST_RETRY_DELAYS[-1])
        if (status is not None and status < 500) or time.monotonic() - started + delay >= deadline:
            return answer
        time.sleep(delay)


def installed_list_result(installed, package_root, published, answers, listing=None, notes=None, deadline=None):
    """(label, Failure or None) for one installed release's own release list. answers caches what
    each URL answered, so releases that ask at the same address cost one request. A list that
    passes with a remark (an earlier state of this repository's list) leaves it in notes[label].
    deadline: seconds for the request and its retries (default: within(LIST_DEADLINE_SECONDS))."""
    with tempfile.TemporaryDirectory(prefix="release-discovery-") as folder:
        empty = Path(folder) / "empty"
        empty.write_bytes(b"")
        url = installed_list(package_root, empty).get("url")  # the URL alone: nothing is fetched
        if url is None:
            return f"{installed} release list", "its discovery asked for no release list"
        if url not in answers:
            if listing is None:
                answers[url] = asked_list(package_root, within(LIST_DEADLINE_SECONDS) if deadline is None else deadline)
            else:
                saved = Path(folder) / "saved"
                saved.write_bytes(listing)
                answers[url] = installed_list(package_root, saved)
    label = f"{installed} release list ({url})"
    remarks = []
    problem = answer_problem(url, answers[url], published, remarks.append)
    if notes is not None and remarks:
        notes[label] = remarks[0]
    return label, problem


def bundle_package(archive, folder):
    """Unpack the chronicle_ops of a release bundle under folder; the directory to import it from."""
    with tarfile.open(archive, "r:gz") as bundle:
        members = [member for member in bundle.getmembers()
                   if PurePosixPath(member.name).parts[1:3] == ("selfhost", "chronicle_ops")]
        if not members:
            raise ValueError(f"{archive} holds no selfhost/chronicle_ops; it is not a release bundle")
        bundle.extractall(folder, members=members, filter="data")
    return Path(folder) / PurePosixPath(members[0].name).parts[0] / "selfhost"


def check(root, rows, version, feed, bundle=None, published=None, listing=None, notes=None):
    """[(release, problem or None)] for every supported installed release and for the release
    being promoted: the code in the archive `bundle`, else this tree. The promoted release has a
    second row for its feed source; `feed` is the releases feed as saved bytes, or None to read
    it from GitHub now. Each installed release has a second row for its own release list, which
    must answer with `published` (default: rows without the release being promoted); `listing`
    is that answer as saved bytes, or None to ask GitHub now. A release list that passes with a
    remark leaves it in notes[label]. Unread when the feed could not be read from GitHub."""
    root = Path(root)
    results, answers = [], {}
    if published is None:
        published = [row for row in published_now(rows)
                     if str(row.get("tag_name", "")).removeprefix("v") != version.removeprefix("v")]
    with tempfile.TemporaryDirectory(prefix="release-discovery-") as candidate:
        label, package = ("the bundle", bundle_package(bundle, candidate)) if bundle else ("this tree", root / "selfhost")
        tag = next((str(row["tag_name"]) for row in rows if isinstance(row, dict)
                    and str(row.get("tag_name", "")).removeprefix("v") == version.removeprefix("v")), version)
        served, tags = published_feed(live_feed(package) if feed is None else feed, tag)
        server = serve(rows, served)
        port = server.server_address[1]
        url = f"http://127.0.0.1:{port}/repos/fixture/releases?per_page={GITHUB_MAX_PAGE}"
        try:
            for installed in supported_tags(root, version):
                with tempfile.TemporaryDirectory(prefix="release-discovery-") as folder:
                    archive = subprocess.run(["git", "-C", str(root), "archive", "--format=tar", installed, "selfhost/chronicle_ops"],
                                             capture_output=True, check=True).stdout
                    with tarfile.open(fileobj=io.BytesIO(archive)) as members:
                        members.extractall(folder, filter="data")
                    results.append((installed, discover(Path(folder) / "selfhost", url, version)))
                    results.append(installed_list_result(installed, Path(folder) / "selfhost", published, answers, listing, notes))
            results.append((label, discover(package, url, version)))
            results.append((label + " (releases feed)",
                            discover_feed(package, f"http://127.0.0.1:{port}/fixture/releases.atom", version, tags)))
        finally:
            server.shutdown()
            server.server_close()
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("release")
    parser.add_argument("--catalog", type=Path, help="gh api --slurp output (default: standard input)")
    parser.add_argument("--bundle", type=Path, help="the release's bundle archive; its own updater is checked "
                        "as the release being promoted (default: this tree's)")
    parser.add_argument("--feed", type=Path, help="a saved releases feed (default: read from GitHub now, without "
                        "credentials, by the promoted release's own updater)")
    parser.add_argument("--release-list", type=Path, help="a saved answer to each installed release's own release-list "
                        "request (default: ask GitHub now, without credentials, with that release's own updater)")
    options = parser.parse_args()
    document = json.loads(options.catalog.read_text() if options.catalog else sys.stdin.read())
    version = options.release.removeprefix("v")
    notes = {}
    try:
        rows = catalog_rows(document)
        results = check(ROOT, anonymous_catalog(rows, version), version,
                        options.feed.read_bytes() if options.feed else None, options.bundle,
                        published_now(rows), options.release_list.read_bytes() if options.release_list else None, notes)
    except Unread as error:
        print(f"error: {error}. That says nothing about this release; nothing was published, and the promotion can "
              "be run again", file=sys.stderr)
        return EX_TEMPFAIL
    except (OSError, TypeError, ValueError, tarfile.TarError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    failed = [problem for _, problem in results if problem]
    for installed, problem in results:
        passed = ("answers with " + notes.get(installed, "this repository's published releases")
                  if " release list (" in installed else "selects " + version)
        print(f"{installed}: {'FAILS: ' + problem if problem else passed}")
    if failed:
        advice = list(dict.fromkeys(getattr(problem, "advice", CATALOG_ADVICE) for problem in failed))
        undecided = advice == [RERUN_ADVICE]
        print(f"error: {len(failed)} check(s) "
              + (f"could not be completed, so {version} is not published by this run" if undecided
                 else f"failed, so {version} must not be published")
              + ". " + ". ".join(line[0].upper() + line[1:] for line in advice), file=sys.stderr)
        return EX_TEMPFAIL if undecided else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
