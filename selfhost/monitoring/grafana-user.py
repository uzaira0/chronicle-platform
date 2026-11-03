#!/usr/bin/env python3
"""Manage private Grafana Viewer users without putting credentials in argv or output."""

from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


def fail(message: str) -> None:
    raise SystemExit(f"monitoring viewer: {message}")


parts = sys.stdin.buffer.read().split(b"\0")
if parts and parts[-1] == b"":
    parts.pop()
if len(parts) != 5:
    fail("invalid credential input")
base, admin_password, operation, login, viewer_password = (
    value.decode("utf-8") for value in parts
)
if operation not in {"add", "remove", "reset"}:
    fail("unsupported operation")
if not base.startswith("https://"):
    fail("Grafana URL must be HTTPS")
context = ssl.create_default_context(cafile=os.environ["GRAFANA_CA_FILE"])
# Grafana is a private local listener: an inherited HTTPS_PROXY cannot reach it, so never consult one.
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))

authorization = base64.b64encode(f"admin:{admin_password}".encode()).decode()


def request(method: str, path: str, payload: dict | None = None, expected=(200,)):
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=body,
        method=method,
        headers={
            "Authorization": "Basic " + authorization,
            "Content-Type": "application/json",
        },
    )
    try:
        with opener.open(req, timeout=10) as response:
            content = response.read()
            if response.status not in expected:
                fail(f"Grafana returned HTTP {response.status}")
            return json.loads(content) if content else {}
    except urllib.error.HTTPError as exc:
        detail = ""
        with exc:
            try:
                parsed = json.loads(exc.read())
                detail = parsed.get("message", "")
            except Exception:
                pass
        fail(f"Grafana returned HTTP {exc.code}" + (f": {detail}" if detail else ""))
    except urllib.error.URLError:
        fail("Grafana is unreachable; run ./chronicle monitoring status")


lookup_path = "/api/users/lookup?loginOrEmail=" + urllib.parse.quote(login, safe="")

if operation == "add":
    try:
        request("GET", lookup_path)
    except SystemExit as exc:
        if "HTTP 404" not in str(exc):
            raise
    else:
        fail("that login already exists")
    created = request(
        "POST",
        "/api/admin/users",
        {"name": login, "login": login, "password": viewer_password},
        expected=(200,),
    )
    user_id = created.get("id")
    if not isinstance(user_id, int):
        fail("Grafana created the user without returning an id")
    request("PATCH", f"/api/org/users/{user_id}", {"role": "Viewer"}, expected=(200,))
elif operation == "remove":
    user = request("GET", lookup_path)
    user_id = user.get("id")
    if not isinstance(user_id, int):
        fail("Grafana lookup did not return an id")
    request("DELETE", f"/api/admin/users/{user_id}", expected=(200,))
else:
    user = request("GET", lookup_path)
    user_id = user.get("id")
    if not isinstance(user_id, int):
        fail("Grafana lookup did not return an id")
    request(
        "PUT",
        f"/api/admin/users/{user_id}/password",
        {"password": viewer_password},
        expected=(200,),
    )

print(f"Grafana Viewer '{login}' { {'add': 'created', 'remove': 'removed', 'reset': 'updated'}[operation] }.")
