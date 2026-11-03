#!/usr/bin/env python3
"""Probe every published route against the disposable backend's authorization boundary."""

import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote, urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[2]


def cases(routes, study_b, participant_id, fixtures=None):
    values = {"settingType": "DataCollection", "name": "probe", "userId": "test_user2", **(fixtures or {})}
    values.update(studyId=study_b, participantId=participant_id)
    probes, seen = [], set()
    for route in routes:
        method, path, auth = (route[key] for key in ("method", "path", "auth"))
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ValueError(f"Undeclared request method: {method}")
        if auth not in {"PUBLIC", "AUTHENTICATED", "DENY"} or (method, path) in seen:
            raise ValueError(f"Missing authorization or duplicate route: {method} {path}")
        seen.add((method, path))
        parameters = set(re.findall(r"\{([^}]+)\}", path))
        if parameters - values.keys():
            raise ValueError(f"Missing path fixtures: {method} {path}: {sorted(parameters - values.keys())}")
        # Anyone may read the DataCollection settings a phone needs (SecurityRouteAuthorization); a read probes the
        # template's authorization with a setting that is not public.
        route_values = dict(values, settingType="Notifications") if method == "GET" else values
        url = re.sub(r"\{([^}]+)\}", lambda match: quote(route_values[match[1]], safe=""), path)
        operation = route.get("operation", "")
        foreign_resource = auth == "AUTHENTICATED" and bool(parameters - {"name", "settingType"})
        probes.append(dict(method=method, path=url, template=path, label="anonymous", authenticated=False,
                           needs_inputs=auth != "DENY" and (operation.startswith("AdminController.") or foreign_resource),
                           expected=None if auth == "PUBLIC" else {401, 403, 404}))
        if auth == "DENY":
            probes.append(dict(method=method, path=url, template=path, label="denied", authenticated=True, expected={401, 403, 404}))
        elif operation == "AdminController.getCurrentUserPrincipals":
            probes[-1]["expected"] = {401}
            probes.append(dict(method=method, path=url, template=path, label="self-principals", authenticated=True, expected={200}))
        elif operation.startswith("AdminController."):
            probes.append(dict(method=method, path=url, template=path, label="researcher-admin", authenticated=True, expected={403}))
        elif foreign_resource:
            probes.append(dict(method=method, path=url, template=path, label="cross-study", authenticated=True, expected={403, 404}))
    return probes


def validate_target(base):
    target = urlsplit(base)
    if target.scheme != "http" or target.path or target.query or target.fragment or target.username is not None:
        raise ValueError("Authorization probes require a disposable loopback HTTP backend")
    try:
        loopback = ipaddress.ip_address(target.hostname).is_loopback
    except (TypeError, ValueError):
        loopback = False
    if not loopback:
        raise ValueError("Authorization probes require a disposable loopback HTTP backend")
    return target


def request_context(fixtures, actor, method, path):
    operation = fixtures.get("operations", {}).get(method + " " + path, {})
    context = {key: value for key, value in {**fixtures, **operation}.items()
               if key not in {"nativeHeaders", "operations"}}
    # Header names are case-insensitive. Target B supplies state, never the caller's native credentials.
    headers = {}
    for source in (fixtures.get("headers", {}), operation.get("headers", {}), actor.get("nativeHeaders", {})):
        for name, value in source.items():
            headers = {key: old for key, old in headers.items() if key.lower() != name.lower()}
            headers[name] = value
    context["headers"] = headers
    context["query"] = {**fixtures.get("query", {}), **operation.get("query", {})}
    return context


def send_request(target, method, path, token, request=None):
    headers = {"Content-Type": "application/json", "Connection": "close"}
    body = "{}" if method in {"POST", "PUT", "PATCH"} else None
    if request is not None:
        if any(name.lower() in {"authorization", "cookie"} for name in request["headers"]):
            raise ValueError("Request fixtures cannot change the researcher principal")
        headers.update(request["headers"])
        query = urlencode(request["query"], doseq=True)
        path += "?" + query if query else ""
        if "json" in request:
            body = json.dumps(request["json"])
        elif "form" in request:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urlencode(request["form"], doseq=True)
        else:
            body = None
    if token is not None and not any(name.lower() == "x-api-key" for name in headers):
        headers["Authorization"] = "Bearer " + token
    connection = http.client.HTTPConnection(target.hostname, target.port, timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read(65537), response.getheader("Location")
    finally:
        connection.close()


def principal_set(principals):
    if not isinstance(principals, list) or not principals or any(
            not isinstance(principal, dict) or not {"id", "type"} <= principal.keys() for principal in principals):
        raise ValueError("Missing exact actor principal set")
    normalized = [json.dumps(principal, sort_keys=True) for principal in principals]
    if len(set(normalized)) != len(normalized):
        raise ValueError("Duplicate entries in principal set")
    return set(normalized)


def sweep(base, routes, token, study_b, participant_id, fixtures=None, request_builder=None,
          actor_fixtures=None, actor_request_builder=None, reauthentication_path=None):
    target = validate_target(base)
    probes = cases(routes, study_b, participant_id, fixtures)
    failures, count = [], 0
    actor_fixtures = actor_fixtures or {}
    for probe in probes:
        request = None
        if request_builder and (probe["label"] in {"cross-study", "researcher-admin"} or probe.get("needs_inputs")):
            request = request_builder(probe["method"], probe["template"])
            if not probe["authenticated"]:
                native_names = {name.lower() for name in actor_fixtures.get("nativeHeaders", {})} | {"x-api-key"}
                request = {**request, "headers": {name: value for name, value in request["headers"].items()
                                                  if name.lower() not in native_names}}
            elif any(name.lower() == "x-api-key" for name in request["headers"]):
                expected_headers = {name.lower(): value for name, value in actor_fixtures.get("nativeHeaders", {}).items()}
                actual_headers = {name.lower(): value for name, value in request["headers"].items()}
                if not actor_request_builder or not expected_headers.get("x-api-key") or any(
                        actual_headers.get(name) != value for name, value in expected_headers.items()):
                    raise ValueError("Native probe requires the actor's exact enrolled credentials and own-resource control")
                controls = [route for route in routes if route.get("operation") == "MobileReminderController.getParticipationStatus"
                            and route["auth"] == "AUTHENTICATED" and route["method"] == "GET"]
                if len(controls) != 1:
                    raise ValueError("Native own-resource control requires the inventory's exact canonical status-read owner")
                own_template = controls[0]["path"]
                names = re.findall(r"\{([^}]+)\}", own_template)
                if set(names) - actor_fixtures.keys():
                    raise ValueError("Native own-resource control is missing real actor path fixtures")
                own_path = re.sub(r"\{([^}]+)\}", lambda match: quote(actor_fixtures[match[1]], safe=""), own_template)
                own_request = actor_request_builder("GET", own_template)
                if {name.lower(): value for name, value in own_request["headers"].items()
                        if name.lower() in expected_headers} != expected_headers:
                    raise ValueError("Native own-resource control must use the same exact actor credentials")
                status, _payload, _location = send_request(target, "GET", own_path, None, own_request)
                count += 1
                if not 200 <= status < 300:
                    raise ValueError(f'own-resource control {probe["method"]} {probe["template"]}: HTTP {status}')
        status, payload, location = send_request(target, probe["method"], probe["path"],
                                                 token if probe["authenticated"] else None, request)
        count += 1
        expected = probe["expected"]
        # An anonymous native form download is sent to sign in again (NativeExportDownload), never served.
        if (status == 303 and expected is not None and not probe["authenticated"] and request is not None
                and "form" in request and reauthentication_path is not None
                and location in {reauthentication_path, "/chronicle" + reauthentication_path}):
            expected = expected | {303}
        accepted = status < 500 if expected is None else status in expected
        oversized = expected is not None and len(payload) > 65536
        leaked = expected is not None and probe["label"] != "self-principals" and any(
            value.encode() in payload for value in (study_b, participant_id))
        if not accepted or leaked or oversized:
            failures.append(f'{probe["label"]} {probe["method"]} {probe["path"]}: HTTP {status}'
                            + (" exposed a foreign fixture identifier" if leaked else "")
                            + (" response exceeds bounded inspection" if oversized else ""))
        elif probe["label"] == "self-principals":
            try:
                if principal_set(json.loads(payload)) != principal_set(actor_fixtures.get("principals")):
                    raise ValueError("Unexpected principal set")
            except (ValueError, UnicodeDecodeError) as error:
                failures.append(f'{probe["label"]}: invalid actor principal set: {error}')
    if failures:
        raise ValueError("\n".join(failures))
    return count


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--validate-target":
        validate_target(sys.argv[2])
        return
    if len(sys.argv) != 1:
        raise ValueError("Use --validate-target URL or supply the disposable fixture environment")
    routes = json.loads((ROOT / "chronicle-server/src/test/resources/route-inventory.json").read_text())
    if not routes:
        raise ValueError("Route inventory is empty")
    import yaml
    from route_probe_inputs import request_inputs

    fixtures = json.loads(Path(os.environ["CHRONICLE_PROBE_FIXTURES"]).read_text())
    fixtures.update(studyId=os.environ["STUDY_B"], participantId=os.environ["PARTICIPANT_ID"])
    actor = json.loads(Path(os.environ["CHRONICLE_PROBE_ACTOR_FIXTURES"]).read_text())
    document = yaml.safe_load((ROOT / "chronicle-api/chronicle.yaml").read_text())
    constants = yaml.safe_load((ROOT / "ontology/chronicle.linkml.yaml").read_text())["constants"]

    def request_builder(method, path):
        return request_inputs(document, path, method, request_context(fixtures, actor, method, path))

    def actor_request_builder(method, path):
        return request_inputs(document, path, method, request_context(actor, actor, method, path))

    count = sweep(os.environ["BASE_URL"], routes, os.environ["AUTH_TOKEN"],
                  os.environ["STUDY_B"], os.environ["PARTICIPANT_ID"], fixtures, request_builder, actor, actor_request_builder,
                  constants["BROWSER_DOWNLOAD_REAUTHENTICATION_PATH"]["value"])
    print(f"Authorization probes: {len(routes)} inventory routes, {count} requests; every route exercised")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, OSError, http.client.HTTPException) as error:
        sys.exit(str(error))
