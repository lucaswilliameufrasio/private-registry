"""Bounded local SCIM target for the Authentik interoperability spike."""

import copy
import json
import os
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


STATE_PATH = "/tmp/private-registry-authentik-scim-state.json"
TOKEN = os.environ["PRIVATE_REGISTRY_SCIM_FIXTURE_TOKEN"]
STATE = {"requests": [], "users": {}, "groups": {}, "failure_mode": False}
LOCK = threading.Lock()


def save_state():
    temporary = STATE_PATH + ".tmp"
    with open(temporary, "w", encoding="utf-8") as state_file:
        json.dump(STATE, state_file, separators=(",", ":"))
    os.replace(temporary, STATE_PATH)


def response(handler, status, value=None):
    body = b"" if value is None else json.dumps(value, separators=(",", ":")).encode()
    handler.send_response(status)
    if value is not None:
        handler.send_header("Content-Type", "application/scim+json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    if body:
        handler.wfile.write(body)


def scim_list(resources):
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(resources),
        "startIndex": 1,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


def filtered_resources(resources, query):
    match = re.search(r'(?:externalId|userName|displayName|id)\s+eq\s+"([^"]*)"', query)
    if match is None:
        return list(resources.values())
    expected = match.group(1)
    return [
        resource
        for resource in resources.values()
        if expected in (resource.get("externalId"), resource.get("userName"), resource.get("displayName"), resource.get("id"))
    ]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format_string, *args):
        return

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            response(self, 200, {"ready": True})
            return
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            response(self, 401, {"detail": "unauthorized"})
            return

        if parsed.path == "/__test/state":
            with LOCK:
                response(self, 200, STATE)
            return
        if parsed.path == "/__test/reset":
            with LOCK:
                STATE["requests"] = []
                STATE["users"] = {}
                STATE["groups"] = {}
                STATE["failure_mode"] = False
                save_state()
                response(self, 200, {"reset": True})
            return
        if self.reject_during_failure("GET", parsed.path):
            return
        if parsed.path.rstrip("/") == "/scim/v2/ServiceProviderConfig":
            response(
                self,
                200,
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                    "patch": {"supported": True},
                    "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
                    "filter": {"supported": True, "maxResults": 200},
                    "changePassword": {"supported": False},
                    "sort": {"supported": False},
                    "etag": {"supported": False},
                    "authenticationSchemes": [
                        {
                            "type": "oauthbearertoken",
                            "name": "Bearer Token",
                            "description": "Synthetic token for this local integration fixture",
                            "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                            "primary": True,
                        }
                    ],
                },
            )
            return

        collection = self.collection(parsed.path)
        if collection is None:
            response(self, 404, {"detail": "not found"})
            return
        query = parse_qs(parsed.query).get("filter", [""])[0]
        with LOCK:
            resources = filtered_resources(STATE[collection], query)
            STATE["requests"].append({
                "collection": collection,
                "method": "GET",
                "path": parsed.path,
                "filter": query,
                "result_count": len(resources),
                "status": 200,
                "observed_at_monotonic_ns": time.monotonic_ns(),
            })
            save_state()
            response(self, 200, scim_list(resources))

    def do_POST(self):
        parsed = urlsplit(self.path)
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            response(self, 401, {"detail": "unauthorized"})
            return
        if parsed.path == "/__test/failure":
            try:
                value = self.read_json()
            except (ValueError, json.JSONDecodeError):
                response(self, 400, {"detail": "invalid JSON"})
                return
            with LOCK:
                STATE["failure_mode"] = bool(value.get("enabled"))
                save_state()
                response(self, 200, {"failure_mode": STATE["failure_mode"]})
            return
        if parsed.path == "/__test/override-user-display-name":
            try:
                value = self.read_json()
            except (ValueError, json.JSONDecodeError):
                response(self, 400, {"detail": "invalid JSON"})
                return
            username = value.get("userName")
            display_name = value.get("displayName")
            if not isinstance(username, str) or not isinstance(display_name, str):
                response(self, 400, {"detail": "userName and displayName are required"})
                return
            with LOCK:
                user = next((item for item in STATE["users"].values() if item.get("userName") == username), None)
                if user is None:
                    response(self, 404, {"detail": "user not found"})
                    return
                user["displayName"] = display_name
                save_state()
                response(self, 200, {"updated": True})
            return
        if self.reject_during_failure("POST", parsed.path):
            return
        collection = self.collection(parsed.path)
        if collection is None:
            response(self, 404, {"detail": "not found"})
            return
        try:
            value = self.read_json()
        except (ValueError, json.JSONDecodeError):
            response(self, 400, {"detail": "invalid JSON"})
            return
        with LOCK:
            external_id = value.get("externalId")
            if external_id and any(item.get("externalId") == external_id for item in STATE[collection].values()):
                STATE["requests"].append({
                    "collection": collection,
                    "method": "POST",
                    "path": parsed.path,
                    "request": copy.deepcopy(value),
                    "status": 409,
                    "observed_at_monotonic_ns": time.monotonic_ns(),
                })
                save_state()
                response(self, 409, {"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "status": "409", "scimType": "uniqueness", "detail": "externalId already exists"})
                return
            resource_id = str(uuid.uuid4())
            value["id"] = resource_id
            value["meta"] = {"resourceType": collection[:-1].title()}
            STATE[collection][resource_id] = value
            self.record(collection, "POST", parsed.path, value, status=201)
            save_state()
        response(self, 201, value)

    def do_PUT(self):
        self.update_resource("PUT")

    def do_PATCH(self):
        self.update_resource("PATCH")

    def do_DELETE(self):
        parsed = urlsplit(self.path)
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            response(self, 401, {"detail": "unauthorized"})
            return
        if self.reject_during_failure("DELETE", parsed.path):
            return
        collection, resource_id = self.resource_path(parsed.path)
        if collection is None:
            response(self, 404, {"detail": "not found"})
            return
        with LOCK:
            resource = STATE[collection].pop(resource_id, None)
            self.record(collection, "DELETE", parsed.path, resource or {})
            save_state()
        response(self, 204)

    def update_resource(self, method):
        parsed = urlsplit(self.path)
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            response(self, 401, {"detail": "unauthorized"})
            return
        if self.reject_during_failure(method, parsed.path):
            return
        collection, resource_id = self.resource_path(parsed.path)
        if collection is None:
            response(self, 404, {"detail": "not found"})
            return
        try:
            value = self.read_json()
        except (ValueError, json.JSONDecodeError):
            response(self, 400, {"detail": "invalid JSON"})
            return
        with LOCK:
            current = STATE[collection].get(resource_id)
            if current is None:
                response(self, 404, {"detail": "resource not found"})
                return
            if method == "PUT":
                value["id"] = resource_id
                STATE[collection][resource_id] = value
            else:
                operations = value.get("Operations", value.get("operations", []))
                self.apply_patch(current, operations)
            result = STATE[collection][resource_id]
            self.record(collection, method, parsed.path, result, request=value)
            save_state()
        response(self, 200, result)

    def apply_patch(self, resource, operations):
        for operation in operations:
            op = operation.get("op", "").lower()
            path = operation.get("path", "")
            value = operation.get("value")
            if path.lower() == "active" and op in ("replace", "add"):
                resource["active"] = value
            elif path.lower() == "members" and isinstance(value, list):
                members = resource.setdefault("members", [])
                for member in value:
                    member_id = member.get("value")
                    if op == "add" and not any(item.get("value") == member_id for item in members):
                        members.append(member)
                    if op == "remove":
                        members[:] = [item for item in members if item.get("value") != member_id]
            elif path.lower().startswith("members[") and op == "remove":
                match = re.search(r'value\s+eq\s+"([^"]+)"', path)
                if match is not None:
                    members = resource.setdefault("members", [])
                    members[:] = [item for item in members if item.get("value") != match.group(1)]

    def record(self, collection, method, path, value, request=None, status=200):
        STATE["requests"].append({
            "collection": collection,
            "method": method,
            "path": path,
            "resource": copy.deepcopy(value),
            "request": copy.deepcopy(request),
            "status": status,
            "observed_at_monotonic_ns": time.monotonic_ns(),
        })

    def reject_during_failure(self, method, path):
        if path.startswith("/__test/"):
            return False
        with LOCK:
            if not STATE["failure_mode"]:
                return False
            STATE["requests"].append({
                "method": method,
                "path": path,
                "status": 503,
                "observed_at_monotonic_ns": time.monotonic_ns(),
            })
            save_state()
        response(self, 503, {"detail": "synthetic fixture outage"})
        return True

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_048_576:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(length))

    @staticmethod
    def collection(path):
        if path.rstrip("/") == "/scim/v2/Users":
            return "users"
        if path.rstrip("/") == "/scim/v2/Groups":
            return "groups"
        return None

    @classmethod
    def resource_path(cls, path):
        parts = path.rstrip("/").rsplit("/", 1)
        if len(parts) != 2:
            return None, None
        collection = cls.collection(parts[0])
        if collection is None:
            return None, None
        return collection, parts[1]


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8765), Handler)
    server.daemon_threads = True
    server.serve_forever()
