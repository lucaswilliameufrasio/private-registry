"""Exercise the pinned Authentik OIDC and SCIM contract against local fixtures."""

import base64
import hashlib
import http.cookiejar
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


BASE = "http://127.0.0.1:9000"
API = BASE + "/api/v3"
SCIM_TARGET = "http://127.0.0.1:8765"
BOOTSTRAP_TOKEN = os.environ["AUTHENTIK_BOOTSTRAP_TOKEN"]
SCIM_TOKEN = os.environ["PRIVATE_REGISTRY_SCIM_FIXTURE_TOKEN"]
SENSITIVE_VALUES = [BOOTSTRAP_TOKEN, SCIM_TOKEN]


def api(method, path, value=None):
    headers = {"Authorization": "Bearer " + BOOTSTRAP_TOKEN}
    body = None
    if value is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(value, separators=(",", ":")).encode()
    request = urllib.request.Request(API + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read()
            return None if not data else json.loads(data)
    except urllib.error.HTTPError as error:
        message = error.read().decode("utf-8", errors="replace")
        for secret in SENSITIVE_VALUES:
            message = message.replace(secret, "[redacted]")
        raise RuntimeError(f"Authentik API {method} {path} returned {error.code}: {message[:500]}") from None


def target(method, path, value=None):
    headers = {"Authorization": "Bearer " + SCIM_TOKEN}
    body = None
    if value is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(value, separators=(",", ":")).encode()
    request = urllib.request.Request(SCIM_TARGET + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = response.read()
            return None if not data else json.loads(data)
    except urllib.error.HTTPError as error:
        message = error.read().decode("utf-8", errors="replace")
        for secret in SENSITIVE_VALUES:
            message = message.replace(secret, "[redacted]")
        raise RuntimeError(f"SCIM fixture {method} {path} returned {error.code}: {message[:300]}") from None


def wait_until(description, predicate, timeout_seconds=60):
    deadline = time.monotonic() + timeout_seconds
    last_value = None
    while time.monotonic() < deadline:
        last_value = predicate()
        if last_value:
            return last_value
        time.sleep(0.2)
    raise RuntimeError(f"timed out waiting for {description}; latest state={last_value!r}")


def get_target_state():
    return target("GET", "/__test/state")


def create_application_with_provider(name, slug, provider_model, provider, policy_bindings=None):
    result = api(
        "PUT",
        "/core/transactional/applications/",
        {
            "app": {"name": name, "slug": slug},
            "provider_model": provider_model,
            "provider": provider,
            "policy_bindings": policy_bindings or [],
        },
    )
    application = api("GET", "/core/applications/" + slug + "/")
    return result, application


def verify_oidc_login(slug, expected_username):
    application = api("GET", "/core/applications/" + slug + "/")
    provider_id = application.get("provider")
    if not provider_id:
        raise RuntimeError("OIDC application has no provider")
    provider = api("GET", f"/providers/oauth2/{provider_id}/")
    metadata = json.load(urllib.request.urlopen(BASE + f"/application/o/{slug}/.well-known/openid-configuration", timeout=15))
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(18)
    nonce = secrets.token_urlsafe(18)
    redirect_uri = "http://127.0.0.1:9999/callback"
    authorization_query = urllib.parse.urlencode(
        {
            "client_id": provider["client_id"],
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )

    cookie_jar = http.cookiejar.CookieJar()
    browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
    flow_page = browser.open(BASE + "/application/o/authorize/?" + authorization_query, timeout=20)
    flow_location = urllib.parse.urlsplit(flow_page.geturl())
    flow_slug = flow_location.path.strip("/").split("/")[-1]
    flow_query = flow_location.query
    flow_url = API + "/flows/executor/" + flow_slug + "/?" + urllib.parse.urlencode({"query": flow_query})
    challenge_data = json.load(browser.open(flow_url, timeout=15))
    if challenge_data.get("component") != "ak-stage-identification":
        raise RuntimeError("Authentik did not start with its identification stage")

    challenge_data = solve_flow(browser, flow_url, {"component": "ak-stage-identification", "uid_field": expected_username})
    challenge_data = solve_flow(browser, flow_url, {"component": "ak-stage-password", "password": USER_PASSWORD})
    if challenge_data.get("component") != "xak-flow-redirect" or not challenge_data.get("final_redirect"):
        raise RuntimeError("Authentik did not finish the authorization-code login flow")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, file_pointer, code, message, headers, new_url):
            return None

    no_redirect = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar), NoRedirect())
    try:
        no_redirect.open(BASE + challenge_data["to"], timeout=15)
        raise RuntimeError("expected redirect to the registered OIDC callback")
    except urllib.error.HTTPError as error:
        if error.code not in (301, 302, 303, 307, 308):
            raise RuntimeError(f"OIDC authorization ended with HTTP {error.code}") from None
        callback_url = error.headers.get("Location", "")

    callback = urllib.parse.urlsplit(callback_url)
    callback_values = urllib.parse.parse_qs(callback.query)
    if (
        callback.hostname != "127.0.0.1"
        or callback.port != 9999
        or callback.path != "/callback"
        or callback_values.get("state") != [state]
        or not callback_values.get("code")
    ):
        raise RuntimeError("OIDC callback did not match the registered redirect and state")

    token_form = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": callback_values["code"][0],
            "redirect_uri": redirect_uri,
            "client_id": provider["client_id"],
            "code_verifier": verifier,
        }
    ).encode()
    token_request = urllib.request.Request(
        BASE + "/application/o/token/",
        data=token_form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    token_response = json.load(urllib.request.urlopen(token_request, timeout=15))
    id_token = token_response.get("id_token", "")
    parts = id_token.split(".")
    if len(parts) != 3:
        raise RuntimeError("OIDC token endpoint did not return a compact signed ID token")
    header = decode_jwt_part(parts[0])
    claims = decode_jwt_part(parts[1])
    jwks = json.load(urllib.request.urlopen(metadata["jwks_uri"], timeout=15))
    key = next((item for item in jwks.get("keys", []) if item.get("kid") == header.get("kid")), None)
    if key is None or header.get("alg") != "RS256":
        raise RuntimeError("OIDC signing key was not an RS256 key published by JWKS")
    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(decode_base64url(key["e"]), "big"),
        int.from_bytes(decode_base64url(key["n"]), "big"),
    ).public_key()
    public_key.verify(
        decode_base64url(parts[2]),
        (parts[0] + "." + parts[1]).encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    audience = claims.get("aud", [])
    if isinstance(audience, str):
        audience = [audience]
    valid = (
        claims.get("iss") == metadata.get("issuer")
        and provider["client_id"] in audience
        and claims.get("nonce") == nonce
        and claims.get("exp", 0) > int(time.time())
    )
    if not valid:
        raise RuntimeError("OIDC ID token failed issuer, audience, nonce, or expiry validation")
    target_state = get_target_state()
    scim_user = next(
        (item for item in target_state.get("users", {}).values() if item.get("userName") == expected_username),
        None,
    )
    if scim_user is None:
        raise RuntimeError("OIDC user has no corresponding SCIM identity")
    email_values = [item.get("value") for item in scim_user.get("emails", []) if item.get("value")]
    return {
        "subject": claims.get("sub"),
        "algorithm": header.get("alg"),
        "signature_verified": True,
        "subject_is_not_email": claims.get("sub") not in email_values,
    }


def solve_flow(browser, flow_url, payload):
    request = urllib.request.Request(
        flow_url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return json.load(browser.open(request, timeout=15))


def decode_base64url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decode_jwt_part(value):
    return json.loads(decode_base64url(value))


def task_rows(provider_id):
    data = api("GET", "/tasks/tasks/?page_size=100")
    return [
        item
        for item in data.get("results", [])
        if (
            item.get("rel_obj_model") == "scimprovider" and str(item.get("rel_obj_id")) == str(provider_id)
        )
        or "scim" in str(item.get("description", "")).lower()
    ]


def wait_for_provider_idle(provider_id, timeout_seconds=60):
    observed_rows = []

    def idle():
        nonlocal observed_rows
        rows = task_rows(provider_id)
        observed_rows = rows
        running = [item for item in rows if item.get("state") in ("queued", "running", "retrying")]
        return not running

    try:
        wait_until("SCIM provider tasks to become idle", idle, timeout_seconds)
    except RuntimeError:
        blocking_tasks = [
            {
                "description": item.get("description"),
                "state": item.get("state"),
                "aggregated_status": item.get("aggregated_status"),
                "mtime": item.get("mtime"),
                "message_id": item.get("message_id"),
                "rel_obj_model": item.get("rel_obj_model"),
                "rel_obj_id": item.get("rel_obj_id"),
            }
            for item in observed_rows
            if item.get("state") in ("queued", "running", "retrying")
        ]
        raise RuntimeError(
            "SCIM provider did not become idle; blocking tasks="
            + json.dumps(blocking_tasks[:20], sort_keys=True)
            + "; recent tasks="
            + json.dumps(recent_task_diagnostics(provider_id), sort_keys=True)
        ) from None


def trigger_full_sync(provider_id, schedule_uid, previous_success=None):
    schedules = api("GET", "/tasks/schedules/?page_size=100")
    schedule = next((item for item in schedules.get("results", []) if item.get("uid") == schedule_uid), None)
    if schedule is None:
        raise RuntimeError("SCIM provider has no full-sync schedule")
    wait_for_provider_idle(provider_id)
    api("POST", f"/tasks/schedules/{schedule['id']}/send/", {})

    def completed():
        status = api("GET", f"/providers/scim/{provider_id}/sync/status/")
        if status.get("is_running"):
            return None
        if previous_success is not None and status.get("last_successful_sync") == previous_success:
            return None
        return status

    status = wait_until("SCIM full sync status to update", completed, 60)
    wait_for_provider_idle(provider_id)
    return status


def provider_task_failure_signals(provider_id, known_task_ids):
    rows = [item for item in task_rows(provider_id) if item.get("message_id") not in known_task_ids]
    status = api("GET", f"/providers/scim/{provider_id}/sync/status/")
    error_log_count = 0
    task_status_signals = []
    task_summaries = []
    for row in rows:
        row_status = str(row.get("aggregated_status") or "").lower()
        row_state = str(row.get("state") or "").lower()
        if row_status in ("warning", "error", "failed", "failure") or row_state in ("warning", "error", "failed", "failure"):
            task_status_signals.append({"description": row.get("description"), "state": row_state, "status": row_status})
        if not row.get("message_id"):
            continue
        detail = api("GET", "/tasks/tasks/" + row["message_id"] + "/")
        row_error_count = 0
        for entry in detail.get("logs", []):
            level = str(entry.get("log_level") or "").lower()
            if level in ("warning", "error", "critical", "fatal"):
                error_log_count += 1
                row_error_count += 1
        task_summaries.append(
            {
                "description": row.get("description"),
                "state": row_state,
                "status": row_status,
                "error_log_count": row_error_count,
            }
        )
    sync_status = str(status.get("last_sync_status") or "").lower()
    status_signal = sync_status in ("warning", "error", "failed", "failure")
    return {
        "observed": status_signal or bool(task_status_signals) or error_log_count > 0,
        "sync_status": status.get("last_sync_status"),
        "last_successful_sync_unchanged": None,
        "task_status_signals": task_status_signals,
        "error_log_count": error_log_count,
        "new_task_count": len(rows),
        "task_summaries": task_summaries[:8],
    }


def recent_task_diagnostics(provider_id, limit=10):
    rows = sorted(
        task_rows(provider_id),
        key=lambda item: item.get("mtime") or "",
        reverse=True,
    )[:limit]
    diagnostics = []
    for row in rows:
        summary = {
            "description": row.get("description"),
            "state": row.get("state"),
            "aggregated_status": row.get("aggregated_status"),
            "mtime": row.get("mtime"),
        }
        message_id = row.get("message_id")
        if message_id:
            detail = api("GET", "/tasks/tasks/" + message_id + "/")
            levels = [str(item.get("log_level") or "unknown").lower() for item in detail.get("logs", [])]
            summary["log_level_counts"] = {level: levels.count(level) for level in sorted(set(levels))}
        diagnostics.append(summary)
    return diagnostics


def main():
    global USER_PASSWORD
    suffix = uuid.uuid4().hex[:10]
    user_name = "scim-user-" + suffix
    group_a_name = "scim-team-a-" + suffix
    group_b_name = "scim-team-b-" + suffix
    user_password = secrets.token_urlsafe(24)
    USER_PASSWORD = user_password
    SENSITIVE_VALUES.append(user_password)

    group_a = api("POST", "/core/groups/", {"name": group_a_name})
    group_b = api("POST", "/core/groups/", {"name": group_b_name})

    def oauth_flows():
        authorization = api("GET", "/flows/instances/?designation=authorization").get("results", [])
        invalidation = api("GET", "/flows/instances/?designation=invalidation").get("results", [])
        found = {item.get("slug"): item.get("pk") for item in authorization + invalidation}
        if "default-provider-authorization-implicit-consent" not in found:
            return None
        if "default-provider-invalidation-flow" not in found:
            return None
        return found

    flow_by_slug = wait_until(
        "default OAuth authorization and invalidation flows",
        oauth_flows,
        timeout_seconds=180,
    )
    certificate_keys = api("GET", "/crypto/certificatekeypairs/?page_size=100").get("results", [])
    signing_key = next((item.get("pk") for item in certificate_keys if item.get("name") == "authentik Self-signed Certificate"), None)
    if signing_key is None:
        raise RuntimeError("Authentik fixture did not provide its self-signed signing key")
    oidc_slug = "registry-oidc-" + suffix
    oidc_name = "Private Registry OIDC " + suffix
    _, oidc_application = create_application_with_provider(
        oidc_name,
        oidc_slug,
        "authentik_providers_oauth2.oauth2provider",
        {
            "name": oidc_name,
            "authorization_flow": flow_by_slug["default-provider-authorization-implicit-consent"],
            "invalidation_flow": flow_by_slug["default-provider-invalidation-flow"],
            "redirect_uris": [{"matching_mode": "strict", "url": "http://127.0.0.1:9999/callback"}],
            "client_type": "public",
            "grant_types": ["authorization_code"],
            "sub_mode": "hashed_user_id",
            "signing_key": signing_key,
        },
    )

    def default_scim_mappings():
        mappings = api("GET", "/propertymappings/provider/scim/?page_size=100").get("results", [])
        user = next((item.get("pk") for item in mappings if item.get("name", "").endswith("User")), None)
        group = next((item.get("pk") for item in mappings if item.get("name", "").endswith("Group")), None)
        if user is None or group is None:
            return None
        return user, group

    user_mapping, group_mapping = wait_until(
        "default SCIM user and group property mappings",
        default_scim_mappings,
        timeout_seconds=180,
    )

    scim_slug = "registry-scim-" + suffix
    scim_name = "Private Registry SCIM " + suffix
    transaction_result, scim_application = create_application_with_provider(
        scim_name,
        scim_slug,
        "authentik_providers_scim.scimprovider",
        {
            "name": scim_name,
            "url": "http://server:8765/scim/v2",
            "token": SCIM_TOKEN,
            "auth_mode": "token",
            "property_mappings": [user_mapping],
            "property_mappings_group": [group_mapping],
            "service_provider_config_cache_timeout": "hours=0;minutes=0",
            "discovery_enabled": True,
            "exclude_users_service_account": True,
        },
        [
            {"group": group_a["pk"], "order": 0, "enabled": True},
            {"group": group_b["pk"], "order": 1, "enabled": True},
        ],
    )
    scim_provider = transaction_result.get("provider", {})
    scim_provider_id = scim_provider.get("pk")
    if not scim_provider_id:
        scim_provider = api("GET", "/providers/scim/?page_size=100").get("results", [])
        scim_provider = next((item for item in scim_provider if item.get("name") == scim_name), None)
        if scim_provider is None:
            raise RuntimeError("SCIM application transaction did not create a provider")
        scim_provider_id = scim_provider.get("pk")
    linked_backchannel = scim_provider_id in scim_application.get("backchannel_providers", [])
    if not linked_backchannel:
        application_patch = {"provider": None, "backchannel_providers": [scim_provider_id]}
        scim_application = api("PATCH", "/core/applications/" + scim_slug + "/", application_patch)
    if scim_provider_id not in scim_application.get("backchannel_providers", []):
        raise RuntimeError("SCIM provider is not linked as an application's backchannel provider")

    # The fixture worker is CPU-limited; provider bootstrap sync can exceed two minutes.
    wait_for_provider_idle(scim_provider_id, timeout_seconds=240)

    user = api(
        "POST",
        "/core/users/",
        {
            "name": "Synthetic SCIM Contract User",
            "username": user_name,
            "email": user_name + "@example.invalid",
            "is_active": True,
        },
    )
    api("POST", f"/core/users/{user['pk']}/set_password/", {"password": user_password})
    event_start = time.monotonic_ns()
    api("POST", f"/core/groups/{group_a['pk']}/add_user/", {"pk": user["pk"]})

    def first_membership_provisioned():
        state = get_target_state()
        remote_user = next((item for item in state["users"].values() if item.get("userName") == user_name), None)
        remote_groups = [item for item in state["groups"].values() if item.get("displayName") == group_a_name]
        remote_group = next((item for item in remote_groups if item.get("members")), None)
        if remote_user is None or remote_group is None:
            return None
        return state, remote_user, remote_group

    try:
        wait_until(
            "SCIM first group membership before the next membership change",
            first_membership_provisioned,
            timeout_seconds=120,
        )
    except RuntimeError:
        target_state = get_target_state()
        matching_groups = [
            item
            for item in target_state["groups"].values()
            if item.get("displayName") in (group_a_name, group_b_name)
        ]
        matching_requests = []
        for item in target_state.get("requests", []):
            resource = item.get("resource")
            if not isinstance(resource, dict):
                resource = {}
            if item.get("collection") != "groups" and resource.get("displayName") not in (group_a_name, group_b_name):
                continue
            if resource.get("displayName") not in (group_a_name, group_b_name) and not (
                item.get("collection") == "groups" and item.get("method") == "GET"
            ):
                continue
            matching_requests.append(
                {
                    "method": item.get("method"),
                    "path": item.get("path"),
                    "filter": item.get("filter"),
                    "result_count": item.get("result_count"),
                    "status": item.get("status"),
                    "externalId": resource.get("externalId"),
                    "displayName": resource.get("displayName"),
                    "member_count": len(resource.get("members", [])),
                    "observed_at_monotonic_ns": item.get("observed_at_monotonic_ns"),
                }
            )
        diagnostic = {
            "target_user": next(
                (item for item in target_state["users"].values() if item.get("userName") == user_name),
                None,
            ),
            "matching_groups": matching_groups,
            "matching_requests": matching_requests[-40:],
            "recent_provider_tasks": recent_task_diagnostics(scim_provider_id),
        }
        raise RuntimeError("SCIM first membership diagnostics=" + json.dumps(diagnostic, sort_keys=True)) from None
    wait_for_provider_idle(scim_provider_id, timeout_seconds=60)
    api("POST", f"/core/groups/{group_b['pk']}/add_user/", {"pk": user["pk"]})

    def provisioned_resources():
        state = get_target_state()
        remote_user = next((item for item in state["users"].values() if item.get("userName") == user_name), None)
        remote_groups_a = [item for item in state["groups"].values() if item.get("displayName") == group_a_name]
        remote_groups_b = [item for item in state["groups"].values() if item.get("displayName") == group_b_name]
        remote_a = next((item for item in remote_groups_a if item.get("members")), None)
        remote_b = next((item for item in remote_groups_b if item.get("members")), None)
        if remote_user is None or remote_a is None or remote_b is None:
            return None
        return state, remote_user, remote_a, remote_b

    try:
        provisioned = wait_until("SCIM user and both group memberships", provisioned_resources)
    except RuntimeError:
        target_state = get_target_state()
        provider_state = api("GET", f"/providers/scim/{scim_provider_id}/")
        sync_state = api("GET", f"/providers/scim/{scim_provider_id}/sync/status/")
        recent_tasks = sorted(task_rows(scim_provider_id), key=lambda item: item.get("mtime") or "", reverse=True)[:8]
        target_request_summaries = []
        for item in target_state.get("requests", [])[-40:]:
            resource = item.get("resource")
            if not isinstance(resource, dict):
                resource = {}
            request_value = item.get("request")
            if not isinstance(request_value, dict):
                request_value = {}
            patch_operations = request_value.get("Operations", request_value.get("operations", []))
            if not isinstance(patch_operations, list):
                patch_operations = []
            target_request_summaries.append(
                {
                    "method": item.get("method"),
                    "path": item.get("path"),
                    "filter": item.get("filter"),
                    "result_count": item.get("result_count"),
                    "status": item.get("status"),
                    "externalId": resource.get("externalId"),
                    "userName": resource.get("userName"),
                    "displayName": resource.get("displayName"),
                    "member_count": len(resource.get("members", [])),
                    "patch_operation_count": len(patch_operations),
                }
            )
        diagnostics = {
            "target_users": [
                {
                    "externalId": item.get("externalId"),
                    "userName": item.get("userName"),
                    "displayName": item.get("displayName"),
                    "active": item.get("active"),
                }
                for item in target_state.get("users", {}).values()
            ],
            "target_groups": [
                {
                    "externalId": item.get("externalId"),
                    "displayName": item.get("displayName"),
                    "members": item.get("members", []),
                }
                for item in target_state.get("groups", {}).values()
            ],
            "target_requests": target_request_summaries,
            "provider_url": provider_state.get("url"),
            "provider_auth_mode": provider_state.get("auth_mode"),
            "provider_dry_run": provider_state.get("dry_run"),
            "provider_mapping_count": len(provider_state.get("property_mappings", [])),
            "provider_group_mapping_count": len(provider_state.get("property_mappings_group", [])),
            "application_provider": scim_application.get("provider"),
            "application_backchannels": scim_application.get("backchannel_providers", []),
            "sync_status": sync_state,
            "recent_provider_tasks": [
                {
                    "description": item.get("description"),
                    "state": item.get("state"),
                    "aggregated_status": item.get("aggregated_status"),
                    "mtime": item.get("mtime"),
                }
                for item in recent_tasks
            ],
        }
        raise RuntimeError("SCIM provisioning diagnostics=" + json.dumps(diagnostics, sort_keys=True)) from None
    state, remote_user, remote_group_a, remote_group_b = provisioned
    oidc_result = verify_oidc_login(oidc_slug, user_name)
    if remote_user.get("externalId") != oidc_result["subject"]:
        raise RuntimeError("OIDC sub does not match SCIM externalId for the same Authentik user")

    removal_start = time.monotonic_ns()
    api("POST", f"/core/groups/{group_a['pk']}/remove_user/", {"pk": user["pk"]})

    def removed_from_group_a():
        current = get_target_state()
        groups_a = [item for item in current["groups"].values() if item.get("displayName") == group_a_name]
        groups_b = [item for item in current["groups"].values() if item.get("displayName") == group_b_name]
        remote = next((item for item in current["users"].values() if item.get("userName") == user_name), None)
        still_assigned_group = next((item for item in groups_b if item.get("members")), None)
        if not groups_a or still_assigned_group is None or remote is None:
            return None
        if any(item.get("members") for item in groups_a):
            return None
        return current, groups_a[0], still_assigned_group, remote

    removal = wait_until("SCIM group membership removal while user remains assigned", removed_from_group_a)
    removal_state, removed_group, still_assigned_group_b, still_assigned_user = removal
    if not still_assigned_user.get("active") or not still_assigned_group_b.get("members"):
        raise RuntimeError("removing one group removed the user or its independent second membership")

    deactivation_start = time.monotonic_ns()
    api("PATCH", f"/core/users/{user['pk']}/", {"is_active": False})

    def deactivated_user():
        current = get_target_state()
        remote = next((item for item in current["users"].values() if item.get("userName") == user_name), None)
        if remote is None or remote.get("active") is not False:
            return None
        return current, remote

    deactivation = wait_until("SCIM inactive status after Authentik user deactivation", deactivated_user)
    deactivation_state, inactive_user = deactivation

    endpoint_time = time.monotonic_ns()
    latency_seconds = {
        "group_removal": event_latency(removal_state, removal_start, endpoint_time, group_a_name, "groups", "PATCH"),
        "deactivation": event_latency(deactivation_state, deactivation_start, endpoint_time, user_name, "users", "PUT"),
    }
    if max(latency_seconds.values()) > 60:
        raise RuntimeError("observed SCIM event delivery exceeded the 60-second normal-operation target")

    recovery_user_name = user_name + "-recovery"
    recovery_user_started_ns = time.monotonic_ns()
    recovery_prior_task_ids = {item.get("message_id") for item in task_rows(scim_provider_id)}
    recovery_user = api(
        "POST",
        "/core/users/",
        {
            "name": "Synthetic Active Recovery User",
            "username": recovery_user_name,
            "email": recovery_user_name + "@example.invalid",
            "is_active": True,
        },
    )

    def recovery_user_provisioned():
        current = get_target_state()
        remote = next((item for item in current["users"].values() if item.get("userName") == recovery_user_name), None)
        groups = [item for item in current["groups"].values() if item.get("displayName") == group_b_name]
        if remote is None or remote.get("active") is not True:
            return None
        group_with_member = next(
            (
                item
                for item in groups
                if any(member.get("value") == remote.get("id") for member in item.get("members", []))
            ),
            None,
        )
        if group_with_member is None:
            return None
        return remote

    try:
        api("POST", f"/core/groups/{group_b['pk']}/add_user/", {"pk": recovery_user["pk"]})
        remote_recovery_user = wait_until(
            "active SCIM recovery user and group membership",
            recovery_user_provisioned,
        )
    except RuntimeError:
        recovery_state = get_target_state()
        provider_state = api("GET", f"/providers/scim/{scim_provider_id}/")
        sync_state = api("GET", f"/providers/scim/{scim_provider_id}/sync/status/")
        requests_since_user_creation = [
            {
                "method": item.get("method"),
                "path": item.get("path"),
                "filter": item.get("filter"),
                "result_count": item.get("result_count"),
                "status": item.get("status"),
                "userName": item.get("resource", {}).get("userName"),
                "displayName": item.get("resource", {}).get("displayName"),
            }
            for item in recovery_state.get("requests", [])
            if item.get("observed_at_monotonic_ns", 0) >= recovery_user_started_ns
        ]
        recovery_task_rows = [
            item for item in task_rows(scim_provider_id)
            if item.get("message_id") not in recovery_prior_task_ids
        ]
        recovery_task_diagnostics = []
        for row in recovery_task_rows[-12:]:
            message_id = row.get("message_id")
            if not message_id:
                continue
            detail = api("GET", "/tasks/tasks/" + message_id + "/")
            logs = []
            for item in detail.get("logs", [])[-12:]:
                message = item.get("log_message") or item.get("message") or item.get("event")
                if message is None:
                    continue
                message = str(message)
                for secret in SENSITIVE_VALUES:
                    message = message.replace(secret, "[redacted]")
                logs.append({
                    "log_level": item.get("log_level"),
                    "message": message[:500],
                })
            recovery_task_diagnostics.append({
                "description": row.get("description"),
                "state": row.get("state"),
                "aggregated_status": row.get("aggregated_status"),
                "rel_obj_model": row.get("rel_obj_model"),
                "rel_obj_id": row.get("rel_obj_id"),
                "logs": logs,
            })
        diagnostic = {
            "recovery_user_id": recovery_user.get("pk"),
            "recovery_user_name": recovery_user_name,
            "recovery_user_active": recovery_user.get("is_active"),
            "group_b_id": group_b.get("pk"),
            "target_users": [
                {
                    "id": item.get("id"),
                    "userName": item.get("userName"),
                    "displayName": item.get("displayName"),
                    "active": item.get("active"),
                }
                for item in recovery_state.get("users", {}).values()
            ],
            "target_groups": [
                {
                    "displayName": item.get("displayName"),
                    "members": item.get("members", []),
                }
                for item in recovery_state.get("groups", {}).values()
            ],
            "requests_since_user_creation": requests_since_user_creation[-30:],
            "provider_url": provider_state.get("url"),
            "provider_dry_run": provider_state.get("dry_run"),
            "sync_status": sync_state,
            "new_task_ids": [item.get("message_id") for item in recovery_task_rows],
            "new_task_diagnostics": recovery_task_diagnostics,
            "recent_tasks": recent_task_diagnostics(scim_provider_id),
        }
        raise RuntimeError("SCIM recovery-user provisioning diagnostics=" + json.dumps(diagnostic, sort_keys=True)) from None
    healthy_display_name = "Synthetic Active Recovery User - healthy mapping"
    api("PATCH", f"/core/users/{recovery_user['pk']}/", {"name": healthy_display_name})

    def healthy_mapping_observed():
        current = get_target_state()
        remote = next((item for item in current["users"].values() if item.get("userName") == recovery_user_name), None)
        if remote is None or remote.get("displayName") != healthy_display_name:
            return None
        return remote

    remote_recovery_user = wait_until("healthy SCIM mapping of Authentik name to displayName", healthy_mapping_observed)
    wait_for_provider_idle(scim_provider_id)

    provider_status = api("GET", f"/providers/scim/{scim_provider_id}/sync/status/")
    schedule_uid = "authentik.providers.scim.tasks.scim_sync:" + scim_name
    full_sync_status = trigger_full_sync(scim_provider_id, schedule_uid, provider_status.get("last_successful_sync"))

    wait_for_provider_idle(scim_provider_id)
    successful_sync = api("GET", f"/providers/scim/{scim_provider_id}/sync/status/")
    previous_successful_sync = successful_sync.get("last_successful_sync")
    prior_task_ids = {item.get("message_id") for item in task_rows(scim_provider_id)}
    failure_started = time.monotonic_ns()
    target("POST", "/__test/failure", {"enabled": True})
    recovered_display_name = "Synthetic Active Recovery User - outage reconciliation"
    api("PATCH", f"/core/users/{recovery_user['pk']}/", {"name": recovered_display_name})

    def rejected_requests():
        current = get_target_state()
        rejected = [
            item
            for item in current.get("requests", [])
            if item.get("status") == 503 and item.get("observed_at_monotonic_ns", 0) >= failure_started
        ]
        if not rejected:
            return None
        return current, rejected

    failure_observation = wait_until("Authentik to attempt SCIM calls during the synthetic outage", rejected_requests, 45)
    failure_state, rejected = failure_observation
    failure_signals = None
    signal_deadline = time.monotonic() + 20
    while time.monotonic() < signal_deadline:
        failure_signals = provider_task_failure_signals(scim_provider_id, prior_task_ids)
        if failure_signals["observed"]:
            break
        time.sleep(1)
    if failure_signals is None:
        failure_signals = provider_task_failure_signals(scim_provider_id, prior_task_ids)
    failure_status = api("GET", f"/providers/scim/{scim_provider_id}/sync/status/")
    failure_signals["last_successful_sync_unchanged"] = failure_status.get("last_successful_sync") == previous_successful_sync
    failure_signals["target_503_request_count"] = len(rejected)
    failure_signals["target_503_paths"] = sorted({item.get("path", "") for item in rejected})
    target("POST", "/__test/failure", {"enabled": False})
    wait_for_provider_idle(scim_provider_id, timeout_seconds=90)
    retry_state = get_target_state()
    retry_remote_user = next(
        (item for item in retry_state["users"].values() if item.get("userName") == recovery_user_name),
        None,
    )
    recovery_event_retry_reconciled = (
        retry_remote_user is not None
        and retry_remote_user.get("active") is True
        and retry_remote_user.get("displayName") == recovered_display_name
    )

    stale_display_name = "Synthetic Active Recovery User - deliberately stale fixture state"
    stale_started_ns = time.monotonic_ns()
    target(
        "POST",
        "/__test/override-user-display-name",
        {"userName": recovery_user_name, "displayName": stale_display_name},
    )
    stale_state = get_target_state()
    stale_user = next((item for item in stale_state["users"].values() if item.get("userName") == recovery_user_name), None)
    if stale_user is None or stale_user.get("displayName") != stale_display_name:
        raise RuntimeError("SCIM fixture did not establish the controlled stale state for full-sync reconciliation")
    recovered_sync = trigger_full_sync(
        scim_provider_id,
        schedule_uid,
        previous_successful_sync,
    )

    latest_target_state = get_target_state()
    reconciled_remote_user = next(
        (item for item in latest_target_state.get("users", {}).values() if item.get("userName") == recovery_user_name),
        None,
    )
    recovery_reconciled = (
        reconciled_remote_user is not None
        and reconciled_remote_user.get("active") is True
        and reconciled_remote_user.get("displayName") == recovered_display_name
    )
    full_sync_requests = [
        item
        for item in latest_target_state.get("requests", [])
        if item.get("observed_at_monotonic_ns", 0) >= stale_started_ns
    ]
    full_sync_user_read_observed = any(
        item.get("collection") == "users" and item.get("method") == "GET"
        for item in full_sync_requests
    )
    full_sync_user_update_count = sum(
        1
        for item in full_sync_requests
        if item.get("collection") == "users" and item.get("method") in ("PUT", "PATCH")
    )
    synthetic_group_a_count = sum(
        1
        for item in latest_target_state.get("groups", {}).values()
        if item.get("displayName") == group_a_name
    )
    synthetic_group_b_count = sum(
        1
        for item in latest_target_state.get("groups", {}).values()
        if item.get("displayName") == group_b_name
    )
    duplicate_group_resource_count = max(0, synthetic_group_a_count - 1) + max(0, synthetic_group_b_count - 1)

    print(
        json.dumps(
            {
                "authentik_version": "2026.8.3",
                "oidc_algorithm": oidc_result["algorithm"],
                "oidc_signature_verified": oidc_result["signature_verified"],
                "oidc_subject_matches_scim_external_id": True,
                "oidc_subject_is_not_email": oidc_result["subject_is_not_email"],
                "scim_deactivation_applied": inactive_user.get("active") is False,
                "scim_group_removal_kept_second_membership": bool(still_assigned_group_b.get("members")),
                "event_latency_seconds": latency_seconds,
                "full_sync_last_status": full_sync_status.get("last_sync_status"),
                "full_sync_last_successful_sync_present": bool(full_sync_status.get("last_successful_sync")),
                "health_failure_signal_observed": failure_signals["observed"],
                "failure_sync_status": failure_signals["sync_status"],
                "failure_last_successful_sync_unchanged": failure_signals["last_successful_sync_unchanged"],
                "failure_error_log_count": failure_signals["error_log_count"],
                "failure_new_task_count": failure_signals["new_task_count"],
                "failure_task_summaries": failure_signals["task_summaries"],
                "failure_target_503_request_count": failure_signals["target_503_request_count"],
                "recovery_full_sync_status": recovered_sync.get("last_sync_status"),
                "recovery_event_retry_reconciled_user": recovery_event_retry_reconciled,
                "recovery_full_sync_repaired_fixture_drift": recovery_reconciled,
                "recovery_full_sync_user_read_observed": full_sync_user_read_observed,
                "recovery_full_sync_user_update_count": full_sync_user_update_count,
                "scim_user_count_seen": len(state.get("users", {})),
                "scim_duplicate_group_resource_count": duplicate_group_resource_count,
            },
            sort_keys=True,
        )
    )


def event_latency(state, start_ns, end_ns, resource_name, collection, method):
    matches = [
        item
        for item in state.get("requests", [])
        if item.get("collection") == collection
        and item.get("method") == method
        and item.get("observed_at_monotonic_ns", 0) >= start_ns
        and item.get("observed_at_monotonic_ns", 0) <= end_ns
    ]
    if collection == "groups":
        matches = [item for item in matches if item.get("resource", {}).get("displayName") == resource_name]
    else:
        matches = [item for item in matches if item.get("resource", {}).get("userName") == resource_name]
    if not matches:
        raise RuntimeError(f"SCIM fixture did not record the expected {method} for {collection}")
    observed = min(item["observed_at_monotonic_ns"] for item in matches)
    return round(max(0, observed - start_ns) / 1_000_000_000, 3)


if __name__ == "__main__":
    USER_PASSWORD = ""
    main()
