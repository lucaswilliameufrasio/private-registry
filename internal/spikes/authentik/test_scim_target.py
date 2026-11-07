"""Regression tests for the local SCIM fixture's diagnostic evidence."""

import os
import json
import threading
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

os.environ.setdefault("PRIVATE_REGISTRY_SCIM_FIXTURE_TOKEN", "synthetic-test-token")
import scim_target


class RecordingTest(unittest.TestCase):
    def setUp(self):
        scim_target.STATE["requests"] = []

    def test_records_are_snapshots_with_actual_response_status(self):
        resource = {"members": [{"value": "initial"}]}
        request = {"Operations": [{"value": [{"value": "initial"}]}]}
        scim_target.Handler.record(None, "groups", "POST", "/scim/v2/Groups", resource, request, status=201)
        resource["members"].clear()
        request["Operations"][0]["value"].clear()
        recorded = scim_target.STATE["requests"][0]
        self.assertEqual(recorded["resource"]["members"], [{"value": "initial"}])
        self.assertEqual(recorded["request"]["Operations"][0]["value"], [{"value": "initial"}])
        self.assertEqual(recorded["status"], 201)

    def test_concurrent_creates_reject_duplicate_external_id(self):
        scim_target.STATE = {"requests": [], "users": {}, "groups": {}, "failure_mode": False}
        server = scim_target.ThreadingHTTPServer(("127.0.0.1", 0), scim_target.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        url = "http://127.0.0.1:%d/scim/v2/Groups" % server.server_port

        def create():
            request = urllib.request.Request(
                url,
                data=json.dumps({"externalId": "synthetic", "displayName": "Synthetic"}).encode(),
                headers={"Authorization": "Bearer " + scim_target.TOKEN, "Content-Type": "application/scim+json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=5) as result:
                    return result.status
            except urllib.error.HTTPError as err:
                try:
                    return err.code
                finally:
                    err.close()

        with patch.object(scim_target, "save_state"), ThreadPoolExecutor(max_workers=2) as executor:
            statuses = list(executor.map(lambda _: create(), range(2)))
        self.assertEqual(sorted(statuses), [201, 409])
        self.assertEqual(len(scim_target.STATE["groups"]), 1)
        self.assertEqual(sorted(item["status"] for item in scim_target.STATE["requests"]), [201, 409])


if __name__ == "__main__":
    unittest.main()
