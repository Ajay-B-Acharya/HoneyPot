"""End-to-end software integration test suite for IoT Honeypot Monitor.

Tests the full request lifecycle from ingestion, detection evaluation,
database persistence, filtering, statistics aggregation, API contract
compatibility, and failure recovery.
"""

from datetime import datetime, timezone, timedelta
import pytest


# =============================================================================
# 1. NORMAL REQUEST FLOW
# =============================================================================

class TestNormalRequestFlow:
    """Verifies that legitimate requests to allowed endpoints are handled cleanly."""

    def test_normal_request_flow(self, harness):
        """Submit a request log for an allowed endpoint (/status).

        Verify:
        - The request log is persisted.
        - No unknown-endpoint event is generated.
        - The request can be retrieved through GET /api/logs.
        - Statistics reflect the new request.
        """
        # 1. Submit normal request log to /status
        res = harness.submit_log(
            endpoint="/status",
            method="GET",
            device_id="rw612-e2e-node1",
            source_ip="10.0.0.50",
            response_code=200,
            classification="normal",
        )
        assert res.status_code == 201
        created_log = res.json()
        assert created_log["id"] is not None
        assert created_log["endpoint"] == "/status"
        assert created_log["classification"] == "normal"
        assert created_log["device_id"] == "rw612-e2e-node1"

        # 2. Verify no security events were created
        events_res = harness.get_events()
        assert events_res.status_code == 200
        assert events_res.json()["total"] == 0
        assert events_res.json()["items"] == []

        # 3. Verify request can be retrieved via GET /api/logs
        logs_res = harness.get_logs(device_id="rw612-e2e-node1")
        assert logs_res.status_code == 200
        logs_data = logs_res.json()
        assert logs_data["total"] == 1
        assert logs_data["items"][0]["id"] == created_log["id"]
        assert logs_data["items"][0]["endpoint"] == "/status"
        assert logs_data["items"][0]["source_ip"] == "10.0.0.50"

        # 4. Verify statistics reflect the new request
        stats = harness.get_stats()
        assert stats["total_requests"] == 1
        assert stats["normal_requests"] == 1
        assert stats["unusual_requests"] == 0
        assert stats["suspicious_requests"] == 0
        assert stats["total_security_events"] == 0
        assert stats["requests_by_classification"]["normal"] == 1


# =============================================================================
# 2. UNKNOWN-ENDPOINT FLOW
# =============================================================================

class TestUnknownEndpointFlow:
    """Verifies reconnaissance detection when probing unexposed endpoints."""

    def test_unknown_endpoint_flow(self, harness):
        """Submit a request log for /admin.

        Verify:
        - The request log is persisted.
        - An unknown_endpoint event is generated.
        - The event is stored in the database.
        - GET /api/events returns the event.
        - GET /api/stats reflects the generated event.
        """
        # 1. Submit request log for /admin
        log_res = harness.submit_log(
            endpoint="/admin",
            method="GET",
            device_id="rw612-e2e-node2",
            source_ip="198.51.100.22",
            response_code=404,
            classification="normal",
        )
        assert log_res.status_code == 201
        created_log = log_res.json()
        assert created_log["endpoint"] == "/admin"

        # 2. Verify an unknown_endpoint event was generated and stored in DB
        events_res = harness.get_events(event_type="unknown_endpoint")
        assert events_res.status_code == 200
        events_data = events_res.json()
        assert events_data["total"] == 1
        assert len(events_data["items"]) == 1

        event = events_data["items"][0]
        assert event["event_type"] == "unknown_endpoint"
        assert event["severity"] == "warning"
        assert event["device_id"] == "rw612-e2e-node2"
        assert event["source_ip"] == "198.51.100.22"
        assert event["metadata"]["endpoint"] == "/admin"
        assert event["metadata"]["normalized_endpoint"] == "/admin"
        assert event["metadata"]["method"] == "GET"

        # 3. Verify request log is also retrievable
        logs_res = harness.get_logs(device_id="rw612-e2e-node2")
        assert logs_res.json()["total"] == 1

        # 4. Verify statistics reflect both the request and the event
        stats = harness.get_stats()
        assert stats["total_requests"] == 1
        assert stats["total_security_events"] == 1
        assert stats["events_by_severity"]["warning"] == 1
        assert stats["events_by_severity"]["critical"] == 0
        assert stats["events_by_severity"]["informational"] == 0


# =============================================================================
# 3. REQUEST-RATE FLOW
# =============================================================================

class TestRequestRateFlow:
    """Verifies volumetric flood detection using test-configured thresholds."""

    def test_request_rate_flow_with_custom_threshold(self, harness):
        """Configure a small request threshold specifically for the test.

        Submit enough requests to exceed that threshold.
        Verify:
        - The correct high_request_rate event is generated.
        - The event contains the expected count and time window.
        - Cooldown prevents duplicate alert floods.
        """
        # Configure small test threshold: 4 requests in 10s, 10s cooldown
        harness.configure_detection(
            rate_threshold=4,
            rate_window=10,
            rate_cooldown=10,
        )

        test_ip = "203.0.113.88"
        base_time = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

        # 1. Submit 3 requests (below threshold of 4)
        for i in range(3):
            t = base_time + timedelta(milliseconds=i * 200)
            res = harness.submit_log(
                endpoint="/status",
                source_ip=test_ip,
                timestamp=t,
            )
            assert res.status_code == 201

        # Verify no rate alert yet
        events_res = harness.get_events(event_type="high_request_rate")
        assert events_res.json()["total"] == 0

        # 2. Submit 4th request (crossing the threshold)
        t4 = base_time + timedelta(milliseconds=600)
        res4 = harness.submit_log(
            endpoint="/status",
            source_ip=test_ip,
            timestamp=t4,
        )
        assert res4.status_code == 201

        # Verify high_request_rate event is generated
        events_res = harness.get_events(event_type="high_request_rate")
        assert events_res.status_code == 200
        data = events_res.json()
        assert data["total"] == 1
        event = data["items"][0]
        assert event["event_type"] == "high_request_rate"
        assert event["severity"] == "warning"
        assert event["request_count"] == 4
        assert event["time_window_seconds"] == 10
        assert event["source_ip"] == test_ip
        assert event["metadata"]["threshold"] == 4

        # 3. Submit 5th and 6th requests immediately (cooldown active)
        for i in range(2):
            t_subsequent = base_time + timedelta(milliseconds=800 + i * 200)
            res_sub = harness.submit_log(
                endpoint="/status",
                source_ip=test_ip,
                timestamp=t_subsequent,
            )
            assert res_sub.status_code == 201

        # Verify cooldown prevented alert flood (still only 1 event)
        events_res_after = harness.get_events(event_type="high_request_rate")
        assert events_res_after.json()["total"] == 1


# =============================================================================
# 4. REPEATED-REQUEST FLOW
# =============================================================================

class TestRepeatedRequestFlow:
    """Verifies repeated request detection and endpoint grouping."""

    def test_repeated_request_flow_and_distinct_endpoints(self, harness):
        """Submit repeated requests to the same endpoint from the same source.

        Verify that the configured rule triggers the expected event.
        Also verify that requests to different endpoints are handled correctly.
        """
        # Configure small test threshold: 3 repeated requests in 10s, 10s cooldown
        harness.configure_detection(
            repeated_threshold=3,
            repeated_window=10,
            repeated_cooldown=10,
        )

        test_ip = "192.168.1.180"
        base_time = datetime(2026, 10, 21, 15, 0, 0, tzinfo=timezone.utc)

        # 1. Send 2 requests to /status and 2 requests to /info
        # Neither endpoint has reached threshold 3 yet
        for i in range(2):
            t1 = base_time + timedelta(milliseconds=i * 200)
            harness.submit_log(endpoint="/status", source_ip=test_ip, timestamp=t1)
            t2 = base_time + timedelta(milliseconds=i * 200 + 100)
            harness.submit_log(endpoint="/info", source_ip=test_ip, timestamp=t2)

        # Verify no repeated_requests alert fired
        events_res = harness.get_events(event_type="repeated_requests")
        assert events_res.json()["total"] == 0

        # 2. Send 3rd request to /status (crosses threshold for /status only)
        t_status_3 = base_time + timedelta(milliseconds=500)
        harness.submit_log(endpoint="/status", source_ip=test_ip, timestamp=t_status_3)

        # Verify repeated_requests event triggered for /status
        events_res = harness.get_events(event_type="repeated_requests")
        data = events_res.json()
        assert data["total"] == 1
        event = data["items"][0]
        assert event["event_type"] == "repeated_requests"
        assert event["request_count"] == 3
        assert event["metadata"]["normalized_endpoint"] == "/status"

        # 3. Verify cooldown: send 4th request to /status
        t_status_4 = base_time + timedelta(milliseconds=700)
        harness.submit_log(endpoint="/status", source_ip=test_ip, timestamp=t_status_4)
        assert harness.get_events(event_type="repeated_requests").json()["total"] == 1


# =============================================================================
# 5. DATABASE CONSISTENCY
# =============================================================================

class TestDatabaseConsistency:
    """Verifies relational integrity, aggregation accuracy, and atomic rollbacks."""

    def test_database_consistency_and_stats_agreement(self, harness):
        """Verify:
        - Logs and events persist correctly.
        - Generated events can be retrieved.
        - Statistics agree with stored records.
        """
        # Create a mixture of normal and suspicious logs + unknown endpoints
        harness.submit_log(endpoint="/status", classification="normal")
        harness.submit_log(endpoint="/status", classification="normal")
        harness.submit_log(endpoint="/info", classification="unusual")
        # /admin generates unknown_endpoint event
        harness.submit_log(endpoint="/admin", classification="suspicious")

        # Manually create one critical event
        harness.submit_event(
            event_type="tamper_detected",
            severity="critical",
            description="Hardware chassis opened",
        )

        # Fetch all logs and events
        logs_res = harness.get_logs(limit=100)
        events_res = harness.get_events(limit=100)
        stats = harness.get_stats()

        logs_items = logs_res.json()["items"]
        events_items = events_res.json()["items"]

        # Assert total counts agree
        assert len(logs_items) == stats["total_requests"] == 4
        assert len(events_items) == stats["total_security_events"] == 2

        # Assert classification breakdowns match exactly
        normal_count = sum(1 for l in logs_items if l["classification"] == "normal")
        unusual_count = sum(1 for l in logs_items if l["classification"] == "unusual")
        suspicious_count = sum(1 for l in logs_items if l["classification"] == "suspicious")

        assert stats["normal_requests"] == normal_count == 2
        assert stats["unusual_requests"] == unusual_count == 1
        assert stats["suspicious_requests"] == suspicious_count == 1
        assert stats["requests_by_classification"] == {
            "normal": 2,
            "unusual": 1,
            "suspicious": 1,
        }

        # Assert severity breakdowns match exactly
        warn_count = sum(1 for e in events_items if e["severity"] == "warning")
        crit_count = sum(1 for e in events_items if e["severity"] == "critical")
        info_count = sum(1 for e in events_items if e["severity"] == "informational")

        assert stats["events_by_severity"]["warning"] == warn_count == 1
        assert stats["events_by_severity"]["critical"] == crit_count == 1
        assert stats["events_by_severity"]["informational"] == info_count == 0

    def test_failed_operations_do_not_leave_inconsistent_records(self, harness, client):
        """Failed operations do not leave partial or orphaned records."""
        # Baseline check
        initial_stats = harness.get_stats()
        assert initial_stats["total_requests"] == 0
        assert initial_stats["total_security_events"] == 0

        # Attempt to insert various invalid payloads
        client.post("/api/logs", json={"endpoint": "/status"})  # missing required fields
        client.post("/api/logs", json={"invalid": "payload"})
        client.post("/api/events", json={"invalid": "payload"})

        # Verify nothing was persisted
        logs_res = harness.get_logs()
        events_res = harness.get_events()
        stats = harness.get_stats()

        assert logs_res.json()["total"] == 0
        assert events_res.json()["total"] == 0
        assert stats["total_requests"] == 0
        assert stats["total_security_events"] == 0


# =============================================================================
# 6. API COMPATIBILITY
# =============================================================================

class TestApiCompatibility:
    """Verifies that all endpoint contracts remain strictly intact for the frontend."""

    def test_health_endpoint_contract(self, harness):
        """GET /api/health schema compatibility."""
        res = harness.client.get("/api/health")
        assert res.status_code == 200
        data = res.json()
        assert set(data.keys()) == {"status", "service"}
        assert data["status"] == "ok"
        assert isinstance(data["service"], str)

    def test_logs_endpoint_contract(self, harness):
        """POST /api/logs and GET /api/logs schema compatibility."""
        post_res = harness.submit_log(endpoint="/status")
        assert post_res.status_code == 201
        log_keys = {
            "id", "timestamp", "device_id", "source_ip",
            "method", "endpoint", "response_code", "classification",
            "created_at",
        }
        assert set(post_res.json().keys()) == log_keys

        get_res = harness.get_logs()
        assert get_res.status_code == 200
        envelope_keys = {"items", "total", "skip", "limit"}
        assert set(get_res.json().keys()) == envelope_keys
        assert set(get_res.json()["items"][0].keys()) == log_keys

    def test_events_endpoint_contract(self, harness):
        """POST /api/events and GET /api/events schema compatibility."""
        post_res = harness.submit_event(
            event_type="test_alert",
            severity="warning",
            description="Compatibility check",
        )
        assert post_res.status_code == 201
        event_keys = {
            "id", "timestamp", "device_id", "event_type",
            "severity", "description", "source_ip", "request_count",
            "time_window_seconds", "metadata", "created_at",
        }
        assert set(post_res.json().keys()) == event_keys

        get_res = harness.get_events()
        assert get_res.status_code == 200
        assert set(get_res.json().keys()) == {"items", "total", "skip", "limit"}
        assert set(get_res.json()["items"][0].keys()) == event_keys

    def test_stats_endpoint_contract(self, harness):
        """GET /api/stats schema compatibility."""
        stats = harness.get_stats()
        expected_keys = {
            "total_requests",
            "normal_requests",
            "unusual_requests",
            "suspicious_requests",
            "total_security_events",
            "events_by_severity",
            "requests_by_classification",
        }
        assert set(stats.keys()) == expected_keys
        assert set(stats["events_by_severity"].keys()) == {
            "informational", "warning", "critical"
        }
        assert set(stats["requests_by_classification"].keys()) == {
            "normal", "unusual", "suspicious"
        }

    def test_device_status_endpoint_contract(self, harness):
        """GET /api/device/status schema compatibility."""
        # When empty
        status_empty = harness.get_device_status()
        assert "devices" in status_empty
        assert isinstance(status_empty["devices"], list)

        # After logging device activity
        harness.submit_log(device_id="rw612-active-01")
        status_data = harness.get_device_status()
        assert len(status_data["devices"]) >= 1
        dev = status_data["devices"][0]
        assert set(dev.keys()) == {"device_id", "status", "last_seen", "last_activity"}
        assert dev["status"] in ("active", "inactive", "unknown")


# =============================================================================
# 7. FAILURE CASES
# =============================================================================

class TestFailureCases:
    """Verifies that invalid payloads, classifications, and parameters fail safely."""

    def test_invalid_log_payloads_return_422(self, client):
        """Missing required fields or invalid types fail with HTTP 422."""
        # Empty body
        assert client.post("/api/logs", json={}).status_code == 422

        # Missing endpoint
        assert client.post("/api/logs", json={
            "timestamp": "2026-10-21T10:00:00Z",
            "device_id": "rw612-01",
            "method": "GET",
        }).status_code == 422

        # Invalid classification
        assert client.post("/api/logs", json={
            "timestamp": "2026-10-21T10:00:00Z",
            "device_id": "rw612-01",
            "method": "GET",
            "endpoint": "/status",
            "classification": "unknown_classification",
        }).status_code == 422

        # Invalid response code (< 100 or > 599)
        assert client.post("/api/logs", json={
            "timestamp": "2026-10-21T10:00:00Z",
            "device_id": "rw612-01",
            "method": "GET",
            "endpoint": "/status",
            "response_code": 99,
        }).status_code == 422

        assert client.post("/api/logs", json={
            "timestamp": "2026-10-21T10:00:00Z",
            "device_id": "rw612-01",
            "method": "GET",
            "endpoint": "/status",
            "response_code": 600,
        }).status_code == 422

    def test_invalid_event_payloads_return_422(self, client):
        """Invalid severity or missing required event fields fail with HTTP 422."""
        assert client.post("/api/events", json={
            "timestamp": "2026-10-21T10:00:00Z",
            "device_id": "rw612-01",
            "event_type": "alert",
            "severity": "extreme_danger",  # invalid severity enum
            "description": "test",
        }).status_code == 422

        assert client.post("/api/events", json={
            "timestamp": "2026-10-21T10:00:00Z",
            "device_id": "rw612-01",
            "event_type": "alert",
            "severity": "warning",
            "request_count": -1,  # negative count rejected
            "description": "test",
        }).status_code == 422

    def test_invalid_query_parameters_return_400_or_422(self, client):
        """Query parameter range errors and validation."""
        # start_time > end_time returns 400
        res_logs = client.get(
            "/api/logs?start_time=2026-10-21T14:00:00Z&end_time=2026-10-21T10:00:00Z"
        )
        assert res_logs.status_code == 400
        assert res_logs.json()["detail"] == "start_time must be before end_time"

        res_events = client.get(
            "/api/events?start_time=2026-10-21T14:00:00Z&end_time=2026-10-21T10:00:00Z"
        )
        assert res_events.status_code == 400
        assert res_events.json()["detail"] == "start_time must be before end_time"

        # Negative skip or limit > 100 returns 422
        assert client.get("/api/logs?skip=-1").status_code == 422
        assert client.get("/api/logs?limit=101").status_code == 422
        assert client.get("/api/events?skip=-5").status_code == 422
        assert client.get("/api/events?limit=200").status_code == 422
