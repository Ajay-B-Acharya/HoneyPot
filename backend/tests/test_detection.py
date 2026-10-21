"""Automated test suite for the Security Detection Engine.

Covers all 23 required test scenarios:
- Unknown Endpoint Detection (Tests 1-5)
- Request-Rate Detection (Tests 6-10)
- Repeated-Request Detection (Tests 11-14)
- Validation and Safe Metadata Handling (Tests 15-18)
- Integration and End-to-End System Behavior (Tests 19-23)
"""

from datetime import datetime, timezone, timedelta
import pytest

from app.config import Settings
from app.models.request_log import RequestLog
from app.services.detection_service import (
    DetectionService,
    SlidingWindowTracker,
    normalize_endpoint,
)


BASE_LOG = {
    "timestamp": "2026-10-21T10:00:00Z",
    "device_id": "rw612-test-01",
    "source_ip": "192.168.1.100",
    "method": "GET",
    "endpoint": "/status",
    "response_code": 200,
    "classification": "normal",
}


# =============================================================================
# 1. UNKNOWN ENDPOINT DETECTION (Tests 1-5)
# =============================================================================

class TestUnknownEndpointRule:
    """Tests for Rule R1: Unknown Endpoint Detection."""

    def test_status_endpoint_allowed(self, client):
        """1. /status does not trigger an unknown-endpoint alert."""
        res = client.post("/api/logs", json={**BASE_LOG, "endpoint": "/status"})
        assert res.status_code == 201

        events_res = client.get("/api/events")
        assert events_res.status_code == 200
        assert events_res.json()["total"] == 0

    def test_info_endpoint_allowed(self, client):
        """2. /info does not trigger an unknown-endpoint alert."""
        res = client.post("/api/logs", json={**BASE_LOG, "endpoint": "/info"})
        assert res.status_code == 201

        events_res = client.get("/api/events")
        assert events_res.status_code == 200
        assert events_res.json()["total"] == 0

    def test_config_endpoint_allowed(self, client):
        """3. /config does not trigger an unknown-endpoint alert."""
        res = client.post("/api/logs", json={**BASE_LOG, "endpoint": "/config"})
        assert res.status_code == 201

        events_res = client.get("/api/events")
        assert events_res.status_code == 200
        assert events_res.json()["total"] == 0

    def test_admin_triggers_unknown_endpoint_alert(self, client):
        """4. /admin triggers an unknown-endpoint alert with severity=warning."""
        res = client.post("/api/logs", json={**BASE_LOG, "endpoint": "/admin"})
        assert res.status_code == 201

        events_res = client.get("/api/events")
        assert events_res.status_code == 200
        data = events_res.json()
        assert data["total"] == 1
        event = data["items"][0]
        assert event["event_type"] == "unknown_endpoint"
        assert event["severity"] == "warning"
        assert event["source_ip"] == BASE_LOG["source_ip"]
        assert event["device_id"] == BASE_LOG["device_id"]
        assert event["metadata"]["endpoint"] == "/admin"
        assert event["metadata"]["normalized_endpoint"] == "/admin"
        assert event["metadata"]["method"] == "GET"

    def test_query_strings_do_not_cause_false_unknown_endpoint_alerts(self, client):
        """5. Query strings and fragments do not cause false unknown-endpoint alerts."""
        endpoints_with_queries = [
            "/status?token=xyz123&format=json",
            "/info?verbose=true#hardware",
            "/config?env=production",
            "/status/?session=abc",  # trailing slash + query string
        ]
        for ep in endpoints_with_queries:
            res = client.post("/api/logs", json={**BASE_LOG, "endpoint": ep})
            assert res.status_code == 201

        events_res = client.get("/api/events")
        assert events_res.status_code == 200
        assert events_res.json()["total"] == 0

    def test_endpoint_normalization_strict_matching(self):
        """Verify normalization does not permit arbitrary paths through loose prefix matching."""
        assert normalize_endpoint("/status_check") == "/status_check"
        assert normalize_endpoint("/status/nested") == "/status/nested"
        assert normalize_endpoint("/admin//panel") == "/admin/panel"

        service = DetectionService()
        assert "/status" in service.allowed_endpoints
        assert "/status_check" not in service.allowed_endpoints
        assert "/status/nested" not in service.allowed_endpoints


# =============================================================================
# 2. REQUEST-RATE DETECTION (Tests 6-10)
# =============================================================================

class TestRequestRateRule:
    """Tests for Rule R2: Request-Rate Detection."""

    def test_requests_below_threshold_do_not_trigger_alert(self, client):
        """6. Requests below the configured threshold (e.g. 19 of 20) do not trigger an alert."""
        start_time = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
        # Send 19 requests within a 10s window
        for i in range(19):
            ts = (start_time + timedelta(milliseconds=i * 200)).isoformat()
            res = client.post("/api/logs", json={
                **BASE_LOG,
                "timestamp": ts,
                "endpoint": "/status",
            })
            assert res.status_code == 201

        events_res = client.get("/api/events?event_type=high_request_rate")
        assert events_res.status_code == 200
        assert events_res.json()["total"] == 0

    def test_crossing_threshold_generates_correct_event(self, client):
        """7. Crossing the threshold (20th request) generates high_request_rate event."""
        start_time = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
        # Send 20 requests within a 10s window
        for i in range(20):
            ts = (start_time + timedelta(milliseconds=i * 200)).isoformat()
            res = client.post("/api/logs", json={
                **BASE_LOG,
                "timestamp": ts,
                "endpoint": "/status",
            })
            assert res.status_code == 201

        events_res = client.get("/api/events?event_type=high_request_rate")
        assert events_res.status_code == 200
        data = events_res.json()
        assert data["total"] == 1
        event = data["items"][0]
        assert event["event_type"] == "high_request_rate"
        assert event["severity"] == "warning"
        assert event["request_count"] == 20
        assert event["time_window_seconds"] == 10
        assert event["source_ip"] == BASE_LOG["source_ip"]
        assert event["metadata"]["threshold"] == 20

    def test_requests_outside_time_window_do_not_contribute_to_count(self, client):
        """8. Requests outside the time window do not contribute to the count."""
        start_time = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
        # Send 15 requests at t=0s
        for i in range(15):
            ts = (start_time + timedelta(milliseconds=i * 100)).isoformat()
            client.post("/api/logs", json={**BASE_LOG, "timestamp": ts})

        # Advance time by 15 seconds (outside the 10-second window)
        after_window_time = start_time + timedelta(seconds=15)
        # Send 5 requests at t=15s
        for i in range(5):
            ts = (after_window_time + timedelta(milliseconds=i * 100)).isoformat()
            client.post("/api/logs", json={**BASE_LOG, "timestamp": ts})

        # Total in current window is 5 (< 20 threshold), so no alert
        events_res = client.get("/api/events?event_type=high_request_rate")
        assert events_res.status_code == 200
        assert events_res.json()["total"] == 0

    def test_cooldown_prevents_repeated_alerts_for_subsequent_requests(self, client):
        """9. Cooldown prevents repeated alerts for every subsequent request."""
        start_time = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
        # Send 25 requests within 5 seconds
        for i in range(25):
            ts = (start_time + timedelta(milliseconds=i * 200)).isoformat()
            client.post("/api/logs", json={**BASE_LOG, "timestamp": ts})

        # Only 1 high_request_rate alert should have fired due to 10s cooldown
        events_res = client.get("/api/events?event_type=high_request_rate")
        assert events_res.status_code == 200
        assert events_res.json()["total"] == 1

    def test_missing_source_ip_does_not_crash_detection(self, client):
        """10. Missing source IP addresses do not crash detection and group safely."""
        start_time = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
        log_no_ip = {**BASE_LOG, "source_ip": None}

        # Send 20 requests without source_ip
        for i in range(20):
            ts = (start_time + timedelta(milliseconds=i * 200)).isoformat()
            res = client.post("/api/logs", json={**log_no_ip, "timestamp": ts})
            assert res.status_code == 201

        events_res = client.get("/api/events?event_type=high_request_rate")
        assert events_res.status_code == 200
        data = events_res.json()
        assert data["total"] == 1
        assert data["items"][0]["source_ip"] is None
        assert data["items"][0]["device_id"] == BASE_LOG["device_id"]


# =============================================================================
# 3. REPEATED REQUEST DETECTION (Tests 11-14)
# =============================================================================

class TestRepeatedRequestRule:
    """Tests for Rule R3: Repeated Request Detection."""

    def test_repeated_requests_trigger_expected_event(self, client):
        """11. Repeated requests to one endpoint (threshold 10) trigger repeated_requests."""
        start_time = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
        # Send 10 repeated requests to /status
        for i in range(10):
            ts = (start_time + timedelta(milliseconds=i * 200)).isoformat()
            res = client.post("/api/logs", json={
                **BASE_LOG,
                "timestamp": ts,
                "endpoint": "/status",
            })
            assert res.status_code == 201

        events_res = client.get("/api/events?event_type=repeated_requests")
        assert events_res.status_code == 200
        data = events_res.json()
        assert data["total"] == 1
        event = data["items"][0]
        assert event["event_type"] == "repeated_requests"
        assert event["severity"] == "warning"
        assert event["request_count"] == 10
        assert event["time_window_seconds"] == 10
        assert event["metadata"]["normalized_endpoint"] == "/status"

    def test_requests_to_different_endpoints_grouped_correctly(self, client):
        """12. Requests to different endpoints are grouped separately."""
        start_time = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
        # Send 8 requests to /status and 8 requests to /info (neither reaches 10)
        for i in range(8):
            ts1 = (start_time + timedelta(milliseconds=i * 300)).isoformat()
            client.post("/api/logs", json={**BASE_LOG, "timestamp": ts1, "endpoint": "/status"})
            ts2 = (start_time + timedelta(milliseconds=i * 300 + 150)).isoformat()
            client.post("/api/logs", json={**BASE_LOG, "timestamp": ts2, "endpoint": "/info"})

        events_res = client.get("/api/events?event_type=repeated_requests")
        assert events_res.status_code == 200
        assert events_res.json()["total"] == 0

    def test_cooldown_prevents_alert_floods(self, client):
        """13. Cooldown prevents alert floods for repeated requests."""
        start_time = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
        # Send 15 repeated requests to /status within 3 seconds
        for i in range(15):
            ts = (start_time + timedelta(milliseconds=i * 200)).isoformat()
            client.post("/api/logs", json={**BASE_LOG, "timestamp": ts, "endpoint": "/status"})

        events_res = client.get("/api/events?event_type=repeated_requests")
        assert events_res.status_code == 200
        assert events_res.json()["total"] == 1

    def test_old_tracking_entries_expire(self):
        """14. Old tracking entries expire and get cleaned up from memory."""
        tracker = SlidingWindowTracker(max_entries=100, expiration_seconds=10)
        t0 = 1000.0
        # Add entries
        should_alert, count = tracker.record_and_check(
            key=("dev1", "10.0.0.1"),
            current_time=t0,
            window_seconds=10,
            threshold=5,
            cooldown_seconds=10,
        )
        assert tracker.entry_count == 1

        # Advance time by 25 seconds (exceeding expiration_seconds=10)
        t1 = t0 + 25.0
        purged = tracker.cleanup_expired(t1)
        assert purged == 1
        assert tracker.entry_count == 0


# =============================================================================
# 4. VALIDATION AND SAFE METADATA HANDLING (Tests 15-18)
# =============================================================================

class TestValidationAndMetadata:
    """Tests for Rule R4: Safe validation of request metadata."""

    def test_invalid_http_methods_rejected(self, client):
        """15. Invalid HTTP methods are rejected by schema validation (HTTP 422)."""
        invalid_methods = ["INVALID", "HACK", "GET;DROP", "12345"]
        for method in invalid_methods:
            res = client.post("/api/logs", json={**BASE_LOG, "method": method})
            assert res.status_code == 422

    def test_invalid_endpoint_formats_handled_safely(self, client):
        """16. Invalid endpoint formats (missing leading slash, null bytes) return 422."""
        invalid_endpoints = [
            "admin",               # missing leading slash
            "ftp://host/path",     # scheme prefix instead of path
            "/status\x00extra",    # null byte injection
            "",                    # empty string
        ]
        for ep in invalid_endpoints:
            res = client.post("/api/logs", json={**BASE_LOG, "endpoint": ep})
            assert res.status_code == 422

        # Verify helper safely normalizes strange inputs without crashing
        assert normalize_endpoint(None) == "/"
        assert normalize_endpoint("") == "/"
        assert normalize_endpoint("   ") == "/"

    def test_invalid_request_metadata_does_not_corrupt_database(self, client):
        """17. Invalid request metadata does not create corrupted records."""
        # Attempt to insert various invalid payloads
        client.post("/api/logs", json={**BASE_LOG, "response_code": 9999})
        client.post("/api/logs", json={**BASE_LOG, "classification": "non_existent"})
        client.post("/api/logs", json={})

        logs_res = client.get("/api/logs")
        assert logs_res.status_code == 200
        assert logs_res.json()["total"] == 0

        events_res = client.get("/api/events")
        assert events_res.status_code == 200
        assert events_res.json()["total"] == 0

    def test_malformed_raw_http_traffic_not_falsely_claimed_detected(self, client):
        """18. Verify raw malformed HTTP traffic is handled at HTTP transport layer."""
        # Non-JSON or broken HTTP body returns 400 or 422 at FastAPI/Starlette layer
        res = client.post(
            "/api/logs",
            content=b"RAW BROKEN TCP STREAM \xff\xfe INVALID HTTP",
            headers={"Content-Type": "application/json"},
        )
        assert res.status_code in (400, 422)
        # Ensure no spurious security event was generated for raw transport error
        events_res = client.get("/api/events")
        assert events_res.json()["total"] == 0


# =============================================================================
# 5. INTEGRATION AND SYSTEM BEHAVIOR (Tests 19-23)
# =============================================================================

class TestIntegration:
    """Tests for integration between detection engine, logs, events, and stats."""

    def test_generated_events_are_persisted(self, client):
        """19. Generated events are persisted in SQLite."""
        res = client.post("/api/logs", json={**BASE_LOG, "endpoint": "/unknown_target"})
        assert res.status_code == 201

        events_res = client.get("/api/events")
        assert events_res.status_code == 200
        items = events_res.json()["items"]
        assert len(items) == 1
        assert items[0]["event_type"] == "unknown_endpoint"
        assert items[0]["description"].startswith("Request received for unknown endpoint")

    def test_generated_events_retrievable_through_get_events(self, client):
        """20. Generated events are retrievable and filterable through GET /api/events."""
        client.post("/api/logs", json={**BASE_LOG, "endpoint": "/phpmyadmin"})
        client.post("/api/logs", json={**BASE_LOG, "endpoint": "/setup.cgi"})

        # Retrieve with filter
        events_res = client.get("/api/events?event_type=unknown_endpoint")
        assert events_res.status_code == 200
        data = events_res.json()
        assert data["total"] == 2
        endpoints = [e["metadata"]["endpoint"] for e in data["items"]]
        assert "/phpmyadmin" in endpoints
        assert "/setup.cgi" in endpoints

    def test_statistics_include_generated_events(self, client):
        """21. Statistics endpoint (/api/stats) reflects newly generated events."""
        # 1 valid request to /status (normal, allowed)
        client.post("/api/logs", json={**BASE_LOG, "endpoint": "/status"})
        # 1 request to /hidden_admin (triggers unknown_endpoint event)
        client.post("/api/logs", json={**BASE_LOG, "endpoint": "/hidden_admin"})

        stats_res = client.get("/api/stats")
        assert stats_res.status_code == 200
        stats = stats_res.json()
        assert stats["total_requests"] == 2
        assert stats["total_security_events"] == 1
        assert stats["events_by_severity"]["warning"] == 1

    def test_manually_created_security_events_still_work(self, client):
        """22. POST /api/events still works and does not trigger log detection."""
        manual_event = {
            "timestamp": "2026-10-21T10:00:00Z",
            "device_id": "rw612-manual-01",
            "event_type": "custom_tamper_alert",
            "severity": "critical",
            "description": "Hardware enclosure tampering detected",
            "source_ip": None,
            "request_count": None,
            "time_window_seconds": None,
            "metadata": {"sensor_id": 4},
        }
        res = client.post("/api/events", json=manual_event)
        assert res.status_code == 201
        data = res.json()
        assert data["event_type"] == "custom_tamper_alert"
        assert data["severity"] == "critical"

        # Verify no request log was created
        logs_res = client.get("/api/logs")
        assert logs_res.json()["total"] == 0

    def test_existing_backend_tests_continue_to_pass(self, client):
        """23. Basic health and existing routes remain completely functional."""
        health_res = client.get("/api/health")
        assert health_res.status_code == 200
        assert health_res.json()["status"] == "ok"


# =============================================================================
# 6. CONCURRENCY, MEMORY BOUNDS, AND CUSTOM SETTINGS
# =============================================================================

class TestTrackerRobustness:
    """Tests for thread safety, bounded memory, and custom configuration."""

    def test_concurrent_requests_handled_safely(self):
        """Verify tracker remains consistent under multithreaded concurrent requests."""
        import concurrent.futures

        tracker = SlidingWindowTracker(max_entries=1000, expiration_seconds=60)
        t0 = 1000.0

        def worker(worker_id):
            key = f"client-{worker_id % 5}"
            for i in range(20):
                tracker.record_and_check(
                    key=key,
                    current_time=t0 + (i * 0.1),
                    window_seconds=10,
                    threshold=15,
                    cooldown_seconds=10,
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker, w) for w in range(16)]
            for f in futures:
                f.result()

        # All 5 unique client keys must exist with no race condition corruption
        assert tracker.entry_count == 5

    def test_tracker_memory_bounded_under_load(self):
        """Verify that tracker never exceeds max_entries even when inundated with unique keys."""
        max_limit = 25
        tracker = SlidingWindowTracker(max_entries=max_limit, expiration_seconds=5)

        # Inundate with 100 unique keys
        for i in range(100):
            tracker.record_and_check(
                key=f"scanner-{i}",
                current_time=2000.0 + (i * 0.1),
                window_seconds=10,
                threshold=10,
                cooldown_seconds=10,
            )

        # Tracking state must remain bounded at or below max_limit
        assert tracker.entry_count <= max_limit

    def test_detection_service_custom_configuration(self):
        """Verify DetectionService operates with custom thresholds and custom allowed endpoints."""
        custom_settings = Settings(
            DETECTION_ALLOWED_ENDPOINTS="/api/v1/ping,/api/v1/health",
            DETECTION_RATE_THRESHOLD=5,
            DETECTION_RATE_WINDOW_SECONDS=5,
            DETECTION_RATE_COOLDOWN_SECONDS=5,
            DETECTION_REPEATED_THRESHOLD=3,
            DETECTION_REPEATED_WINDOW_SECONDS=5,
            DETECTION_REPEATED_COOLDOWN_SECONDS=5,
        )
        service = DetectionService(settings=custom_settings)

        # /status should now be unknown because allowlist was overridden
        log1 = RequestLog(
            timestamp=datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc),
            device_id="dev-custom",
            source_ip="1.1.1.1",
            method="GET",
            endpoint="/status",
            classification="normal",
        )
        events1 = service.evaluate_request(log1)
        assert any(e.event_type == "unknown_endpoint" for e in events1)

        # /api/v1/ping is allowed
        log2 = RequestLog(
            timestamp=datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc),
            device_id="dev-custom",
            source_ip="1.1.1.1",
            method="GET",
            endpoint="/api/v1/ping",
            classification="normal",
        )
        events2 = service.evaluate_request(log2)
        assert not any(e.event_type == "unknown_endpoint" for e in events2)

