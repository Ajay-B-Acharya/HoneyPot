"""Tests for the statistics endpoint."""


VALID_LOG = {
    "timestamp": "2026-10-20T06:30:00Z",
    "device_id": "rw612-security-01",
    "method": "GET",
    "endpoint": "/status",
    "classification": "normal",
}

VALID_EVENT = {
    "timestamp": "2026-10-20T06:30:00Z",
    "device_id": "rw612-security-01",
    "event_type": "unknown_endpoint",
    "severity": "warning",
    "description": "Test event",
}


class TestStats:
    """Tests for GET /api/stats."""

    def test_stats_empty_database(self, client):
        """Test statistics when no data exists."""
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_requests"] == 0
        assert data["normal_requests"] == 0
        assert data["unusual_requests"] == 0
        assert data["suspicious_requests"] == 0
        assert data["total_security_events"] == 0
        assert data["events_by_severity"] == {
            "informational": 0,
            "warning": 0,
            "critical": 0,
        }
        assert data["requests_by_classification"] == {
            "normal": 0,
            "unusual": 0,
            "suspicious": 0,
        }

    def test_stats_with_logs(self, client):
        """Test statistics after creating request logs."""
        client.post("/api/logs", json={**VALID_LOG, "classification": "normal"})
        client.post("/api/logs", json={**VALID_LOG, "classification": "normal"})
        client.post("/api/logs", json={**VALID_LOG, "classification": "suspicious"})

        response = client.get("/api/stats")
        data = response.json()
        assert data["total_requests"] == 3
        assert data["normal_requests"] == 2
        assert data["suspicious_requests"] == 1
        assert data["unusual_requests"] == 0
        assert data["requests_by_classification"]["normal"] == 2
        assert data["requests_by_classification"]["suspicious"] == 1

    def test_stats_with_events(self, client):
        """Test statistics after creating security events."""
        client.post("/api/events", json={**VALID_EVENT, "severity": "warning"})
        client.post("/api/events", json={**VALID_EVENT, "severity": "critical"})
        client.post("/api/events", json={**VALID_EVENT, "severity": "informational"})
        client.post("/api/events", json={**VALID_EVENT, "severity": "critical"})

        response = client.get("/api/stats")
        data = response.json()
        assert data["total_security_events"] == 4
        assert data["events_by_severity"]["warning"] == 1
        assert data["events_by_severity"]["critical"] == 2
        assert data["events_by_severity"]["informational"] == 1

    def test_stats_response_structure(self, client):
        """Test that stats response has the expected structure."""
        response = client.get("/api/stats")
        data = response.json()
        expected_keys = {
            "total_requests",
            "normal_requests",
            "unusual_requests",
            "suspicious_requests",
            "total_security_events",
            "events_by_severity",
            "requests_by_classification",
        }
        assert set(data.keys()) == expected_keys
