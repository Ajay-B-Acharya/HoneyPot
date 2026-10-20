"""Tests for security event endpoints."""

import pytest


VALID_EVENT = {
    "timestamp": "2026-10-20T06:30:00Z",
    "device_id": "rw612-security-01",
    "event_type": "unknown_endpoint",
    "severity": "warning",
    "description": "Request received for an unknown endpoint",
    "source_ip": "192.168.1.25",
    "request_count": None,
    "time_window_seconds": None,
    "metadata": {"endpoint": "/admin", "method": "GET"},
}


class TestCreateEvent:
    """Tests for POST /api/events."""

    def test_create_event_success(self, client):
        """Test successful creation of a security event."""
        response = client.post("/api/events", json=VALID_EVENT)
        assert response.status_code == 201
        data = response.json()
        assert data["id"] is not None
        assert data["device_id"] == "rw612-security-01"
        assert data["event_type"] == "unknown_endpoint"
        assert data["severity"] == "warning"
        assert data["description"] == "Request received for an unknown endpoint"
        assert data["source_ip"] == "192.168.1.25"
        assert data["metadata"] == {"endpoint": "/admin", "method": "GET"}
        assert data["created_at"] is not None

    def test_create_event_minimal(self, client):
        """Test creating an event with only required fields."""
        event = {
            "timestamp": "2026-10-20T06:30:00Z",
            "device_id": "rw612-01",
            "event_type": "scan_detected",
            "severity": "informational",
            "description": "Port scan detected",
        }
        response = client.post("/api/events", json=event)
        assert response.status_code == 201
        data = response.json()
        assert data["source_ip"] is None
        assert data["request_count"] is None
        assert data["metadata"] is None

    def test_create_event_invalid_severity(self, client):
        """Test that invalid severity values are rejected."""
        event = {**VALID_EVENT, "severity": "extreme"}
        response = client.post("/api/events", json=event)
        assert response.status_code == 422

    def test_create_event_missing_required_fields(self, client):
        """Test that missing required fields return 422."""
        response = client.post("/api/events", json={})
        assert response.status_code == 422

    def test_create_event_empty_device_id(self, client):
        """Test that empty device_id is rejected."""
        event = {**VALID_EVENT, "device_id": ""}
        response = client.post("/api/events", json=event)
        assert response.status_code == 422

    def test_create_event_empty_description(self, client):
        """Test that empty description is rejected."""
        event = {**VALID_EVENT, "description": ""}
        response = client.post("/api/events", json=event)
        assert response.status_code == 422

    def test_create_event_negative_request_count(self, client):
        """Test that negative request_count is rejected."""
        event = {**VALID_EVENT, "request_count": -5}
        response = client.post("/api/events", json=event)
        assert response.status_code == 422

    def test_create_event_negative_time_window(self, client):
        """Test that negative time_window_seconds is rejected."""
        event = {**VALID_EVENT, "time_window_seconds": -10}
        response = client.post("/api/events", json=event)
        assert response.status_code == 422

    def test_create_event_with_request_count(self, client):
        """Test creating an event with a valid request count."""
        event = {**VALID_EVENT, "request_count": 42, "time_window_seconds": 60}
        response = client.post("/api/events", json=event)
        assert response.status_code == 201
        data = response.json()
        assert data["request_count"] == 42
        assert data["time_window_seconds"] == 60

    def test_create_event_all_severities(self, client):
        """Test that all valid severity values are accepted."""
        for severity in ["informational", "warning", "critical"]:
            event = {**VALID_EVENT, "severity": severity}
            response = client.post("/api/events", json=event)
            assert response.status_code == 201
            assert response.json()["severity"] == severity


class TestListEvents:
    """Tests for GET /api/events."""

    def test_list_events_empty(self, client):
        """Test listing events when database is empty."""
        response = client.get("/api/events")
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["skip"] == 0
        assert data["limit"] == 20

    def test_list_events_after_creation(self, client):
        """Test listing events after creating some."""
        client.post("/api/events", json=VALID_EVENT)
        client.post("/api/events", json={**VALID_EVENT, "severity": "critical"})

        response = client.get("/api/events")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    def test_list_events_filter_severity(self, client):
        """Test filtering events by severity."""
        client.post("/api/events", json={**VALID_EVENT, "severity": "warning"})
        client.post("/api/events", json={**VALID_EVENT, "severity": "critical"})
        client.post("/api/events", json={**VALID_EVENT, "severity": "informational"})

        response = client.get("/api/events?severity=critical")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["severity"] == "critical"

    def test_list_events_filter_event_type(self, client):
        """Test filtering events by event type."""
        client.post("/api/events", json=VALID_EVENT)
        client.post("/api/events", json={**VALID_EVENT, "event_type": "brute_force"})

        response = client.get("/api/events?event_type=brute_force")
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["event_type"] == "brute_force"

    def test_list_events_filter_device_id(self, client):
        """Test filtering events by device ID."""
        client.post("/api/events", json=VALID_EVENT)
        client.post("/api/events", json={**VALID_EVENT, "device_id": "rw612-02"})

        response = client.get("/api/events?device_id=rw612-02")
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["device_id"] == "rw612-02"

    def test_list_events_pagination(self, client):
        """Test pagination of events."""
        for i in range(5):
            client.post("/api/events", json={**VALID_EVENT, "description": f"Event {i}"})

        response = client.get("/api/events?skip=2&limit=2")
        data = response.json()
        assert data["total"] == 5
        assert len(data["items"]) == 2
        assert data["skip"] == 2
        assert data["limit"] == 2

    def test_list_events_time_range(self, client):
        """Test filtering events by time range."""
        client.post("/api/events", json={
            **VALID_EVENT,
            "timestamp": "2026-10-20T06:00:00Z"
        })
        client.post("/api/events", json={
            **VALID_EVENT,
            "timestamp": "2026-10-20T12:00:00Z"
        })

        response = client.get(
            "/api/events?start_time=2026-10-20T10:00:00Z&end_time=2026-10-20T14:00:00Z"
        )
        data = response.json()
        assert data["total"] == 1

    def test_list_events_invalid_time_range(self, client):
        """Test that start_time after end_time returns 400."""
        response = client.get(
            "/api/events?start_time=2026-10-20T14:00:00Z&end_time=2026-10-20T10:00:00Z"
        )
        assert response.status_code == 400
