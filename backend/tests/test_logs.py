"""Tests for request log endpoints."""

import pytest


VALID_LOG = {
    "timestamp": "2026-10-20T06:30:00Z",
    "device_id": "rw612-security-01",
    "source_ip": "192.168.1.25",
    "method": "GET",
    "endpoint": "/status",
    "response_code": 200,
    "classification": "normal",
}


class TestCreateLog:
    """Tests for POST /api/logs."""

    def test_create_log_success(self, client):
        """Test successful creation of a request log."""
        response = client.post("/api/logs", json=VALID_LOG)
        assert response.status_code == 201
        data = response.json()
        assert data["id"] is not None
        assert data["device_id"] == "rw612-security-01"
        assert data["method"] == "GET"
        assert data["endpoint"] == "/status"
        assert data["response_code"] == 200
        assert data["classification"] == "normal"
        assert data["created_at"] is not None

    def test_create_log_minimal(self, client):
        """Test creating a log with optional fields as None."""
        log = {
            "timestamp": "2026-10-20T06:30:00Z",
            "device_id": "rw612-01",
            "method": "POST",
            "endpoint": "/data",
            "classification": "normal",
        }
        response = client.post("/api/logs", json=log)
        assert response.status_code == 201
        data = response.json()
        assert data["source_ip"] is None
        assert data["response_code"] is None

    def test_create_log_invalid_classification(self, client):
        """Test that invalid classification values are rejected."""
        log = {**VALID_LOG, "classification": "dangerous"}
        response = client.post("/api/logs", json=log)
        assert response.status_code == 422

    def test_create_log_missing_required_fields(self, client):
        """Test that missing required fields return 422."""
        response = client.post("/api/logs", json={})
        assert response.status_code == 422

    def test_create_log_empty_device_id(self, client):
        """Test that empty device_id is rejected."""
        log = {**VALID_LOG, "device_id": ""}
        response = client.post("/api/logs", json=log)
        assert response.status_code == 422

    def test_create_log_invalid_response_code_low(self, client):
        """Test that response code below 100 is rejected."""
        log = {**VALID_LOG, "response_code": 50}
        response = client.post("/api/logs", json=log)
        assert response.status_code == 422

    def test_create_log_invalid_response_code_high(self, client):
        """Test that response code above 599 is rejected."""
        log = {**VALID_LOG, "response_code": 600}
        response = client.post("/api/logs", json=log)
        assert response.status_code == 422

    def test_create_log_all_classifications(self, client):
        """Test that all valid classification values are accepted."""
        for cls in ["normal", "unusual", "suspicious"]:
            log = {**VALID_LOG, "classification": cls}
            response = client.post("/api/logs", json=log)
            assert response.status_code == 201
            assert response.json()["classification"] == cls


class TestListLogs:
    """Tests for GET /api/logs."""

    def test_list_logs_empty(self, client):
        """Test listing logs when database is empty."""
        response = client.get("/api/logs")
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["skip"] == 0
        assert data["limit"] == 20

    def test_list_logs_after_creation(self, client):
        """Test listing logs after creating some."""
        client.post("/api/logs", json=VALID_LOG)
        client.post("/api/logs", json={**VALID_LOG, "endpoint": "/admin"})

        response = client.get("/api/logs")
        data = response.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    def test_list_logs_filter_classification(self, client):
        """Test filtering logs by classification."""
        client.post("/api/logs", json={**VALID_LOG, "classification": "normal"})
        client.post("/api/logs", json={**VALID_LOG, "classification": "suspicious"})

        response = client.get("/api/logs?classification=suspicious")
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["classification"] == "suspicious"

    def test_list_logs_filter_device_id(self, client):
        """Test filtering logs by device ID."""
        client.post("/api/logs", json=VALID_LOG)
        client.post("/api/logs", json={**VALID_LOG, "device_id": "rw612-02"})

        response = client.get("/api/logs?device_id=rw612-02")
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["device_id"] == "rw612-02"

    def test_list_logs_pagination(self, client):
        """Test pagination of logs."""
        for i in range(5):
            client.post("/api/logs", json={**VALID_LOG, "endpoint": f"/path/{i}"})

        response = client.get("/api/logs?skip=1&limit=2")
        data = response.json()
        assert data["total"] == 5
        assert len(data["items"]) == 2
        assert data["skip"] == 1
        assert data["limit"] == 2

    def test_list_logs_time_range(self, client):
        """Test filtering logs by time range."""
        client.post("/api/logs", json={
            **VALID_LOG,
            "timestamp": "2026-10-20T06:00:00Z"
        })
        client.post("/api/logs", json={
            **VALID_LOG,
            "timestamp": "2026-10-20T12:00:00Z"
        })

        response = client.get(
            "/api/logs?start_time=2026-10-20T10:00:00Z&end_time=2026-10-20T14:00:00Z"
        )
        data = response.json()
        assert data["total"] == 1

    def test_list_logs_invalid_time_range(self, client):
        """Test that start_time after end_time returns 400."""
        response = client.get(
            "/api/logs?start_time=2026-10-20T14:00:00Z&end_time=2026-10-20T10:00:00Z"
        )
        assert response.status_code == 400
