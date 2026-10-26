"""Tests for the device status endpoint."""


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
    "event_type": "scan_detected",
    "severity": "warning",
    "description": "Test event",
}


class TestDeviceStatus:
    """Tests for GET /api/device/status."""

    def test_device_status_empty(self, client):
        """Test device status when no data exists."""
        response = client.get("/api/device/status")
        assert response.status_code == 200
        data = response.json()
        assert data["devices"] == []

    def test_device_status_after_log(self, client):
        """Test device status after creating a request log."""
        client.post("/api/logs", json=VALID_LOG)

        response = client.get("/api/device/status")
        data = response.json()
        assert len(data["devices"]) == 1
        device = data["devices"][0]
        assert device["device_id"] == "rw612-security-01"
        assert device["status"] in ["active", "inactive"]
        assert device["last_seen"] is not None
        assert device["last_activity"] is not None

    def test_device_status_after_event(self, client):
        """Test device status after creating a security event."""
        client.post("/api/events", json=VALID_EVENT)

        response = client.get("/api/device/status")
        data = response.json()
        assert len(data["devices"]) == 1
        assert data["devices"][0]["device_id"] == "rw612-security-01"

    def test_device_status_multiple_devices(self, client):
        """Test device status with multiple devices."""
        client.post("/api/logs", json=VALID_LOG)
        client.post("/api/logs", json={**VALID_LOG, "device_id": "rw612-02"})
        client.post("/api/events", json={**VALID_EVENT, "device_id": "rw612-03"})

        response = client.get("/api/device/status")
        data = response.json()
        device_ids = [d["device_id"] for d in data["devices"]]
        assert "rw612-security-01" in device_ids
        assert "rw612-02" in device_ids
        assert "rw612-03" in device_ids

    def test_device_status_response_structure(self, client):
        """Test device status response has expected structure."""
        client.post("/api/logs", json=VALID_LOG)

        response = client.get("/api/device/status")
        data = response.json()
        assert "devices" in data
        device = data["devices"][0]
        assert "device_id" in device
        assert "status" in device
        assert "last_seen" in device
        assert "last_activity" in device

    def test_device_old_timestamp_inactive(self, client):
        """Test that a device with an old timestamp shows as inactive."""
        # Use a very old timestamp
        old_log = {**VALID_LOG, "timestamp": "2020-01-01T00:00:00Z"}
        client.post("/api/logs", json=old_log)

        response = client.get("/api/device/status")
        data = response.json()
        assert data["devices"][0]["status"] == "inactive"

    def test_device_status_mixed_timestamps_and_activity(self, client):
        """Test that device status handles mixed activity and timestamp ordering safely."""
        # Post an older log then a newer event for the same device
        client.post("/api/logs", json={**VALID_LOG, "timestamp": "2026-10-20T06:00:00Z"})
        client.post("/api/events", json={**VALID_EVENT, "timestamp": "2026-10-20T06:30:00Z"})

        response = client.get("/api/device/status")
        assert response.status_code == 200
        data = response.json()
        assert len(data["devices"]) == 1
        assert "2026-10-20T06:30:00" in data["devices"][0]["last_seen"]
