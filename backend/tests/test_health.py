"""Tests for the health check endpoint."""


def test_health_check(client):
    """Test that the health endpoint returns expected status."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "iot-honeypot-backend"


def test_health_check_response_format(client):
    """Test that the health response has exactly the expected keys."""
    response = client.get("/api/health")
    data = response.json()
    assert set(data.keys()) == {"status", "service"}
