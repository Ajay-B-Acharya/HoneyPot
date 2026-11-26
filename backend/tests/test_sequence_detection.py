"""Unit and integration tests for Attack Sequence Detection."""

import pytest
from fastapi.testclient import TestClient


class TestAttackSequenceDetection:
    """Test suite for multi-stage attack sequence detection."""

    def test_normal_traffic_does_not_trigger_sequence(self, client: TestClient):
        """Verify normal browsing to legitimate endpoints does not trigger sequence alerts."""
        normal_paths = ["/status", "/info", "/status"]
        for path in normal_paths:
            client.post("/api/logs", json={
                "timestamp": "2026-10-20T06:30:00Z",
                "device_id": "rw612-security-01",
                "source_ip": "192.168.1.10",
                "method": "GET",
                "endpoint": path,
                "response_code": 200,
                "classification": "normal",
            })

        events = client.get("/api/events?event_type=attack_sequence").json()
        assert events["total"] == 0

    def test_reconnaissance_sequence_detection(self, client: TestClient):
        """Verify reconnaissance sequence (/ -> /admin -> /config) triggers an attack sequence event."""
        recon_paths = ["/", "/admin", "/config"]
        for i, path in enumerate(recon_paths):
            client.post("/api/logs", json={
                "timestamp": f"2026-10-20T06:30:0{i}Z",
                "device_id": "rw612-security-01",
                "source_ip": "192.168.1.50",
                "method": "GET",
                "endpoint": path,
                "response_code": 200 if path in ("/", "/config") else 404,
                "classification": "normal",
            })

        events = client.get("/api/events?event_type=attack_sequence").json()
        assert events["total"] == 1
        event = events["items"][0]
        assert event["event_type"] == "attack_sequence"
        assert event["severity"] == "critical"
        assert event["source_ip"] == "192.168.1.50"
        assert event["metadata"]["pattern"] == "reconnaissance_probe"
        assert event["metadata"]["sequence_threat_score"] == 35

    def test_credential_hunting_detection(self, client: TestClient):
        """Verify credential hunting sequence (/admin -> /login) triggers attack sequence event."""
        cred_paths = ["/admin", "/login"]
        for i, path in enumerate(cred_paths):
            client.post("/api/logs", json={
                "timestamp": f"2026-10-20T06:30:0{i}Z",
                "device_id": "rw612-security-01",
                "source_ip": "192.168.1.60",
                "method": "GET",
                "endpoint": path,
                "response_code": 404,
                "classification": "suspicious",
            })

        events = client.get("/api/events?event_type=attack_sequence").json()
        assert events["total"] == 1
        event = events["items"][0]
        assert event["metadata"]["pattern"] == "credential_hunting"
        assert event["severity"] == "critical"

    def test_config_probing_detection(self, client: TestClient):
        """Verify repeated configuration access attempts trigger config_probing pattern."""
        config_paths = ["/config", "/setup", "/system/settings"]
        for i, path in enumerate(config_paths):
            client.post("/api/logs", json={
                "timestamp": f"2026-10-20T06:30:0{i}Z",
                "device_id": "rw612-security-01",
                "source_ip": "192.168.1.70",
                "method": "GET",
                "endpoint": path,
                "response_code": 200,
                "classification": "normal",
            })

        events = client.get("/api/events?event_type=attack_sequence").json()
        assert events["total"] == 1
        event = events["items"][0]
        assert event["metadata"]["pattern"] == "config_probing"

    def test_unknown_endpoint_sweep_detection(self, client: TestClient):
        """Verify 3 consecutive unknown endpoint probes trigger unknown_sweep pattern."""
        sweep_paths = ["/test1.php", "/shell.cgi", "/cmd.sh"]
        for i, path in enumerate(sweep_paths):
            client.post("/api/logs", json={
                "timestamp": f"2026-10-20T06:30:0{i}Z",
                "device_id": "rw612-security-01",
                "source_ip": "192.168.1.80",
                "method": "GET",
                "endpoint": path,
                "response_code": 404,
                "classification": "normal",
            })

        events = client.get("/api/events?event_type=attack_sequence").json()
        assert events["total"] == 1
        event = events["items"][0]
        assert event["metadata"]["pattern"] == "unknown_sweep"

    def test_sequence_cooldown_prevents_duplicate_flood(self, client: TestClient):
        """Verify cooldown prevents duplicate sequence alerts within 15 seconds."""
        paths = ["/", "/admin", "/config"]
        for i, path in enumerate(paths):
            client.post("/api/logs", json={
                "timestamp": f"2026-10-20T06:30:0{i}Z",
                "device_id": "rw612-security-01",
                "source_ip": "192.168.1.90",
                "method": "GET",
                "endpoint": path,
                "response_code": 200,
                "classification": "normal",
            })

        # Immediately repeat the sequence
        for i, path in enumerate(paths):
            client.post("/api/logs", json={
                "timestamp": f"2026-10-20T06:30:0{i + 4}Z",
                "device_id": "rw612-security-01",
                "source_ip": "192.168.1.90",
                "method": "GET",
                "endpoint": path,
                "response_code": 200,
                "classification": "normal",
            })

        events = client.get("/api/events?event_type=attack_sequence").json()
        assert events["total"] == 1  # Cooldown prevented second alert

    def test_interleaved_ips_do_not_contaminate_sequences(self, client: TestClient):
        """Verify request sequences from different source IPs are tracked independently."""
        # IP A does root and admin
        client.post("/api/logs", json={
            "timestamp": "2026-10-20T06:30:01Z",
            "device_id": "rw612-security-01",
            "source_ip": "10.0.0.100",
            "method": "GET",
            "endpoint": "/",
            "response_code": 200,
            "classification": "normal",
        })
        client.post("/api/logs", json={
            "timestamp": "2026-10-20T06:30:02Z",
            "device_id": "rw612-security-01",
            "source_ip": "10.0.0.100",
            "method": "GET",
            "endpoint": "/admin",
            "response_code": 404,
            "classification": "normal",
        })

        # IP B does a single config request
        client.post("/api/logs", json={
            "timestamp": "2026-10-20T06:30:03Z",
            "device_id": "rw612-security-01",
            "source_ip": "10.0.0.200",
            "method": "GET",
            "endpoint": "/config",
            "response_code": 200,
            "classification": "normal",
        })

        # At this point, neither IP has completed a full sequence
        assert client.get("/api/events?event_type=attack_sequence").json()["total"] == 0

        # IP A now does config -> completes recon sequence for IP A only
        client.post("/api/logs", json={
            "timestamp": "2026-10-20T06:30:04Z",
            "device_id": "rw612-security-01",
            "source_ip": "10.0.0.100",
            "method": "GET",
            "endpoint": "/config",
            "response_code": 200,
            "classification": "normal",
        })

        events = client.get("/api/events?event_type=attack_sequence").json()
        assert events["total"] == 1
        assert events["items"][0]["source_ip"] == "10.0.0.100"
