"""Unit and integration tests for Behavioral IP Profiling."""

from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.ip_profile import IPProfile
from app.services import ip_profile_service


class TestIPProfiling:
    """Test suite for behavioral IP profiling functionality."""

    def test_single_ip_profile_creation(self, client: TestClient):
        """Verify an IP profile is automatically created when a request log is ingested."""
        payload = {
            "timestamp": "2026-10-20T06:30:00Z",
            "device_id": "rw612-security-01",
            "source_ip": "192.168.1.100",
            "method": "GET",
            "endpoint": "/status",
            "response_code": 200,
            "classification": "normal",
        }
        resp = client.post("/api/logs", json=payload)
        assert resp.status_code == 201

        profile_resp = client.get("/api/ip-profiles/192.168.1.100")
        assert profile_resp.status_code == 200
        data = profile_resp.json()
        assert data["ip_address"] == "192.168.1.100"
        assert data["total_requests"] == 1
        assert data["unique_endpoints_count"] == 1
        assert data["unique_endpoints"] == ["/status"]
        assert data["suspicious_requests"] == 0
        assert data["threat_score"] < 30
        assert data["risk_level"] == "low"

    def test_multiple_ips_maintain_independent_profiles(self, client: TestClient):
        """Verify multiple IP addresses maintain completely independent tracking state."""
        ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

        for ip in ips:
            client.post("/api/logs", json={
                "timestamp": "2026-10-20T06:30:00Z",
                "device_id": "rw612-security-01",
                "source_ip": ip,
                "method": "GET",
                "endpoint": "/status",
                "response_code": 200,
                "classification": "normal",
            })

        # Add 2 more requests specifically for 10.0.0.2
        for _ in range(2):
            client.post("/api/logs", json={
                "timestamp": "2026-10-20T06:30:05Z",
                "device_id": "rw612-security-01",
                "source_ip": "10.0.0.2",
                "method": "GET",
                "endpoint": "/info",
                "response_code": 200,
                "classification": "normal",
            })

        p1 = client.get("/api/ip-profiles/10.0.0.1").json()
        p2 = client.get("/api/ip-profiles/10.0.0.2").json()
        p3 = client.get("/api/ip-profiles/10.0.0.3").json()

        assert p1["total_requests"] == 1
        assert p1["unique_endpoints_count"] == 1
        assert p2["total_requests"] == 3
        assert p2["unique_endpoints_count"] == 2
        assert p3["total_requests"] == 1

    def test_suspicious_requests_increase_threat_score(self, client: TestClient):
        """Verify suspicious/unknown endpoints elevate threat score and risk level."""
        # Clean request
        client.post("/api/logs", json={
            "timestamp": "2026-10-20T06:30:00Z",
            "device_id": "rw612-security-01",
            "source_ip": "172.16.0.5",
            "method": "GET",
            "endpoint": "/status",
            "response_code": 200,
            "classification": "normal",
        })
        p_clean = client.get("/api/ip-profiles/172.16.0.5").json()
        initial_score = p_clean["threat_score"]

        # Probing unknown endpoints (triggers Rule R1 unknown_endpoint)
        probes = ["/admin", "/config.php", "/api/v1/debug"]
        for ep in probes:
            client.post("/api/logs", json={
                "timestamp": "2026-10-20T06:30:02Z",
                "device_id": "rw612-security-01",
                "source_ip": "172.16.0.5",
                "method": "GET",
                "endpoint": ep,
                "response_code": 404,
                "classification": "normal",
            })

        p_attack = client.get("/api/ip-profiles/172.16.0.5").json()
        assert p_attack["total_requests"] == 4
        assert p_attack["suspicious_requests"] >= 3
        assert p_attack["unique_endpoints_count"] == 4
        assert p_attack["threat_score"] > initial_score
        assert p_attack["threat_score"] >= 45
        assert p_attack["risk_level"] in ("medium", "high", "critical")

    def test_repeated_requests_tracking(self, client: TestClient):
        """Verify consecutive requests to the same endpoint increment repeated_requests."""
        for _ in range(4):
            client.post("/api/logs", json={
                "timestamp": "2026-10-20T06:30:00Z",
                "device_id": "rw612-security-01",
                "source_ip": "192.168.1.55",
                "method": "GET",
                "endpoint": "/status",
                "response_code": 200,
                "classification": "normal",
            })

        p = client.get("/api/ip-profiles/192.168.1.55").json()
        assert p["total_requests"] == 4
        assert p["repeated_requests"] >= 3

    def test_profile_list_pagination_and_filters(self, client: TestClient):
        """Verify GET /api/ip-profiles filtering by risk_level, min_threat_score, and search_ip."""
        # 1 benign IP
        client.post("/api/logs", json={
            "timestamp": "2026-10-20T06:30:00Z",
            "device_id": "rw612-security-01",
            "source_ip": "192.168.1.10",
            "method": "GET",
            "endpoint": "/status",
            "response_code": 200,
            "classification": "normal",
        })

        # 1 aggressive IP
        for ep in ["/admin", "/shell", "/exec", "/login"]:
            client.post("/api/logs", json={
                "timestamp": "2026-10-20T06:30:01Z",
                "device_id": "rw612-security-01",
                "source_ip": "192.168.1.99",
                "method": "GET",
                "endpoint": ep,
                "response_code": 404,
                "classification": "suspicious",
            })

        # List all
        all_res = client.get("/api/ip-profiles").json()
        assert all_res["total"] == 2

        # Search IP
        search_res = client.get("/api/ip-profiles?search_ip=1.99").json()
        assert search_res["total"] == 1
        assert search_res["items"][0]["ip_address"] == "192.168.1.99"

        # Filter by min threat score
        high_res = client.get("/api/ip-profiles?min_threat_score=40").json()
        assert high_res["total"] == 1
        assert high_res["items"][0]["ip_address"] == "192.168.1.99"

    def test_profile_summary_endpoint(self, client: TestClient):
        """Verify GET /api/ip-profiles/summary returns correct aggregate counts."""
        client.post("/api/logs", json={
            "timestamp": "2026-10-20T06:30:00Z",
            "device_id": "rw612-security-01",
            "source_ip": "192.168.1.11",
            "method": "GET",
            "endpoint": "/status",
            "response_code": 200,
            "classification": "normal",
        })

        summary = client.get("/api/ip-profiles/summary").json()
        assert summary["total_profiles"] == 1
        assert summary["active_profiles"] == 1
        assert "max_threat_score" in summary
        assert "top_threat_ip" in summary

    def test_nonexistent_ip_returns_404(self, client: TestClient):
        """Verify 404 Not Found when querying unknown IP."""
        resp = client.get("/api/ip-profiles/255.255.255.255")
        assert resp.status_code == 404

    def test_inactive_profile_expiration(self, client: TestClient, db_session: Session):
        """Verify inactive profiles older than timeout can be expired."""
        client.post("/api/logs", json={
            "timestamp": "2026-10-20T06:00:00Z",
            "device_id": "rw612-security-01",
            "source_ip": "192.168.1.123",
            "method": "GET",
            "endpoint": "/status",
            "response_code": 200,
            "classification": "normal",
        })

        # Artificially age the profile in DB
        profile = db_session.query(IPProfile).filter(IPProfile.ip_address == "192.168.1.123").first()
        assert profile is not None
        profile.last_seen = datetime.now(timezone.utc) - timedelta(seconds=600)
        db_session.commit()

        # Call expire endpoint
        resp = client.post("/api/ip-profiles/expire?timeout_seconds=300")
        assert resp.status_code == 200
        assert resp.json()["expired_count"] == 1

        # Check that is_active is now False
        db_session.refresh(profile)
        assert profile.is_active is False
