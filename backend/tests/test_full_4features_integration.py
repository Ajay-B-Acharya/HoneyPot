"""End-to-End Integration Test for all 4 Advanced Features:
1. Behavioral IP Profiling
2. Attack Sequence Detection
3. Memory-Aware Threat Preservation
4. Offline Detection Continuity & State Reconciliation
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.services import memory_service, ip_profile_service, detection_service


@pytest.fixture(autouse=True)
def clean_environment():
    """Ensure clean state across all services."""
    memory_service.reset_memory_stats()
    detection_service.reset_detection_service()
    yield
    memory_service.reset_memory_stats()
    detection_service.reset_detection_service()


def test_full_four_features_synergy(client: TestClient):
    """Verify simultaneous operation and synergy between all 4 features."""

    # -------------------------------------------------------------------------
    # FEATURE 1 & 2: Behavioral IP Profiling & Attack Sequence Detection
    # -------------------------------------------------------------------------
    attacker_ip = "192.168.1.189"
    now = datetime.now(timezone.utc)

    # Attacker executes multi-stage reconnaissance probe: / -> /admin -> /config
    endpoints = ["/", "/admin", "/config"]
    for i, ep in enumerate(endpoints):
        log_res = client.post("/api/logs", json={
            "timestamp": now.isoformat(),
            "device_id": "rw612-security-01",
            "source_ip": attacker_ip,
            "method": "GET",
            "endpoint": ep,
            "response_code": 200 if ep in ["/", "/config"] else 404,
            "classification": "unusual" if ep == "/admin" else "normal",
        })
        assert log_res.status_code == 201

    # Verify IP profile updated and threat score elevated
    profile_res = client.get(f"/api/ip-profiles/{attacker_ip}")
    assert profile_res.status_code == 200
    profile = profile_res.json()
    assert profile["total_requests"] == 3
    assert profile["threat_score"] >= 30
    assert profile["risk_level"] in ["medium", "high", "critical"]

    # Verify Attack Sequence generated a security event
    events_res = client.get(f"/api/events?event_type=attack_sequence&limit=5")
    assert events_res.status_code == 200
    seq_events = events_res.json()["items"]
    attacker_events = [e for e in seq_events if e["source_ip"] == attacker_ip]
    assert len(attacker_events) >= 1
    assert "Reconnaissance sequence" in attacker_events[0]["description"]

    # -------------------------------------------------------------------------
    # FEATURE 3: Memory-Aware Threat Preservation
    # -------------------------------------------------------------------------
    # Simulate high volume of benign IPs (25 distinct IPs) to induce memory pressure
    for i in range(1, 26):
        client.post("/api/logs", json={
            "timestamp": now.isoformat(),
            "device_id": "rw612-security-01",
            "source_ip": f"10.0.1.{i}",
            "method": "GET",
            "endpoint": "/status",
            "response_code": 200,
            "classification": "normal",
        })

    # Query device memory diagnostics
    mem_res = client.get("/api/device/memory")
    assert mem_res.status_code == 200
    mem_stats = mem_res.json()

    # Verify memory pressure transitioned to high/critical
    assert mem_stats["pressure_level"] in ["high", "critical"]
    assert mem_stats["total_security_bss_bytes"] == 22528

    # Simulate eviction of low-priority benign IPs
    for i in range(1, 5):
        memory_service.record_eviction(
            ip_str=f"10.0.1.{i}",
            threat_score=10,
            total_reqs=1,
            susp_reqs=0,
        )

    # Check that compressed historical telemetry is preserved
    updated_mem = client.get("/api/device/memory").json()
    assert updated_mem["eviction_summary"]["total_evicted_count"] >= 4
    assert updated_mem["eviction_summary"]["evicted_benign_count"] >= 4
    assert updated_mem["eviction_summary"]["aggregate_evicted_requests"] >= 4

    # Crucial check: verify high-threat attacker IP profile was NOT evicted
    check_attacker = client.get(f"/api/ip-profiles/{attacker_ip}")
    assert check_attacker.status_code == 200
    assert check_attacker.json()["threat_score"] >= 30

    # -------------------------------------------------------------------------
    # FEATURE 4: Offline Detection Continuity & State Reconciliation
    # -------------------------------------------------------------------------
    batch_data = {
        "events": [
            {
                "client_event_id": "rw612-evt-offline-001",
                "timestamp": "2026-10-27T10:00:00Z",
                "device_id": "rw612-security-01",
                "event_type": "unknown_endpoint",
                "severity": "warning",
                "description": "Probe to /boaform/admin.cgi during network outage",
                "source_ip": attacker_ip,
                "metadata": {"endpoint": "/boaform/admin.cgi", "threat_score": 65, "risk_level": "medium"},
            },
            {
                "client_event_id": "rw612-evt-offline-002",
                "timestamp": "2026-10-27T10:01:00Z",
                "device_id": "rw612-security-01",
                "event_type": "attack_sequence",
                "severity": "critical",
                "description": "Outage credential sweep: /admin -> /login",
                "source_ip": attacker_ip,
                "metadata": {"endpoint": "/login", "threat_score": 90, "risk_level": "critical"},
            },
        ]
    }

    # First reconciliation upload
    sync_res = client.post("/api/events/batch", json=batch_data)
    assert sync_res.status_code == 201
    sync_json = sync_res.json()
    assert sync_json["received"] == 2
    assert sync_json["inserted"] == 2
    assert sync_json["duplicates"] == 0
    assert sync_json["status"] == "reconciled"

    # Retry same batch (simulating network dropped ACK, device retransmitting)
    retry_res = client.post("/api/events/batch", json=batch_data)
    assert retry_res.status_code == 201
    retry_json = retry_res.json()
    assert retry_json["received"] == 2
    assert retry_json["inserted"] == 0
    assert retry_json["duplicates"] == 2
    assert retry_json["status"] == "reconciled"

    # Verify reconciled event timestamps and severities are intact
    reconciled_events = client.get("/api/events?limit=10").json()["items"]
    offline_event_1 = next(
        (e for e in reconciled_events if (e.get("metadata") or {}).get("client_event_id") == "rw612-evt-offline-001"),
        None,
    )
    assert offline_event_1 is not None
    assert offline_event_1["severity"] == "warning"
    assert offline_event_1["source_ip"] == attacker_ip
    assert "2026-10-27T10:00:00" in offline_event_1["timestamp"]
