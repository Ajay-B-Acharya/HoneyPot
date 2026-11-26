"""Unit and integration tests for Offline Detection Continuity & State Reconciliation (Feature 4)."""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db


def test_batch_reconcile_events_success(client: TestClient):
    """Verify batch synchronization of events stored during network outage."""
    batch_payload = {
        "events": [
            {
                "client_event_id": "rw612-evt-00010000-0001",
                "timestamp": "2026-10-27T08:15:00Z",
                "device_id": "rw612-security-01",
                "event_type": "unknown_endpoint",
                "severity": "warning",
                "description": "Probe to /cgi-bin/test",
                "source_ip": "192.168.1.150",
                "metadata": {"endpoint": "/cgi-bin/test", "threat_score": 45, "risk_level": "medium"},
            },
            {
                "client_event_id": "rw612-evt-00010000-0002",
                "timestamp": "2026-10-27T08:16:00Z",
                "device_id": "rw612-security-01",
                "event_type": "attack_sequence",
                "severity": "critical",
                "description": "Multi-stage reconnaissance probe: / -> /admin -> /config",
                "source_ip": "192.168.1.150",
                "metadata": {"endpoint": "/config", "threat_score": 80, "risk_level": "high"},
            },
        ]
    }

    response = client.post("/api/events/batch", json=batch_payload)
    assert response.status_code == 201
    data = response.json()
    assert data["received"] == 2
    assert data["inserted"] == 2
    assert data["duplicates"] == 0
    assert data["status"] == "reconciled"


def test_batch_reconcile_idempotency_prevents_duplicates(client: TestClient):
    """Verify that resubmitting already synced events produces 0 duplicate records."""
    event_id = "rw612-evt-idempotent-0001"
    batch_payload = {
        "events": [
            {
                "client_event_id": event_id,
                "timestamp": "2026-10-27T08:20:00Z",
                "device_id": "rw612-security-01",
                "event_type": "high_request_rate",
                "severity": "warning",
                "description": "Rate limit burst violation",
                "source_ip": "192.168.1.180",
                "metadata": {"threat_score": 50, "risk_level": "medium"},
            }
        ]
    }

    # First transmission
    res1 = client.post("/api/events/batch", json=batch_payload)
    assert res1.status_code == 201
    assert res1.json()["inserted"] == 1
    assert res1.json()["duplicates"] == 0

    # Second transmission (e.g. device retrying after dropped ACK)
    res2 = client.post("/api/events/batch", json=batch_payload)
    assert res2.status_code == 201
    assert res2.json()["received"] == 1
    assert res2.json()["inserted"] == 0
    assert res2.json()["duplicates"] == 1
    assert res2.json()["status"] == "reconciled"


def test_batch_preserves_event_attributes(client: TestClient):
    """Verify that event timestamps, severities, descriptions, and source IPs are faithfully preserved."""
    event_id = "rw612-evt-preserved-attr-0001"
    timestamp_str = "2026-10-27T09:30:45Z"
    batch_payload = {
        "events": [
            {
                "client_event_id": event_id,
                "timestamp": timestamp_str,
                "device_id": "rw612-security-01",
                "event_type": "repeated_requests",
                "severity": "informational",
                "description": "Repeated probe on /status",
                "source_ip": "192.168.1.200",
                "metadata": {"endpoint": "/status", "threat_score": 15, "risk_level": "low"},
            }
        ]
    }

    res = client.post("/api/events/batch", json=batch_payload)
    assert res.status_code == 201

    # Query event back via list endpoint
    list_res = client.get("/api/events?limit=10")
    assert list_res.status_code == 200
    events = list_res.json()["items"]
    matched = [e for e in events if (e.get("metadata") or {}).get("client_event_id") == event_id]
    assert len(matched) == 1
    evt = matched[0]
    assert evt["severity"] == "informational"
    assert evt["source_ip"] == "192.168.1.200"
    assert evt["event_type"] == "repeated_requests"
    assert "2026-10-27T09:30:45" in evt["timestamp"]
