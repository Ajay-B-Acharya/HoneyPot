"""Tests for resilient telemetry: idempotent logs, batch acks, and duplicate prevention."""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_batch_events_idempotent_with_acked_ids():
    cid1 = "rw612-test-batch-0001"
    cid2 = "rw612-test-batch-0002"
    payload = {
        "events": [
            {
                "client_event_id": cid1,
                "timestamp": "2026-11-26T12:00:00Z",
                "device_id": "rw612-security-01",
                "event_type": "attack_sequence",
                "severity": "critical",
                "description": "Critical recon alert",
                "source_ip": "192.168.1.99",
            },
            {
                "client_event_id": cid2,
                "timestamp": "2026-11-26T12:00:01Z",
                "device_id": "rw612-security-01",
                "event_type": "unknown_endpoint",
                "severity": "warning",
                "description": "Probe /shell",
                "source_ip": "192.168.1.99",
            },
        ]
    }
    r1 = client.post("/api/events/batch", json=payload)
    assert r1.status_code == 201
    d1 = r1.json()
    assert d1["received"] == 2
    assert cid1 in d1["acked_ids"]
    assert cid2 in d1["acked_ids"]
    assert d1["failed_ids"] == []

    # Resubmit same batch -> 0 new inserts, 2 duplicates, still acked
    r2 = client.post("/api/events/batch", json=payload)
    assert r2.status_code == 201
    d2 = r2.json()
    assert d2["inserted"] == 0
    assert d2["duplicates"] == 2
    assert set(d2["acked_ids"]) == {cid1, cid2}


def test_request_log_deduplication_preserves_timestamp():
    ts = "2026-11-26T10:15:30Z"
    payload = {
        "client_event_id": "rw612-evt-00001234-0001-log",
        "timestamp": ts,
        "device_id": "rw612-security-01",
        "source_ip": "192.168.1.88",
        "method": "GET",
        "endpoint": "/status",
        "response_code": 200,
        "classification": "normal",
    }
    r1 = client.post("/api/logs", json=payload)
    assert r1.status_code == 201
    id1 = r1.json()["id"]

    r2 = client.post("/api/logs", json=payload)
    assert r2.status_code == 201
    assert r2.json()["id"] == id1
    assert r2.json()["timestamp"].startswith("2026-11-26T10:15:30")
