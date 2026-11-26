"""Tests for Split-Stage Edge-to-Backend Threat Correlation & IP Churn / Shared-IP handling."""

import uuid
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_out_of_order_observations_reconstruct_sequence():
    tag = uuid.uuid4().hex[:8]
    # Send observations out of chronological order (step 3 first, then 1, then 2)
    batch = {
        "observations": [
            {
                "observation_id": f"obs-ooo-{tag}-003",
                "device_id": "rw612-security-01",
                "source_ip": f"10.10.10.{int(tag[:2], 16) % 200 + 1}",
                "endpoint_id": 12,
                "endpoint": "/config",
                "event_timestamp": "2026-11-26T12:00:03Z",
                "sequence_num": 3,
                "edge_score": 55,
                "triggered_event": "attack_sequence",
            },
            {
                "observation_id": f"obs-ooo-{tag}-001",
                "device_id": "rw612-security-01",
                "source_ip": f"10.10.10.{int(tag[:2], 16) % 200 + 1}",
                "endpoint_id": 1,
                "endpoint": "/",
                "event_timestamp": "2026-11-26T12:00:01Z",
                "sequence_num": 1,
                "edge_score": 2,
            },
            {
                "observation_id": f"obs-ooo-{tag}-002",
                "device_id": "rw612-security-01",
                "source_ip": f"10.10.10.{int(tag[:2], 16) % 200 + 1}",
                "endpoint_id": 10,
                "endpoint": "/admin",
                "event_timestamp": "2026-11-26T12:00:02Z",
                "sequence_num": 2,
                "edge_score": 32,
            },
        ]
    }
    r = client.post("/api/observations/batch", json=batch)
    assert r.status_code == 201
    data = r.json()
    assert data["inserted"] == 3
    assert data["derived_alerts_created"] >= 1

    # Duplicate resubmission must be idempotent
    r_dup = client.post("/api/observations/batch", json=batch)
    assert r_dup.status_code == 201
    assert r_dup.json()["inserted"] == 0
    assert r_dup.json()["duplicates"] == 3


def test_shared_ip_ambiguity_lowers_confidence():
    shared_ip = "172.16.0.99"
    seq = [
        ("obs-nat-1", "/status", 1, 0, "2026-11-26T12:05:01Z"),
        ("obs-nat-2", "/admin", 10, 15, "2026-11-26T12:05:02Z"),
        ("obs-nat-3", "/info", 2, 0, "2026-11-26T12:05:03Z"),
        ("obs-nat-4", "/login", 11, 50, "2026-11-26T12:05:04Z"),
    ]
    last_resp = None
    for idx, (oid, ep, eid, score, ts) in enumerate(seq, start=1):
        r = client.post(
            "/api/observations",
            json={
                "observation_id": oid,
                "device_id": "rw612-security-01",
                "source_ip": shared_ip,
                "endpoint_id": eid,
                "endpoint": ep,
                "event_timestamp": ts,
                "sequence_num": idx,
                "edge_score": score,
            },
        )
        assert r.status_code == 201
        last_resp = r.json()

    assert last_resp["shared_ip_suspected"] is True
    assert last_resp["correlation_confidence"] <= 0.6


def test_ip_churn_roaming_fingerprint_match():
    tag = uuid.uuid4().hex[:8]
    # First IP runs /admin -> /login
    for idx, (oid, ep, eid, score, ts) in enumerate(
        [
            (f"obs-churn-{tag}-a1", "/admin", 10, 15, "2026-11-26T12:10:01Z"),
            (f"obs-churn-{tag}-a2", "/login", 11, 50, "2026-11-26T12:10:02Z"),
        ],
        start=1,
    ):
        r = client.post(
            "/api/observations",
            json={
                "observation_id": oid,
                "device_id": "rw612-security-01",
                "source_ip": "198.51.100.10",
                "endpoint_id": eid,
                "endpoint": ep,
                "event_timestamp": ts,
                "sequence_num": idx,
                "edge_score": score,
            },
        )
        assert r.status_code == 201

    # Second IP immediately exhibits identical /admin -> /login fingerprint
    for idx, (oid, ep, eid, score, ts) in enumerate(
        [
            (f"obs-churn-{tag}-b1", "/admin", 10, 15, "2026-11-26T12:10:20Z"),
            (f"obs-churn-{tag}-b2", "/login", 11, 50, "2026-11-26T12:10:21Z"),
        ],
        start=1,
    ):
        r = client.post(
            "/api/observations",
            json={
                "observation_id": oid,
                "device_id": "rw612-security-01",
                "source_ip": "198.51.100.77",
                "endpoint_id": eid,
                "endpoint": ep,
                "event_timestamp": ts,
                "sequence_num": idx,
                "edge_score": score,
            },
        )
        assert r.status_code == 201
        res = r.json()

    assert res["correlation_score"] >= 75
    assert res["derived_event_id"] is not None
