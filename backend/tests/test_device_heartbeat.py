"""Tests for physical FRDM-RW612 heartbeat ingestion, status thresholds, reboot, and stale rejection."""

from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models.device_heartbeat import DeviceHeartbeat
from app.services import device_service

client = TestClient(app)


def test_heartbeat_online_unstable_offline_and_reboot():
    dev_id = "rw612-hb-test-01"

    # 1. Fresh heartbeat -> ONLINE
    r1 = client.post(
        "/api/device/heartbeat",
        json={
            "device_id": dev_id,
            "uptime_seconds": 100,
            "wifi_connected": True,
            "device_ip": "10.213.149.191",
            "free_heap_bytes": 68240,
            "firmware_version": "1.0.0-rw612",
            "heartbeat_seq": 10,
        },
    )
    assert r1.status_code == 200
    assert r1.json()["status"] == "online"
    assert r1.json()["accepted"] is True

    # 2. Stale / older heartbeat_seq with same/higher uptime -> rejected
    r_stale = client.post(
        "/api/device/heartbeat",
        json={
            "device_id": dev_id,
            "uptime_seconds": 100,
            "wifi_connected": True,
            "device_ip": "10.213.149.191",
            "free_heap_bytes": 68240,
            "firmware_version": "1.0.0-rw612",
            "heartbeat_seq": 9,
        },
    )
    assert r_stale.status_code == 200
    assert r_stale.json()["accepted"] is False
    assert r_stale.json()["heartbeat_seq"] == 10

    # 3. Device reboot (uptime_seconds resets < 100 even with seq=1) -> accepted
    r_reboot = client.post(
        "/api/device/heartbeat",
        json={
            "device_id": dev_id,
            "uptime_seconds": 2,
            "wifi_connected": True,
            "device_ip": "10.213.149.191",
            "free_heap_bytes": 70100,
            "firmware_version": "1.0.0-rw612",
            "heartbeat_seq": 1,
        },
    )
    assert r_reboot.status_code == 200
    assert r_reboot.json()["accepted"] is True
    assert r_reboot.json()["heartbeat_seq"] == 1

    # 4. Evaluate CONNECTION_UNSTABLE (10s old) and OFFLINE (20s old)
    db = SessionLocal()
    try:
        hb = db.query(DeviceHeartbeat).filter(DeviceHeartbeat.device_id == dev_id).first()
        assert hb is not None
        now = datetime.now(timezone.utc)
        hb.last_heartbeat_at = now - timedelta(seconds=10)
        assert device_service.evaluate_heartbeat_status(hb, now) == "connection_unstable"

        hb.last_heartbeat_at = now - timedelta(seconds=20)
        assert device_service.evaluate_heartbeat_status(hb, now) == "offline"
    finally:
        db.close()

    # 5. GET /api/device/status includes device fields
    rs = client.get("/api/device/status")
    assert rs.status_code == 200
    items = [d for d in rs.json()["devices"] if d["device_id"] == dev_id]
    assert len(items) == 1
    assert items[0]["device_ip"] == "10.213.149.191"
    assert items[0]["firmware_version"] == "1.0.0-rw612"
