"""Unit and integration tests for Memory-Aware Threat Preservation (Feature 3)."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import memory_service
from app.schemas.memory_stats import DeviceMemoryStats, ThreatEvictionSummary


@pytest.fixture(autouse=True)
def clean_memory_state():
    """Reset memory diagnostics before and after each test."""
    memory_service.reset_memory_stats()
    yield
    memory_service.reset_memory_stats()


def test_initial_memory_footprint():
    """Verify compile-time static RAM limits and initial diagnostics."""
    stats = memory_service.get_memory_stats()
    assert stats.device_id == "rw612-security-01"
    assert stats.total_security_bss_bytes == 22528  # ~22 KB static BSS
    assert stats.max_profiles == 24
    assert stats.active_profiles == 0
    assert stats.profile_bytes_used == 0
    assert stats.free_heap_bytes >= 100000  # >= 100 KB free FreeRTOS heap
    assert stats.pressure_level == "normal"
    assert stats.eviction_summary.total_evicted_count == 0


def test_memory_pressure_thresholds():
    """Verify progression across normal, moderate, high, and critical pressure."""
    # 0 to 13 -> normal
    assert memory_service.get_memory_stats(5).pressure_level == "normal"
    assert memory_service.get_memory_stats(13).pressure_level == "normal"

    # 14 to 19 -> moderate
    assert memory_service.get_memory_stats(14).pressure_level == "moderate"
    assert memory_service.get_memory_stats(19).pressure_level == "moderate"

    # 20 to 23 -> high
    assert memory_service.get_memory_stats(20).pressure_level == "high"
    assert memory_service.get_memory_stats(23).pressure_level == "high"

    # 24+ -> critical
    assert memory_service.get_memory_stats(24).pressure_level == "critical"
    assert memory_service.get_memory_stats(30).pressure_level == "critical"


def test_eviction_recording_and_compression():
    """Verify that evicted profiles are compressed into aggregate historical statistics."""
    # Evict 2 benign profiles
    s1 = memory_service.record_eviction("192.168.1.10", threat_score=15, total_reqs=10, susp_reqs=1)
    s2 = memory_service.record_eviction("192.168.1.11", threat_score=20, total_reqs=5, susp_reqs=0)

    assert s2.total_evicted_count == 2
    assert s2.evicted_benign_count == 2
    assert s2.evicted_suspicious_count == 0
    assert s2.aggregate_evicted_requests == 15
    assert s2.aggregate_suspicious_requests == 1
    assert s2.highest_evicted_threat_score == 20
    assert s2.last_evicted_ip == "192.168.1.11"

    # Evict 1 high-threat profile under critical pressure
    s3 = memory_service.record_eviction("192.168.1.99", threat_score=85, total_reqs=40, susp_reqs=12)
    assert s3.total_evicted_count == 3
    assert s3.evicted_benign_count == 2
    assert s3.evicted_suspicious_count == 1
    assert s3.aggregate_evicted_requests == 55
    assert s3.aggregate_suspicious_requests == 13
    assert s3.highest_evicted_threat_score == 85
    assert s3.last_evicted_ip == "192.168.1.99"


def test_api_device_memory_endpoint():
    """Verify GET /api/device/memory API endpoint."""
    client = TestClient(app)
    response = client.get("/api/device/memory")
    assert response.status_code == 200
    data = response.json()
    assert data["device_id"] == "rw612-security-01"
    assert data["total_security_bss_bytes"] == 22528
    assert data["max_profiles"] == 24
    assert "pressure_level" in data
    assert "eviction_summary" in data


def test_api_device_memory_report():
    """Verify board telemetry reporting via POST /api/device/memory/report."""
    client = TestClient(app)
    payload = {
        "device_id": "rw612-security-01",
        "total_security_bss_bytes": 22528,
        "active_profiles": 22,
        "max_profiles": 24,
        "profile_bytes_used": 10560,
        "free_heap_bytes": 116240,
        "min_ever_free_heap_bytes": 112100,
        "pressure_level": "high",
        "pending_offline_events": 3,
        "eviction_summary": {
            "total_evicted_count": 8,
            "evicted_benign_count": 7,
            "evicted_suspicious_count": 1,
            "aggregate_evicted_requests": 64,
            "aggregate_suspicious_requests": 4,
            "highest_evicted_threat_score": 45,
            "last_evicted_ip": "10.0.0.88",
        },
    }
    response = client.post("/api/device/memory/report", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["active_profiles"] == 22
    assert data["pressure_level"] == "high"
    assert data["eviction_summary"]["total_evicted_count"] == 8
