"""Service layer for device memory monitoring and threat preservation."""

from app.schemas.memory_stats import DeviceMemoryStats, ThreatEvictionSummary

# In-memory diagnostics store representing device state
_current_memory_stats = DeviceMemoryStats(
    device_id="rw612-security-01",
    total_security_bss_bytes=22528,  # ~22 KB static security allocation
    active_profiles=0,
    max_profiles=24,
    profile_bytes_used=0,
    free_heap_bytes=118784,         # ~116 KB free FreeRTOS heap
    min_ever_free_heap_bytes=114688,
    pressure_level="normal",
    pending_offline_events=0,
    eviction_summary=ThreatEvictionSummary(),
)


def get_memory_stats(active_ip_count: int = 0) -> DeviceMemoryStats:
    """Retrieve current memory diagnostics, dynamically calculating pressure level."""
    profile_size = 480  # bytes per IPProfile_t
    max_cap = _current_memory_stats.max_profiles
    used_profiles = max(active_ip_count, _current_memory_stats.active_profiles)

    # Determine pressure level
    if used_profiles >= max_cap:
        pressure = "critical"
    elif used_profiles >= 20:
        pressure = "high"
    elif used_profiles >= 14:
        pressure = "moderate"
    else:
        pressure = "normal"

    _current_memory_stats.active_profiles = used_profiles
    _current_memory_stats.profile_bytes_used = used_profiles * profile_size
    _current_memory_stats.pressure_level = pressure

    return _current_memory_stats


def update_memory_stats(stats: DeviceMemoryStats) -> DeviceMemoryStats:
    """Update memory stats from device reporting."""
    global _current_memory_stats
    _current_memory_stats = stats
    return _current_memory_stats


def record_eviction(ip_str: str, threat_score: int, total_reqs: int, susp_reqs: int) -> ThreatEvictionSummary:
    """Record eviction and update historical summary metrics."""
    summary = _current_memory_stats.eviction_summary
    summary.total_evicted_count += 1
    summary.aggregate_evicted_requests += total_reqs
    summary.aggregate_suspicious_requests += susp_reqs
    summary.last_evicted_ip = ip_str

    if threat_score < 30:
        summary.evicted_benign_count += 1
    else:
        summary.evicted_suspicious_count += 1

    if threat_score > summary.highest_evicted_threat_score:
        summary.highest_evicted_threat_score = threat_score

    return summary


def reset_memory_stats() -> None:
    """Reset diagnostics state for unit tests."""
    global _current_memory_stats
    _current_memory_stats = DeviceMemoryStats(
        device_id="rw612-security-01",
        total_security_bss_bytes=22528,
        active_profiles=0,
        max_profiles=24,
        profile_bytes_used=0,
        free_heap_bytes=118784,
        min_ever_free_heap_bytes=114688,
        pressure_level="normal",
        pending_offline_events=0,
        eviction_summary=ThreatEvictionSummary(),
    )
