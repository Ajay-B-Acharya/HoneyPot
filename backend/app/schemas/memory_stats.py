"""Pydantic schemas for device memory diagnostics and threat preservation."""

from pydantic import BaseModel, Field


class ThreatEvictionSummary(BaseModel):
    """Historical summary of telemetry intelligence from evicted profiles."""
    total_evicted_count: int = Field(0, description="Total profiles evicted")
    evicted_benign_count: int = Field(0, description="Evicted low-threat profiles")
    evicted_suspicious_count: int = Field(0, description="Evicted suspicious profiles")
    aggregate_evicted_requests: int = Field(0, description="Sum of requests across evicted profiles")
    aggregate_suspicious_requests: int = Field(0, description="Sum of suspicious requests from evicted profiles")
    highest_evicted_threat_score: int = Field(0, description="Max threat score among evicted IPs")
    last_evicted_ip: str | None = Field(None, description="Most recently evicted IP address")


class DeviceMemoryStats(BaseModel):
    """Memory diagnostics and threat preservation metrics for FRDM-RW612."""
    device_id: str = Field("rw612-security-01", description="Honeypot device ID")
    total_security_bss_bytes: int = Field(22528, description="Compile-time static RAM budget (bytes)")
    active_profiles: int = Field(0, description="Current active IP profiles")
    max_profiles: int = Field(24, description="Maximum profile capacity")
    profile_bytes_used: int = Field(0, description="RAM bytes consumed by active profiles")
    free_heap_bytes: int = Field(118784, description="Current FreeRTOS heap free bytes")
    min_ever_free_heap_bytes: int = Field(114688, description="FreeRTOS heap high-water mark")
    pressure_level: str = Field("normal", description="Memory pressure: normal, moderate, high, critical")
    pending_offline_events: int = Field(0, description="Events pending offline synchronization")
    eviction_summary: ThreatEvictionSummary = Field(default_factory=ThreatEvictionSummary)
