"""Reusable test harness and client utility for IoT Honeypot Monitor.

Restricted exclusively to local automated testing against the in-memory
FastAPI test application. Does not perform external network communication
or scanning.
"""

from datetime import datetime, timezone, timedelta
from typing import Any
from fastapi.testclient import TestClient
from httpx import Response

from app.config import Settings
from app.services.detection_service import get_detection_service


class HoneypotTestHarness:
    """Safe, controlled test harness for backend end-to-end integration tests."""

    def __init__(self, client: TestClient):
        self.client = client
        self.default_device_id = "rw612-test-e2e"
        self.default_ip = "192.168.1.150"

    def configure_detection(
        self,
        allowed_endpoints: str | None = None,
        rate_threshold: int | None = None,
        rate_window: int | None = None,
        rate_cooldown: int | None = None,
        repeated_threshold: int | None = None,
        repeated_window: int | None = None,
        repeated_cooldown: int | None = None,
    ):
        """Configure detection service with test-specific parameters (e.g. small thresholds)."""
        overrides: dict[str, Any] = {}
        if allowed_endpoints is not None:
            overrides["DETECTION_ALLOWED_ENDPOINTS"] = allowed_endpoints
        if rate_threshold is not None:
            overrides["DETECTION_RATE_THRESHOLD"] = rate_threshold
        if rate_window is not None:
            overrides["DETECTION_RATE_WINDOW_SECONDS"] = rate_window
        if rate_cooldown is not None:
            overrides["DETECTION_RATE_COOLDOWN_SECONDS"] = rate_cooldown
        if repeated_threshold is not None:
            overrides["DETECTION_REPEATED_THRESHOLD"] = repeated_threshold
        if repeated_window is not None:
            overrides["DETECTION_REPEATED_WINDOW_SECONDS"] = repeated_window
        if repeated_cooldown is not None:
            overrides["DETECTION_REPEATED_COOLDOWN_SECONDS"] = repeated_cooldown

        custom_settings = Settings(**overrides)
        return get_detection_service(settings=custom_settings)

    def submit_log(
        self,
        endpoint: str = "/status",
        method: str = "GET",
        device_id: str | None = None,
        source_ip: str | None = ...,  # type: ignore
        response_code: int | None = 200,
        classification: str = "normal",
        timestamp: datetime | str | None = None,
    ) -> Response:
        """Submit a request log to POST /api/logs."""
        if device_id is None:
            device_id = self.default_device_id

        resolved_ip = self.default_ip if source_ip is ... else source_ip

        if timestamp is None:
            ts_str = datetime.now(timezone.utc).isoformat()
        elif isinstance(timestamp, datetime):
            ts_str = timestamp.isoformat()
        else:
            ts_str = timestamp

        payload = {
            "timestamp": ts_str,
            "device_id": device_id,
            "source_ip": resolved_ip,
            "method": method,
            "endpoint": endpoint,
            "response_code": response_code,
            "classification": classification,
        }
        return self.client.post("/api/logs", json=payload)

    def submit_event(
        self,
        event_type: str,
        severity: str = "warning",
        description: str = "Automated test security event",
        device_id: str | None = None,
        source_ip: str | None = ...,  # type: ignore
        request_count: int | None = None,
        time_window_seconds: int | None = None,
        metadata: dict[str, Any] | None = None,
        timestamp: datetime | str | None = None,
    ) -> Response:
        """Submit a manual security event to POST /api/events."""
        if device_id is None:
            device_id = self.default_device_id

        resolved_ip = self.default_ip if source_ip is ... else source_ip

        if timestamp is None:
            ts_str = datetime.now(timezone.utc).isoformat()
        elif isinstance(timestamp, datetime):
            ts_str = timestamp.isoformat()
        else:
            ts_str = timestamp

        payload = {
            "timestamp": ts_str,
            "device_id": device_id,
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "source_ip": resolved_ip,
            "request_count": request_count,
            "time_window_seconds": time_window_seconds,
            "metadata": metadata,
        }
        return self.client.post("/api/events", json=payload)

    def get_logs(self, **params) -> Response:
        """Fetch request logs with optional query params."""
        return self.client.get("/api/logs", params=params)

    def get_events(self, **params) -> Response:
        """Fetch security events with optional query params."""
        return self.client.get("/api/events", params=params)

    def get_stats(self) -> dict[str, Any]:
        """Fetch dashboard statistics dictionary."""
        res = self.client.get("/api/stats")
        assert res.status_code == 200
        return res.json()

    def get_device_status(self) -> dict[str, Any]:
        """Fetch device status dictionary."""
        res = self.client.get("/api/device/status")
        assert res.status_code == 200
        return res.json()

    def simulate_burst(
        self,
        count: int,
        endpoint: str = "/status",
        source_ip: str | None = ...,  # type: ignore
        device_id: str | None = None,
        interval_ms: int = 100,
        base_time: datetime | None = None,
    ) -> list[Response]:
        """Simulate a controlled sequence of request logs with deterministic timestamps."""
        if base_time is None:
            base_time = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

        responses = []
        for i in range(count):
            t = base_time + timedelta(milliseconds=i * interval_ms)
            res = self.submit_log(
                endpoint=endpoint,
                source_ip=source_ip,
                device_id=device_id,
                timestamp=t,
            )
            responses.append(res)
        return responses
