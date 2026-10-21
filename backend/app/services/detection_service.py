"""Security detection engine service.

Implements modular security detection rules for the IoT Honeypot Monitor:
- Rule R1: Unknown endpoint detection (configurable allowlist, safe path normalization)
- Rule R2: Request-rate monitoring (configurable threshold, rolling time window, alert cooldown)
- Rule R3: Repeated request monitoring (endpoint grouping, sliding window, alert cooldown)
- Rule R4: Safe validation for malformed request metadata

Evaluates request metadata and generates SecurityEvent models.
Designed to run in Python backend while maintaining algorithmic simplicity
suitable for future embedded C implementation on the NXP FRDM-RW612.
"""

from collections import deque
from datetime import datetime, timezone
import json
import re
import threading
import time
import urllib.parse
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.models.request_log import RequestLog
from app.models.security_event import SecurityEvent
from app.schemas.security_event import SecurityEventCreate, SeverityEnum


def normalize_endpoint(endpoint: str | None) -> str:
    """Normalize an HTTP endpoint path safely.

    - Handles None or empty paths safely by defaulting to '/'
    - Strips leading and trailing whitespace
    - Strips query parameters (?query=...) and fragments (#section) safely
    - Safely unquotes percent-encoded paths (e.g. %20 -> space)
    - Ensures leading slash
    - Collapses consecutive slashes (e.g. '//admin' -> '/admin')
    - Strips trailing slash unless the path is root '/'

    Args:
        endpoint: Raw endpoint string.

    Returns:
        Canonical normalized path string.
    """
    if not endpoint:
        return "/"

    cleaned = endpoint.strip()
    if not cleaned:
        return "/"

    # urlsplit safely separates path from query string and fragment
    split_result = urllib.parse.urlsplit(cleaned)
    path = split_result.path

    if not path:
        path = "/"

    # URL-decode percent-encoded characters safely
    path = urllib.parse.unquote(path)

    # Ensure leading slash
    if not path.startswith("/"):
        path = "/" + path

    # Collapse consecutive slashes
    path = re.sub(r"/+", "/", path)

    # Strip trailing slash unless root '/'
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    return path


class SlidingWindowTracker:
    """Thread-safe, bounded in-memory sliding window tracker.

    Tracks timestamps for grouping keys and manages alert cooldowns.
    Periodically expires old entries and enforces memory bounds.

    Limitations:
    - In-memory state resets when the backend process restarts.
    - Multiple backend worker processes maintain separate in-memory state.
    - Production multi-worker deployments require centralized state (e.g. Redis).
    """

    def __init__(self, max_entries: int = 10000, expiration_seconds: int = 60):
        self._lock = threading.Lock()
        self._requests: dict[Any, deque[float]] = {}
        self._cooldowns: dict[Any, float] = {}
        self._max_entries = max_entries
        self._expiration_seconds = expiration_seconds

    def record_and_check(
        self,
        key: Any,
        current_time: float,
        window_seconds: int,
        threshold: int,
        cooldown_seconds: int,
    ) -> tuple[bool, int]:
        """Record an event timestamp and check if the threshold is reached or exceeded.

        Threshold condition: count >= threshold.

        Args:
            key: Grouping key (e.g. tuple).
            current_time: Current timestamp (seconds since epoch).
            window_seconds: Sliding window duration in seconds.
            threshold: Minimum request count to trigger an alert (count >= threshold).
            cooldown_seconds: Minimum seconds before a duplicate alert can fire for this key.

        Returns:
            Tuple of (should_alert: bool, current_window_count: int).
        """
        with self._lock:
            # 1. Clean up overall state if table exceeds maximum bound
            if len(self._requests) >= self._max_entries:
                self._evict_expired(current_time)
                if len(self._requests) >= self._max_entries:
                    # Pop the oldest entry to strictly preserve memory bounds
                    oldest_key = next(iter(self._requests))
                    del self._requests[oldest_key]
                    self._cooldowns.pop(oldest_key, None)

            # 2. Get or create deque for this key
            deq = self._requests.setdefault(key, deque())

            # 3. Discard timestamps outside sliding window
            cutoff = current_time - window_seconds
            while deq and deq[0] < cutoff:
                deq.popleft()

            # 4. Add current event timestamp
            deq.append(current_time)
            count = len(deq)

            # 5. Evaluate threshold and cooldown
            should_alert = False
            if count >= threshold:
                last_alert = self._cooldowns.get(key)
                if last_alert is None or (current_time - last_alert) >= cooldown_seconds:
                    should_alert = True
                    self._cooldowns[key] = current_time

            return should_alert, count

    def _evict_expired(self, current_time: float) -> None:
        """Internal helper to remove expired tracking entries."""
        cutoff = current_time - self._expiration_seconds
        expired_keys = []
        for key, deq in self._requests.items():
            while deq and deq[0] < cutoff:
                deq.popleft()
            last_alert = self._cooldowns.get(key, 0)
            if not deq and last_alert < cutoff:
                expired_keys.append(key)

        for key in expired_keys:
            del self._requests[key]
            self._cooldowns.pop(key, None)

    def cleanup_expired(self, current_time: float) -> int:
        """Explicitly purge expired entries. Returns count of purged keys."""
        with self._lock:
            before_count = len(self._requests)
            self._evict_expired(current_time)
            return before_count - len(self._requests)

    def reset(self) -> None:
        """Clear all tracking state."""
        with self._lock:
            self._requests.clear()
            self._cooldowns.clear()

    @property
    def entry_count(self) -> int:
        """Return the number of tracked keys."""
        with self._lock:
            return len(self._requests)


class DetectionService:
    """Security detection engine.

    Evaluates request logs against detection rules and creates security events.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        clock: Callable[[], float] | None = None,
    ):
        self._settings = settings or get_settings()
        self._clock = clock or time.time
        self._rate_tracker = SlidingWindowTracker(
            max_entries=self._settings.DETECTION_MAX_TRACKING_ENTRIES,
            expiration_seconds=self._settings.DETECTION_TRACKING_EXPIRATION_SECONDS,
        )
        self._repeated_tracker = SlidingWindowTracker(
            max_entries=self._settings.DETECTION_MAX_TRACKING_ENTRIES,
            expiration_seconds=self._settings.DETECTION_TRACKING_EXPIRATION_SECONDS,
        )

    @property
    def allowed_endpoints(self) -> set[str]:
        """Return set of normalized allowed endpoints."""
        raw_list = self._settings.detection_allowed_endpoints_set
        return {normalize_endpoint(ep) for ep in raw_list}

    def _resolve_timestamp(
        self,
        log: RequestLog | Any,
        explicit_time: float | None = None,
    ) -> tuple[datetime, float]:
        """Resolve event datetime and epoch timestamp."""
        if explicit_time is not None:
            dt = datetime.fromtimestamp(explicit_time, tz=timezone.utc)
            return dt, explicit_time

        log_ts = getattr(log, "timestamp", None)
        if isinstance(log_ts, datetime):
            # Ensure timezone awareness
            if log_ts.tzinfo is None:
                log_ts = log_ts.replace(tzinfo=timezone.utc)
            return log_ts, log_ts.timestamp()

        now_sec = self._clock()
        return datetime.fromtimestamp(now_sec, tz=timezone.utc), now_sec

    def evaluate_request(
        self,
        log: RequestLog | Any,
        current_time: float | None = None,
    ) -> list[SecurityEventCreate]:
        """Evaluate a request log against all active detection rules.

        Rules evaluated:
        - R1: Unknown Endpoint Detection
        - R2: High Request Rate Detection
        - R3: Repeated Request Detection

        Args:
            log: Request log model or schema instance.
            current_time: Optional explicit timestamp (epoch seconds) for deterministic testing.

        Returns:
            List of generated SecurityEventCreate schemas.
        """
        generated_events: list[SecurityEventCreate] = []
        event_dt, epoch_sec = self._resolve_timestamp(log, current_time)

        device_id = getattr(log, "device_id", "unknown_device")
        source_ip = getattr(log, "source_ip", None)
        raw_endpoint = getattr(log, "endpoint", "/")
        method = getattr(log, "method", "UNKNOWN")

        normalized_ep = normalize_endpoint(raw_endpoint)

        # ---------------------------------------------------------------------
        # RULE R1: Unknown Endpoint Detection
        # ---------------------------------------------------------------------
        # Checks if normalized endpoint is in the configured allowlist.
        # Exact match is enforced to avoid loose prefix vulnerabilities.
        # Query strings and trailing slashes are safely normalized beforehand.
        # ---------------------------------------------------------------------
        if normalized_ep not in self.allowed_endpoints:
            r1_event = SecurityEventCreate(
                timestamp=event_dt,
                device_id=device_id,
                event_type="unknown_endpoint",
                severity=SeverityEnum.warning,
                description=f"Request received for unknown endpoint: '{normalized_ep}'",
                source_ip=source_ip,
                request_count=None,
                time_window_seconds=None,
                metadata={
                    "endpoint": raw_endpoint,
                    "normalized_endpoint": normalized_ep,
                    "method": method,
                },
            )
            generated_events.append(r1_event)

        # ---------------------------------------------------------------------
        # RULE R2: High Request-Rate Detection
        # ---------------------------------------------------------------------
        # Tracks request frequency over a rolling time window.
        # Primary grouping: (device_id, source_ip). Missing IPs handled safely.
        # Condition: count >= threshold.
        # Alert cooldown prevents flooding on every subsequent request.
        # ---------------------------------------------------------------------
        ip_group = source_ip if source_ip else "unknown_source"
        rate_key = (device_id, ip_group)

        should_rate_alert, rate_count = self._rate_tracker.record_and_check(
            key=rate_key,
            current_time=epoch_sec,
            window_seconds=self._settings.DETECTION_RATE_WINDOW_SECONDS,
            threshold=self._settings.DETECTION_RATE_THRESHOLD,
            cooldown_seconds=self._settings.DETECTION_RATE_COOLDOWN_SECONDS,
        )

        if should_rate_alert:
            source_label = source_ip if source_ip else "unknown source"
            r2_event = SecurityEventCreate(
                timestamp=event_dt,
                device_id=device_id,
                event_type="high_request_rate",
                severity=SeverityEnum.warning,
                description=(
                    f"High request rate detected from {source_label}: "
                    f"{rate_count} requests in {self._settings.DETECTION_RATE_WINDOW_SECONDS}s "
                    f"(threshold: {self._settings.DETECTION_RATE_THRESHOLD})"
                ),
                source_ip=source_ip,
                request_count=rate_count,
                time_window_seconds=self._settings.DETECTION_RATE_WINDOW_SECONDS,
                metadata={
                    "threshold": self._settings.DETECTION_RATE_THRESHOLD,
                    "time_window_seconds": self._settings.DETECTION_RATE_WINDOW_SECONDS,
                    "request_count": rate_count,
                    "device_id": device_id,
                    "source_ip": source_ip,
                },
            )
            generated_events.append(r2_event)

        # ---------------------------------------------------------------------
        # RULE R3: Repeated Request Detection
        # ---------------------------------------------------------------------
        # Tracks repeated requests to the same endpoint within a sliding window.
        # Grouping key: (device_id, source_ip, normalized_endpoint).
        # Condition: count >= threshold.
        # Alert cooldown prevents duplicate alert floods.
        # ---------------------------------------------------------------------
        repeated_key = (device_id, ip_group, normalized_ep)

        should_repeated_alert, rep_count = self._repeated_tracker.record_and_check(
            key=repeated_key,
            current_time=epoch_sec,
            window_seconds=self._settings.DETECTION_REPEATED_WINDOW_SECONDS,
            threshold=self._settings.DETECTION_REPEATED_THRESHOLD,
            cooldown_seconds=self._settings.DETECTION_REPEATED_COOLDOWN_SECONDS,
        )

        if should_repeated_alert:
            r3_event = SecurityEventCreate(
                timestamp=event_dt,
                device_id=device_id,
                event_type="repeated_requests",
                severity=SeverityEnum.warning,
                description=(
                    f"Repeated requests detected for endpoint '{normalized_ep}': "
                    f"{rep_count} requests in {self._settings.DETECTION_REPEATED_WINDOW_SECONDS}s "
                    f"(threshold: {self._settings.DETECTION_REPEATED_THRESHOLD})"
                ),
                source_ip=source_ip,
                request_count=rep_count,
                time_window_seconds=self._settings.DETECTION_REPEATED_WINDOW_SECONDS,
                metadata={
                    "endpoint": raw_endpoint,
                    "normalized_endpoint": normalized_ep,
                    "request_count": rep_count,
                    "threshold": self._settings.DETECTION_REPEATED_THRESHOLD,
                    "time_window_seconds": self._settings.DETECTION_REPEATED_WINDOW_SECONDS,
                    "device_id": device_id,
                    "source_ip": source_ip,
                },
            )
            generated_events.append(r3_event)

        return generated_events

    def process_request_log(
        self,
        db: Session,
        log: RequestLog,
        current_time: float | None = None,
    ) -> list[SecurityEvent]:
        """Evaluate rules and add generated security event models to the DB session.

        Does NOT commit the session directly. Allows atomic commit by the caller.

        Args:
            db: Database session.
            log: Created RequestLog ORM instance.
            current_time: Optional explicit timestamp.

        Returns:
            List of created SecurityEvent ORM instances.
        """
        event_schemas = self.evaluate_request(log, current_time=current_time)
        created_events: list[SecurityEvent] = []

        for schema in event_schemas:
            db_event = SecurityEvent(
                timestamp=schema.timestamp,
                device_id=schema.device_id,
                event_type=schema.event_type,
                severity=schema.severity.value,
                description=schema.description,
                source_ip=schema.source_ip,
                request_count=schema.request_count,
                time_window_seconds=schema.time_window_seconds,
                metadata_json=json.dumps(schema.metadata) if schema.metadata else None,
            )
            db.add(db_event)
            created_events.append(db_event)

        return created_events

    def reset_state(self) -> None:
        """Reset internal in-memory trackers."""
        self._rate_tracker.reset()
        self._repeated_tracker.reset()


# Singleton instance
_detection_service_instance: DetectionService | None = None
_instance_lock = threading.Lock()


def get_detection_service(settings: Settings | None = None) -> DetectionService:
    """Return the global detection service instance."""
    global _detection_service_instance
    with _instance_lock:
        if _detection_service_instance is None or settings is not None:
            _detection_service_instance = DetectionService(settings=settings)
        return _detection_service_instance


def reset_detection_service() -> None:
    """Reset the singleton instance and clear its trackers."""
    global _detection_service_instance
    with _instance_lock:
        if _detection_service_instance is not None:
            _detection_service_instance.reset_state()
            _detection_service_instance = None
