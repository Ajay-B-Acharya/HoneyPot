# IoT Honeypot Monitor — API Contract

> [!IMPORTANT]
> This document defines the REST API contract between the backend and frontend.
> Both developers must keep this document synchronized with any API changes.

## Base URL

```
http://127.0.0.1:8000/api
```

The frontend should configure this via environment variable:
```
VITE_API_BASE_URL=http://127.0.0.1:8000/api
```

## General Conventions

- **Timestamps**: ISO 8601 format with UTC timezone (`2026-10-20T06:30:00+00:00`)
- **Field naming**: `snake_case` for all JSON fields
- **Nullable fields**: Represented as `null` in JSON (never omitted)
- **Empty collections**: Represented as `[]` (never `null`)
- **Pagination**: All list endpoints use `skip` and `limit` parameters

## Error Response Format

All errors follow this structure:

```json
{
  "detail": "Human-readable error message",
  "status_code": 400
}
```

For validation errors (422):
```json
{
  "detail": [
    {
      "loc": ["body", "field_name"],
      "msg": "Error description",
      "type": "error_type"
    }
  ]
}
```

## HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200  | Successful retrieval |
| 201  | Resource created |
| 400  | Invalid query parameters (e.g., start_time > end_time) |
| 422  | Request body validation failure |
| 500  | Internal server error |

---

## Endpoints

### 1. Health Check

**`GET /api/health`**

Returns the service health status.

**Response** `200 OK`:
```json
{
  "status": "ok",
  "service": "iot-honeypot-backend"
}
```

---

### 2. Security Events

#### Create Event

**`POST /api/events`**

Record a new security event.

**Request Body**:
```json
{
  "timestamp": "2026-10-20T06:30:00Z",
  "device_id": "rw612-security-01",
  "event_type": "unknown_endpoint",
  "severity": "warning",
  "description": "Request received for an unknown endpoint",
  "source_ip": "192.168.1.25",
  "request_count": null,
  "time_window_seconds": null,
  "metadata": {
    "endpoint": "/admin",
    "method": "GET"
  }
}
```

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `timestamp` | string (ISO 8601) | Yes | UTC timestamp |
| `device_id` | string | Yes | 1–128 characters |
| `event_type` | string | Yes | 1–64 characters |
| `severity` | string (enum) | Yes | `informational`, `warning`, `critical` |
| `description` | string | Yes | Non-empty |
| `source_ip` | string \| null | No | Max 45 characters |
| `request_count` | integer \| null | No | >= 0 |
| `time_window_seconds` | integer \| null | No | >= 0 |
| `metadata` | object \| null | No | Arbitrary JSON object |

**Response** `201 Created`:
```json
{
  "id": 1,
  "timestamp": "2026-10-20T06:30:00+00:00",
  "device_id": "rw612-security-01",
  "event_type": "unknown_endpoint",
  "severity": "warning",
  "description": "Request received for an unknown endpoint",
  "source_ip": "192.168.1.25",
  "request_count": null,
  "time_window_seconds": null,
  "metadata": {
    "endpoint": "/admin",
    "method": "GET"
  },
  "created_at": "2026-10-20T07:01:00+00:00"
}
```

#### List Events

**`GET /api/events`**

Retrieve security events with optional filtering and pagination.

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `skip` | integer | 0 | Records to skip (>= 0) |
| `limit` | integer | 20 | Max records to return (1–100) |
| `severity` | string | — | Filter: `informational`, `warning`, `critical` |
| `event_type` | string | — | Filter by event type |
| `device_id` | string | — | Filter by device ID |
| `start_time` | string (ISO 8601) | — | Events after this time |
| `end_time` | string (ISO 8601) | — | Events before this time |

**Response** `200 OK`:
```json
{
  "items": [
    {
      "id": 1,
      "timestamp": "2026-10-20T06:30:00+00:00",
      "device_id": "rw612-security-01",
      "event_type": "unknown_endpoint",
      "severity": "warning",
      "description": "Request received for an unknown endpoint",
      "source_ip": "192.168.1.25",
      "request_count": null,
      "time_window_seconds": null,
      "metadata": {"endpoint": "/admin", "method": "GET"},
      "created_at": "2026-10-20T07:01:00+00:00"
    }
  ],
  "total": 1,
  "skip": 0,
  "limit": 20
}
```

**Error** `400 Bad Request` (if `start_time` > `end_time`):
```json
{
  "detail": "start_time must be before end_time"
}
```

---

### 3. Request Logs

#### Create Log

**`POST /api/logs`**

Record a new HTTP request log.

**Request Body**:
```json
{
  "timestamp": "2026-10-20T06:30:00Z",
  "device_id": "rw612-security-01",
  "source_ip": "192.168.1.25",
  "method": "GET",
  "endpoint": "/status",
  "response_code": 200,
  "classification": "normal"
}
```

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `timestamp` | string (ISO 8601) | Yes | UTC timestamp |
| `device_id` | string | Yes | 1–128 characters |
| `source_ip` | string \| null | No | Max 45 characters |
| `method` | string | Yes | 1–10 characters |
| `endpoint` | string | Yes | 1–512 characters |
| `response_code` | integer \| null | No | 100–599 |
| `classification` | string (enum) | Yes | `normal`, `unusual`, `suspicious` |

**Response** `201 Created`:
```json
{
  "id": 1,
  "timestamp": "2026-10-20T06:30:00+00:00",
  "device_id": "rw612-security-01",
  "source_ip": "192.168.1.25",
  "method": "GET",
  "endpoint": "/status",
  "response_code": 200,
  "classification": "normal",
  "created_at": "2026-10-20T07:01:00+00:00"
}
```

#### List Logs

**`GET /api/logs`**

Retrieve request logs with optional filtering and pagination.

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `skip` | integer | 0 | Records to skip (>= 0) |
| `limit` | integer | 20 | Max records to return (1–100) |
| `classification` | string | — | Filter: `normal`, `unusual`, `suspicious` |
| `device_id` | string | — | Filter by device ID |
| `start_time` | string (ISO 8601) | — | Logs after this time |
| `end_time` | string (ISO 8601) | — | Logs before this time |

**Response** `200 OK`:
```json
{
  "items": [
    {
      "id": 1,
      "timestamp": "2026-10-20T06:30:00+00:00",
      "device_id": "rw612-security-01",
      "source_ip": "192.168.1.25",
      "method": "GET",
      "endpoint": "/status",
      "response_code": 200,
      "classification": "normal",
      "created_at": "2026-10-20T07:01:00+00:00"
    }
  ],
  "total": 1,
  "skip": 0,
  "limit": 20
}
```

---

### 4. Statistics

**`GET /api/stats`**

Returns aggregated dashboard statistics.

**Response** `200 OK`:
```json
{
  "total_requests": 0,
  "normal_requests": 0,
  "unusual_requests": 0,
  "suspicious_requests": 0,
  "total_security_events": 0,
  "events_by_severity": {
    "informational": 0,
    "warning": 0,
    "critical": 0
  },
  "requests_by_classification": {
    "normal": 0,
    "unusual": 0,
    "suspicious": 0
  }
}
```

All fields are always present. Values default to `0` when no data exists.

---

### 5. Device Status

**`GET /api/device/status`**

Returns status information for all known devices.

> [!NOTE]
> Device status is derived from the most recent activity (request logs and
> security events). It does NOT represent real-time connectivity. A device
> shown as "active" simply sent data recently. For reliable connectivity
> monitoring, implement a dedicated heartbeat mechanism.

**Response** `200 OK`:
```json
{
  "devices": [
    {
      "device_id": "rw612-security-01",
      "status": "active",
      "last_seen": "2026-10-20T06:30:00+00:00",
      "last_activity": "2026-10-20T06:30:00+00:00"
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `device_id` | string | Device identifier |
| `status` | string | `active`, `inactive`, or `unknown` |
| `last_seen` | string \| null | ISO 8601 timestamp of most recent activity |
| `last_activity` | string \| null | Same as `last_seen` (provided for convenience) |

Status determination:
- **`active`**: Device seen within the last 300 seconds (configurable)
- **`inactive`**: Device not seen within the threshold
- **`unknown`**: No recorded activity for this device

When no devices exist, returns `{"devices": []}`.

---

## Enum Values Reference

### Severity
- `informational`
- `warning`
- `critical`

### Classification
- `normal`
- `unusual`
- `suspicious`

### Device Status
- `active`
- `inactive`
- `unknown`

### Standard Security Event Types
- `unknown_endpoint`: Generated when a request targets an endpoint outside the allowlist (`/status`, `/info`, `/config`).
- `high_request_rate`: Generated when an IP/device exceeds the request rate threshold (default: >= 20 requests in 10s).
- `repeated_requests`: Generated when requests to the same endpoint exceed the repetition threshold (default: >= 10 requests in 10s).
- Custom events (e.g. `scan_detected`, `brute_force_attempt`, `tamper_detected`) submitted manually via `POST /api/events`.

---

## Client Classification vs. Automated Security Events

A critical architectural principle of the IoT Honeypot Monitor is the **strict separation** between client-supplied telemetry classifications and authoritative security events:

| Characteristic | Client Request Classification (`POST /api/logs`) | Automated Security Events (`SecurityEvent`) |
| :--- | :--- | :--- |
| **Origin** | Reported by the client or IoT device firmware in the `classification` field (`normal`, `unusual`, `suspicious`). | Generated authoritatively by the backend Detection Engine upon evaluating ingested telemetry against security rules. |
| **Trust Level** | Untrusted / Informational edge telemetry. The backend does not trust the edge device to assess its own compromise. | Authoritative and verifiable. Evaluated server-side using strict pattern and rate thresholds. |
| **Trigger Mechanism** | Set by client when sending request log payload. | Triggered automatically when rule thresholds (R1 unknown endpoint, R2 high rate, R3 repeated probe) are met. |
| **Storage Table** | `request_logs` (`classification` column). | `security_events` (`event_type`, `severity`, `description`, `metadata_json`). |
| **Impact on Stats** | Increments `requests_by_classification` counts. | Increments `events_by_severity` and `total_security_events`. |
| **Independence Proof** | If a client logs an attack probe to `/admin` but tags it as `normal`, the log preserves `classification="normal"`, but the engine generates an authoritative `unknown_endpoint` security event with `severity="warning"`. | If a client tags a clean request to `/status` as `suspicious`, the log stores `suspicious`, but no security event is generated by the engine. |

