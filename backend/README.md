# IoT Honeypot Monitor — Backend

FastAPI backend for the IoT Honeypot Monitor system.

## Quick Start

### Prerequisites

- Python 3.11 or later

### Setup

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (macOS/Linux)
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create configuration
copy .env.example .env
```

### Run the Server

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The API will be available at:
- **API**: http://127.0.0.1:8000/api
- **Swagger UI**: http://127.0.0.1:8000/docs
- **ReDoc**: http://127.0.0.1:8000/redoc

### Run Tests

```bash
pytest -v
```

## Configuration

Copy `.env.example` to `.env` and adjust values:

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | `iot-honeypot-backend` | Application name |
| `APP_VERSION` | `0.1.0` | Application version |
| `DEBUG` | `false` | Enable debug logging |
| `DATABASE_URL` | `sqlite:///./honeypot.db` | Database connection string |
| `CORS_ORIGINS` | `http://localhost:5173,...` | Allowed frontend origins |
| `DEVICE_INACTIVE_THRESHOLD_SECONDS` | `300` | Inactive device threshold |
| `DETECTION_ALLOWED_ENDPOINTS` | `/status,/info,/config` | Comma-separated allowlist of valid endpoints |
| `DETECTION_RATE_THRESHOLD` | `20` | Request threshold for high request rate alert (`count >= threshold`) |
| `DETECTION_RATE_WINDOW_SECONDS` | `10` | Time window in seconds for request rate monitoring |
| `DETECTION_RATE_COOLDOWN_SECONDS` | `10` | Alert cooldown in seconds for request rate alerts |
| `DETECTION_REPEATED_THRESHOLD` | `10` | Repeated requests threshold to same endpoint (`count >= threshold`) |
| `DETECTION_REPEATED_WINDOW_SECONDS` | `10` | Time window in seconds for repeated requests |
| `DETECTION_REPEATED_COOLDOWN_SECONDS` | `10` | Alert cooldown in seconds for repeated request alerts |
| `DETECTION_MAX_TRACKING_ENTRIES` | `10000` | Maximum in-memory tracking entries before eviction |
| `DETECTION_TRACKING_EXPIRATION_SECONDS` | `60` | Inactive entry expiration duration in seconds |

## Security Detection Engine

The backend includes an integrated, modular security detection engine (`app/services/detection_service.py`). When HTTP request logs are recorded via `POST /api/logs`, the detection engine evaluates the request metadata against active detection rules and automatically generates `SecurityEvent` records stored atomically in the database.

### Detection Rules

1. **Rule R1: Unknown Endpoint Detection (`unknown_endpoint`)**
   - **Purpose**: Detect requests targeting endpoints that are not in the configured allowlist.
   - **Allowed Endpoints**: Default `/status`, `/info`, `/config` (configured via `DETECTION_ALLOWED_ENDPOINTS`).
   - **Normalization**: Paths are stripped of query strings and URL fragments, URL percent-decodings are resolved safely, consecutive slashes collapsed, and trailing slashes stripped. Exact path matching is enforced to prevent loose prefix matching bypasses.
   - **Severity**: `warning`.
   - **Distinction**: Unusual endpoint requests indicate reconnaissance or scanning, but are not automatically classified as confirmed breaches.

2. **Rule R2: Request-Rate Monitoring (`high_request_rate`)**
   - **Purpose**: Identify volumetric floods or rapid scanning from a single source or device.
   - **Threshold**: Exceeded when requests in the rolling time window reach or exceed `DETECTION_RATE_THRESHOLD` (`count >= 20` in 10s by default).
   - **Grouping**: Grouped primarily by `(device_id, source_ip)`. Requests without a source IP are safely grouped under `unknown_source`.
   - **Alert Throttling**: A configurable cooldown period (`DETECTION_RATE_COOLDOWN_SECONDS`) prevents alert floods on every subsequent request after the threshold is crossed.
   - **Severity**: `warning`.

3. **Rule R3: Repeated Request Monitoring (`repeated_requests`)**
   - **Purpose**: Detect anomalous loops, endpoint hammering, or brute force attempts targeting a specific endpoint.
   - **Threshold**: Exceeded when requests to the same endpoint from a source reach or exceed `DETECTION_REPEATED_THRESHOLD` (`count >= 10` in 10s by default).
   - **Grouping**: Grouped by `(device_id, source_ip, normalized_endpoint)`.
   - **Alert Throttling**: Configurable cooldown (`DETECTION_REPEATED_COOLDOWN_SECONDS`) suppresses duplicate alerts.
   - **Severity**: `warning`.

4. **Rule R4: Malformed Request Metadata Safe Handling**
   - **Safe Rejection**: Schema validation rejects invalid HTTP methods, malformed endpoint formats (missing leading slash, null bytes, control characters), invalid response codes (< 100 or > 599), and malformed types with HTTP 422 before database insertion, preventing database corruption.
   - **Layer Distinction**:
     - *Tier A*: Invalid JSON or schema payloads rejected at the FastAPI/Starlette layer (HTTP 422/400).
     - *Tier B*: Application-layer metadata evaluated and normalized by the detection engine.
     - *Tier C*: Raw malformed HTTP traffic (e.g., corrupted TCP/IP packets or invalid raw HTTP request lines) handled at the web server (Uvicorn) or embedded firmware (lwIP) layer.

### In-Memory Tracking Limitations

- **Process Lifetime**: In-memory rate counters and cooldowns reset whenever the backend restarts.
- **Worker Isolation**: In multi-worker deployments (e.g. `uvicorn --workers 4`), each worker maintains its own independent in-memory state.
- **Production Scaling**: For distributed multi-worker deployments, a centralized caching layer (such as Redis) should be introduced for synchronized sliding-window rate tracking.

### Embedded Hardware Compatibility (NXP FRDM-RW612)

This architecture is designed for eventual deployment on the **NXP FRDM-RW612** microcontroller:
- **Rule R1 in Embedded C**: Lightweight string comparison (`strcmp`) or trie against allowed paths (`/status`, `/info`, `/config`) can run directly in FreeRTOS tasks with minimal RAM.
- **Rule R2/R3 in Embedded C**: Fixed-size static ring buffers tracking active IP counters using FreeRTOS tick counts (`xTaskGetTickCount()`) with strictly bounded SRAM usage.
- **Rule R4 in Embedded C**: The embedded HTTP server (lwIP) will reject raw malformed HTTP requests at the socket level and can emit compact security events directly to the backend.

## Project Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI application factory
│   ├── config.py         # Settings from environment
│   ├── database.py       # SQLAlchemy engine and session
│   ├── models/           # ORM models
│   ├── schemas/          # Pydantic validation schemas
│   ├── routers/          # API endpoint handlers
│   └── services/         # Business logic layer
├── tests/                # Automated test suite
├── .env.example          # Environment template
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

## Database

SQLite is used for development. The database file (`honeypot.db`) is created automatically on first startup.

To switch to PostgreSQL, update `DATABASE_URL` in `.env`:
```
DATABASE_URL=postgresql://user:password@localhost:5432/honeypot
```

> [!WARNING]
> This prototype is intended for a trusted development environment.
> Access control and authenticated device communication must be implemented
> before broader deployment. Do not expose the API directly to the public internet.
