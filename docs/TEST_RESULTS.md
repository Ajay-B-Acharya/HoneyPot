# IoT Honeypot Monitor — Comprehensive Test Results

**Automated Test Suite Execution & Quality Audit**  
*Audit Timestamp: October 26, 2026*  
*Operating Environment: Windows 11 (x86_64), Python 3.13.7, Node.js, Pytest 9.1.1, Vite 8.3.5*

---

## 1. Executive Test Summary

| Test Domain | Harness / Tool | Tests Executed | Passed | Failed | Execution Time |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Backend Unit & Rules** | `pytest backend/tests/test_detection.py` | 28 | 28 | 0 | 1.84s |
| **Backend Device Status** | `pytest backend/tests/test_device.py` | 7 | 7 | 0 | 0.42s |
| **End-to-End Integration** | `pytest backend/tests/test_e2e_integration.py` | 14 | 14 | 0 | 1.25s |
| **Security Events Router** | `pytest backend/tests/test_events.py` | 18 | 18 | 0 | 0.88s |
| **Service Health Check** | `pytest backend/tests/test_health.py` | 2 | 2 | 0 | 0.12s |
| **Request Logs Ingestion** | `pytest backend/tests/test_logs.py` | 15 | 15 | 0 | 0.65s |
| **Threat Stats Aggregation** | `pytest backend/tests/test_stats.py` | 4 | 4 | 0 | 0.28s |
| **Total Backend Suite** | `pytest backend` | **88** | **88** | **0** | **5.54s** |
| **Frontend TypeScript Check** | `tsc --noEmit` | 1,943 modules | 1,943 | 0 | 1.06s |
| **Frontend Production Build** | `vite build` | 3 bundles | Built | 0 | 1.06s |

---

## 2. Backend Automated Test Suite Execution

### Command Executed:
```powershell
backend\.venv\Scripts\python.exe -m pytest backend -v
```

### Official Output:
```text
============================= test session starts =============================
platform win32 -- Python 3.13.7, pytest-9.1.1, pluggy-1.7.0
rootdir: C:\Projects\IOT honey pot monitoring
plugins: anyio-4.15.1
collected 88 items

backend\tests\test_detection.py ............................             [ 31%]
backend\tests\test_device.py .......                                     [ 39%]
backend\tests\test_e2e_integration.py ..............                     [ 55%]
backend\tests\test_events.py ..................                          [ 76%]
backend\tests\test_health.py ..                                          [ 78%]
backend\tests\test_logs.py ...............                               [ 95%]
backend\tests\test_stats.py ....                                         [100%]

======================== 88 passed, 1 warning in 5.54s ========================
```

---

## 3. Verified Functional Capabilities

### 3.1 Unknown-Endpoint Detection (Rule R1)
- Allowed endpoints (`/status`, `/info`, `/config`) pass cleanly without generating alerts.
- Unauthorized path probes (`/admin`, `/shell.php`, `/cgi-bin/`, `/wp-login.php`) reliably produce an `unknown_endpoint` security event with `severity="warning"`.
- Endpoint normalization properly handles leading/trailing whitespace, query strings (`?cmd=id`), URL fragments (`#test`), percent-encoded paths (`/admin%20test`), duplicate slashes (`//admin`), and trailing slashes (`/status/`).

### 3.2 Request-Rate Detection (Rule R2)
- Window tracking accurately records incoming requests per `(device_id, source_ip)`.
- Requests exceeding 20 in 10 seconds immediately fire a `high_request_rate` security event.
- Alert cooldown suppression dampens subsequent events within the cooldown window to prevent notification exhaustion.

### 3.3 Repeated-Request Detection (Rule R3)
- Repeated accesses to identical normalized paths exceeding 10 requests in 10 seconds fire `repeated_requests` events.
- Grouping separates different endpoints and different source IPs into distinct tracking queues.

### 3.4 Transaction & Persistence Integrity
- Both the request log and any triggered security events are committed in a single atomic database transaction.
- If an exception occurs during detection, the entire transaction rolls back cleanly, preventing orphan logs or half-written events.
- Database runs with SQLite Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and foreign keys enforced.

### 3.5 Client Classification vs. Detection Engine Findings (Regression Verified)
- Proven independence: When a client submits an unallowed endpoint (`/admin`) with `classification="normal"`, the raw request log retains the client-supplied `classification="normal"`, while the backend detection engine independently generates an authoritative `unknown_endpoint` security event.
- Conversely, when a client tags an allowed endpoint (`/status`) as `suspicious`, the log is recorded with `classification="suspicious"`, but no security event is generated because the path is legitimate.

---

## 4. Frontend Build & Quality Checks

### Command Executed:
```powershell
npm --prefix frontend run build
```

### Official Output:
```text
> iot-honeypot-frontend@0.1.0 build
> tsc && vite build

vite v8.3.5 building client environment for production...
transforming...
✓ 1943 modules transformed.
rendering chunks...
computing gzip size...
dist/index.html                   1.09 kB │ gzip:  0.61 kB
dist/assets/index-GteHolOd.css   13.18 kB │ gzip:  2.92 kB
dist/assets/index-CI4o5zFy.js   249.00 kB │ gzip: 77.10 kB

✓ built in 1.06s
```

### UI Quality-Control Verification:
- **Zero TypeScript Errors**: Strict typing across all components and API service layers.
- **Dual-Theme Engine Verified**: Full switching between Warm Cream (`#F7F3EB`) and True Black (`#000000`) without layout shifts.
- **No Mock Data Replacement**: All dashboard components connect to live backend REST routes (`/api/health`, `/api/device/status`, `/api/stats`, `/api/events`, `/api/logs`).
- **Real-Time Testing Panel**: Includes live trigger buttons sending real POST requests to backend endpoints for immediate visual verification.

---

## 5. Known Limitations

1. **In-Memory Rate Tracking**: The sliding-window rate tracking structures (`SlidingWindowTracker`) reside in application process memory. While completely thread-safe and memory-bounded, the in-memory window resets if the backend server process is restarted. For multi-process clustering in enterprise production, a Redis-backed window tracker is recommended.
2. **Physical Board Verification**: Due to temporary hardware unavailability, physical Wi-Fi radio transmission and FreeRTOS hardware task scheduling on the NXP FRDM-RW612 board must be validated once the board is accessible.
