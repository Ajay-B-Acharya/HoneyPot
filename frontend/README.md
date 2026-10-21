# IoT Honeypot Monitor — Frontend Testing Dashboard

Compact React + TypeScript testing dashboard for the **IoT Honeypot Monitor — Embedded Network Intrusion Detection System Using NXP FRDM-RW612**.

This testing dashboard provides immediate real-time visibility into the FastAPI backend, the integrated Python security detection engine, and recorded telemetry before physical deployment of the FRDM-RW612 microcontroller.

---

## Prerequisites

- **Node.js**: v18 or later (tested on v22)
- **npm**: v9 or later (tested on v11)
- **Backend**: FastAPI backend running on `http://127.0.0.1:8000`

---

## Quick Start

### Terminal 1: Start Backend

```powershell
cd "C:\Projects\IOT honey pot monitoring\backend"
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Terminal 2: Start Frontend

```powershell
cd "C:\Projects\IOT honey pot monitoring\frontend"

# Install dependencies
npm install

# Configure environment (copy template)
copy .env.example .env

# Run development server
npm run dev
```

Open your browser at **http://127.0.0.1:5173**.

---

## Configuration

The frontend communicates with the backend via Vite environment variables defined in `.env`:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api
```

Template file: `.env.example`

---

## Dashboard Sections & Features

1. **Backend Connection Status**
   - Polls `GET /api/health` to confirm backend service availability.
   - Distinct online/offline state indicator. Never falsely marks backend as online if unreachable.
   - Displays last successful refresh timestamp and manual **Refresh** button.
   - Optional automatic background refresh every 5 seconds (toggleable).

2. **Hardware Device Status**
   - Polls `GET /api/device/status`.
   - Distinguishes backend service availability from physical device connectivity.
   - If the FRDM-RW612 is not connected, clearly displays `FRDM-RW612 Not Connected` and `Hardware awaiting deployment`.

3. **Statistics Overview**
   - Polls `GET /api/stats`.
   - Displays real backend aggregations: Total Requests, Security Events, Suspicious Requests, and Normal Requests.

4. **Security Events Table**
   - Queries `GET /api/events`.
   - Displays real-time intrusion events with timestamp, event type, severity badges (`critical`, `warning`, `informational`), target endpoint, source IP, and detection descriptions.
   - Full empty state and loading state support.

5. **HTTP Request Logs Table**
   - Queries `GET /api/logs`.
   - Displays incoming requests with HTTP method, requested endpoint, source IP, response code, and classification.

6. **Backend Detection Testing Panel**
   - **Normal Log (`/status`)**: Submits an allowed request log via `POST /api/logs`. Verifies clean ingestion with zero alerts.
   - **Probe Unknown (`/admin`)**: Submits an unallowed endpoint request via `POST /api/logs`. Demonstrates Rule R1 automatic detection and creates an `unknown_endpoint` security event in SQLite.
   - **Traffic Burst (5x)**: Rapid sequential requests to test sliding-window rate tracking.
   - **Manual Critical Event**: Submits a direct hardware enclosure tamper event via `POST /api/events`.

---

## Backend Endpoints Consumed

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Backend health and service verification |
| `/api/stats` | GET | Aggregated requests and security event metrics |
| `/api/device/status` | GET | Hardware device connectivity status |
| `/api/events` | GET, POST | List and create security event records |
| `/api/logs` | GET, POST | List and create HTTP request logs (triggers detection engine) |

---

## How to Verify Real Backend Data

1. Start both backend and frontend.
2. In the testing panel, click **Probe Unknown (`/admin`)**.
3. Observe feedback: `Log #X recorded... backend detection engine generated 'unknown_endpoint'`.
4. The dashboard automatically refreshes:
   - Security Events table immediately displays the new `unknown_endpoint` event with `warning` severity.
   - Statistics card increments `Total Security Events` by 1.
   - Request Logs table displays the `/admin` entry.
5. Cross-check in browser at `http://127.0.0.1:8000/docs` (Swagger UI): `GET /api/events` returns the exact same record.

---

## Known Limitations

- **Prototype In-Memory Tracking**: Detection engine rate limits and sliding windows reset when the Python backend restarts.
- **Physical Board Status**: Device status displays `FRDM-RW612 Not Connected` until physical firmware sends its first HTTP request to `/api/logs`.
- **Production Scaling**: Designed for local development and verification; multi-worker production deployments should back rate tracking with Redis.
