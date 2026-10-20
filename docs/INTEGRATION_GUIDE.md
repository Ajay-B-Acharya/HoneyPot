# IoT Honeypot Monitor — Frontend Integration Guide

This guide helps the frontend developer connect a React + TypeScript dashboard to the backend API **without needing to inspect or understand the backend Python source code**.

---

## 1. Quick Start: Running the Backend

Ensure Python 3.11+ is installed.

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Windows (cmd):
venv\Scripts\activate.bat
# Linux/macOS:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create environment configuration from example template
copy .env.example .env     # Windows
# cp .env.example .env     # Linux/macOS

# Run the development server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Verify the backend is live:
```bash
curl http://127.0.0.1:8000/api/health
# Response: {"status":"ok","service":"iot-honeypot-backend"}
```

Or open interactive Swagger documentation in your browser:
- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 2. Configuring Frontend API Base URL

In your React/Vite project (inside `frontend/`), set up an environment file (`.env`):

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api
```

In your frontend code, reference it with fallback:

```typescript
export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api";
```

> [!NOTE]
> The backend does not depend on Vite or frontend environment files. The backend serves endpoints under `/api`.

---

## 3. TypeScript Interfaces for the Frontend

You can directly copy these TypeScript types into your frontend project (e.g. `src/types/api.ts`):

```typescript
// =============================================================================
// IoT Honeypot Monitor API Types
// =============================================================================

/** Health Check Response */
export interface HealthResponse {
  status: string;
  service: string;
}

/** Severity enum for security events */
export type EventSeverity = "informational" | "warning" | "critical";

/** Classification enum for request logs */
export type RequestClassification = "normal" | "unusual" | "suspicious";

/** Device connectivity status */
export type DeviceState = "active" | "inactive" | "unknown";

/** Request Log model */
export interface RequestLog {
  id: number;
  timestamp: string; // ISO 8601 UTC string (e.g. "2026-10-20T06:30:00+00:00")
  device_id: string;
  source_ip: string | null;
  method: string;
  endpoint: string;
  response_code: number | null;
  classification: RequestClassification;
  created_at: string; // ISO 8601 UTC string
}

/** Security Event model */
export interface SecurityEvent {
  id: number;
  timestamp: string; // ISO 8601 UTC string
  device_id: string;
  event_type: string;
  severity: EventSeverity;
  description: string;
  source_ip: string | null;
  request_count: number | null;
  time_window_seconds: number | null;
  metadata: Record<string, unknown> | null;
  created_at: string; // ISO 8601 UTC string
}

/** Generic Paginated List Envelope */
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  skip: number;
  limit: number;
}

/** Events breakdown by severity */
export interface EventsBySeverity {
  informational: number;
  warning: number;
  critical: number;
}

/** Requests breakdown by classification */
export interface RequestsByClassification {
  normal: number;
  unusual: number;
  suspicious: number;
}

/** Dashboard Aggregated Statistics */
export interface DashboardStats {
  total_requests: number;
  normal_requests: number;
  unusual_requests: number;
  suspicious_requests: number;
  total_security_events: number;
  events_by_severity: EventsBySeverity;
  requests_by_classification: RequestsByClassification;
}

/** Device Status Details */
export interface DeviceStatusItem {
  device_id: string;
  status: DeviceState;
  last_seen: string | null;     // ISO 8601 UTC string or null
  last_activity: string | null; // ISO 8601 UTC string or null
}

/** Device Status Response */
export interface DeviceStatusResponse {
  devices: DeviceStatusItem[];
}

/** Standard Error Response Payload */
export interface ApiErrorResponse {
  detail: string | Array<{ loc: (string | number)[]; msg: string; type: string }>;
  status_code?: number;
}
```

---

## 4. API Client Implementation Examples (Native Fetch)

Here are reusable API utility functions using standard browser `fetch`:

```typescript
import {
  API_BASE_URL,
  DashboardStats,
  DeviceStatusResponse,
  PaginatedResponse,
  RequestLog,
  SecurityEvent,
  EventSeverity,
  RequestClassification,
} from "../types/api";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE_URL}${path}`;
  const response = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers || {}),
    },
    ...options,
  });

  if (!response.ok) {
    let errorDetail = `HTTP ${response.status} ${response.statusText}`;
    try {
      const errJson = await response.json();
      if (typeof errJson.detail === "string") {
        errorDetail = errJson.detail;
      } else if (Array.isArray(errJson.detail)) {
        errorDetail = errJson.detail.map((e: any) => `${e.loc.join('.')}: ${e.msg}`).join(", ");
      }
    } catch {
      // Body not JSON
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

// -----------------------------------------------------------------------------
// Dashboard Statistics
// -----------------------------------------------------------------------------
export async function fetchDashboardStats(): Promise<DashboardStats> {
  return request<DashboardStats>("/stats");
}

// -----------------------------------------------------------------------------
// Device Status
// -----------------------------------------------------------------------------
export async function fetchDeviceStatuses(): Promise<DeviceStatusResponse> {
  return request<DeviceStatusResponse>("/device/status");
}

// -----------------------------------------------------------------------------
// Security Events (with pagination & filters)
// -----------------------------------------------------------------------------
export interface EventFilterParams {
  skip?: number;
  limit?: number;
  severity?: EventSeverity;
  event_type?: string;
  device_id?: string;
  start_time?: string; // ISO 8601 UTC
  end_time?: string;   // ISO 8601 UTC
}

export async function fetchSecurityEvents(
  params: EventFilterParams = {}
): Promise<PaginatedResponse<SecurityEvent>> {
  const query = new URLSearchParams();
  if (params.skip !== undefined) query.set("skip", params.skip.toString());
  if (params.limit !== undefined) query.set("limit", params.limit.toString());
  if (params.severity) query.set("severity", params.severity);
  if (params.event_type) query.set("event_type", params.event_type);
  if (params.device_id) query.set("device_id", params.device_id);
  if (params.start_time) query.set("start_time", params.start_time);
  if (params.end_time) query.set("end_time", params.end_time);

  const qs = query.toString();
  return request<PaginatedResponse<SecurityEvent>>(`/events${qs ? `?${qs}` : ""}`);
}

// -----------------------------------------------------------------------------
// Request Logs (with pagination & filters)
// -----------------------------------------------------------------------------
export interface LogFilterParams {
  skip?: number;
  limit?: number;
  classification?: RequestClassification;
  device_id?: string;
  start_time?: string;
  end_time?: string;
}

export async function fetchRequestLogs(
  params: LogFilterParams = {}
): Promise<PaginatedResponse<RequestLog>> {
  const query = new URLSearchParams();
  if (params.skip !== undefined) query.set("skip", params.skip.toString());
  if (params.limit !== undefined) query.set("limit", params.limit.toString());
  if (params.classification) query.set("classification", params.classification);
  if (params.device_id) query.set("device_id", params.device_id);
  if (params.start_time) query.set("start_time", params.start_time);
  if (params.end_time) query.set("end_time", params.end_time);

  const qs = query.toString();
  return request<PaginatedResponse<RequestLog>>(`/logs${qs ? `?${qs}` : ""}`);
}
```

---

## 5. UI Component to Endpoint Mapping

| Dashboard Component | Target API Endpoint | Expected Response Structure |
|---|---|---|
| **Top Metric Cards** | `GET /api/stats` | `total_requests`, `normal_requests`, `unusual_requests`, `suspicious_requests`, `total_security_events` |
| **Severity Breakdown Chart** | `GET /api/stats` | `events_by_severity` (`informational`, `warning`, `critical`) |
| **Classification Pie Chart** | `GET /api/stats` | `requests_by_classification` (`normal`, `unusual`, `suspicious`) |
| **Device Monitor Table/Card**| `GET /api/device/status` | `devices: [{ device_id, status, last_seen, last_activity }]` |
| **Security Events Data Grid**| `GET /api/events` | `PaginatedResponse<SecurityEvent>` with sorting, filter & pagination |
| **HTTP Request Logs Table**  | `GET /api/logs` | `PaginatedResponse<RequestLog>` with filter & pagination |

---

## 6. How Pagination & Filtering Work

### Pagination
Both `/api/events` and `/api/logs` accept:
- `skip` (integer >= 0, default: `0`): The offset of items to skip.
- `limit` (integer 1-100, default: `20`): Maximum items returned per page.

The returned response envelope is:
```json
{
  "items": [...],
  "total": 128,
  "skip": 20,
  "limit": 20
}
```

To calculate total pages in your React table/pager:
```typescript
const totalPages = Math.ceil(response.total / response.limit);
const currentPage = Math.floor(response.skip / response.limit) + 1;
```

### Time Range Filtering
Both endpoints accept `start_time` and `end_time` in ISO 8601 format:
- `2026-10-20T00:00:00Z` or `2026-10-20T00:00:00+00:00`
- If `start_time > end_time`, the backend returns HTTP 400 Bad Request with:
  ```json
  {"detail": "start_time must be before end_time"}
  ```

---

## 7. Handling Loading, Empty, and Error States

### Zero / Empty Data
- If no security events or request logs exist, the backend returns:
  ```json
  { "items": [], "total": 0, "skip": 0, "limit": 20 }
  ```
  The `items` field is **never `null`**. It will always be an empty array `[]`.
- If no devices have recorded activity yet, `/api/device/status` returns:
  ```json
  { "devices": [] }
  ```
- If no logs or events exist, `/api/stats` returns zero counts:
  ```json
  {
    "total_requests": 0,
    "normal_requests": 0,
    "unusual_requests": 0,
    "suspicious_requests": 0,
    "total_security_events": 0,
    "events_by_severity": { "informational": 0, "warning": 0, "critical": 0 },
    "requests_by_classification": { "normal": 0, "unusual": 0, "suspicious": 0 }
  }
  ```

### Nullable Fields
- `source_ip`: Can be `null` if source IP was not identifiable.
- `response_code`: Can be `null` if the request timed out or was dropped.
- `request_count`, `time_window_seconds`, `metadata`: Can be `null`.
- In your React UI, render `-` or `N/A` when values are `null`.

### Error Handling
React hook pattern example:

```tsx
import React, { useEffect, useState } from "react";
import { fetchDashboardStats } from "./api/client";
import { DashboardStats } from "./types/api";

export function StatsOverview() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDashboardStats()
      .then((data) => {
        setStats(data);
        setError(null);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div>Loading intrusion statistics...</div>;
  if (error) return <div className="error-banner">Error loading stats: {error}</div>;
  if (!stats) return <div>No data available.</div>;

  return (
    <div className="stats-grid">
      <div className="card">Total Requests: {stats.total_requests}</div>
      <div className="card">Suspicious: {stats.suspicious_requests}</div>
      <div className="card">Security Events: {stats.total_security_events}</div>
      <div className="card">Critical Alerts: {stats.events_by_severity.critical}</div>
    </div>
  );
}
```

---

## 8. CORS Configuration for Local Development

The backend default allows:
- `http://localhost:5173`
- `http://127.0.0.1:5173`

If your Vite dev server runs on another port (e.g. `3000` or `5174`), update `CORS_ORIGINS` in `backend/.env`:
```env
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000
```
Then restart Uvicorn.

---

## 9. Understanding Device Status & Limitations

In `/api/device/status`, `status` is evaluated based on whether the device logged any request or security event within the last `DEVICE_INACTIVE_THRESHOLD_SECONDS` (default: 300 seconds / 5 minutes).

> [!NOTE]
> **Important Limitation:**
> The `status` field indicates **persisted activity freshness**, not an active TCP ping/keepalive or real-time online socket. If a honeypot device loses power or Wi-Fi, it will transition to `inactive` only after 5 minutes of silence.
