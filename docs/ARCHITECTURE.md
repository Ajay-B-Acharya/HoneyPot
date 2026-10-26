# IoT Honeypot Monitor — System Architecture

**Comprehensive Architectural Specification**  
*Covers Edge Hardware, Detection Engine, Ingestion Backend, Storage Engine, and Security Dashboard*

---

## 1. System Architecture Overview

```mermaid
flowchart TD
    subgraph EdgeHardware["1. Edge Hardware (NXP FRDM-RW612)"]
        WiFi["Wi-Fi Radio / WPL Driver"] --> LwIP["lwIP TCP/IP Stack"]
        LwIP --> HttpSrv["httpsrv Embedded Server"]
        HttpSrv --> EdgeDecoy["Decoy Services (/status, /info, /config)"]
        EdgeDecoy --> TelemetryClient["Edge Telemetry Dispatcher (HTTP POST)"]
    end

    subgraph BackendEngine["2. Ingestion & Security Detection (FastAPI)"]
        APIRouters["FastAPI Routers (/api/logs, /api/events, /api/stats)"]
        Validation["Pydantic v2 Schema Validation"]
        APIRouters --> Validation
        Validation --> DetEngine["Detection Engine (DetectionService)"]
        
        subgraph DetectionRules["Modular Rule Evaluation"]
            R1["Rule R1: Unknown Endpoint (Normalization & Allowlist)"]
            R2["Rule R2: Request-Rate Sliding Window Tracker"]
            R3["Rule R3: Repeated-Request Sliding Window Tracker"]
            R4["Rule R4: Safe Metadata & Null-Byte Defense"]
        end
        DetEngine --> DetectionRules
    end

    subgraph StorageLayer["3. Persistence Layer (SQLite + WAL)"]
        ORM["SQLAlchemy 2.0 Engine"]
        LogsTable[("request_logs Table")]
        EventsTable[("security_events Table")]
        ORM --> LogsTable
        ORM --> EventsTable
    end

    subgraph SecurityUI["4. Security Dashboard (React + TypeScript)"]
        ThemeEngine["Dual-Theme Engine (Warm Cream / True Black)"]
        HeaderControls["Sticky Navigation & Auto-Refresh Poller"]
        Hero["Telemetry Overview Hero Section"]
        StatusCards["API Health & Physical Device Status Cards"]
        StatsGrid["Aggregated Threat Metrics"]
        DataGrids["Security Events Grid & HTTP Logs Grid"]
        TestHarness["Real-Time Detection Test Panel"]
    end

    TelemetryClient -- "HTTP JSON /api/logs" --> APIRouters
    DetectionRules -- "Atomic DB Commit" --> ORM
    SecurityUI -- "REST Polling & JSON Payloads" --> APIRouters
```

---

## 2. Layer-by-Layer Architectural Breakdown

### 2.1 Edge Microcontroller Layer (NXP FRDM-RW612)
- **Processor**: NXP RW612 dual-core wireless MCU featuring an Arm Cortex-M33 running at 260 MHz.
- **Operating System**: FreeRTOS real-time kernel managing concurrent network tasks.
- **Network Stack**: NXP Wireless Processing Layer (WPL) interfacing with the integrated Wi-Fi radio subsystem and lwIP lightweight TCP/IP stack.
- **Decoy Server**: `httpsrv` lightweight HTTP daemon exposing legitimate-looking services:
  - `GET /status`: Device health, memory, and uptime metrics.
  - `GET /info`: Firmware version, hardware MAC, and device identifier.
  - `GET /config`: Non-sensitive network configuration parameters.
- **Telemetry Egress**: Any HTTP access (valid or probing) triggers an outgoing non-blocking HTTP POST request to the central FastAPI ingestion endpoint (`/api/logs`).

### 2.2 Ingestion & Detection Layer (FastAPI + Python 3.11+)
- **Application Framework**: FastAPI with asynchronous ASGI request processing and strict Pydantic v2 data validation schemas.
- **Security Detection Engine (`DetectionService`)**:
  - Implements thread-safe in-memory sliding window trackers (`SlidingWindowTracker`) backed by bounded double-ended queues (`deque`).
  - **Memory Safeguards**: Strict table limits (`DETECTION_MAX_TRACKING_ENTRIES = 10000`) and automatic eviction of expired window keys prevent memory denial-of-service.
  - **Normalization Subsystem**: RFC 3986 path canonicalization stripping URL fragments, query parameters, percent-encoding attacks, consecutive slashes, and trailing slashes.
  - **Alert Dampening**: Cooldown timers prevent duplicate security events from exhausting database storage during rapid automated attacks.

### 2.3 Storage Layer (SQLAlchemy 2.0 + SQLite WAL)
- **Database Engine**: SQLite configured in **Write-Ahead Logging (WAL)** mode (`PRAGMA journal_mode=WAL`) allowing concurrent read transactions alongside background log writes.
- **Transaction Handling**: Ingested request logs and all triggered security events are committed **atomically** in a single database transaction (`db.commit()`), guaranteeing complete audit consistency.
- **Migration Ready**: Pure SQLAlchemy 2.0 ORM declarations (`Base = DeclarativeBase()`), ensuring seamless migration to PostgreSQL for enterprise deployments.

### 2.4 Operations Dashboard Layer (React 19 + TypeScript)
- **Modern Build**: Vite 8 with strict TypeScript typing (`noUnusedLocals`, `strict: true`).
- **Design System**: Accessible dual-theme system:
  - **Light Mode**: Warm Cream palette (`#F7F3EB`, `#FFFCF6`, `#24231F`, `#E5DED2`).
  - **Dark Mode**: True Black palette (`#000000`, `#080808`, `#FFFFFF`, `#262626`) with zero low-contrast text and no decorative drop shadows.
- **Typography**: Inter (body & UI), Space Grotesk (headings), Instrument Serif (italic editorial accents), and JetBrains Mono (timestamps, IPs, and endpoints).
- **Resilience**: Dynamic fallback banners when backend is unreachable, automatic auto-refresh (5s interval) with prevention of duplicate background fetches.

---

## 3. Security Detection Engine Specification

```mermaid
sequenceDiagram
    autonumber
    actor Attacker
    participant Microcontroller as NXP FRDM-RW612
    participant API as FastAPI Ingestion (/api/logs)
    participant Engine as Detection Engine
    participant DB as SQLite WAL Storage
    participant UI as React Security Dashboard

    Attacker->>Microcontroller: HTTP GET /admin (Unallowed Path)
    Microcontroller-->>Attacker: 404 Not Found (Decoy Response)
    Microcontroller->>API: POST /api/logs (Telemetry Payload)
    API->>Engine: evaluate_request(log)
    
    activate Engine
    Engine->>Engine: normalize_endpoint('/admin') -> '/admin'
    Engine->>Engine: Rule R1: '/admin' not in {'/status','/info','/config'}
    Engine->>Engine: Trigger SecurityEvent ('unknown_endpoint', severity='warning')
    Engine->>Engine: Rule R2: Check sliding-window request count
    Engine->>Engine: Rule R3: Check repeated-endpoint count
    deactivate Engine
    
    API->>DB: Atomic Commit (RequestLog + SecurityEvent)
    DB-->>API: Success (IDs generated)
    API-->>Microcontroller: 201 Created (Log Response)
    
    UI->>API: GET /api/stats, GET /api/events, GET /api/logs
    API->>DB: Aggregated Queries
    DB-->>API: Result Sets
    API-->>UI: Real-Time Threat Metrics
```

### Detection Rules Table

| Rule ID | Rule Name | Trigger Criteria | Output Severity | Metadata Captured |
| :--- | :--- | :--- | :--- | :--- |
| **R1** | Unknown Endpoint | `normalized_path NOT IN allowed_endpoints_set` | `warning` | Raw endpoint, normalized endpoint, HTTP method. |
| **R2** | High Request Rate | Requests from `(device_id, source_ip)` in 10s >= 20 | `warning` | Window request count, threshold, window seconds, IP. |
| **R3** | Repeated Probes | Requests to `(device_id, source_ip, endpoint)` in 10s >= 10 | `warning` | Repeated count, threshold, endpoint, IP. |
| **R4** | Malformed Metadata | Non-standard method, invalid chars, missing fields | `422 Unprocessable` | Validation error path, rejected value, error type. |

---

## 4. Hardware Independence & Graceful Degradation

When physical hardware is disconnected or temporarily unavailable:
1. The **Backend** remains 100% operational, accepting telemetry from local test benches, edge simulators, or scripts.
2. The **Device Service** computes device activity based on verifiable timestamps. If no device has communicated within 300 seconds, status automatically reflects `inactive` or `not connected`.
3. The **Dashboard** clearly informs operators that the FRDM-RW612 board is not currently communicating, avoiding fabricated indicators or synthetic sensor readings.
