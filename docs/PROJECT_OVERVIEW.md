# IoT Honeypot Monitor — Project Overview

**Embedded Network Intrusion Detection System (NIDS) using NXP FRDM-RW612**  
*Project Status: Submission Ready (October 2026)*

---

## 1. Problem Statement

Internet of Things (IoT) devices—such as smart home bridges, industrial sensors, and building automation nodes—are relentless targets of automated botnets (e.g., Mirai variants), port scanners, and brute-force credential probes. Resource-constrained edge microcontrollers typically lack the computing and memory overhead required to run traditional enterprise host intrusion detection agents. Consequently, when an embedded system is scanned or exploited on a local network, network administrators frequently remain unaware until downstream lateral movement occurs.

## 2. Project Objectives

The **IoT Honeypot Monitor** bridges this defensive gap by creating an integrated, edge-assisted intrusion detection honeypot:

1. **Realistic Edge Decoy**: Configure an embedded NXP FRDM-RW612 Wi-Fi microcontroller to act as a benign, believable IoT node exposing standard management endpoints (`/status`, `/info`, `/config`).
2. **Deterministic Intrusion Detection Engine**: Implement a thread-safe, bounded sliding-window detection engine capable of real-time threat evaluation (Rule R1: Unknown Endpoints, Rule R2: High Request Rates, Rule R3: Repeated Probes).
3. **Robust Backend Aggregation**: Provide a resilient FastAPI service backed by SQLite in Write-Ahead Logging (WAL) mode for atomic log persistence, query filtering, and threat metrics aggregation.
4. **Operations Dashboard**: Deliver an accessible React + TypeScript security dashboard with full light-mode (warm cream) and dark-mode (true black) support, real-time health and device status indicators, and one-click testing harness controls.

---

## 3. Scope & Verification Boundaries

To maintain software integrity and transparent evaluation, system capabilities are strictly categorized into their verification boundaries:

### Implemented & Software-Tested (100% Verified)
- **FastAPI Backend Services**: All 7 RESTful endpoints (`POST /api/logs`, `GET /api/logs`, `POST /api/events`, `GET /api/events`, `GET /api/stats`, `GET /api/device/status`, `GET /api/health`).
- **Comprehensive Test Suite**: 88 automated pytest scenarios covering detection rules, rate trackers, time windows, cooldowns, input validation, date-time normalization, and statistics consistency.
- **Client Classification Independence**: Proven separation between edge-supplied labels and server-side authoritative security events.
- **React 19 + TypeScript Frontend**: Dual-theme UI (Warm Cream `#F7F3EB` & Pure Black `#000000`), sticky navigation, theme persistence, live API connectivity, empty/loading/error handling, and zero fabricated telemetry.

### Features Verified Through Simulation (Software Harness)
- **Simulated Attacker Payloads**: Probes targeting unallowed paths (`/admin`, `/shell.php`, `/wp-login.php`, `//secret/`).
- **High-Rate Bursts**: Simulated traffic spikes of 25+ requests in under 10 seconds evaluating sliding-window threshold detection and alert suppression cooldowns.
- **Hardware Tamper Events**: Simulated GPIO enclosure switch triggers submitted via `POST /api/events`.

### Features Requiring the Physical Hardware Board
- **Physical Wi-Fi Radio Association**: Hardware WPA2/WPA3 link establishment via NXP Wi-Fi stack (`WPL_Init()`, `WPL_Start()`).
- **LwIP Embedded HTTP Server**: Execution of `httpsrv` directly within FreeRTOS on the FRDM-RW612 Cortex-M33 core.
- **Physical GPIO Interrupts**: Hardware sensor triggers for physical enclosure tampering.

### Features Planned for Post-Submission Iteration
- Distributed Redis backend for multi-worker backend clustering.
- TLS client certificate mutual authentication (mTLS) between microcontroller and ingestion API.
- Automated dynamic blacklisting integration via local firewall APIs.

---

## 4. Key Architectural Features

- **Normalization Defense**: Canonicalizes percent-encoded characters, collapses consecutive slashes, strips URL fragments and query parameters, and blocks null bytes before allowlist verification.
- **Memory Bounded Trackers**: Sliding-window tracking structures enforce maximum capacity (`DETECTION_MAX_TRACKING_ENTRIES = 10000`) and automatic expiration eviction to prevent memory exhaustion under denial-of-service.
- **Alert Flood Cooldown**: Prevents denial-of-service against the security database by dampening repetitive alerts for the same source within the configured window.
- **Dual-Theme Design System**: Clean Space Grotesk and Inter typography with Instrument Serif editorial accents, adhering to accessible contrast ratios in both light and dark modes.
