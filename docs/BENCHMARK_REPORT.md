# IoT Honeypot Monitor — Benchmarking & Validation Report

**Target Platform:** NXP FRDM-RW612 (ARM Cortex-M33) + FastAPI Backend (SQLite WAL)  
**Measurement Policy:** All metrics below are **actual measured outputs** from the compiled ARM ELF (`arm-none-eabi-gcc 14.2.1`), host C unit/microbenchmarks (`gcc -O2`), and live FastAPI HTTP benchmarks (`127.0.0.1:8000`). Hardware vs. host/software measurements are explicitly separated.

---

## 1. Hardware & Test Environment Configuration
- **MCU Target:** NXP FRDM-RW612 (`frdmrw612`, `flash_release` build via `west` + `arm-none-eabi-gcc 14.2.1`, FreeRTOS `heap_4` = `128 KB`). Connected J-Link CDC UART detected on `COM7`.
- **Host / Backend:** Windows 11 x86_64 (Intel Core i5-1335U), Python 3.13 + FastAPI + Uvicorn + SQLite WAL (`http://127.0.0.1:8000`).

---

## 2. Measured Results

### A. MCU Memory & Firmware Footprint (ARM Cortex-M33 `iot_honeypot.elf` — Target Build)
Measured via `west build` (`flash_release`) and `arm-none-eabi-size`:

| Metric | Measured Value | Notes |
|---|---|---|
| `m_text` (Flash code/rodata) | `413,768 B / 2,092,416 B` (`19.77%`) | Baseline Phase 1 was `409,920 B` (`+3,848 B` for resilient telemetry & observation metadata) |
| `m_data` (SRAM initialized/data) | `479,504 B / 1,164 KB` (`40.23%`) | Within 1,164 KB RW612 SRAM budget |
| `arm-none-eabi-size` (`text` / `data` / `bss`) | `520,816 B` / `63,851 B` / `323,968 B` | Total `908,635 B` |
| `SeqRingEntry_t` | `4 bytes` | `uint16_t endpoint_id` + `uint16_t delta_100ms` |
| `IPSequenceHistory_t` (8-entry ring) | `48 bytes` | Compact relative timestamps + integer score |
| `IPProfile_t` | `192 bytes` | Reduced from ~256 bytes (hash array replaced by `uint16_t endpoint_ids[8]`) |
| 24 IP Profiles Static BSS | `4,608 bytes` (`4.5 KB`) | `THREAT_MEM_MAX_PROFILES = 24` |

### B. Host C Microbenchmarks & Functional Validation (`gcc -O2 -DHOST_UNIT_TEST`)
| Test / Benchmark | Measured Result |
|---|---|
| `10,000` calls to `Sequence_Evaluate()` | `18.000 ms` (`~1.8 µs/eval` on host x86_64; zero floating-point ops) |
| Sequence Scoring Suite (`test_sequence_scoring.c`) | **6/6 passed** (normal browsing score `0`, recon `/ -> /admin -> /config` score `58`, repeated transition score `100`, wraparound decay `50 -> 10`, collision safety distinct IDs `44, 40, 41`, 28-IP pressure `24 active / 5 evicted / attacker preserved`) |
| Resilient Telemetry Suite (`test_resilient_telemetry.c`) | **3/3 passed** (`15/15` critical events preserved on 48-slot overflow with `5` non-critical evicted; partial batch ack removed `2/4` IDs accurately; adaptive backoff `200 ms – 30,000 ms` & batch `1..8` verified) |

### C. Live Backend & Correlation Benchmarks (`http://127.0.0.1:8000`)
Measured via `backend/tests/run_benchmark.py` and `pytest`:

| Metric | Measured Value |
|---|---|
| `POST /api/observations` avg latency (10 reqs) | `28.79 ms` (`min 13.87 ms`, `max 114.24 ms`) |
| `POST /api/events/batch` (8 new events) | `58.02 ms` (`inserted=8, duplicates=0`) |
| `POST /api/events/batch` (8 duplicate events) | `6.37 ms` (`inserted=0, duplicates=8`) |
| Normal traffic false positives (`/status`, `/info` × 5) | `0 / 5` (`0%`) |
| Attack sequence false negatives (`/ -> /admin -> /config`) | `0 / 1` (`0%`) |
| Full Backend Test Suite (`pytest`) | **117 / 117 passed** in `7.19 s` |
| Frontend Production Build (`tsc && vite build`) | **Passed** in `1.95 s` (`270.98 kB` JS bundle) |

---

## 3. Baseline Comparison
| Capability | Baseline Implementation | Improved Architecture |
|---|---|---|
| **Sequence Scoring** | Fixed static pattern match; `uint32_t` ticks; `~256 B` profile | Integer weighted progression + decay; `uint16_t` relative deltas; `192 B` profile (`-25%` per-IP RAM) |
| **Telemetry Queueing** | Single `16`-slot FIFO (`RequestRecord_t`); routine logs could drop alerts | Dual priority queues (`16` critical + `16` routine); `15/15` critical alerts preserved in overflow test |
| **Offline Reconciliation** | Fixed batch `4`; whole-batch ack; `s_head_idx` eviction bug | Adaptive batch `1..8`; per-ID `acked_ids` partial recovery; selective non-critical eviction |
| **Threat Correlation** | IP-only grouping; failed on out-of-order/NAT | `(event_timestamp, sequence_num)` ordering; shared-IP uncertainty (`conf <= 0.55`); IP churn linking (`conf = 0.80`) |

---

## 4. Limitations
- Sequence latency (`1.8 µs/eval`) and queue overflow behavior were measured on host `x86_64` (`-DHOST_UNIT_TEST`); on-chip FRDM-RW612 cycle counts and live Wi-Fi outage throughput require flashing `iot_honeypot.elf` to the board on `COM7` and capturing UART logs.
- Backend `run_benchmark.py` ran over loopback (`127.0.0.1:8000`); LAN Wi-Fi RTT will add wireless link latency.
