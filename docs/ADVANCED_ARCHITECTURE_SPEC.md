# IoT Honeypot Monitor — Advanced Edge-to-Backend Architecture Specification

**Target Hardware:** NXP FRDM-RW612 (ARM Cortex-M33, FreeRTOS `heap_4` 128 KB)  
**Backend:** FastAPI + SQLAlchemy (SQLite WAL / PostgreSQL-compatible)  
**Frontend:** React + TypeScript + Vite  

---

## 1. MCU Sequence Scoring Algorithm (`firmware/src/sequence_detection.c`)
- **Purpose:** Deterministic, integer-only multi-stage attack progression scoring executed in the HTTP request path without floating-point arithmetic or dynamic heap allocation.
- **Data Types & Bit Widths:**
  - `SeqRingEntry_t` (**4 bytes**): `uint16_t endpoint_id`, `uint16_t delta_100ms`.
  - `IPSequenceHistory_t` (**48 bytes**): `SeqRingEntry_t entries[8]`, `uint32_t last_obs_tick`, `uint32_t last_alert_tick`, `uint16_t sequence_score`, `uint16_t pattern_count`, `uint8_t count`, `uint8_t head`, `uint8_t repeat_streak`, `uint8_t last_detected_pattern`.
- **Constants & Thresholds:**
  - `SEQ_HISTORY_DEPTH = 8` entries
  - `SEQ_WINDOW_MS = 30000` ms (30 s)
  - `SEQ_ALERT_COOLDOWN_MS = 15000` ms (15 s)
  - `SEQ_DECAY_MS_PER_POINT = 1000` ms (1 pt/s)
  - `SEQ_SCORE_WARN_THRESHOLD = 40` (`SEV_WARNING`)
  - `SEQ_SCORE_CRIT_THRESHOLD = 70` (`SEV_CRITICAL`)
  - `SEQ_SCORE_MAX = 100`

## 2. Endpoint Identifier Mapping (`Sequence_ResolveEndpointId`)
- **Structure:** Static 64-slot table `s_ep_registry[ENDPOINT_REGISTRY_MAX]` (`ENDPOINT_REGISTRY_MAX = 64`), each slot storing `uint32_t hash` (DJB2), `char path[32]`, `uint8_t category` (`EndpointCategory_t`), `bool in_use`.
- **Collision Safety:** Linear probing from `hash % 64` with full `strncmp(slot->path, normalized_path, 31) == 0` verification. Colliding paths never merge silently; `registry_collisions_resolved` increments. If all 64 slots are occupied, returns `EP_ID_UNKNOWN_OVERFLOW (0xFFFE)`.
- **Thread Safety:** Guarded by FreeRTOS mutex `s_seq_mutex`.

## 3. Fixed-Size Ring-Buffer Structure
- Circular array `entries[8]` indexed by `uint8_t head` (`0..7`) and `uint8_t count` (`0..8`).
- Stores compact `uint16_t delta_100ms = min(elapsed_ms / 100, 65535)` (100 ms resolution, max ~109 min per step) instead of `uint32_t` or `uint64_t` timestamps.
- Time-window reconstruction walks backwards from `(head + 7) % 8` accumulating `delta_100ms` until `accum_100ms > SEQ_WINDOW_MS / 100`.

## 4. Exact Scoring Formula
$$\text{sequence\_score}_t = \min\Big(100,\; \text{decayed}_{t} + W(\text{cat}_t) + P(\text{cat}_{t-1}, \text{cat}_t) + R_t\Big)$$
- **Endpoint Severity Weight $W$:** `STATUS`/`INFO` = `0`; `ROOT (/)` = `2`; `CONFIG` = `10`; `ADMIN` = `15`; `LOGIN` = `15`; `UNKNOWN` = `18`.
- **Transition Bonus $P$ (within `SEQ_WINDOW_MS`):**
  - `ROOT -> ADMIN`: `+15`
  - `ADMIN -> LOGIN`: `+20`
  - `ADMIN -> CONFIG`: `+18`
  - `ROOT -> CONFIG`: `+12`
  - `LOGIN -> CONFIG` / `CONFIG -> ADMIN`: `+12`
  - `UNKNOWN -> UNKNOWN`: `+10`
- **Repeated Transition / Probe Bonus $R$ (when $W > 0$):**
  - Consecutive identical `endpoint_id`: `+min(repeat_streak * 5, 15)`
  - Repeated `(prev_ep_id -> curr_ep_id)` pair in ring buffer: `+8` (capped at `20`).

## 5. Time-Decay Mechanism
- Wraparound-safe elapsed time: `uint32_t elapsed_ms = (uint32_t)(current_tick - history->last_obs_tick);`
- Integer decay: `decay_pts = elapsed_ms / 1000U`, `decayed = (score > decay_pts) ? (score - decay_pts) : 0`.
- Benign `/status` and `/info` requests ($W = 0$) allow the score to decay naturally without adding threat points.

## 6. Memory-Pressure & Eviction Policy (`threat_memory_manager.c`)
- **Static Budget:** `THREAT_MEM_MAX_PROFILES = 24` (`24 × 192 B = 4,608 B` BSS).
- **Pressure Levels:** `NORMAL` (`<14`), `MODERATE` (`14–19`), `HIGH` (`20–23`), `CRITICAL` (`24/24`).
- **Protected Profiles (`ThreatMem_IsCriticalProtected`):** `threat_score >= 70`, `risk_level >= RISK_HIGH`, `sequence_score >= 70`, `suspicious_requests >= 5`, or `priority >= 150`.
- **3-Stage Eviction (`ThreatMem_SelectEvictionVictim`):**
  1. Expired benign profiles (`threat_score < 30`, `elapsed >= 300000 ms`).
  2. Lowest-priority non-protected profile.
  3. Under extreme pressure (all protected), lowest priority with longest idle `(uint32_t)(current_tick - last_seen_tick)`.
- **Counters:** `total_evicted_count`, `evicted_benign_count`, `evicted_suspicious_count`, `memory_pressure_events`, `sequence_detections`.

## 7. FreeRTOS Queue Architecture (`telemetry_client.c`)
- **Dual Priority Queues** (`TelemetryItem_t`):
  - `s_critical_queue`: `16` slots (`TELEMETRY_CRIT_QUEUE_LENGTH = 16`) for `EVENT_NONE != triggered_event`.
  - `s_routine_queue`: `16` slots (`TELEMETRY_ROUTINE_QUEUE_LENGTH = 16`) for routine `EVENT_NONE` traffic logs.
- **Isolation:** Routine traffic never enters `s_critical_queue`. When `s_routine_queue` is full, only the oldest routine item is dropped (`routine_dropped++`). When `s_critical_queue` is full, alerts spill into `OfflineBuffer_PushWithId`.

## 8. Priority-Based Telemetry Delivery
- `Telemetry_Task` always attempts non-blocking `xQueueReceive(s_critical_queue, &item, 0)` first.
- Only when `s_critical_queue` is empty does it wait up to `1000 ms` on `s_routine_queue`, then re-checks `s_critical_queue`.
- HTTP request handling (`Honeypot_Server_Task`) uses `xQueueSend(..., 0)` (0-tick non-blocking), decoupling HTTP latency from Wi-Fi/backend state.

## 9. Adaptive Retry & Batching Algorithm
- **Retry Backoff (`Telemetry_ComputeAdaptiveBackoffMs`):**
  - `failure_streak == 0`: `200 ms` if queue occupancy $\ge 75\%$, else `1000 ms`.
  - `failure_streak >= 1`: `min(30000, 1000 << (min(failure_streak, 6) - 1))` ms, halved (min `1000 ms`) when critical queue occupancy $\ge 75\%$.
- **Adaptive Batch Size (`Telemetry_ComputeAdaptiveBatchSize`):**
  - Bounds: `[1, 8]` (`TELEMETRY_MIN_BATCH_SIZE = 1`, `TELEMETRY_MAX_BATCH_SIZE = 8`).
  - Doubles up to `8` on batch success under $\ge 50\%$ offline occupancy (or increments up to `4`); halves toward `1` on transmission failure.

## 10. Event Deduplication Protocol
- MCU assigns a monotonic `uint32_t seq_num` and `client_event_id = "rw612-evt-<tick_hex>-<seq_hex>"` at `Telemetry_Enqueue` time.
- Backend enforces `UNIQUE` database indexes on `SecurityEvent.client_event_id`, `RequestLog.client_event_id`, and `EdgeObservation.observation_id`, backed by SQLAlchemy savepoints (`db.begin_nested()`) and `IntegrityError` recovery.
- `POST /api/events/batch` returns `acked_ids` and `failed_ids`; MCU `OfflineBuffer_AckByIds` removes only acknowledged IDs, preserving unacknowledged items across partial batch failures.

## 11. Edge-to-Backend Observation Correlation (`correlation_service.py`)
- Edge sends compact observations (`observation_id`, `source_ip`, `endpoint_id`, `event_timestamp`, `sequence_num`, `edge_score`).
- Backend queries a `300 s` window per `source_ip`, sorts by `(event_timestamp, sequence_num)` to handle delayed/out-of-order arrivals, reconstructs multi-stage patterns (`reconnaissance_probe`, `credential_hunting`, `unknown_sweep`), and emits derived `SecurityEvent` (`correlated_attack_sequence`) retaining `observation_id`, `source_observation_ids`, and `attack_timeline`.

## 12. IP Churn & Shared-IP Handling
- **Transition Fingerprinting:** Builds 4-step category transition signatures (`cat1->cat2->cat3->cat4`) and average inter-arrival cadence.
- **Shared-IP / NAT Uncertainty:** When a single `source_ip` interleaves $\ge 2$ benign health polls (`/status`, `/info`) with $\ge 2$ attack probes (`admin`, `login`, `config`, `unknown`), `shared_ip_suspected = True` is set, `correlation_confidence` is capped at `0.55`, and `correlation_score` is capped at `65` rather than falsely condemning all traffic on that IP.
- **IP Churn Correlation:** When a new `source_ip` reproduces an identical suspicious transition fingerprint within `CHURN_WINDOW_SECONDS = 120 s`, it is linked via `roaming_fingerprint_match` with `roaming_from_ip` and `correlation_confidence = 0.80`.

## 13. Online / Offline State Transitions
- `LinkStatusChangeCallback` and `WiFi_ConnectAP` update `Telemetry_SetWifiConnected(bool)`.
- **Online $\to$ Offline:** Wi-Fi down or backend HTTP failure increments `failure_streak`, routes alerts to `OfflineBuffer_PushWithId`, and applies adaptive backoff without blocking `Honeypot_Server_Task`.
- **Offline $\to$ Online:** `Telemetry_Task` detects `s_wifi_connected == true` and `OfflineBuffer_GetPendingCount() > 0` (within at most `1000 ms` idle poll) and invokes `ReconcileOfflineEvents()`.

## 14. Synchronization & Recovery Mechanism
- `OfflineBuffer` (48 static slots) uses selective eviction (`RemoveAtLogicalOffset`) to drop non-critical (`SEV_INFORMATIONAL` / `SEV_WARNING`) entries before `SEV_CRITICAL` alerts.
- During recovery, batches of `1..8` events are packed into `2048 B` JSON payloads, posted to `/api/events/batch`, and selectively cleared via `OfflineBuffer_AckByIds`.

---

## Comparison Against Conventional Approaches
| Dimension | Conventional Baseline | Implemented Architecture |
|---|---|---|
| **Rate Control** | Basic fixed-window request counter (treats all endpoints equally) | Integer weighted progression + endpoint severity weights + 1 pt/s time decay |
| **Sequence Detection** | Static string/boolean pattern matching on full URLs | Collision-safe `uint16_t` endpoint IDs + 4-byte `SeqRingEntry_t` + weighted transitions |
| **Telemetry Queueing** | Single FIFO queue (routine logs can starve/evict critical alerts) | Isolated dual priority queues (`16` critical + `16` routine) + selective offline preservation |
| **Threat Correlation** | IP-only grouping (fails under NAT/shared IPs and IP rotation) | Split-stage edge score + backend transition fingerprints, cadence, and shared-IP uncertainty |
