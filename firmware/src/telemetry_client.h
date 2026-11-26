/*
 * IoT Honeypot Monitor — FRDM-RW612 Telemetry Dispatcher Header
 *
 * Implements priority-tiered FreeRTOS telemetry queues, monotonic event IDs,
 * Wi-Fi link awareness, adaptive retry/backoff, and adaptive batch reconciliation.
 */

#ifndef TELEMETRY_CLIENT_H_
#define TELEMETRY_CLIENT_H_

#include "detection_rules.h"
#include <stdbool.h>
#include <stdint.h>

#define TELEMETRY_CRIT_QUEUE_LENGTH    16U
#define TELEMETRY_ROUTINE_QUEUE_LENGTH 16U
#define TELEMETRY_MAX_BATCH_SIZE       8U
#define TELEMETRY_MIN_BATCH_SIZE       1U

typedef struct {
    uint32_t seq_num;
    char client_event_id[48];
    char method[8];
    char endpoint[64];
    char source_ip[48];
    int32_t response_code;
    uint32_t timestamp_tick;
    bool is_unknown_endpoint;
    SecurityEventType_t triggered_event;
    EventSeverity_t severity;
    char event_description[96];
    uint8_t ip_threat_score;
    uint16_t endpoint_id;
    uint16_t edge_seq_score;
    char ip_risk_level[16];
} TelemetryItem_t;

typedef struct {
    uint32_t critical_queue_depth;
    uint32_t critical_queue_capacity;
    uint32_t routine_queue_depth;
    uint32_t routine_queue_capacity;
    uint32_t critical_enqueued;
    uint32_t routine_enqueued;
    uint32_t critical_dropped;
    uint32_t routine_dropped;
    uint32_t spilled_to_offline;
    uint32_t total_retries;
    uint32_t failure_streak;
    uint32_t current_backoff_ms;
    uint32_t current_batch_size;
    bool wifi_connected;
    bool backend_online;
} TelemetryStats_t;

/* Initialize priority-tiered telemetry queues and offline buffer */
bool Telemetry_Init(void);

/* Enqueue an observed request into critical or routine queue (non-blocking) */
bool Telemetry_Enqueue(const RequestRecord_t *record);

/* Update Wi-Fi link state from WPL link callback */
void Telemetry_SetWifiConnected(bool connected);
bool Telemetry_IsWifiConnected(void);

/* Compute adaptive retry/backoff interval (ms) from queue occupancy & failure streak */
uint32_t Telemetry_ComputeAdaptiveBackoffMs(uint32_t queue_occ_pct, uint32_t failure_streak);

/* Compute adaptive batch size (1..8) from failure streak & consecutive successes */
uint32_t Telemetry_ComputeAdaptiveBatchSize(uint32_t current_size, bool last_batch_ok, uint32_t queue_occ_pct);

/* Query telemetry queue, drop, and retry statistics */
void Telemetry_GetStats(TelemetryStats_t *out_stats);

/* Task entry point for FreeRTOS */
void Telemetry_Task(void *param);

#endif /* TELEMETRY_CLIENT_H_ */
