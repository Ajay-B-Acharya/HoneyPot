/*
 * IoT Honeypot Monitor — FRDM-RW612 Offline Detection Continuity Buffer Header
 *
 * Implements bounded, thread-safe on-device security event persistence:
 * - Deterministic, bounded BSS storage (48 events)
 * - Monotonic client_event_id preservation for idempotent reconciliation
 * - Selective eviction protecting SEV_CRITICAL alerts during overflow
 * - Partial-batch acknowledgement removal by client_event_id
 */

#ifndef OFFLINE_BUFFER_H_
#define OFFLINE_BUFFER_H_

#include "detection_rules.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define OFFLINE_BUFFER_MAX_EVENTS 48

typedef struct {
    char client_event_id[48];
    uint32_t timestamp_tick;
    uint32_t sequence_num;
    SecurityEventType_t event_type;
    EventSeverity_t severity;
    char description[64];
    char source_ip[45];
    char endpoint[64];
    char method[8];
    uint8_t threat_score;
    char risk_level[16];
    bool is_synced;
    uint8_t retry_count;
} OfflineEvent_t;

typedef struct {
    uint32_t capacity;
    uint32_t pending_count;
    uint32_t total_recorded;
    uint32_t total_reconciled;
    uint32_t total_dropped;
    uint32_t total_dropped_routine;
    uint32_t total_dropped_critical;
    bool is_reconciling;
    uint32_t last_sync_tick;
} OfflineBufferStats_t;

/* Initialize offline event buffer */
void OfflineBuffer_Init(void);

/* Store a security event with optional pre-assigned client_event_id and seq_num */
bool OfflineBuffer_PushWithId(const RequestRecord_t *record, const char *client_event_id, uint32_t seq_num);

/* Store a security event (generates client_event_id if needed) */
bool OfflineBuffer_Push(const RequestRecord_t *record);

/* Get number of pending unsynchronized events */
uint32_t OfflineBuffer_GetPendingCount(void);

/* Retrieve up to max_count pending events for batch transmission */
uint32_t OfflineBuffer_GetBatch(OfflineEvent_t *out_batch, uint32_t max_count);

/* Acknowledge successful synchronization of count leading events */
void OfflineBuffer_AckBatch(uint32_t count);

/* Acknowledge only specific client_event_ids (handles partial batch failures) */
uint32_t OfflineBuffer_AckByIds(const char acked_ids[][48], uint32_t acked_count);

/* Retrieve buffer statistics */
void OfflineBuffer_GetStats(OfflineBufferStats_t *out_stats);

/* Set reconciliation active state */
void OfflineBuffer_SetReconciling(bool is_reconciling);

#endif /* OFFLINE_BUFFER_H_ */
