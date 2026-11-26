/*
 * IoT Honeypot Monitor — FRDM-RW612 Offline Detection Continuity Buffer Implementation
 */

#include "offline_buffer.h"
#include "fsl_debug_console.h"
#include <string.h>
#include <stdio.h>

static OfflineEvent_t s_offline_events[OFFLINE_BUFFER_MAX_EVENTS];
static uint32_t s_head_idx = 0;   /* Read pointer for reconciliation */
static uint32_t s_tail_idx = 0;   /* Write pointer for new events */
static uint32_t s_count = 0;      /* Current pending unsynced events */
static uint32_t s_total_recorded = 0;
static uint32_t s_total_reconciled = 0;
static uint32_t s_total_dropped = 0;
static uint32_t s_event_seq = 0;
static bool s_is_reconciling = false;
static uint32_t s_last_sync_tick = 0;

void OfflineBuffer_Init(void)
{
    memset(s_offline_events, 0, sizeof(s_offline_events));
    s_head_idx = 0;
    s_tail_idx = 0;
    s_count = 0;
    s_total_recorded = 0;
    s_total_reconciled = 0;
    s_total_dropped = 0;
    s_event_seq = 0;
    s_is_reconciling = false;
    s_last_sync_tick = 0;
}

bool OfflineBuffer_Push(const RequestRecord_t *record)
{
    if (!record || record->triggered_event == EVENT_NONE) {
        return false;
    }

    /* If buffer is full, apply memory-aware eviction:
     * Search for an informational/warning event to drop; preserve critical events */
    if (s_count >= OFFLINE_BUFFER_MAX_EVENTS) {
        int32_t victim_idx = -1;
        for (uint32_t i = 0; i < s_count; i++) {
            uint32_t idx = (s_head_idx + i) % OFFLINE_BUFFER_MAX_EVENTS;
            if (s_offline_events[idx].severity == SEV_INFORMATIONAL ||
                s_offline_events[idx].severity == SEV_WARNING) {
                victim_idx = (int32_t)idx;
                break;
            }
        }

        if (victim_idx >= 0) {
            /* Drop low severity event by shifting head pointer forward */
            s_head_idx = (s_head_idx + 1) % OFFLINE_BUFFER_MAX_EVENTS;
            s_count--;
            s_total_dropped++;
            PRINTF("[OfflineBuffer] Memory limit: Evicted low-priority event to preserve critical alert.\r\n");
        } else {
            /* All events are critical, evict oldest to make room */
            s_head_idx = (s_head_idx + 1) % OFFLINE_BUFFER_MAX_EVENTS;
            s_count--;
            s_total_dropped++;
            PRINTF("[OfflineBuffer] Warning: Event buffer capacity reached. Dropped oldest critical event.\r\n");
        }
    }

    OfflineEvent_t *entry = &s_offline_events[s_tail_idx];
    memset(entry, 0, sizeof(OfflineEvent_t));

    /* Generate deterministic unique ID: rw612-evt-<tick>-<seq> */
    s_event_seq++;
    snprintf(entry->client_event_id, sizeof(entry->client_event_id),
             "rw612-evt-%08lx-%04lx",
             (unsigned long)record->timestamp_tick,
             (unsigned long)(s_event_seq & 0xFFFF));

    entry->timestamp_tick = record->timestamp_tick;
    entry->event_type = record->triggered_event;
    entry->severity = record->severity;
    strncpy(entry->description, record->event_description, sizeof(entry->description) - 1);
    strncpy(entry->source_ip, record->source_ip, sizeof(entry->source_ip) - 1);
    strncpy(entry->endpoint, record->endpoint, sizeof(entry->endpoint) - 1);
    strncpy(entry->method, record->method, sizeof(entry->method) - 1);
    entry->threat_score = record->ip_threat_score;
    strncpy(entry->risk_level, record->ip_risk_level, sizeof(entry->risk_level) - 1);
    entry->is_synced = false;
    entry->retry_count = 0;

    s_tail_idx = (s_tail_idx + 1) % OFFLINE_BUFFER_MAX_EVENTS;
    s_count++;
    s_total_recorded++;

    PRINTF("[OfflineBuffer] Stored offline event '%s' [ID: %s] (Pending: %lu/%d)\r\n",
           Detection_GetEventString(entry->event_type), entry->client_event_id,
           (unsigned long)s_count, OFFLINE_BUFFER_MAX_EVENTS);

    return true;
}

uint32_t OfflineBuffer_GetPendingCount(void)
{
    return s_count;
}

uint32_t OfflineBuffer_GetBatch(OfflineEvent_t *out_batch, uint32_t max_count)
{
    if (!out_batch || max_count == 0 || s_count == 0) {
        return 0;
    }

    uint32_t fetch_count = (s_count < max_count) ? s_count : max_count;
    for (uint32_t i = 0; i < fetch_count; i++) {
        uint32_t idx = (s_head_idx + i) % OFFLINE_BUFFER_MAX_EVENTS;
        memcpy(&out_batch[i], &s_offline_events[idx], sizeof(OfflineEvent_t));
    }

    return fetch_count;
}

void OfflineBuffer_AckBatch(uint32_t count)
{
    if (count == 0 || s_count == 0) {
        return;
    }

    if (count > s_count) {
        count = s_count;
    }

    s_head_idx = (s_head_idx + count) % OFFLINE_BUFFER_MAX_EVENTS;
    s_count -= count;
    s_total_reconciled += count;

    PRINTF("[OfflineBuffer] Reconciled %lu events. Remaining pending: %lu\r\n",
           (unsigned long)count, (unsigned long)s_count);
}

void OfflineBuffer_GetStats(OfflineBufferStats_t *out_stats)
{
    if (!out_stats) {
        return;
    }

    out_stats->capacity = OFFLINE_BUFFER_MAX_EVENTS;
    out_stats->pending_count = s_count;
    out_stats->total_recorded = s_total_recorded;
    out_stats->total_reconciled = s_total_reconciled;
    out_stats->total_dropped = s_total_dropped;
    out_stats->is_reconciling = s_is_reconciling;
    out_stats->last_sync_tick = s_last_sync_tick;
}

void OfflineBuffer_SetReconciling(bool is_reconciling)
{
    s_is_reconciling = is_reconciling;
}
