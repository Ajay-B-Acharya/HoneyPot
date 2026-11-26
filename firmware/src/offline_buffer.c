/*
 * IoT Honeypot Monitor — FRDM-RW612 Offline Detection Continuity Buffer Implementation
 */

#include "offline_buffer.h"
#ifndef HOST_UNIT_TEST
#include "FreeRTOS.h"
#include "semphr.h"
#include "fsl_debug_console.h"
static SemaphoreHandle_t s_off_mutex = NULL;
#define OFF_LOCK()   do { if (s_off_mutex != NULL) xSemaphoreTake(s_off_mutex, portMAX_DELAY); } while (0)
#define OFF_UNLOCK() do { if (s_off_mutex != NULL) xSemaphoreGive(s_off_mutex); } while (0)
#else
#define PRINTF(...) ((void)0)
#define OFF_LOCK()   ((void)0)
#define OFF_UNLOCK() ((void)0)
#endif

#include <string.h>
#include <stdio.h>

static OfflineEvent_t s_offline_events[OFFLINE_BUFFER_MAX_EVENTS];
static uint32_t s_head_idx = 0;   /* Read pointer for reconciliation */
static uint32_t s_tail_idx = 0;   /* Write pointer for new events */
static uint32_t s_count = 0;      /* Current pending unsynced events */
static uint32_t s_total_recorded = 0;
static uint32_t s_total_reconciled = 0;
static uint32_t s_total_dropped = 0;
static uint32_t s_total_dropped_routine = 0;
static uint32_t s_total_dropped_critical = 0;
static uint32_t s_event_seq = 0;
static bool s_is_reconciling = false;
static uint32_t s_last_sync_tick = 0;

void OfflineBuffer_Init(void)
{
#ifndef HOST_UNIT_TEST
    if (s_off_mutex == NULL) {
        s_off_mutex = xSemaphoreCreateMutex();
    }
#endif
    OFF_LOCK();
    memset(s_offline_events, 0, sizeof(s_offline_events));
    s_head_idx = 0;
    s_tail_idx = 0;
    s_count = 0;
    s_total_recorded = 0;
    s_total_reconciled = 0;
    s_total_dropped = 0;
    s_total_dropped_routine = 0;
    s_total_dropped_critical = 0;
    s_event_seq = 0;
    s_is_reconciling = false;
    s_last_sync_tick = 0;
    OFF_UNLOCK();
}

/* Remove element at logical offset `pos` (0 .. s_count-1) from ring buffer */
static void RemoveAtLogicalOffset(uint32_t pos)
{
    if (pos >= s_count || s_count == 0U) {
        return;
    }
    for (uint32_t i = pos; i + 1U < s_count; i++) {
        uint32_t dst = (s_head_idx + i) % OFFLINE_BUFFER_MAX_EVENTS;
        uint32_t src = (s_head_idx + i + 1U) % OFFLINE_BUFFER_MAX_EVENTS;
        memcpy(&s_offline_events[dst], &s_offline_events[src], sizeof(OfflineEvent_t));
    }
    s_count--;
    s_tail_idx = (s_head_idx + s_count) % OFFLINE_BUFFER_MAX_EVENTS;
    memset(&s_offline_events[s_tail_idx], 0, sizeof(OfflineEvent_t));
}

bool OfflineBuffer_PushWithId(const RequestRecord_t *record, const char *client_event_id, uint32_t seq_num)
{
    if (!record || record->triggered_event == EVENT_NONE) {
        return false;
    }

    OFF_LOCK();

    /* Selective eviction when full: drop oldest non-critical event first */
    if (s_count >= OFFLINE_BUFFER_MAX_EVENTS) {
        int32_t victim_pos = -1;
        for (uint32_t i = 0; i < s_count; i++) {
            uint32_t idx = (s_head_idx + i) % OFFLINE_BUFFER_MAX_EVENTS;
            if (s_offline_events[idx].severity != SEV_CRITICAL) {
                victim_pos = (int32_t)i;
                break;
            }
        }

        if (victim_pos >= 0) {
            RemoveAtLogicalOffset((uint32_t)victim_pos);
            s_total_dropped++;
            s_total_dropped_routine++;
            PRINTF("[OfflineBuffer] Evicted non-critical event at pos %ld to preserve critical alerts.\r\n",
                   (long)victim_pos);
        } else {
            /* All events are critical; drop oldest critical */
            RemoveAtLogicalOffset(0U);
            s_total_dropped++;
            s_total_dropped_critical++;
            PRINTF("[OfflineBuffer] Warning: All buffered events critical; dropped oldest critical event.\r\n");
        }
    }

    OfflineEvent_t *entry = &s_offline_events[s_tail_idx];
    memset(entry, 0, sizeof(OfflineEvent_t));

    s_event_seq++;
    entry->sequence_num = (seq_num > 0U) ? seq_num : s_event_seq;
    if (client_event_id != NULL && client_event_id[0] != '\0') {
        strncpy(entry->client_event_id, client_event_id, sizeof(entry->client_event_id) - 1U);
    } else {
        snprintf(entry->client_event_id, sizeof(entry->client_event_id),
                 "rw612-evt-%08lx-%04lx",
                 (unsigned long)record->timestamp_tick,
                 (unsigned long)(entry->sequence_num & 0xFFFFU));
    }

    entry->timestamp_tick = record->timestamp_tick;
    entry->event_type = record->triggered_event;
    entry->severity = record->severity;
    strncpy(entry->description, record->event_description, sizeof(entry->description) - 1U);
    strncpy(entry->source_ip, record->source_ip, sizeof(entry->source_ip) - 1U);
    strncpy(entry->endpoint, record->endpoint, sizeof(entry->endpoint) - 1U);
    strncpy(entry->method, record->method, sizeof(entry->method) - 1U);
    entry->threat_score = record->ip_threat_score;
    strncpy(entry->risk_level, record->ip_risk_level, sizeof(entry->risk_level) - 1U);
    entry->is_synced = false;
    entry->retry_count = 0;

    s_tail_idx = (s_tail_idx + 1U) % OFFLINE_BUFFER_MAX_EVENTS;
    s_count++;
    s_total_recorded++;

    PRINTF("[OfflineBuffer] Stored offline event '%s' [ID: %s] (Pending: %lu/%d)\r\n",
           Detection_GetEventString(entry->event_type), entry->client_event_id,
           (unsigned long)s_count, OFFLINE_BUFFER_MAX_EVENTS);

    OFF_UNLOCK();
    return true;
}

bool OfflineBuffer_Push(const RequestRecord_t *record)
{
    return OfflineBuffer_PushWithId(record, NULL, 0U);
}

uint32_t OfflineBuffer_GetPendingCount(void)
{
    OFF_LOCK();
    uint32_t c = s_count;
    OFF_UNLOCK();
    return c;
}

uint32_t OfflineBuffer_GetBatch(OfflineEvent_t *out_batch, uint32_t max_count)
{
    if (!out_batch || max_count == 0U) {
        return 0U;
    }

    OFF_LOCK();
    uint32_t fetch_count = (s_count < max_count) ? s_count : max_count;
    for (uint32_t i = 0; i < fetch_count; i++) {
        uint32_t idx = (s_head_idx + i) % OFFLINE_BUFFER_MAX_EVENTS;
        memcpy(&out_batch[i], &s_offline_events[idx], sizeof(OfflineEvent_t));
    }
    OFF_UNLOCK();

    return fetch_count;
}

void OfflineBuffer_AckBatch(uint32_t count)
{
    OFF_LOCK();
    if (count > 0U && s_count > 0U) {
        if (count > s_count) {
            count = s_count;
        }
        s_head_idx = (s_head_idx + count) % OFFLINE_BUFFER_MAX_EVENTS;
        s_count -= count;
        s_total_reconciled += count;
        PRINTF("[OfflineBuffer] Reconciled %lu events. Remaining pending: %lu\r\n",
               (unsigned long)count, (unsigned long)s_count);
    }
    OFF_UNLOCK();
}

uint32_t OfflineBuffer_AckByIds(const char acked_ids[][48], uint32_t acked_count)
{
    if (!acked_ids || acked_count == 0U) {
        return 0U;
    }

    uint32_t removed = 0U;
    OFF_LOCK();
    for (uint32_t a = 0; a < acked_count; a++) {
        if (acked_ids[a][0] == '\0') {
            continue;
        }
        for (uint32_t i = 0; i < s_count; i++) {
            uint32_t idx = (s_head_idx + i) % OFFLINE_BUFFER_MAX_EVENTS;
            if (strncmp(s_offline_events[idx].client_event_id, acked_ids[a], 48) == 0) {
                RemoveAtLogicalOffset(i);
                s_total_reconciled++;
                removed++;
                break;
            }
        }
    }
    OFF_UNLOCK();
    return removed;
}

void OfflineBuffer_GetStats(OfflineBufferStats_t *out_stats)
{
    if (!out_stats) {
        return;
    }

    OFF_LOCK();
    out_stats->capacity = OFFLINE_BUFFER_MAX_EVENTS;
    out_stats->pending_count = s_count;
    out_stats->total_recorded = s_total_recorded;
    out_stats->total_reconciled = s_total_reconciled;
    out_stats->total_dropped = s_total_dropped;
    out_stats->total_dropped_routine = s_total_dropped_routine;
    out_stats->total_dropped_critical = s_total_dropped_critical;
    out_stats->is_reconciling = s_is_reconciling;
    out_stats->last_sync_tick = s_last_sync_tick;
    OFF_UNLOCK();
}

void OfflineBuffer_SetReconciling(bool is_reconciling)
{
    OFF_LOCK();
    s_is_reconciling = is_reconciling;
    OFF_UNLOCK();
}
