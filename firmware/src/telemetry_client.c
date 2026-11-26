/*
 * IoT Honeypot Monitor — FRDM-RW612 Resilient Telemetry Dispatcher Implementation
 */

#include "telemetry_client.h"
#include "offline_buffer.h"
#include "honeypot_config.h"

#ifndef HOST_UNIT_TEST
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "fsl_debug_console.h"
#else
#include <stdlib.h>
#define PRINTF(...) ((void)0)
typedef void *QueueHandle_t;
#define pdPASS 1
#define pdMS_TO_TICKS(x) (x)
#define vTaskDelay(x) ((void)0)
static inline QueueHandle_t xQueueCreate(uint32_t len, uint32_t item_sz) { (void)len; (void)item_sz; return (QueueHandle_t)1; }
static inline int xQueueSend(QueueHandle_t q, const void *item, uint32_t ticks) { (void)q; (void)item; (void)ticks; return pdPASS; }
static inline int xQueueReceive(QueueHandle_t q, void *item, uint32_t ticks) { (void)q; (void)item; (void)ticks; return 0; }
static inline uint32_t uxQueueMessagesWaiting(QueueHandle_t q) { (void)q; return 0; }
#endif

#include <stdio.h>
#include <string.h>

static QueueHandle_t s_critical_queue = NULL;
static QueueHandle_t s_routine_queue = NULL;

static volatile bool s_wifi_connected = false;
static bool s_backend_online = true;
static uint32_t s_monotonic_seq = 0;

static TelemetryStats_t s_tel_stats;

uint32_t Telemetry_ComputeAdaptiveBackoffMs(uint32_t queue_occ_pct, uint32_t failure_streak)
{
    if (failure_streak == 0U) {
        return (queue_occ_pct >= 75U) ? 200U : 1000U;
    }
    uint32_t shift = (failure_streak > 6U) ? 6U : failure_streak;
    uint32_t delay = 1000U << (shift - 1U);
    if (delay > 30000U) {
        delay = 30000U;
    }
    /* Under high queue pressure, probe slightly faster (half backoff, min 1s) */
    if (queue_occ_pct >= 75U && delay > 1000U) {
        delay = delay / 2U;
        if (delay < 1000U) {
            delay = 1000U;
        }
    }
    return delay;
}

uint32_t Telemetry_ComputeAdaptiveBatchSize(uint32_t current_size, bool last_batch_ok, uint32_t queue_occ_pct)
{
    uint32_t sz = current_size;
    if (sz < TELEMETRY_MIN_BATCH_SIZE) {
        sz = TELEMETRY_MIN_BATCH_SIZE;
    }
    if (last_batch_ok) {
        if (queue_occ_pct >= 50U && sz < TELEMETRY_MAX_BATCH_SIZE) {
            sz = (sz * 2U <= TELEMETRY_MAX_BATCH_SIZE) ? (sz * 2U) : TELEMETRY_MAX_BATCH_SIZE;
        } else if (sz < 4U) {
            sz++;
        }
    } else {
        sz = (sz > 1U) ? (sz / 2U) : 1U;
    }
    return sz;
}

bool Telemetry_Init(void)
{
    if (s_critical_queue != NULL && s_routine_queue != NULL) {
        return true;
    }

    OfflineBuffer_Init();
    memset(&s_tel_stats, 0, sizeof(s_tel_stats));
    s_tel_stats.critical_queue_capacity = TELEMETRY_CRIT_QUEUE_LENGTH;
    s_tel_stats.routine_queue_capacity = TELEMETRY_ROUTINE_QUEUE_LENGTH;
    s_tel_stats.current_backoff_ms = 1000U;
    s_tel_stats.current_batch_size = 4U;
    s_tel_stats.backend_online = true;

    s_critical_queue = xQueueCreate(TELEMETRY_CRIT_QUEUE_LENGTH, sizeof(TelemetryItem_t));
    s_routine_queue = xQueueCreate(TELEMETRY_ROUTINE_QUEUE_LENGTH, sizeof(TelemetryItem_t));
    if (s_critical_queue == NULL || s_routine_queue == NULL) {
        PRINTF("[Telemetry] Failed to create priority-tiered FreeRTOS queues!\r\n");
        return false;
    }

    return true;
}

void Telemetry_SetWifiConnected(bool connected)
{
    s_wifi_connected = connected;
    s_tel_stats.wifi_connected = connected;
}

bool Telemetry_IsWifiConnected(void)
{
    return s_wifi_connected;
}

bool Telemetry_Enqueue(const RequestRecord_t *record)
{
    if (s_critical_queue == NULL || s_routine_queue == NULL || record == NULL) {
        return false;
    }

    TelemetryItem_t item;
    memset(&item, 0, sizeof(item));

    s_monotonic_seq++;
    item.seq_num = s_monotonic_seq;
    snprintf(item.client_event_id, sizeof(item.client_event_id),
             "rw612-evt-%08lx-%04lx",
             (unsigned long)record->timestamp_tick,
             (unsigned long)(item.seq_num & 0xFFFFU));

    strncpy(item.method, record->method, sizeof(item.method) - 1U);
    strncpy(item.endpoint, record->endpoint, sizeof(item.endpoint) - 1U);
    strncpy(item.source_ip, record->source_ip, sizeof(item.source_ip) - 1U);
    item.response_code = record->response_code;
    item.timestamp_tick = record->timestamp_tick;
    item.is_unknown_endpoint = record->is_unknown_endpoint;
    item.triggered_event = record->triggered_event;
    item.severity = record->severity;
    strncpy(item.event_description, record->event_description, sizeof(item.event_description) - 1U);
    item.ip_threat_score = record->ip_threat_score;
    item.endpoint_id = record->endpoint_id;
    item.edge_seq_score = record->edge_seq_score;
    strncpy(item.ip_risk_level, record->ip_risk_level, sizeof(item.ip_risk_level) - 1U);

    bool is_alert = (item.triggered_event != EVENT_NONE);
    if (is_alert) {
        if (xQueueSend(s_critical_queue, &item, 0) == pdPASS) {
            s_tel_stats.critical_enqueued++;
            return true;
        }
        /* Critical queue full: spill directly to OfflineBuffer so alert is never lost */
        if (OfflineBuffer_PushWithId(record, item.client_event_id, item.seq_num)) {
            s_tel_stats.spilled_to_offline++;
        } else {
            s_tel_stats.critical_dropped++;
        }
        return true;
    }

    /* Routine log: non-blocking send; drop oldest routine item if full (never touches critical queue) */
    if (xQueueSend(s_routine_queue, &item, 0) != pdPASS) {
        TelemetryItem_t dropped;
        (void)xQueueReceive(s_routine_queue, &dropped, 0);
        s_tel_stats.routine_dropped++;
        (void)xQueueSend(s_routine_queue, &item, 0);
    }
    s_tel_stats.routine_enqueued++;
    return true;
}

void Telemetry_GetStats(TelemetryStats_t *out_stats)
{
    if (!out_stats) {
        return;
    }
    s_tel_stats.critical_queue_depth = (s_critical_queue != NULL) ? (uint32_t)uxQueueMessagesWaiting(s_critical_queue) : 0U;
    s_tel_stats.routine_queue_depth = (s_routine_queue != NULL) ? (uint32_t)uxQueueMessagesWaiting(s_routine_queue) : 0U;
    s_tel_stats.wifi_connected = s_wifi_connected;
    s_tel_stats.backend_online = s_backend_online;
    memcpy(out_stats, &s_tel_stats, sizeof(TelemetryStats_t));
}

#ifndef HOST_UNIT_TEST
static bool SendHttpPayload(const char *path, const char *json_payload, char *out_body, size_t out_body_sz)
{
    if (!s_wifi_connected) {
        return false;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }

    struct timeval tv;
    tv.tv_sec = TELEMETRY_TIMEOUT_MS / 1000;
    tv.tv_usec = (TELEMETRY_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(BACKEND_HOST_PORT);
    serv_addr.sin_addr.s_addr = inet_addr(BACKEND_HOST_IP);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return false;
    }

    char http_req[2560];
    int req_len = snprintf(http_req, sizeof(http_req),
                           "POST %s HTTP/1.1\r\n"
                           "Host: %s:%d\r\n"
                           "Content-Type: application/json\r\n"
                           "Content-Length: %d\r\n"
                           "Connection: close\r\n\r\n"
                           "%s",
                           path, BACKEND_HOST_IP, BACKEND_HOST_PORT,
                           (int)strlen(json_payload), json_payload);

    if (req_len <= 0 || req_len >= (int)sizeof(http_req)) {
        close(sock);
        return false;
    }

    if (send(sock, http_req, req_len, 0) < 0) {
        close(sock);
        return false;
    }

    char rx_buf[512];
    int recvd = recv(sock, rx_buf, sizeof(rx_buf) - 1, 0);
    close(sock);

    if (recvd > 0) {
        rx_buf[recvd] = '\0';
        if (out_body != NULL && out_body_sz > 0U) {
            char *body_start = strstr(rx_buf, "\r\n\r\n");
            if (body_start != NULL) {
                strncpy(out_body, body_start + 4, out_body_sz - 1U);
                out_body[out_body_sz - 1U] = '\0';
            } else {
                out_body[0] = '\0';
            }
        }
        if (strstr(rx_buf, "200 OK") != NULL || strstr(rx_buf, "201 Created") != NULL) {
            return true;
        }
    }
    return false;
}

static uint32_t ParseAckedIdsFromJson(const char *json_body, char acked_ids[][48], uint32_t max_ids)
{
    if (!json_body || !acked_ids || max_ids == 0U) {
        return 0U;
    }
    const char *arr = strstr(json_body, "\"acked_ids\"");
    if (!arr) {
        return 0U;
    }
    const char *p = strchr(arr, '[');
    const char *end = p ? strchr(p, ']') : NULL;
    if (!p || !end) {
        return 0U;
    }

    uint32_t count = 0U;
    p++;
    while (p < end && count < max_ids) {
        const char *q1 = strchr(p, '"');
        if (!q1 || q1 >= end) break;
        const char *q2 = strchr(q1 + 1, '"');
        if (!q2 || q2 >= end) break;
        size_t len = (size_t)(q2 - (q1 + 1));
        if (len > 0U && len < 48U) {
            memcpy(acked_ids[count], q1 + 1, len);
            acked_ids[count][len] = '\0';
            count++;
        }
        p = q2 + 1;
    }
    return count;
}

static void ReconcileOfflineEvents(void)
{
    if (!s_wifi_connected || OfflineBuffer_GetPendingCount() == 0U) {
        return;
    }

    OfflineBuffer_SetReconciling(true);
    OfflineEvent_t batch[TELEMETRY_MAX_BATCH_SIZE];
    char batch_buf[2048];
    char resp_body[512];
    char acked_ids[TELEMETRY_MAX_BATCH_SIZE][48];

    while (OfflineBuffer_GetPendingCount() > 0U && s_wifi_connected) {
        uint32_t req_batch = s_tel_stats.current_batch_size;
        if (req_batch > TELEMETRY_MAX_BATCH_SIZE) req_batch = TELEMETRY_MAX_BATCH_SIZE;
        if (req_batch < TELEMETRY_MIN_BATCH_SIZE) req_batch = TELEMETRY_MIN_BATCH_SIZE;

        uint32_t count = OfflineBuffer_GetBatch(batch, req_batch);
        if (count == 0U) {
            break;
        }

        int offset = snprintf(batch_buf, sizeof(batch_buf), "{\"events\":[");
        uint32_t packed = 0U;
        for (uint32_t i = 0; i < count; i++) {
            int written = snprintf(batch_buf + offset, sizeof(batch_buf) - (size_t)offset,
                                   "%s{"
                                   "\"client_event_id\":\"%s\","
                                   "\"timestamp\":\"2026-10-27T08:00:00Z\","
                                   "\"device_id\":\"%s\","
                                   "\"event_type\":\"%s\","
                                   "\"severity\":\"%s\","
                                   "\"description\":\"%s\","
                                   "\"source_ip\":\"%s\","
                                   "\"metadata\":{\"endpoint\":\"%s\",\"method\":\"%s\",\"threat_score\":%u,\"risk_level\":\"%s\",\"uptime_ms\":%lu,\"seq_num\":%lu}"
                                   "}",
                                   (packed > 0U) ? "," : "",
                                   batch[i].client_event_id,
                                   HONEYPOT_DEVICE_ID,
                                   Detection_GetEventString(batch[i].event_type),
                                   Detection_GetSeverityString(batch[i].severity),
                                   batch[i].description,
                                   batch[i].source_ip,
                                   batch[i].endpoint,
                                   batch[i].method,
                                   batch[i].threat_score,
                                   batch[i].risk_level,
                                   (unsigned long)batch[i].timestamp_tick,
                                   (unsigned long)batch[i].sequence_num);
            if (written < 0 || (size_t)(offset + written) >= sizeof(batch_buf) - 16U) {
                break;
            }
            offset += written;
            packed++;
        }
        snprintf(batch_buf + offset, sizeof(batch_buf) - (size_t)offset, "]}");

        if (packed == 0U) {
            break;
        }

        uint32_t occ_pct = (OfflineBuffer_GetPendingCount() * 100U) / OFFLINE_BUFFER_MAX_EVENTS;
        if (SendHttpPayload("/api/events/batch", batch_buf, resp_body, sizeof(resp_body))) {
            uint32_t acked_n = ParseAckedIdsFromJson(resp_body, acked_ids, TELEMETRY_MAX_BATCH_SIZE);
            if (acked_n > 0U) {
                OfflineBuffer_AckByIds(acked_ids, acked_n);
            } else {
                OfflineBuffer_AckBatch(packed);
            }
            s_tel_stats.current_batch_size = Telemetry_ComputeAdaptiveBatchSize(s_tel_stats.current_batch_size, true, occ_pct);
            vTaskDelay(pdMS_TO_TICKS(50));
        } else {
            s_tel_stats.current_batch_size = Telemetry_ComputeAdaptiveBatchSize(s_tel_stats.current_batch_size, false, occ_pct);
            break;
        }
    }
    OfflineBuffer_SetReconciling(false);
}

static void ItemToRequestRecord(const TelemetryItem_t *item, RequestRecord_t *out)
{
    memset(out, 0, sizeof(*out));
    strncpy(out->method, item->method, sizeof(out->method) - 1U);
    strncpy(out->endpoint, item->endpoint, sizeof(out->endpoint) - 1U);
    strncpy(out->source_ip, item->source_ip, sizeof(out->source_ip) - 1U);
    out->response_code = item->response_code;
    out->timestamp_tick = item->timestamp_tick;
    out->is_unknown_endpoint = item->is_unknown_endpoint;
    out->triggered_event = item->triggered_event;
    out->severity = item->severity;
    strncpy(out->event_description, item->event_description, sizeof(out->event_description) - 1U);
    out->ip_threat_score = item->ip_threat_score;
    strncpy(out->ip_risk_level, item->ip_risk_level, sizeof(out->ip_risk_level) - 1U);
}

void Telemetry_Task(void *param)
{
    (void)param;
    TelemetryItem_t item;
    char json_buf[640];

    PRINTF("[Telemetry] Resilient Telemetry task running. Target: %s:%d\r\n",
           BACKEND_HOST_IP, BACKEND_HOST_PORT);

    for (;;) {
        /* 1. Priority-ordered dequeue: ALWAYS drain critical queue before routine queue */
        bool got_item = (xQueueReceive(s_critical_queue, &item, 0) == pdPASS);
        if (!got_item) {
            got_item = (xQueueReceive(s_routine_queue, &item, pdMS_TO_TICKS(1000)) == pdPASS);
            /* Re-check critical queue in case a critical alert arrived while waiting */
            if (!got_item && xQueueReceive(s_critical_queue, &item, 0) == pdPASS) {
                got_item = true;
            }
        }

        if (!got_item) {
            if (s_wifi_connected && OfflineBuffer_GetPendingCount() > 0U) {
                ReconcileOfflineEvents();
            }
            continue;
        }

        /* 2. If Wi-Fi is down, immediately preserve security alerts offline without blocking */
        if (!s_wifi_connected) {
            s_backend_online = false;
            if (item.triggered_event != EVENT_NONE) {
                RequestRecord_t rec;
                ItemToRequestRecord(&item, &rec);
                OfflineBuffer_PushWithId(&rec, item.client_event_id, item.seq_num);
            }
            s_tel_stats.failure_streak++;
            uint32_t occ = ((uint32_t)uxQueueMessagesWaiting(s_critical_queue) * 100U) / TELEMETRY_CRIT_QUEUE_LENGTH;
            s_tel_stats.current_backoff_ms = Telemetry_ComputeAdaptiveBackoffMs(occ, s_tel_stats.failure_streak);
            vTaskDelay(pdMS_TO_TICKS(s_tel_stats.current_backoff_ms));
            continue;
        }

        /* 3. Dispatch POST /api/logs with idempotent client_event_id */
        snprintf(json_buf, sizeof(json_buf),
                 "{"
                 "\"client_event_id\":\"%s-log\","
                 "\"timestamp\":\"2026-10-27T08:00:00Z\","
                 "\"device_id\":\"%s\","
                 "\"source_ip\":\"%s\","
                 "\"method\":\"%s\","
                 "\"endpoint\":\"%s\","
                 "\"response_code\":%d,"
                 "\"classification\":\"%s\""
                 "}",
                 item.client_event_id,
                 HONEYPOT_DEVICE_ID,
                 item.source_ip,
                 item.method,
                 item.endpoint,
                 (int)item.response_code,
                 item.is_unknown_endpoint ? "unusual" : "normal");

        bool log_sent = false;
        for (int attempt = 1; attempt <= TELEMETRY_MAX_RETRIES; attempt++) {
            if (SendHttpPayload("/api/logs", json_buf, NULL, 0U)) {
                log_sent = true;
                break;
            }
            s_tel_stats.total_retries++;
            vTaskDelay(pdMS_TO_TICKS(300 * attempt));
        }

        /* 4. Dispatch POST /api/events if security event triggered */
        bool event_sent = true;
        if (item.triggered_event != EVENT_NONE) {
            event_sent = false;
            snprintf(json_buf, sizeof(json_buf),
                     "{"
                     "\"client_event_id\":\"%s\","
                     "\"timestamp\":\"2026-10-27T08:00:00Z\","
                     "\"device_id\":\"%s\","
                     "\"event_type\":\"%s\","
                     "\"severity\":\"%s\","
                     "\"description\":\"%s\","
                     "\"source_ip\":\"%s\","
                     "\"metadata\":{\"endpoint\":\"%s\",\"endpoint_id\":%u,\"method\":\"%s\",\"threat_score\":%u,\"edge_score\":%u,\"observation_id\":\"%s\",\"risk_level\":\"%s\",\"uptime_ms\":%lu,\"seq_num\":%lu}"
                     "}",
                     item.client_event_id,
                     HONEYPOT_DEVICE_ID,
                     Detection_GetEventString(item.triggered_event),
                     Detection_GetSeverityString(item.severity),
                     item.event_description,
                     item.source_ip,
                     item.endpoint,
                     (unsigned int)item.endpoint_id,
                     item.method,
                     item.ip_threat_score,
                     (unsigned int)item.edge_seq_score,
                     item.client_event_id,
                     item.ip_risk_level,
                     (unsigned long)item.timestamp_tick,
                     (unsigned long)item.seq_num);

            for (int attempt = 1; attempt <= TELEMETRY_MAX_RETRIES; attempt++) {
                if (SendHttpPayload("/api/events", json_buf, NULL, 0U)) {
                    event_sent = true;
                    break;
                }
                s_tel_stats.total_retries++;
                vTaskDelay(pdMS_TO_TICKS(300 * attempt));
            }
        }

        /* 5. Offline continuity & adaptive backoff */
        uint32_t crit_occ = ((uint32_t)uxQueueMessagesWaiting(s_critical_queue) * 100U) / TELEMETRY_CRIT_QUEUE_LENGTH;
        if (!log_sent || !event_sent) {
            s_backend_online = false;
            s_tel_stats.failure_streak++;
            if (item.triggered_event != EVENT_NONE && !event_sent) {
                RequestRecord_t rec;
                ItemToRequestRecord(&item, &rec);
                OfflineBuffer_PushWithId(&rec, item.client_event_id, item.seq_num);
            }
            s_tel_stats.current_backoff_ms = Telemetry_ComputeAdaptiveBackoffMs(crit_occ, s_tel_stats.failure_streak);
            vTaskDelay(pdMS_TO_TICKS(s_tel_stats.current_backoff_ms));
        } else {
            s_backend_online = true;
            s_tel_stats.failure_streak = 0U;
            s_tel_stats.current_backoff_ms = Telemetry_ComputeAdaptiveBackoffMs(crit_occ, 0U);
            if (OfflineBuffer_GetPendingCount() > 0U) {
                ReconcileOfflineEvents();
            }
        }
    }
}
#endif
