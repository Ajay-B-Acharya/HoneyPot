/*
 * IoT Honeypot Monitor — FRDM-RW612 Telemetry Dispatcher Implementation
 */

#include "telemetry_client.h"
#include "offline_buffer.h"
#include "honeypot_config.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "fsl_debug_console.h"

#include <stdio.h>
#include <string.h>

static QueueHandle_t s_telemetry_queue = NULL;
static bool s_backend_online = true;
static uint32_t s_backoff_ms = 1000;

bool Telemetry_Init(void)
{
    if (s_telemetry_queue != NULL) {
        return true;
    }

    OfflineBuffer_Init();

    s_telemetry_queue = xQueueCreate(TELEMETRY_QUEUE_LENGTH, sizeof(RequestRecord_t));
    if (s_telemetry_queue == NULL) {
        PRINTF("[Telemetry] Failed to create FreeRTOS telemetry queue!\r\n");
        return false;
    }

    return true;
}

bool Telemetry_Enqueue(const RequestRecord_t *record)
{
    if (s_telemetry_queue == NULL || record == NULL) {
        return false;
    }

    BaseType_t status = xQueueSend(s_telemetry_queue, record, pdMS_TO_TICKS(50));
    if (status != pdPASS) {
        PRINTF("[Telemetry] Queue full! Dropping oldest telemetry record.\r\n");
        RequestRecord_t dummy;
        xQueueReceive(s_telemetry_queue, &dummy, 0);
        xQueueSend(s_telemetry_queue, record, 0);
    }
    return true;
}

static bool SendHttpPayload(const char *path, const char *json_payload)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        PRINTF("[Telemetry] socket() failed: %d\r\n", sock);
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
        PRINTF("[Telemetry] connect() to %s:%d failed!\r\n", BACKEND_HOST_IP, BACKEND_HOST_PORT);
        close(sock);
        return false;
    }

    char http_req[1024];
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

    int sent = send(sock, http_req, req_len, 0);
    if (sent < 0) {
        PRINTF("[Telemetry] send() failed!\r\n");
        close(sock);
        return false;
    }

    char rx_buf[256];
    int recvd = recv(sock, rx_buf, sizeof(rx_buf) - 1, 0);
    close(sock);

    if (recvd > 0) {
        rx_buf[recvd] = '\0';
        if (strstr(rx_buf, "200 OK") != NULL || strstr(rx_buf, "201 Created") != NULL) {
            return true;
        }
        PRINTF("[Telemetry] Backend responded with non-2xx status: %.32s\r\n", rx_buf);
    }
    return false;
}

static void ReconcileOfflineEvents(void)
{
    if (OfflineBuffer_GetPendingCount() == 0) {
        return;
    }

    OfflineBuffer_SetReconciling(true);
    PRINTF("[Telemetry] Starting offline reconciliation (%lu pending events)...\r\n",
           (unsigned long)OfflineBuffer_GetPendingCount());

    OfflineEvent_t batch[4];
    char batch_buf[2048];

    while (OfflineBuffer_GetPendingCount() > 0) {
        uint32_t count = OfflineBuffer_GetBatch(batch, 4);
        if (count == 0) {
            break;
        }

        int offset = snprintf(batch_buf, sizeof(batch_buf), "{\"events\":[");
        for (uint32_t i = 0; i < count; i++) {
            offset += snprintf(batch_buf + offset, sizeof(batch_buf) - offset,
                               "%s{"
                               "\"client_event_id\":\"%s\","
                               "\"timestamp\":\"2026-10-27T08:00:00Z\","
                               "\"device_id\":\"%s\","
                               "\"event_type\":\"%s\","
                               "\"severity\":\"%s\","
                               "\"description\":\"%s\","
                               "\"source_ip\":\"%s\","
                               "\"metadata\":{\"endpoint\":\"%s\",\"method\":\"%s\",\"threat_score\":%u,\"risk_level\":\"%s\"}"
                               "}",
                               (i > 0) ? "," : "",
                               batch[i].client_event_id,
                               HONEYPOT_DEVICE_ID,
                               Detection_GetEventString(batch[i].event_type),
                               Detection_GetSeverityString(batch[i].severity),
                               batch[i].description,
                               batch[i].source_ip,
                               batch[i].endpoint,
                               batch[i].method,
                               batch[i].threat_score,
                               batch[i].risk_level);
            if (offset >= (int)sizeof(batch_buf) - 64) {
                break;
            }
        }
        snprintf(batch_buf + offset, sizeof(batch_buf) - offset, "]}");

        if (SendHttpPayload("/api/events/batch", batch_buf)) {
            OfflineBuffer_AckBatch(count);
            vTaskDelay(pdMS_TO_TICKS(100)); /* Gentle pacing between batches */
        } else {
            PRINTF("[Telemetry] Batch reconciliation paused due to transmission failure.\r\n");
            break;
        }
    }
    OfflineBuffer_SetReconciling(false);
}

void Telemetry_Task(void *param)
{
    (void)param;
    RequestRecord_t record;
    char json_buf[512];

    PRINTF("[Telemetry] Telemetry task running. Target: %s:%d\r\n",
           BACKEND_HOST_IP, BACKEND_HOST_PORT);

    for (;;) {
        if (xQueueReceive(s_telemetry_queue, &record, portMAX_DELAY) == pdPASS) {
            /* 1. Format and dispatch POST /api/logs payload */
            snprintf(json_buf, sizeof(json_buf),
                     "{"
                     "\"timestamp\":\"2026-10-27T08:00:00Z\","
                     "\"device_id\":\"%s\","
                     "\"source_ip\":\"%s\","
                     "\"method\":\"%s\","
                     "\"endpoint\":\"%s\","
                     "\"response_code\":%d,"
                     "\"classification\":\"%s\""
                     "}",
                     HONEYPOT_DEVICE_ID,
                     record.source_ip,
                     record.method,
                     record.endpoint,
                     record.response_code,
                     record.is_unknown_endpoint ? "unusual" : "normal");

            bool log_sent = false;
            for (int attempt = 1; attempt <= TELEMETRY_MAX_RETRIES; attempt++) {
                if (SendHttpPayload("/api/logs", json_buf)) {
                    log_sent = true;
                    break;
                }
                vTaskDelay(pdMS_TO_TICKS(500 * attempt));
            }

            /* 2. Dispatch security event if triggered */
            bool event_sent = true;
            if (record.triggered_event != EVENT_NONE) {
                event_sent = false;
                snprintf(json_buf, sizeof(json_buf),
                         "{"
                         "\"timestamp\":\"2026-10-27T08:00:00Z\","
                         "\"device_id\":\"%s\","
                         "\"event_type\":\"%s\","
                         "\"severity\":\"%s\","
                         "\"description\":\"%s\","
                         "\"source_ip\":\"%s\","
                         "\"metadata\":{\"endpoint\":\"%s\",\"method\":\"%s\",\"threat_score\":%u,\"risk_level\":\"%s\"}"
                         "}",
                         HONEYPOT_DEVICE_ID,
                         Detection_GetEventString(record.triggered_event),
                         Detection_GetSeverityString(record.severity),
                         record.event_description,
                         record.source_ip,
                         record.endpoint,
                         record.method,
                         record.ip_threat_score,
                         record.ip_risk_level);

                for (int attempt = 1; attempt <= TELEMETRY_MAX_RETRIES; attempt++) {
                    if (SendHttpPayload("/api/events", json_buf)) {
                        event_sent = true;
                        break;
                    }
                    vTaskDelay(pdMS_TO_TICKS(500 * attempt));
                }
            }

            /* 3. Handle Offline Continuity & State Reconciliation */
            if (!log_sent || !event_sent) {
                /* Backend is currently offline */
                if (s_backend_online) {
                    s_backend_online = false;
                    PRINTF("[Telemetry] Backend unreachable. Entering OFFLINE detection mode.\r\n");
                }

                /* Store security event in bounded local offline buffer */
                if (record.triggered_event != EVENT_NONE) {
                    OfflineBuffer_Push(&record);
                }

                /* Apply exponential backoff delay (max 30s) */
                s_backoff_ms = (s_backoff_ms < 15000) ? (s_backoff_ms * 2) : 30000;
                vTaskDelay(pdMS_TO_TICKS(s_backoff_ms));
            } else {
                /* Telemetry dispatched successfully */
                if (!s_backend_online) {
                    s_backend_online = true;
                    s_backoff_ms = 1000;
                    PRINTF("[Telemetry] Connectivity restored! Initiating state reconciliation...\r\n");
                    ReconcileOfflineEvents();
                } else if (OfflineBuffer_GetPendingCount() > 0) {
                    ReconcileOfflineEvents();
                }
            }
        }
    }
}
