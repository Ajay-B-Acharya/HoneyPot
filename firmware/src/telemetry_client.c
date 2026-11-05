/*
 * IoT Honeypot Monitor — FRDM-RW612 Telemetry Dispatcher Implementation
 */

#include "telemetry_client.h"
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

bool Telemetry_Init(void)
{
    if (s_telemetry_queue != NULL) {
        return true;
    }

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

            bool sent_ok = false;
            for (int attempt = 1; attempt <= TELEMETRY_MAX_RETRIES; attempt++) {
                if (SendHttpPayload("/api/logs", json_buf)) {
                    PRINTF("[Telemetry] Ingested log: %s %s -> HTTP %d\r\n",
                           record.method, record.endpoint, record.response_code);
                    sent_ok = true;
                    break;
                }
                PRINTF("[Telemetry] Log dispatch retry %d/%d...\r\n", attempt, TELEMETRY_MAX_RETRIES);
                vTaskDelay(pdMS_TO_TICKS(1000 * attempt));
            }
            if (!sent_ok) {
                PRINTF("[Telemetry] Warning: Log dispatch failed after all retries.\r\n");
            }

            /* 2. If a security anomaly occurred, dispatch POST /api/events */
            if (record.triggered_event != EVENT_NONE) {
                snprintf(json_buf, sizeof(json_buf),
                         "{"
                         "\"timestamp\":\"2026-10-27T08:00:00Z\","
                         "\"device_id\":\"%s\","
                         "\"event_type\":\"%s\","
                         "\"severity\":\"%s\","
                         "\"description\":\"%s\","
                         "\"source_ip\":\"%s\","
                         "\"metadata\":{\"endpoint\":\"%s\",\"method\":\"%s\"}"
                         "}",
                         HONEYPOT_DEVICE_ID,
                         Detection_GetEventString(record.triggered_event),
                         Detection_GetSeverityString(record.severity),
                         record.event_description,
                         record.source_ip,
                         record.endpoint,
                         record.method);

                for (int attempt = 1; attempt <= TELEMETRY_MAX_RETRIES; attempt++) {
                    if (SendHttpPayload("/api/events", json_buf)) {
                        PRINTF("[Telemetry] Alert dispatched! Type: %s, Sev: %s\r\n",
                               Detection_GetEventString(record.triggered_event),
                               Detection_GetSeverityString(record.severity));
                        break;
                    }
                    vTaskDelay(pdMS_TO_TICKS(1000 * attempt));
                }
            }
        }
    }
}
