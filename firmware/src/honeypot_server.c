/*
 * IoT Honeypot Monitor — FRDM-RW612 Honeypot HTTP Server Implementation
 */

#include "honeypot_server.h"
#include "honeypot_config.h"
#include "detection_rules.h"
#include "telemetry_client.h"

#include "FreeRTOS.h"
#include "task.h"

#include "lwip/sockets.h"
#include "fsl_debug_console.h"

#include <stdio.h>
#include <string.h>

static void HandleHttpClient(int client_sock, struct sockaddr_in *client_addr)
{
    char rx_buffer[1024];
    char resp_body[256];
    char http_resp[512];

    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int bytes_read = recv(client_sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
    if (bytes_read <= 0) {
        close(client_sock);
        return;
    }
    rx_buffer[bytes_read] = '\0';

    /* Parse request line: e.g. "GET /status HTTP/1.1" */
    char method[12] = "GET";
    char raw_path[128] = "/";
    char norm_path[128] = "/";

    char *first_space = strchr(rx_buffer, ' ');
    if (first_space != NULL) {
        size_t method_len = first_space - rx_buffer;
        if (method_len < sizeof(method)) {
            memcpy(method, rx_buffer, method_len);
            method[method_len] = '\0';
        }

        char *second_space = strchr(first_space + 1, ' ');
        if (second_space != NULL) {
            size_t path_len = second_space - (first_space + 1);
            if (path_len < sizeof(raw_path)) {
                memcpy(raw_path, first_space + 1, path_len);
                raw_path[path_len] = '\0';
            }
        }
    }

    Detection_NormalizePath(raw_path, norm_path, sizeof(norm_path));

    /* Populate Request Record */
    RequestRecord_t record;
    memset(&record, 0, sizeof(record));
    strncpy(record.method, method, sizeof(record.method) - 1);
    strncpy(record.endpoint, norm_path, sizeof(record.endpoint) - 1);
    strncpy(record.source_ip, inet_ntoa(client_addr->sin_addr), sizeof(record.source_ip) - 1);
    record.timestamp_tick = xTaskGetTickCount() * portTICK_PERIOD_MS;

    /* Evaluate Threat Rules on Board */
    Detection_Evaluate(&record);

    int status_code = 200;
    const char *status_text = "OK";

    if (strcmp(norm_path, "/status") == 0) {
        uint32_t uptime_sec = (record.timestamp_tick / 1000);
        snprintf(resp_body, sizeof(resp_body),
                 "{\"device_status\":\"ok\",\"uptime_sec\":%lu,\"device_id\":\"%s\",\"free_heap\":%u}\r\n",
                 (unsigned long)uptime_sec, HONEYPOT_DEVICE_ID, (unsigned int)xPortGetFreeHeapSize());
    } else if (strcmp(norm_path, "/info") == 0) {
        snprintf(resp_body, sizeof(resp_body),
                 "{\"vendor\":\"NXP Semiconductors\",\"model\":\"%s\",\"firmware\":\"%s\",\"device_id\":\"%s\"}\r\n",
                 HONEYPOT_MODEL, HONEYPOT_FW_VERSION, HONEYPOT_DEVICE_ID);
    } else if (strcmp(norm_path, "/config") == 0) {
        snprintf(resp_body, sizeof(resp_body),
                 "{\"dhcp_enabled\":true,\"reporting_interval_ms\":5000,\"telemetry_mode\":\"edge\"}\r\n");
    } else {
        /* Unknown Endpoint -> 404 Decoy */
        status_code = 404;
        status_text = "Not Found";
        snprintf(resp_body, sizeof(resp_body),
                 "{\"error\":\"Not Found\",\"endpoint\":\"%s\"}\r\n", norm_path);
    }

    record.response_code = status_code;

    /* Format HTTP response headers and body */
    int resp_len = snprintf(http_resp, sizeof(http_resp),
                            "HTTP/1.1 %d %s\r\n"
                            "Content-Type: application/json\r\n"
                            "Content-Length: %d\r\n"
                            "Server: NXP-FRDM-RW612-Honeypot\r\n"
                            "Connection: close\r\n\r\n"
                            "%s",
                            status_code, status_text, (int)strlen(resp_body), resp_body);

    if (resp_len > 0) {
        send(client_sock, http_resp, resp_len, 0);
    }
    close(client_sock);

    PRINTF("[Honeypot] %s %s from %s -> %d %s %s\r\n",
           record.method, record.endpoint, record.source_ip,
           record.response_code,
           record.is_unknown_endpoint ? "[ALERT: Unknown Endpoint]" : "",
           record.triggered_event == EVENT_HIGH_REQUEST_RATE ? "[ALERT: High Rate]" : "");

    /* Forward to Telemetry Queue for Ingestion */
    Telemetry_Enqueue(&record);
}

void Honeypot_Server_Task(void *param)
{
    (void)param;
    int listen_sock = -1;
    struct sockaddr_in server_addr;

    PRINTF("[Honeypot] Starting Honeypot HTTP Listener on port %d...\r\n", HONEYPOT_HTTP_PORT);

    while (listen_sock < 0) {
        listen_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_sock < 0) {
            PRINTF("[Honeypot] Waiting for network stack... (socket error: %d)\r\n", listen_sock);
            vTaskDelay(pdMS_TO_TICKS(1500));
        }
    }

    int enable = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(HONEYPOT_HTTP_PORT);

    while (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        PRINTF("[Honeypot] Socket bind() retrying in 1s...\r\n");
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    if (listen(listen_sock, 4) < 0) {
        PRINTF("[Honeypot] Socket listen() failed!\r\n");
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }

    PRINTF("[Honeypot] Decoy server active. Decoy routes: /status, /info, /config\r\n");

    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_len);

        if (client_sock >= 0) {
            HandleHttpClient(client_sock, &client_addr);
        }
    }
}
