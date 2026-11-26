/*
 * IoT Honeypot Monitor — FRDM-RW612 Honeypot HTTP Server Implementation
 */

#include "honeypot_server.h"
#include "honeypot_config.h"
#include "detection_rules.h"
#include "ip_profile.h"
#include "sequence_detection.h"
#include "threat_memory_manager.h"
#include "offline_buffer.h"
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
    char resp_body[512];
    char http_resp[768];

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

    /* Update Behavioral IP Profile on FRDM-RW612 (thread-safe) */
    IPProfile_Lock();
    IPProfile_t *profile = IPProfile_GetOrCreate(record.source_ip, record.timestamp_tick);
    if (profile != NULL) {
        IPProfile_Update(profile, &record);

        /* Evaluate Multi-Stage Attack Sequences */
        uint8_t seq_threat_delta = 0;
        char seq_desc[128] = "";
        AttackPattern_t pattern = Sequence_Evaluate(&profile->sequence_history,
                                                    record.endpoint,
                                                    record.timestamp_tick,
                                                    &seq_threat_delta,
                                                    seq_desc,
                                                    sizeof(seq_desc));
        if (pattern != PATTERN_NONE) {
            uint32_t new_score = profile->threat_score + seq_threat_delta;
            profile->threat_score = (new_score > 100) ? 100 : (uint8_t)new_score;
            record.triggered_event = EVENT_ATTACK_SEQUENCE;
            record.severity = (pattern == PATTERN_RECONNAISSANCE ||
                               pattern == PATTERN_CREDENTIAL_HUNT ||
                               profile->sequence_history.sequence_score >= SEQ_SCORE_CRIT_THRESHOLD) ?
                              SEV_CRITICAL : SEV_WARNING;
            strncpy(record.event_description, seq_desc, sizeof(record.event_description) - 1);
            PRINTF("[Sequence] ALERT: Pattern '%s' detected from %s (+%u score, seq=%u)\r\n",
                   Sequence_GetPatternString(pattern), record.source_ip,
                   seq_threat_delta, (unsigned int)profile->sequence_history.sequence_score);
        }

        record.ip_threat_score = profile->threat_score;
        strncpy(record.ip_risk_level, IPProfile_GetRiskLevelString(profile->risk_level), sizeof(record.ip_risk_level) - 1);
    }
    IPProfile_Unlock();

    int status_code = 200;
    const char *status_text = "OK";

    if (strcmp(norm_path, "/status") == 0) {
        uint32_t uptime_sec = (record.timestamp_tick / 1000);
        uint32_t active_ips = IPProfile_GetActiveCount();
        MemoryPressureLevel_t pressure = ThreatMem_GetPressureLevel(active_ips);
        snprintf(resp_body, sizeof(resp_body),
                 "{\"device_status\":\"ok\",\"uptime_sec\":%lu,\"device_id\":\"%s\",\"free_heap\":%u,"
                 "\"active_ip_profiles\":%lu,\"mem_pressure\":\"%s\",\"pending_offline_events\":%lu}\r\n",
                 (unsigned long)uptime_sec, HONEYPOT_DEVICE_ID, (unsigned int)xPortGetFreeHeapSize(),
                 (unsigned long)active_ips, ThreatMem_GetPressureString(pressure),
                 (unsigned long)OfflineBuffer_GetPendingCount());
    } else if (strcmp(norm_path, "/memory") == 0) {
        ThreatMemoryStats_t mem_stats;
        IPProfile_Lock();
        ThreatMem_GetStats(&mem_stats, IPProfile_GetActiveCount());
        IPProfile_Unlock();
        OfflineBufferStats_t off_stats;
        OfflineBuffer_GetStats(&off_stats);
        snprintf(resp_body, sizeof(resp_body),
                 "{\"device_id\":\"%s\",\"total_security_bss_bytes\":%lu,\"active_profiles\":%lu,"
                 "\"max_profiles\":%lu,\"profile_bytes_used\":%lu,\"free_heap\":%lu,\"min_free_heap\":%lu,"
                 "\"pressure_level\":\"%s\",\"evictions\":%lu,\"pressure_events\":%lu,\"sequence_detections\":%lu,"
                 "\"compressed_benign\":%lu,\"compressed_suspicious\":%lu,\"highest_evicted_score\":%u,\"pending_offline_events\":%lu}\r\n",
                 HONEYPOT_DEVICE_ID,
                 (unsigned long)mem_stats.total_security_bss_bytes,
                 (unsigned long)mem_stats.active_profiles_count,
                 (unsigned long)mem_stats.max_profiles_capacity,
                 (unsigned long)mem_stats.profile_bytes_used,
                 (unsigned long)mem_stats.free_heap_bytes,
                 (unsigned long)mem_stats.min_ever_free_heap_bytes,
                 ThreatMem_GetPressureString(mem_stats.pressure_level),
                 (unsigned long)mem_stats.eviction_summary.total_evicted_count,
                 (unsigned long)mem_stats.memory_pressure_events,
                 (unsigned long)mem_stats.sequence_detections,
                 (unsigned long)mem_stats.eviction_summary.evicted_benign_count,
                 (unsigned long)mem_stats.eviction_summary.evicted_suspicious_count,
                 mem_stats.eviction_summary.highest_evicted_threat_score,
                 (unsigned long)off_stats.pending_count);
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

    PRINTF("[Honeypot] %s %s from %s -> %d (Score: %u, Risk: %s) %s %s\r\n",
           record.method, record.endpoint, record.source_ip,
           record.response_code,
           record.ip_threat_score, record.ip_risk_level,
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
