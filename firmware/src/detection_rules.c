/*
 * IoT Honeypot Monitor — FRDM-RW612 Edge Intrusion Detection Rules Implementation
 */

#include "detection_rules.h"
#include "honeypot_config.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define RATE_RING_SIZE 32

/* In-memory sliding buffer for edge rate monitoring */
static uint32_t s_request_ticks[RATE_RING_SIZE];
static uint32_t s_ring_head = 0;
static uint32_t s_total_recorded = 0;

/* Repeated request tracking */
static char s_last_endpoint[128] = "";
static char s_last_ip[48] = "";
static uint32_t s_repeat_count = 0;

void Detection_Init(void)
{
    memset(s_request_ticks, 0, sizeof(s_request_ticks));
    s_ring_head = 0;
    s_total_recorded = 0;
    memset(s_last_endpoint, 0, sizeof(s_last_endpoint));
    memset(s_last_ip, 0, sizeof(s_last_ip));
    s_repeat_count = 0;
}

void Detection_NormalizePath(const char *raw_path, char *out_path, size_t max_len)
{
    if (!raw_path || !out_path || max_len < 2) {
        if (out_path && max_len > 1) {
            out_path[0] = '/';
            out_path[1] = '\0';
        }
        return;
    }

    size_t in_len = strlen(raw_path);
    size_t out_idx = 0;

    /* Ensure leading slash */
    out_path[out_idx++] = '/';

    size_t i = 0;
    /* Skip leading whitespace and leading slashes */
    while (i < in_len && (raw_path[i] == ' ' || raw_path[i] == '/')) {
        i++;
    }

    bool last_was_slash = true;

    while (i < in_len && out_idx < (max_len - 1)) {
        char c = raw_path[i];

        /* Stop at query string or fragment */
        if (c == '?' || c == '#') {
            break;
        }

        /* Collapse multiple consecutive slashes */
        if (c == '/') {
            if (!last_was_slash) {
                out_path[out_idx++] = '/';
                last_was_slash = true;
            }
        } else {
            out_path[out_idx++] = c;
            last_was_slash = false;
        }
        i++;
    }

    /* Strip trailing slash unless root '/' */
    if (out_idx > 1 && out_path[out_idx - 1] == '/') {
        out_idx--;
    }

    out_path[out_idx] = '\0';
}

bool Detection_IsAllowedEndpoint(const char *normalized_path)
{
    if (!normalized_path) return false;

    if (strcmp(normalized_path, "/status") == 0 ||
        strcmp(normalized_path, "/info") == 0 ||
        strcmp(normalized_path, "/config") == 0) {
        return true;
    }
    return false;
}

void Detection_Evaluate(RequestRecord_t *record)
{
    if (!record) return;

    record->triggered_event = EVENT_NONE;
    record->severity = SEV_INFORMATIONAL;
    record->event_description[0] = '\0';

    /* Rule R1: Unknown Endpoint Detection */
    if (!Detection_IsAllowedEndpoint(record->endpoint)) {
        record->is_unknown_endpoint = true;
        record->triggered_event = EVENT_UNKNOWN_ENDPOINT;
        record->severity = SEV_WARNING;
        snprintf(record->event_description, sizeof(record->event_description),
                 "Request received for unknown endpoint: '%s'", record->endpoint);
        return;
    } else {
        record->is_unknown_endpoint = false;
    }

    /* Rule R2: Request-Rate Tracking (Sliding Tick Window) */
    uint32_t now_tick = record->timestamp_tick;
    s_request_ticks[s_ring_head] = now_tick;
    s_ring_head = (s_ring_head + 1) % RATE_RING_SIZE;
    if (s_total_recorded < RATE_RING_SIZE) {
        s_total_recorded++;
    }

    uint32_t window_count = 0;
    for (uint32_t k = 0; k < s_total_recorded; k++) {
        if ((now_tick >= s_request_ticks[k]) &&
            ((now_tick - s_request_ticks[k]) <= EDGE_RATE_WINDOW_MS)) {
            window_count++;
        }
    }

    if (window_count >= EDGE_RATE_THRESHOLD) {
        record->triggered_event = EVENT_HIGH_REQUEST_RATE;
        record->severity = SEV_WARNING;
        snprintf(record->event_description, sizeof(record->event_description),
                 "High request rate detected from %s: %lu requests in window",
                 record->source_ip, (unsigned long)window_count);
        return;
    }

    /* Rule R3: Repeated Endpoint Probing */
    if (strcmp(s_last_endpoint, record->endpoint) == 0 &&
        strcmp(s_last_ip, record->source_ip) == 0) {
        s_repeat_count++;
        if (s_repeat_count >= EDGE_REPEATED_THRESHOLD) {
            record->triggered_event = EVENT_REPEATED_REQUESTS;
            record->severity = SEV_WARNING;
            snprintf(record->event_description, sizeof(record->event_description),
                     "Repeated requests detected for endpoint '%s': %lu requests",
                     record->endpoint, (unsigned long)s_repeat_count);
            return;
        }
    } else {
        strncpy(s_last_endpoint, record->endpoint, sizeof(s_last_endpoint) - 1);
        strncpy(s_last_ip, record->source_ip, sizeof(s_last_ip) - 1);
        s_repeat_count = 1;
    }
}

const char *Detection_GetSeverityString(EventSeverity_t severity)
{
    switch (severity) {
        case SEV_CRITICAL: return "critical";
        case SEV_WARNING:  return "warning";
        default:           return "informational";
    }
}

const char *Detection_GetEventString(SecurityEventType_t event_type)
{
    switch (event_type) {
        case EVENT_UNKNOWN_ENDPOINT:    return "unknown_endpoint";
        case EVENT_HIGH_REQUEST_RATE:   return "high_request_rate";
        case EVENT_REPEATED_REQUESTS:   return "repeated_requests";
        case EVENT_MALFORMED_METADATA:  return "malformed_request";
        default:                        return "normal_traffic";
    }
}
