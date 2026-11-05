/*
 * IoT Honeypot Monitor — FRDM-RW612 Edge Intrusion Detection Rules Header
 */

#ifndef DETECTION_RULES_H_
#define DETECTION_RULES_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef enum {
    SEV_INFORMATIONAL = 0,
    SEV_WARNING = 1,
    SEV_CRITICAL = 2
} EventSeverity_t;

typedef enum {
    EVENT_NONE = 0,
    EVENT_UNKNOWN_ENDPOINT,
    EVENT_HIGH_REQUEST_RATE,
    EVENT_REPEATED_REQUESTS,
    EVENT_MALFORMED_METADATA
} SecurityEventType_t;

typedef struct {
    char method[12];
    char endpoint[128];
    char source_ip[48];
    int response_code;
    uint32_t timestamp_tick;
    bool is_unknown_endpoint;
    SecurityEventType_t triggered_event;
    EventSeverity_t severity;
    char event_description[128];
} RequestRecord_t;

/* Initialize edge detection tracking state */
void Detection_Init(void);

/* Normalize HTTP path safely: strips query strings, collapses duplicate slashes */
void Detection_NormalizePath(const char *raw_path, char *out_path, size_t max_len);

/* Check if normalized endpoint is in allowlist (/status, /info, /config) */
bool Detection_IsAllowedEndpoint(const char *normalized_path);

/* Evaluate request against edge detection rules */
void Detection_Evaluate(RequestRecord_t *record);

/* Helper to convert enum to string representations */
const char *Detection_GetSeverityString(EventSeverity_t severity);
const char *Detection_GetEventString(SecurityEventType_t event_type);

#endif /* DETECTION_RULES_H_ */
