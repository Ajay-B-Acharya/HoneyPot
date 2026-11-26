/*
 * IoT Honeypot Monitor — FRDM-RW612 Attack Sequence Detection Header
 *
 * Implements lightweight multi-stage attack sequence pattern recognition:
 * - Endpoint categorization (Root, Admin, Config, Login, Unknown, Status/Info)
 * - Per-IP rolling request history ring buffer
 * - Multi-stage attack sequence patterns:
 *   1. Reconnaissance Probe: / -> /admin -> /config
 *   2. Credential Hunting: /admin -> /login
 *   3. Configuration Probing: repeated /config probes
 *   4. Unknown Endpoint Sweep: >= 3 unknown endpoints
 * - Sequence threat score generation
 * - Integration with Behavioral IP Profiling and Security Events
 */

#ifndef SEQUENCE_DETECTION_H_
#define SEQUENCE_DETECTION_H_

#include "detection_rules.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define SEQ_HISTORY_DEPTH          6
#define SEQ_WINDOW_MS              30000 /* 30 seconds rolling window */
#define SEQ_ALERT_COOLDOWN_MS      15000 /* 15 seconds cooldown per pattern */

typedef enum {
    EP_CAT_OTHER = 0,
    EP_CAT_ROOT,       /* "/" */
    EP_CAT_STATUS,     /* "/status" */
    EP_CAT_INFO,       /* "/info" */
    EP_CAT_CONFIG,     /* "/config", "/setup", "/system", "/settings" */
    EP_CAT_ADMIN,      /* "/admin", "/administrator", "/wp-admin", "/manager" */
    EP_CAT_LOGIN,      /* "/login", "/auth", "/signin", "/wp-login.php" */
    EP_CAT_UNKNOWN     /* other unallowed endpoints like /shell, /cmd, etc. */
} EndpointCategory_t;

typedef enum {
    PATTERN_NONE = 0,
    PATTERN_RECONNAISSANCE,    /* Root -> Admin -> Config / Login */
    PATTERN_CREDENTIAL_HUNT,   /* Admin -> Login probing */
    PATTERN_CONFIG_PROBING,    /* Repeated configuration probing */
    PATTERN_UNKNOWN_SWEEP      /* Multi-unknown endpoint sweep */
} AttackPattern_t;

typedef struct {
    EndpointCategory_t endpoints[SEQ_HISTORY_DEPTH];
    uint32_t ticks[SEQ_HISTORY_DEPTH];
    uint8_t count;
    uint8_t head;
    AttackPattern_t last_detected_pattern;
    uint32_t last_alert_tick;
    uint32_t pattern_count;
} IPSequenceHistory_t;

/* Initialize sequence detection subsystem */
void Sequence_Init(void);

/* Classify an endpoint path into a lightweight token category */
EndpointCategory_t Sequence_CategorizeEndpoint(const char *path);

/* Get human-readable name of endpoint category */
const char *Sequence_GetCategoryString(EndpointCategory_t cat);

/* Get human-readable name of attack pattern */
const char *Sequence_GetPatternString(AttackPattern_t pattern);

/*
 * Record request in IP sequence history and evaluate for attack patterns.
 * Returns detected pattern (or PATTERN_NONE).
 * If pattern detected:
 * - out_threat_delta: score increment (e.g. 25-40)
 * - out_desc: human-readable description
 */
AttackPattern_t Sequence_Evaluate(
    IPSequenceHistory_t *history,
    const char *endpoint,
    uint32_t current_tick,
    uint8_t *out_threat_delta,
    char *out_desc,
    size_t max_desc_len
);

#endif /* SEQUENCE_DETECTION_H_ */
