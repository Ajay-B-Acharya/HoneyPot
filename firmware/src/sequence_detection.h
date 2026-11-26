/*
 * IoT Honeypot Monitor — FRDM-RW612 Memory- and CPU-Aware Attack Sequence Detection Header
 *
 * Implements deterministic, integer-only multi-stage attack sequence scoring:
 * - Collision-safe compact endpoint identifier (uint16_t) registry
 * - Fixed-size ring buffer with compact relative timestamps (uint16_t, 100ms units)
 * - Integer weighted progression scoring + endpoint severity weights
 * - Repeated transition & consecutive probe detection
 * - Wraparound-safe integer time-based score decay
 * - Configurable warning/critical thresholds and cooldown suppression
 */

#ifndef SEQUENCE_DETECTION_H_
#define SEQUENCE_DETECTION_H_

#include "detection_rules.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifndef SEQ_HISTORY_DEPTH
#define SEQ_HISTORY_DEPTH          8
#endif

#ifndef SEQ_WINDOW_MS
#define SEQ_WINDOW_MS              30000U /* 30 seconds rolling window */
#endif

#ifndef SEQ_ALERT_COOLDOWN_MS
#define SEQ_ALERT_COOLDOWN_MS      15000U /* 15 seconds cooldown per pattern */
#endif

#ifndef SEQ_DECAY_MS_PER_POINT
#define SEQ_DECAY_MS_PER_POINT     1000U  /* 1 point decayed per 1000 ms */
#endif

#ifndef SEQ_SCORE_WARN_THRESHOLD
#define SEQ_SCORE_WARN_THRESHOLD   40U
#endif

#ifndef SEQ_SCORE_CRIT_THRESHOLD
#define SEQ_SCORE_CRIT_THRESHOLD   70U
#endif

#ifndef SEQ_SCORE_MAX
#define SEQ_SCORE_MAX              100U
#endif

#ifndef ENDPOINT_REGISTRY_MAX
#define ENDPOINT_REGISTRY_MAX      64U
#endif

#define EP_ID_INVALID              ((uint16_t)0xFFFFU)
#define EP_ID_UNKNOWN_OVERFLOW     ((uint16_t)0xFFFEU)

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
    PATTERN_RECONNAISSANCE,      /* Root -> Admin -> Config / Login */
    PATTERN_CREDENTIAL_HUNT,     /* Admin -> Login probing */
    PATTERN_CONFIG_PROBING,      /* Repeated configuration probing */
    PATTERN_UNKNOWN_SWEEP,       /* Multi-unknown endpoint sweep */
    PATTERN_WEIGHTED_PROGRESSION /* Integer sequence score >= threshold */
} AttackPattern_t;

/* Compact ring-buffer observation entry: 4 bytes total */
typedef struct {
    uint16_t endpoint_id;    /* Compact endpoint ID from collision-safe registry */
    uint16_t delta_100ms;    /* Relative delta since previous observation (100ms units) */
} SeqRingEntry_t;

typedef struct {
    SeqRingEntry_t entries[SEQ_HISTORY_DEPTH];
    uint32_t last_obs_tick;
    uint32_t last_alert_tick;
    uint16_t sequence_score;
    uint16_t pattern_count;
    uint8_t  count;
    uint8_t  head;
    uint8_t  repeat_streak;
    uint8_t  last_detected_pattern; /* AttackPattern_t stored as uint8_t */
} IPSequenceHistory_t;

typedef struct {
    uint32_t total_evaluations;
    uint32_t total_sequence_detections;
    uint32_t total_decay_applications;
    uint32_t registry_entries_used;
    uint32_t registry_collisions_resolved;
    uint32_t registry_overflows;
} SequenceStats_t;

/* Initialize sequence detection subsystem & endpoint registry */
void Sequence_Init(void);

/* Resolve or register a normalized endpoint path into a collision-safe uint16_t ID */
uint16_t Sequence_ResolveEndpointId(const char *normalized_path, EndpointCategory_t *out_cat);

/* Retrieve endpoint category for a registered endpoint ID */
EndpointCategory_t Sequence_GetCategoryById(uint16_t endpoint_id);

/* Retrieve endpoint severity weight (integer 0..20) */
uint8_t Sequence_GetEndpointWeight(EndpointCategory_t cat);

/* Classify an endpoint path into a lightweight token category */
EndpointCategory_t Sequence_CategorizeEndpoint(const char *path);

/* Get human-readable name of endpoint category */
const char *Sequence_GetCategoryString(EndpointCategory_t cat);

/* Get human-readable name of attack pattern */
const char *Sequence_GetPatternString(AttackPattern_t pattern);

/*
 * Record request in IP sequence history and evaluate weighted integer sequence score.
 * Thread-safe on target via internal registry mutex.
 * Returns detected pattern (or PATTERN_NONE if below threshold or in cooldown).
 */
AttackPattern_t Sequence_Evaluate(
    IPSequenceHistory_t *history,
    const char *endpoint,
    uint32_t current_tick,
    uint8_t *out_threat_delta,
    char *out_desc,
    size_t max_desc_len
);

/* Query global sequence detection & registry statistics */
void Sequence_GetStats(SequenceStats_t *out_stats);

#endif /* SEQUENCE_DETECTION_H_ */
