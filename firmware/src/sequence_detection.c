/*
 * IoT Honeypot Monitor — FRDM-RW612 Memory- and CPU-Aware Attack Sequence Detection
 *
 * Integer-only weighted progression scoring, collision-safe endpoint ID registry,
 * compact uint16_t relative timestamps, and wraparound-safe time decay.
 */

#include "sequence_detection.h"
#include <string.h>
#include <stdio.h>

#ifndef HOST_UNIT_TEST
#include "FreeRTOS.h"
#include "semphr.h"
static SemaphoreHandle_t s_seq_mutex = NULL;
#define SEQ_LOCK()   do { if (s_seq_mutex != NULL) xSemaphoreTake(s_seq_mutex, portMAX_DELAY); } while (0)
#define SEQ_UNLOCK() do { if (s_seq_mutex != NULL) xSemaphoreGive(s_seq_mutex); } while (0)
#else
#define SEQ_LOCK()   ((void)0)
#define SEQ_UNLOCK() ((void)0)
#endif

#define EP_PATH_STORE_LEN 32U

typedef struct {
    uint32_t hash;
    char     path[EP_PATH_STORE_LEN];
    uint8_t  category; /* EndpointCategory_t */
    bool     in_use;
} EndpointRegistryEntry_t;

static EndpointRegistryEntry_t s_ep_registry[ENDPOINT_REGISTRY_MAX];
static SequenceStats_t s_seq_stats;

static uint32_t Djb2Hash(const char *str)
{
    uint32_t hash = 5381U;
    unsigned char c;
    while ((c = (unsigned char)*str++) != 0U) {
        hash = ((hash << 5U) + hash) + c;
    }
    return hash;
}

void Sequence_Init(void)
{
#ifndef HOST_UNIT_TEST
    if (s_seq_mutex == NULL) {
        s_seq_mutex = xSemaphoreCreateMutex();
    }
#endif
    SEQ_LOCK();
    memset(s_ep_registry, 0, sizeof(s_ep_registry));
    memset(&s_seq_stats, 0, sizeof(s_seq_stats));
    SEQ_UNLOCK();
}

EndpointCategory_t Sequence_CategorizeEndpoint(const char *path)
{
    if (!path || path[0] == '\0') {
        return EP_CAT_OTHER;
    }

    if (strcmp(path, "/") == 0) {
        return EP_CAT_ROOT;
    }
    if (strcmp(path, "/status") == 0) {
        return EP_CAT_STATUS;
    }
    if (strcmp(path, "/info") == 0) {
        return EP_CAT_INFO;
    }
    if (strstr(path, "/config") != NULL || strstr(path, "/setup") != NULL ||
        strstr(path, "/system") != NULL || strstr(path, "/settings") != NULL) {
        return EP_CAT_CONFIG;
    }
    if (strstr(path, "/admin") != NULL || strstr(path, "/administrator") != NULL ||
        strstr(path, "/wp-admin") != NULL || strstr(path, "/manager") != NULL) {
        return EP_CAT_ADMIN;
    }
    if (strstr(path, "/login") != NULL || strstr(path, "/auth") != NULL ||
        strstr(path, "/signin") != NULL || strstr(path, "/wp-login") != NULL) {
        return EP_CAT_LOGIN;
    }

    return EP_CAT_UNKNOWN;
}

uint8_t Sequence_GetEndpointWeight(EndpointCategory_t cat)
{
    switch (cat) {
        case EP_CAT_STATUS:
        case EP_CAT_INFO:
            return 0U;
        case EP_CAT_ROOT:
            return 2U;
        case EP_CAT_CONFIG:
            return 10U;
        case EP_CAT_ADMIN:
            return 15U;
        case EP_CAT_LOGIN:
            return 15U;
        case EP_CAT_UNKNOWN:
            return 18U;
        default:
            return 4U;
    }
}

uint16_t Sequence_ResolveEndpointId(const char *normalized_path, EndpointCategory_t *out_cat)
{
    EndpointCategory_t cat = Sequence_CategorizeEndpoint(normalized_path);
    if (out_cat) {
        *out_cat = cat;
    }
    if (!normalized_path || normalized_path[0] == '\0') {
        return EP_ID_INVALID;
    }

    uint32_t hash = Djb2Hash(normalized_path);
    uint32_t start_idx = hash % ENDPOINT_REGISTRY_MAX;

    SEQ_LOCK();
    for (uint32_t probe = 0; probe < ENDPOINT_REGISTRY_MAX; probe++) {
        uint32_t idx = (start_idx + probe) % ENDPOINT_REGISTRY_MAX;
        EndpointRegistryEntry_t *slot = &s_ep_registry[idx];

        if (!slot->in_use) {
            slot->in_use = true;
            slot->hash = hash;
            slot->category = (uint8_t)cat;
            strncpy(slot->path, normalized_path, EP_PATH_STORE_LEN - 1U);
            slot->path[EP_PATH_STORE_LEN - 1U] = '\0';
            s_seq_stats.registry_entries_used++;
            SEQ_UNLOCK();
            return (uint16_t)idx;
        }

        if (slot->hash == hash) {
            if (strncmp(slot->path, normalized_path, EP_PATH_STORE_LEN - 1U) == 0) {
                SEQ_UNLOCK();
                return (uint16_t)idx;
            }
            /* Hash collision: different path with same DJB2 hash -> continue linear probing */
            s_seq_stats.registry_collisions_resolved++;
        }
    }

    s_seq_stats.registry_overflows++;
    SEQ_UNLOCK();
    return EP_ID_UNKNOWN_OVERFLOW;
}

EndpointCategory_t Sequence_GetCategoryById(uint16_t endpoint_id)
{
    if (endpoint_id < ENDPOINT_REGISTRY_MAX && s_ep_registry[endpoint_id].in_use) {
        return (EndpointCategory_t)s_ep_registry[endpoint_id].category;
    }
    if (endpoint_id == EP_ID_UNKNOWN_OVERFLOW) {
        return EP_CAT_UNKNOWN;
    }
    return EP_CAT_OTHER;
}

const char *Sequence_GetCategoryString(EndpointCategory_t cat)
{
    switch (cat) {
        case EP_CAT_ROOT:    return "/";
        case EP_CAT_STATUS:  return "/status";
        case EP_CAT_INFO:    return "/info";
        case EP_CAT_CONFIG:  return "config";
        case EP_CAT_ADMIN:   return "admin";
        case EP_CAT_LOGIN:   return "login";
        case EP_CAT_UNKNOWN: return "unknown";
        default:             return "other";
    }
}

const char *Sequence_GetPatternString(AttackPattern_t pattern)
{
    switch (pattern) {
        case PATTERN_RECONNAISSANCE:       return "reconnaissance_probe";
        case PATTERN_CREDENTIAL_HUNT:      return "credential_hunting";
        case PATTERN_CONFIG_PROBING:       return "config_probing";
        case PATTERN_UNKNOWN_SWEEP:        return "unknown_sweep";
        case PATTERN_WEIGHTED_PROGRESSION: return "weighted_progression";
        default:                           return "none";
    }
}

static uint8_t CalculateTransitionBonus(EndpointCategory_t prev_cat, EndpointCategory_t curr_cat)
{
    if (prev_cat == EP_CAT_ROOT && curr_cat == EP_CAT_ADMIN) {
        return 15U;
    }
    if (prev_cat == EP_CAT_ADMIN && curr_cat == EP_CAT_LOGIN) {
        return 20U;
    }
    if (prev_cat == EP_CAT_ADMIN && curr_cat == EP_CAT_CONFIG) {
        return 18U;
    }
    if (prev_cat == EP_CAT_ROOT && curr_cat == EP_CAT_CONFIG) {
        return 12U;
    }
    if ((prev_cat == EP_CAT_LOGIN && curr_cat == EP_CAT_CONFIG) ||
        (prev_cat == EP_CAT_CONFIG && curr_cat == EP_CAT_ADMIN)) {
        return 12U;
    }
    if (prev_cat == EP_CAT_UNKNOWN && curr_cat == EP_CAT_UNKNOWN) {
        return 10U;
    }
    return 0U;
}

AttackPattern_t Sequence_Evaluate(
    IPSequenceHistory_t *history,
    const char *endpoint,
    uint32_t current_tick,
    uint8_t *out_threat_delta,
    char *out_desc,
    size_t max_desc_len
) {
    if (!history || !endpoint || !out_threat_delta || !out_desc || max_desc_len < 16U) {
        return PATTERN_NONE;
    }

    *out_threat_delta = 0U;
    out_desc[0] = '\0';

    /* 1. Resolve compact collision-safe endpoint ID and category */
    EndpointCategory_t cat = EP_CAT_OTHER;
    uint16_t ep_id = Sequence_ResolveEndpointId(endpoint, &cat);

    SEQ_LOCK();
    s_seq_stats.total_evaluations++;
    SEQ_UNLOCK();

    /* 2. Wraparound-safe elapsed time and compact relative delta (100ms units) */
    uint32_t elapsed_ms = 0U;
    uint16_t delta_100ms = 0U;
    uint16_t prev_ep_id = EP_ID_INVALID;
    EndpointCategory_t prev_cat = EP_CAT_OTHER;

    if (history->count > 0U) {
        uint8_t prev_idx = (uint8_t)((history->head + SEQ_HISTORY_DEPTH - 1U) % SEQ_HISTORY_DEPTH);
        prev_ep_id = history->entries[prev_idx].endpoint_id;
        prev_cat = Sequence_GetCategoryById(prev_ep_id);

        elapsed_ms = (uint32_t)(current_tick - history->last_obs_tick);
        uint32_t d = elapsed_ms / 100U;
        delta_100ms = (d > 65535U) ? 65535U : (uint16_t)d;
    }

    /* 3. Apply integer time-based score decay */
    uint16_t decayed_score = history->sequence_score;
    if (history->count > 0U && elapsed_ms >= SEQ_DECAY_MS_PER_POINT && decayed_score > 0U) {
        uint32_t decay_pts = elapsed_ms / SEQ_DECAY_MS_PER_POINT;
        decayed_score = (decayed_score > decay_pts) ? (uint16_t)(decayed_score - decay_pts) : 0U;
        SEQ_LOCK();
        s_seq_stats.total_decay_applications++;
        SEQ_UNLOCK();
    }

    /* 4. Calculate integer weighted progression + repeated transition score */
    uint8_t ep_weight = Sequence_GetEndpointWeight(cat);
    uint8_t trans_bonus = 0U;
    uint8_t repeat_bonus = 0U;

    if (history->count > 0U && elapsed_ms <= SEQ_WINDOW_MS) {
        trans_bonus = CalculateTransitionBonus(prev_cat, cat);

        if (ep_id == prev_ep_id && ep_weight > 0U) {
            if (history->repeat_streak < 255U) {
                history->repeat_streak++;
            }
            uint32_t r = (uint32_t)history->repeat_streak * 5U;
            repeat_bonus = (r > 15U) ? 15U : (uint8_t)r;
        } else {
            history->repeat_streak = 0U;
        }

        /* Check if this (prev_ep_id -> ep_id) transition appeared earlier in window */
        if (history->count >= 2U && ep_weight > 0U) {
            uint8_t start_idx = (history->count < SEQ_HISTORY_DEPTH) ? 0U : history->head;
            for (uint8_t i = 1U; i < history->count; i++) {
                uint8_t a_idx = (uint8_t)((start_idx + i - 1U) % SEQ_HISTORY_DEPTH);
                uint8_t b_idx = (uint8_t)((start_idx + i) % SEQ_HISTORY_DEPTH);
                if (history->entries[a_idx].endpoint_id == prev_ep_id &&
                    history->entries[b_idx].endpoint_id == ep_id) {
                    repeat_bonus = (uint8_t)((repeat_bonus + 8U > 20U) ? 20U : (repeat_bonus + 8U));
                    break;
                }
            }
        }
    } else {
        history->repeat_streak = 0U;
    }

    uint32_t new_score = (uint32_t)decayed_score + ep_weight + trans_bonus + repeat_bonus;
    if (new_score > SEQ_SCORE_MAX) {
        new_score = SEQ_SCORE_MAX;
    }
    history->sequence_score = (uint16_t)new_score;

    /* 5. Push compact observation into fixed-size ring buffer */
    history->entries[history->head].endpoint_id = ep_id;
    history->entries[history->head].delta_100ms = delta_100ms;
    history->head = (uint8_t)((history->head + 1U) % SEQ_HISTORY_DEPTH);
    if (history->count < SEQ_HISTORY_DEPTH) {
        history->count++;
    }
    history->last_obs_tick = current_tick;

    if (history->count < 2U) {
        return PATTERN_NONE;
    }

    /* 6. Reconstruct in-order chronological categories within rolling window */
    EndpointCategory_t in_order[SEQ_HISTORY_DEPTH];
    uint8_t valid_count = 0U;
    uint32_t window_100ms = SEQ_WINDOW_MS / 100U;

    /* Walk backwards from newest entry accumulating delta_100ms */
    uint8_t newest_idx = (uint8_t)((history->head + SEQ_HISTORY_DEPTH - 1U) % SEQ_HISTORY_DEPTH);
    uint32_t accum_100ms = 0U;
    uint8_t rev_cats[SEQ_HISTORY_DEPTH];
    uint8_t rev_count = 0U;

    for (uint8_t step = 0U; step < history->count; step++) {
        uint8_t idx = (uint8_t)((newest_idx + SEQ_HISTORY_DEPTH - step) % SEQ_HISTORY_DEPTH);
        if (step > 0U && accum_100ms > window_100ms) {
            break;
        }
        rev_cats[rev_count++] = (uint8_t)Sequence_GetCategoryById(history->entries[idx].endpoint_id);
        accum_100ms += history->entries[idx].delta_100ms;
    }

    for (uint8_t i = 0U; i < rev_count; i++) {
        in_order[i] = (EndpointCategory_t)rev_cats[rev_count - 1U - i];
    }
    valid_count = rev_count;

    if (valid_count < 2U) {
        return PATTERN_NONE;
    }

    AttackPattern_t detected = PATTERN_NONE;

    /* Pattern 1: Multi-stage Reconnaissance (Root -> Admin -> Config/Login) */
    bool seen_root = false;
    bool seen_admin = false;
    bool seen_config_or_login = false;
    for (uint8_t i = 0U; i < valid_count; i++) {
        if (!seen_root && in_order[i] == EP_CAT_ROOT) {
            seen_root = true;
        } else if (seen_root && !seen_admin && in_order[i] == EP_CAT_ADMIN) {
            seen_admin = true;
        } else if (seen_admin && (in_order[i] == EP_CAT_CONFIG || in_order[i] == EP_CAT_LOGIN)) {
            seen_config_or_login = true;
            break;
        }
    }

    if (seen_root && seen_admin && seen_config_or_login) {
        detected = PATTERN_RECONNAISSANCE;
        *out_threat_delta = 35U;
        snprintf(out_desc, max_desc_len,
                 "Reconnaissance sequence (score=%u): / -> /admin -> %s",
                 (unsigned int)history->sequence_score,
                 Sequence_GetCategoryString(in_order[valid_count - 1U]));
    }

    /* Pattern 2: Credential Hunting (Admin -> Login probing) */
    if (detected == PATTERN_NONE) {
        bool admin_found = false;
        for (uint8_t i = 0U; i < valid_count; i++) {
            if (!admin_found && in_order[i] == EP_CAT_ADMIN) {
                admin_found = true;
            } else if (admin_found && in_order[i] == EP_CAT_LOGIN) {
                detected = PATTERN_CREDENTIAL_HUNT;
                *out_threat_delta = 30U;
                snprintf(out_desc, max_desc_len,
                         "Credential hunting sequence (score=%u): admin -> login",
                         (unsigned int)history->sequence_score);
                break;
            }
        }
    }

    /* Pattern 3: Repeated Configuration Probing (>= 3 config hits) */
    if (detected == PATTERN_NONE) {
        uint8_t config_count = 0U;
        for (uint8_t i = 0U; i < valid_count; i++) {
            if (in_order[i] == EP_CAT_CONFIG) {
                config_count++;
            }
        }
        if (config_count >= 3U) {
            detected = PATTERN_CONFIG_PROBING;
            *out_threat_delta = 25U;
            snprintf(out_desc, max_desc_len,
                     "Configuration probing (score=%u): %u config attempts",
                     (unsigned int)history->sequence_score, config_count);
        }
    }

    /* Pattern 4: Unknown Endpoint Sweep (>= 3 consecutive unknown endpoints) */
    if (detected == PATTERN_NONE && valid_count >= 3U) {
        uint8_t unknown_streak = 0U;
        for (uint8_t i = 0U; i < valid_count; i++) {
            if (in_order[i] == EP_CAT_UNKNOWN) {
                unknown_streak++;
                if (unknown_streak >= 3U) {
                    detected = PATTERN_UNKNOWN_SWEEP;
                    *out_threat_delta = 30U;
                    snprintf(out_desc, max_desc_len,
                             "Unknown endpoint sweep (score=%u): %u consecutive probes",
                             (unsigned int)history->sequence_score, unknown_streak);
                    break;
                }
            } else {
                unknown_streak = 0U;
            }
        }
    }

    /* Pattern 5: Weighted progression score threshold exceeded */
    if (detected == PATTERN_NONE && history->sequence_score >= SEQ_SCORE_WARN_THRESHOLD) {
        detected = PATTERN_WEIGHTED_PROGRESSION;
        *out_threat_delta = (history->sequence_score >= SEQ_SCORE_CRIT_THRESHOLD) ? 35U : 20U;
        snprintf(out_desc, max_desc_len,
                 "Weighted sequence progression alert (score=%u/%u)",
                 (unsigned int)history->sequence_score, (unsigned int)SEQ_SCORE_MAX);
    }

    if (detected == PATTERN_NONE) {
        return PATTERN_NONE;
    }

    /* 7. Wraparound-safe cooldown check */
    if (history->pattern_count > 0U && detected == (AttackPattern_t)history->last_detected_pattern) {
        uint32_t time_since_last = (uint32_t)(current_tick - history->last_alert_tick);
        if (time_since_last < SEQ_ALERT_COOLDOWN_MS) {
            return PATTERN_NONE;
        }
    }

    history->last_detected_pattern = (uint8_t)detected;
    history->last_alert_tick = current_tick;
    history->pattern_count++;

    SEQ_LOCK();
    s_seq_stats.total_sequence_detections++;
    SEQ_UNLOCK();

    return detected;
}

void Sequence_GetStats(SequenceStats_t *out_stats)
{
    if (!out_stats) {
        return;
    }
    SEQ_LOCK();
    memcpy(out_stats, &s_seq_stats, sizeof(SequenceStats_t));
    SEQ_UNLOCK();
}
