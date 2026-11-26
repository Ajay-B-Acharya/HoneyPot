/*
 * IoT Honeypot Monitor — FRDM-RW612 Attack Sequence Detection Implementation
 */

#include "sequence_detection.h"
#include <string.h>
#include <stdio.h>

void Sequence_Init(void)
{
    /* No global state needed; history is per-IP */
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
        case PATTERN_RECONNAISSANCE:  return "reconnaissance_probe";
        case PATTERN_CREDENTIAL_HUNT: return "credential_hunting";
        case PATTERN_CONFIG_PROBING:  return "config_probing";
        case PATTERN_UNKNOWN_SWEEP:   return "unknown_sweep";
        default:                      return "none";
    }
}

AttackPattern_t Sequence_Evaluate(
    IPSequenceHistory_t *history,
    const char *endpoint,
    uint32_t current_tick,
    uint8_t *out_threat_delta,
    char *out_desc,
    size_t max_desc_len
) {
    if (!history || !endpoint || !out_threat_delta || !out_desc || max_desc_len < 16) {
        return PATTERN_NONE;
    }

    *out_threat_delta = 0;
    out_desc[0] = '\0';

    /* 1. Categorize current endpoint */
    EndpointCategory_t cat = Sequence_CategorizeEndpoint(endpoint);

    /* 2. Add to circular buffer */
    history->endpoints[history->head] = cat;
    history->ticks[history->head] = current_tick;
    history->head = (history->head + 1) % SEQ_HISTORY_DEPTH;
    if (history->count < SEQ_HISTORY_DEPTH) {
        history->count++;
    }

    /* Need at least 2 requests to form any sequence */
    if (history->count < 2) {
        return PATTERN_NONE;
    }

    /* 3. Reconstruct in-order chronological sequence within time window */
    EndpointCategory_t in_order[SEQ_HISTORY_DEPTH];
    uint8_t valid_count = 0;

    /* Start from oldest available */
    uint8_t start_idx = (history->count < SEQ_HISTORY_DEPTH) ? 0 : history->head;
    for (uint8_t i = 0; i < history->count; i++) {
        uint8_t idx = (start_idx + i) % SEQ_HISTORY_DEPTH;
        uint32_t tick = history->ticks[idx];

        uint32_t age = (current_tick >= tick) ? (current_tick - tick) : 0;
        if (age <= SEQ_WINDOW_MS) {
            in_order[valid_count] = history->endpoints[idx];
            valid_count++;
        }
    }

    if (valid_count < 2) {
        return PATTERN_NONE;
    }

    AttackPattern_t detected = PATTERN_NONE;

    /* 4. Pattern 1: Multi-stage Reconnaissance (Root -> Admin -> Config/Login) */
    bool seen_root = false;
    bool seen_admin = false;
    bool seen_config_or_login = false;

    for (uint8_t i = 0; i < valid_count; i++) {
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
        *out_threat_delta = 35;
        snprintf(out_desc, max_desc_len,
                 "Reconnaissance sequence detected: / -> /admin -> %s",
                 Sequence_GetCategoryString(in_order[valid_count - 1]));
    }

    /* 5. Pattern 2: Credential Hunting (Admin -> Login probing) */
    if (detected == PATTERN_NONE) {
        bool admin_found = false;
        for (uint8_t i = 0; i < valid_count; i++) {
            if (!admin_found && in_order[i] == EP_CAT_ADMIN) {
                admin_found = true;
            } else if (admin_found && in_order[i] == EP_CAT_LOGIN) {
                detected = PATTERN_CREDENTIAL_HUNT;
                *out_threat_delta = 30;
                snprintf(out_desc, max_desc_len,
                         "Credential hunting sequence: admin discovery followed by login endpoint probing");
                break;
            }
        }
    }

    /* 6. Pattern 3: Repeated Configuration Probing (>= 3 config hits) */
    if (detected == PATTERN_NONE) {
        uint8_t config_count = 0;
        for (uint8_t i = 0; i < valid_count; i++) {
            if (in_order[i] == EP_CAT_CONFIG) {
                config_count++;
            }
        }
        if (config_count >= 3) {
            detected = PATTERN_CONFIG_PROBING;
            *out_threat_delta = 25;
            snprintf(out_desc, max_desc_len,
                     "Configuration probing sequence: %u attempts to access configuration endpoints",
                     config_count);
        }
    }

    /* 7. Pattern 4: Unknown Endpoint Sweep (>= 3 consecutive unknown endpoints) */
    if (detected == PATTERN_NONE && valid_count >= 3) {
        uint8_t unknown_streak = 0;
        for (uint8_t i = 0; i < valid_count; i++) {
            if (in_order[i] == EP_CAT_UNKNOWN) {
                unknown_streak++;
                if (unknown_streak >= 3) {
                    detected = PATTERN_UNKNOWN_SWEEP;
                    *out_threat_delta = 30;
                    snprintf(out_desc, max_desc_len,
                             "Unknown endpoint sweep: %u consecutive unmapped endpoint probes",
                             unknown_streak);
                    break;
                }
            } else {
                unknown_streak = 0;
            }
        }
    }

    if (detected == PATTERN_NONE) {
        return PATTERN_NONE;
    }

    /* 8. Cooldown check: prevent duplicate alerts for the same pattern */
    if (detected == history->last_detected_pattern) {
        uint32_t time_since_last = (current_tick >= history->last_alert_tick) ?
                                   (current_tick - history->last_alert_tick) : 0xFFFFFFFF;
        if (time_since_last < SEQ_ALERT_COOLDOWN_MS) {
            /* Cooldown active; suppress duplicate event but return pattern */
            return PATTERN_NONE;
        }
    }

    /* 9. Record alert emission */
    history->last_detected_pattern = detected;
    history->last_alert_tick = current_tick;
    history->pattern_count++;

    return detected;
}
