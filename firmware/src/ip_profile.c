/*
 * IoT Honeypot Monitor — FRDM-RW612 Behavioral IP Profiling Implementation
 */

#include "ip_profile.h"
#include "threat_memory_manager.h"
#include "sequence_detection.h"
#include "honeypot_config.h"
#include <string.h>
#include <stdio.h>

#ifndef HOST_UNIT_TEST
#include "FreeRTOS.h"
#include "semphr.h"
static SemaphoreHandle_t s_profile_mutex = NULL;
#endif

static IPProfile_t s_ip_profiles[IP_PROFILE_MAX_ENTRIES];
static uint32_t s_active_count = 0;

void IPProfile_Lock(void)
{
#ifndef HOST_UNIT_TEST
    if (s_profile_mutex != NULL) {
        xSemaphoreTake(s_profile_mutex, portMAX_DELAY);
    }
#endif
}

void IPProfile_Unlock(void)
{
#ifndef HOST_UNIT_TEST
    if (s_profile_mutex != NULL) {
        xSemaphoreGive(s_profile_mutex);
    }
#endif
}

void IPProfile_Init(void)
{
#ifndef HOST_UNIT_TEST
    if (s_profile_mutex == NULL) {
        s_profile_mutex = xSemaphoreCreateMutex();
    }
#endif
    IPProfile_Lock();
    memset(s_ip_profiles, 0, sizeof(s_ip_profiles));
    s_active_count = 0;
    ThreatMem_Init();
    IPProfile_Unlock();
}

IPProfile_t *IPProfile_Lookup(const char *ip_str)
{
    if (!ip_str || ip_str[0] == '\0') {
        return NULL;
    }

    for (uint32_t i = 0; i < IP_PROFILE_MAX_ENTRIES; i++) {
        if (s_ip_profiles[i].is_active &&
            strncmp(s_ip_profiles[i].ip_str, ip_str, sizeof(s_ip_profiles[i].ip_str)) == 0) {
            return &s_ip_profiles[i];
        }
    }
    return NULL;
}

uint32_t IPProfile_ExpireInactive(uint32_t current_tick, uint32_t timeout_ms)
{
    uint32_t expired = 0;

    for (uint32_t i = 0; i < IP_PROFILE_MAX_ENTRIES; i++) {
        if (s_ip_profiles[i].is_active) {
            uint32_t elapsed = (uint32_t)(current_tick - s_ip_profiles[i].last_seen_tick);

            if (elapsed >= timeout_ms && s_ip_profiles[i].threat_score < 70) {
                /* Never expire active high-threat or critical profiles prematurely */
                memset(&s_ip_profiles[i], 0, sizeof(IPProfile_t));
                if (s_active_count > 0) {
                    s_active_count--;
                }
                expired++;
            }
        }
    }
    return expired;
}

IPProfile_t *IPProfile_GetOrCreate(const char *ip_str, uint32_t current_tick)
{
    if (!ip_str || ip_str[0] == '\0') {
        return NULL;
    }

    /* 1. Check for existing active profile */
    IPProfile_t *existing = IPProfile_Lookup(ip_str);
    if (existing != NULL) {
        return existing;
    }

    /* 2. Find empty slot */
    for (uint32_t i = 0; i < IP_PROFILE_MAX_ENTRIES; i++) {
        if (!s_ip_profiles[i].is_active) {
            memset(&s_ip_profiles[i], 0, sizeof(IPProfile_t));
            strncpy(s_ip_profiles[i].ip_str, ip_str, sizeof(s_ip_profiles[i].ip_str) - 1);
            s_ip_profiles[i].is_active = true;
            s_ip_profiles[i].first_seen_tick = current_tick;
            s_ip_profiles[i].last_seen_tick = current_tick;
            s_ip_profiles[i].last_endpoint_id = EP_ID_INVALID;
            s_ip_profiles[i].risk_level = RISK_LOW;
            s_active_count++;
            ThreatMem_RecordPressureEvent(ThreatMem_GetPressureLevel(s_active_count));
            return &s_ip_profiles[i];
        }
    }

    /* 3. Table full: Expire inactive low-risk profiles first */
    if (IPProfile_ExpireInactive(current_tick, IP_PROFILE_INACTIVE_TIMEOUT_MS) > 0) {
        for (uint32_t i = 0; i < IP_PROFILE_MAX_ENTRIES; i++) {
            if (!s_ip_profiles[i].is_active) {
                memset(&s_ip_profiles[i], 0, sizeof(IPProfile_t));
                strncpy(s_ip_profiles[i].ip_str, ip_str, sizeof(s_ip_profiles[i].ip_str) - 1);
                s_ip_profiles[i].is_active = true;
                s_ip_profiles[i].first_seen_tick = current_tick;
                s_ip_profiles[i].last_seen_tick = current_tick;
                s_ip_profiles[i].risk_level = RISK_LOW;
                s_active_count++;
                return &s_ip_profiles[i];
            }
        }
    }

    /* 4. Memory-Aware Controlled Eviction: Select candidate with lowest priority */
    ThreatMem_RecordPressureEvent(MEM_PRESSURE_CRITICAL);
    int32_t victim_idx = ThreatMem_SelectEvictionVictim(s_ip_profiles, IP_PROFILE_MAX_ENTRIES, current_tick);
    if (victim_idx < 0) {
        victim_idx = 0;
    }

    /* Record historical summary of evicted telemetry intelligence */
    ThreatMem_RecordEviction(&s_ip_profiles[victim_idx], current_tick);

    memset(&s_ip_profiles[victim_idx], 0, sizeof(IPProfile_t));
    strncpy(s_ip_profiles[victim_idx].ip_str, ip_str, sizeof(s_ip_profiles[victim_idx].ip_str) - 1);
    s_ip_profiles[victim_idx].is_active = true;
    s_ip_profiles[victim_idx].first_seen_tick = current_tick;
    s_ip_profiles[victim_idx].last_seen_tick = current_tick;
    s_ip_profiles[victim_idx].last_endpoint_id = EP_ID_INVALID;
    s_ip_profiles[victim_idx].risk_level = RISK_LOW;
    return &s_ip_profiles[victim_idx];
}

uint8_t IPProfile_CalculateThreatScore(const IPProfile_t *p)
{
    if (!p) return 0;

    uint32_t score = 0;

    /* Factor 1: Suspicious / unknown endpoint probes (15 pts each, max 45) */
    if (p->suspicious_requests > 0) {
        uint32_t susp_points = p->suspicious_requests * 15;
        if (susp_points > 45) susp_points = 45;
        score += susp_points;
    }

    /* Factor 2: Repeated probes on identical endpoint (4 pts per repeat, max 25) */
    if (p->repeated_requests > 0) {
        uint32_t rep_points = p->repeated_requests * 4;
        if (rep_points > 25) rep_points = 25;
        score += rep_points;
    }

    /* Factor 3: Multi-endpoint scanning behavior (5 pts per unique endpoint > 1, max 20) */
    if (p->unique_endpoints_count >= 3) {
        score += 15;
    } else if (p->unique_endpoints_count == 2) {
        score += 5;
    }

    /* Factor 4: Request frequency (high rate bursts) */
    if (p->request_rate_per_min >= 60) {
        score += 25; /* > 1 req/sec */
    } else if (p->request_rate_per_min >= 30) {
        score += 15; /* > 0.5 req/sec */
    }

    /* Factor 5: Overall volume of requests */
    if (p->total_requests >= 20) {
        score += 10;
    } else if (p->total_requests >= 10) {
        score += 5;
    }

    if (score > 100) {
        score = 100;
    }
    return (uint8_t)score;
}

void IPProfile_Update(IPProfile_t *p, const RequestRecord_t *record)
{
    if (!p || !record) return;

    p->total_requests++;
    p->last_seen_tick = record->timestamp_tick;

    /* 1. Track unique endpoints via collision-safe compact endpoint IDs */
    uint16_t ep_id = Sequence_ResolveEndpointId(record->endpoint, NULL);
    bool seen = false;
    for (uint32_t i = 0; i < p->unique_endpoints_count && i < IP_PROFILE_MAX_UNIQUE_HASHES; i++) {
        if (p->endpoint_ids[i] == ep_id) {
            seen = true;
            break;
        }
    }
    if (!seen && p->unique_endpoints_count < IP_PROFILE_MAX_UNIQUE_HASHES) {
        p->endpoint_ids[p->unique_endpoints_count] = ep_id;
        p->unique_endpoints_count++;
    }

    /* 2. Track consecutive repeated endpoint access */
    if (p->last_endpoint_id != EP_ID_INVALID && p->last_endpoint_id == ep_id) {
        p->consecutive_endpoint_count++;
        if (p->consecutive_endpoint_count >= 2) {
            p->repeated_requests++;
        }
    } else {
        p->last_endpoint_id = ep_id;
        p->consecutive_endpoint_count = 1;
    }

    /* 3. Track suspicious / rule violations */
    if (record->is_unknown_endpoint || record->triggered_event != EVENT_NONE) {
        p->suspicious_requests++;
    }

    /* 4. Estimate frequency using rolling window */
    p->recent_window_ticks[p->recent_window_idx] = record->timestamp_tick;
    p->recent_window_idx = (p->recent_window_idx + 1) % 8;

    uint32_t total_span_ms = (record->timestamp_tick >= p->first_seen_tick) ?
                             (record->timestamp_tick - p->first_seen_tick) : 1000;
    if (total_span_ms < 1000) total_span_ms = 1000;

    /* requests / (span_ms / 60000) */
    p->request_rate_per_min = (uint16_t)((uint64_t)p->total_requests * 60000 / total_span_ms);

    /* 5. Update threat score & risk level */
    p->threat_score = IPProfile_CalculateThreatScore(p);

    if (p->threat_score >= 90) {
        p->risk_level = RISK_CRITICAL;
    } else if (p->threat_score >= 70) {
        p->risk_level = RISK_HIGH;
    } else if (p->threat_score >= 30) {
        p->risk_level = RISK_MEDIUM;
    } else {
        p->risk_level = RISK_LOW;
    }
}

uint32_t IPProfile_GetActiveCount(void)
{
    return s_active_count;
}

bool IPProfile_GetByIndex(uint32_t index, IPProfile_t *out_profile)
{
    if (index >= IP_PROFILE_MAX_ENTRIES || !out_profile) {
        return false;
    }
    if (s_ip_profiles[index].is_active) {
        memcpy(out_profile, &s_ip_profiles[index], sizeof(IPProfile_t));
        return true;
    }
    return false;
}

const char *IPProfile_GetRiskLevelString(RiskLevel_t level)
{
    switch (level) {
        case RISK_CRITICAL: return "critical";
        case RISK_HIGH:     return "high";
        case RISK_MEDIUM:   return "medium";
        default:            return "low";
    }
}
