/*
 * IoT Honeypot Monitor — FRDM-RW612 Memory-Aware Threat Preservation Implementation
 */

#include "threat_memory_manager.h"
#include "ip_profile.h"
#include "sequence_detection.h"

#ifndef HOST_UNIT_TEST
#include "FreeRTOS.h"
#include "task.h"
#include "fsl_debug_console.h"
#else
#define PRINTF(...) ((void)0)
static inline size_t xPortGetFreeHeapSize(void) { return 0; }
static inline size_t xPortGetMinimumEverFreeHeapSize(void) { return 0; }
#endif

#include <string.h>
#include <stdio.h>

static ThreatEvictionSummary_t s_eviction_summary;
static uint32_t s_memory_pressure_events = 0;

void ThreatMem_Init(void)
{
    memset(&s_eviction_summary, 0, sizeof(s_eviction_summary));
    s_memory_pressure_events = 0;
}

void ThreatMem_RecordPressureEvent(MemoryPressureLevel_t level)
{
    if (level >= MEM_PRESSURE_MODERATE) {
        s_memory_pressure_events++;
    }
}

uint32_t ThreatMem_CalculatePriority(const IPProfile_t *p, uint32_t current_tick)
{
    if (!p || !p->is_active) {
        return 0;
    }

    uint32_t priority = 0;

    /* 1. Core threat score (weight = 4, max 400 pts) */
    priority += ((uint32_t)p->threat_score * 4);

    /* 2. Suspicious request count (weight = 8, cap at 160 pts) */
    uint32_t susp_score = p->suspicious_requests * 8;
    if (susp_score > 160) {
        susp_score = 160;
    }
    priority += susp_score;

    /* 3. Attack sequence detection bonus (+50 pts) */
    if (p->sequence_history.sequence_score >= SEQ_SCORE_WARN_THRESHOLD ||
        p->sequence_history.pattern_count > 0) {
        priority += 50;
    }

    /* 4. Recency bonus (wraparound-safe) */
    uint32_t elapsed = (uint32_t)(current_tick - p->last_seen_tick);

    if (elapsed < 60000) {          /* Active within past 60s */
        priority += 25;
    } else if (elapsed < 300000) {   /* Active within past 5m */
        priority += 10;
    }

    return priority;
}

bool ThreatMem_IsCriticalProtected(const IPProfile_t *p, uint32_t current_tick)
{
    if (!p || !p->is_active) {
        return false;
    }

    /* Protected if risk level is HIGH or CRITICAL or high sequence score */
    if (p->threat_score >= 70 || p->risk_level >= RISK_HIGH ||
        p->sequence_history.sequence_score >= SEQ_SCORE_CRIT_THRESHOLD) {
        return true;
    }

    /* Protected if suspicious activity is persistent */
    if (p->suspicious_requests >= 5) {
        return true;
    }

    /* Protected if priority score exceeds critical threshold */
    if (ThreatMem_CalculatePriority(p, current_tick) >= THREAT_MEM_CRITICAL_PRIORITY_SCORE) {
        return true;
    }

    return false;
}

void ThreatMem_RecordEviction(const IPProfile_t *victim, uint32_t current_tick)
{
    if (!victim) {
        return;
    }

    s_eviction_summary.total_evicted_count++;
    s_eviction_summary.aggregate_evicted_requests += victim->total_requests;
    s_eviction_summary.aggregate_suspicious_requests += victim->suspicious_requests;
    s_eviction_summary.last_eviction_tick = current_tick;
    strncpy(s_eviction_summary.last_evicted_ip, victim->ip_str, sizeof(s_eviction_summary.last_evicted_ip) - 1);

    if (victim->threat_score < 30) {
        s_eviction_summary.evicted_benign_count++;
    } else {
        s_eviction_summary.evicted_suspicious_count++;
    }

    if (victim->threat_score > s_eviction_summary.highest_evicted_threat_score) {
        s_eviction_summary.highest_evicted_threat_score = victim->threat_score;
    }

    PRINTF("[ThreatMem] Evicted IP %s (Score: %u, Priority: %lu). Total evictions: %lu\r\n",
           victim->ip_str, victim->threat_score,
           (unsigned long)ThreatMem_CalculatePriority(victim, current_tick),
           (unsigned long)s_eviction_summary.total_evicted_count);
}

int32_t ThreatMem_SelectEvictionVictim(const IPProfile_t *profiles, uint32_t count, uint32_t current_tick)
{
    if (!profiles || count == 0) {
        return -1;
    }

    /* Stage 1: Check for expired inactive benign profiles (threat score < 30, elapsed > 300s) */
    for (uint32_t i = 0; i < count; i++) {
        if (profiles[i].is_active && profiles[i].threat_score < 30) {
            uint32_t elapsed = (current_tick >= profiles[i].last_seen_tick) ?
                               (current_tick - profiles[i].last_seen_tick) :
                               (0xFFFFFFFF - profiles[i].last_seen_tick + current_tick);
            if (elapsed >= 300000) {
                return (int32_t)i;
            }
        }
    }

    /* Stage 2: Find lowest priority non-critical profile */
    int32_t best_victim = -1;
    uint32_t min_priority = 0xFFFFFFFF;

    for (uint32_t i = 0; i < count; i++) {
        if (profiles[i].is_active && !ThreatMem_IsCriticalProtected(&profiles[i], current_tick)) {
            uint32_t prio = ThreatMem_CalculatePriority(&profiles[i], current_tick);
            if (prio < min_priority) {
                min_priority = prio;
                best_victim = (int32_t)i;
            }
        }
    }

    if (best_victim >= 0) {
        return best_victim;
    }

    /* Stage 3: Extreme memory pressure (all profiles have high priority)
     * Even under pressure, evict the profile with lowest calculated priority and longest idle elapsed time */
    uint32_t max_elapsed = 0;
    min_priority = 0xFFFFFFFF;

    for (uint32_t i = 0; i < count; i++) {
        if (profiles[i].is_active) {
            uint32_t prio = ThreatMem_CalculatePriority(&profiles[i], current_tick);
            uint32_t idle_elapsed = (uint32_t)(current_tick - profiles[i].last_seen_tick);
            if (prio < min_priority || (prio == min_priority && idle_elapsed > max_elapsed)) {
                min_priority = prio;
                max_elapsed = idle_elapsed;
                best_victim = (int32_t)i;
            }
        }
    }

    return best_victim;
}

MemoryPressureLevel_t ThreatMem_GetPressureLevel(uint32_t active_count)
{
    if (active_count >= THREAT_MEM_MAX_PROFILES) {
        return MEM_PRESSURE_CRITICAL;
    } else if (active_count >= 20) {
        return MEM_PRESSURE_HIGH;
    } else if (active_count >= 14) {
        return MEM_PRESSURE_MODERATE;
    }
    return MEM_PRESSURE_NORMAL;
}

const char *ThreatMem_GetPressureString(MemoryPressureLevel_t level)
{
    switch (level) {
        case MEM_PRESSURE_CRITICAL: return "critical";
        case MEM_PRESSURE_HIGH:     return "high";
        case MEM_PRESSURE_MODERATE: return "moderate";
        default:                    return "normal";
    }
}

void ThreatMem_GetStats(ThreatMemoryStats_t *out_stats, uint32_t active_count)
{
    if (!out_stats) {
        return;
    }

    SequenceStats_t seq_stats;
    Sequence_GetStats(&seq_stats);

    out_stats->max_profiles_capacity = THREAT_MEM_MAX_PROFILES;
    out_stats->active_profiles_count = active_count;
    out_stats->profile_bytes_used = active_count * sizeof(IPProfile_t);
    out_stats->total_security_bss_bytes = (THREAT_MEM_MAX_PROFILES * sizeof(IPProfile_t)) + sizeof(ThreatEvictionSummary_t);
    out_stats->free_heap_bytes = (uint32_t)xPortGetFreeHeapSize();
    out_stats->min_ever_free_heap_bytes = (uint32_t)xPortGetMinimumEverFreeHeapSize();
    out_stats->memory_pressure_events = s_memory_pressure_events;
    out_stats->sequence_detections = seq_stats.total_sequence_detections;
    out_stats->pressure_level = ThreatMem_GetPressureLevel(active_count);
    memcpy(&out_stats->eviction_summary, &s_eviction_summary, sizeof(ThreatEvictionSummary_t));
}
