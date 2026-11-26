/*
 * IoT Honeypot Monitor — FRDM-RW612 Memory-Aware Threat Preservation Header
 *
 * Implements deterministic memory management for intrusion detection structures:
 * - Compile-time static RAM budgets (no dynamic pvPortMalloc fragmentation)
 * - Multi-factor threat priority scoring
 * - Controlled eviction policy protecting critical security intelligence
 * - Historical summarization / compression of evicted low-priority profiles
 * - Runtime memory usage diagnostics & FreeRTOS heap watermark reporting
 */

#ifndef THREAT_MEMORY_MANAGER_H_
#define THREAT_MEMORY_MANAGER_H_

#include "ip_profile.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Memory Budget Limits */
#define THREAT_MEM_MAX_PROFILES            24
#define THREAT_MEM_CRITICAL_PRIORITY_SCORE 150
#define THREAT_MEM_HIGH_PRIORITY_SCORE     100
#define THREAT_MEM_MEDIUM_PRIORITY_SCORE   50

/* Memory Pressure States */
typedef enum {
    MEM_PRESSURE_NORMAL = 0,   /* < 60% capacity (0 - 14 active profiles) */
    MEM_PRESSURE_MODERATE = 1, /* 60% - 84% capacity (15 - 20 active profiles) */
    MEM_PRESSURE_HIGH = 2,     /* 85% - 99% capacity (21 - 23 active profiles) */
    MEM_PRESSURE_CRITICAL = 3  /* 100% capacity (24/24 active profiles) */
} MemoryPressureLevel_t;

/* Aggregated historical summary of evicted profiles */
typedef struct {
    uint32_t total_evicted_count;
    uint32_t evicted_benign_count;     /* threat score < 30 */
    uint32_t evicted_suspicious_count; /* threat score >= 30 */
    uint32_t aggregate_evicted_requests;
    uint32_t aggregate_suspicious_requests;
    uint8_t  highest_evicted_threat_score;
    uint32_t last_eviction_tick;
    char     last_evicted_ip[48];
} ThreatEvictionSummary_t;

/* System Memory Diagnostics */
typedef struct {
    uint32_t total_security_bss_bytes;
    uint32_t active_profiles_count;
    uint32_t max_profiles_capacity;
    uint32_t profile_bytes_used;
    uint32_t free_heap_bytes;
    uint32_t min_ever_free_heap_bytes;
    MemoryPressureLevel_t pressure_level;
    ThreatEvictionSummary_t eviction_summary;
} ThreatMemoryStats_t;

/* Initialize threat memory manager */
void ThreatMem_Init(void);

/* Calculate threat priority score for an IP profile based on:
 * - Threat score (x4)
 * - Suspicious request count (x8)
 * - Sequence detection flag (50 pts)
 * - Recency bonus (20 pts for <60s, 10 pts for <300s)
 */
uint32_t ThreatMem_CalculatePriority(const IPProfile_t *profile, uint32_t current_tick);

/* Determine whether an IP profile is protected from eviction */
bool ThreatMem_IsCriticalProtected(const IPProfile_t *profile, uint32_t current_tick);

/* Record the eviction of an IP profile and summarize its telemetry */
void ThreatMem_RecordEviction(const IPProfile_t *victim_profile, uint32_t current_tick);

/* Select best candidate index (0 .. THREAT_MEM_MAX_PROFILES-1) for eviction */
int32_t ThreatMem_SelectEvictionVictim(const IPProfile_t *profiles, uint32_t count, uint32_t current_tick);

/* Retrieve current memory pressure level */
MemoryPressureLevel_t ThreatMem_GetPressureLevel(uint32_t active_count);

/* Convert memory pressure level to string */
const char *ThreatMem_GetPressureString(MemoryPressureLevel_t level);

/* Query complete memory diagnostics snapshot */
void ThreatMem_GetStats(ThreatMemoryStats_t *out_stats, uint32_t active_count);

#endif /* THREAT_MEMORY_MANAGER_H_ */
