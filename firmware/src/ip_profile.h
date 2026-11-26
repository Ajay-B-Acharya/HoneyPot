/*
 * IoT Honeypot Monitor — FRDM-RW612 Behavioral IP Profiling Header
 *
 * Implements lightweight, memory-efficient per-source-IP behavioral tracking:
 * - Total request count
 * - Unique endpoints accessed
 * - Request frequency estimation
 * - Repeated endpoint access
 * - Suspicious request count
 * - Last activity timestamp
 * - Dynamic threat score (0-100) and risk level
 * - Profile expiration and inactive IP eviction
 */

#ifndef IP_PROFILE_H_
#define IP_PROFILE_H_

#include "detection_rules.h"
#include "sequence_detection.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define IP_PROFILE_MAX_ENTRIES       24
#define IP_PROFILE_MAX_UNIQUE_HASHES 8
#define IP_PROFILE_INACTIVE_TIMEOUT_MS (300 * 1000) /* 5 minutes */

typedef enum {
    RISK_LOW = 0,      /* Threat score 0 - 29 */
    RISK_MEDIUM = 1,   /* Threat score 30 - 69 */
    RISK_HIGH = 2,     /* Threat score 70 - 89 */
    RISK_CRITICAL = 3  /* Threat score 90 - 100 */
} RiskLevel_t;

typedef struct {
    char ip_str[48];
    bool is_active;
    
    /* Metrics */
    uint32_t total_requests;
    uint32_t suspicious_requests;
    uint32_t repeated_requests;
    uint32_t unique_endpoints_count;
    uint32_t first_seen_tick;
    uint32_t last_seen_tick;
    
    /* Sliding / frequency metrics */
    uint32_t recent_window_ticks[8];
    uint8_t  recent_window_idx;
    uint16_t request_rate_per_min;
    
    /* Endpoint tracking */
    uint32_t endpoint_hashes[IP_PROFILE_MAX_UNIQUE_HASHES];
    char last_endpoint[64];
    uint32_t consecutive_endpoint_count;
    
    /* Threat scoring */
    uint8_t threat_score; /* 0 to 100 */
    RiskLevel_t risk_level;

    /* Recent request sequence history */
    IPSequenceHistory_t sequence_history;
} IPProfile_t;

/* Initialize behavioral profiling subsystem */
void IPProfile_Init(void);

/* Find existing profile or allocate a new slot for source IP */
IPProfile_t *IPProfile_GetOrCreate(const char *ip_str, uint32_t current_tick);

/* Update behavioral profile on arrival of a new HTTP request */
void IPProfile_Update(IPProfile_t *profile, const RequestRecord_t *record);

/* Fast lookup by IP string */
IPProfile_t *IPProfile_Lookup(const char *ip_str);

/* Evict inactive profiles exceeding timeout */
uint32_t IPProfile_ExpireInactive(uint32_t current_tick, uint32_t timeout_ms);

/* Get number of active tracked IP profiles */
uint32_t IPProfile_GetActiveCount(void);

/* Retrieve a copy of a profile by index (0 .. IP_PROFILE_MAX_ENTRIES - 1) */
bool IPProfile_GetByIndex(uint32_t index, IPProfile_t *out_profile);

/* Convert risk level enum to string */
const char *IPProfile_GetRiskLevelString(RiskLevel_t level);

/* Calculate threat score based on behavioral parameters */
uint8_t IPProfile_CalculateThreatScore(const IPProfile_t *profile);

#endif /* IP_PROFILE_H_ */
