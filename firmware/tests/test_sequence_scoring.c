#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../src/detection_rules.h"
#include "../src/sequence_detection.h"
#include "../src/ip_profile.h"
#include "../src/threat_memory_manager.h"

static void test_normal_browsing(void) {
    IPSequenceHistory_t hist;
    memset(&hist, 0, sizeof(hist));
    uint8_t delta = 0;
    char desc[128];

    assert(Sequence_Evaluate(&hist, "/status", 1000, &delta, desc, sizeof(desc)) == PATTERN_NONE);
    assert(Sequence_Evaluate(&hist, "/info",   2000, &delta, desc, sizeof(desc)) == PATTERN_NONE);
    assert(Sequence_Evaluate(&hist, "/status", 3000, &delta, desc, sizeof(desc)) == PATTERN_NONE);
    assert(hist.sequence_score == 0);
    printf("[PASS] test_normal_browsing (score=%u)\n", hist.sequence_score);
}

static void test_admin_probing_and_recon(void) {
    IPSequenceHistory_t hist;
    memset(&hist, 0, sizeof(hist));
    uint8_t delta = 0;
    char desc[128];

    assert(Sequence_Evaluate(&hist, "/",       1000, &delta, desc, sizeof(desc)) == PATTERN_NONE);
    assert(Sequence_Evaluate(&hist, "/admin",  2000, &delta, desc, sizeof(desc)) == PATTERN_NONE);
    AttackPattern_t p = Sequence_Evaluate(&hist, "/config", 3000, &delta, desc, sizeof(desc));
    assert(p == PATTERN_RECONNAISSANCE);
    assert(delta == 35);
    assert(hist.sequence_score >= SEQ_SCORE_WARN_THRESHOLD);
    printf("[PASS] test_admin_probing_and_recon (pattern=%s, score=%u)\n",
           Sequence_GetPatternString(p), hist.sequence_score);
}

static void test_repeated_transitions(void) {
    IPSequenceHistory_t hist;
    memset(&hist, 0, sizeof(hist));
    uint8_t delta = 0;
    char desc[128];

    Sequence_Evaluate(&hist, "/admin", 1000, &delta, desc, sizeof(desc));
    AttackPattern_t p1 = Sequence_Evaluate(&hist, "/login", 1500, &delta, desc, sizeof(desc));
    assert(p1 == PATTERN_CREDENTIAL_HUNT);
    uint16_t score_after_first = hist.sequence_score;

    /* Repeat /admin -> /login transition within window */
    Sequence_Evaluate(&hist, "/admin", 2000, &delta, desc, sizeof(desc));
    Sequence_Evaluate(&hist, "/login", 2500, &delta, desc, sizeof(desc));
    assert(hist.sequence_score > score_after_first);
    printf("[PASS] test_repeated_transitions (first=%u, repeated=%u)\n",
           score_after_first, hist.sequence_score);
}

static void test_time_decay_and_wraparound(void) {
    IPSequenceHistory_t hist;
    memset(&hist, 0, sizeof(hist));
    uint8_t delta = 0;
    char desc[128];

    /* Start near uint32_t max to test wraparound */
    uint32_t t0 = 0xFFFFFF00U;
    Sequence_Evaluate(&hist, "/admin", t0, &delta, desc, sizeof(desc));
    Sequence_Evaluate(&hist, "/login", t0 + 500U, &delta, desc, sizeof(desc)); /* wraps across 0 */
    uint16_t peak = hist.sequence_score;
    assert(peak >= 40);

    /* Advance 40 seconds (40,000 ms -> 40 pts decay) */
    Sequence_Evaluate(&hist, "/status", t0 + 40500U, &delta, desc, sizeof(desc));
    assert(hist.sequence_score < peak);
    printf("[PASS] test_time_decay_and_wraparound (peak=%u, decayed=%u)\n",
           peak, hist.sequence_score);
}

static void test_collision_safety(void) {
    /* Two paths that may hash to same bucket or collide: verify distinct IDs */
    uint16_t id1 = Sequence_ResolveEndpointId("/shell", NULL);
    uint16_t id2 = Sequence_ResolveEndpointId("/cmd", NULL);
    uint16_t id3 = Sequence_ResolveEndpointId("/cgi-bin/luci", NULL);
    uint16_t id1_again = Sequence_ResolveEndpointId("/shell", NULL);
    assert(id1 == id1_again);
    assert(id1 != id2 && id2 != id3 && id1 != id3);
    printf("[PASS] test_collision_safety (ids: %u, %u, %u)\n", id1, id2, id3);
}

static void test_multi_ip_and_memory_pressure(void) {
    IPProfile_Init();
    Sequence_Init();

    /* Create high-risk attacker IP at slot 0 */
    RequestRecord_t atk;
    memset(&atk, 0, sizeof(atk));
    strcpy(atk.source_ip, "192.168.1.200");
    strcpy(atk.method, "GET");
    strcpy(atk.endpoint, "/admin");
    atk.is_unknown_endpoint = true;
    atk.triggered_event = EVENT_UNKNOWN_ENDPOINT;
    atk.timestamp_tick = 1000;

    IPProfile_t *p_atk = IPProfile_GetOrCreate(atk.source_ip, 1000);
    assert(p_atk != NULL);
    for (int k = 0; k < 6; k++) {
        atk.timestamp_tick = 1000 + (uint32_t)(k * 200);
        strcpy(atk.endpoint, (k % 2 == 0) ? "/admin" : "/login");
        IPProfile_Update(p_atk, &atk);
        uint8_t d = 0;
        char desc[128];
        Sequence_Evaluate(&p_atk->sequence_history, atk.endpoint, atk.timestamp_tick, &d, desc, sizeof(desc));
        if (d > 0) {
            uint32_t ns = p_atk->threat_score + d;
            p_atk->threat_score = (ns > 100) ? 100 : (uint8_t)ns;
        }
    }
    assert(p_atk->threat_score >= 70);

    /* Fill remaining 23 slots + 5 more benign IPs to trigger memory pressure & eviction */
    for (int i = 1; i <= 28; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.0.0.%d", i);
        RequestRecord_t ben;
        memset(&ben, 0, sizeof(ben));
        strcpy(ben.source_ip, ip);
        strcpy(ben.method, "GET");
        strcpy(ben.endpoint, "/status");
        ben.timestamp_tick = 5000 + (uint32_t)(i * 100);
        IPProfile_t *p = IPProfile_GetOrCreate(ip, ben.timestamp_tick);
        assert(p != NULL);
        IPProfile_Update(p, &ben);
    }

    /* High-risk attacker must still be preserved */
    assert(IPProfile_Lookup("192.168.1.200") != NULL);

    ThreatMemoryStats_t stats;
    ThreatMem_GetStats(&stats, IPProfile_GetActiveCount());
    assert(stats.eviction_summary.total_evicted_count == 5);
    assert(stats.memory_pressure_events > 0);
    assert(stats.sequence_detections > 0);
    printf("[PASS] test_multi_ip_and_memory_pressure (active=%lu, evictions=%lu, pressure_events=%lu, seq_det=%lu)\n",
           (unsigned long)stats.active_profiles_count,
           (unsigned long)stats.eviction_summary.total_evicted_count,
           (unsigned long)stats.memory_pressure_events,
           (unsigned long)stats.sequence_detections);
}

int main(void) {
    Sequence_Init();
    Detection_Init();
    IPProfile_Init();

    test_normal_browsing();
    test_admin_probing_and_recon();
    test_repeated_transitions();
    test_time_decay_and_wraparound();
    test_collision_safety();
    test_multi_ip_and_memory_pressure();

    /* Benchmark 10,000 sequence evaluations */
    IPSequenceHistory_t bench_hist;
    memset(&bench_hist, 0, sizeof(bench_hist));
    uint8_t d = 0;
    char desc[128];
    const char *eps[4] = {"/", "/admin", "/login", "/status"};
    clock_t start = clock();
    for (int i = 0; i < 10000; i++) {
        Sequence_Evaluate(&bench_hist, eps[i & 3], (uint32_t)(i * 100), &d, desc, sizeof(desc));
    }
    clock_t end = clock();
    double elapsed_ms = ((double)(end - start) * 1000.0) / CLOCKS_PER_SEC;

    printf("\n--- Struct Sizes & Overhead ---\n");
    printf("sizeof(SeqRingEntry_t)      = %zu bytes\n", sizeof(SeqRingEntry_t));
    printf("sizeof(IPSequenceHistory_t) = %zu bytes\n", sizeof(IPSequenceHistory_t));
    printf("sizeof(IPProfile_t)         = %zu bytes\n", sizeof(IPProfile_t));
    printf("24 x IPProfile_t BSS        = %zu bytes\n", 24 * sizeof(IPProfile_t));
    printf("10,000 Sequence_Evaluate()  = %.3f ms (host x86_64)\n", elapsed_ms);
    return 0;
}
