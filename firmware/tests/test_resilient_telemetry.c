#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/detection_rules.h"
#include "../src/offline_buffer.h"
#include "../src/telemetry_client.h"

static void test_selective_eviction_preserves_critical(void) {
    OfflineBuffer_Init();

    /* Push 10 critical events first, then fill remaining 38 with warning events */
    for (int i = 0; i < 48; i++) {
        RequestRecord_t rec;
        memset(&rec, 0, sizeof(rec));
        strcpy(rec.source_ip, "192.168.1.50");
        strcpy(rec.method, "GET");
        strcpy(rec.endpoint, (i < 10) ? "/admin" : "/probe");
        rec.timestamp_tick = 1000 + (uint32_t)(i * 10);
        rec.triggered_event = (i < 10) ? EVENT_ATTACK_SEQUENCE : EVENT_UNKNOWN_ENDPOINT;
        rec.severity = (i < 10) ? SEV_CRITICAL : SEV_WARNING;
        snprintf(rec.event_description, sizeof(rec.event_description), "evt-%d", i);
        assert(OfflineBuffer_Push(&rec));
    }
    assert(OfflineBuffer_GetPendingCount() == 48);

    /* Push 5 more critical events -> must evict WARNING events, NOT the 10 CRITICAL ones */
    for (int i = 48; i < 53; i++) {
        RequestRecord_t rec;
        memset(&rec, 0, sizeof(rec));
        strcpy(rec.source_ip, "192.168.1.50");
        strcpy(rec.method, "GET");
        strcpy(rec.endpoint, "/admin");
        rec.timestamp_tick = 2000 + (uint32_t)i;
        rec.triggered_event = EVENT_ATTACK_SEQUENCE;
        rec.severity = SEV_CRITICAL;
        snprintf(rec.event_description, sizeof(rec.event_description), "crit-%d", i);
        assert(OfflineBuffer_Push(&rec));
    }

    OfflineEvent_t batch[48];
    uint32_t got = OfflineBuffer_GetBatch(batch, 48);
    assert(got == 48);
    int crit_count = 0;
    for (uint32_t i = 0; i < got; i++) {
        if (batch[i].severity == SEV_CRITICAL) crit_count++;
    }
    assert(crit_count == 15);
    OfflineBufferStats_t stats;
    OfflineBuffer_GetStats(&stats);
    assert(stats.total_dropped_routine == 5);
    assert(stats.total_dropped_critical == 0);
    printf("[PASS] test_selective_eviction_preserves_critical (crit=%d, dropped_routine=%lu)\n",
           crit_count, (unsigned long)stats.total_dropped_routine);
}

static void test_partial_batch_ack_by_ids(void) {
    OfflineBuffer_Init();
    for (int i = 0; i < 4; i++) {
        RequestRecord_t rec;
        memset(&rec, 0, sizeof(rec));
        strcpy(rec.source_ip, "10.0.0.5");
        strcpy(rec.method, "GET");
        strcpy(rec.endpoint, "/shell");
        rec.timestamp_tick = 5000 + (uint32_t)i;
        rec.triggered_event = EVENT_UNKNOWN_ENDPOINT;
        rec.severity = SEV_WARNING;
        char cid[48];
        snprintf(cid, sizeof(cid), "rw612-evt-5000-%04d", i + 1);
        assert(OfflineBuffer_PushWithId(&rec, cid, (uint32_t)(i + 1)));
    }
    assert(OfflineBuffer_GetPendingCount() == 4);

    /* Ack only 1st and 3rd (simulate partial batch failure on 2nd and 4th) */
    char acked[2][48];
    strcpy(acked[0], "rw612-evt-5000-0001");
    strcpy(acked[1], "rw612-evt-5000-0003");
    uint32_t removed = OfflineBuffer_AckByIds(acked, 2);
    assert(removed == 2);
    assert(OfflineBuffer_GetPendingCount() == 2);

    OfflineEvent_t rem[2];
    OfflineBuffer_GetBatch(rem, 2);
    assert(strcmp(rem[0].client_event_id, "rw612-evt-5000-0002") == 0);
    assert(strcmp(rem[1].client_event_id, "rw612-evt-5000-0004") == 0);
    printf("[PASS] test_partial_batch_ack_by_ids (remaining: %s, %s)\n",
           rem[0].client_event_id, rem[1].client_event_id);
}

static void test_adaptive_retry_and_batch(void) {
    assert(Telemetry_ComputeAdaptiveBackoffMs(10, 0) == 1000);
    assert(Telemetry_ComputeAdaptiveBackoffMs(80, 0) == 200);
    assert(Telemetry_ComputeAdaptiveBackoffMs(20, 3) == 4000);
    assert(Telemetry_ComputeAdaptiveBackoffMs(80, 3) == 2000);
    assert(Telemetry_ComputeAdaptiveBackoffMs(10, 10) == 30000);

    uint32_t b = 4;
    b = Telemetry_ComputeAdaptiveBatchSize(b, true, 60);
    assert(b == 8);
    b = Telemetry_ComputeAdaptiveBatchSize(b, false, 60);
    assert(b == 4);
    b = Telemetry_ComputeAdaptiveBatchSize(b, false, 60);
    assert(b == 2);
    printf("[PASS] test_adaptive_retry_and_batch\n");
}

int main(void) {
    Telemetry_Init();
    test_selective_eviction_preserves_critical();
    test_partial_batch_ack_by_ids();
    test_adaptive_retry_and_batch();
    return 0;
}
