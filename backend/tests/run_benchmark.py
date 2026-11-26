"""Measured benchmark script for IoT Honeypot Monitor backend & correlation."""

import json
import time
import urllib.request

BASE = "http://127.0.0.1:8000"


def post_json(path: str, data: dict) -> tuple[int, dict, float]:
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        BASE + path,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req) as resp:
        raw = resp.read().decode("utf-8")
        dt_ms = (time.perf_counter() - t0) * 1000.0
        return resp.status, json.loads(raw), dt_ms


def main():
    ts_prefix = int(time.time())

    # 1. Single observation ingestion & correlation latency (10 requests)
    obs_latencies = []
    for i in range(10):
        ep = ["/", "/admin", "/login"][i % 3]
        status, _, dt_ms = post_json(
            "/api/observations",
            {
                "observation_id": f"bench-obs-{ts_prefix}-{i}",
                "device_id": "rw612-security-01",
                "source_ip": "203.0.113.42",
                "endpoint_id": 10 + (i % 3),
                "endpoint": ep,
                "event_timestamp": f"2026-11-26T12:30:{i:02d}Z",
                "sequence_num": i + 1,
                "edge_score": 50 if ep != "/" else 2,
            },
        )
        assert status == 201
        obs_latencies.append(dt_ms)

    # 2. Batch 8-event sync latency & duplicate prevention
    batch_payload = {
        "events": [
            {
                "client_event_id": f"bench-evt-{ts_prefix}-{i}",
                "timestamp": "2026-11-26T12:31:00Z",
                "device_id": "rw612-security-01",
                "event_type": "unknown_endpoint",
                "severity": "warning",
                "description": "Benchmark event",
                "source_ip": "203.0.113.42",
            }
            for i in range(8)
        ]
    }
    b_status, b_res, b_ms = post_json("/api/events/batch", batch_payload)
    assert b_status == 201
    dup_status, dup_res, dup_ms = post_json("/api/events/batch", batch_payload)
    assert dup_status == 201

    # 3. False-positive / false-negative check across normal vs attack sequences
    fp_count = 0
    for i in range(5):
        _, res, _ = post_json(
            "/api/observations",
            {
                "observation_id": f"bench-norm-{ts_prefix}-{i}",
                "device_id": "rw612-security-01",
                "source_ip": "192.0.2.10",
                "endpoint_id": 1 if i % 2 == 0 else 2,
                "endpoint": "/status" if i % 2 == 0 else "/info",
                "event_timestamp": f"2026-11-26T12:32:{i:02d}Z",
                "sequence_num": i + 1,
                "edge_score": 0,
            },
        )
        if res["derived_event_id"] is not None:
            fp_count += 1

    fn_count = 0
    atk_seq = [("/", 1, 2), ("/admin", 10, 20), ("/config", 12, 58)]
    last_atk = None
    for i, (ep, eid, sc) in enumerate(atk_seq):
        _, last_atk, _ = post_json(
            "/api/observations",
            {
                "observation_id": f"bench-atk-{ts_prefix}-{i}",
                "device_id": "rw612-security-01",
                "source_ip": "192.0.2.99",
                "endpoint_id": eid,
                "endpoint": ep,
                "event_timestamp": f"2026-11-26T12:33:{i:02d}Z",
                "sequence_num": i + 1,
                "edge_score": sc,
            },
        )
    if last_atk["derived_event_id"] is None:
        fn_count += 1

    print(f"ObsAvgMs={sum(obs_latencies)/len(obs_latencies):.2f}")
    print(f"ObsMinMs={min(obs_latencies):.2f}")
    print(f"ObsMaxMs={max(obs_latencies):.2f}")
    print(f"Batch8Ms={b_ms:.2f},inserted={b_res['inserted']},dup={b_res['duplicates']}")
    print(f"DupBatch8Ms={dup_ms:.2f},inserted={dup_res['inserted']},dup={dup_res['duplicates']}")
    print(f"NormalTrafficFP={fp_count}/5,AttackSeqFN={fn_count}/1")


if __name__ == "__main__":
    main()
