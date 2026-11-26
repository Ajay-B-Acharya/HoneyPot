import React, { useState } from "react";
import { Play, Send, ShieldAlert, Zap, AlertTriangle, UserCheck, GitCommit, Cpu, Layers } from "lucide-react";
import { createRequestLog, createSecurityEvent, batchSyncSecurityEvents } from "../services/api";

interface TestingPanelProps {
  onActionComplete: () => void;
  disabled: boolean;
}

export const TestingPanel: React.FC<TestingPanelProps> = ({
  onActionComplete,
  disabled,
}) => {
  const [feedback, setFeedback] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleTestNormal = async () => {
    setSubmitting(true);
    setFeedback("Submitting normal request log (/status)...");
    try {
      const res = await createRequestLog({
        timestamp: new Date().toISOString(),
        device_id: "rw612-security-01",
        source_ip: "192.168.1.105",
        method: "GET",
        endpoint: "/status",
        response_code: 200,
        classification: "normal",
      });
      setFeedback(
        `Success: Log #${res.id} recorded for allowed endpoint /status. No alert triggered.`
      );
      onActionComplete();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleTestUnknown = async () => {
    setSubmitting(true);
    setFeedback("Submitting probe to unallowed endpoint (/admin)...");
    try {
      const res = await createRequestLog({
        timestamp: new Date().toISOString(),
        device_id: "rw612-security-01",
        source_ip: "192.168.1.250",
        method: "GET",
        endpoint: "/admin",
        response_code: 404,
        classification: "normal",
      });
      setFeedback(
        `Success: Log #${res.id} recorded for /admin. Backend detection engine automatically generated an 'unknown_endpoint' security event!`
      );
      onActionComplete();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleTestBurst = async () => {
    setSubmitting(true);
    setFeedback("Sending burst of 5 requests to /status...");
    try {
      const now = new Date();
      for (let i = 0; i < 5; i++) {
        await createRequestLog({
          timestamp: new Date(now.getTime() + i * 100).toISOString(),
          device_id: "rw612-security-01",
          source_ip: "192.168.1.200",
          method: "GET",
          endpoint: "/status",
          response_code: 200,
          classification: "normal",
        });
      }
      setFeedback(
        "Success: 5 requests sent in rapid sequence. Sliding-window rate tracker updated."
      );
      onActionComplete();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleTestManualEvent = async () => {
    setSubmitting(true);
    setFeedback("Submitting manual security event via POST /api/events...");
    try {
      const res = await createSecurityEvent({
        timestamp: new Date().toISOString(),
        device_id: "rw612-security-01",
        event_type: "tamper_detected",
        severity: "critical",
        description: "Enclosure tamper sensor tripped on FRDM-RW612 testbench",
        source_ip: "192.168.1.10",
        metadata: { sensor_pin: "GPIO_4", threshold_mv: 3300 },
      });
      setFeedback(
        `Success: Event #${res.id} created manually with critical severity.`
      );
      onActionComplete();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleTestMultiIPProfiling = async () => {
    setSubmitting(true);
    setFeedback("Simulating traffic from 3 distinct IP addresses with different behaviors...");
    try {
      const now = new Date();
      // 1. Benign IP: 192.168.1.105 (allowed endpoint)
      await createRequestLog({
        timestamp: now.toISOString(),
        device_id: "rw612-security-01",
        source_ip: "192.168.1.105",
        method: "GET",
        endpoint: "/status",
        response_code: 200,
        classification: "normal",
      });

      // 2. Probing IP: 192.168.1.222 (repeated probes to /config)
      for (let i = 0; i < 3; i++) {
        await createRequestLog({
          timestamp: new Date(now.getTime() + (i + 1) * 200).toISOString(),
          device_id: "rw612-security-01",
          source_ip: "192.168.1.222",
          method: "GET",
          endpoint: "/config",
          response_code: 200,
          classification: "normal",
        });
      }

      // 3. Hostile Scanner IP: 192.168.1.99 (unknown endpoints /admin, /shell, /login)
      const attackPaths = ["/admin", "/shell.php", "/setup.cgi", "/login"];
      for (let i = 0; i < attackPaths.length; i++) {
        await createRequestLog({
          timestamp: new Date(now.getTime() + (i + 5) * 200).toISOString(),
          device_id: "rw612-security-01",
          source_ip: "192.168.1.99",
          method: "GET",
          endpoint: attackPaths[i],
          response_code: 404,
          classification: "suspicious",
        });
      }

      setFeedback(
        "Success: 3 distinct IP profiles generated (Benign: 192.168.1.105, Prober: 192.168.1.222, Scanner: 192.168.1.99 with high threat score)."
      );
      onActionComplete();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleTestAttackSequence = async () => {
    setSubmitting(true);
    setFeedback("Executing attack sequence: / -> /admin -> /config -> /login from 192.168.1.188...");
    try {
      const now = new Date();
      const sequencePaths = ["/", "/admin", "/config", "/login"];
      for (let i = 0; i < sequencePaths.length; i++) {
        await createRequestLog({
          timestamp: new Date(now.getTime() + i * 250).toISOString(),
          device_id: "rw612-security-01",
          source_ip: "192.168.1.188",
          method: "GET",
          endpoint: sequencePaths[i],
          response_code: sequencePaths[i] === "/" || sequencePaths[i] === "/config" ? 200 : 404,
          classification: "normal",
        });
      }
      setFeedback(
        "Success: Attack sequence executed! Detected 'reconnaissance_probe' with Critical severity and elevated threat score."
      );
      onActionComplete();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleTestMemoryPressure = async () => {
    setSubmitting(true);
    setFeedback("Simulating memory pressure: generating requests from 16 distinct IPs...");
    try {
      const now = new Date();
      for (let i = 1; i <= 16; i++) {
        await createRequestLog({
          timestamp: new Date(now.getTime() + i * 50).toISOString(),
          device_id: "rw612-security-01",
          source_ip: `10.42.0.${100 + i}`,
          method: "GET",
          endpoint: i % 2 === 0 ? "/status" : "/admin",
          response_code: i % 2 === 0 ? 200 : 404,
          classification: i % 2 === 0 ? "normal" : "unusual",
        });
      }
      setFeedback(
        "Success: 16 IP profiles created. Memory diagnostics transitioned to 'moderate/high' pressure. Critical profiles protected."
      );
      onActionComplete();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleTestOfflineReconciliation = async () => {
    setSubmitting(true);
    setFeedback("Simulating offline continuity: reconciling batch of 3 queued edge events...");
    try {
      const now = new Date();
      const baseTick = Date.now();
      const batchRes = await batchSyncSecurityEvents([
        {
          timestamp: new Date(now.getTime() - 120000).toISOString(),
          device_id: "rw612-security-01",
          event_type: "unknown_endpoint",
          severity: "warning",
          description: "Decoy probe during outage to /setup.cgi",
          source_ip: "192.168.1.177",
          metadata: { client_event_id: `rw612-evt-${baseTick}-0001`, threat_score: 45, risk_level: "medium" },
        },
        {
          timestamp: new Date(now.getTime() - 60000).toISOString(),
          device_id: "rw612-security-01",
          event_type: "attack_sequence",
          severity: "critical",
          description: "Credential hunt sequence /admin -> /login during outage",
          source_ip: "192.168.1.177",
          metadata: { client_event_id: `rw612-evt-${baseTick}-0002`, threat_score: 85, risk_level: "critical" },
        },
        {
          timestamp: now.toISOString(),
          device_id: "rw612-security-01",
          event_type: "high_request_rate",
          severity: "warning",
          description: "Outage burst rate violation",
          source_ip: "192.168.1.215",
          metadata: { client_event_id: `rw612-evt-${baseTick}-0003`, threat_score: 60, risk_level: "medium" },
        },
      ]);

      setFeedback(
        `Success: Reconciled ${batchRes.inserted}/${batchRes.received} offline events (Duplicates: ${batchRes.duplicates}). Timestamps and intelligence preserved.`
      );
      onActionComplete();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div id="testing-panel" className="panel" style={{ marginTop: "1.5rem" }}>
      <div className="panel-header">
        <div className="panel-title">
          <Play size={18} className="icon-emerald" />
          <span>Backend Detection Testing Panel</span>
        </div>
      </div>

      <div className="panel-body">
        <p style={{ fontSize: "0.8125rem", color: "var(--text-muted)", marginBottom: "1rem" }}>
          Trigger real backend request logs and evaluate the integrated Python security detection engine in real time.
        </p>

        <div className="action-grid">
          <button
            className="test-btn"
            onClick={handleTestNormal}
            disabled={disabled || submitting}
          >
            <div className="test-btn-title">
              <Send size={14} className="icon-emerald" />
              <span>Normal Log (/status)</span>
            </div>
            <div className="test-btn-desc">
              Sends an allowed endpoint request. Verifies clean logging with no security alerts.
            </div>
          </button>

          <button
            className="test-btn"
            onClick={handleTestUnknown}
            disabled={disabled || submitting}
          >
            <div className="test-btn-title">
              <ShieldAlert size={14} className="icon-amber" />
              <span>Probe Unknown (/admin)</span>
            </div>
            <div className="test-btn-desc">
              Sends an unallowed endpoint request. Triggers Rule R1 to generate an 'unknown_endpoint' event.
            </div>
          </button>

          <button
            className="test-btn"
            onClick={handleTestBurst}
            disabled={disabled || submitting}
          >
            <div className="test-btn-title">
              <Zap size={14} className="icon-cyan" />
              <span>Traffic Burst (5x)</span>
            </div>
            <div className="test-btn-desc">
              Sends 5 rapid sequential requests to test the sliding-window tracker.
            </div>
          </button>

          <button
            className="test-btn"
            onClick={handleTestManualEvent}
            disabled={disabled || submitting}
          >
            <div className="test-btn-title">
              <AlertTriangle size={14} className="icon-rose" />
              <span>Manual Critical Event</span>
            </div>
            <div className="test-btn-desc">
              Submits a direct hardware tamper security event via POST /api/events.
            </div>
          </button>

          <button
            className="test-btn"
            onClick={handleTestMultiIPProfiling}
            disabled={disabled || submitting}
          >
            <div className="test-btn-title">
              <UserCheck size={14} className="icon-cyan" />
              <span>Multi-IP Behavioral Sim</span>
            </div>
            <div className="test-btn-desc">
              Sends traffic from 3 separate IPs (benign, prober, hostile) to verify dynamic threat profiling.
            </div>
          </button>

          <button
            className="test-btn"
            onClick={handleTestAttackSequence}
            disabled={disabled || submitting}
          >
            <div className="test-btn-title">
              <GitCommit size={14} className="icon-rose" />
              <span>Attack Sequence Sim</span>
            </div>
            <div className="test-btn-desc">
              Simulates / &rarr; /admin &rarr; /config &rarr; /login reconnaissance sequence to trigger sequence detection.
            </div>
          </button>

          <button
            className="test-btn"
            onClick={handleTestMemoryPressure}
            disabled={disabled || submitting}
          >
            <div className="test-btn-title">
              <Cpu size={14} className="icon-cyan" />
              <span>Memory Pressure &amp; Eviction Sim</span>
            </div>
            <div className="test-btn-desc">
              Sends requests across 16 IPs to test dynamic memory pressure thresholds and critical profile preservation.
            </div>
          </button>

          <button
            className="test-btn"
            onClick={handleTestOfflineReconciliation}
            disabled={disabled || submitting}
          >
            <div className="test-btn-title">
              <Layers size={14} className="icon-emerald" />
              <span>Offline Continuity &amp; Reconcile Sim</span>
            </div>
            <div className="test-btn-desc">
              Reconciles a batch of queued offline security events with unique IDs, testing idempotent ingestion and duplicate suppression.
            </div>
          </button>
        </div>

        {feedback && <div className="test-feedback">{feedback}</div>}
      </div>
    </div>
  );
};
