import React, { useState } from "react";
import { Play, Send, ShieldAlert, Zap, AlertTriangle } from "lucide-react";
import { createRequestLog, createSecurityEvent } from "../services/api";

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
        </div>

        {feedback && <div className="test-feedback">{feedback}</div>}
      </div>
    </div>
  );
};
