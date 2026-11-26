import React from "react";
import { ShieldAlert, AlertTriangle, AlertOctagon, Info, GitCommit, ArrowRight } from "lucide-react";
import { SecurityEvent } from "../types/api";

interface SecurityEventsTableProps {
  events: SecurityEvent[];
  loading: boolean;
  error: string | null;
}

export const SecurityEventsTable: React.FC<SecurityEventsTableProps> = ({
  events,
  loading,
  error,
}) => {
  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return (
          <span className="badge badge-critical">
            <AlertOctagon size={12} style={{ marginRight: "3px" }} />
            Critical
          </span>
        );
      case "warning":
        return (
          <span className="badge badge-warning">
            <AlertTriangle size={12} style={{ marginRight: "3px" }} />
            Warning
          </span>
        );
      case "informational":
      default:
        return (
          <span className="badge badge-info">
            <Info size={12} style={{ marginRight: "3px" }} />
            Info
          </span>
        );
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">
          <ShieldAlert size={18} className="icon-amber" />
          <span>Security Events ({events.length})</span>
        </div>
      </div>

      <div className="table-container">
        {loading ? (
          <div className="loading-state">Loading security events...</div>
        ) : error ? (
          <div className="empty-state" style={{ color: "var(--accent-rose)" }}>
            Error loading events: {error}
          </div>
        ) : events.length === 0 ? (
          <div className="empty-state">
            No security events detected. Normal system state.
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Time (UTC)</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Endpoint</th>
                <th>Source IP</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {events.map((evt) => {
                const endpoint =
                  evt.metadata?.endpoint ??
                  evt.metadata?.normalized_endpoint ??
                  "-";

                return (
                  <tr key={evt.id}>
                    <td className="mono-cell">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </td>
                    <td>
                      {evt.event_type === "attack_sequence" ? (
                        <span className="badge badge-critical" style={{ background: "#4c0519", color: "#f43f5e" }}>
                          <GitCommit size={12} style={{ marginRight: "3px" }} />
                          {evt.metadata?.pattern ?? "attack_sequence"}
                        </span>
                      ) : (
                        <span className="badge badge-info">{evt.event_type}</span>
                      )}
                    </td>
                    <td>{getSeverityBadge(evt.severity)}</td>
                    <td className="mono-cell">
                      {evt.metadata && Array.isArray(evt.metadata.sequence) ? (
                        <div style={{ display: "flex", alignItems: "center", gap: "2px", flexWrap: "wrap" }}>
                          {(evt.metadata.sequence as string[]).map((step: string, idx: number, arr: string[]) => (
                            <React.Fragment key={idx}>
                              <span style={{ fontSize: "0.6875rem", background: "var(--border-color)", padding: "1px 4px", borderRadius: "3px" }}>
                                {step}
                              </span>
                              {idx < arr.length - 1 && (
                                <ArrowRight size={10} style={{ color: "var(--text-muted)" }} />
                              )}
                            </React.Fragment>
                          ))}
                        </div>
                      ) : (
                        endpoint
                      )}
                    </td>
                    <td className="mono-cell">{evt.source_ip ?? "None"}</td>
                    <td title={evt.description} style={{ maxWidth: "320px" }}>
                      {evt.description}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
