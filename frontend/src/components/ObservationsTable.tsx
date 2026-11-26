import React from "react";
import { Radio } from "lucide-react";
import { EdgeObservation } from "../types/api";

interface ObservationsTableProps {
  observations: EdgeObservation[];
  loading: boolean;
  error: string | null;
}

export const ObservationsTable: React.FC<ObservationsTableProps> = ({
  observations,
  loading,
  error,
}) => {
  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">
          <Radio size={18} className="icon-cyan" />
          <span>Compact Edge Observations ({observations.length})</span>
        </div>
      </div>

      <div className="table-container">
        {loading ? (
          <div className="loading-state">Loading edge observations...</div>
        ) : error ? (
          <div className="empty-state" style={{ color: "var(--accent-rose)" }}>
            Error loading observations: {error}
          </div>
        ) : observations.length === 0 ? (
          <div className="empty-state">No compact edge observations ingested yet.</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Time (UTC)</th>
                <th>Observation ID</th>
                <th>Source IP</th>
                <th>Endpoint (ID)</th>
                <th>Edge Score</th>
                <th>Corr Score</th>
                <th>Confidence</th>
                <th>Fingerprint</th>
              </tr>
            </thead>
            <tbody>
              {observations.map((obs) => (
                <tr key={obs.id}>
                  <td className="mono-cell">
                    {new Date(obs.event_timestamp).toLocaleTimeString()}
                  </td>
                  <td className="mono-cell">{obs.observation_id}</td>
                  <td className="mono-cell">{obs.source_ip}</td>
                  <td className="mono-cell">
                    {obs.endpoint ?? "-"} ({obs.endpoint_id})
                  </td>
                  <td className="mono-cell">{obs.edge_score}</td>
                  <td className="mono-cell">{obs.correlation_score}</td>
                  <td className="mono-cell">
                    {Math.round(obs.correlation_confidence * 100)}%
                    {obs.shared_ip_suspected && (
                      <span className="badge badge-warning" style={{ marginLeft: "4px" }}>
                        Shared IP
                      </span>
                    )}
                  </td>
                  <td className="mono-cell">{obs.transition_fingerprint ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
