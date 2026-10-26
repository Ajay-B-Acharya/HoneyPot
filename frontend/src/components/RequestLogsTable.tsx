import React from "react";
import { Terminal } from "lucide-react";
import { RequestLog } from "../types/api";

interface RequestLogsTableProps {
  logs: RequestLog[];
  loading: boolean;
  error: string | null;
}

export const RequestLogsTable: React.FC<RequestLogsTableProps> = ({
  logs,
  loading,
  error,
}) => {
  const getClassificationBadge = (classification: string) => {
    switch (classification) {
      case "suspicious":
        return <span className="badge badge-critical">Suspicious</span>;
      case "unusual":
        return <span className="badge badge-warning">Unusual</span>;
      case "normal":
      default:
        return <span className="badge badge-normal">Normal</span>;
    }
  };

  const getStatusColor = (code: number | null) => {
    if (!code) return "var(--text-dim)";
    if (code >= 200 && code < 300) return "var(--accent-emerald)";
    if (code >= 400 && code < 500) return "var(--accent-amber)";
    if (code >= 500) return "var(--accent-rose)";
    return "var(--text-main)";
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">
          <Terminal size={18} className="icon-cyan" />
          <span>HTTP Request Logs ({logs.length})</span>
        </div>
      </div>

      <div className="table-container">
        {loading ? (
          <div className="loading-state">Loading HTTP request logs...</div>
        ) : error ? (
          <div className="empty-state" style={{ color: "var(--accent-rose)" }}>
            Error loading logs: {error}
          </div>
        ) : logs.length === 0 ? (
          <div className="empty-state">
            No request logs recorded yet. Submit a test request below.
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Time (UTC)</th>
                <th>Method</th>
                <th>Endpoint</th>
                <th>Source IP</th>
                <th>Status</th>
                <th>Classification</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id}>
                  <td className="mono-cell">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </td>
                  <td>
                    <span className="badge-method">{log.method}</span>
                  </td>
                  <td className="mono-cell">{log.endpoint}</td>
                  <td className="mono-cell">{log.source_ip ?? "-"}</td>
                  <td
                    className="mono-cell"
                    style={{
                      color: getStatusColor(log.response_code),
                      fontWeight: 600,
                    }}
                  >
                    {log.response_code ?? "-"}
                  </td>
                  <td>{getClassificationBadge(log.classification)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
