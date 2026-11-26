import React, { useState } from "react";
import { UserCheck, Shield, AlertTriangle, Flame, Search, Filter } from "lucide-react";
import { IPProfile, RiskLevel } from "../types/api";

interface IPProfilesTableProps {
  profiles: IPProfile[];
  loading: boolean;
  error: string | null;
}

export const IPProfilesTable: React.FC<IPProfilesTableProps> = ({
  profiles,
  loading,
  error,
}) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedRisk, setSelectedRisk] = useState<string>("all");

  const filteredProfiles = profiles.filter((p) => {
    const matchesSearch =
      searchTerm.trim() === "" ||
      p.ip_address.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRisk =
      selectedRisk === "all" || p.risk_level.toLowerCase() === selectedRisk;
    return matchesSearch && matchesRisk;
  });

  const getRiskBadge = (risk: RiskLevel) => {
    switch (risk) {
      case "critical":
        return (
          <span className="badge badge-critical">
            <Flame size={12} style={{ marginRight: "3px" }} />
            Critical
          </span>
        );
      case "high":
        return (
          <span className="badge badge-critical" style={{ background: "#7f1d1d", color: "#fca5a5" }}>
            <AlertTriangle size={12} style={{ marginRight: "3px" }} />
            High
          </span>
        );
      case "medium":
        return (
          <span className="badge badge-warning">
            <AlertTriangle size={12} style={{ marginRight: "3px" }} />
            Medium
          </span>
        );
      case "low":
      default:
        return (
          <span className="badge badge-info">
            <Shield size={12} style={{ marginRight: "3px" }} />
            Low
          </span>
        );
    }
  };

  const getThreatScoreColor = (score: number) => {
    if (score >= 90) return "var(--accent-rose, #f43f5e)";
    if (score >= 70) return "#f97316"; // Orange
    if (score >= 30) return "var(--accent-amber, #eab308)";
    return "var(--accent-emerald, #10b981)";
  };

  return (
    <div className="panel" style={{ marginTop: "1.5rem" }}>
      <div className="panel-header" style={{ flexWrap: "wrap", gap: "0.75rem" }}>
        <div className="panel-title">
          <UserCheck size={18} className="icon-cyan" />
          <span>Behavioral IP Profiles ({filteredProfiles.length} of {profiles.length})</span>
        </div>

        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
            <Search size={14} style={{ position: "absolute", left: "8px", color: "var(--text-muted)" }} />
            <input
              type="text"
              placeholder="Search IP..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                padding: "0.35rem 0.5rem 0.35rem 1.75rem",
                fontSize: "0.75rem",
                borderRadius: "4px",
                border: "1px solid var(--border-color)",
                background: "var(--bg-main)",
                color: "var(--text-main)",
                outline: "none",
                width: "140px",
              }}
            />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
            <Filter size={14} style={{ color: "var(--text-muted)" }} />
            <select
              value={selectedRisk}
              onChange={(e) => setSelectedRisk(e.target.value)}
              style={{
                padding: "0.35rem 0.5rem",
                fontSize: "0.75rem",
                borderRadius: "4px",
                border: "1px solid var(--border-color)",
                background: "var(--bg-main)",
                color: "var(--text-main)",
                outline: "none",
              }}
            >
              <option value="all">All Risks</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>
      </div>

      <div className="table-container">
        {loading ? (
          <div className="loading-state">Loading IP profiles...</div>
        ) : error ? (
          <div className="empty-state" style={{ color: "var(--accent-rose)" }}>
            Error loading IP profiles: {error}
          </div>
        ) : filteredProfiles.length === 0 ? (
          <div className="empty-state">
            {profiles.length === 0
              ? "No behavioral IP profiles tracked yet. Incoming traffic will automatically generate per-IP profiles."
              : "No IP profiles match the selected filter."}
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Source IP</th>
                <th>Threat Score</th>
                <th>Risk Level</th>
                <th>Requests</th>
                <th>Suspicious</th>
                <th>Repeated</th>
                <th>Unique Endpoints</th>
                <th>Rate (req/min)</th>
                <th>Confidence</th>
                <th>Last Active</th>
              </tr>
            </thead>
            <tbody>
              {filteredProfiles.map((p) => {
                const scoreColor = getThreatScoreColor(p.threat_score);
                return (
                  <tr key={p.id}>
                    <td>
                      <span className="mono-text" style={{ fontWeight: 600 }}>
                        {p.ip_address}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                        <div
                          style={{
                            width: "48px",
                            height: "6px",
                            borderRadius: "3px",
                            backgroundColor: "var(--border-color)",
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              width: `${p.threat_score}%`,
                              height: "100%",
                              backgroundColor: scoreColor,
                              transition: "width 0.3s ease",
                            }}
                          />
                        </div>
                        <span
                          className="mono-text"
                          style={{ fontWeight: 600, color: scoreColor, minWidth: "24px" }}
                        >
                          {p.threat_score}
                        </span>
                      </div>
                    </td>
                    <td>{getRiskBadge(p.risk_level)}</td>
                    <td className="mono-text">{p.total_requests}</td>
                    <td>
                      <span
                        className="mono-text"
                        style={{
                          color: p.suspicious_requests > 0 ? "var(--accent-rose)" : "inherit",
                          fontWeight: p.suspicious_requests > 0 ? 600 : "normal",
                        }}
                      >
                        {p.suspicious_requests}
                      </span>
                    </td>
                    <td className="mono-text">{p.repeated_requests}</td>
                    <td>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "3px" }}>
                        <span className="badge badge-info">{p.unique_endpoints_count} total</span>
                        {p.unique_endpoints.slice(0, 3).map((ep, idx) => (
                          <span
                            key={idx}
                            className="mono-text"
                            style={{
                              fontSize: "0.6875rem",
                              background: "var(--border-color)",
                              padding: "1px 4px",
                              borderRadius: "3px",
                            }}
                          >
                            {ep}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="mono-text">{p.request_frequency}</td>
                    <td className="mono-text" style={{ fontSize: "0.75rem" }}>
                      {typeof p.correlation_confidence === "number"
                        ? `${Math.round(p.correlation_confidence * 100)}%`
                        : "100%"}
                      {p.shared_ip_suspected && (
                        <span className="badge badge-warning" style={{ marginLeft: "4px" }}>
                          Shared IP
                        </span>
                      )}
                    </td>
                    <td className="mono-text" style={{ fontSize: "0.75rem" }}>
                      {new Date(p.last_seen).toLocaleTimeString()}
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
