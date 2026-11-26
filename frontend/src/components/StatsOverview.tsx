import React from "react";
import { Activity, ShieldAlert, AlertOctagon, Users, Cpu } from "lucide-react";
import { DashboardStats, DeviceStatusResponse, IPProfile } from "../types/api";

interface StatsOverviewProps {
  stats: DashboardStats | null;
  ipProfiles: IPProfile[];
  deviceData: DeviceStatusResponse | null;
  loading: boolean;
}

export const StatsOverview: React.FC<StatsOverviewProps> = ({
  stats,
  ipProfiles,
  deviceData,
  loading,
}) => {
  const suspiciousIpCount = ipProfiles.filter(
    (p) => p.threat_score >= 30 || p.risk_level !== "low"
  ).length;

  const primaryDevice =
    deviceData?.devices.find((d) => d.device_id === "rw612-security-01") ??
    deviceData?.devices[0] ??
    null;

  const devStatus = primaryDevice?.status ?? "not_registered";
  const devLabel =
    devStatus === "online" || devStatus === "active"
      ? "ONLINE"
      : devStatus === "connection_unstable"
      ? "UNSTABLE"
      : devStatus === "offline" || devStatus === "inactive"
      ? "OFFLINE"
      : "NOT REGISTERED";

  const devColor =
    devStatus === "online" || devStatus === "active"
      ? "#10b981"
      : devStatus === "connection_unstable"
      ? "#f59e0b"
      : devStatus === "offline" || devStatus === "inactive"
      ? "#ef4444"
      : "#64748b";

  return (
    <div className="stats-grid kpi-grid-5">
      <div className="stat-card">
        <div className="stat-header">
          <span>Total Security Events</span>
          <ShieldAlert size={16} className="icon-amber" />
        </div>
        <div className="stat-value">
          {loading ? "..." : stats?.total_security_events ?? 0}
        </div>
        <div className="stat-breakdown">
          <span>Warn: {stats?.events_by_severity?.warning ?? 0}</span>
          <span>•</span>
          <span>Info: {stats?.events_by_severity?.informational ?? 0}</span>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-header">
          <span>Critical Threats</span>
          <AlertOctagon size={16} className="icon-rose" />
        </div>
        <div className="stat-value" style={{ color: "var(--accent-rose)" }}>
          {loading ? "..." : stats?.events_by_severity?.critical ?? 0}
        </div>
        <div className="stat-breakdown">
          <span>High-severity alerts</span>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-header">
          <span>Suspicious IPs</span>
          <Users size={16} className="icon-cyan" />
        </div>
        <div className="stat-value">
          {loading ? "..." : suspiciousIpCount}
        </div>
        <div className="stat-breakdown">
          <span>of {ipProfiles.length} tracked profiles</span>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-header">
          <span>Total Requests</span>
          <Activity size={16} className="icon-emerald" />
        </div>
        <div className="stat-value">
          {loading ? "..." : stats?.total_requests ?? 0}
        </div>
        <div className="stat-breakdown">
          <span>Normal: {stats?.normal_requests ?? 0}</span>
          <span>•</span>
          <span>Unusual: {stats?.unusual_requests ?? 0}</span>
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-header">
          <span>Device Connectivity</span>
          <Cpu size={16} style={{ color: devColor }} />
        </div>
        <div className="stat-value" style={{ fontSize: "1.25rem", color: devColor }}>
          {loading ? "..." : devLabel}
        </div>
        <div className="stat-breakdown">
          <span>{primaryDevice ? primaryDevice.device_id : "No heartbeat"}</span>
        </div>
      </div>
    </div>
  );
};
