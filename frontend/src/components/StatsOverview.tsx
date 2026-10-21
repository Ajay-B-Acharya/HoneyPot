import React from "react";
import { Activity, ShieldAlert, AlertTriangle, ShieldCheck } from "lucide-react";
import { DashboardStats } from "../types/api";

interface StatsOverviewProps {
  stats: DashboardStats | null;
  loading: boolean;
}

export const StatsOverview: React.FC<StatsOverviewProps> = ({ stats, loading }) => {
  return (
    <div className="stats-grid">
      {/* Total Requests */}
      <div className="stat-card">
        <div className="stat-header">
          <span>Total Requests</span>
          <Activity size={16} />
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

      {/* Security Events */}
      <div className="stat-card">
        <div className="stat-header">
          <span>Security Events</span>
          <ShieldAlert size={16} className="text-amber-400" />
        </div>
        <div className="stat-value">
          {loading ? "..." : stats?.total_security_events ?? 0}
        </div>
        <div className="stat-breakdown">
          <span>Warn: {stats?.events_by_severity?.warning ?? 0}</span>
          <span>•</span>
          <span>Crit: {stats?.events_by_severity?.critical ?? 0}</span>
        </div>
      </div>

      {/* Suspicious Traffic */}
      <div className="stat-card">
        <div className="stat-header">
          <span>Suspicious Requests</span>
          <AlertTriangle size={16} className="text-rose-400" />
        </div>
        <div className="stat-value">
          {loading ? "..." : stats?.suspicious_requests ?? 0}
        </div>
        <div className="stat-breakdown">
          <span>
            {stats && stats.total_requests > 0
              ? `${Math.round(
                  (stats.suspicious_requests / stats.total_requests) * 100
                )}% of total`
              : "0% of total"}
          </span>
        </div>
      </div>

      {/* Normal Requests */}
      <div className="stat-card">
        <div className="stat-header">
          <span>Normal Requests</span>
          <ShieldCheck size={16} className="text-emerald-400" />
        </div>
        <div className="stat-value">
          {loading ? "..." : stats?.normal_requests ?? 0}
        </div>
        <div className="stat-breakdown">
          <span>
            {stats && stats.total_requests > 0
              ? `${Math.round(
                  (stats.normal_requests / stats.total_requests) * 100
                )}% clean traffic`
              : "100% clean"}
          </span>
        </div>
      </div>
    </div>
  );
};
