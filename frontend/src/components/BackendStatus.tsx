import React from "react";
import { Server, Wifi, WifiOff } from "lucide-react";
import { HealthResponse } from "../types/api";

interface BackendStatusProps {
  health: HealthResponse | null;
  loading: boolean;
  error: string | null;
  lastRefresh: Date | null;
}

export const BackendStatus: React.FC<BackendStatusProps> = ({
  health,
  loading,
  error,
  lastRefresh,
}) => {
  const isOnline = !!health && !error && health.status === "ok";

  return (
    <div className="status-card">
      <div
        className={`status-indicator-dot ${
          loading
            ? "status-unknown"
            : isOnline
            ? "status-online"
            : "status-offline"
        }`}
      />
      <div className="status-details">
        <div className="status-label">Backend API Server</div>
        <div className="status-value">
          {loading ? (
            "Connecting..."
          ) : isOnline ? (
            <>
              <Wifi size={16} className="text-emerald-400" />
              <span>Online (FastAPI)</span>
            </>
          ) : (
            <>
              <WifiOff size={16} className="text-rose-400" />
              <span>Offline / Unreachable</span>
            </>
          )}
        </div>
        <div className="status-meta">
          {isOnline
            ? `Service: ${health?.service ?? "backend"} | Connected`
            : error
            ? `Error: ${error}`
            : "Awaiting connection..."}
          {lastRefresh && ` | Refreshed: ${lastRefresh.toLocaleTimeString()}`}
        </div>
      </div>
      <Server size={22} className="brand-icon" />
    </div>
  );
};
