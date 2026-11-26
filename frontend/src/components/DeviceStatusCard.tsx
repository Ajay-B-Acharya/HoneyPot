import React from "react";
import { Cpu, CheckCircle2, AlertTriangle, XCircle, HelpCircle, Wifi, WifiOff } from "lucide-react";
import { DeviceStatusResponse } from "../types/api";

interface DeviceStatusCardProps {
  deviceData: DeviceStatusResponse | null;
  loading: boolean;
  error: string | null;
}

export const DeviceStatusCard: React.FC<DeviceStatusCardProps> = ({
  deviceData,
  loading,
  error,
}) => {
  const devices = deviceData?.devices ?? [];
  const primaryDevice =
    devices.find((d) => d.device_id === "rw612-security-01") ??
    (devices.length > 0 ? devices[0] : null);

  const rawStatus = primaryDevice?.status ?? "not_registered";
  const isOnline = rawStatus === "online" || rawStatus === "active";
  const isUnstable = rawStatus === "connection_unstable";
  const isOffline = rawStatus === "offline" || rawStatus === "inactive";

  const dotStyle: React.CSSProperties = {
    backgroundColor: loading
      ? "#64748b"
      : isOnline
      ? "#10b981" // GREEN = ONLINE
      : isUnstable
      ? "#f59e0b" // AMBER = CONNECTION UNSTABLE
      : isOffline
      ? "#ef4444" // RED = OFFLINE
      : "#64748b", // GREY = NOT REGISTERED
  };

  const statusLabel = loading
    ? "Checking hardware presence..."
    : !primaryDevice
    ? "NOT REGISTERED"
    : isOnline
    ? "ONLINE"
    : isUnstable
    ? "CONNECTION UNSTABLE"
    : isOffline
    ? "OFFLINE"
    : "NOT REGISTERED";

  const formatUptime = (sec?: number | null) => {
    if (sec === null || sec === undefined) return "N/A";
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    return h > 0 ? `${h}h ${m}m ${s}s` : `${m}m ${s}s`;
  };

  return (
    <div className="status-card">
      <div className="status-indicator-dot" style={dotStyle} />
      <div className="status-details">
        <div className="status-label">Physical FRDM-RW612 Presence</div>
        <div className="status-value">
          {isOnline ? (
            <CheckCircle2 size={16} style={{ color: "#10b981" }} />
          ) : isUnstable ? (
            <AlertTriangle size={16} style={{ color: "#f59e0b" }} />
          ) : isOffline ? (
            <XCircle size={16} style={{ color: "#ef4444" }} />
          ) : (
            <HelpCircle size={16} style={{ color: "#64748b" }} />
          )}
          <span>
            {primaryDevice ? `${primaryDevice.device_id} — ${statusLabel}` : `FRDM-RW612 — ${statusLabel}`}
          </span>
        </div>

        <div className="status-meta" style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", marginTop: "0.25rem" }}>
          {primaryDevice ? (
            <>
              <span>IP: {primaryDevice.device_ip ?? "N/A"}</span>
              <span>|</span>
              <span style={{ display: "inline-flex", alignItems: "center", gap: "3px" }}>
                {primaryDevice.wifi_connected ? <Wifi size={12} /> : <WifiOff size={12} />}
                Wi-Fi: {primaryDevice.wifi_connected ? "Connected" : "Disconnected"}
              </span>
              <span>|</span>
              <span>Uptime: {formatUptime(primaryDevice.uptime_seconds)}</span>
              <span>|</span>
              <span>
                Heap: {primaryDevice.free_heap_bytes != null ? `${Math.round(primaryDevice.free_heap_bytes / 1024)} KB` : "N/A"}
              </span>
              <span>|</span>
              <span>FW: {primaryDevice.firmware_version ?? "N/A"}</span>
              <span>|</span>
              <span>
                Last heartbeat:{" "}
                {primaryDevice.last_heartbeat
                  ? new Date(primaryDevice.last_heartbeat).toLocaleString()
                  : primaryDevice.last_seen
                  ? new Date(primaryDevice.last_seen).toLocaleString()
                  : "Never"}
              </span>
            </>
          ) : error ? (
            `Device API error: ${error}`
          ) : (
            "No physical hardware heartbeat registered"
          )}
        </div>
      </div>
      <Cpu size={22} className="brand-icon" />
    </div>
  );
};
