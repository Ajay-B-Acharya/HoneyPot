import React from "react";
import { Cpu, CheckCircle2, Clock, AlertCircle } from "lucide-react";
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
  const primaryDevice = devices.length > 0 ? devices[0] : null;

  const isDeviceActive = primaryDevice?.status === "active";
  const isDeviceInactive = primaryDevice?.status === "inactive";

  return (
    <div className="status-card">
      <div
        className={`status-indicator-dot ${
          loading
            ? "status-unknown"
            : isDeviceActive
            ? "status-online"
            : isDeviceInactive
            ? "status-offline"
            : "status-unknown"
        }`}
      />
      <div className="status-details">
        <div className="status-label">Hardware Device Status</div>
        <div className="status-value">
          {loading ? (
            "Checking device status..."
          ) : primaryDevice ? (
            <>
              {isDeviceActive ? (
                <CheckCircle2 size={16} className="icon-emerald" />
              ) : (
                <Clock size={16} className="icon-amber" />
              )}
              <span>
                {primaryDevice.device_id} ({primaryDevice.status})
              </span>
            </>
          ) : (
            <>
              <AlertCircle size={16} className="icon-dim" />
              <span>FRDM-RW612 Not Connected</span>
            </>
          )}
        </div>
        <div className="status-meta">
          {primaryDevice?.last_seen ? (
            `Last seen: ${new Date(primaryDevice.last_seen).toLocaleString()} (${devices.length} registered)`
          ) : error ? (
            `Device API error: ${error}`
          ) : (
            "Hardware awaiting deployment / No telemetry received"
          )}
        </div>
      </div>
      <Cpu size={22} className="brand-icon" />
    </div>
  );
};
