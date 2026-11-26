import React from "react";
import {
  Shield,
  LayoutDashboard,
  ShieldAlert,
  Activity,
  PieChart,
  Users,
  Radio,
  Cpu,
  Settings,
  X,
} from "lucide-react";
import { DeviceStatusResponse, HealthResponse } from "../types/api";

export type NavSection =
  | "overview"
  | "events"
  | "traffic"
  | "analysis"
  | "profiles"
  | "observations"
  | "device"
  | "settings";

interface SidebarProps {
  activeSection: NavSection;
  onSelectSection: (section: NavSection) => void;
  collapsed: boolean;
  mobileOpen: boolean;
  onCloseMobile: () => void;
  health: HealthResponse | null;
  deviceData: DeviceStatusResponse | null;
}

const NAV_ITEMS: { id: NavSection; label: string; icon: React.ComponentType<{ size?: number }> }[] = [
  { id: "overview", label: "Dashboard", icon: LayoutDashboard },
  { id: "events", label: "Security Events", icon: ShieldAlert },
  { id: "traffic", label: "Traffic Monitor", icon: Activity },
  { id: "analysis", label: "Attack Analysis", icon: PieChart },
  { id: "profiles", label: "IP Profiles", icon: Users },
  { id: "observations", label: "Observations", icon: Radio },
  { id: "device", label: "Device Status", icon: Cpu },
  { id: "settings", label: "System / Settings", icon: Settings },
];

export const Sidebar: React.FC<SidebarProps> = ({
  activeSection,
  onSelectSection,
  collapsed,
  mobileOpen,
  onCloseMobile,
  health,
  deviceData,
}) => {
  const primaryDevice =
    deviceData?.devices.find((d) => d.device_id === "rw612-security-01") ??
    deviceData?.devices[0] ??
    null;

  const devStatus = primaryDevice?.status ?? "not_registered";
  const devColor =
    devStatus === "online" || devStatus === "active"
      ? "#10b981"
      : devStatus === "connection_unstable"
      ? "#f59e0b"
      : devStatus === "offline" || devStatus === "inactive"
      ? "#ef4444"
      : "#64748b";

  const devLabel =
    devStatus === "online" || devStatus === "active"
      ? "ONLINE"
      : devStatus === "connection_unstable"
      ? "UNSTABLE"
      : devStatus === "offline" || devStatus === "inactive"
      ? "OFFLINE"
      : "NOT REGISTERED";

  const backendOk = health?.status === "ok";

  return (
    <>
      {mobileOpen && (
        <div
          className="sidebar-backdrop"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}
      <aside
        className={`nids-sidebar ${collapsed ? "collapsed" : ""} ${
          mobileOpen ? "mobile-open" : ""
        }`}
        aria-label="Primary Navigation"
      >
        <div className="sidebar-brand">
          <div className="sidebar-brand-left">
            <div className="sidebar-logo-box">
              <Shield size={20} />
            </div>
            {!collapsed && (
              <div className="sidebar-brand-text">
                <div className="sidebar-brand-title">NIDS Monitor</div>
                <div className="sidebar-brand-sub">FRDM-RW612 Edge</div>
              </div>
            )}
          </div>
          <button
            type="button"
            className="sidebar-mobile-close"
            onClick={onCloseMobile}
            aria-label="Close navigation menu"
          >
            <X size={18} />
          </button>
        </div>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeSection === item.id;
            return (
              <button
                key={item.id}
                type="button"
                className={`sidebar-nav-item ${isActive ? "active" : ""}`}
                onClick={() => {
                  onSelectSection(item.id);
                  onCloseMobile();
                }}
                title={collapsed ? item.label : undefined}
                aria-current={isActive ? "page" : undefined}
              >
                <Icon size={17} />
                {!collapsed && <span>{item.label}</span>}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          {!collapsed ? (
            <>
              <div className="sidebar-status-row">
                <span className="sidebar-status-label">System</span>
                <span className="sidebar-status-val">
                  <span
                    className="status-dot-sm"
                    style={{ backgroundColor: backendOk ? "#10b981" : "#ef4444" }}
                  />
                  {backendOk ? "Operational" : "Degraded"}
                </span>
              </div>
              <div className="sidebar-status-row">
                <span className="sidebar-status-label">Backend API</span>
                <span className="sidebar-status-val">
                  <span
                    className="status-dot-sm"
                    style={{ backgroundColor: backendOk ? "#10b981" : "#ef4444" }}
                  />
                  {backendOk ? "Connected" : "Offline"}
                </span>
              </div>
              <div className="sidebar-status-row">
                <span className="sidebar-status-label">Hardware</span>
                <span className="sidebar-status-val">
                  <span
                    className="status-dot-sm"
                    style={{ backgroundColor: devColor }}
                  />
                  {devLabel}
                </span>
              </div>
              <div className="sidebar-version">IoT Honeypot v1.0.0</div>
            </>
          ) : (
            <div className="sidebar-collapsed-dots" title={`Backend: ${backendOk ? "Connected" : "Offline"} | Hardware: ${devLabel}`}>
              <span
                className="status-dot-sm"
                style={{ backgroundColor: backendOk ? "#10b981" : "#ef4444" }}
              />
              <span
                className="status-dot-sm"
                style={{ backgroundColor: devColor }}
              />
            </div>
          )}
        </div>
      </aside>
    </>
  );
};
