import React, { useState, useRef, useEffect } from "react";
import {
  PanelLeftClose,
  PanelLeftOpen,
  Menu,
  Search,
  Bell,
  Settings,
  RefreshCw,
  UserCheck,
  Trash2,
} from "lucide-react";
import { ThemeToggle } from "./ThemeToggle";
import { SecurityEvent } from "../types/api";

interface TopBarProps {
  collapsed: boolean;
  onToggleCollapse: () => void;
  onOpenMobileMenu: () => void;
  searchQuery: string;
  onSearchChange: (value: string) => void;
  criticalCount: number;
  notifications: SecurityEvent[];
  onDeleteNotification: (eventId: number) => void;
  onClearNotifications: () => void;
  refreshing: boolean;
  onRefresh: () => void;
  autoRefresh: boolean;
  onToggleAutoRefresh: (checked: boolean) => void;
  onOpenEvents: () => void;
  onOpenSettings: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  collapsed,
  onToggleCollapse,
  onOpenMobileMenu,
  searchQuery,
  onSearchChange,
  criticalCount,
  notifications,
  onDeleteNotification,
  onClearNotifications,
  refreshing,
  onRefresh,
  autoRefresh,
  onToggleAutoRefresh,
  onOpenEvents,
  onOpenSettings,
}) => {
  const [notifOpen, setNotifOpen] = useState(false);
  const notifRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setNotifOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const recentNotifications = notifications.slice(0, 8);
  return (
    <header className="nids-topbar">
      <div className="topbar-left">
        <button
          type="button"
          className="icon-btn mobile-menu-btn"
          onClick={onOpenMobileMenu}
          aria-label="Open navigation menu"
        >
          <Menu size={18} />
        </button>

        <button
          type="button"
          className="icon-btn desktop-collapse-btn"
          onClick={onToggleCollapse}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
        </button>

        <div className="topbar-search">
          <Search size={15} className="topbar-search-icon" />
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search IP, endpoint, observation ID..."
            aria-label="Search events, logs, and IP profiles"
          />
        </div>
      </div>

      <div className="topbar-right">
        <label className="auto-refresh-toggle" title="Poll backend every 5 seconds">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => onToggleAutoRefresh(e.target.checked)}
          />
          <span>Auto 5s</span>
        </label>

        <button
          type="button"
          className="icon-btn"
          onClick={onRefresh}
          disabled={refreshing}
          aria-label="Refresh telemetry data"
          title="Refresh telemetry data"
        >
          <RefreshCw
            size={16}
            style={{ animation: refreshing ? "spin 1s linear infinite" : "none" }}
          />
        </button>

        <ThemeToggle />

        <div className="notification-wrapper" ref={notifRef}>
          <button
            type="button"
            className="icon-btn notification-btn"
            onClick={() => setNotifOpen((o) => !o)}
            aria-label={`Security notifications (${criticalCount} critical)`}
            aria-expanded={notifOpen}
            title={`${criticalCount} critical alerts`}
          >
            <Bell size={16} />
            {criticalCount > 0 && (
              <span className="notification-badge">
                {criticalCount > 99 ? "99+" : criticalCount}
              </span>
            )}
          </button>

          {notifOpen && (
            <div className="notification-popover" role="dialog" aria-label="Security notifications">
              <div className="notification-popover-header">
                <span>Notifications ({notifications.length})</span>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                  {notifications.length > 0 && (
                    <button
                      type="button"
                      className="btn-danger-ghost"
                      onClick={() => {
                        onClearNotifications();
                        setNotifOpen(false);
                      }}
                    >
                      Clear All
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn-link"
                    onClick={() => {
                      setNotifOpen(false);
                      onOpenEvents();
                    }}
                  >
                    View All
                  </button>
                </div>
              </div>

              <div className="notification-popover-body">
                {recentNotifications.length === 0 ? (
                  <div className="notification-empty">No active security notifications.</div>
                ) : (
                  recentNotifications.map((evt) => (
                    <div key={evt.id} className="notification-item">
                      <div className="notification-item-content">
                        <div className="notification-item-title">
                          <span className={`badge badge-${evt.severity === "critical" ? "critical" : evt.severity === "warning" ? "warning" : "info"}`}>
                            {evt.severity}
                          </span>
                          <span className="mono-cell">{evt.event_type}</span>
                        </div>
                        <div className="notification-item-desc" title={evt.description}>
                          {evt.description}
                        </div>
                        <div className="notification-item-meta">
                          {evt.source_ip ?? "Unknown IP"} · {new Date(evt.timestamp).toLocaleTimeString()}
                        </div>
                      </div>
                      <button
                        type="button"
                        className="icon-btn"
                        style={{ width: "26px", height: "26px", flexShrink: 0 }}
                        onClick={() => onDeleteNotification(evt.id)}
                        aria-label={`Delete notification ${evt.id}`}
                        title="Delete notification"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        <button
          type="button"
          className="icon-btn"
          onClick={onOpenSettings}
          aria-label="System settings"
          title="System / Settings"
        >
          <Settings size={16} />
        </button>

        <div className="admin-profile-pill" title="Security Administrator">
          <UserCheck size={15} />
          <span className="admin-label">Admin</span>
        </div>
      </div>
    </header>
  );
};
