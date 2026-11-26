import React from "react";
import {
  PanelLeftClose,
  PanelLeftOpen,
  Menu,
  Search,
  Bell,
  Settings,
  RefreshCw,
  UserCheck,
} from "lucide-react";
import { ThemeToggle } from "./ThemeToggle";

interface TopBarProps {
  collapsed: boolean;
  onToggleCollapse: () => void;
  onOpenMobileMenu: () => void;
  searchQuery: string;
  onSearchChange: (value: string) => void;
  criticalCount: number;
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
  refreshing,
  onRefresh,
  autoRefresh,
  onToggleAutoRefresh,
  onOpenEvents,
  onOpenSettings,
}) => {
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

        <button
          type="button"
          className="icon-btn notification-btn"
          onClick={onOpenEvents}
          aria-label={`Security notifications (${criticalCount} critical)`}
          title={`${criticalCount} critical alerts`}
        >
          <Bell size={16} />
          {criticalCount > 0 && (
            <span className="notification-badge">
              {criticalCount > 99 ? "99+" : criticalCount}
            </span>
          )}
        </button>

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
