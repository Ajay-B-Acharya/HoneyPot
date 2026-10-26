import React, { useState, useEffect, useCallback, useRef } from "react";
import { Shield, RefreshCw, AlertCircle } from "lucide-react";
import {
  fetchHealth,
  fetchDashboardStats,
  fetchDeviceStatuses,
  fetchSecurityEvents,
  fetchRequestLogs,
} from "./services/api";
import {
  HealthResponse,
  DashboardStats,
  DeviceStatusResponse,
  SecurityEvent,
  RequestLog,
} from "./types/api";
import { BackendStatus } from "./components/BackendStatus";
import { DeviceStatusCard } from "./components/DeviceStatusCard";
import { StatsOverview } from "./components/StatsOverview";
import { SecurityEventsTable } from "./components/SecurityEventsTable";
import { RequestLogsTable } from "./components/RequestLogsTable";
import { TestingPanel } from "./components/TestingPanel";
import { ThemeToggle } from "./components/ThemeToggle";
import { HeroSection } from "./components/HeroSection";
import { ScrollProgressBar, BackToTop } from "./components/ScrollUtils";

export const App: React.FC = () => {
  // State
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [deviceData, setDeviceData] = useState<DeviceStatusResponse | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [logs, setLogs] = useState<RequestLog[]>([]);

  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);

  const isFetchingRef = useRef<boolean>(false);

  const loadDashboardData = useCallback(async (isInitial = false) => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;

    if (isInitial) {
      setLoading(true);
    } else {
      setRefreshing(true);
    }

    try {
      // 1. Check Backend Health
      let healthRes: HealthResponse | null = null;
      try {
        healthRes = await fetchHealth();
        setHealth(healthRes);
        setError(null);
      } catch (err: any) {
        setHealth(null);
        setError(err.message || "Failed to reach backend server");
        return;
      }

      // 2. Fetch all telemetry concurrently if backend is online
      const [statsRes, devicesRes, eventsRes, logsRes] = await Promise.allSettled([
        fetchDashboardStats(),
        fetchDeviceStatuses(),
        fetchSecurityEvents({ limit: 20 }),
        fetchRequestLogs({ limit: 20 }),
      ]);

      if (statsRes.status === "fulfilled") {
        setStats(statsRes.value);
      }
      if (devicesRes.status === "fulfilled") {
        setDeviceData(devicesRes.value);
      }
      if (eventsRes.status === "fulfilled") {
        setEvents(eventsRes.value.items);
      }
      if (logsRes.status === "fulfilled") {
        setLogs(logsRes.value.items);
      }

      setLastRefresh(new Date());
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred");
    } finally {
      setLoading(false);
      setRefreshing(false);
      isFetchingRef.current = false;
    }
  }, []);

  // Initial load
  useEffect(() => {
    loadDashboardData(true);
  }, [loadDashboardData]);

  // Periodic Auto-refresh (5 seconds)
  useEffect(() => {
    if (!autoRefresh) return;

    const intervalId = setInterval(() => {
      loadDashboardData(false);
    }, 5000);

    return () => {
      clearInterval(intervalId);
    };
  }, [autoRefresh, loadDashboardData]);

  const handleScrollToTesting = () => {
    const el = document.getElementById("testing-panel");
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
    }
  };

  const activeDeviceCount =
    deviceData?.devices.filter((d) => d.status === "active").length ?? 0;

  return (
    <div className="dashboard-container">
      <ScrollProgressBar />
      <BackToTop />

      {/* Top Sticky Header */}
      <header className="dashboard-header">
        <div className="brand-section">
          <Shield size={26} className="brand-icon" />
          <div>
            <div className="brand-title">IoT Honeypot Monitor</div>
            <div className="brand-subtitle">
              Embedded Network Intrusion Detection System • NXP FRDM-RW612
            </div>
          </div>
        </div>

        <div className="header-controls">
          <ThemeToggle />

          <label className="auto-refresh-toggle">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            <span>Auto-refresh (5s)</span>
          </label>

          <button
            className="refresh-btn"
            onClick={() => loadDashboardData(false)}
            disabled={refreshing}
            title="Refresh dashboard data"
          >
            <RefreshCw
              size={14}
              style={{
                animation: refreshing ? "spin 1s linear infinite" : "none",
              }}
            />
            <span>{refreshing ? "Refreshing..." : "Refresh"}</span>
          </button>
        </div>
      </header>

      {/* Hero Section */}
      <HeroSection
        onScrollToTesting={handleScrollToTesting}
        activeDeviceCount={activeDeviceCount}
      />

      {/* Global Connection Error Banner if Backend is Down */}
      {error && (
        <div className="error-banner">
          <AlertCircle size={18} />
          <span>
            Backend connection offline: {error}. Make sure the FastAPI backend is running on 127.0.0.1:8000.
          </span>
        </div>
      )}

      {/* Connection & Hardware Status Bar */}
      <div className="status-bar-grid">
        <BackendStatus
          health={health}
          loading={loading}
          error={error}
          lastRefresh={lastRefresh}
        />
        <DeviceStatusCard
          deviceData={deviceData}
          loading={loading}
          error={error}
        />
      </div>

      {/* Aggregated Statistics Cards */}
      <StatsOverview stats={stats} loading={loading} />

      {/* Main Events & Logs Grid */}
      <div className="main-grid">
        <SecurityEventsTable
          events={events}
          loading={loading}
          error={error}
        />
        <RequestLogsTable
          logs={logs}
          loading={loading}
          error={error}
        />
      </div>

      {/* Real-time Testing & Validation Panel */}
      <TestingPanel
        onActionComplete={() => loadDashboardData(false)}
        disabled={loading || !health}
      />
    </div>
  );
};
