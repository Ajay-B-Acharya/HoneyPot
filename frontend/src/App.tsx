import React, { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { AlertCircle } from "lucide-react";
import {
  fetchHealth,
  fetchDashboardStats,
  fetchDeviceStatuses,
  fetchSecurityEvents,
  fetchRequestLogs,
  fetchIPProfiles,
  fetchDeviceMemoryStats,
  fetchObservations,
} from "./services/api";
import {
  HealthResponse,
  DashboardStats,
  DeviceStatusResponse,
  SecurityEvent,
  RequestLog,
  IPProfile,
  DeviceMemoryStats,
  EdgeObservation,
} from "./types/api";
import { Sidebar, NavSection } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { BackendStatus } from "./components/BackendStatus";
import { DeviceStatusCard } from "./components/DeviceStatusCard";
import { StatsOverview } from "./components/StatsOverview";
import { TrafficOverviewChart } from "./components/TrafficOverviewChart";
import { AttackAnalysisCard } from "./components/AttackAnalysisCard";
import { MemoryDiagnosticsCard } from "./components/MemoryDiagnosticsCard";
import { SecurityEventsTable } from "./components/SecurityEventsTable";
import { RequestLogsTable } from "./components/RequestLogsTable";
import { IPProfilesTable } from "./components/IPProfilesTable";
import { ObservationsTable } from "./components/ObservationsTable";
import { TestingPanel } from "./components/TestingPanel";
import { ScrollProgressBar, BackToTop } from "./components/ScrollUtils";

export const App: React.FC = () => {
  const [activeSection, setActiveSection] = useState<NavSection>("overview");
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>("");

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [deviceData, setDeviceData] = useState<DeviceStatusResponse | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [logs, setLogs] = useState<RequestLog[]>([]);
  const [ipProfiles, setIpProfiles] = useState<IPProfile[]>([]);
  const [observations, setObservations] = useState<EdgeObservation[]>([]);
  const [memoryStats, setMemoryStats] = useState<DeviceMemoryStats | null>(null);

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

      const [
        statsRes,
        devicesRes,
        eventsRes,
        logsRes,
        profilesRes,
        memoryRes,
        obsRes,
      ] = await Promise.allSettled([
        fetchDashboardStats(),
        fetchDeviceStatuses(),
        fetchSecurityEvents({ limit: 50 }),
        fetchRequestLogs({ limit: 50 }),
        fetchIPProfiles({ limit: 50 }),
        fetchDeviceMemoryStats(),
        fetchObservations(50),
      ]);

      if (statsRes.status === "fulfilled") setStats(statsRes.value);
      if (devicesRes.status === "fulfilled") setDeviceData(devicesRes.value);
      if (eventsRes.status === "fulfilled") setEvents(eventsRes.value.items);
      if (logsRes.status === "fulfilled") setLogs(logsRes.value.items);
      if (profilesRes.status === "fulfilled") setIpProfiles(profilesRes.value.items);
      if (memoryRes.status === "fulfilled") setMemoryStats(memoryRes.value);
      if (obsRes.status === "fulfilled") setObservations(obsRes.value);

      setLastRefresh(new Date());
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred");
    } finally {
      setLoading(false);
      setRefreshing(false);
      isFetchingRef.current = false;
    }
  }, []);

  useEffect(() => {
    loadDashboardData(true);
  }, [loadDashboardData]);

  useEffect(() => {
    if (!autoRefresh) return;
    const intervalId = setInterval(() => {
      loadDashboardData(false);
    }, 5000);
    return () => clearInterval(intervalId);
  }, [autoRefresh, loadDashboardData]);

  const q = searchQuery.trim().toLowerCase();

  const filteredEvents = useMemo(() => {
    if (!q) return events;
    return events.filter(
      (e) =>
        (e.source_ip ?? "").toLowerCase().includes(q) ||
        e.event_type.toLowerCase().includes(q) ||
        e.description.toLowerCase().includes(q) ||
        String(e.metadata?.observation_id ?? "").toLowerCase().includes(q) ||
        String(e.metadata?.endpoint ?? "").toLowerCase().includes(q)
    );
  }, [events, q]);

  const filteredLogs = useMemo(() => {
    if (!q) return logs;
    return logs.filter(
      (l) =>
        (l.source_ip ?? "").toLowerCase().includes(q) ||
        l.endpoint.toLowerCase().includes(q) ||
        l.method.toLowerCase().includes(q)
    );
  }, [logs, q]);

  const filteredProfiles = useMemo(() => {
    if (!q) return ipProfiles;
    return ipProfiles.filter((p) => p.ip_address.toLowerCase().includes(q));
  }, [ipProfiles, q]);

  const filteredObservations = useMemo(() => {
    if (!q) return observations;
    return observations.filter(
      (o) =>
        o.source_ip.toLowerCase().includes(q) ||
        o.observation_id.toLowerCase().includes(q) ||
        (o.endpoint ?? "").toLowerCase().includes(q)
    );
  }, [observations, q]);

  const criticalCount = stats?.events_by_severity?.critical ?? 0;

  return (
    <div className={`nids-shell ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
      <ScrollProgressBar />
      <BackToTop />

      <Sidebar
        activeSection={activeSection}
        onSelectSection={setActiveSection}
        collapsed={sidebarCollapsed}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
        health={health}
        deviceData={deviceData}
      />

      <div className="nids-main">
        <TopBar
          collapsed={sidebarCollapsed}
          onToggleCollapse={() => setSidebarCollapsed((c) => !c)}
          onOpenMobileMenu={() => setMobileMenuOpen(true)}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          criticalCount={criticalCount}
          refreshing={refreshing}
          onRefresh={() => loadDashboardData(false)}
          autoRefresh={autoRefresh}
          onToggleAutoRefresh={setAutoRefresh}
          onOpenEvents={() => setActiveSection("events")}
          onOpenSettings={() => setActiveSection("settings")}
        />

        <main className="nids-content">
          <div className="page-heading-row">
            <div>
              <h1 className="page-title">
                IoT Honeypot <span className="page-title-serif">Monitor</span>
              </h1>
              <p className="page-subtitle">
                NXP FRDM-RW612 Embedded Network Intrusion Detection &amp; Edge Correlation
              </p>
            </div>
          </div>

          {error && (
            <div className="error-banner" role="alert">
              <AlertCircle size={18} />
              <span>
                Backend connection offline: {error}. Verify FastAPI is running on 127.0.0.1:8000.
              </span>
            </div>
          )}

          {activeSection === "overview" && (
            <>
              <StatsOverview
                stats={stats}
                ipProfiles={ipProfiles}
                deviceData={deviceData}
                loading={loading}
              />

              <div className="charts-grid">
                <TrafficOverviewChart logs={filteredLogs} events={filteredEvents} loading={loading} />
                <AttackAnalysisCard events={filteredEvents} stats={stats} loading={loading} />
              </div>

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

              <SecurityEventsTable
                events={filteredEvents.slice(0, 10)}
                loading={loading}
                error={error}
                onViewAll={() => setActiveSection("events")}
              />
            </>
          )}

          {activeSection === "events" && (
            <SecurityEventsTable
              events={filteredEvents}
              loading={loading}
              error={error}
            />
          )}

          {activeSection === "traffic" && (
            <>
              <TrafficOverviewChart logs={filteredLogs} events={filteredEvents} loading={loading} />
              <div style={{ marginTop: "1.5rem" }}>
                <RequestLogsTable logs={filteredLogs} loading={loading} error={error} />
              </div>
            </>
          )}

          {activeSection === "analysis" && (
            <>
              <div className="charts-grid">
                <AttackAnalysisCard events={filteredEvents} stats={stats} loading={loading} />
                <MemoryDiagnosticsCard stats={memoryStats} loading={loading} />
              </div>
              <div style={{ marginTop: "1.5rem" }}>
                <ObservationsTable
                  observations={filteredObservations}
                  loading={loading}
                  error={error}
                />
              </div>
            </>
          )}

          {activeSection === "profiles" && (
            <IPProfilesTable
              profiles={filteredProfiles}
              loading={loading}
              error={error}
            />
          )}

          {activeSection === "observations" && (
            <ObservationsTable
              observations={filteredObservations}
              loading={loading}
              error={error}
            />
          )}

          {activeSection === "device" && (
            <>
              <div className="status-bar-grid">
                <DeviceStatusCard
                  deviceData={deviceData}
                  loading={loading}
                  error={error}
                />
                <BackendStatus
                  health={health}
                  loading={loading}
                  error={error}
                  lastRefresh={lastRefresh}
                />
              </div>
              <MemoryDiagnosticsCard stats={memoryStats} loading={loading} />
            </>
          )}

          {activeSection === "settings" && (
            <TestingPanel
              onActionComplete={() => loadDashboardData(false)}
              disabled={loading || !health}
            />
          )}
        </main>
      </div>
    </div>
  );
};

export default App;
