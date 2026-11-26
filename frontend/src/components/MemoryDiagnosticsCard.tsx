import React from "react";
import { DeviceMemoryStats } from "../types/api";
import { Cpu, Database, AlertOctagon, CheckCircle2, ShieldAlert, HardDrive } from "lucide-react";

interface MemoryDiagnosticsCardProps {
  stats: DeviceMemoryStats | null;
  loading: boolean;
}

export const MemoryDiagnosticsCard: React.FC<MemoryDiagnosticsCardProps> = ({
  stats,
  loading,
}) => {
  if (loading && !stats) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg animate-pulse">
        <div className="h-5 bg-slate-800 rounded w-1/3 mb-4"></div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="h-16 bg-slate-800/60 rounded"></div>
          <div className="h-16 bg-slate-800/60 rounded"></div>
          <div className="h-16 bg-slate-800/60 rounded"></div>
          <div className="h-16 bg-slate-800/60 rounded"></div>
        </div>
      </div>
    );
  }

  const s = stats || {
    device_id: "rw612-security-01",
    total_security_bss_bytes: 22528,
    active_profiles: 0,
    max_profiles: 24,
    profile_bytes_used: 0,
    free_heap_bytes: 118784,
    min_ever_free_heap_bytes: 114688,
    pressure_level: "normal",
    pending_offline_events: 0,
    eviction_summary: {
      total_evicted_count: 0,
      evicted_benign_count: 0,
      evicted_suspicious_count: 0,
      aggregate_evicted_requests: 0,
      aggregate_suspicious_requests: 0,
      highest_evicted_threat_score: 0,
      last_evicted_ip: null,
    },
  };

  const getPressureBadge = (level: string) => {
    switch (level) {
      case "critical":
        return (
          <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-red-950/80 text-red-300 border border-red-800/60 flex items-center gap-1.5 animate-pulse">
            <AlertOctagon className="w-3.5 h-3.5 text-red-400" />
            CRITICAL PRESSURE (100%)
          </span>
        );
      case "high":
        return (
          <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-orange-950/80 text-orange-300 border border-orange-800/60 flex items-center gap-1.5">
            <AlertOctagon className="w-3.5 h-3.5 text-orange-400" />
            HIGH PRESSURE (&ge;85%)
          </span>
        );
      case "moderate":
        return (
          <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-amber-950/80 text-amber-300 border border-amber-800/60 flex items-center gap-1.5">
            <AlertOctagon className="w-3.5 h-3.5 text-amber-400" />
            MODERATE (&ge;60%)
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-emerald-950/80 text-emerald-300 border border-emerald-800/60 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            OPTIMAL (NORMAL)
          </span>
        );
    }
  };

  const profileUsagePct = Math.min(
    100,
    Math.round((s.active_profiles / s.max_profiles) * 100)
  );

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5 border-b border-slate-800/70 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              FRDM-RW612 Memory Diagnostics &amp; Threat Preservation
            </h2>
            <p className="text-xs text-slate-400">
              Deterministic Static RAM Limits &bull; Zero Heap Fragmentation &bull; Priority-Based Eviction
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">{getPressureBadge(s.pressure_level)}</div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-5">
        <div className="bg-slate-800/40 border border-slate-800 rounded-lg p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
            <span>Tracked IP Profiles</span>
            <Database className="w-3.5 h-3.5 text-indigo-400" />
          </div>
          <div className="text-xl font-bold text-slate-100">
            {s.active_profiles}{" "}
            <span className="text-xs font-normal text-slate-400">/ {s.max_profiles}</span>
          </div>
          <div className="w-full bg-slate-700/60 rounded-full h-1.5 mt-2">
            <div
              className={`h-1.5 rounded-full transition-all duration-300 ${
                profileUsagePct >= 90
                  ? "bg-red-500"
                  : profileUsagePct >= 60
                  ? "bg-amber-500"
                  : "bg-indigo-500"
              }`}
              style={{ width: `${profileUsagePct}%` }}
            ></div>
          </div>
        </div>

        <div className="bg-slate-800/40 border border-slate-800 rounded-lg p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
            <span>Static BSS Budget</span>
            <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-slate-100">
            {(s.total_security_bss_bytes / 1024).toFixed(1)}{" "}
            <span className="text-xs font-normal text-slate-400">KB</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            BSS usage: {(s.profile_bytes_used / 1024).toFixed(1)} KB active
          </p>
        </div>

        <div className="bg-slate-800/40 border border-slate-800 rounded-lg p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
            <span>FreeRTOS Heap Free</span>
            <Cpu className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold text-emerald-400">
            {(s.free_heap_bytes / 1024).toFixed(1)}{" "}
            <span className="text-xs font-normal text-slate-400">KB</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Watermark: {(s.min_ever_free_heap_bytes / 1024).toFixed(1)} KB min
          </p>
        </div>

        <div className="bg-slate-800/40 border border-slate-800 rounded-lg p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
            <span>Preserved Evictions</span>
            <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-xl font-bold text-purple-300">
            {s.eviction_summary.total_evicted_count}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            {s.eviction_summary.evicted_benign_count} benign &bull;{" "}
            {s.eviction_summary.evicted_suspicious_count} susp
          </p>
        </div>
      </div>

      {s.eviction_summary.total_evicted_count > 0 && (
        <div className="bg-slate-800/25 border border-slate-800/60 rounded-lg p-3 text-xs text-slate-300 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-200">Compressed Historical Telemetry:</span>
            <span>
              {s.eviction_summary.aggregate_evicted_requests} total requests summarized ({s.eviction_summary.aggregate_suspicious_requests} suspicious).
            </span>
          </div>
          <div className="flex items-center gap-3 text-slate-400">
            <span>Peak Evicted Threat: <strong className="text-slate-200">{s.eviction_summary.highest_evicted_threat_score}</strong>/100</span>
            {s.eviction_summary.last_evicted_ip && (
              <span>Last Evicted: <code className="text-slate-200 bg-slate-800 px-1.5 py-0.5 rounded">{s.eviction_summary.last_evicted_ip}</code></span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
