import React, { useMemo } from "react";
import { PieChart } from "lucide-react";
import { DashboardStats, SecurityEvent } from "../types/api";

interface AttackAnalysisCardProps {
  events: SecurityEvent[];
  stats: DashboardStats | null;
  loading: boolean;
}

const PALETTE = [
  "var(--accent-rose)",
  "var(--accent-amber)",
  "var(--accent-cyan)",
  "var(--accent-emerald)",
  "#94a3b8",
];

export const AttackAnalysisCard: React.FC<AttackAnalysisCardProps> = ({
  events,
  stats,
  loading,
}) => {
  const categories = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const evt of events) {
      const label = evt.event_type || "unknown";
      counts[label] = (counts[label] || 0) + 1;
    }
    const entries = Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
    const total = entries.reduce((acc, [, c]) => acc + c, 0);
    return { entries, total };
  }, [events]);

  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  let offsetAcc = 0;

  return (
    <div className="panel chart-panel">
      <div className="panel-header">
        <div className="panel-title">
          <PieChart size={18} className="icon-amber" />
          <span>Attack Analysis</span>
        </div>
        <span className="panel-subtitle">
          {stats ? `${stats.total_security_events} total` : "Distribution"}
        </span>
      </div>

      <div className="donut-layout">
        {loading ? (
          <div className="loading-state">Analyzing events...</div>
        ) : categories.total === 0 ? (
          <div className="empty-state">No security events recorded yet.</div>
        ) : (
          <>
            <svg viewBox="0 0 140 140" className="donut-svg" role="img" aria-label="Attack event distribution donut chart">
              <circle
                cx="70"
                cy="70"
                r={radius}
                fill="none"
                stroke="var(--border-color)"
                strokeWidth="16"
              />
              {categories.entries.map(([name, count], idx) => {
                const segLen = (count / categories.total) * circumference;
                const dashArray = `${segLen.toFixed(2)} ${(circumference - segLen).toFixed(2)}`;
                const dashOffset = -offsetAcc;
                offsetAcc += segLen;
                return (
                  <circle
                    key={name}
                    cx="70"
                    cy="70"
                    r={radius}
                    fill="none"
                    stroke={PALETTE[idx % PALETTE.length]}
                    strokeWidth="16"
                    strokeDasharray={dashArray}
                    strokeDashoffset={dashOffset}
                    transform="rotate(-90 70 70)"
                  />
                );
              })}
              <text
                x="70"
                y="67"
                textAnchor="middle"
                fontSize="18"
                fontWeight="700"
                fill="var(--text-main)"
              >
                {categories.total}
              </text>
              <text
                x="70"
                y="82"
                textAnchor="middle"
                fontSize="9"
                fill="var(--text-muted)"
              >
                EVENTS
              </text>
            </svg>

            <div className="donut-legend">
              {categories.entries.map(([name, count], idx) => {
                const pct = Math.round((count / categories.total) * 100);
                return (
                  <div key={name} className="donut-legend-row">
                    <span className="legend-item">
                      <span
                        className="legend-dot"
                        style={{ background: PALETTE[idx % PALETTE.length] }}
                      />
                      <span className="mono-cell">{name}</span>
                    </span>
                    <span className="mono-cell">
                      {count} ({pct}%)
                    </span>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </div>
  );
};
