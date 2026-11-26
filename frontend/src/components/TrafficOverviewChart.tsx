import React, { useMemo, useState } from "react";
import { Activity } from "lucide-react";
import { RequestLog, SecurityEvent } from "../types/api";

interface TrafficOverviewChartProps {
  logs: RequestLog[];
  events: SecurityEvent[];
  loading: boolean;
}

type TimeRange = "24h" | "7d" | "30d";

export const TrafficOverviewChart: React.FC<TrafficOverviewChartProps> = ({
  logs,
  events,
  loading,
}) => {
  const [range, setRange] = useState<TimeRange>("24h");

  const buckets = useMemo(() => {
    const slotCount = range === "24h" ? 12 : range === "7d" ? 7 : 10;
    const now = Date.now();
    const spanMs =
      range === "24h"
        ? 24 * 3600 * 1000
        : range === "7d"
        ? 7 * 24 * 3600 * 1000
        : 30 * 24 * 3600 * 1000;
    const stepMs = spanMs / slotCount;
    const startMs = now - spanMs;

    const data = Array.from({ length: slotCount }, (_, idx) => {
      const t = new Date(startMs + (idx + 1) * stepMs);
      const label =
        range === "24h"
          ? `${t.getHours().toString().padStart(2, "0")}:00`
          : `${t.getMonth() + 1}/${t.getDate()}`;
      return { label, normal: 0, suspicious: 0, malicious: 0 };
    });

    for (const log of logs) {
      const ts = new Date(log.timestamp).getTime();
      if (Number.isNaN(ts) || ts < startMs) continue;
      const idx = Math.min(
        slotCount - 1,
        Math.max(0, Math.floor((ts - startMs) / stepMs))
      );
      if (log.classification === "normal") {
        data[idx].normal += 1;
      } else if (log.classification === "unusual") {
        data[idx].suspicious += 1;
      } else {
        data[idx].malicious += 1;
      }
    }

    for (const evt of events) {
      const ts = new Date(evt.timestamp).getTime();
      if (Number.isNaN(ts) || ts < startMs) continue;
      const idx = Math.min(
        slotCount - 1,
        Math.max(0, Math.floor((ts - startMs) / stepMs))
      );
      if (evt.severity === "critical") {
        data[idx].malicious += 1;
      } else if (evt.severity === "warning") {
        data[idx].suspicious += 1;
      }
    }

    return data;
  }, [logs, events, range]);

  const maxY = Math.max(
    4,
    ...buckets.map((b) => Math.max(b.normal, b.suspicious, b.malicious))
  );

  const width = 640;
  const height = 210;
  const padL = 34;
  const padR = 14;
  const padT = 14;
  const padB = 28;
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;

  const toPoints = (key: "normal" | "suspicious" | "malicious") =>
    buckets
      .map((b, i) => {
        const x = padL + (buckets.length > 1 ? (i / (buckets.length - 1)) * plotW : plotW / 2);
        const y = padT + plotH - (b[key] / maxY) * plotH;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");

  const toArea = (key: "normal" | "suspicious" | "malicious") => {
    const pts = toPoints(key);
    const firstX = padL.toFixed(1);
    const lastX = (padL + plotW).toFixed(1);
    const baseY = (padT + plotH).toFixed(1);
    return `M ${firstX},${baseY} L ${pts.split(" ").join(" L ")} L ${lastX},${baseY} Z`;
  };

  return (
    <div className="panel chart-panel">
      <div className="panel-header">
        <div className="panel-title">
          <Activity size={18} className="icon-cyan" />
          <span>Traffic Overview</span>
        </div>

        <div className="chart-controls">
          <div className="chart-legend">
            <span className="legend-item">
              <span className="legend-dot" style={{ background: "var(--accent-emerald)" }} />
              Normal
            </span>
            <span className="legend-item">
              <span className="legend-dot" style={{ background: "var(--accent-amber)" }} />
              Suspicious
            </span>
            <span className="legend-item">
              <span className="legend-dot" style={{ background: "var(--accent-rose)" }} />
              Malicious
            </span>
          </div>

          <select
            className="chart-range-select"
            value={range}
            onChange={(e) => setRange(e.target.value as TimeRange)}
            aria-label="Traffic time filter"
          >
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
        </div>
      </div>

      <div className="chart-body">
        {loading ? (
          <div className="loading-state">Loading traffic telemetry...</div>
        ) : (
          <svg
            viewBox={`0 0 ${width} ${height}`}
            className="traffic-svg"
            role="img"
            aria-label="Traffic trend chart showing normal, suspicious, and malicious requests"
          >
            {[0, 0.25, 0.5, 0.75, 1].map((frac, idx) => {
              const y = padT + plotH * (1 - frac);
              const val = Math.round(maxY * frac);
              return (
                <g key={idx}>
                  <line
                    x1={padL}
                    y1={y}
                    x2={width - padR}
                    y2={y}
                    stroke="var(--border-color)"
                    strokeDasharray="3 3"
                    strokeWidth="1"
                  />
                  <text
                    x={padL - 6}
                    y={y + 4}
                    textAnchor="end"
                    fontSize="10"
                    fill="var(--text-dim)"
                  >
                    {val}
                  </text>
                </g>
              );
            })}

            <path d={toArea("normal")} fill="var(--accent-emerald-bg)" />
            <path d={toArea("malicious")} fill="var(--accent-rose-bg)" />

            <polyline
              fill="none"
              stroke="var(--accent-emerald)"
              strokeWidth="2"
              points={toPoints("normal")}
            />
            <polyline
              fill="none"
              stroke="var(--accent-amber)"
              strokeWidth="2"
              points={toPoints("suspicious")}
            />
            <polyline
              fill="none"
              stroke="var(--accent-rose)"
              strokeWidth="2"
              points={toPoints("malicious")}
            />

            {buckets.map((b, i) => {
              if (buckets.length > 8 && i % 2 !== 0 && i !== buckets.length - 1) return null;
              const x = padL + (buckets.length > 1 ? (i / (buckets.length - 1)) * plotW : plotW / 2);
              return (
                <text
                  key={i}
                  x={x}
                  y={height - 6}
                  textAnchor="middle"
                  fontSize="10"
                  fill="var(--text-dim)"
                >
                  {b.label}
                </text>
              );
            })}
          </svg>
        )}
      </div>
    </div>
  );
};
