import React, { useMemo, useState, useRef, useCallback } from "react";
import { Activity, ZoomIn, ZoomOut, RotateCcw } from "lucide-react";
import { RequestLog, SecurityEvent } from "../types/api";

interface TrafficOverviewChartProps {
  logs: RequestLog[];
  events: SecurityEvent[];
  loading: boolean;
}

type TimeRange = "15m" | "1h" | "24h" | "7d" | "30d";
type SeriesKey = "normal" | "suspicious" | "malicious";

const RANGE_MS: Record<TimeRange, number> = {
  "15m": 15 * 60 * 1000,
  "1h": 3600 * 1000,
  "24h": 24 * 3600 * 1000,
  "7d": 7 * 24 * 3600 * 1000,
  "30d": 30 * 24 * 3600 * 1000,
};

const MIN_WINDOW_MS = 60 * 1000; // 1 minute minimum zoom window

function parseUtcMs(iso?: string | null): number {
  if (!iso) return Number.NaN;
  const hasTz = /[zZ]|[+-]\d{2}:?\d{2}$/.test(iso);
  return new Date(hasTz ? iso : `${iso}Z`).getTime();
}

function getEffectiveTimeMs(timestamp: string, createdAt?: string | null): number {
  const tsMs = parseUtcMs(timestamp);
  const createdMs = parseUtcMs(createdAt);
  if (Number.isNaN(tsMs)) return createdMs;
  if (!Number.isNaN(createdMs) && Math.abs(createdMs - tsMs) > 3600 * 1000) {
    // Hardware without RTC sends a fixed epoch timestamp; use backend ingestion time
    return createdMs;
  }
  return tsMs;
}

function formatBucketLabel(ms: number, spanMs: number): string {
  const d = new Date(ms);
  if (spanMs <= 2 * 3600 * 1000) {
    return `${d.getHours().toString().padStart(2, "0")}:${d
      .getMinutes()
      .toString()
      .padStart(2, "0")}`;
  }
  if (spanMs <= 48 * 3600 * 1000) {
    return `${d.getHours().toString().padStart(2, "0")}:${d
      .getMinutes()
      .toString()
      .padStart(2, "0")}`;
  }
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

function formatStepDuration(stepMs: number): string {
  if (stepMs < 60 * 1000) return `${Math.max(1, Math.round(stepMs / 1000))}s`;
  if (stepMs < 3600 * 1000) return `${Math.round(stepMs / (60 * 1000))}m`;
  if (stepMs < 24 * 3600 * 1000) return `${(stepMs / (3600 * 1000)).toFixed(1).replace(/\.0$/, "")}h`;
  return `${(stepMs / (24 * 3600 * 1000)).toFixed(1).replace(/\.0$/, "")}d`;
}

export const TrafficOverviewChart: React.FC<TrafficOverviewChartProps> = ({
  logs,
  events,
  loading,
}) => {
  const [range, setRange] = useState<TimeRange>("24h");
  const [zoomWindow, setZoomWindow] = useState<{ start: number; end: number } | null>(null);
  const [visibleSeries, setVisibleSeries] = useState<Record<SeriesKey, boolean>>({
    normal: true,
    suspicious: true,
    malicious: true,
  });
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const [dragState, setDragState] = useState<{
    startX: number;
    origStart: number;
    origEnd: number;
  } | null>(null);

  const svgRef = useRef<SVGSVGElement | null>(null);

  const baseSpanMs = RANGE_MS[range];
  const nowMs = Date.now();
  const viewStart = zoomWindow ? zoomWindow.start : nowMs - baseSpanMs;
  const viewEnd = zoomWindow ? zoomWindow.end : nowMs;
  const viewSpanMs = Math.max(MIN_WINDOW_MS, viewEnd - viewStart);
  const zoomFactor = baseSpanMs / viewSpanMs;
  const isZoomed = zoomWindow !== null && zoomFactor > 1.05;

  const handleRangeChange = (newRange: TimeRange) => {
    setRange(newRange);
    setZoomWindow(null);
    setHoverIndex(null);
  };

  const applyZoom = useCallback(
    (scale: number, anchorRatio = 0.5) => {
      const currentStart = zoomWindow ? zoomWindow.start : Date.now() - baseSpanMs;
      const currentEnd = zoomWindow ? zoomWindow.end : Date.now();
      const currentSpan = currentEnd - currentStart;
      const newSpan = Math.min(baseSpanMs, Math.max(MIN_WINDOW_MS, currentSpan * scale));

      if (newSpan >= baseSpanMs * 0.98) {
        setZoomWindow(null);
        return;
      }

      const anchorMs = currentStart + currentSpan * anchorRatio;
      let newStart = anchorMs - newSpan * anchorRatio;
      let newEnd = newStart + newSpan;

      const maxEnd = Date.now();
      const minStart = maxEnd - baseSpanMs;
      if (newEnd > maxEnd) {
        newEnd = maxEnd;
        newStart = newEnd - newSpan;
      }
      if (newStart < minStart) {
        newStart = minStart;
        newEnd = newStart + newSpan;
      }
      setZoomWindow({ start: newStart, end: newEnd });
    },
    [zoomWindow, baseSpanMs]
  );

  const toggleSeries = (key: SeriesKey) => {
    setVisibleSeries((prev) => {
      const activeCount = Object.values(prev).filter(Boolean).length;
      if (prev[key] && activeCount === 1) return prev; // Keep at least one series visible
      return { ...prev, [key]: !prev[key] };
    });
  };

  const buckets = useMemo(() => {
    const slotCount = 16;
    const stepMs = viewSpanMs / slotCount;

    const data = Array.from({ length: slotCount }, (_, idx) => {
      const bucketStart = viewStart + idx * stepMs;
      const bucketEnd = bucketStart + stepMs;
      return {
        label: formatBucketLabel(bucketEnd, viewSpanMs),
        rangeLabel: `${new Date(bucketStart).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        })} – ${new Date(bucketEnd).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        })}`,
        normal: 0,
        suspicious: 0,
        malicious: 0,
      };
    });

    for (const log of logs) {
      const ts = getEffectiveTimeMs(log.timestamp, log.created_at);
      if (Number.isNaN(ts) || ts < viewStart || ts > viewEnd) continue;
      const idx = Math.min(
        slotCount - 1,
        Math.max(0, Math.floor((ts - viewStart) / stepMs))
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
      const ts = getEffectiveTimeMs(evt.timestamp, evt.created_at);
      if (Number.isNaN(ts) || ts < viewStart || ts > viewEnd) continue;
      const idx = Math.min(
        slotCount - 1,
        Math.max(0, Math.floor((ts - viewStart) / stepMs))
      );
      if (evt.severity === "critical") {
        data[idx].malicious += 1;
      } else if (evt.severity === "warning") {
        data[idx].suspicious += 1;
      }
    }

    return data;
  }, [logs, events, viewStart, viewEnd, viewSpanMs]);

  const totals = useMemo(() => {
    return buckets.reduce(
      (acc, b) => ({
        normal: acc.normal + b.normal,
        suspicious: acc.suspicious + b.suspicious,
        malicious: acc.malicious + b.malicious,
      }),
      { normal: 0, suspicious: 0, malicious: 0 }
    );
  }, [buckets]);

  const maxY = Math.max(
    4,
    ...buckets.map((b) =>
      Math.max(
        visibleSeries.normal ? b.normal : 0,
        visibleSeries.suspicious ? b.suspicious : 0,
        visibleSeries.malicious ? b.malicious : 0
      )
    )
  );

  const width = 640;
  const height = 230;
  const padL = 42;
  const padR = 16;
  const padT = 16;
  const padB = 34;
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;

  const getX = (i: number) =>
    padL + (buckets.length > 1 ? (i / (buckets.length - 1)) * plotW : plotW / 2);
  const getY = (val: number) => padT + plotH - (val / maxY) * plotH;

  const toPoints = (key: SeriesKey) =>
    buckets.map((b, i) => `${getX(i).toFixed(1)},${getY(b[key]).toFixed(1)}`).join(" ");

  const toArea = (key: SeriesKey) => {
    const pts = toPoints(key);
    const firstX = padL.toFixed(1);
    const lastX = (padL + plotW).toFixed(1);
    const baseY = (padT + plotH).toFixed(1);
    return `M ${firstX},${baseY} L ${pts.split(" ").join(" L ")} L ${lastX},${baseY} Z`;
  };

  const handleWheel = (e: React.WheelEvent<SVGSVGElement>) => {
    e.preventDefault();
    if (!svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const relX = (e.clientX - rect.left) / rect.width;
    const anchorRatio = Math.min(1, Math.max(0, (relX * width - padL) / plotW));
    const scale = e.deltaY < 0 ? 0.65 : 1.5;
    applyZoom(scale, anchorRatio);
  };

  const handleMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!isZoomed) return;
    setDragState({
      startX: e.clientX,
      origStart: viewStart,
      origEnd: viewEnd,
    });
  };

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();

    if (dragState) {
      const dxPx = e.clientX - dragState.startX;
      const dxMs = (dxPx / rect.width) * (dragState.origEnd - dragState.origStart);
      const span = dragState.origEnd - dragState.origStart;
      const maxEnd = Date.now();
      const minStart = maxEnd - baseSpanMs;
      let newStart = dragState.origStart - dxMs;
      let newEnd = newStart + span;
      if (newStart < minStart) {
        newStart = minStart;
        newEnd = newStart + span;
      }
      if (newEnd > maxEnd) {
        newEnd = maxEnd;
        newStart = newEnd - span;
      }
      setZoomWindow({ start: newStart, end: newEnd });
      return;
    }

    const svgX = ((e.clientX - rect.left) / rect.width) * width;
    const clampedX = Math.min(padL + plotW, Math.max(padL, svgX));
    const ratio = (clampedX - padL) / plotW;
    const idx = Math.round(ratio * (buckets.length - 1));
    setHoverIndex(Math.min(buckets.length - 1, Math.max(0, idx)));
  };

  const handleMouseUpOrLeave = () => {
    setDragState(null);
  };

  const hoveredBucket = hoverIndex !== null ? buckets[hoverIndex] : null;
  const stepMs = viewSpanMs / buckets.length;

  return (
    <div className="panel chart-panel">
      <div className="panel-header">
        <div>
          <div className="panel-title">
            <Activity size={18} className="icon-cyan" />
            <span>Traffic &amp; Threat Timeline</span>
          </div>
          <div className="chart-submeta">
            <span>
              Window: {totals.normal} normal · {totals.suspicious} suspicious · {totals.malicious} malicious
            </span>
            <span>·</span>
            <span>
              {formatStepDuration(stepMs)}/bucket{isZoomed ? ` · ${zoomFactor.toFixed(1)}x zoom` : ""}
            </span>
          </div>
        </div>

        <div className="chart-controls">
          <div className="chart-legend" role="group" aria-label="Toggle traffic series">
            {(
              [
                { key: "normal", label: "Normal", color: "var(--accent-emerald)" },
                { key: "suspicious", label: "Suspicious", color: "var(--accent-amber)" },
                { key: "malicious", label: "Malicious", color: "var(--accent-rose)" },
              ] as const
            ).map((s) => (
              <button
                key={s.key}
                type="button"
                className={`legend-toggle ${visibleSeries[s.key] ? "active" : "muted"}`}
                onClick={() => toggleSeries(s.key)}
                title={`Toggle ${s.label} series`}
              >
                <span className="legend-dot" style={{ background: s.color }} />
                {s.label}
              </button>
            ))}
          </div>

          <div className="chart-zoom-group">
            <button
              type="button"
              className="icon-btn chart-zoom-btn"
              onClick={() => applyZoom(0.6, 0.5)}
              title="Zoom in (or scroll up)"
              aria-label="Zoom in chart"
            >
              <ZoomIn size={14} />
            </button>
            <button
              type="button"
              className="icon-btn chart-zoom-btn"
              onClick={() => applyZoom(1.6, 0.5)}
              disabled={!isZoomed}
              title="Zoom out (or scroll down)"
              aria-label="Zoom out chart"
            >
              <ZoomOut size={14} />
            </button>
            {isZoomed && (
              <button
                type="button"
                className="icon-btn chart-zoom-btn"
                onClick={() => setZoomWindow(null)}
                title="Reset zoom"
                aria-label="Reset chart zoom"
              >
                <RotateCcw size={14} />
              </button>
            )}
          </div>

          <select
            className="chart-range-select"
            value={range}
            onChange={(e) => handleRangeChange(e.target.value as TimeRange)}
            aria-label="Traffic time filter"
          >
            <option value="15m">Last 15 Min</option>
            <option value="1h">Last 1 Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
        </div>
      </div>

      <div className="chart-body" style={{ position: "relative" }}>
        {loading ? (
          <div className="loading-state">Loading traffic telemetry...</div>
        ) : (
          <>
            <svg
              ref={svgRef}
              viewBox={`0 0 ${width} ${height}`}
              className="traffic-svg"
              style={{ cursor: isZoomed ? (dragState ? "grabbing" : "grab") : "crosshair" }}
              onWheel={handleWheel}
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUpOrLeave}
              onMouseLeave={() => {
                handleMouseUpOrLeave();
                setHoverIndex(null);
              }}
              role="img"
              aria-label="Zoomable traffic trend chart showing normal, suspicious, and malicious requests"
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

              <text
                x={12}
                y={padT + plotH / 2}
                textAnchor="middle"
                fontSize="9"
                fill="var(--text-muted)"
                transform={`rotate(-90 12 ${padT + plotH / 2})`}
              >
                Count
              </text>

              {visibleSeries.normal && (
                <path d={toArea("normal")} fill="var(--accent-emerald-bg)" />
              )}
              {visibleSeries.malicious && (
                <path d={toArea("malicious")} fill="var(--accent-rose-bg)" />
              )}

              {visibleSeries.normal && (
                <polyline
                  fill="none"
                  stroke="var(--accent-emerald)"
                  strokeWidth="2"
                  points={toPoints("normal")}
                />
              )}
              {visibleSeries.suspicious && (
                <polyline
                  fill="none"
                  stroke="var(--accent-amber)"
                  strokeWidth="2"
                  points={toPoints("suspicious")}
                />
              )}
              {visibleSeries.malicious && (
                <polyline
                  fill="none"
                  stroke="var(--accent-rose)"
                  strokeWidth="2"
                  points={toPoints("malicious")}
                />
              )}

              {hoverIndex !== null && (
                <line
                  x1={getX(hoverIndex)}
                  y1={padT}
                  x2={getX(hoverIndex)}
                  y2={padT + plotH}
                  stroke="var(--text-muted)"
                  strokeDasharray="2 2"
                  strokeWidth="1"
                />
              )}

              {buckets.map((b, i) => {
                const x = getX(i);
                const isHovered = hoverIndex === i;
                return (
                  <g key={i}>
                    {visibleSeries.normal && (b.normal > 0 || isHovered) && (
                      <circle
                        cx={x}
                        cy={getY(b.normal)}
                        r={isHovered ? 4 : 2.2}
                        fill="var(--accent-emerald)"
                      />
                    )}
                    {visibleSeries.suspicious && (b.suspicious > 0 || isHovered) && (
                      <circle
                        cx={x}
                        cy={getY(b.suspicious)}
                        r={isHovered ? 4 : 2.2}
                        fill="var(--accent-amber)"
                      />
                    )}
                    {visibleSeries.malicious && (b.malicious > 0 || isHovered) && (
                      <circle
                        cx={x}
                        cy={getY(b.malicious)}
                        r={isHovered ? 4 : 2.2}
                        fill="var(--accent-rose)"
                      />
                    )}
                  </g>
                );
              })}

              {buckets.map((b, i) => {
                if (i % 3 !== 0 && i !== buckets.length - 1) return null;
                return (
                  <text
                    key={i}
                    x={getX(i)}
                    y={height - 10}
                    textAnchor="middle"
                    fontSize="10"
                    fill="var(--text-dim)"
                  >
                    {b.label}
                  </text>
                );
              })}
            </svg>

            {hoveredBucket && hoverIndex !== null && (
              <div
                className="chart-tooltip"
                style={{
                  left: `${Math.min(72, Math.max(8, (getX(hoverIndex) / width) * 100))}%`,
                }}
              >
                <div className="chart-tooltip-time">{hoveredBucket.rangeLabel}</div>
                {visibleSeries.normal && (
                  <div className="chart-tooltip-row">
                    <span className="legend-dot" style={{ background: "var(--accent-emerald)" }} />
                    <span>Normal:</span>
                    <strong>{hoveredBucket.normal}</strong>
                  </div>
                )}
                {visibleSeries.suspicious && (
                  <div className="chart-tooltip-row">
                    <span className="legend-dot" style={{ background: "var(--accent-amber)" }} />
                    <span>Suspicious:</span>
                    <strong>{hoveredBucket.suspicious}</strong>
                  </div>
                )}
                {visibleSeries.malicious && (
                  <div className="chart-tooltip-row">
                    <span className="legend-dot" style={{ background: "var(--accent-rose)" }} />
                    <span>Malicious:</span>
                    <strong>{hoveredBucket.malicious}</strong>
                  </div>
                )}
              </div>
            )}

            <div className="chart-hint">
              Scroll to zoom · Click legend to toggle series{isZoomed ? " · Drag to pan" : ""}
            </div>
          </>
        )}
      </div>
    </div>
  );
};
