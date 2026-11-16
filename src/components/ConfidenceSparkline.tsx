import { useEffect, useId, useRef, useState } from 'react';
import type { IndicatorConfidenceTrend } from '../utils/confidenceTrend';

interface ConfidenceSparklineProps {
  indicator: string;
  trend?: IndicatorConfidenceTrend;
}

const SVG_WIDTH = 56;
const SVG_HEIGHT = 22;
const PAD_X = 3;
const PAD_Y = 3;

export function ConfidenceSparkline({ indicator, trend }: ConfidenceSparklineProps) {
  const [open, setOpen] = useState(false);
  const [popoverCoords, setPopoverCoords] = useState<{ top: number; left: number } | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const popoverRef = useRef<HTMLDivElement | null>(null);
  const gradientId = useId();

  useEffect(() => {
    if (!open) return;

    function updatePosition() {
      const rect = triggerRef.current?.getBoundingClientRect();
      if (!rect) return;
      const panelWidth = 256;
      const maxLeft = Math.max(12, window.innerWidth - panelWidth - 12);
      const left = Math.min(Math.max(12, rect.left - 40), maxLeft);
      const showBelow = rect.top < 190;
      const top = showBelow ? rect.bottom + 6 : Math.max(12, rect.top - 172);
      setPopoverCoords({ top, left });
    }

    updatePosition();

    function handleClickOutside(e: MouseEvent) {
      const target = e.target as Node | null;
      if (
        triggerRef.current?.contains(target) ||
        popoverRef.current?.contains(target)
      ) {
        return;
      }
      setOpen(false);
    }

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setOpen(false);
      }
    }

    window.addEventListener('mousedown', handleClickOutside);
    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('scroll', updatePosition, true);
    window.addEventListener('resize', updatePosition);
    return () => {
      window.removeEventListener('mousedown', handleClickOutside);
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('scroll', updatePosition, true);
      window.removeEventListener('resize', updatePosition);
    };
  }, [open]);

  if (!trend || trend.points.length === 0) {
    return (
      <span
        data-testid="confidence-sparkline-empty"
        className="font-mono text-xs text-slate-400 dark:text-slate-500"
      >
        —
      </span>
    );
  }

  const points = trend.points;
  const innerW = SVG_WIDTH - PAD_X * 2;
  const innerH = SVG_HEIGHT - PAD_Y * 2;
  const threshold50Y = PAD_Y + innerH * (1 - 50 / 100);

  const coords = points.map((pt, idx) => {
    const x =
      points.length === 1
        ? SVG_WIDTH / 2
        : PAD_X + (idx / Math.max(1, points.length - 1)) * innerW;
    const clampedScore = Math.max(0, Math.min(100, pt.score));
    const y = PAD_Y + innerH * (1 - clampedScore / 100);
    return { x, y, pt };
  });

  const linePath =
    coords.length >= 2
      ? coords
          .map((c, idx) => `${idx === 0 ? 'M' : 'L'}${c.x.toFixed(1)},${c.y.toFixed(1)}`)
          .join(' ')
      : '';

  const areaPath =
    coords.length >= 2
      ? `${linePath} L${coords[coords.length - 1].x.toFixed(1)},${(PAD_Y + innerH).toFixed(1)} L${coords[0].x.toFixed(1)},${(PAD_Y + innerH).toFixed(1)} Z`
      : '';

  const strokeHex =
    trend.direction === 'rising'
      ? '#dc2626'
      : trend.direction === 'falling'
        ? '#16a34a'
        : '#64748b';

  const deltaToneClass =
    trend.direction === 'rising'
      ? 'text-red-700 dark:text-red-400'
      : trend.direction === 'falling'
        ? 'text-emerald-700 dark:text-emerald-400'
        : 'text-slate-500 dark:text-slate-400';

  const netDelta = trend.netDelta ?? 0;
  const deltaText =
    trend.direction === 'single'
      ? '1 run'
      : trend.direction === 'rising'
        ? `↗ ${netDelta >= 0 ? `+${netDelta}` : netDelta}`
        : trend.direction === 'falling'
          ? `↘ ${netDelta}`
          : `→ ${netDelta > 0 ? `+${netDelta}` : netDelta}`;

  const lastCoord = coords[coords.length - 1];
  const tooltipSummary = `${indicator}: ${points.length} run${points.length === 1 ? '' : 's'} · Latest ${trend.latestScore ?? 'N/A'}/100 (${deltaText}${trend.emergingThreat ? ' · Emerging Threat' : ''})`;

  return (
    <div className="inline-flex items-center">
      <button
        ref={triggerRef}
        type="button"
        data-testid="confidence-sparkline-trigger"
        aria-label={tooltipSummary}
        aria-expanded={open}
        title={tooltipSummary}
        onClick={() => setOpen((prev) => !prev)}
        className="group inline-flex items-center gap-2 rounded-md px-1.5 py-0.5 text-left transition-colors hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
      >
        <svg
          width={SVG_WIDTH}
          height={SVG_HEIGHT}
          viewBox={`0 0 ${SVG_WIDTH} ${SVG_HEIGHT}`}
          aria-hidden="true"
          className="shrink-0 overflow-visible"
        >
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={strokeHex} stopOpacity="0.22" />
              <stop offset="100%" stopColor={strokeHex} stopOpacity="0.02" />
            </linearGradient>
          </defs>

          <line
            x1={PAD_X}
            x2={SVG_WIDTH - PAD_X}
            y1={threshold50Y}
            y2={threshold50Y}
            stroke="currentColor"
            strokeOpacity="0.18"
            strokeDasharray="2 2"
            strokeWidth={1}
          />

          {coords.length === 1 && (
            <line
              x1={PAD_X + 6}
              x2={SVG_WIDTH - PAD_X - 6}
              y1={lastCoord.y}
              y2={lastCoord.y}
              stroke={strokeHex}
              strokeOpacity="0.35"
              strokeWidth={1.25}
              strokeDasharray="2 2"
            />
          )}

          {areaPath && <path d={areaPath} fill={`url(#${gradientId})`} />}
          {linePath && (
            <path
              d={linePath}
              fill="none"
              stroke={strokeHex}
              strokeWidth={1.75}
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          )}
          <circle
            cx={lastCoord.x}
            cy={lastCoord.y}
            r={2.5}
            fill={strokeHex}
          />
        </svg>

        <div className="flex flex-col leading-tight">
          <span
            data-testid="confidence-sparkline-delta"
            className={`font-mono text-[11px] font-semibold tabular-nums whitespace-nowrap ${deltaToneClass}`}
          >
            {deltaText}
          </span>
          {trend.emergingThreat && (
            <span
              data-testid="confidence-sparkline-emerging"
              className="text-[10px] font-semibold text-red-700 dark:text-red-400 whitespace-nowrap"
            >
              Emerging
            </span>
          )}
        </div>
      </button>

      {open && popoverCoords && (
        <div
          ref={popoverRef}
          data-testid="confidence-sparkline-popover"
          role="dialog"
          aria-label={`Historical confidence trend for ${indicator}`}
          style={{ top: popoverCoords.top, left: popoverCoords.left }}
          className="fixed z-50 w-64 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-3 shadow-lg text-xs"
        >
          <div className="flex items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-2">
            <span className="font-mono font-semibold text-slate-900 dark:text-slate-100 truncate">
              {indicator}
            </span>
            <span className={`font-mono font-semibold tabular-nums ${deltaToneClass}`}>
              {deltaText}
            </span>
          </div>

          <div className="mt-2 space-y-1 max-h-36 overflow-y-auto">
            {points
              .slice(-6)
              .reverse()
              .map((pt, idx) => (
                <div
                  key={`${pt.timestamp}-${idx}`}
                  className="flex items-center justify-between gap-2 text-[11px]"
                >
                  <span className="font-mono text-slate-500 dark:text-slate-400 tabular-nums">
                    {pt.label}
                  </span>
                  <span className="font-mono font-semibold text-slate-800 dark:text-slate-200 tabular-nums">
                    {pt.score}/100
                  </span>
                </div>
              ))}
          </div>

          {trend.emergingThreat && (
            <div className="mt-2 border-t border-slate-100 dark:border-slate-800 pt-1.5 text-[11px] font-medium text-red-700 dark:text-red-400">
              Emerging threat signal: confidence rising over recent runs.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
