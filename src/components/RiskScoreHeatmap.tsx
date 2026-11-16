import { useEffect, useMemo, useRef, useState } from 'react';
import * as d3 from 'd3';
import {
  Activity,
  AlertTriangle,
  CalendarClock,
  CheckCircle2,
  Layers,
  Search,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import type { LookupResult } from '../utils/indicators';
import type { ReportMeta } from '../utils/reportsAnalytics';
import {
  buildRiskScoreHeatmap,
  type PostureRating,
  type RiskBandId,
  type RiskHeatmapCell,
  type RiskHeatmapViewMode,
} from '../utils/riskScoreHeatmap';
import type { ThemeMode } from '../utils/theme';

interface RiskScoreHeatmapProps {
  reports: ReportMeta[];
  allRunRows: Record<string, string>[];
  currentResults?: LookupResult[];
  selectedRunName?: string | null;
  theme?: ThemeMode;
  loading?: boolean;
  onSelectReport?: (reportName: string) => void;
  onInspectIndicator?: (indicator: string) => void;
}

const BAND_META: Record<
  RiskBandId,
  {
    title: string;
    rangeLabel: string;
    accentText: string;
    swatchClass: string;
  }
> = {
  High: {
    title: 'High Risk',
    rangeLabel: '50–100',
    accentText: 'text-red-700 dark:text-red-400',
    swatchClass: 'bg-red-600 dark:bg-red-500',
  },
  Medium: {
    title: 'Medium Risk',
    rangeLabel: '25–49',
    accentText: 'text-amber-700 dark:text-amber-400',
    swatchClass: 'bg-amber-500 dark:bg-amber-400',
  },
  Low: {
    title: 'Low Risk',
    rangeLabel: '0–24',
    accentText: 'text-emerald-700 dark:text-emerald-400',
    swatchClass: 'bg-emerald-600 dark:bg-emerald-500',
  },
};

function interpolateRiskCellFill(
  cell: RiskHeatmapCell,
  maxCellCount: number,
  isDark: boolean,
): string {
  if (cell.count === 0) {
    return isDark ? '#0F172A' : '#F8FAFC';
  }
  const denominator = Math.max(1, maxCellCount);
  const t = 0.28 + 0.72 * Math.min(1, cell.count / denominator);

  if (cell.band === 'High') {
    return isDark
      ? d3.interpolateRgb('#7F1D1D', '#EF4444')(t)
      : d3.interpolateRgb('#FEE2E2', '#B91C1C')(t);
  }
  if (cell.band === 'Medium') {
    return isDark
      ? d3.interpolateRgb('#78350F', '#F59E0B')(t)
      : d3.interpolateRgb('#FEF3C7', '#B45309')(t);
  }
  return isDark
    ? d3.interpolateRgb('#064E3B', '#10B981')(t)
    : d3.interpolateRgb('#D1FAE5', '#047857')(t);
}

function getPosturePresentation(rating: PostureRating): {
  colorClass: string;
  Icon: typeof ShieldAlert;
} {
  switch (rating) {
    case 'Critical':
      return { colorClass: 'text-red-700 dark:text-red-400', Icon: ShieldAlert };
    case 'Elevated':
      return { colorClass: 'text-amber-700 dark:text-amber-400', Icon: AlertTriangle };
    case 'Moderate':
      return { colorClass: 'text-slate-900 dark:text-slate-100', Icon: Activity };
    case 'Low':
      return { colorClass: 'text-emerald-700 dark:text-emerald-400', Icon: ShieldCheck };
    default:
      return { colorClass: 'text-slate-500 dark:text-slate-400', Icon: CheckCircle2 };
  }
}

export function RiskScoreHeatmap({
  reports,
  allRunRows,
  currentResults = [],
  selectedRunName = null,
  theme = 'light',
  loading = false,
  onSelectReport,
  onInspectIndicator,
}: RiskScoreHeatmapProps) {
  const isDark = theme === 'dark';
  const [mode, setMode] = useState<RiskHeatmapViewMode>('investigations');
  const [hoveredCell, setHoveredCell] = useState<RiskHeatmapCell | null>(null);
  const [selectedCell, setSelectedCell] = useState<RiskHeatmapCell | null>(null);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [containerWidth, setContainerWidth] = useState<number>(720);

  const heatmap = useMemo(
    () =>
      buildRiskScoreHeatmap({
        reports,
        allRunRows,
        currentResults,
        mode,
        maxRuns: 14,
      }),
    [reports, allRunRows, currentResults, mode],
  );

  const hasColumns = heatmap.columns.length > 0 && heatmap.totalEvaluatedIndicators > 0;

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const updateWidth = () => {
      const next = Math.max(300, Math.floor(el.getBoundingClientRect().width));
      setContainerWidth(next);
    };
    updateWidth();

    if (typeof ResizeObserver !== 'undefined') {
      const observer = new ResizeObserver(() => updateWidth());
      observer.observe(el);
      return () => observer.disconnect();
    }
    window.addEventListener('resize', updateWidth);
    return () => window.removeEventListener('resize', updateWidth);
  }, [hasColumns]);

  // Clear or refresh selected cell when underlying matrix or mode updates
  useEffect(() => {
    setHoveredCell(null);
    setSelectedCell((prev) => {
      if (!prev) return null;
      return (
        heatmap.cells.find(
          (c) => c.colKey === prev.colKey && c.band === prev.band && c.count > 0,
        ) ?? null
      );
    });
  }, [heatmap]);

  // Render D3 matrix
  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl || !hasColumns) return;

    const colCount = heatmap.columns.length;
    const baseWidth = Math.max(300, containerWidth);
    const isNarrow = baseWidth < 520;
    const leftMargin = isNarrow ? 104 : 138;
    const rightMargin = 16;
    const topMargin = 48;
    const bottomMargin = 12;

    const minColWidth = mode === 'investigations' ? (colCount > 6 ? 78 : 88) : 110;
    const svgWidth = Math.max(baseWidth, leftMargin + rightMargin + colCount * minColWidth);
    const innerWidth = Math.max(150, svgWidth - leftMargin - rightMargin);
    const rowHeight = isNarrow ? 54 : 58;
    const innerHeight = heatmap.bands.length * rowHeight;
    const svgHeight = topMargin + innerHeight + bottomMargin;

    const svg = d3.select(svgEl);
    svg.selectAll('*').remove();
    svg
      .attr('viewBox', `0 0 ${svgWidth} ${svgHeight}`)
      .attr('width', svgWidth)
      .attr('height', svgHeight);

    const xScale = d3
      .scaleBand<string>()
      .domain(heatmap.columns.map((c) => c.key))
      .range([0, innerWidth])
      .padding(0.12);

    const yScale = d3
      .scaleBand<RiskBandId>()
      .domain(heatmap.bands)
      .range([0, innerHeight])
      .padding(0.16);

    const rootG = svg
      .append('g')
      .attr('transform', `translate(${leftMargin}, ${topMargin})`);

    const bandWidth = xScale.bandwidth();
    const compactCell = bandWidth < 76;

    // X-Axis column headers
    const headerPrimaryColor = isDark ? '#E2E8F0' : '#0F172A';
    const headerActiveColor = isDark ? '#F87171' : '#DC2626';
    const headerSubColor = isDark ? '#94A3B8' : '#64748B';

    const colHeaderGroup = rootG.append('g').attr('class', 'risk-heatmap-x-headers');
    colHeaderGroup
      .selectAll<SVGGElement, (typeof heatmap.columns)[number]>('g.col-header')
      .data(heatmap.columns)
      .join('g')
      .attr('class', 'col-header')
      .attr(
        'transform',
        (col) => `translate(${(xScale(col.key) ?? 0) + bandWidth / 2}, -26)`,
      )
      .style('cursor', mode === 'investigations' && onSelectReport ? 'pointer' : 'default')
      .on('click', (_event, col) => {
        if (mode === 'investigations' && col.key !== 'active-session' && onSelectReport) {
          onSelectReport(col.key);
        }
      })
      .each(function (col) {
        const g = d3.select(this);
        const isActiveRun = Boolean(selectedRunName && col.key === selectedRunName);
        const maxLabelChars = compactCell ? 11 : 16;
        const labelText =
          col.shortLabel.length > maxLabelChars
            ? `${col.shortLabel.slice(0, maxLabelChars - 1)}…`
            : col.shortLabel;

        g.append('text')
          .attr('x', 0)
          .attr('y', 0)
          .attr('text-anchor', 'middle')
          .attr('fill', isActiveRun ? headerActiveColor : headerPrimaryColor)
          .attr('font-size', compactCell ? '10.5px' : '11.5px')
          .attr('font-weight', isActiveRun ? '700' : '600')
          .attr('font-family', mode === 'investigations' ? 'ui-monospace, SFMono-Regular, Menlo, monospace' : 'inherit')
          .text(labelText)
          .append('title')
          .text(`${col.label} (${col.totalEvaluated} evaluated IOCs)`);

        g.append('text')
          .attr('x', 0)
          .attr('y', 14)
          .attr('text-anchor', 'middle')
          .attr('fill', headerSubColor)
          .attr('font-size', '10px')
          .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
          .text(`${col.totalEvaluated} IOC${col.totalEvaluated === 1 ? '' : 's'}`);
      });

    // Y-Axis risk band labels
    const rowLabelGroup = rootG.append('g').attr('class', 'risk-heatmap-y-labels');
    rowLabelGroup
      .selectAll<SVGGElement, RiskBandId>('g.y-band-label')
      .data(heatmap.bands)
      .join('g')
      .attr('class', 'y-band-label')
      .attr(
        'transform',
        (band) => `translate(-12, ${(yScale(band) ?? 0) + yScale.bandwidth() / 2})`,
      )
      .each(function (band) {
        const g = d3.select(this);
        const meta = BAND_META[band];
        const summary = heatmap.bandSummary[band];
        const titleColor =
          band === 'High'
            ? isDark
              ? '#FCA5A5'
              : '#B91C1C'
            : band === 'Medium'
              ? isDark
                ? '#FCD34D'
                : '#B45309'
              : isDark
                ? '#6EE7B7'
                : '#047857';

        g.append('text')
          .attr('x', 0)
          .attr('y', -7)
          .attr('text-anchor', 'end')
          .attr('dominant-baseline', 'middle')
          .attr('fill', titleColor)
          .attr('font-size', isNarrow ? '11px' : '12px')
          .attr('font-weight', '700')
          .text(meta.title);

        g.append('text')
          .attr('x', 0)
          .attr('y', 8)
          .attr('text-anchor', 'end')
          .attr('dominant-baseline', 'middle')
          .attr('fill', headerSubColor)
          .attr('font-size', '10px')
          .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
          .text(`${meta.rangeLabel} · ${summary.count}`);
      });

    // Cells
    const emptyStroke = isDark ? '#1E293B' : '#E2E8F0';
    const activeStroke = isDark ? '#F8FAFC' : '#0F172A';

    const cellGroups = rootG
      .selectAll<SVGGElement, RiskHeatmapCell>('g.risk-heatmap-cell')
      .data(heatmap.cells)
      .join('g')
      .attr('class', 'risk-heatmap-cell')
      .attr('data-testid', (c) => `risk-heatmap-cell-${c.band.toLowerCase()}-${c.colKey}`)
      .attr(
        'transform',
        (c) => `translate(${xScale(c.colKey) ?? 0}, ${yScale(c.band) ?? 0})`,
      )
      .style('cursor', (c) => (c.count > 0 ? 'pointer' : 'default'))
      .on('mouseenter', function (_event, cell) {
        setHoveredCell(cell);
        if (cell.count > 0) {
          d3.select(this)
            .select('rect')
            .attr('stroke', activeStroke)
            .attr('stroke-width', 2);
        }
      })
      .on('mouseleave', function (_event, cell) {
        setHoveredCell((prev) =>
          prev && prev.colKey === cell.colKey && prev.band === cell.band ? null : prev,
        );
        const isSelected =
          selectedCell &&
          selectedCell.colKey === cell.colKey &&
          selectedCell.band === cell.band;
        d3.select(this)
          .select('rect')
          .attr('stroke', isSelected ? activeStroke : emptyStroke)
          .attr('stroke-width', isSelected ? 2 : 1);
      })
      .on('click', (_event, cell) => {
        if (cell.count === 0) return;
        setSelectedCell((prev) =>
          prev && prev.colKey === cell.colKey && prev.band === cell.band ? null : cell,
        );
      });

    cellGroups
      .append('rect')
      .attr('width', bandWidth)
      .attr('height', yScale.bandwidth())
      .attr('rx', 6)
      .attr('ry', 6)
      .attr('fill', (c) => interpolateRiskCellFill(c, heatmap.maxCellCount, isDark))
      .attr('stroke', (c) => {
        const isSelected =
          selectedCell && selectedCell.colKey === c.colKey && selectedCell.band === c.band;
        return isSelected ? activeStroke : emptyStroke;
      })
      .attr('stroke-width', (c) => {
        const isSelected =
          selectedCell && selectedCell.colKey === c.colKey && selectedCell.band === c.band;
        return isSelected ? 2 : 1;
      });

    // Primary cell count
    cellGroups
      .append('text')
      .attr('x', bandWidth / 2)
      .attr('y', (c) =>
        c.count > 0 && yScale.bandwidth() >= 42
          ? yScale.bandwidth() / 2 - 6
          : yScale.bandwidth() / 2,
      )
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'middle')
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
      .attr('font-size', compactCell ? '11.5px' : '12.5px')
      .attr('font-weight', (c) => (c.count > 0 ? '700' : '400'))
      .attr('fill', (c) => {
        if (c.count === 0) return isDark ? '#475569' : '#94A3B8';
        const ratio = c.count / Math.max(1, heatmap.maxCellCount);
        if (!isDark && ratio < 0.48) return '#0F172A';
        return '#FFFFFF';
      })
      .text((c) => `${c.count}`);

    // Percentage share of column inside cell
    cellGroups
      .filter((c) => c.count > 0 && yScale.bandwidth() >= 42)
      .append('text')
      .attr('x', bandWidth / 2)
      .attr('y', yScale.bandwidth() / 2 + 10)
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'middle')
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
      .attr('font-size', '10px')
      .attr('font-weight', '500')
      .attr('fill', (c) => {
        const ratio = c.count / Math.max(1, heatmap.maxCellCount);
        if (!isDark && ratio < 0.48) return '#334155';
        return 'rgba(255, 255, 255, 0.88)';
      })
      .text((c) => `${c.percentageOfColumn}%`);
  }, [heatmap, containerWidth, hasColumns, isDark, mode, selectedCell, selectedRunName, onSelectReport]);

  const activeCell = selectedCell ?? hoveredCell;
  const posture = getPosturePresentation(heatmap.postureRating);
  const PostureIcon = posture.Icon;

  return (
    <section
      aria-label="Risk Score Heatmap"
      data-testid="risk-score-heatmap-section"
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 md:p-6 print:border-slate-300 print:p-4"
    >
      <div className="flex flex-col gap-3 border-b border-slate-100 dark:border-slate-800 pb-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">
              Risk Score Heatmap
            </h2>
            <span className="font-mono text-xs font-medium text-slate-500 dark:text-slate-400 tabular-nums">
              · {heatmap.totalEvaluatedIndicators} IOCs across {heatmap.totalInvestigationsProcessed}{' '}
              investigation{heatmap.totalInvestigationsProcessed === 1 ? '' : 's'}
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            Distribution of High (50–100), Medium (25–49), and Low (0–24) risk indicators across processed investigations. Click a cell to drill down.
          </p>
        </div>

        <div
          className="inline-flex items-center rounded-lg bg-slate-100 dark:bg-slate-800 p-1 self-start lg:self-auto shrink-0 print:hidden"
          role="group"
          aria-label="Risk heatmap grouping mode"
        >
          <button
            type="button"
            data-testid="risk-heatmap-mode-investigations"
            onClick={() => setMode('investigations')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              mode === 'investigations'
                ? 'bg-white dark:bg-slate-950 text-slate-950 dark:text-slate-50 shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
            }`}
          >
            <CalendarClock className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Across Investigations</span>
          </button>
          <button
            type="button"
            data-testid="risk-heatmap-mode-types"
            onClick={() => setMode('indicator_type')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              mode === 'indicator_type'
                ? 'bg-white dark:bg-slate-950 text-slate-950 dark:text-slate-50 shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
            }`}
          >
            <Layers className="h-3.5 w-3.5" aria-hidden="true" />
            <span>By Indicator Type</span>
          </button>
        </div>
      </div>

      {/* Unboxed 5-column Security Posture Summary Strip */}
      <dl
        data-testid="risk-heatmap-posture-summary"
        className="grid grid-cols-2 border-b border-slate-100 dark:border-slate-800 divide-y divide-slate-100 dark:divide-slate-800 sm:grid-cols-5 sm:divide-x sm:divide-y-0"
      >
        <div className="col-span-2 sm:col-span-1 py-3.5 sm:pr-4">
          <dt className="text-xs font-medium text-slate-500 dark:text-slate-400">Overall Posture</dt>
          <dd className={`mt-1 flex items-center gap-1.5 text-lg font-bold tracking-tight ${posture.colorClass}`}>
            <PostureIcon className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>{heatmap.postureRating}</span>
          </dd>
          <dd className="mt-0.5 font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
            {heatmap.uniqueEvaluatedIndicators} unique IOC{heatmap.uniqueEvaluatedIndicators === 1 ? '' : 's'}
          </dd>
        </div>

        <div className="py-3.5 sm:px-4">
          <dt className="text-xs font-medium text-slate-500 dark:text-slate-400">Investigations</dt>
          <dd className="mt-1 font-mono text-xl font-bold text-slate-950 dark:text-slate-50 tabular-nums">
            {heatmap.totalInvestigationsProcessed}
          </dd>
          <dd className="mt-0.5 font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
            {heatmap.displayedInvestigationsCount} in timeline
          </dd>
        </div>

        <div className="py-3.5 pl-4 sm:px-4">
          <dt className="text-xs font-medium text-red-700 dark:text-red-400">High Risk (50–100)</dt>
          <dd className="mt-1 font-mono text-xl font-bold text-red-700 dark:text-red-400 tabular-nums">
            {heatmap.bandSummary.High.percentage}%
          </dd>
          <dd className="mt-0.5 font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
            {heatmap.bandSummary.High.count} IOCs · {heatmap.bandSummary.High.criticalCount} critical
          </dd>
        </div>

        <div className="py-3.5 sm:px-4">
          <dt className="text-xs font-medium text-amber-700 dark:text-amber-400">Medium Risk (25–49)</dt>
          <dd className="mt-1 font-mono text-xl font-bold text-amber-700 dark:text-amber-400 tabular-nums">
            {heatmap.bandSummary.Medium.percentage}%
          </dd>
          <dd className="mt-0.5 font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
            {heatmap.bandSummary.Medium.count} IOC{heatmap.bandSummary.Medium.count === 1 ? '' : 's'}
          </dd>
        </div>

        <div className="py-3.5 pl-4 sm:pl-4">
          <dt className="text-xs font-medium text-emerald-700 dark:text-emerald-400">Low Risk (0–24)</dt>
          <dd className="mt-1 font-mono text-xl font-bold text-emerald-700 dark:text-emerald-400 tabular-nums">
            {heatmap.bandSummary.Low.percentage}%
          </dd>
          <dd className="mt-0.5 font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
            {heatmap.bandSummary.Low.count} IOC{heatmap.bandSummary.Low.count === 1 ? '' : 's'}
          </dd>
        </div>
      </dl>

      {loading && !hasColumns ? (
        <div className="py-10 text-center text-xs text-slate-500 dark:text-slate-400">
          Computing risk score distribution across processed investigations...
        </div>
      ) : !hasColumns ? (
        <div className="py-10 text-center">
          <ShieldAlert
            className="mx-auto h-7 w-7 text-slate-400 dark:text-slate-500"
            aria-hidden="true"
          />
          <p className="mt-2 text-sm font-medium text-slate-900 dark:text-slate-100">
            No scored investigations available yet
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Run an enrichment lookup from the Investigate tab to populate the High / Medium / Low risk score heatmap.
          </p>
        </div>
      ) : (
        <div className="mt-4 space-y-4">
          <div ref={containerRef} className="w-full overflow-x-auto pb-1">
            <svg
              ref={svgRef}
              data-testid="risk-score-heatmap-svg"
              role="img"
              aria-label="D3 matrix heatmap showing High, Medium, and Low risk score distribution across processed investigations"
              className="block select-none"
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 dark:border-slate-800 pt-3 text-xs text-slate-500 dark:text-slate-400">
            <div className="flex flex-wrap items-center gap-4">
              <span className="font-medium text-slate-700 dark:text-slate-300">Risk Bands:</span>
              <span className="inline-flex items-center gap-1.5">
                <span className="h-3 w-3 rounded-sm border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900" />
                <span>0 IOCs</span>
              </span>
              {heatmap.bands.map((band) => (
                <span key={band} className="inline-flex items-center gap-1.5">
                  <span className={`h-3 w-3 rounded-sm ${BAND_META[band].swatchClass}`} />
                  <span>
                    {BAND_META[band].title} ({BAND_META[band].rangeLabel})
                  </span>
                </span>
              ))}
            </div>
            <span className="font-mono text-[11px] tabular-nums">
              {mode === 'investigations'
                ? `Showing ${heatmap.columns.length} of ${heatmap.totalInvestigationsProcessed} processed investigation${heatmap.totalInvestigationsProcessed === 1 ? '' : 's'} (peak ${heatmap.maxCellCount})`
                : `Aggregated across ${heatmap.totalInvestigationsProcessed} investigation${heatmap.totalInvestigationsProcessed === 1 ? '' : 's'} (peak ${heatmap.maxCellCount})`}
            </span>
          </div>

          {activeCell && activeCell.count > 0 && (
            <div
              data-testid="risk-heatmap-cell-inspector"
              className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-4"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2 text-xs min-w-0">
                  <span className="font-mono font-semibold text-slate-950 dark:text-slate-50">
                    {activeCell.colLabel}
                  </span>
                  <span className="text-slate-400 dark:text-slate-600" aria-hidden="true">·</span>
                  <span className={`font-semibold ${BAND_META[activeCell.band].accentText}`}>
                    {BAND_META[activeCell.band].title} ({BAND_META[activeCell.band].rangeLabel})
                  </span>
                  <span className="text-slate-400 dark:text-slate-600" aria-hidden="true">·</span>
                  <span className="font-mono text-slate-600 dark:text-slate-400 tabular-nums">
                    {activeCell.count} IOC{activeCell.count === 1 ? '' : 's'} ({activeCell.percentageOfColumn}% of column · avg {activeCell.avgScore}/100, max {activeCell.maxScore}/100)
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-3 shrink-0 print:hidden">
                  {mode === 'investigations' &&
                    activeCell.colKey !== 'active-session' &&
                    onSelectReport && (
                      <button
                        type="button"
                        data-testid="risk-heatmap-inspect-run-btn"
                        onClick={() => onSelectReport(activeCell.colKey)}
                        className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-800 dark:text-slate-200 hover:border-red-300 dark:hover:border-red-700 hover:text-red-700 dark:hover:text-red-300 whitespace-nowrap cursor-pointer"
                      >
                        <span>Inspect Run</span>
                      </button>
                    )}
                  {selectedCell && (
                    <button
                      type="button"
                      onClick={() => setSelectedCell(null)}
                      className="inline-flex items-center gap-1 text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
                    >
                      <X className="h-3 w-3" aria-hidden="true" />
                      <span>Clear</span>
                    </button>
                  )}
                </div>
              </div>

              <div className="mt-3 divide-y divide-slate-200/70 dark:divide-slate-800 border-t border-slate-200/70 dark:border-slate-800">
                {activeCell.items.slice(0, 6).map((item) => (
                  <div
                    key={`${activeCell.colKey}-${item.indicator}`}
                    className="flex flex-wrap items-center justify-between gap-3 py-2 text-xs"
                  >
                    <div className="flex flex-wrap items-center gap-2 min-w-0">
                      <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                        {item.indicator}
                      </span>
                      <span className="font-mono text-[11px] uppercase text-slate-500 dark:text-slate-400">
                        {item.type}
                      </span>
                      <span className="text-slate-400 dark:text-slate-600" aria-hidden="true">·</span>
                      <span className={`font-mono font-semibold tabular-nums ${BAND_META[item.riskBand].accentText}`}>
                        {item.confidenceScore}/100 ({item.riskLevel})
                      </span>
                      <span className="text-slate-400 dark:text-slate-600" aria-hidden="true">·</span>
                      <span className="text-slate-600 dark:text-slate-400">
                        {item.verdictSummary}
                      </span>
                    </div>

                    {onInspectIndicator && (
                      <button
                        type="button"
                        onClick={() => onInspectIndicator(item.indicator)}
                        className="inline-flex items-center gap-1 text-xs font-medium text-slate-700 dark:text-slate-300 hover:text-red-700 dark:hover:text-red-400 whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        <Search className="h-3 w-3" aria-hidden="true" />
                        <span>Filter Table</span>
                      </button>
                    )}
                  </div>
                ))}
                {activeCell.items.length > 6 && (
                  <div className="pt-2 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                    +{activeCell.items.length - 6} additional indicator{activeCell.items.length - 6 === 1 ? '' : 's'} in this risk bucket
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
