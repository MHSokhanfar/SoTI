import { useEffect, useMemo, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Globe, Network, Search, ShieldAlert } from 'lucide-react';
import {
  buildIocHeatmapMatrix,
  csvRowsToLookupResults,
  type HeatmapCell,
  type HeatmapDimension,
  type HeatmapThresholdFilter,
  type RiskTierBucketId,
} from '../utils/heatmapAnalytics';
import type { ThemeMode } from '../utils/theme';

export type HeatmapDataScope = 'all_runs' | 'selected_run';

interface IocRegionHeatmapProps {
  allRunRows: Record<string, string>[];
  selectedRunRows: Record<string, string>[];
  selectedRunName: string | null;
  reportCount: number;
  theme?: ThemeMode;
  loading?: boolean;
  onInspectIndicator?: (indicator: string) => void;
}

const COLUMN_HINTS: Record<RiskTierBucketId, string> = {
  Critical: '≥ 75',
  High: '50–74',
  Medium: '25–49',
  Low: '0–24',
};

function interpolateHeatmapFill(
  cell: HeatmapCell,
  maxCellCount: number,
  isDark: boolean,
): string {
  if (cell.count === 0) {
    return isDark ? '#0F172A' : '#F8FAFC';
  }
  const denominator = Math.max(1, maxCellCount);
  // Ensure low non-zero counts remain visibly tinted relative to empty cells
  const t = 0.25 + 0.75 * Math.min(1, cell.count / denominator);

  if (cell.colKey === 'Critical') {
    return isDark
      ? d3.interpolateRgb('#7F1D1D', '#EF4444')(t)
      : d3.interpolateRgb('#FEE2E2', '#B91C1C')(t);
  }
  if (cell.colKey === 'High') {
    return isDark
      ? d3.interpolateRgb('#7C2D12', '#F97316')(t)
      : d3.interpolateRgb('#FFEDD5', '#C2410C')(t);
  }
  if (cell.colKey === 'Medium') {
    return isDark
      ? d3.interpolateRgb('#78350F', '#F59E0B')(t)
      : d3.interpolateRgb('#FEF3C7', '#B45309')(t);
  }
  return isDark
    ? d3.interpolateRgb('#064E3B', '#10B981')(t)
    : d3.interpolateRgb('#D1FAE5', '#047857')(t);
}

export function IocRegionHeatmap({
  allRunRows,
  selectedRunRows,
  selectedRunName,
  reportCount,
  theme = 'light',
  loading = false,
  onInspectIndicator,
}: IocRegionHeatmapProps) {
  const isDark = theme === 'dark';
  const [dimension, setDimension] = useState<HeatmapDimension>('region');
  const [thresholdFilter, setThresholdFilter] =
    useState<HeatmapThresholdFilter>('high_confidence');
  const [scope, setScope] = useState<HeatmapDataScope>('all_runs');
  const [hoveredCell, setHoveredCell] = useState<HeatmapCell | null>(null);
  const [selectedCell, setSelectedCell] = useState<HeatmapCell | null>(null);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [containerWidth, setContainerWidth] = useState<number>(680);

  const activeRows = useMemo(
    () => (scope === 'selected_run' && selectedRunRows.length > 0 ? selectedRunRows : allRunRows),
    [scope, selectedRunRows, allRunRows],
  );

  const lookupResults = useMemo(() => csvRowsToLookupResults(activeRows), [activeRows]);

  const matrix = useMemo(
    () =>
      buildIocHeatmapMatrix(lookupResults, {
        dimension,
        thresholdFilter,
        maxRows: 8,
      }),
    [lookupResults, dimension, thresholdFilter],
  );

  const hasMatrixRows = matrix.rows.length > 0;

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const updateWidth = () => {
      const next = Math.max(280, Math.floor(el.getBoundingClientRect().width));
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
  }, [hasMatrixRows]);

  // Clear stale selected cell when filters/scope change
  useEffect(() => {
    setHoveredCell(null);
    setSelectedCell((prev) => {
      if (!prev) return null;
      return (
        matrix.cells.find(
          (c) => c.rowKey === prev.rowKey && c.colKey === prev.colKey && c.count > 0,
        ) ?? null
      );
    });
  }, [matrix]);

  // Render SVG matrix with D3.js scales and data joins
  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl || matrix.rows.length === 0) return;

    const width = Math.max(280, containerWidth);
    const isNarrow = width < 460;
    const leftMargin = isNarrow ? 130 : width < 600 ? 168 : 204;
    const rightMargin = isNarrow ? 8 : 20;
    const topMargin = 36;
    const bottomMargin = 14;
    const rowHeight = isNarrow ? 36 : 38;
    const innerHeight = Math.max(110, matrix.rows.length * rowHeight);
    const height = topMargin + innerHeight + bottomMargin;
    const innerWidth = Math.max(130, width - leftMargin - rightMargin);

    const svg = d3.select(svgEl);
    svg.selectAll('*').remove();
    svg
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('width', '100%')
      .attr('height', height);

    const xScale = d3
      .scaleBand<RiskTierBucketId>()
      .domain(matrix.columns)
      .range([0, innerWidth])
      .padding(0.1);

    const yScale = d3
      .scaleBand<string>()
      .domain(matrix.rows.map((r) => r.key))
      .range([0, innerHeight])
      .padding(0.14);

    const rootG = svg
      .append('g')
      .attr('transform', `translate(${leftMargin}, ${topMargin})`);

    const bandWidth = xScale.bandwidth();
    const compactCells = bandWidth < 110;

    // Column headers (Risk Tiers)
    const headerGroup = rootG.append('g').attr('class', 'heatmap-x-headers');
    headerGroup
      .selectAll('text.col-title')
      .data(matrix.columns)
      .join('text')
      .attr('class', 'col-title')
      .attr('x', (col) => (xScale(col) ?? 0) + bandWidth / 2)
      .attr('y', -16)
      .attr('text-anchor', 'middle')
      .attr('fill', isDark ? '#E2E8F0' : '#0F172A')
      .attr('font-size', compactCells ? '11px' : '12px')
      .attr('font-weight', '600')
      .text((col) => (compactCells ? col : `${col} (${COLUMN_HINTS[col]})`));

    // Row labels (Geographic Region or Network Segment)
    const yLabelColor = isDark ? '#CBD5E1' : '#334155';
    const ySubColor = isDark ? '#64748B' : '#94A3B8';
    const rowLabelGroup = rootG.append('g').attr('class', 'heatmap-y-labels');

    rowLabelGroup
      .selectAll('g.y-label-item')
      .data(matrix.rows)
      .join('g')
      .attr('class', 'y-label-item')
      .attr(
        'transform',
        (row) => `translate(-8, ${(yScale(row.key) ?? 0) + yScale.bandwidth() / 2})`,
      )
      .each(function (row) {
        const g = d3.select(this);
        const maxChars = isNarrow ? 16 : width < 600 ? 22 : 28;
        const truncated =
          row.key.length > maxChars ? `${row.key.slice(0, maxChars - 1)}…` : row.key;
        g.append('text')
          .attr('x', 0)
          .attr('y', -2)
          .attr('text-anchor', 'end')
          .attr('dominant-baseline', 'middle')
          .attr('fill', yLabelColor)
          .attr('font-size', isNarrow ? '10.5px' : '11.5px')
          .attr('font-weight', '500')
          .text(truncated)
          .append('title')
          .text(row.key);

        g.append('text')
          .attr('x', 0)
          .attr('y', 10)
          .attr('text-anchor', 'end')
          .attr('dominant-baseline', 'middle')
          .attr('fill', ySubColor)
          .attr('font-size', '9.5px')
          .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
          .text(`${row.totalCount} IOC${row.totalCount === 1 ? '' : 's'}`);
      });

    // Cells
    const emptyStroke = isDark ? '#1E293B' : '#E2E8F0';
    const selectedStroke = isDark ? '#F8FAFC' : '#0F172A';

    const cellGroups = rootG
      .selectAll<SVGGElement, HeatmapCell>('g.heatmap-cell')
      .data(matrix.cells)
      .join('g')
      .attr('class', 'heatmap-cell')
      .attr('data-testid', (c) => `heatmap-cell-${c.colKey}-${c.rowKey}`)
      .attr(
        'transform',
        (c) => `translate(${xScale(c.colKey) ?? 0}, ${yScale(c.rowKey) ?? 0})`,
      )
      .style('cursor', (c) => (c.count > 0 ? 'pointer' : 'default'))
      .on('mouseenter', function (_event, cell) {
        setHoveredCell(cell);
        if (cell.count > 0) {
          d3.select(this)
            .select('rect')
            .attr('stroke', selectedStroke)
            .attr('stroke-width', 2);
        }
      })
      .on('mouseleave', function (_event, cell) {
        setHoveredCell((prev) =>
          prev && prev.rowKey === cell.rowKey && prev.colKey === cell.colKey ? null : prev,
        );
        const isSelected =
          selectedCell &&
          selectedCell.rowKey === cell.rowKey &&
          selectedCell.colKey === cell.colKey;
        d3.select(this)
          .select('rect')
          .attr('stroke', isSelected ? selectedStroke : emptyStroke)
          .attr('stroke-width', isSelected ? 2 : 1);
      })
      .on('click', (_event, cell) => {
        if (cell.count > 0) {
          setSelectedCell((prev) =>
            prev && prev.rowKey === cell.rowKey && prev.colKey === cell.colKey ? null : cell,
          );
        }
      });

    cellGroups
      .append('rect')
      .attr('width', bandWidth)
      .attr('height', yScale.bandwidth())
      .attr('rx', 6)
      .attr('ry', 6)
      .attr('fill', (c) => interpolateHeatmapFill(c, matrix.maxCellCount, isDark))
      .attr('stroke', (c) => {
        const isSelected =
          selectedCell && selectedCell.rowKey === c.rowKey && selectedCell.colKey === c.colKey;
        return isSelected ? selectedStroke : emptyStroke;
      })
      .attr('stroke-width', (c) => {
        const isSelected =
          selectedCell && selectedCell.rowKey === c.rowKey && selectedCell.colKey === c.colKey;
        return isSelected ? 2 : 1;
      });

    // Count labels inside cells
    cellGroups
      .append('text')
      .attr('x', bandWidth / 2)
      .attr('y', yScale.bandwidth() / 2)
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'middle')
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
      .attr('font-size', compactCells ? '11px' : '12px')
      .attr('font-weight', (c) => (c.count > 0 ? '700' : '400'))
      .attr('fill', (c) => {
        if (c.count === 0) return isDark ? '#475569' : '#94A3B8';
        const ratio = c.count / Math.max(1, matrix.maxCellCount);
        if (!isDark && ratio < 0.45) return '#0F172A';
        return '#FFFFFF';
      })
      .text((c) => {
        if (c.count === 0) return '0';
        return compactCells ? `${c.count}` : `${c.count} · avg ${c.avgScore}%`;
      });
  }, [matrix, containerWidth, isDark, selectedCell]);

  const activeInspectionCell = selectedCell ?? hoveredCell;

  return (
    <section
      aria-label="High-Confidence IOC Distribution Heatmap"
      data-testid="ioc-region-heatmap-section"
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 md:p-6 print:border-slate-300"
    >
      <div className="flex flex-col gap-3 border-b border-slate-100 dark:border-slate-800 pb-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">
              High-Confidence IOC Distribution Heatmap
            </h2>
            <span className="font-mono text-xs font-medium text-slate-500 dark:text-slate-400 tabular-nums">
              · {matrix.totalHighConfidenceIocs}/{matrix.totalEvaluatedIocs} high-confidence
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            D3.js distribution matrix across geographic regions or network segments. Click a cell to inspect indicators.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0 print:hidden">
          <div
            className="inline-flex items-center rounded-lg bg-slate-100 dark:bg-slate-800 p-1"
            role="group"
            aria-label="Heatmap grouping dimension"
          >
            <button
              type="button"
              data-testid="heatmap-dim-region"
              onClick={() => setDimension('region')}
              className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                dimension === 'region'
                  ? 'bg-white dark:bg-slate-950 text-slate-950 dark:text-slate-50 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
              }`}
            >
              <Globe className="h-3.5 w-3.5" aria-hidden="true" />
              Geographic Regions
            </button>
            <button
              type="button"
              data-testid="heatmap-dim-network"
              onClick={() => setDimension('network')}
              className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                dimension === 'network'
                  ? 'bg-white dark:bg-slate-950 text-slate-950 dark:text-slate-50 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
              }`}
            >
              <Network className="h-3.5 w-3.5" aria-hidden="true" />
              Network Segments
            </button>
          </div>

          <select
            aria-label="Heatmap confidence threshold"
            data-testid="heatmap-threshold-select"
            value={thresholdFilter}
            onChange={(e) => setThresholdFilter(e.target.value as HeatmapThresholdFilter)}
            className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-1.5 text-xs font-medium text-slate-800 dark:text-slate-200 focus:border-red-600 focus:outline-none cursor-pointer"
          >
            <option value="high_confidence">High-Confidence (≥ 50)</option>
            <option value="critical_only">Critical Only (≥ 75)</option>
            <option value="all">All Risk Tiers</option>
          </select>

          <select
            aria-label="Heatmap run scope"
            data-testid="heatmap-scope-select"
            value={scope}
            onChange={(e) => setScope(e.target.value as HeatmapDataScope)}
            className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-1.5 text-xs font-medium text-slate-800 dark:text-slate-200 focus:border-red-600 focus:outline-none cursor-pointer"
          >
            <option value="all_runs">
              All Runs ({reportCount})
            </option>
            <option value="selected_run" disabled={!selectedRunName}>
              Selected Run{selectedRunName ? `: ${selectedRunName.slice(5, 16)}` : ''}
            </option>
          </select>
        </div>
      </div>

      {loading && activeRows.length === 0 ? (
        <div className="py-10 text-center text-xs text-slate-500 dark:text-slate-400">
          Loading regional &amp; network enrichment telemetry...
        </div>
      ) : matrix.rows.length === 0 ? (
        <div className="py-10 text-center">
          <ShieldAlert
            className="mx-auto h-7 w-7 text-slate-400 dark:text-slate-500"
            aria-hidden="true"
          />
          <p className="mt-2 text-sm font-medium text-slate-900 dark:text-slate-100">
            No indicators match the active confidence filter
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Switch to &ldquo;All Risk Tiers&rdquo; or run an enrichment lookup to populate geographic and ASN heatmap buckets.
          </p>
          {thresholdFilter !== 'all' && (
            <button
              type="button"
              onClick={() => setThresholdFilter('all')}
              className="mt-3 inline-flex items-center rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
            >
              Show All Risk Tiers
            </button>
          )}
        </div>
      ) : (
        <div className="mt-4 space-y-4">
          <div ref={containerRef} className="w-full overflow-x-auto">
            <svg
              ref={svgRef}
              data-testid="ioc-heatmap-svg"
              role="img"
              aria-label="D3 matrix heatmap of IOC confidence scores by region or network segment"
              className="block w-full select-none"
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 dark:border-slate-800 pt-3 text-xs text-slate-500 dark:text-slate-400">
            <div className="flex flex-wrap items-center gap-4">
              <span className="font-medium text-slate-700 dark:text-slate-300">Intensity Scale:</span>
              <span className="inline-flex items-center gap-1.5">
                <span className="h-3 w-3 rounded-sm border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900" />
                <span>0 IOCs</span>
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="h-3 w-3 rounded-sm bg-red-200 dark:bg-red-900" />
                <span>Low density</span>
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="h-3 w-3 rounded-sm bg-red-600 dark:bg-red-500" />
                <span>Peak density (max {matrix.maxCellCount})</span>
              </span>
            </div>
            <span className="font-mono text-[11px] tabular-nums">
              Showing top {matrix.rows.length}{' '}
              {dimension === 'region' ? 'geographic regions' : 'network segments'}
            </span>
          </div>

          {activeInspectionCell && activeInspectionCell.count > 0 && (
            <div
              data-testid="heatmap-cell-inspector"
              className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 p-4"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="font-semibold text-slate-950 dark:text-slate-50">
                      {activeInspectionCell.rowKey}
                    </span>
                    <span className="text-slate-400 dark:text-slate-600" aria-hidden="true">·</span>
                    <span className="font-semibold text-red-700 dark:text-red-400">
                      {activeInspectionCell.colKey} Risk Tier
                    </span>
                    <span className="text-slate-400 dark:text-slate-600" aria-hidden="true">·</span>
                    <span className="font-mono text-slate-600 dark:text-slate-400 tabular-nums">
                      {activeInspectionCell.count} IOC{activeInspectionCell.count === 1 ? '' : 's'} (max{' '}
                      {activeInspectionCell.maxScore}%, avg {activeInspectionCell.avgScore}%)
                    </span>
                  </div>
                </div>
                {selectedCell && (
                  <button
                    type="button"
                    onClick={() => setSelectedCell(null)}
                    className="text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
                  >
                    Clear Selection
                  </button>
                )}
              </div>

              <div className="mt-3 divide-y divide-slate-200/70 dark:divide-slate-800 border-t border-slate-200/70 dark:border-slate-800">
                {activeInspectionCell.indicators.slice(0, 6).map((item) => (
                  <div
                    key={item.indicator}
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
                      <span className="font-mono font-semibold text-red-700 dark:text-red-400 tabular-nums">
                        {item.confidenceScore}/100
                      </span>
                      <span className="text-slate-400 dark:text-slate-600" aria-hidden="true">·</span>
                      <span className="text-slate-600 dark:text-slate-400 truncate">
                        {item.networkSegment}
                      </span>
                    </div>

                    {onInspectIndicator && (
                      <button
                        type="button"
                        onClick={() => onInspectIndicator(item.indicator)}
                        className="inline-flex items-center gap-1 text-xs font-medium text-slate-700 dark:text-slate-300 hover:text-red-700 dark:hover:text-red-400 whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        <Search className="h-3 w-3" aria-hidden="true" />
                        Filter Table
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
