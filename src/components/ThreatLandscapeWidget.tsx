import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Globe2, MapPin, Radio, RefreshCw, Search, ShieldAlert } from 'lucide-react';
import { csvRowsToLookupResults, type HeatmapThresholdFilter } from '../utils/heatmapAnalytics';
import type { LookupResult } from '../utils/indicators';
import {
  aggregateThreatLandscape,
  getLandmassRegionSummary,
  mergeRealTimeLookupResults,
  WORLD_LAND_GEOJSON,
  type LandmassRegionSummary,
  type ThreatClusterPoint,
} from '../utils/threatLandscape';
import type { ThemeMode } from '../utils/theme';
import { maskIndicatorValue } from '../utils/privacyMode';
import { usePrivacyMode } from './PrivacyModeContext';

export type ThreatLandscapeScope = 'active_realtime' | 'all_runs' | 'selected_run' | 'current_investigation';

interface ThreatLandscapeWidgetProps {
  allRunRows: Record<string, string>[];
  selectedRunRows: Record<string, string>[];
  selectedRunName: string | null;
  reportCount: number;
  currentResults?: LookupResult[];
  theme?: ThemeMode;
  loading?: boolean;
  onInspectIndicator?: (indicator: string) => void;
}

function getTierHexColor(
  tier: ThreatClusterPoint['dominantTier'],
  isDark: boolean,
): string {
  switch (tier) {
    case 'Critical':
      return isDark ? '#EF4444' : '#DC2626';
    case 'High':
      return isDark ? '#F97316' : '#EA580C';
    case 'Medium':
      return isDark ? '#F59E0B' : '#D97706';
    default:
      return isDark ? '#10B981' : '#059669';
  }
}

function getTierTextClass(tier: ThreatClusterPoint['dominantTier']): string {
  switch (tier) {
    case 'Critical':
      return 'text-red-700 dark:text-red-400';
    case 'High':
      return 'text-orange-700 dark:text-orange-400';
    case 'Medium':
      return 'text-amber-700 dark:text-amber-400';
    default:
      return 'text-emerald-700 dark:text-emerald-400';
  }
}

export function ThreatLandscapeWidget({
  allRunRows,
  selectedRunRows,
  selectedRunName,
  reportCount,
  currentResults = [],
  theme = 'light',
  loading = false,
  onInspectIndicator,
}: ThreatLandscapeWidgetProps) {
  const privacyMode = usePrivacyMode();
  const isDark = theme === 'dark';
  const [thresholdFilter, setThresholdFilter] =
    useState<HeatmapThresholdFilter>('all');
  const [scope, setScope] = useState<ThreatLandscapeScope>('active_realtime');
  const [realtimeSyncEnabled, setRealtimeSyncEnabled] = useState<boolean>(true);
  const [polledReportRows, setPolledReportRows] = useState<Record<string, string>[] | null>(null);
  const [lastSyncedUtc, setLastSyncedUtc] = useState<string | null>(null);
  const [syncingRealtime, setSyncingRealtime] = useState(false);
  const [hoveredCode, setHoveredCode] = useState<string | null>(null);
  const [selectedCode, setSelectedCode] = useState<string | null>(null);
  const [mapTooltip, setMapTooltip] = useState<
    | { kind: 'region'; summary: LandmassRegionSummary; x: number; y: number }
    | { kind: 'cluster'; cluster: ThreatClusterPoint; x: number; y: number }
    | null
  >(null);

  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [mapWidth, setMapWidth] = useState<number>(640);

  const effectiveAllRunRows = polledReportRows ?? allRunRows;

  const syncRealtimeFeed = useCallback(async () => {
    setSyncingRealtime(true);
    try {
      const res = await fetch('/api/reports/all-rows');
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data?.rows)) {
          setPolledReportRows(data.rows);
          setLastSyncedUtc(new Date().toISOString().slice(11, 19));
        }
      }
    } catch {
      // Non-fatal offline fallback
    } finally {
      setSyncingRealtime(false);
    }
  }, []);

  useEffect(() => {
    setPolledReportRows(null);
  }, [allRunRows]);

  useEffect(() => {
    if (!realtimeSyncEnabled) return;
    const timer = window.setInterval(() => {
      void syncRealtimeFeed();
    }, 30000);
    return () => window.clearInterval(timer);
  }, [realtimeSyncEnabled, syncRealtimeFeed]);

  const activeLookupResults = useMemo(() => {
    if (scope === 'active_realtime') {
      const histLookup = csvRowsToLookupResults(effectiveAllRunRows);
      return mergeRealTimeLookupResults(currentResults, histLookup);
    }
    if (scope === 'current_investigation' && currentResults.length > 0) {
      return currentResults;
    }
    const rows =
      scope === 'selected_run' && selectedRunRows.length > 0 ? selectedRunRows : effectiveAllRunRows;
    return csvRowsToLookupResults(rows);
  }, [scope, currentResults, selectedRunRows, effectiveAllRunRows]);

  const landscape = useMemo(
    () => aggregateThreatLandscape(activeLookupResults, { thresholdFilter }),
    [activeLookupResults, thresholdFilter],
  );

  // If user switches to current_investigation and it becomes empty, fall back gracefully
  useEffect(() => {
    if (scope === 'current_investigation' && currentResults.length === 0) {
      setScope('active_realtime');
    }
  }, [scope, currentResults.length]);

  // Keep selected cluster valid when filters change; default-select top cluster when available
  useEffect(() => {
    setHoveredCode(null);
    setMapTooltip(null);
    setSelectedCode((prev) => {
      if (prev && landscape.clusters.some((c) => c.countryCode === prev)) {
        return prev;
      }
      return landscape.clusters[0]?.countryCode ?? null;
    });
  }, [landscape.clusters]);

  const isLoadingEmpty = loading && activeLookupResults.length === 0;

  useEffect(() => {
    const el = mapContainerRef.current;
    if (!el) return;

    const updateWidth = () => {
      const next = Math.max(280, Math.floor(el.getBoundingClientRect().width));
      setMapWidth(next);
    };
    updateWidth();

    if (typeof ResizeObserver !== 'undefined') {
      const observer = new ResizeObserver(() => updateWidth());
      observer.observe(el);
      return () => observer.disconnect();
    }
    window.addEventListener('resize', updateWidth);
    return () => window.removeEventListener('resize', updateWidth);
  }, [isLoadingEmpty]);

  // Render D3 Natural Earth geographic projection & cluster frequency markers
  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl || isLoadingEmpty) return;

    const width = Math.max(280, mapWidth);
    const isNarrow = width < 440;
    const height = Math.round(Math.max(220, Math.min(340, width * 0.5)));

    const svg = d3.select(svgEl);
    svg.selectAll('*').remove();
    svg
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('width', '100%')
      .attr('height', height);

    const projection = d3
      .geoNaturalEarth1()
      .fitExtent(
        [
          [10, 10],
          [width - 10, height - 10],
        ],
        WORLD_LAND_GEOJSON as unknown as d3.GeoPermissibleObjects,
      );

    const pathGenerator = d3.geoPath(projection);

    // Subtle spherical globe outline + graticule
    const gratColor = isDark ? '#1E293B' : '#E2E8F0';
    const sphereColor = isDark ? '#334155' : '#CBD5E1';
    const landFill = isDark ? '#1E293B' : '#E2E8F0';
    const landStroke = isDark ? '#334155' : '#CBD5E1';

    svg
      .append('path')
      .datum({ type: 'Sphere' } as unknown as d3.GeoPermissibleObjects)
      .attr('d', pathGenerator)
      .attr('fill', isDark ? '#0B1120' : '#F8FAFC')
      .attr('stroke', sphereColor)
      .attr('stroke-width', 1);

    svg
      .append('path')
      .datum(d3.geoGraticule10() as unknown as d3.GeoPermissibleObjects)
      .attr('d', pathGenerator)
      .attr('fill', 'none')
      .attr('stroke', gratColor)
      .attr('stroke-width', 0.6)
      .attr('stroke-opacity', 0.75);

    const regionSummaryById = new Map<string, LandmassRegionSummary>();
    for (const feature of WORLD_LAND_GEOJSON.features) {
      regionSummaryById.set(feature.id, getLandmassRegionSummary(feature.id, landscape.clusters));
    }

    const resolveContainerPointer = (event: MouseEvent): { x: number; y: number } => {
      const rect = mapContainerRef.current?.getBoundingClientRect();
      if (!rect) return { x: 24, y: 24 };
      return {
        x: Math.max(12, Math.min(event.clientX - rect.left, Math.max(12, rect.width - 210))),
        y: Math.max(12, Math.min(event.clientY - rect.top + 14, Math.max(12, rect.height - 96))),
      };
    };

    const landHoverFill = isDark ? '#334155' : '#CBD5E1';
    const landThreatFill = isDark ? '#263244' : '#DCE4EE';

    svg
      .append('g')
      .attr('class', 'threat-landscape-land')
      .selectAll('path')
      .data(WORLD_LAND_GEOJSON.features)
      .join('path')
      .attr('data-testid', (f) => `world-map-region-${f.id}`)
      .attr('d', (f) => pathGenerator(f as unknown as d3.GeoPermissibleObjects) ?? '')
      .attr('fill', (f) => {
        const summary = regionSummaryById.get(f.id);
        return summary && summary.threatCount > 0 ? landThreatFill : landFill;
      })
      .attr('stroke', landStroke)
      .attr('stroke-width', 0.85)
      .style('cursor', 'pointer')
      .on('mouseenter', (event: MouseEvent, f) => {
        const summary =
          regionSummaryById.get(f.id) ?? getLandmassRegionSummary(f.id, landscape.clusters);
        if (event.currentTarget) {
          d3.select(event.currentTarget as SVGPathElement)
            .attr('fill', landHoverFill)
            .attr('stroke', isDark ? '#F87171' : '#DC2626')
            .attr('stroke-width', 1.4);
        }
        setHoveredCode(null);
        const pos = resolveContainerPointer(event);
        setMapTooltip({ kind: 'region', summary, x: pos.x, y: pos.y });
      })
      .on('mousemove', (event: MouseEvent, f) => {
        const summary =
          regionSummaryById.get(f.id) ?? getLandmassRegionSummary(f.id, landscape.clusters);
        const pos = resolveContainerPointer(event);
        setMapTooltip({ kind: 'region', summary, x: pos.x, y: pos.y });
      })
      .on('mouseleave', (event: MouseEvent, f) => {
        if (event.currentTarget) {
          const summary = regionSummaryById.get(f.id);
          d3.select(event.currentTarget as SVGPathElement)
            .attr('fill', summary && summary.threatCount > 0 ? landThreatFill : landFill)
            .attr('stroke', landStroke)
            .attr('stroke-width', 0.85);
        }
        setMapTooltip(null);
      });

    if (landscape.clusters.length === 0) return;

    const radiusScale = d3
      .scaleSqrt()
      .domain([1, Math.max(2, landscape.maxClusterCount)])
      .range([isNarrow ? 5.5 : 7, isNarrow ? 15 : 20]);

    // Draw smaller bubbles last so they stay clickable above large neighboring clusters
    const orderedClusters = [...landscape.clusters].sort((a, b) => b.count - a.count);

    const markersGroup = svg.append('g').attr('class', 'threat-landscape-clusters');

    const activeCode = hoveredCode ?? selectedCode;

    const clusterGroups = markersGroup
      .selectAll<SVGGElement, ThreatClusterPoint>('g.threat-cluster')
      .data(orderedClusters, (d) => d.countryCode)
      .join('g')
      .attr('class', 'threat-cluster')
      .attr('data-testid', (d) => `threat-cluster-marker-${d.countryCode}`)
      .attr('transform', (d) => {
        const projected = projection([d.lon, d.lat]);
        if (!projected) return 'translate(-999,-999)';
        return `translate(${projected[0]}, ${projected[1]})`;
      })
      .style('cursor', 'pointer')
      .on('mouseenter', (event: MouseEvent, d) => {
        setHoveredCode(d.countryCode);
        const pos = resolveContainerPointer(event);
        setMapTooltip({ kind: 'cluster', cluster: d, x: pos.x, y: pos.y });
      })
      .on('mousemove', (event: MouseEvent, d) => {
        const pos = resolveContainerPointer(event);
        setMapTooltip({ kind: 'cluster', cluster: d, x: pos.x, y: pos.y });
      })
      .on('mouseleave', (_event, d) => {
        setHoveredCode((prev) => (prev === d.countryCode ? null : prev));
        setMapTooltip(null);
      })
      .on('click', (_event, d) =>
        setSelectedCode((prev) => (prev === d.countryCode ? null : d.countryCode)),
      );

    // Outer cluster influence ring (subtle, static hairline)
    clusterGroups
      .append('circle')
      .attr('class', 'cluster-ring')
      .style('pointer-events', 'none')
      .attr('r', (d) => radiusScale(d.count) + (d.countryCode === activeCode ? 6 : 3.5))
      .attr('fill', (d) => getTierHexColor(d.dominantTier, isDark))
      .attr('fill-opacity', (d) => (d.countryCode === activeCode ? 0.24 : 0.14))
      .attr('stroke', (d) => getTierHexColor(d.dominantTier, isDark))
      .attr('stroke-opacity', (d) => (d.countryCode === activeCode ? 0.75 : 0.35))
      .attr('stroke-width', (d) => (d.countryCode === activeCode ? 1.5 : 0.8));

    // Core proportional frequency circle
    clusterGroups
      .append('circle')
      .attr('class', 'cluster-core')
      .attr('r', (d) => radiusScale(d.count))
      .attr('fill', (d) => getTierHexColor(d.dominantTier, isDark))
      .attr('fill-opacity', 0.92)
      .attr('stroke', (d) =>
        d.countryCode === activeCode ? (isDark ? '#F8FAFC' : '#0F172A') : isDark ? '#0F172A' : '#FFFFFF',
      )
      .attr('stroke-width', (d) => (d.countryCode === activeCode ? 2 : 1.25));

    // Frequency count inside bubble
    clusterGroups
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'central')
      .attr('fill', '#FFFFFF')
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
      .attr('font-size', (d) => (radiusScale(d.count) >= 12 ? '10.5px' : '9px'))
      .attr('font-weight', '700')
      .style('pointer-events', 'none')
      .text((d) => String(d.count));

    // Non-overlapping country code micro-labels (staggered around dense clusters)
    if (!isNarrow) {
      const labeledCodes = new Set(orderedClusters.slice(0, 6).map((c) => c.countryCode));
      if (activeCode) labeledCodes.add(activeCode);

      const placedBoxes: { x1: number; y1: number; x2: number; y2: number }[] = [];
      const priorityList = orderedClusters
        .filter((c) => labeledCodes.has(c.countryCode))
        .sort((a, b) => {
          if (a.countryCode === activeCode) return -1;
          if (b.countryCode === activeCode) return 1;
          return b.count - a.count;
        });

      const labelOverlay = svg.append('g').attr('class', 'threat-landscape-labels');
      for (const cluster of priorityList) {
        const pt = projection([cluster.lon, cluster.lat]);
        if (!pt) continue;
        const [cx, cy] = pt;
        const r = radiusScale(cluster.count);
        const w = 18;
        const h = 11;
        const candidates: Array<{ x: number; y: number; anchor: 'middle' | 'start' | 'end' }> = [
          { x: cx, y: cy + r + 11, anchor: 'middle' },
          { x: cx, y: cy - r - 8, anchor: 'middle' },
          { x: cx + r + 6, y: cy + 3, anchor: 'start' },
          { x: cx - r - 6, y: cy + 3, anchor: 'end' },
        ];

        let chosen: { x: number; y: number; anchor: 'middle' | 'start' | 'end' } | null = null;
        for (const cand of candidates) {
          const x1 =
            cand.anchor === 'middle'
              ? cand.x - w / 2
              : cand.anchor === 'start'
                ? cand.x
                : cand.x - w;
          const x2 = x1 + w;
          const y1 = cand.y - h;
          const y2 = cand.y + 2;
          const collides = placedBoxes.some(
            (b) => !(x2 < b.x1 - 2 || x1 > b.x2 + 2 || y2 < b.y1 - 2 || y1 > b.y2 + 2),
          );
          if (!collides) {
            chosen = cand;
            placedBoxes.push({ x1, y1, x2, y2 });
            break;
          }
        }

        if (chosen) {
          labelOverlay
            .append('text')
            .attr('x', chosen.x)
            .attr('y', chosen.y)
            .attr('text-anchor', chosen.anchor)
            .attr('fill', isDark ? '#CBD5E1' : '#334155')
            .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
            .attr('font-size', '9.5px')
            .attr('font-weight', cluster.countryCode === activeCode ? '700' : '600')
            .style('pointer-events', 'none')
            .text(cluster.countryCode);
        }
      }
    }

    clusterGroups
      .append('title')
      .text(
        (d) =>
          `${d.countryName} (${d.countryCode}) · ${d.count} IOC${d.count === 1 ? '' : 's'} · Max score ${d.maxScore}/100`,
      );
  }, [landscape, mapWidth, isDark, isLoadingEmpty]);

  // Update active cluster ring/stroke attributes smoothly without recreating SVG nodes
  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl || isLoadingEmpty) return;
    const isNarrow = Math.max(280, mapWidth) < 440;
    const radiusScale = d3
      .scaleSqrt()
      .domain([1, Math.max(2, landscape.maxClusterCount)])
      .range([isNarrow ? 5.5 : 7, isNarrow ? 15 : 20]);
    const activeCode = hoveredCode ?? selectedCode;

    const clusters = d3
      .select(svgEl)
      .selectAll<SVGGElement, ThreatClusterPoint>('g.threat-cluster');

    clusters
      .select<SVGCircleElement>('circle.cluster-ring')
      .attr('r', (d) => radiusScale(d.count) + (d.countryCode === activeCode ? 6 : 3.5))
      .attr('fill-opacity', (d) => (d.countryCode === activeCode ? 0.24 : 0.14))
      .attr('stroke-opacity', (d) => (d.countryCode === activeCode ? 0.75 : 0.35))
      .attr('stroke-width', (d) => (d.countryCode === activeCode ? 1.5 : 0.8));

    clusters
      .select<SVGCircleElement>('circle.cluster-core')
      .attr('stroke', (d) =>
        d.countryCode === activeCode
          ? isDark
            ? '#F8FAFC'
            : '#0F172A'
          : isDark
            ? '#0F172A'
            : '#FFFFFF',
      )
      .attr('stroke-width', (d) => (d.countryCode === activeCode ? 2 : 1.25));
  }, [hoveredCode, selectedCode, landscape.maxClusterCount, mapWidth, isDark, isLoadingEmpty]);

  const activeCluster = useMemo(() => {
    const targetCode = hoveredCode ?? selectedCode;
    if (!targetCode) return landscape.topCluster;
    return (
      landscape.clusters.find((c) => c.countryCode === targetCode) ??
      landscape.topCluster
    );
  }, [landscape.clusters, landscape.topCluster, hoveredCode, selectedCode]);

  const maxMacroCount = useMemo(
    () =>
      landscape.macroRegions.length > 0
        ? Math.max(...landscape.macroRegions.map((m) => m.count))
        : 1,
    [landscape.macroRegions],
  );

  return (
    <section
      aria-label="Global Threat Landscape"
      data-testid="threat-landscape-widget"
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 md:p-6 print:border-slate-300"
    >
      <div className="flex flex-col gap-3 border-b border-slate-100 dark:border-slate-800 pb-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Globe2 className="h-4 w-4 shrink-0 text-red-600 dark:text-red-400" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">
              Threat Landscape
            </h2>
            <span className="font-mono text-xs font-medium text-slate-500 dark:text-slate-400 tabular-nums">
              · {landscape.geolocatedIocCount} geolocated · {landscape.clusters.length}{' '}
              {landscape.clusters.length === 1 ? 'country' : 'countries'}
              {landscape.unattributedCount > 0
                ? ` · ${landscape.unattributedCount} unattributed`
                : ''}
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            D3.js global source frequency of high-confidence IOCs to spot regional threat clusters. Click a map marker or region row to inspect indicators.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0 print:hidden">
          <button
            type="button"
            data-testid="world-map-realtime-toggle"
            aria-pressed={realtimeSyncEnabled}
            onClick={() => {
              const next = !realtimeSyncEnabled;
              setRealtimeSyncEnabled(next);
              if (next) void syncRealtimeFeed();
            }}
            className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              realtimeSyncEnabled
                ? 'border-red-200 dark:border-red-900/60 bg-red-50/70 dark:bg-red-950/35 text-red-700 dark:text-red-300'
                : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800'
            }`}
          >
            <Radio className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span>{realtimeSyncEnabled ? 'Real-Time Sync' : 'Sync Off'}</span>
            {lastSyncedUtc && (
              <span className="font-mono text-[10px] opacity-80 tabular-nums">
                {lastSyncedUtc}
              </span>
            )}
          </button>

          <button
            type="button"
            data-testid="world-map-refresh-btn"
            disabled={syncingRealtime}
            onClick={() => void syncRealtimeFeed()}
            aria-label="Refresh world map telemetry"
            className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-2 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${syncingRealtime ? 'animate-spin' : ''}`} aria-hidden="true" />
          </button>

          <select
            aria-label="Threat landscape confidence threshold"
            data-testid="threat-landscape-threshold-select"
            value={thresholdFilter}
            onChange={(e) => setThresholdFilter(e.target.value as HeatmapThresholdFilter)}
            className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-1.5 text-xs font-medium text-slate-800 dark:text-slate-200 focus:border-red-600 focus:outline-none cursor-pointer"
          >
            <option value="all">All Risk Tiers</option>
            <option value="high_confidence">High-Confidence (≥ 50)</option>
            <option value="critical_only">Critical Only (≥ 75)</option>
          </select>

          <select
            aria-label="Threat landscape data scope"
            data-testid="threat-landscape-scope-select"
            value={scope}
            onChange={(e) => setScope(e.target.value as ThreatLandscapeScope)}
            className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-1.5 text-xs font-medium text-slate-800 dark:text-slate-200 focus:border-red-600 focus:outline-none cursor-pointer"
          >
            <option value="active_realtime">Active IOCs (Real-Time)</option>
            <option value="all_runs">All Runs ({reportCount})</option>
            <option value="selected_run" disabled={!selectedRunName}>
              Selected Run{selectedRunName ? `: ${selectedRunName.slice(5, 16)}` : ''}
            </option>
            {currentResults.length > 0 && (
              <option value="current_investigation">
                Current Investigation ({currentResults.length} rows)
              </option>
            )}
          </select>
        </div>
      </div>

      {isLoadingEmpty ? (
        <div className="py-10 text-center text-xs text-slate-500 dark:text-slate-400">
          Aggregating global threat source telemetry...
        </div>
      ) : (
        <div className="mt-4 grid gap-6 lg:grid-cols-[minmax(0,1.65fr)_minmax(280px,1fr)]">
          {/* Left: D3 Natural Earth World Map */}
          <div className="min-w-0 space-y-3">
            <div
              ref={mapContainerRef}
              className="relative w-full overflow-hidden rounded-lg border border-slate-200 dark:border-slate-800"
            >
              <svg
                ref={svgRef}
                data-testid="threat-landscape-svg"
                role="img"
                aria-label="D3 global threat landscape map showing active IOC origin points and regional threat counts"
                className="block w-full select-none"
              />

              {mapTooltip && (
                <div
                  data-testid="world-map-hover-tooltip"
                  role="status"
                  style={{ left: mapTooltip.x, top: mapTooltip.y }}
                  className="pointer-events-none absolute z-20 w-52 rounded-lg border border-slate-200 dark:border-slate-700 bg-white/95 dark:bg-slate-900/95 px-3 py-2 shadow-md backdrop-blur-xs text-xs"
                >
                  {mapTooltip.kind === 'region' ? (
                    <div className="space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-slate-950 dark:text-slate-50">
                          {mapTooltip.summary.regionName}
                        </span>
                        <span className="font-mono font-semibold text-red-700 dark:text-red-400 tabular-nums">
                          {mapTooltip.summary.threatCount} threat{mapTooltip.summary.threatCount === 1 ? '' : 's'}
                        </span>
                      </div>
                      <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                        {mapTooltip.summary.threatCount > 0
                          ? `${mapTooltip.summary.countryCount} countr${mapTooltip.summary.countryCount === 1 ? 'y' : 'ies'} · Peak ${mapTooltip.summary.maxScore}/100`
                          : 'No active IOC origins detected'}
                      </div>
                      {mapTooltip.summary.topCountries.length > 0 && (
                        <div className="text-[11px] text-slate-600 dark:text-slate-300">
                          {mapTooltip.summary.topCountries
                            .map((c) => `${c.countryCode} (${c.count})`)
                            .join(' · ')}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-slate-950 dark:text-slate-50">
                          {mapTooltip.cluster.countryName} ({mapTooltip.cluster.countryCode})
                        </span>
                        <span className="font-mono font-semibold text-red-700 dark:text-red-400 tabular-nums">
                          {mapTooltip.cluster.count} IOC{mapTooltip.cluster.count === 1 ? '' : 's'}
                        </span>
                      </div>
                      <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                        {mapTooltip.cluster.macroRegion} · Max {mapTooltip.cluster.maxScore}/100
                      </div>
                      <div className="truncate font-mono text-[11px] text-slate-700 dark:text-slate-200">
                        {mapTooltip.cluster.indicators
                          .slice(0, 2)
                          .map((i) => maskIndicatorValue(i.indicator, null, privacyMode))
                          .join(', ')}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500 dark:text-slate-400">
              <div className="flex flex-wrap items-center gap-3.5">
                <span className="font-medium text-slate-700 dark:text-slate-300">
                  Peak Severity:
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-red-600 dark:bg-red-500" />
                  <span>Critical (≥75)</span>
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-orange-600 dark:bg-orange-500" />
                  <span>High (50–74)</span>
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-amber-600 dark:bg-amber-500" />
                  <span>Medium (25–49)</span>
                </span>
              </div>
              <span className="font-mono text-[11px] tabular-nums">
                Bubble radius = IOC frequency
              </span>
            </div>

            {landscape.clusters.length === 0 && (
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 px-4 py-3 text-xs">
                <div className="flex items-center gap-2 text-slate-600 dark:text-slate-300">
                  <ShieldAlert className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
                  <span>
                    No geolocated IOCs match the active confidence filter
                    {landscape.unattributedCount > 0
                      ? ` (${landscape.unattributedCount} matched IOC${landscape.unattributedCount === 1 ? ' lacks' : 's lack'} country attribution)`
                      : ''}
                    .
                  </span>
                </div>
                {thresholdFilter !== 'all' && (
                  <button
                    type="button"
                    onClick={() => setThresholdFilter('all')}
                    className="rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    Show All Risk Tiers
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Right: Regional Clusters Breakdown & Selected Country Inspector */}
          <div className="min-w-0 flex flex-col justify-between gap-4 border-t border-slate-100 dark:border-slate-800 pt-4 lg:border-t-0 lg:border-l lg:pl-5 lg:pt-0">
            <div className="space-y-4">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                  Regional Threat Clusters
                </h3>
                {landscape.macroRegions.length === 0 ? (
                  <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                    No regional clusters in the active filter window.
                  </p>
                ) : (
                  <ul
                    data-testid="threat-macro-region-list"
                    className="mt-2.5 space-y-2.5"
                  >
                    {landscape.macroRegions.slice(0, 5).map((region) => {
                      const pctWidth = Math.max(
                        8,
                        Math.round((region.count / Math.max(1, maxMacroCount)) * 100),
                      );
                      return (
                        <li key={region.macroRegion} className="space-y-1">
                          <div className="flex items-baseline justify-between gap-2 text-xs">
                            <span className="font-medium text-slate-800 dark:text-slate-200 truncate">
                              {region.macroRegion}
                              <span className="ml-1.5 font-mono text-[11px] text-slate-400 dark:text-slate-500">
                                ({region.countries.join(', ')})
                              </span>
                            </span>
                            <span className="font-mono font-semibold text-slate-900 dark:text-slate-100 tabular-nums shrink-0">
                              {region.count} ({region.sharePercent}%)
                            </span>
                          </div>
                          <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                            <div
                              className={`h-full rounded-full ${
                                region.criticalCount > 0
                                  ? 'bg-red-600 dark:bg-red-500'
                                  : 'bg-orange-500 dark:bg-orange-400'
                              }`}
                              style={{ width: `${pctWidth}%` }}
                            />
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>

              {landscape.clusters.length > 0 && (
                <div className="border-t border-slate-100 dark:border-slate-800 pt-3">
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                      Source Countries ({landscape.clusters.length})
                    </h3>
                  </div>

                  <div
                    data-testid="threat-country-cluster-list"
                    className="mt-2 flex flex-wrap gap-1.5"
                  >
                    {landscape.clusters.slice(0, 10).map((cluster) => {
                      const isSelected = activeCluster?.countryCode === cluster.countryCode;
                      return (
                        <button
                          key={cluster.countryCode}
                          type="button"
                          data-testid={`threat-country-btn-${cluster.countryCode}`}
                          onClick={() => setSelectedCode(cluster.countryCode)}
                          className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                            isSelected
                              ? 'border-slate-900 dark:border-slate-100 bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-950'
                              : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800'
                          }`}
                        >
                          <span className="font-mono font-semibold">{cluster.countryCode}</span>
                          <span
                            className={`font-mono tabular-nums ${
                              isSelected
                                ? 'text-slate-200 dark:text-slate-700'
                                : getTierTextClass(cluster.dominantTier)
                            }`}
                          >
                            {cluster.count}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {activeCluster && (
              <div
                data-testid="threat-landscape-cluster-inspector"
                className="border-t border-slate-200 dark:border-slate-800 pt-3"
              >
                <div className="flex items-baseline justify-between gap-2">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <MapPin
                      className={`h-3.5 w-3.5 shrink-0 ${getTierTextClass(activeCluster.dominantTier)}`}
                      aria-hidden="true"
                    />
                    <span className="text-xs font-semibold text-slate-950 dark:text-slate-50 truncate">
                      {activeCluster.countryName} ({activeCluster.countryCode})
                    </span>
                  </div>
                  <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums shrink-0">
                    {activeCluster.count} IOC{activeCluster.count === 1 ? '' : 's'} · avg{' '}
                    {activeCluster.avgScore}%
                  </span>
                </div>

                <ul className="mt-2 divide-y divide-slate-100 dark:divide-slate-800">
                  {activeCluster.indicators.slice(0, 4).map((item) => (
                    <li
                      key={item.indicator}
                      className="flex items-center justify-between gap-2 py-1.5 text-xs"
                    >
                      <div className="min-w-0">
                        <div className="font-mono font-medium text-slate-900 dark:text-slate-100 truncate">
                          {maskIndicatorValue(item.indicator, null, privacyMode)}
                        </div>
                        <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                          <span className={getTierTextClass(
                            item.riskLevel === 'Unknown' ? 'Low' : item.riskLevel,
                          )}>
                            {item.confidenceScore}/100
                          </span>{' '}
                          · {item.networkSegment}
                        </div>
                      </div>

                      {onInspectIndicator && (
                        <button
                          type="button"
                          onClick={() => onInspectIndicator(item.indicator)}
                          className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-red-700 dark:hover:text-red-400 whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          <Search className="h-3 w-3" aria-hidden="true" />
                          Filter
                        </button>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
