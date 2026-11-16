import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  AlertCircle,
  Check,
  CheckCircle2,
  Copy,
  Download,
  FileSpreadsheet,
  FileText,
  Link2,
  Loader2,
  RefreshCw,
  Search,
  Share2,
  Sparkles,
  X,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  areAllVisibleReportsSelected,
  buildAggregatedCsvFilename,
  buildHistoricalChartData,
  buildThreatAlertTrend30Days,
  computeIndicatorConfidenceMap,
  computeReportsQuickStats,
  DEFAULT_REPORTS_REFRESH_SECONDS,
  DEFAULT_TABLE_DENSITY,
  filterReportList,
  filterReportRows,
  formatRefreshIntervalLabel,
  getTableDensitySpec,
  mergeHistoricalCsvRows,
  normalizeRefreshIntervalSeconds,
  normalizeTableDensity,
  pruneReportSelection,
  REPORTS_REFRESH_INTERVAL_OPTIONS,
  serializeHistoricalSummaryCsv,
  TABLE_DENSITY_OPTIONS,
  toggleReportSelection,
  toggleSelectAllReports,
  type ReportMeta,
  type TableDensity,
  type VerdictFilterOption,
} from '../utils/reportsAnalytics';
import { exportDashboardSummaryPdf, exportReportsDashboardPdf } from '../utils/reportPdf';
import {
  buildShareReportMessage,
  SHARE_TTL_OPTIONS,
  type SharedReportSnapshot,
} from '../utils/reportSharing';
import { copyToClipboard } from '../utils/clipboard';
import type { EmailAlertRecord } from '../utils/emailAlerts';
import type { LookupResult } from '../utils/indicators';
import type { RecentInvestigationEntry } from '../utils/investigationHistory';
import type { ThemeMode } from '../utils/theme';
import { IocRegionHeatmap } from './IocRegionHeatmap';
import { LiveActivityFeed } from './LiveActivityFeed';
import { RecentHistoryDashboardPanel } from './RecentHistoryDashboardPanel';
import { RelationshipGraphWidget } from './RelationshipGraphWidget';
import { RiskScoreHeatmap } from './RiskScoreHeatmap';
import { ThreatLandscapeWidget } from './ThreatLandscapeWidget';
import { maskIndicatorValue, maskSensitiveText } from '../utils/privacyMode';
import { usePrivacyMode } from './PrivacyModeContext';

type ChartScope = 'malicious_clean' | 'all_verdicts';
type TrendMode = 'total' | 'severity';
type ToastVariant = 'info' | 'success' | 'error';

interface ToastNotification {
  id: string;
  variant: ToastVariant;
  title: string;
  detail: string;
}

export interface ReportsNavigationTarget {
  reportName?: string | null;
  searchQuery?: string;
  nonce: number;
}

interface ReportsViewProps {
  theme?: ThemeMode;
  navigationTarget?: ReportsNavigationTarget | null;
  currentResults?: LookupResult[];
  recentInvestigations?: RecentInvestigationEntry[];
  dispatchedEmailAlerts?: EmailAlertRecord[];
  activeRegionFilter?: string | null;
  onFilterRecentByRegion?: (regionLabel: string | null, options?: { navigate?: boolean }) => void;
  sharedReportSnapshot?: SharedReportSnapshot | null;
  sharedReportError?: string | null;
  onDismissSharedReport?: () => void;
  onOpenInvestigation?: (entry: RecentInvestigationEntry) => void;
  onNavigateToInvestigate?: () => void;
}

function renderInlineSummaryTokens(text: string): ReactNode[] {
  const tokens = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return tokens.map((part, idx) => {
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      return (
        <strong key={idx} className="font-semibold text-slate-950 dark:text-slate-50">
          {part.slice(2, -2)}
        </strong>
      );
    }
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
      return (
        <code
          key={idx}
          className="rounded bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-xs text-slate-900 dark:text-slate-100"
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    return <span key={idx}>{part}</span>;
  });
}

function renderExecutiveSummaryContent(summary: string): ReactNode {
  const lines = summary.split(/\r?\n/);
  const blocks: ReactNode[] = [];
  let bulletBuffer: string[] = [];

  const flushBullets = (keyPrefix: string) => {
    if (bulletBuffer.length === 0) return;
    blocks.push(
      <ul key={keyPrefix} className="list-disc pl-5 space-y-1.5">
        {bulletBuffer.map((item, idx) => (
          <li key={idx} className="text-sm leading-relaxed text-slate-700 dark:text-slate-300">
            {renderInlineSummaryTokens(item)}
          </li>
        ))}
      </ul>,
    );
    bulletBuffer = [];
  };

  lines.forEach((rawLine, idx) => {
    const trimmed = rawLine.trim();
    if (!trimmed) {
      flushBullets(`ul-gap-${idx}`);
      return;
    }
    const bulletMatch = trimmed.match(/^(?:[-*]|\u2022)\s+(.*)$/);
    if (bulletMatch) {
      bulletBuffer.push(bulletMatch[1]);
      return;
    }
    flushBullets(`ul-${idx}`);
    const isHeadingLine =
      /^#{1,4}\s+/.test(trimmed) ||
      (/^\*\*\d+\)/.test(trimmed) && trimmed.endsWith('**')) ||
      /^\d+\)\s+[A-Z]/.test(trimmed);
    const cleanedHeading = trimmed.replace(/^#{1,4}\s+/, '');
    if (isHeadingLine && trimmed.length < 90) {
      blocks.push(
        <h3
          key={`h-${idx}`}
          className="pt-1 text-xs font-semibold uppercase tracking-wide text-slate-900 dark:text-slate-100"
        >
          {renderInlineSummaryTokens(cleanedHeading)}
        </h3>,
      );
    } else {
      blocks.push(
        <p key={`p-${idx}`} className="text-sm leading-relaxed text-slate-700 dark:text-slate-300">
          {renderInlineSummaryTokens(trimmed)}
        </p>,
      );
    }
  });

  flushBullets('ul-end');
  return <div className="space-y-2.5">{blocks}</div>;
}

export function ReportsView({
  theme = 'light',
  navigationTarget,
  currentResults = [],
  recentInvestigations = [],
  dispatchedEmailAlerts = [],
  activeRegionFilter = null,
  onFilterRecentByRegion,
  sharedReportSnapshot = null,
  sharedReportError = null,
  onDismissSharedReport,
  onOpenInvestigation,
  onNavigateToInvestigate,
}: ReportsViewProps) {
  const privacyMode = usePrivacyMode();
  const isDark = theme === 'dark';
  const [reports, setReports] = useState<ReportMeta[]>([]);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [rows, setRows] = useState<Record<string, string>[]>([]);
  const [allRunRows, setAllRunRows] = useState<Record<string, string>[]>([]);
  const [allRunsCount, setAllRunsCount] = useState<number>(0);
  const [loadingHeatmapRows, setLoadingHeatmapRows] = useState(true);
  const [loadingList, setLoadingList] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [loadingRows, setLoadingRows] = useState(false);
  const [exportingCsv, setExportingCsv] = useState(false);
  const [exportingSelectedCsv, setExportingSelectedCsv] = useState(false);
  const [exportingPdf, setExportingPdf] = useState(false);
  const [exportingSummaryPdf, setExportingSummaryPdf] = useState(false);
  const [selectedForExport, setSelectedForExport] = useState<string[]>([]);
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(true);
  const [refreshIntervalSec, setRefreshIntervalSec] = useState<number>(DEFAULT_REPORTS_REFRESH_SECONDS);
  const [tableDensity, setTableDensity] = useState<TableDensity>(DEFAULT_TABLE_DENSITY);
  const [lastRefreshedAt, setLastRefreshedAt] = useState<string | null>(null);
  const [chartScope, setChartScope] = useState<ChartScope>('malicious_clean');
  const [trendMode, setTrendMode] = useState<TrendMode>('total');
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilterOption>('All');
  const [aiSummary, setAiSummary] = useState<string | null>(null);
  const [aiSummaryMeta, setAiSummaryMeta] = useState<{ model: string; generatedAt: string } | null>(null);
  const [generatingSummary, setGeneratingSummary] = useState(false);
  const [aiSummaryError, setAiSummaryError] = useState<string | null>(null);
  const [copiedSummary, setCopiedSummary] = useState(false);

  const [shareModalOpen, setShareModalOpen] = useState(false);
  const [shareTtlHours, setShareTtlHours] = useState<number>(24);
  const [creatingShare, setCreatingShare] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [createdShareSnapshot, setCreatedShareSnapshot] = useState<SharedReportSnapshot | null>(null);
  const [createdShareUrl, setCreatedShareUrl] = useState<string | null>(null);
  const [copiedShareLink, setCopiedShareLink] = useState(false);
  const [copiedShareMessage, setCopiedShareMessage] = useState(false);

  const [toasts, setToasts] = useState<ToastNotification[]>([]);
  const toastTimersRef = useRef<Map<string, number>>(new Map());
  const selectedNameRef = useRef<string | null>(null);
  const refreshInFlightRef = useRef(false);

  function scheduleToastAutoDismiss(id: string, durationMs = 4500) {
    const existing = toastTimersRef.current.get(id);
    if (existing !== undefined) {
      window.clearTimeout(existing);
    }
    const handle = window.setTimeout(() => {
      setToasts((prev) => prev.filter((item) => item.id !== id));
      toastTimersRef.current.delete(id);
    }, durationMs);
    toastTimersRef.current.set(id, handle);
  }

  function pushToast(
    notification: Omit<ToastNotification, 'id'>,
    options: { id?: string; durationMs?: number } = {},
  ): string {
    const id = options.id || `toast-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`;
    setToasts((prev) => {
      const exists = prev.some((item) => item.id === id);
      if (exists) {
        return prev.map((item) => (item.id === id ? { ...notification, id } : item));
      }
      return [...prev.slice(-2), { ...notification, id }];
    });
    scheduleToastAutoDismiss(id, options.durationMs ?? 4500);
    return id;
  }

  function dismissToast(id: string) {
    const existing = toastTimersRef.current.get(id);
    if (existing !== undefined) {
      window.clearTimeout(existing);
      toastTimersRef.current.delete(id);
    }
    setToasts((prev) => prev.filter((item) => item.id !== id));
  }

  async function handleDownloadHistoricalCsv() {
    if (reports.length === 0 || exportingCsv) return;
    setExportingCsv(true);

    const runLabel = `${reports.length} historical run${reports.length === 1 ? '' : 's'}`;
    const toastId = pushToast(
      {
        variant: 'info',
        title: 'CSV export started',
        detail: `Preparing soti_historical_analysis.csv (${runLabel})...`,
      },
      { durationMs: 8000 },
    );

    try {
      let csvText: string;
      const resp = await fetch('/api/reports/export/historical');
      if (resp.ok) {
        csvText = await resp.text();
      } else {
        csvText = serializeHistoricalSummaryCsv(reports);
      }
      const blob = new Blob([csvText], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'soti_historical_analysis.csv';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);

      pushToast(
        {
          variant: 'success',
          title: 'Report download started',
          detail: `soti_historical_analysis.csv (${runLabel})`,
        },
        { id: toastId, durationMs: 4500 },
      );
    } catch {
      pushToast(
        {
          variant: 'error',
          title: 'CSV export failed',
          detail: 'Unable to generate historical CSV export.',
        },
        { id: toastId, durationMs: 5000 },
      );
    } finally {
      setExportingCsv(false);
    }
  }

  async function handleDownloadSelectedCsv() {
    if (selectedForExport.length === 0 || exportingSelectedCsv) return;
    setExportingSelectedCsv(true);

    const count = selectedForExport.length;
    const filename = buildAggregatedCsvFilename(count);
    const runLabel = `${count} selected report${count === 1 ? '' : 's'}`;
    const toastId = pushToast(
      {
        variant: 'info',
        title: 'Aggregated CSV export started',
        detail: `Combining ${runLabel} into ${filename}...`,
      },
      { durationMs: 8000 },
    );

    try {
      let csvText: string;
      const resp = await fetch('/api/reports/export/historical', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ names: selectedForExport }),
      });

      if (resp.ok) {
        csvText = await resp.text();
      } else {
        const fetchedEntries = await Promise.all(
          [...selectedForExport].sort().map(async (name) => {
            const entryResp = await fetch(`/api/reports/${encodeURIComponent(name)}`);
            if (!entryResp.ok) return { name, rows: [] as Record<string, string>[] };
            const entryData = await entryResp.json();
            return { name, rows: (entryData.rows || []) as Record<string, string>[] };
          }),
        );
        csvText = mergeHistoricalCsvRows(fetchedEntries);
      }

      const blob = new Blob([csvText], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);

      pushToast(
        {
          variant: 'success',
          title: 'Aggregated CSV downloaded',
          detail: `${filename} (${runLabel})`,
        },
        { id: toastId, durationMs: 4500 },
      );
    } catch {
      pushToast(
        {
          variant: 'error',
          title: 'Aggregated CSV export failed',
          detail: 'Unable to aggregate selected historical reports.',
        },
        { id: toastId, durationMs: 5000 },
      );
    } finally {
      setExportingSelectedCsv(false);
    }
  }

  async function handleDownloadPdf() {
    if (reports.length === 0 || exportingPdf) return;
    setExportingPdf(true);

    const toastId = pushToast(
      {
        variant: 'info',
        title: 'Generating PDF report',
        detail: 'Capturing analytics charts and current data table...',
      },
      { id: 'pdf-export-toast', durationMs: 12000 },
    );

    try {
      const result = await exportReportsDashboardPdf({
        reports,
        filteredReports,
        selectedName,
        allRowsCount: rows.length,
        filteredRows,
        confidenceMap,
        searchQuery,
        verdictFilter,
        quickStats,
        totals,
        trendSummary,
      });

      pushToast(
        {
          variant: 'success',
          title: 'PDF report downloaded',
          detail: `${result.filename} (${result.pageCount} page${result.pageCount === 1 ? '' : 's'})`,
        },
        { id: toastId, durationMs: 4500 },
      );
    } catch {
      pushToast(
        {
          variant: 'error',
          title: 'PDF export failed',
          detail: 'Unable to generate downloadable PDF report.',
        },
        { id: toastId, durationMs: 5000 },
      );
    } finally {
      setExportingPdf(false);
    }
  }

  async function handleDownloadSummaryPdf() {
    if ((reports.length === 0 && currentResults.length === 0) || exportingSummaryPdf) return;
    setExportingSummaryPdf(true);

    const toastId = pushToast(
      {
        variant: 'info',
        title: 'Generating summary report',
        detail: 'Consolidating risk trendline, heatmap distribution, and top malicious indicators...',
      },
      { id: 'summary-pdf-export-toast', durationMs: 12000 },
    );

    try {
      const result = await exportDashboardSummaryPdf({
        reports,
        allRunRows,
        selectedRows: rows,
        currentResults,
        quickStats,
        totals,
        trendSeries,
        trendSummary,
        aiSummary,
        privacyMode,
      });

      pushToast(
        {
          variant: 'success',
          title: 'Summary PDF downloaded',
          detail: `${result.filename} (${result.pageCount} page${result.pageCount === 1 ? '' : 's'})`,
        },
        { id: toastId, durationMs: 4500 },
      );
    } catch {
      pushToast(
        {
          variant: 'error',
          title: 'Summary PDF export failed',
          detail: 'Unable to generate consolidated risk summary PDF.',
        },
        { id: toastId, durationMs: 5000 },
      );
    } finally {
      setExportingSummaryPdf(false);
    }
  }

  async function handleGenerateExecutiveSummary() {
    if (reports.length === 0 || generatingSummary) return;
    setGeneratingSummary(true);
    setAiSummaryError(null);
    setCopiedSummary(false);

    try {
      const rowsSample = filteredRows.slice(0, 35).map((r) => {
        const conf = confidenceMap.get((r.indicator || '').trim().toLowerCase());
        return {
          indicator: r.indicator || '',
          type: r.type || '',
          source: r.source || '',
          verdict: r.status === 'ok' ? r.verdict : r.status,
          score: r.score || '',
          confidenceScore: conf?.score ?? null,
          summary: r.summary || '',
        };
      });

      const resp = await fetch('/api/reports/executive-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reportName: selectedName,
          verdictFilter,
          searchQuery,
          quickStats,
          totals,
          trendSummary,
          rowsSample,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        const msg = data?.error || 'Unable to generate AI executive summary.';
        setAiSummaryError(msg);
        pushToast({
          variant: 'error',
          title: 'Executive summary unavailable',
          detail: msg,
        });
        return;
      }

      setAiSummary(String(data.summary || ''));
      setAiSummaryMeta({
        model: String(data.model || 'Gemini'),
        generatedAt: String(data.generatedAt || new Date().toISOString()),
      });
      pushToast({
        variant: 'success',
        title: 'AI executive summary ready',
        detail: `Synthesized ${filteredRows.length} visible row(s) with Gemini`,
      });
    } catch {
      const msg = 'Network error while requesting Gemini AI executive summary.';
      setAiSummaryError(msg);
      pushToast({
        variant: 'error',
        title: 'Summary request failed',
        detail: msg,
      });
    } finally {
      setGeneratingSummary(false);
    }
  }

  async function handleCreateShareSnapshot() {
    if (creatingShare) return;
    setCreatingShare(true);
    setShareError(null);
    setCopiedShareLink(false);
    setCopiedShareMessage(false);

    try {
      const seenIndicators = new Set<string>();
      const topIndicators: SharedReportSnapshot['topIndicators'] = [];
      for (const r of filteredRows) {
        const ind = (r.indicator || '').trim();
        const key = ind.toLowerCase();
        if (!ind || seenIndicators.has(key)) continue;
        seenIndicators.add(key);
        const conf = confidenceMap.get(key);
        topIndicators.push({
          indicator: ind,
          type: r.type || 'ioc',
          confidenceScore: conf?.score ?? null,
          verdictSummary: r.status === 'ok' ? r.verdict || 'Unknown' : r.status || 'Unknown',
        });
        if (topIndicators.length >= 6) break;
      }

      const resp = await fetch('/api/reports/share', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ttlHours: shareTtlHours,
          reportName: selectedName,
          searchQuery,
          verdictFilter,
          quickStats,
          totals,
          topIndicators,
          executiveSummary: aiSummary,
        }),
      });
      const data = await resp.json();
      if (!resp.ok || !data?.snapshot) {
        setShareError(data?.error || 'Failed to generate temporary share link.');
        return;
      }

      const origin = typeof window !== 'undefined' ? window.location.origin : '';
      const url = `${origin}${data.sharePath}`;
      setCreatedShareSnapshot(data.snapshot);
      setCreatedShareUrl(url);
      pushToast({
        variant: 'success',
        title: 'Shareable report link created',
        detail: `Expires in ${data.snapshot.ttlHours}h`,
      });
    } catch {
      setShareError('Unable to reach server to create share link.');
    } finally {
      setCreatingShare(false);
    }
  }

  async function loadReports(options: { silent?: boolean } = {}) {
    if (refreshInFlightRef.current) return;
    refreshInFlightRef.current = true;

    const isInitialLoad = !options.silent && reports.length === 0;
    if (isInitialLoad) {
      setLoadingList(true);
    } else {
      setRefreshing(true);
    }

    try {
      const resp = await fetch('/api/reports');
      const data = await resp.json();
      const list: ReportMeta[] = data.reports || [];
      setReports(list);
      setLastRefreshedAt(new Date().toISOString().slice(11, 19));

      const currentSelected = selectedNameRef.current;
      if (list.length > 0 && !currentSelected) {
        await selectReport(list[0].name);
      } else if (currentSelected && list.some((r) => r.name === currentSelected)) {
        const rowsResp = await fetch(`/api/reports/${encodeURIComponent(currentSelected)}`);
        if (rowsResp.ok) {
          const rowsData = await rowsResp.json();
          setRows(rowsData.rows || []);
        }
      }

      fetch('/api/reports/all-rows')
        .then((r) => (r.ok ? r.json() : null))
        .then((allData) => {
          if (allData && Array.isArray(allData.rows)) {
            setAllRunRows(allData.rows);
            setAllRunsCount(Number(allData.reportCount || list.length));
          }
        })
        .catch(() => {})
        .finally(() => setLoadingHeatmapRows(false));
    } finally {
      refreshInFlightRef.current = false;
      setLoadingList(false);
      setRefreshing(false);
    }
  }

  async function selectReport(name: string) {
    selectedNameRef.current = name;
    setSelectedName(name);
    setLoadingRows(true);
    try {
      const resp = await fetch(`/api/reports/${encodeURIComponent(name)}`);
      const data = await resp.json();
      setRows(data.rows || []);
    } finally {
      setLoadingRows(false);
    }
  }

  useEffect(() => {
    selectedNameRef.current = selectedName;
  }, [selectedName]);

  useEffect(() => {
    loadReports();
    return () => {
      for (const timer of toastTimersRef.current.values()) {
        window.clearTimeout(timer);
      }
      toastTimersRef.current.clear();
    };
  }, []);

  useEffect(() => {
    if (!autoRefreshEnabled) return;
    const timer = window.setInterval(() => {
      loadReports({ silent: true });
    }, refreshIntervalSec * 1000);
    return () => window.clearInterval(timer);
  }, [autoRefreshEnabled, refreshIntervalSec]);

  useEffect(() => {
    if (!navigationTarget) return;
    setVerdictFilter('All');
    if (typeof navigationTarget.searchQuery === 'string') {
      setSearchQuery(navigationTarget.searchQuery);
    }
    if (navigationTarget.reportName) {
      selectReport(navigationTarget.reportName);
    }
  }, [navigationTarget?.nonce]);

  const { series, totals } = useMemo(
    () => buildHistoricalChartData(reports),
    [reports],
  );

  const quickStats = useMemo(
    () => computeReportsQuickStats(reports),
    [reports],
  );

  const { series: trendSeries, summary: trendSummary } = useMemo(
    () => buildThreatAlertTrend30Days(reports),
    [reports],
  );

  const { trendTicks, trendLabelMap } = useMemo(() => {
    const labelMap = new Map<string, string>();
    for (const point of trendSeries) {
      labelMap.set(point.dateKey, point.label);
    }
    const tickIndices = [0, 6, 12, 18, 24, 29];
    const ticks = tickIndices
      .map((idx) => trendSeries[idx]?.dateKey)
      .filter((k): k is string => Boolean(k));
    return { trendTicks: ticks, trendLabelMap: labelMap };
  }, [trendSeries]);

  const filteredReports = useMemo(
    () => filterReportList(reports, searchQuery, verdictFilter),
    [reports, searchQuery, verdictFilter],
  );

  const allFilteredSelected = useMemo(
    () => areAllVisibleReportsSelected(selectedForExport, filteredReports),
    [selectedForExport, filteredReports],
  );

  useEffect(() => {
    setSelectedForExport((prev) => pruneReportSelection(prev, reports));
  }, [reports]);

  const filteredRows = useMemo(
    () => filterReportRows(rows, searchQuery, verdictFilter),
    [rows, searchQuery, verdictFilter],
  );

  const confidenceMap = useMemo(
    () => computeIndicatorConfidenceMap(rows),
    [rows],
  );

  useEffect(() => {
    if (
      filteredReports.length > 0 &&
      (!selectedName || !filteredReports.some((r) => r.name === selectedName))
    ) {
      selectReport(filteredReports[0].name);
    }
  }, [filteredReports, selectedName]);

  const hasActiveFilters = searchQuery.trim().length > 0 || verdictFilter !== 'All';
  const densitySpec = useMemo(() => getTableDensitySpec(tableDensity), [tableDensity]);

  const chartGridColor = isDark ? '#1E293B' : '#E2E8F0';
  const chartTickColor = isDark ? '#94A3B8' : '#64748B';
  const chartDotStroke = isDark ? '#0F172A' : '#FFFFFF';
  const tooltipStyle = {
    backgroundColor: isDark ? '#0F172A' : '#FFFFFF',
    border: isDark ? '1px solid #334155' : '1px solid #E2E8F0',
    borderRadius: '8px',
    fontSize: '12px',
    color: isDark ? '#F1F5F9' : '#0F172A',
    boxShadow: isDark ? '0 4px 12px rgba(0, 0, 0, 0.45)' : '0 4px 12px rgba(15, 23, 42, 0.06)',
  };

  return (
    <div className="space-y-6 print:space-y-4">
      <div className="hidden print:flex print:items-end print:justify-between print:border-b-2 print:border-red-600 print:pb-3">
        <div>
          <h1 className="text-lg font-bold tracking-tight text-slate-950">
            SoTI Threat Intelligence Report
          </h1>
          <p className="mt-0.5 text-xs text-slate-600">
            Dashboard Analytics &amp; Historical Indicator Archive
            {selectedName ? ` · Active Run: ${selectedName}` : ''}
          </p>
        </div>
        <div className="text-right font-mono text-[11px] text-slate-600 tabular-nums">
          <div>Generated {new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC</div>
          <div>
            {filteredReports.length} of {reports.length} run{reports.length === 1 ? '' : 's'}
            {hasActiveFilters ? ` · Filter: ${verdictFilter}` : ''}
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-4 print:hidden">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-950 dark:text-slate-50">CSV Reports Archive</h1>
          <p className="mt-0.5 text-sm text-slate-600 dark:text-slate-400">
            UTF-8-SIG exports saved automatically to the <code className="font-mono text-xs">reports/</code> directory
            {lastRefreshedAt && (
              <span className="font-mono text-xs text-slate-500 dark:text-slate-400 tabular-nums">
                {' '}· Updated {lastRefreshedAt} UTC
              </span>
            )}
            .
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 print:hidden">
          <div className="inline-flex items-center rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
            <button
              type="button"
              role="switch"
              aria-checked={autoRefreshEnabled}
              aria-label="Toggle automatic periodic refresh"
              data-testid="reports-auto-refresh-toggle"
              onClick={() => setAutoRefreshEnabled((prev) => !prev)}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 rounded-l-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
            >
              <span
                aria-hidden="true"
                className={`relative inline-flex h-4 w-7 shrink-0 items-center rounded-full transition-colors ${
                  autoRefreshEnabled
                    ? 'bg-emerald-600 dark:bg-emerald-500'
                    : 'bg-slate-300 dark:bg-slate-700'
                }`}
              >
                <span
                  className={`inline-block h-3 w-3 rounded-full bg-white transition-transform ${
                    autoRefreshEnabled ? 'translate-x-3.5' : 'translate-x-0.5'
                  }`}
                />
              </span>
              <span>Auto-refresh</span>
            </button>

            <span className="h-4 w-px bg-slate-200 dark:bg-slate-800" aria-hidden="true" />

            <select
              aria-label="Auto-refresh interval"
              data-testid="reports-auto-refresh-interval"
              value={refreshIntervalSec}
              disabled={!autoRefreshEnabled}
              onChange={(e) => setRefreshIntervalSec(normalizeRefreshIntervalSeconds(e.target.value))}
              className="rounded-r-lg bg-transparent px-2 py-1.5 font-mono text-xs font-medium text-slate-700 dark:text-slate-200 focus:outline-none disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed tabular-nums"
            >
              {REPORTS_REFRESH_INTERVAL_OPTIONS.map((sec) => (
                <option key={sec} value={sec} className="bg-white dark:bg-slate-900">
                  {formatRefreshIntervalLabel(sec)}
                </option>
              ))}
            </select>
          </div>

          <div className="inline-flex items-center rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
            <label
              htmlFor="reports-table-density"
              className="pl-2.5 pr-1 py-1.5 text-xs font-medium text-slate-500 dark:text-slate-400 whitespace-nowrap select-none"
            >
              Density
            </label>
            <select
              id="reports-table-density"
              data-testid="reports-density-select"
              aria-label="Reports table density"
              value={tableDensity}
              onChange={(e) => setTableDensity(normalizeTableDensity(e.target.value))}
              className="rounded-r-lg bg-transparent pr-2 py-1.5 text-xs font-medium text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer"
            >
              {TABLE_DENSITY_OPTIONS.map((opt) => (
                <option key={opt.id} value={opt.id} className="bg-white dark:bg-slate-900">
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <button
            type="button"
            onClick={() => loadReports()}
            disabled={refreshing}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
            Refresh
          </button>

          <button
            type="button"
            data-testid="generate-ai-summary-btn"
            onClick={handleGenerateExecutiveSummary}
            disabled={reports.length === 0 || generatingSummary}
            aria-label="Generate AI executive summary"
            title="Use Gemini AI to draft an executive summary from visible investigation data and charts"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-semibold text-slate-800 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-100"
          >
            {generatingSummary ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-red-600 dark:text-red-400" aria-hidden="true" />
            ) : (
              <Sparkles className="h-3.5 w-3.5 text-red-600 dark:text-red-400" aria-hidden="true" />
            )}
            <span>{generatingSummary ? 'Generating...' : 'Generate Summary'}</span>
          </button>

          <button
            type="button"
            data-testid="share-report-button"
            onClick={() => {
              setShareError(null);
              setShareModalOpen(true);
            }}
            disabled={reports.length === 0}
            aria-label="Share Report"
            title="Create a temporary shareable link or copy formatted report message"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-semibold text-slate-800 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-100"
          >
            <Share2 className="h-3.5 w-3.5 text-slate-600 dark:text-slate-400" aria-hidden="true" />
            <span>Share Report</span>
          </button>

          <button
            type="button"
            data-testid="download-summary-button"
            onClick={handleDownloadSummaryPdf}
            disabled={(reports.length === 0 && currentResults.length === 0) || exportingSummaryPdf}
            aria-label="Download Summary"
            title="Download consolidated risk trendline, heatmap distribution, and top malicious indicators PDF"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-semibold text-slate-800 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-100"
          >
            {exportingSummaryPdf ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-red-600 dark:text-red-400" aria-hidden="true" />
            ) : (
              <FileText className="h-3.5 w-3.5 text-red-600 dark:text-red-400" aria-hidden="true" />
            )}
            <span>{exportingSummaryPdf ? 'Summarizing...' : 'Download Summary'}</span>
          </button>

          <button
            type="button"
            data-testid="download-pdf-button"
            onClick={handleDownloadPdf}
            disabled={reports.length === 0 || exportingPdf}
            aria-label="Download PDF"
            title="Download current dashboard charts and data table as PDF"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-semibold text-slate-800 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-100"
          >
            {exportingPdf ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-slate-600 dark:text-slate-300" aria-hidden="true" />
            ) : (
              <FileText className="h-3.5 w-3.5 text-slate-600 dark:text-slate-400" aria-hidden="true" />
            )}
            <span>{exportingPdf ? 'Generating PDF...' : 'Download PDF'}</span>
          </button>

          <button
            type="button"
            onClick={handleDownloadHistoricalCsv}
            disabled={reports.length === 0 || exportingCsv}
            className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3.5 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-red-700 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            {exportingCsv ? 'Exporting...' : 'Download as CSV'}
          </button>
        </div>
      </div>

      {sharedReportError && (
        <div
          role="alert"
          data-testid="shared-report-error-banner"
          className="flex items-center justify-between gap-3 rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 px-4 py-3 text-xs text-amber-950 dark:text-amber-100 print:hidden"
        >
          <span>{sharedReportError}</span>
          {onDismissSharedReport && (
            <button
              type="button"
              onClick={onDismissSharedReport}
              className="rounded p-1 hover:bg-amber-100 dark:hover:bg-amber-900/40 cursor-pointer"
              aria-label="Dismiss shared link notice"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          )}
        </div>
      )}

      {sharedReportSnapshot && (
        <section
          aria-label="Shared Report Snapshot"
          data-testid="shared-report-banner"
          className="rounded-xl border border-red-200 dark:border-red-900/60 bg-red-50/60 dark:bg-red-950/30 p-5 space-y-3"
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <Link2 className="h-4 w-4 text-red-600 dark:text-red-400 shrink-0" aria-hidden="true" />
                <h2 className="text-sm font-bold text-slate-950 dark:text-slate-50">
                  Shared Report Snapshot
                  {sharedReportSnapshot.reportName ? ` — ${sharedReportSnapshot.reportName}` : ''}
                </h2>
              </div>
              <p className="font-mono text-[11px] text-slate-600 dark:text-slate-400 tabular-nums">
                Shared {sharedReportSnapshot.createdAt.slice(0, 16).replace('T', ' ')} UTC · Expires{' '}
                {sharedReportSnapshot.expiresAt.slice(0, 16).replace('T', ' ')} UTC
              </p>
            </div>
            {onDismissSharedReport && (
              <button
                type="button"
                data-testid="dismiss-shared-report-banner"
                onClick={onDismissSharedReport}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Exit Shared View</span>
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-x-5 gap-y-1 font-mono text-xs text-slate-800 dark:text-slate-200 tabular-nums">
            <span>{sharedReportSnapshot.quickStats.uniqueIndicatorsCount} unique IOCs</span>
            <span className="text-red-700 dark:text-red-400 font-semibold">
              {sharedReportSnapshot.totals.malicious} Malicious ({sharedReportSnapshot.quickStats.maliciousPercentage}%)
            </span>
            <span className="text-amber-700 dark:text-amber-400">
              {sharedReportSnapshot.totals.suspicious} Suspicious
            </span>
            <span className="text-emerald-700 dark:text-emerald-400">
              {sharedReportSnapshot.totals.clean} Clean
            </span>
          </div>

          {sharedReportSnapshot.topIndicators.length > 0 && (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-700 dark:text-slate-300">
              <span className="font-semibold">Top Indicators:</span>
              {sharedReportSnapshot.topIndicators.slice(0, 5).map((item) => (
                <span key={item.indicator} className="font-mono">
                  {maskIndicatorValue(item.indicator, null, privacyMode)}{' '}
                  <span className="text-slate-500 dark:text-slate-400">
                    ({item.confidenceScore !== null ? `${item.confidenceScore}/100 · ` : ''}
                    {item.verdictSummary})
                  </span>
                </span>
              ))}
            </div>
          )}

          {sharedReportSnapshot.executiveSummary && (
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-3.5 text-xs leading-relaxed text-slate-800 dark:text-slate-200 whitespace-pre-wrap">
              {maskSensitiveText(sharedReportSnapshot.executiveSummary, privacyMode)}
            </div>
          )}
        </section>
      )}

      {loadingList ? (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-8 text-sm text-slate-500 dark:text-slate-400">
          Loading reports...
        </div>
      ) : reports.length === 0 ? (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-6 py-12 text-center">
            <FileSpreadsheet className="mx-auto h-8 w-8 text-slate-400 dark:text-slate-500" aria-hidden="true" />
            <h2 className="mt-3 text-base font-semibold text-slate-900 dark:text-slate-100">No CSV reports yet</h2>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
              Run an enrichment lookup from the Investigate tab to generate a report.
            </p>
          </div>

          <LiveActivityFeed
            reports={reports}
            recentInvestigations={recentInvestigations}
            dispatchedEmailAlerts={dispatchedEmailAlerts}
            onInspectIndicator={(indicator) => {
              setVerdictFilter('All');
              setSearchQuery(indicator);
            }}
            onSelectReport={(reportName) => {
              selectReport(reportName);
            }}
          />

          {currentResults.length > 0 && (
            <RiskScoreHeatmap
              reports={reports}
              allRunRows={allRunRows}
              currentResults={currentResults}
              selectedRunName={selectedName}
              theme={theme}
              loading={loadingHeatmapRows}
              onSelectReport={(reportName) => {
                selectReport(reportName);
              }}
              onInspectIndicator={(indicator) => {
                setVerdictFilter('All');
                setSearchQuery(indicator);
              }}
            />
          )}

          <RecentHistoryDashboardPanel
            entries={recentInvestigations}
            onOpenInvestigation={onOpenInvestigation}
            onNavigateToInvestigate={onNavigateToInvestigate}
            onExportSuccess={({ filename, count }) =>
              pushToast({
                variant: 'success',
                title: 'Investigation history exported',
                detail: `${filename} (${count} investigation ID${count === 1 ? '' : 's'})`,
              })
            }
          />
        </div>
      ) : (
        <>
          <section
            aria-label="Quick Stats"
            data-testid="reports-quick-stats"
            className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 print:border-slate-300"
          >
            <dl className="grid divide-y divide-slate-100 dark:divide-slate-800 sm:grid-cols-3 sm:divide-x sm:divide-y-0 print:grid-cols-3 print:divide-x print:divide-y-0">
              <div className="px-5 py-4 md:px-6 md:py-5">
                <dt className="text-xs font-medium text-slate-500 dark:text-slate-400">Total Threats Analyzed</dt>
                <dd className="mt-1 font-mono text-2xl font-bold text-slate-950 dark:text-slate-50 tabular-nums">
                  {quickStats.totalThreatsAnalyzed}
                </dd>
                <dd className="mt-1 font-mono text-xs text-slate-500 dark:text-slate-400 tabular-nums">
                  {quickStats.uniqueIndicatorsCount} unique IOCs · {quickStats.totalRuns} report
                  {quickStats.totalRuns === 1 ? '' : 's'}
                </dd>
              </div>

              <div className="px-5 py-4 md:px-6 md:py-5">
                <dt className="text-xs font-medium text-slate-500 dark:text-slate-400">Malicious Findings</dt>
                <dd className="mt-1 font-mono text-2xl font-bold text-red-700 dark:text-red-400 tabular-nums">
                  {quickStats.maliciousPercentage}%
                </dd>
                <dd className="mt-1 font-mono text-xs text-slate-500 dark:text-slate-400 tabular-nums">
                  {quickStats.maliciousCount} malicious of {quickStats.evaluatedVerdictsCount} verdicts
                </dd>
              </div>

              <div className="px-5 py-4 md:px-6 md:py-5">
                <dt className="text-xs font-medium text-slate-500 dark:text-slate-400">Top Queried Indicator Type</dt>
                <dd className="mt-1 flex items-baseline gap-2">
                  <span className="text-2xl font-bold tracking-tight text-slate-950 dark:text-slate-50">
                    {quickStats.topIndicatorLabel}
                  </span>
                  {quickStats.topIndicatorType && (
                    <span className="font-mono text-xs font-medium text-slate-500 dark:text-slate-400 tabular-nums">
                      ({quickStats.topIndicatorShare}%)
                    </span>
                  )}
                </dd>
                <dd className="mt-1 font-mono text-xs text-slate-500 dark:text-slate-400 tabular-nums">
                  {quickStats.typeCounts.ip} IP · {quickStats.typeCounts.domain} Domain ·{' '}
                  {quickStats.typeCounts.hash} Hash
                </dd>
              </div>
            </dl>
          </section>

          <LiveActivityFeed
            reports={reports}
            recentInvestigations={recentInvestigations}
            dispatchedEmailAlerts={dispatchedEmailAlerts}
            onInspectIndicator={(indicator) => {
              setVerdictFilter('All');
              setSearchQuery(indicator);
            }}
            onSelectReport={(reportName) => {
              selectReport(reportName);
            }}
          />

          {(aiSummary || aiSummaryError || generatingSummary) && (
            <section
              aria-label="AI Executive Summary"
              data-testid="ai-executive-summary-card"
              className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 md:p-6 space-y-3"
            >
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 dark:border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-red-600 dark:text-red-400 shrink-0" aria-hidden="true" />
                  <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">
                    AI Executive Summary
                  </h2>
                  {aiSummaryMeta && (
                    <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                      · {aiSummaryMeta.model} · {aiSummaryMeta.generatedAt.slice(11, 16)} UTC
                    </span>
                  )}
                </div>

                {aiSummary && (
                  <div className="flex items-center gap-2 shrink-0 print:hidden">
                    <button
                      type="button"
                      data-testid="copy-ai-summary-btn"
                      onClick={async () => {
                        const ok = await copyToClipboard(aiSummary);
                        if (ok) {
                          setCopiedSummary(true);
                          window.setTimeout(() => setCopiedSummary(false), 2000);
                        }
                      }}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 cursor-pointer"
                    >
                      {copiedSummary ? (
                        <>
                          <Check className="h-3.5 w-3.5 text-emerald-600" aria-hidden="true" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>Copy Summary</span>
                        </>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setAiSummary(null);
                        setAiSummaryError(null);
                      }}
                      aria-label="Close AI executive summary"
                      className="rounded-lg p-1 text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer"
                    >
                      <X className="h-4 w-4" aria-hidden="true" />
                    </button>
                  </div>
                )}
              </div>

              {generatingSummary ? (
                <div className="flex items-center gap-2 py-2 text-xs text-slate-600 dark:text-slate-400">
                  <Loader2 className="h-4 w-4 animate-spin text-red-600" aria-hidden="true" />
                  <span>Synthesizing investigation findings and trend telemetry with Gemini AI...</span>
                </div>
              ) : aiSummaryError ? (
                <div
                  role="alert"
                  data-testid="ai-summary-error"
                  className="rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 px-4 py-3 text-xs text-amber-900 dark:text-amber-200"
                >
                  {aiSummaryError}
                </div>
              ) : (
                <div data-testid="ai-summary-content">
                  {renderExecutiveSummaryContent(maskSensitiveText(aiSummary || '', privacyMode))}
                </div>
              )}
            </section>
          )}

          <div className="grid gap-6 xl:grid-cols-2 print:grid-cols-2 print:gap-4">
            <section
              aria-label="Historical Verdict Distribution"
              className="min-w-0 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 md:p-6 print:border-slate-300 print:p-4"
            >
              <div className="flex flex-col gap-3 border-b border-slate-100 dark:border-slate-800 pb-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">
                    Verdict Distribution Across Runs
                  </h2>
                  <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                    Lookup verdicts per CSV run. Click a bar to inspect.
                  </p>
                </div>

                <div
                  className="inline-flex items-center rounded-lg bg-slate-100 dark:bg-slate-800 p-1 self-start sm:self-auto print:hidden"
                  role="group"
                  aria-label="Chart verdict scope"
                >
                  <button
                    type="button"
                    onClick={() => setChartScope('malicious_clean')}
                    className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      chartScope === 'malicious_clean'
                        ? 'bg-white dark:bg-slate-950 text-slate-950 dark:text-slate-50 shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                    }`}
                  >
                    Malicious vs Clean
                  </button>
                  <button
                    type="button"
                    onClick={() => setChartScope('all_verdicts')}
                    className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      chartScope === 'all_verdicts'
                        ? 'bg-white dark:bg-slate-950 text-slate-950 dark:text-slate-50 shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                    }`}
                  >
                    All Verdicts
                  </button>
                </div>
              </div>

              <dl className="grid grid-cols-2 gap-6 border-b border-slate-100 dark:border-slate-800 py-4 sm:grid-cols-4">
                <div>
                  <dt className="text-xs font-medium text-slate-500 dark:text-slate-400">Analysis Runs</dt>
                  <dd className="mt-1 font-mono text-2xl font-bold text-slate-950 dark:text-slate-50 tabular-nums">
                    {totals.runs}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-red-700 dark:text-red-400">Malicious</dt>
                  <dd className="mt-1 font-mono text-2xl font-bold text-red-700 dark:text-red-400 tabular-nums">
                    {totals.malicious}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-emerald-700 dark:text-emerald-400">Clean</dt>
                  <dd className="mt-1 font-mono text-2xl font-bold text-emerald-700 dark:text-emerald-400 tabular-nums">
                    {totals.clean}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-slate-500 dark:text-slate-400 whitespace-nowrap">Other / Susp.</dt>
                  <dd className="mt-1 font-mono text-2xl font-bold text-slate-700 dark:text-slate-300 tabular-nums">
                    {totals.suspicious + totals.unknown}
                  </dd>
                </div>
              </dl>

              <div className="mt-5 h-[240px] w-full" data-testid="verdict-history-chart">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={series}
                    margin={{ top: 8, right: 12, left: -12, bottom: 4 }}
                    onClick={(state: any) => {
                      const clickedName = state?.activePayload?.[0]?.payload?.name;
                      if (typeof clickedName === 'string') {
                        selectReport(clickedName);
                      }
                    }}
                  >
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke={chartGridColor} />
                    <XAxis
                      dataKey="label"
                      tick={{ fontSize: 11, fill: chartTickColor }}
                      tickLine={false}
                      axisLine={{ stroke: chartGridColor }}
                    />
                    <YAxis
                      allowDecimals={false}
                      tick={{ fontSize: 11, fill: chartTickColor }}
                      tickLine={false}
                      axisLine={false}
                    />
                    <Tooltip
                      cursor={{ fill: isDark ? '#1E293B' : '#F8FAFC' }}
                      contentStyle={tooltipStyle}
                      labelFormatter={(_label, payload) => {
                        const item = payload?.[0]?.payload;
                        return item ? `${item.name} (${item.total} rows)` : '';
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '8px', color: chartTickColor }} />
                    <Bar
                      dataKey="malicious"
                      name="Malicious"
                      fill="#DC2626"
                      radius={[4, 4, 0, 0]}
                      maxBarSize={42}
                      className="cursor-pointer"
                    />
                    <Bar
                      dataKey="clean"
                      name="Clean"
                      fill="#16A34A"
                      radius={[4, 4, 0, 0]}
                      maxBarSize={42}
                      className="cursor-pointer"
                    />
                    {chartScope === 'all_verdicts' && (
                      <Bar
                        dataKey="suspicious"
                        name="Suspicious"
                        fill="#D97706"
                        radius={[4, 4, 0, 0]}
                        maxBarSize={42}
                        className="cursor-pointer"
                      />
                    )}
                    {chartScope === 'all_verdicts' && (
                      <Bar
                        dataKey="unknown"
                        name="Unknown"
                        fill="#64748B"
                        radius={[4, 4, 0, 0]}
                        maxBarSize={42}
                        className="cursor-pointer"
                      />
                    )}
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </section>

            <section
              aria-label="30-Day Threat Alert Trend"
              className="min-w-0 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 md:p-6 print:border-slate-300 print:p-4"
            >
              <div className="flex flex-col gap-3 border-b border-slate-100 dark:border-slate-800 pb-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">
                    Threat Alerts (Last 30 Days)
                  </h2>
                  <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                    Daily Malicious &amp; Suspicious alerts over the last 30 days.
                  </p>
                </div>

                <div
                  className="inline-flex items-center rounded-lg bg-slate-100 dark:bg-slate-800 p-1 self-start sm:self-auto print:hidden"
                  role="group"
                  aria-label="Trend line metric mode"
                >
                  <button
                    type="button"
                    onClick={() => setTrendMode('total')}
                    className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      trendMode === 'total'
                        ? 'bg-white dark:bg-slate-950 text-slate-950 dark:text-slate-50 shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                    }`}
                  >
                    Total Alerts
                  </button>
                  <button
                    type="button"
                    onClick={() => setTrendMode('severity')}
                    className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      trendMode === 'severity'
                        ? 'bg-white dark:bg-slate-950 text-slate-950 dark:text-slate-50 shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                    }`}
                  >
                    By Severity
                  </button>
                </div>
              </div>

              <dl className="grid grid-cols-3 gap-4 border-b border-slate-100 dark:border-slate-800 py-4">
                <div>
                  <dt className="text-xs font-medium text-red-700 dark:text-red-400">30-Day Alerts</dt>
                  <dd className="mt-1 font-mono text-2xl font-bold text-red-700 dark:text-red-400 tabular-nums">
                    {trendSummary.totalAlerts}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-slate-500 dark:text-slate-400">Peak Day</dt>
                  <dd className="mt-1 flex items-baseline gap-1.5 font-mono text-2xl font-bold text-slate-950 dark:text-slate-50 tabular-nums">
                    <span>{trendSummary.peakAlerts}</span>
                    {trendSummary.peakAlerts > 0 && (
                      <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
                        ({trendSummary.peakDateLabel})
                      </span>
                    )}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-slate-500 dark:text-slate-400">Alert Days</dt>
                  <dd className="mt-1 font-mono text-2xl font-bold text-slate-700 dark:text-slate-300 tabular-nums">
                    {trendSummary.activeAlertDays}/30
                  </dd>
                </div>
              </dl>

              <div className="mt-5 h-[240px] w-full" data-testid="threat-alert-trend-chart">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={trendSeries}
                    margin={{ top: 8, right: 16, left: -12, bottom: 4 }}
                    onClick={(state: any) => {
                      const reportName = state?.activePayload?.[0]?.payload?.latestReportName;
                      if (typeof reportName === 'string') {
                        selectReport(reportName);
                      }
                    }}
                  >
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke={chartGridColor} />
                    <XAxis
                      dataKey="dateKey"
                      ticks={trendTicks}
                      tickFormatter={(val) => trendLabelMap.get(String(val)) ?? String(val)}
                      tick={{ fontSize: 11, fill: chartTickColor }}
                      tickLine={false}
                      axisLine={{ stroke: chartGridColor }}
                    />
                    <YAxis
                      allowDecimals={false}
                      tick={{ fontSize: 11, fill: chartTickColor }}
                      tickLine={false}
                      axisLine={false}
                    />
                    <Tooltip
                      contentStyle={tooltipStyle}
                      labelFormatter={(_label, payload) => {
                        const item = payload?.[0]?.payload;
                        if (!item) return '';
                        return `${item.displayDate} · ${item.runs} run${item.runs === 1 ? '' : 's'}`;
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '8px', color: chartTickColor }} />
                    {trendMode === 'total' ? (
                      <Line
                        type="monotone"
                        dataKey="threatAlerts"
                        name="Threat Alerts"
                        stroke="#DC2626"
                        strokeWidth={2.5}
                        dot={(props: any) => {
                          const { cx, cy, payload, index } = props;
                          if (typeof cx !== 'number' || typeof cy !== 'number') {
                            return <g key={index} />;
                          }
                          return (
                            <circle
                              key={payload?.dateKey ?? index}
                              cx={cx}
                              cy={cy}
                              r={payload?.threatAlerts > 0 ? 4 : 0}
                              fill="#DC2626"
                              stroke={chartDotStroke}
                              strokeWidth={1.5}
                            />
                          );
                        }}
                        activeDot={{ r: 5, fill: '#DC2626', stroke: chartDotStroke, strokeWidth: 2 }}
                      />
                    ) : (
                      <>
                        <Line
                          type="monotone"
                          dataKey="malicious"
                          name="Malicious"
                          stroke="#DC2626"
                          strokeWidth={2.25}
                          dot={(props: any) => {
                            const { cx, cy, payload, index } = props;
                            if (typeof cx !== 'number' || typeof cy !== 'number') {
                              return <g key={index} />;
                            }
                            return (
                              <circle
                                key={payload?.dateKey ?? index}
                                cx={cx}
                                cy={cy}
                                r={payload?.malicious > 0 ? 3.5 : 0}
                                fill="#DC2626"
                                stroke={chartDotStroke}
                                strokeWidth={1.5}
                              />
                            );
                          }}
                          activeDot={{ r: 5, fill: '#DC2626', stroke: chartDotStroke, strokeWidth: 2 }}
                        />
                        <Line
                          type="monotone"
                          dataKey="suspicious"
                          name="Suspicious"
                          stroke="#D97706"
                          strokeWidth={2}
                          strokeDasharray="4 3"
                          dot={(props: any) => {
                            const { cx, cy, payload, index } = props;
                            if (typeof cx !== 'number' || typeof cy !== 'number') {
                              return <g key={index} />;
                            }
                            return (
                              <circle
                                key={payload?.dateKey ?? index}
                                cx={cx}
                                cy={cy}
                                r={payload?.suspicious > 0 ? 3.5 : 0}
                                fill="#D97706"
                                stroke={chartDotStroke}
                                strokeWidth={1.5}
                              />
                            );
                          }}
                          activeDot={{ r: 5, fill: '#D97706', stroke: chartDotStroke, strokeWidth: 2 }}
                        />
                      </>
                    )}
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </section>
          </div>

          <RiskScoreHeatmap
            reports={reports}
            allRunRows={allRunRows}
            currentResults={currentResults}
            selectedRunName={selectedName}
            theme={theme}
            loading={loadingHeatmapRows}
            onSelectReport={(reportName) => {
              selectReport(reportName);
            }}
            onInspectIndicator={(indicator) => {
              setVerdictFilter('All');
              setSearchQuery(indicator);
            }}
          />

          <RecentHistoryDashboardPanel
            entries={recentInvestigations}
            onOpenInvestigation={onOpenInvestigation}
            onNavigateToInvestigate={onNavigateToInvestigate}
            onExportSuccess={({ filename, count }) =>
              pushToast({
                variant: 'success',
                title: 'Investigation history exported',
                detail: `${filename} (${count} investigation ID${count === 1 ? '' : 's'})`,
              })
            }
          />

          <RelationshipGraphWidget
            allRunRows={allRunRows}
            selectedRunRows={rows}
            selectedRunName={selectedName}
            currentResults={currentResults}
            theme={theme}
            loading={loadingHeatmapRows}
            onInspectIndicator={(indicator) => {
              setVerdictFilter('All');
              setSearchQuery(indicator);
            }}
          />

          <ThreatLandscapeWidget
            allRunRows={allRunRows}
            selectedRunRows={rows}
            selectedRunName={selectedName}
            reportCount={allRunsCount || reports.length}
            currentResults={currentResults}
            theme={theme}
            loading={loadingHeatmapRows}
            onInspectIndicator={(indicator) => {
              setVerdictFilter('All');
              setSearchQuery(indicator);
            }}
          />

          <IocRegionHeatmap
            allRunRows={allRunRows}
            selectedRunRows={rows}
            selectedRunName={selectedName}
            reportCount={allRunsCount || reports.length}
            theme={theme}
            loading={loadingHeatmapRows}
            activeRegionFilter={activeRegionFilter}
            onInspectIndicator={(indicator) => {
              setVerdictFilter('All');
              setSearchQuery(indicator);
            }}
            onFilterRecentByRegion={onFilterRecentByRegion}
          />

          <section aria-label="Filter historical reports" className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 print:hidden">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="relative flex-1">
                <Search
                  className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 dark:text-slate-500"
                  aria-hidden="true"
                />
                <input
                  type="search"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search indicator, source, or summary (e.g. 1[.]2[.]3[.]4, evil.com)..."
                  aria-label="Search historical reports"
                  className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 py-2 pl-9 pr-3 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
                />
              </div>

              <div className="flex items-center gap-2.5 shrink-0">
                <label htmlFor="report-verdict-filter" className="text-xs font-medium text-slate-600 dark:text-slate-400 whitespace-nowrap">
                  Verdict:
                </label>
                <select
                  id="report-verdict-filter"
                  value={verdictFilter}
                  onChange={(e) => setVerdictFilter(e.target.value as VerdictFilterOption)}
                  aria-label="Filter by verdict"
                  className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-xs font-medium text-slate-800 dark:text-slate-200 focus:border-red-600 focus:outline-none cursor-pointer"
                >
                  <option value="All">All Verdicts</option>
                  <option value="Malicious">Malicious</option>
                  <option value="Suspicious">Suspicious</option>
                  <option value="Clean">Clean</option>
                  <option value="Unknown">Unknown</option>
                </select>

                {hasActiveFilters && (
                  <button
                    type="button"
                    onClick={() => {
                      setSearchQuery('');
                      setVerdictFilter('All');
                    }}
                    className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>
          </section>

          <div className="grid gap-6 lg:grid-cols-[320px_1fr] print:grid-cols-1">
            <div className="min-w-0 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden self-start print:hidden">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 px-3.5 py-2.5">
                <div className="flex items-center gap-2 min-w-0">
                  <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700 dark:text-slate-200 cursor-pointer select-none whitespace-nowrap">
                    <input
                      type="checkbox"
                      checked={allFilteredSelected}
                      disabled={filteredReports.length === 0}
                      onChange={() =>
                        setSelectedForExport((prev) =>
                          toggleSelectAllReports(prev, filteredReports),
                        )
                      }
                      aria-label="Select all visible historical reports"
                      className="h-4 w-4 rounded border-slate-300 dark:border-slate-700 dark:bg-slate-950 text-red-600 focus:ring-red-600 cursor-pointer"
                    />
                    <span>
                      {selectedForExport.length > 0 ? (
                        <span className="font-mono tabular-nums" data-testid="selected-reports-count">
                          {selectedForExport.length} selected
                        </span>
                      ) : (
                        'Select all'
                      )}
                    </span>
                  </label>

                  {selectedForExport.length > 0 && (
                    <button
                      type="button"
                      onClick={() => setSelectedForExport([])}
                      className="text-[11px] font-medium text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:underline whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Clear
                    </button>
                  )}
                </div>

                <button
                  type="button"
                  data-testid="export-selected-reports-csv"
                  onClick={handleDownloadSelectedCsv}
                  disabled={selectedForExport.length === 0 || exportingSelectedCsv}
                  className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[11px] font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:cursor-not-allowed ${
                    selectedForExport.length > 0
                      ? 'bg-red-600 text-white hover:bg-red-700 disabled:opacity-60'
                      : 'border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-400 dark:text-slate-500'
                  }`}
                >
                  <Download className="h-3 w-3" aria-hidden="true" />
                  {exportingSelectedCsv
                    ? 'Exporting...'
                    : `Export Selected (${selectedForExport.length})`}
                </button>
              </div>

              <div className="max-h-[540px] overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800">
                {filteredReports.length === 0 ? (
                  <div className="p-5 text-center text-xs text-slate-500 dark:text-slate-400">
                    No historical reports match your search or verdict filter.
                  </div>
                ) : (
                  filteredReports.map((rep) => {
                    const active = rep.name === selectedName;
                    const checked = selectedForExport.includes(rep.name);
                    const v = rep.verdicts || { malicious: 0, clean: 0, suspicious: 0, unknown: 0, other: 0 };
                    return (
                      <div
                        key={rep.name}
                        className={`flex items-start gap-2.5 px-3.5 py-3 transition-colors ${
                          active
                            ? 'bg-slate-100/80 dark:bg-slate-800'
                            : checked
                              ? 'bg-red-50/40 dark:bg-red-950/15'
                              : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() =>
                            setSelectedForExport((prev) => toggleReportSelection(prev, rep.name))
                          }
                          aria-label={`Select report ${rep.name}`}
                          className="mt-0.5 h-4 w-4 rounded border-slate-300 dark:border-slate-700 dark:bg-slate-950 text-red-600 focus:ring-red-600 shrink-0 cursor-pointer"
                        />
                        <button
                          type="button"
                          onClick={() => selectReport(rep.name)}
                          className="min-w-0 flex-1 text-left cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600 rounded-sm"
                        >
                          <div className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">
                            {rep.name}
                          </div>
                          <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-slate-500 dark:text-slate-400 tabular-nums">
                            <span>{rep.rowCount} rows</span>
                            <span aria-hidden="true">·</span>
                            <span className="text-red-700 dark:text-red-400 font-medium">{v.malicious} mal</span>
                            <span aria-hidden="true">/</span>
                            <span className="text-emerald-700 dark:text-emerald-400 font-medium">{v.clean} clean</span>
                          </div>
                        </button>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            <div className="min-w-0 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden">
              <div className="flex items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 px-5 py-3.5">
                <div className="min-w-0">
                  <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100 truncate block">
                    {selectedName}
                  </span>
                  {!loadingRows && rows.length > 0 && (
                    <span className="text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                      Showing {filteredRows.length} of {rows.length} rows
                    </span>
                  )}
                </div>
                {selectedName && (
                  <a
                    href={`/api/reports/${encodeURIComponent(selectedName)}?download=1`}
                    onClick={() =>
                      pushToast({
                        variant: 'success',
                        title: 'Report download started',
                        detail: selectedName,
                      })
                    }
                    className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 dark:bg-slate-100 px-3 py-1.5 text-xs font-medium text-white dark:text-slate-950 hover:bg-slate-800 dark:hover:bg-slate-200 whitespace-nowrap shrink-0 print:hidden"
                  >
                    <Download className="h-3.5 w-3.5" aria-hidden="true" />
                    Download CSV
                  </a>
                )}
              </div>

              {loadingRows ? (
                <div className="p-6 text-sm text-slate-500 dark:text-slate-400">Loading CSV rows...</div>
              ) : filteredReports.length === 0 || filteredRows.length === 0 ? (
                <div className="px-6 py-10 text-center">
                  <p className="text-sm font-medium text-slate-800 dark:text-slate-200">No matching rows found</p>
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    Try adjusting your indicator search query or verdict filter.
                  </p>
                  {hasActiveFilters && (
                    <button
                      type="button"
                      onClick={() => {
                        setSearchQuery('');
                        setVerdictFilter('All');
                      }}
                      className="mt-3 inline-flex items-center rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
                    >
                      Clear filters
                    </button>
                  )}
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table
                    data-testid="reports-data-table"
                    data-density={tableDensity}
                    className={`w-full text-left ${densitySpec.fontSizeClass}`}
                  >
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/60 text-slate-600 dark:text-slate-300">
                        <th className={densitySpec.headerPaddingClass}>Indicator</th>
                        <th className={densitySpec.headerPaddingClass}>Type</th>
                        <th className={densitySpec.headerPaddingClass}>Source</th>
                        <th className={densitySpec.headerPaddingClass}>Verdict</th>
                        <th className={`${densitySpec.headerPaddingClass} text-right`}>Score</th>
                        <th className={`${densitySpec.headerPaddingClass} text-right whitespace-nowrap`}>Confidence</th>
                        <th className={densitySpec.headerPaddingClass}>Summary</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                      {filteredRows.map((row, idx) => {
                        const confidence = confidenceMap.get((row.indicator || '').trim().toLowerCase());
                        return (
                          <tr key={idx} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40">
                            <td className={`${densitySpec.cellPaddingClass} font-mono font-medium text-slate-900 dark:text-slate-100`}>
                              {maskIndicatorValue(row.indicator || '', null, privacyMode)}
                            </td>
                            <td className={`${densitySpec.cellPaddingClass} font-mono text-slate-500 dark:text-slate-400`}>{row.type}</td>
                            <td className={`${densitySpec.cellPaddingClass} text-slate-800 dark:text-slate-200 whitespace-nowrap`}>{row.source}</td>
                            <td className={`${densitySpec.cellPaddingClass} font-medium text-slate-900 dark:text-slate-100 whitespace-nowrap`}>
                              {row.status === 'ok' ? row.verdict : row.status}
                            </td>
                            <td className={`${densitySpec.cellPaddingClass} text-right font-mono tabular-nums text-slate-800 dark:text-slate-200 whitespace-nowrap`}>{row.score}</td>
                            <td
                              className={`${densitySpec.cellPaddingClass} text-right font-mono tabular-nums whitespace-nowrap`}
                              title={confidence?.tooltip}
                            >
                              {confidence && confidence.score !== null ? (
                                <span className="inline-flex items-baseline gap-1.5">
                                  <span
                                    className={`font-semibold ${
                                      confidence.score >= 70
                                        ? 'text-red-700 dark:text-red-400'
                                        : confidence.score >= 35
                                          ? 'text-amber-700 dark:text-amber-400'
                                          : 'text-emerald-700 dark:text-emerald-400'
                                    }`}
                                  >
                                    {confidence.score}%
                                  </span>
                                  <span className="text-[11px] font-normal text-slate-400 dark:text-slate-500">
                                    ({confidence.sourceCount} src)
                                  </span>
                                </span>
                              ) : (
                                <span className="text-slate-400 dark:text-slate-500">—</span>
                              )}
                            </td>
                            <td className={`${densitySpec.cellPaddingClass} text-slate-600 dark:text-slate-300`}>
                              {maskSensitiveText(row.summary || '', privacyMode)}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </>
      )}
      {toasts.length > 0 && (
        <div
          data-testid="reports-toast-container"
          className="fixed bottom-4 left-4 right-4 z-50 flex flex-col gap-2 sm:bottom-5 sm:left-auto sm:right-5 sm:w-96"
        >
          {toasts.map((item) => (
            <div
              key={item.id}
              role="status"
              aria-live="polite"
              data-testid={`reports-toast-${item.variant}`}
              className="flex items-start gap-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-4 py-3 shadow-lg"
            >
              {item.variant === 'info' ? (
                <Loader2 className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-slate-600 dark:text-slate-300" aria-hidden="true" />
              ) : item.variant === 'error' ? (
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-600 dark:text-red-400" aria-hidden="true" />
              ) : (
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
              )}
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold text-slate-950 dark:text-slate-50">{item.title}</p>
                <p className="mt-0.5 font-mono text-[11px] text-slate-600 dark:text-slate-400 truncate">
                  {maskSensitiveText(item.detail, privacyMode)}
                </p>
              </div>
              <button
                type="button"
                onClick={() => dismissToast(item.id)}
                aria-label="Dismiss notification"
                className="rounded-md p-1 text-slate-400 dark:text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-200 shrink-0 cursor-pointer"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </div>
          ))}
        </div>
      )}
      {shareModalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-xs print:hidden"
          role="dialog"
          aria-modal="true"
          aria-labelledby="share-report-modal-title"
          data-testid="share-report-modal"
          onClick={(e) => {
            if (e.target === e.currentTarget) setShareModalOpen(false);
          }}
        >
          <div className="w-full max-w-xl rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 px-6 py-4">
              <div className="flex items-center gap-2.5">
                <Share2 className="h-5 w-5 text-red-600 dark:text-red-400 shrink-0" aria-hidden="true" />
                <div>
                  <h2
                    id="share-report-modal-title"
                    className="text-base font-bold text-slate-950 dark:text-slate-50"
                  >
                    Share Threat Intelligence Report
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Generate a temporary report snapshot link and ready-to-paste team briefing.
                  </p>
                </div>
              </div>
              <button
                type="button"
                data-testid="close-share-report-modal"
                onClick={() => setShareModalOpen(false)}
                aria-label="Close share report modal"
                className="rounded-lg p-1.5 text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>

            <div className="px-6 py-5 space-y-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                <div className="flex-1">
                  <label
                    htmlFor="share-ttl-select"
                    className="block text-xs font-medium text-slate-700 dark:text-slate-300"
                  >
                    Temporary Link Expiration
                  </label>
                  <select
                    id="share-ttl-select"
                    data-testid="share-ttl-select"
                    value={shareTtlHours}
                    onChange={(e) => setShareTtlHours(Number(e.target.value))}
                    className="mt-1.5 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 text-xs font-medium text-slate-900 dark:text-slate-100 focus:border-red-600 focus:outline-none cursor-pointer"
                  >
                    {SHARE_TTL_OPTIONS.map((opt) => (
                      <option key={opt.hours} value={opt.hours}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </div>

                <button
                  type="button"
                  data-testid="create-share-link-btn"
                  onClick={handleCreateShareSnapshot}
                  disabled={creatingShare}
                  className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white hover:bg-red-700 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {creatingShare ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                  ) : (
                    <Link2 className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  <span>{creatingShare ? 'Creating Link...' : 'Generate Temporary Link'}</span>
                </button>
              </div>

              {shareError && (
                <div
                  role="alert"
                  className="rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/40 px-4 py-2.5 text-xs text-red-800 dark:text-red-200"
                >
                  {shareError}
                </div>
              )}

              {createdShareUrl && createdShareSnapshot && (
                <div className="space-y-3 border-t border-slate-100 dark:border-slate-800 pt-4">
                  <div>
                    <label
                      htmlFor="share-link-output"
                      className="block text-xs font-medium text-slate-700 dark:text-slate-300"
                    >
                      Temporary Share URL (expires{' '}
                      {createdShareSnapshot.expiresAt.slice(0, 16).replace('T', ' ')} UTC)
                    </label>
                    <div className="mt-1.5 flex items-center gap-2">
                      <input
                        id="share-link-output"
                        data-testid="share-link-output"
                        type="text"
                        readOnly
                        value={createdShareUrl}
                        className="flex-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 focus:outline-none"
                      />
                      <button
                        type="button"
                        data-testid="copy-share-link-btn"
                        onClick={async () => {
                          const ok = await copyToClipboard(createdShareUrl);
                          if (ok) {
                            setCopiedShareLink(true);
                            window.setTimeout(() => setCopiedShareLink(false), 2000);
                          }
                        }}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-xs font-medium text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        {copiedShareLink ? (
                          <>
                            <Check className="h-3.5 w-3.5 text-emerald-600" aria-hidden="true" />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                            <span>Copy Link</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <label
                        htmlFor="share-message-output"
                        className="block text-xs font-medium text-slate-700 dark:text-slate-300"
                      >
                        Pre-Populated Team Message
                      </label>
                      <button
                        type="button"
                        data-testid="copy-share-message-btn"
                        onClick={async () => {
                          const rawMsg = buildShareReportMessage(createdShareSnapshot, createdShareUrl);
                          const msg = maskSensitiveText(rawMsg, privacyMode);
                          const ok = await copyToClipboard(msg);
                          if (ok) {
                            setCopiedShareMessage(true);
                            window.setTimeout(() => setCopiedShareMessage(false), 2000);
                          }
                        }}
                        className="inline-flex items-center gap-1 text-xs font-semibold text-red-700 dark:text-red-400 hover:underline cursor-pointer"
                      >
                        {copiedShareMessage ? (
                          <>
                            <Check className="h-3.5 w-3.5 text-emerald-600" aria-hidden="true" />
                            <span>Message Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                            <span>Copy Message</span>
                          </>
                        )}
                      </button>
                    </div>
                    <textarea
                      id="share-message-output"
                      data-testid="share-message-output"
                      readOnly
                      rows={5}
                      value={maskSensitiveText(
                        buildShareReportMessage(createdShareSnapshot, createdShareUrl),
                        privacyMode,
                      )}
                      className="mt-1.5 w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 p-3 font-mono text-[11px] leading-relaxed text-slate-800 dark:text-slate-200 focus:outline-none"
                    />
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-end border-t border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 px-6 py-3">
              <button
                type="button"
                onClick={() => setShareModalOpen(false)}
                className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

