import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  FileSpreadsheet,
  FileText,
  Loader2,
  RefreshCw,
  Search,
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
  buildPrintDocumentTitle,
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
import type { ThemeMode } from '../utils/theme';

type ChartScope = 'malicious_clean' | 'all_verdicts';
type TrendMode = 'total' | 'severity';
type ToastVariant = 'info' | 'success' | 'error';

interface ToastNotification {
  id: string;
  variant: ToastVariant;
  title: string;
  detail: string;
}

interface ReportsViewProps {
  theme?: ThemeMode;
}

export function ReportsView({ theme = 'light' }: ReportsViewProps) {
  const isDark = theme === 'dark';
  const [reports, setReports] = useState<ReportMeta[]>([]);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [rows, setRows] = useState<Record<string, string>[]>([]);
  const [loadingList, setLoadingList] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [loadingRows, setLoadingRows] = useState(false);
  const [exportingCsv, setExportingCsv] = useState(false);
  const [exportingSelectedCsv, setExportingSelectedCsv] = useState(false);
  const [selectedForExport, setSelectedForExport] = useState<string[]>([]);
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(true);
  const [refreshIntervalSec, setRefreshIntervalSec] = useState<number>(DEFAULT_REPORTS_REFRESH_SECONDS);
  const [tableDensity, setTableDensity] = useState<TableDensity>(DEFAULT_TABLE_DENSITY);
  const [lastRefreshedAt, setLastRefreshedAt] = useState<string | null>(null);
  const [chartScope, setChartScope] = useState<ChartScope>('malicious_clean');
  const [trendMode, setTrendMode] = useState<TrendMode>('total');
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilterOption>('All');
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

  function handleDownloadPdf() {
    if (reports.length === 0) return;

    const previousTitle = document.title;
    const printTitle = buildPrintDocumentTitle(selectedName);
    document.title = printTitle;

    let restored = false;
    const restoreTitle = () => {
      if (restored) return;
      restored = true;
      document.title = previousTitle;
      window.removeEventListener('afterprint', restoreTitle);
    };

    window.addEventListener('afterprint', restoreTitle);

    pushToast({
      variant: 'info',
      title: 'Print-ready PDF dialog opened',
      detail: `Choose "Save as PDF" (${printTitle}.pdf) in your browser print dialog.`,
    });

    try {
      window.print();
    } catch {
      pushToast({
        variant: 'error',
        title: 'Print dialog unavailable',
        detail: 'Use your browser Print shortcut (Ctrl/Cmd+P) to save as PDF.',
      });
    } finally {
      window.setTimeout(restoreTitle, 1000);
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

        <div className="flex flex-wrap items-center gap-2.5 print:hidden">
          <div className="inline-flex items-center rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
            <button
              type="button"
              role="switch"
              aria-checked={autoRefreshEnabled}
              aria-label="Toggle automatic periodic refresh"
              data-testid="reports-auto-refresh-toggle"
              onClick={() => setAutoRefreshEnabled((prev) => !prev)}
              className="inline-flex items-center gap-2 px-3 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 rounded-l-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
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
              className="rounded-r-lg bg-transparent px-2.5 py-2 font-mono text-xs font-medium text-slate-700 dark:text-slate-200 focus:outline-none disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed tabular-nums"
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
              className="pl-3 pr-1.5 py-2 text-xs font-medium text-slate-500 dark:text-slate-400 whitespace-nowrap select-none"
            >
              Density
            </label>
            <select
              id="reports-table-density"
              data-testid="reports-density-select"
              aria-label="Reports table density"
              value={tableDensity}
              onChange={(e) => setTableDensity(normalizeTableDensity(e.target.value))}
              className="rounded-r-lg bg-transparent pr-2.5 py-2 text-xs font-medium text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer"
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
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-3.5 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
            Refresh
          </button>

          <button
            type="button"
            data-testid="download-pdf-button"
            onClick={handleDownloadPdf}
            disabled={reports.length === 0}
            aria-label="Download PDF"
            title="Capture current dashboard as print-ready PDF"
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-3.5 py-2 text-xs font-semibold text-slate-800 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-100"
          >
            <FileText className="h-3.5 w-3.5 text-slate-600 dark:text-slate-400" aria-hidden="true" />
            <span>Download PDF</span>
          </button>

          <button
            type="button"
            onClick={handleDownloadHistoricalCsv}
            disabled={reports.length === 0 || exportingCsv}
            className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-red-700 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            {exportingCsv ? 'Exporting...' : 'Download as CSV'}
          </button>
        </div>
      </div>

      {loadingList ? (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-8 text-sm text-slate-500 dark:text-slate-400">
          Loading reports...
        </div>
      ) : reports.length === 0 ? (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-6 py-12 text-center">
          <FileSpreadsheet className="mx-auto h-8 w-8 text-slate-400 dark:text-slate-500" aria-hidden="true" />
          <h2 className="mt-3 text-base font-semibold text-slate-900 dark:text-slate-100">No CSV reports yet</h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            Run an enrichment lookup from the Investigate tab to generate a report.
          </p>
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
                            <td className={`${densitySpec.cellPaddingClass} font-mono font-medium text-slate-900 dark:text-slate-100`}>{row.indicator}</td>
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
                            <td className={`${densitySpec.cellPaddingClass} text-slate-600 dark:text-slate-300`}>{row.summary}</td>
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
                <p className="mt-0.5 font-mono text-[11px] text-slate-600 dark:text-slate-400 truncate">{item.detail}</p>
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
    </div>
  );
}

