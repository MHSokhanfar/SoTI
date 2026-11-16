import { useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowUpRight,
  Check,
  Clock,
  Download,
  Pin,
  Search,
} from 'lucide-react';
import {
  buildRecentHistoryExportFilename,
  filterRecentHistoryEntries,
  getInvestigationDisplayTitle,
  serializeRecentHistoryExportJson,
  sortRecentInvestigations,
  type RecentInvestigationEntry,
} from '../utils/investigationHistory';
import { maskIndicatorValue, maskSensitiveText } from '../utils/privacyMode';
import { usePrivacyMode } from './PrivacyModeContext';

interface RecentHistoryDashboardPanelProps {
  entries: RecentInvestigationEntry[];
  onOpenInvestigation?: (entry: RecentInvestigationEntry) => void;
  onNavigateToInvestigate?: () => void;
  onExportSuccess?: (info: { filename: string; count: number }) => void;
}

export function RecentHistoryDashboardPanel({
  entries,
  onOpenInvestigation,
  onNavigateToInvestigate,
  onExportSuccess,
}: RecentHistoryDashboardPanelProps) {
  const privacyMode = usePrivacyMode();
  const [searchQuery, setSearchQuery] = useState('');
  const [exportedCount, setExportedCount] = useState<number | null>(null);
  const resetTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (resetTimerRef.current !== null) {
        window.clearTimeout(resetTimerRef.current);
      }
    };
  }, []);

  const orderedEntries = useMemo(() => sortRecentInvestigations(entries), [entries]);
  const visibleEntries = useMemo(
    () => filterRecentHistoryEntries(orderedEntries, searchQuery),
    [orderedEntries, searchQuery],
  );

  function handleExportAll() {
    if (orderedEntries.length === 0) return;
    const now = new Date();
    const json = serializeRecentHistoryExportJson(orderedEntries, now);
    const filename = buildRecentHistoryExportFilename(now);
    const blob = new Blob([json], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);

    setExportedCount(orderedEntries.length);
    if (resetTimerRef.current !== null) {
      window.clearTimeout(resetTimerRef.current);
    }
    resetTimerRef.current = window.setTimeout(() => {
      setExportedCount(null);
    }, 2400);

    onExportSuccess?.({ filename, count: orderedEntries.length });
  }

  return (
    <section
      aria-label="Recent History"
      data-testid="dashboard-recent-history-section"
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 print:border-slate-300"
    >
      <div className="flex flex-col gap-3 border-b border-slate-100 dark:border-slate-800 px-5 py-4 lg:flex-row lg:items-center lg:justify-between md:px-6">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Clock className="h-4 w-4 text-slate-500 dark:text-slate-400 shrink-0" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">
              Recent History
            </h2>
            <span
              data-testid="dashboard-recent-history-count"
              className="font-mono text-xs text-slate-500 dark:text-slate-400 tabular-nums"
            >
              · {orderedEntries.length} investigation{orderedEntries.length === 1 ? '' : 's'}
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            Completed browser investigation records with unique investigation IDs, IOC targets, verdicts, tags, and notes.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0 print:hidden">
          {orderedEntries.length > 0 && (
            <div className="relative w-full sm:w-60">
              <Search
                className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400 dark:text-slate-500"
                aria-hidden="true"
              />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter ID, IOC, tag..."
                aria-label="Filter recent history"
                data-testid="dashboard-recent-history-search"
                className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 py-1.5 pl-8 pr-3 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
              />
            </div>
          )}

          <button
            type="button"
            data-testid="dashboard-recent-history-export-all-btn"
            onClick={handleExportAll}
            disabled={orderedEntries.length === 0}
            aria-label="Export All investigation history as structured JSON"
            title={
              orderedEntries.length > 0
                ? `Download all ${orderedEntries.length} investigation record(s) and ID metadata as JSON`
                : 'No investigation history available to export'
            }
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 dark:bg-slate-100 px-3.5 py-1.5 text-xs font-semibold text-white dark:text-slate-950 transition-colors hover:bg-slate-800 dark:hover:bg-slate-200 disabled:opacity-45 disabled:cursor-not-allowed whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-100"
          >
            {exportedCount !== null ? (
              <>
                <Check className="h-3.5 w-3.5 text-emerald-400 dark:text-emerald-600" aria-hidden="true" />
                <span>Exported All ({exportedCount})</span>
              </>
            ) : (
              <>
                <Download className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Export All</span>
              </>
            )}
          </button>
        </div>
      </div>

      {orderedEntries.length === 0 ? (
        <div
          data-testid="dashboard-recent-history-empty"
          className="px-6 py-10 text-center space-y-2"
        >
          <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
            No investigation history recorded yet
          </p>
          <p className="mx-auto max-w-md text-xs text-slate-500 dark:text-slate-400">
            Run an enrichment lookup from the Investigate view to record investigation IDs, IOC findings, and full exportable metadata.
          </p>
          {onNavigateToInvestigate && (
            <div className="pt-1 print:hidden">
              <button
                type="button"
                onClick={onNavigateToInvestigate}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3.5 py-1.5 text-xs font-medium text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
              >
                <span>Open Investigate</span>
                <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </div>
          )}
        </div>
      ) : visibleEntries.length === 0 ? (
        <div className="px-6 py-8 text-center text-xs text-slate-500 dark:text-slate-400 space-y-2">
          <p>No recent investigation entries match &ldquo;{searchQuery.trim()}&rdquo;.</p>
          <button
            type="button"
            onClick={() => setSearchQuery('')}
            className="inline-flex items-center rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
          >
            Reset filter
          </button>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table
            data-testid="dashboard-recent-history-table"
            className="w-full text-left text-xs"
          >
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/60 text-slate-600 dark:text-slate-300">
                <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Investigation ID</th>
                <th className="px-4 py-2.5 font-semibold">Title &amp; Indicators</th>
                <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Mode &amp; Sources</th>
                <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Verdicts</th>
                <th className="px-4 py-2.5 font-semibold whitespace-nowrap">Metadata</th>
                <th className="px-4 py-2.5 font-semibold text-right whitespace-nowrap">Timestamp</th>
                {onOpenInvestigation && (
                  <th className="px-4 py-2.5 font-semibold text-right whitespace-nowrap print:hidden">Action</th>
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {visibleEntries.map((entry) => {
                const displayTitle = maskSensitiveText(
                  getInvestigationDisplayTitle(entry),
                  privacyMode,
                );
                const previewIndicators = entry.indicators
                  .slice(0, 3)
                  .map((ind) => maskIndicatorValue(ind, null, privacyMode))
                  .join(', ');
                const extraIndicators =
                  entry.indicators.length > 3 ? ` +${entry.indicators.length - 3}` : '';
                const tagList = Array.isArray(entry.tags) ? entry.tags : [];
                const sourceText =
                  entry.sourceLabels.length > 0
                    ? entry.sourceLabels.slice(0, 3).join(', ') +
                      (entry.sourceLabels.length > 3 ? ` +${entry.sourceLabels.length - 3}` : '')
                    : 'Default APIs';

                return (
                  <tr
                    key={entry.id}
                    data-testid="dashboard-recent-history-row"
                    data-investigation-id={entry.id}
                    className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40"
                  >
                    <td className="px-4 py-3 font-mono text-[11px] font-medium text-slate-700 dark:text-slate-300 whitespace-nowrap tabular-nums">
                      <span className="inline-flex items-center gap-1.5">
                        {entry.pinned && (
                          <Pin
                            className="h-3 w-3 text-amber-600 dark:text-amber-400 shrink-0"
                            aria-label="Pinned"
                          />
                        )}
                        <span>{entry.id}</span>
                      </span>
                    </td>
                    <td className="px-4 py-3 min-w-[200px]">
                      <div className="font-semibold text-slate-900 dark:text-slate-100">
                        {displayTitle}
                      </div>
                      <div className="mt-0.5 font-mono text-[11px] text-slate-500 dark:text-slate-400 truncate max-w-[320px]">
                        {entry.indicatorCount} IOC{entry.indicatorCount === 1 ? '' : 's'}
                        {previewIndicators ? ` · ${previewIndicators}${extraIndicators}` : ''}
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="font-medium text-slate-800 dark:text-slate-200">
                        {entry.mode === 'live' ? 'Live API' : 'Sample Data'}
                      </div>
                      <div className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400 truncate max-w-[180px]">
                        {sourceText}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] whitespace-nowrap tabular-nums">
                      <span className="text-red-700 dark:text-red-400 font-semibold">
                        {entry.verdictSummary.malicious} Mal
                      </span>
                      <span className="text-slate-400 dark:text-slate-600"> · </span>
                      <span className="text-amber-700 dark:text-amber-400">
                        {entry.verdictSummary.suspicious} Susp
                      </span>
                      <span className="text-slate-400 dark:text-slate-600"> · </span>
                      <span className="text-emerald-700 dark:text-emerald-400">
                        {entry.verdictSummary.clean} Clean
                      </span>
                    </td>
                    <td className="px-4 py-3 text-[11px] text-slate-600 dark:text-slate-400 whitespace-nowrap">
                      <span>{entry.results.length} findings</span>
                      {tagList.length > 0 && <span> · {tagList.join(', ')}</span>}
                      {entry.notes && entry.notes.trim().length > 0 && <span> · Notes</span>}
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-[11px] text-slate-600 dark:text-slate-400 whitespace-nowrap tabular-nums">
                      {entry.createdAt.slice(0, 16).replace('T', ' ')} UTC
                    </td>
                    {onOpenInvestigation && (
                      <td className="px-4 py-3 text-right whitespace-nowrap print:hidden">
                        <button
                          type="button"
                          onClick={() => onOpenInvestigation(entry)}
                          className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-200 hover:border-slate-400 dark:hover:border-slate-500 hover:text-slate-950 dark:hover:text-white cursor-pointer whitespace-nowrap"
                        >
                          <span>Open</span>
                          <ArrowUpRight className="h-3 w-3" aria-hidden="true" />
                        </button>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
