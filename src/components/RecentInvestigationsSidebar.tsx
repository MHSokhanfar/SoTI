import { useState } from 'react';
import { ChevronDown, ChevronUp, Clock, Eye, RotateCw, Trash2 } from 'lucide-react';
import {
  formatInvestigationTitle,
  formatRelativeTime,
  getPrimaryVerdictBadge,
  type RecentInvestigationEntry,
} from '../utils/investigationHistory';

interface RecentInvestigationsSidebarProps {
  entries: RecentInvestigationEntry[];
  activeEntryId: string | null;
  isRunning: boolean;
  onViewDetails: (entry: RecentInvestigationEntry) => void;
  onRerun: (entry: RecentInvestigationEntry) => void;
  onRemoveEntry: (id: string) => void;
  onClearAll: () => void;
}

export function RecentInvestigationsSidebar({
  entries,
  activeEntryId,
  isRunning,
  onViewDetails,
  onRerun,
  onRemoveEntry,
  onClearAll,
}: RecentInvestigationsSidebarProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  function handleDetailsClick(entry: RecentInvestigationEntry) {
    setExpandedId((prev) => (prev === entry.id ? null : entry.id));
    onViewDetails(entry);
  }

  return (
    <aside
      aria-label="Recent Investigations"
      data-testid="recent-investigations-sidebar"
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden"
    >
      <div className="flex items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 px-4 py-3.5">
        <div className="flex items-center gap-2 min-w-0">
          <Clock className="h-4 w-4 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-slate-950 dark:text-slate-50 truncate">
            Recent Investigations
          </h2>
          <span className="font-mono text-xs text-slate-500 dark:text-slate-400 tabular-nums shrink-0">
            ({entries.length})
          </span>
        </div>

        {entries.length > 0 && (
          <button
            type="button"
            data-testid="clear-recent-investigations"
            aria-label="Clear all recent investigations"
            onClick={() => {
              setExpandedId(null);
              onClearAll();
            }}
            className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-1 text-xs font-medium text-slate-600 dark:text-slate-300 hover:border-red-300 dark:hover:border-red-800 hover:text-red-700 dark:hover:text-red-400 whitespace-nowrap shrink-0 cursor-pointer"
          >
            Clear All
          </button>
        )}
      </div>

      {entries.length === 0 ? (
        <div
          data-testid="recent-investigations-empty"
          className="px-4 py-8 text-center"
        >
          <p className="text-xs font-medium text-slate-700 dark:text-slate-300">
            No recent queries saved yet
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Completed enrichments are stored locally in your browser so you can inspect results or re-run batches in one click.
          </p>
        </div>
      ) : (
        <ul className="max-h-[540px] overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800">
          {entries.map((entry) => {
            const title = formatInvestigationTitle(entry.indicators, entry.normalizedInput);
            const verdictBadge = getPrimaryVerdictBadge(entry.verdictSummary);
            const isExpanded = expandedId === entry.id;
            const isActive = activeEntryId === entry.id;

            const verdictToneClass =
              verdictBadge.tone === 'malicious'
                ? 'text-red-700 dark:text-red-400 font-semibold'
                : verdictBadge.tone === 'suspicious'
                  ? 'text-amber-700 dark:text-amber-400 font-semibold'
                  : verdictBadge.tone === 'clean'
                    ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                    : 'text-slate-600 dark:text-slate-400 font-medium';

            return (
              <li
                key={entry.id}
                data-testid={`recent-investigation-item`}
                className={`px-4 py-3.5 transition-colors ${
                  isActive
                    ? 'bg-slate-50 dark:bg-slate-800/70'
                    : 'hover:bg-slate-50/70 dark:hover:bg-slate-800/40'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div
                      className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100 truncate"
                      title={entry.normalizedInput}
                    >
                      {title}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                      <span>{formatRelativeTime(entry.createdAt)}</span>
                      <span aria-hidden="true">·</span>
                      <span>{entry.mode === 'live' ? 'Live' : 'Sample'}</span>
                      <span aria-hidden="true">·</span>
                      <span className={verdictToneClass}>{verdictBadge.label}</span>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => onRemoveEntry(entry.id)}
                    aria-label={`Remove ${title} from recent investigations`}
                    title="Remove from history"
                    className="rounded-md p-1 text-slate-400 dark:text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-red-600 dark:hover:text-red-400 shrink-0 cursor-pointer"
                  >
                    <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </div>

                <div className="mt-2.5 flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    data-testid="recent-view-details-btn"
                    aria-expanded={isExpanded}
                    aria-label={`View details for ${title}`}
                    onClick={() => handleDetailsClick(entry)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1.5 text-[11px] font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Eye className="h-3 w-3" aria-hidden="true" />
                    <span>Details</span>
                    {isExpanded ? (
                      <ChevronUp className="h-3 w-3 text-slate-400" aria-hidden="true" />
                    ) : (
                      <ChevronDown className="h-3 w-3 text-slate-400" aria-hidden="true" />
                    )}
                  </button>

                  <button
                    type="button"
                    data-testid="recent-rerun-btn"
                    disabled={isRunning}
                    aria-label={`Re-run ${title}`}
                    onClick={() => onRerun(entry)}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 dark:bg-slate-100 px-2.5 py-1.5 text-[11px] font-semibold text-white dark:text-slate-950 hover:bg-slate-800 dark:hover:bg-slate-200 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <RotateCw className="h-3 w-3" aria-hidden="true" />
                    <span>Re-run</span>
                  </button>
                </div>

                {isExpanded && (
                  <div
                    data-testid="recent-investigation-details"
                    className="mt-3 space-y-2 border-t border-slate-200 dark:border-slate-700 pt-2.5 text-[11px] text-slate-600 dark:text-slate-300"
                  >
                    <div>
                      <span className="font-semibold text-slate-700 dark:text-slate-200">Timestamp: </span>
                      <span className="font-mono tabular-nums">
                        {entry.createdAt.slice(0, 19).replace('T', ' ')} UTC
                      </span>
                    </div>
                    <div>
                      <span className="font-semibold text-slate-700 dark:text-slate-200">
                        Indicators ({entry.indicatorCount}):{' '}
                      </span>
                      <span className="font-mono break-all text-slate-800 dark:text-slate-100">
                        {entry.indicators.join(', ')}
                      </span>
                    </div>
                    <div>
                      <span className="font-semibold text-slate-700 dark:text-slate-200">Sources: </span>
                      <span>
                        {entry.sourceLabels.length > 0 ? entry.sourceLabels.join(' · ') : 'Configured APIs'}
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-x-2.5 gap-y-0.5 font-mono tabular-nums">
                      <span className="text-red-700 dark:text-red-400">
                        Mal: {entry.verdictSummary.malicious}
                      </span>
                      <span className="text-amber-700 dark:text-amber-400">
                        Susp: {entry.verdictSummary.suspicious}
                      </span>
                      <span className="text-emerald-700 dark:text-emerald-400">
                        Clean: {entry.verdictSummary.clean}
                      </span>
                      <span className="text-slate-500 dark:text-slate-400">
                        Unk: {entry.verdictSummary.unknown}
                      </span>
                    </div>
                    {entry.reportFile && (
                      <div className="truncate font-mono text-slate-500 dark:text-slate-400">
                        Report: {entry.reportFile}
                      </div>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </aside>
  );
}
