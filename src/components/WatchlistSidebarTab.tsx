import { useState } from 'react';
import {
  ArrowRight,
  BellRing,
  Check,
  CheckCheck,
  Eye,
  Plus,
  RefreshCw,
  Search,
  Trash2,
} from 'lucide-react';
import { formatRelativeTime } from '../utils/investigationHistory';
import {
  countUnreadWatchlistUpdates,
  type WatchlistItem,
} from '../utils/watchlist';

interface WatchlistSidebarTabProps {
  items: WatchlistItem[];
  isChecking: boolean;
  lastCheckedUtc?: string | null;
  onAddIndicator: (rawInput: string) => { added: boolean; error?: string };
  onRemoveIndicator: (indicator: string) => void;
  onCheckUpdatesNow: () => void;
  onInspectIndicator: (indicator: string) => void;
  onAcknowledgeItem: (indicator: string) => void;
  onAcknowledgeAll: () => void;
}

function getVerdictTextClass(verdict: WatchlistItem['lastVerdict']): string {
  switch (verdict) {
    case 'Malicious':
      return 'text-red-700 dark:text-red-400';
    case 'Suspicious':
      return 'text-amber-700 dark:text-amber-400';
    case 'Clean':
      return 'text-emerald-700 dark:text-emerald-400';
    default:
      return 'text-slate-500 dark:text-slate-400';
  }
}

export function WatchlistSidebarTab({
  items,
  isChecking,
  lastCheckedUtc,
  onAddIndicator,
  onRemoveIndicator,
  onCheckUpdatesNow,
  onInspectIndicator,
  onAcknowledgeItem,
  onAcknowledgeAll,
}: WatchlistSidebarTabProps) {
  const [inputValue, setInputValue] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  const unreadTotal = countUnreadWatchlistUpdates(items);

  const orderedItems = [...items].sort((a, b) => {
    if (b.unreadUpdateCount !== a.unreadUpdateCount) {
      return b.unreadUpdateCount - a.unreadUpdateCount;
    }
    const timeA = Date.parse(a.lastChange?.detectedAt || a.addedAt) || 0;
    const timeB = Date.parse(b.lastChange?.detectedAt || b.addedAt) || 0;
    return timeB - timeA;
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!inputValue.trim()) return;
    const outcome = onAddIndicator(inputValue);
    if (!outcome.added) {
      setFormError(outcome.error || 'Enter a valid IP, domain, URL, or hash.');
      return;
    }
    setFormError(null);
    setInputValue('');
  }

  return (
    <div data-testid="watchlist-sidebar-panel" className="divide-y divide-slate-200 dark:divide-slate-800">
      <div className="px-4 py-3 space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs text-slate-600 dark:text-slate-400">
            <span className="font-semibold text-slate-900 dark:text-slate-100">
              {items.length} monitored
            </span>
            {unreadTotal > 0 && (
              <>
                <span className="mx-1.5 text-slate-400" aria-hidden="true">·</span>
                <span className="font-semibold text-red-700 dark:text-red-400 tabular-nums">
                  {unreadTotal} new update{unreadTotal === 1 ? '' : 's'}
                </span>
              </>
            )}
          </div>

          <div className="flex items-center gap-1.5 shrink-0">
            {unreadTotal > 0 && (
              <button
                type="button"
                data-testid="watchlist-mark-all-read"
                onClick={onAcknowledgeAll}
                className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <CheckCheck className="h-3 w-3" aria-hidden="true" />
                <span>Mark Read</span>
              </button>
            )}
            <button
              type="button"
              data-testid="watchlist-check-now-btn"
              disabled={items.length === 0 || isChecking}
              onClick={onCheckUpdatesNow}
              className="inline-flex items-center gap-1 rounded-md bg-slate-900 dark:bg-slate-100 px-2.5 py-1 text-[11px] font-semibold text-white dark:text-slate-950 hover:bg-slate-800 dark:hover:bg-slate-200 disabled:opacity-45 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RefreshCw
                className={`h-3 w-3 ${isChecking ? 'animate-spin' : ''}`}
                aria-hidden="true"
              />
              <span>{isChecking ? 'Checking...' : 'Check Updates'}</span>
            </button>
          </div>
        </div>

        <form
          data-testid="watchlist-add-form"
          onSubmit={handleSubmit}
          className="flex items-center gap-1.5"
        >
          <input
            type="text"
            data-testid="watchlist-add-input"
            value={inputValue}
            onChange={(e) => {
              setInputValue(e.target.value);
              if (formError) setFormError(null);
            }}
            placeholder="Monitor IP, domain, URL, or hash..."
            aria-label="Add indicator to Watchlist"
            className="min-w-0 flex-1 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-1.5 font-mono text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:outline-none"
          />
          <button
            type="submit"
            data-testid="watchlist-add-btn"
            disabled={!inputValue.trim()}
            className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-800 dark:text-slate-100 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-45 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Watch</span>
          </button>
        </form>

        {formError && (
          <p className="text-[11px] font-medium text-red-700 dark:text-red-400">
            {formError}
          </p>
        )}

        {lastCheckedUtc && (
          <p className="font-mono text-[10px] text-slate-400 dark:text-slate-500 tabular-nums">
            Last verified {lastCheckedUtc}
          </p>
        )}
      </div>

      {orderedItems.length === 0 ? (
        <div
          data-testid="watchlist-empty"
          className="px-4 py-10 text-center space-y-2"
        >
          <Eye className="mx-auto h-6 w-6 text-slate-300 dark:text-slate-600" aria-hidden="true" />
          <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">
            No indicators on Watchlist
          </p>
          <p className="text-[11px] leading-relaxed text-slate-500 dark:text-slate-400">
            Add an IOC above or click <span className="font-semibold">Watch</span> on any results row to monitor verdict and confidence shifts over time.
          </p>
        </div>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-800 max-h-[600px] overflow-y-auto">
          {orderedItems.map((item) => {
            const hasUnread = item.unreadUpdateCount > 0;
            return (
              <li
                key={item.indicator}
                data-testid="watchlist-item"
                className={`px-4 py-3 space-y-2 transition-colors ${
                  hasUnread
                    ? 'bg-red-50/45 dark:bg-red-950/20'
                    : 'hover:bg-slate-50/70 dark:hover:bg-slate-800/40'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      {hasUnread && (
                        <BellRing
                          className="h-3.5 w-3.5 shrink-0 text-red-600 dark:text-red-400"
                          aria-hidden="true"
                        />
                      )}
                      <span className="font-mono text-xs font-semibold text-slate-950 dark:text-slate-50 break-all">
                        {item.indicator}
                      </span>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400">
                      <span className="font-mono uppercase">{item.type}</span>
                      <span aria-hidden="true">·</span>
                      <span className={`font-semibold ${getVerdictTextClass(item.lastVerdict)}`}>
                        {item.lastVerdict ?? 'Pending'}
                      </span>
                      {item.lastConfidenceScore !== null && (
                        <>
                          <span aria-hidden="true">·</span>
                          <span className="font-mono tabular-nums font-semibold text-slate-700 dark:text-slate-300">
                            {item.lastConfidenceScore}/100
                          </span>
                        </>
                      )}
                      <span aria-hidden="true">·</span>
                      <span>
                        {item.lastCheckedAt
                          ? `Checked ${formatRelativeTime(item.lastCheckedAt)}`
                          : 'Awaiting check'}
                      </span>
                    </div>
                  </div>

                  <button
                    type="button"
                    data-testid="watchlist-remove-btn"
                    onClick={() => onRemoveIndicator(item.indicator)}
                    aria-label={`Remove ${item.indicator} from Watchlist`}
                    title="Stop monitoring"
                    className="rounded p-1 text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-red-600 dark:hover:text-red-400 shrink-0 cursor-pointer"
                  >
                    <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </div>

                {item.lastChange && (
                  <div
                    data-testid="watchlist-item-change"
                    className={`rounded-md border px-2.5 py-1.5 text-[11px] ${
                      hasUnread
                        ? 'border-red-200 dark:border-red-900/60 bg-white dark:bg-slate-900 text-red-900 dark:text-red-200'
                        : 'border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/50 text-slate-600 dark:text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="inline-flex items-center gap-1 font-medium">
                        <ArrowRight className="h-3 w-3 shrink-0" aria-hidden="true" />
                        <span>{item.lastChange.summary}</span>
                      </span>
                      {hasUnread && (
                        <button
                          type="button"
                          data-testid="watchlist-ack-btn"
                          onClick={() => onAcknowledgeItem(item.indicator)}
                          aria-label={`Acknowledge update for ${item.indicator}`}
                          className="inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 text-[10px] font-semibold text-red-700 dark:text-red-300 hover:bg-red-100 dark:hover:bg-red-950/60 whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          <Check className="h-3 w-3" aria-hidden="true" />
                          Ack
                        </button>
                      )}
                    </div>
                    <div className="mt-0.5 font-mono text-[10px] opacity-75 tabular-nums">
                      {item.lastChange.detectedAt.slice(0, 19).replace('T', ' ')} UTC
                    </div>
                  </div>
                )}

                <div className="flex items-center justify-between gap-2 pt-0.5">
                  <button
                    type="button"
                    data-testid="watchlist-inspect-btn"
                    onClick={() => onInspectIndicator(item.indicator)}
                    className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Search className="h-3 w-3" aria-hidden="true" />
                    <span>Investigate</span>
                  </button>
                  {item.history.length > 0 && (
                    <span className="font-mono text-[10px] text-slate-400 dark:text-slate-500 tabular-nums">
                      {item.history.length} status change{item.history.length === 1 ? '' : 's'}
                    </span>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
