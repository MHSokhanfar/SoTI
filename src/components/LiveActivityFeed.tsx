import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Pause,
  Play,
  RefreshCw,
  Search,
  ShieldAlert,
  Terminal,
} from 'lucide-react';
import type { EmailAlertRecord } from '../utils/emailAlerts';
import type { RecentInvestigationEntry } from '../utils/investigationHistory';
import {
  buildActivityFromEmailAlert,
  buildActivityFromRecentInvestigation,
  buildActivityFromReportMeta,
  filterLiveActivityEvents,
  formatActivityDateBadge,
  formatActivityUtcTime,
  mergeLiveActivityEvents,
  summarizeLiveActivity,
  type LiveActivityCategory,
  type LiveActivityEvent,
} from '../utils/liveActivity';
import type { ReportMeta } from '../utils/reportsAnalytics';
import { maskSensitiveText } from '../utils/privacyMode';
import { usePrivacyMode } from './PrivacyModeContext';

interface LiveActivityFeedProps {
  reports?: ReportMeta[];
  recentInvestigations?: RecentInvestigationEntry[];
  dispatchedEmailAlerts?: EmailAlertRecord[];
  onInspectIndicator?: (indicator: string) => void;
  onSelectReport?: (reportName: string) => void;
}

const CATEGORY_TABS: { id: 'all' | LiveActivityCategory; label: string }[] = [
  { id: 'all', label: 'All Activity' },
  { id: 'threat_alert', label: 'Threat Alerts' },
  { id: 'investigation', label: 'Investigations' },
  { id: 'system_event', label: 'System Events' },
];

function getSeverityTextClass(severity: LiveActivityEvent['severity']): string {
  switch (severity) {
    case 'critical':
      return 'text-red-700 dark:text-red-400';
    case 'warning':
      return 'text-amber-700 dark:text-amber-400';
    case 'success':
      return 'text-emerald-700 dark:text-emerald-400';
    default:
      return 'text-slate-600 dark:text-slate-400';
  }
}

function getCategoryLabel(category: LiveActivityCategory): string {
  switch (category) {
    case 'threat_alert':
      return 'Threat Alert';
    case 'investigation':
      return 'Investigation';
    default:
      return 'System Event';
  }
}

function EventTypeIcon({ ev }: { ev: LiveActivityEvent }) {
  if (ev.category === 'threat_alert') {
    return ev.severity === 'critical' ? (
      <ShieldAlert className="h-4 w-4 text-red-600 dark:text-red-400 shrink-0" aria-hidden="true" />
    ) : (
      <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0" aria-hidden="true" />
    );
  }
  if (ev.category === 'investigation') {
    return (
      <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400 shrink-0" aria-hidden="true" />
    );
  }
  return <Terminal className="h-4 w-4 text-slate-500 dark:text-slate-400 shrink-0" aria-hidden="true" />;
}

export function LiveActivityFeed({
  reports = [],
  recentInvestigations = [],
  dispatchedEmailAlerts = [],
  onInspectIndicator,
  onSelectReport,
}: LiveActivityFeedProps) {
  const privacyMode = usePrivacyMode();
  const [serverEvents, setServerEvents] = useState<LiveActivityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [streamingEnabled, setStreamingEnabled] = useState(true);
  const [streamConnected, setStreamConnected] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState<'all' | LiveActivityCategory>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [lastSyncUtc, setLastSyncUtc] = useState<string | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  const fetchActivitySnapshot = useCallback(async () => {
    try {
      const resp = await fetch('/api/activity');
      if (!resp.ok) return;
      const data = await resp.json();
      if (Array.isArray(data?.events)) {
        setServerEvents((prev) => mergeLiveActivityEvents(prev, data.events, 80));
        setLastSyncUtc(new Date().toISOString().slice(11, 19));
      }
    } catch {
      // Ignore transient network errors
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchActivitySnapshot();
  }, [fetchActivitySnapshot]);

  useEffect(() => {
    if (!streamingEnabled || typeof EventSource === 'undefined') {
      setStreamConnected(false);
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      return;
    }

    const es = new EventSource('/api/activity/stream');
    eventSourceRef.current = es;

    const handleReady = () => {
      setStreamConnected(true);
      setLastSyncUtc(new Date().toISOString().slice(11, 19));
    };

    const handleActivity = (msg: MessageEvent) => {
      try {
        const parsed = JSON.parse(msg.data) as LiveActivityEvent;
        if (parsed && parsed.id) {
          setServerEvents((prev) => mergeLiveActivityEvents(prev, [parsed], 80));
          setLastSyncUtc(new Date().toISOString().slice(11, 19));
        }
      } catch {
        // Ignore malformed event payloads
      }
    };

    const handleError = () => {
      setStreamConnected(false);
    };

    es.addEventListener('ready', handleReady);
    es.addEventListener('activity', handleActivity as EventListener);
    es.onerror = handleError;

    return () => {
      es.removeEventListener('ready', handleReady);
      es.removeEventListener('activity', handleActivity as EventListener);
      es.close();
      if (eventSourceRef.current === es) {
        eventSourceRef.current = null;
      }
      setStreamConnected(false);
    };
  }, [streamingEnabled]);

  const combinedEvents = useMemo(() => {
    const localDerived: LiveActivityEvent[] = [
      ...reports.slice(0, 12).map(buildActivityFromReportMeta),
      ...recentInvestigations.slice(0, 12).map(buildActivityFromRecentInvestigation),
      ...dispatchedEmailAlerts.slice(0, 12).map(buildActivityFromEmailAlert),
    ];
    return mergeLiveActivityEvents(serverEvents, localDerived, 80);
  }, [serverEvents, reports, recentInvestigations, dispatchedEmailAlerts]);

  const summary = useMemo(() => summarizeLiveActivity(combinedEvents), [combinedEvents]);

  const visibleEvents = useMemo(
    () =>
      filterLiveActivityEvents(combinedEvents, {
        category: categoryFilter,
        searchQuery,
      }),
    [combinedEvents, categoryFilter, searchQuery],
  );

  return (
    <section
      aria-label="Live Activity Feed"
      data-testid="live-activity-feed"
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 print:hidden"
    >
      <div className="flex flex-col gap-3 border-b border-slate-200 dark:border-slate-800 px-5 py-4 lg:flex-row lg:items-center lg:justify-between md:px-6">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Activity className="h-4 w-4 text-red-600 dark:text-red-400 shrink-0" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">
              Live Activity
            </h2>
            <span className="font-mono text-xs text-slate-500 dark:text-slate-400 tabular-nums">
              · {summary.threatAlerts} alert{summary.threatAlerts === 1 ? '' : 's'} · {summary.investigations} run{summary.investigations === 1 ? '' : 's'} · {summary.systemEvents} system event{summary.systemEvents === 1 ? '' : 's'}
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            Real-time stream of threshold alerts, completed enrichments, and provider telemetry
            {lastSyncUtc && (
              <span className="font-mono tabular-nums"> · Synced {lastSyncUtc} UTC</span>
            )}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            data-testid="live-activity-stream-toggle"
            aria-pressed={streamingEnabled}
            onClick={() => setStreamingEnabled((prev) => !prev)}
            className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              streamingEnabled
                ? 'border-emerald-200 dark:border-emerald-800 bg-emerald-50/70 dark:bg-emerald-950/30 text-emerald-800 dark:text-emerald-300'
                : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800'
            }`}
          >
            {streamingEnabled ? (
              <>
                <Pause className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span>{streamConnected ? 'Live Stream Active' : 'Connecting Stream...'}</span>
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span>Stream Paused</span>
              </>
            )}
          </button>

          <button
            type="button"
            data-testid="live-activity-refresh-btn"
            onClick={fetchActivitySnapshot}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
            Refresh
          </button>
        </div>
      </div>

      <div className="flex flex-col gap-3 border-b border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-800/30 px-5 py-3 sm:flex-row sm:items-center sm:justify-between md:px-6">
        <div
          className="inline-flex flex-wrap items-center rounded-lg bg-slate-200/70 dark:bg-slate-800 p-1 self-start sm:self-auto"
          role="group"
          aria-label="Filter live activity category"
        >
          {CATEGORY_TABS.map((tab) => {
            const isActive = categoryFilter === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                data-testid={`live-activity-filter-${tab.id}`}
                onClick={() => setCategoryFilter(tab.id)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  isActive
                    ? 'bg-white dark:bg-slate-950 text-slate-950 dark:text-slate-50 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        <div className="relative w-full sm:w-64 shrink-0">
          <Search
            className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400 dark:text-slate-500"
            aria-hidden="true"
          />
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter activity stream..."
            aria-label="Filter live activity stream"
            data-testid="live-activity-search"
            className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 py-1.5 pl-8 pr-3 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:outline-none"
          />
        </div>
      </div>

      {loading ? (
        <div className="divide-y divide-slate-100 dark:divide-slate-800 px-5 md:px-6">
          {[0, 1, 2].map((idx) => (
            <div key={idx} className="flex items-center justify-between gap-4 py-3.5 animate-pulse">
              <div className="space-y-2 flex-1">
                <div className="h-3.5 w-52 rounded bg-slate-200 dark:bg-slate-800" />
                <div className="h-3 w-80 rounded bg-slate-100 dark:bg-slate-800/70" />
              </div>
              <div className="h-3 w-20 rounded bg-slate-100 dark:bg-slate-800/70" />
            </div>
          ))}
        </div>
      ) : visibleEvents.length === 0 ? (
        <div className="px-6 py-8 text-center text-xs text-slate-500 dark:text-slate-400">
          {combinedEvents.length === 0
            ? 'No live events recorded yet. Run an IOC enrichment or trigger an alert to stream telemetry here.'
            : 'No activity entries match the active category or search filter.'}
        </div>
      ) : (
        <ul
          data-testid="live-activity-scroll-list"
          className="max-h-[300px] divide-y divide-slate-100 dark:divide-slate-800 overflow-y-auto"
        >
          {visibleEvents.map((ev) => {
            const dateBadge = formatActivityDateBadge(ev.timestamp);
            const utcTime = formatActivityUtcTime(ev.timestamp);
            return (
              <li
                key={ev.id}
                data-testid="live-activity-row"
                className="flex flex-col gap-2 px-5 py-3 transition-colors hover:bg-slate-50/80 dark:hover:bg-slate-800/40 sm:flex-row sm:items-center sm:justify-between md:px-6"
              >
                <div className="flex items-start gap-3 min-w-0">
                  <div className="mt-0.5">
                    <EventTypeIcon ev={ev} />
                  </div>
                  <div className="min-w-0 space-y-0.5">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs">
                      <span className="font-semibold text-slate-900 dark:text-slate-100">
                        {maskSensitiveText(ev.title, privacyMode)}
                      </span>
                      <span aria-hidden="true" className="text-slate-300 dark:text-slate-700">·</span>
                      <span className={`font-medium ${getSeverityTextClass(ev.severity)}`}>
                        {getCategoryLabel(ev.category)}
                      </span>
                      {typeof ev.confidenceScore === 'number' && (
                        <>
                          <span aria-hidden="true" className="text-slate-300 dark:text-slate-700">·</span>
                          <span className="font-mono font-semibold text-slate-700 dark:text-slate-300 tabular-nums">
                            {ev.confidenceScore}/100
                          </span>
                        </>
                      )}
                    </div>
                    <p className="text-xs text-slate-600 dark:text-slate-400 break-words">
                      {maskSensitiveText(ev.detail, privacyMode)}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3 pl-7 sm:pl-0 shrink-0">
                  {ev.indicator && onInspectIndicator && (
                    <button
                      type="button"
                      onClick={() => onInspectIndicator(ev.indicator!)}
                      className="text-xs font-medium text-slate-600 dark:text-slate-300 hover:text-red-700 dark:hover:text-red-400 hover:underline whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Filter IOC
                    </button>
                  )}
                  {ev.reportName && onSelectReport && (
                    <button
                      type="button"
                      onClick={() => onSelectReport(ev.reportName!)}
                      className="text-xs font-medium text-slate-600 dark:text-slate-300 hover:text-red-700 dark:hover:text-red-400 hover:underline whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Open Run
                    </button>
                  )}
                  <time
                    dateTime={ev.timestamp}
                    title={dateBadge ? `${dateBadge} ${utcTime}` : utcTime}
                    className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums whitespace-nowrap"
                  >
                    {utcTime}
                  </time>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
