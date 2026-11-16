import { useMemo, useState } from 'react';
import { ArrowDownUp, CalendarClock, Clock } from 'lucide-react';
import type { LookupResult, Verdict } from '../utils/indicators';
import {
  extractIocTimelineEvents,
  type TimelineCategory,
} from '../utils/iocTimeline';

interface IocEventTimelineProps {
  results: LookupResult[];
}

function getCategoryAccentClass(category: TimelineCategory): string {
  switch (category) {
    case 'registered':
      return 'bg-slate-600 dark:bg-slate-400';
    case 'first_seen':
      return 'bg-amber-500 dark:bg-amber-400';
    case 'reported':
      return 'bg-red-600 dark:bg-red-500';
    case 'analysis':
      return 'bg-sky-600 dark:bg-sky-400';
    case 'last_seen':
      return 'bg-orange-500 dark:bg-orange-400';
    default:
      return 'bg-slate-400 dark:bg-slate-500';
  }
}

function getVerdictTextClass(verdict: Verdict): string {
  switch (verdict) {
    case 'Malicious':
      return 'text-red-700 dark:text-red-400 font-semibold';
    case 'Suspicious':
      return 'text-amber-700 dark:text-amber-400 font-semibold';
    case 'Clean':
      return 'text-emerald-700 dark:text-emerald-400 font-medium';
    default:
      return 'text-slate-500 dark:text-slate-400 font-medium';
  }
}

export function IocEventTimeline({ results }: IocEventTimelineProps) {
  const [selectedIndicator, setSelectedIndicator] = useState<string>('all');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  const allEvents = useMemo(
    () => extractIocTimelineEvents(results, { order: 'asc' }),
    [results],
  );

  const uniqueIndicators = useMemo(
    () => Array.from(new Set(allEvents.map((e) => e.indicator))),
    [allEvents],
  );

  const activeIndicatorFilter =
    selectedIndicator !== 'all' && uniqueIndicators.includes(selectedIndicator)
      ? selectedIndicator
      : 'all';

  const visibleEvents = useMemo(
    () =>
      extractIocTimelineEvents(results, {
        indicatorFilter: activeIndicatorFilter === 'all' ? null : activeIndicatorFilter,
        order: sortOrder,
      }),
    [results, activeIndicatorFilter, sortOrder],
  );

  if (allEvents.length === 0) {
    return null;
  }

  return (
    <section
      aria-label="Chronological IOC Activity Timeline"
      data-testid="ioc-event-timeline"
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 md:p-6"
    >
      <div className="flex flex-col gap-3 border-b border-slate-100 dark:border-slate-800 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <CalendarClock
              className="h-4 w-4 shrink-0 text-slate-600 dark:text-slate-400"
              aria-hidden="true"
            />
            <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">
              Chronological IOC Activity Timeline
            </h2>
            <span className="font-mono text-xs text-slate-500 dark:text-slate-400 tabular-nums">
              ({visibleEvents.length} event{visibleEvents.length === 1 ? '' : 's'})
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            Time-ordered domain registrations, first/last seen sightings, abuse reports, and security scans (UTC).
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0 print:hidden">
          {uniqueIndicators.length > 1 && (
            <select
              aria-label="Filter timeline by indicator"
              data-testid="timeline-indicator-filter"
              value={activeIndicatorFilter}
              onChange={(e) => setSelectedIndicator(e.target.value)}
              className="max-w-[200px] rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-1.5 font-mono text-xs font-medium text-slate-800 dark:text-slate-200 focus:border-red-600 focus:outline-none cursor-pointer"
            >
              <option value="all">All IOCs ({uniqueIndicators.length})</option>
              {uniqueIndicators.map((ind) => (
                <option key={ind} value={ind}>
                  {ind}
                </option>
              ))}
            </select>
          )}

          <button
            type="button"
            data-testid="timeline-sort-toggle"
            onClick={() => setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'))}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <ArrowDownUp className="h-3.5 w-3.5" aria-hidden="true" />
            <span>{sortOrder === 'asc' ? 'Oldest First' : 'Newest First'}</span>
          </button>
        </div>
      </div>

      <ol className="relative mt-5 ml-2 border-l border-slate-200 dark:border-slate-800 pl-5 space-y-4">
        {visibleEvents.map((ev) => (
          <li
            key={ev.id}
            data-testid="ioc-timeline-event"
            className="relative"
          >
            <span
              aria-hidden="true"
              className={`absolute -left-[25px] top-1.5 h-2.5 w-2.5 rounded-full ring-4 ring-white dark:ring-slate-900 ${getCategoryAccentClass(ev.category)}`}
            />

            <div className="flex flex-col gap-1 sm:flex-row sm:items-baseline sm:justify-between sm:gap-4">
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 min-w-0">
                <span className="inline-flex items-center gap-1 font-mono text-xs font-semibold text-slate-900 dark:text-slate-100 tabular-nums">
                  <Clock className="h-3 w-3 text-slate-400 dark:text-slate-500 shrink-0" aria-hidden="true" />
                  <span>{ev.displayTime}</span>
                </span>
                <span className="text-slate-300 dark:text-slate-700" aria-hidden="true">·</span>
                <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                  {ev.label}
                </span>
                <span className="text-slate-300 dark:text-slate-700" aria-hidden="true">·</span>
                <span className="font-mono text-xs font-medium text-slate-950 dark:text-slate-50 break-all">
                  {ev.indicator}
                </span>
              </div>

              <div className="flex items-center gap-2 text-xs shrink-0">
                <span className="text-slate-500 dark:text-slate-400">{ev.source}</span>
                <span className="text-slate-300 dark:text-slate-700" aria-hidden="true">·</span>
                <span className={getVerdictTextClass(ev.verdict)}>{ev.verdict}</span>
              </div>
            </div>

            <p className="mt-0.5 text-xs text-slate-600 dark:text-slate-400">
              {ev.detailKey}: {ev.summary}
            </p>
          </li>
        ))}
      </ol>
    </section>
  );
}
