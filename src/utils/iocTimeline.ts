import type { LookupResult, Verdict } from './indicators';

export type TimelineCategory =
  | 'registered'
  | 'first_seen'
  | 'last_seen'
  | 'reported'
  | 'analysis'
  | 'updated'
  | 'expires';

export interface IocTimelineEvent {
  id: string;
  indicator: string;
  indicatorType: LookupResult['type'];
  source: string;
  sourceId: string;
  category: TimelineCategory;
  label: string;
  detailKey: string;
  timestampIso: string;
  displayTime: string;
  epochMs: number;
  verdict: Verdict;
  summary: string;
}

interface DetailFieldSpec {
  match: (normalizedKey: string) => boolean;
  category: TimelineCategory;
  label: string;
}

const DETAIL_TIME_SPECS: DetailFieldSpec[] = [
  {
    match: (k) =>
      k === 'created' ||
      k === 'creation date' ||
      k === 'registered' ||
      k === 'domain created' ||
      k === 'registration date' ||
      k === 'whois created',
    category: 'registered',
    label: 'Domain Registered / Created',
  },
  {
    match: (k) => k === 'first seen' || k === 'first_seen' || k === 'first submission',
    category: 'first_seen',
    label: 'First Seen',
  },
  {
    match: (k) => k === 'last seen' || k === 'last_seen' || k === 'last submission',
    category: 'last_seen',
    label: 'Last Seen',
  },
  {
    match: (k) => k === 'last reported' || k === 'last_reported' || k === 'reported at',
    category: 'reported',
    label: 'Last Abuse Report',
  },
  {
    match: (k) =>
      k === 'last analysis' ||
      k === 'last_analysis' ||
      k === 'scan time' ||
      k === 'scan date' ||
      k === 'latest scan',
    category: 'analysis',
    label: 'Security Scan / Analysis',
  },
  {
    match: (k) => k === 'updated' || k === 'last modified' || k === 'last updated',
    category: 'updated',
    label: 'Record Updated',
  },
  {
    match: (k) => k === 'expires' || k === 'expiration date' || k === 'registry expiry date',
    category: 'expires',
    label: 'Registration Expires',
  },
];

export function parseFlexibleTimestamp(raw: unknown): Date | null {
  if (raw === null || raw === undefined || typeof raw === 'boolean') return null;

  if (typeof raw === 'number') {
    if (!Number.isFinite(raw) || raw <= 0) return null;
    // Heuristic: < 1e11 means Unix seconds; otherwise milliseconds
    const ms = raw < 1e11 ? raw * 1000 : raw;
    const d = new Date(ms);
    return Number.isFinite(d.getTime()) && d.getUTCFullYear() >= 1990 && d.getUTCFullYear() <= 2100
      ? d
      : null;
  }

  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (
    !trimmed ||
    /^(?:n\/a|never|none|unknown|-|—)$/i.test(trimmed)
  ) {
    return null;
  }

  // Numeric Unix timestamp in string form
  if (/^\d{9,13}$/.test(trimmed)) {
    return parseFlexibleTimestamp(Number(trimmed));
  }

  // Handle "YYYY-MM-DD HH:mm UTC" or "YYYY-MM-DD HH:mm:ss UTC"
  const utcSpaceMatch = trimmed.match(
    /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2})?)\s*(?:UTC|GMT)?$/i,
  );
  if (utcSpaceMatch) {
    const timePart = utcSpaceMatch[2].length === 5 ? `${utcSpaceMatch[2]}:00` : utcSpaceMatch[2];
    const parsed = new Date(`${utcSpaceMatch[1]}T${timePart}Z`);
    if (Number.isFinite(parsed.getTime())) return parsed;
  }

  // Handle pure ISO date "YYYY-MM-DD"
  if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
    const parsed = new Date(`${trimmed}T00:00:00Z`);
    if (Number.isFinite(parsed.getTime())) return parsed;
  }

  // Reject bare short strings without date separators
  if (!/[T:/-]/.test(trimmed) || !/\d{4}/.test(trimmed)) {
    return null;
  }

  const parsedMs = Date.parse(trimmed);
  if (!Number.isFinite(parsedMs)) return null;
  const d = new Date(parsedMs);
  return d.getUTCFullYear() >= 1990 && d.getUTCFullYear() <= 2100 ? d : null;
}

export function formatTimelineUtc(date: Date): string {
  return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

export function extractIocTimelineEvents(
  results: LookupResult[],
  options: { indicatorFilter?: string | null; order?: 'asc' | 'desc' } = {},
): IocTimelineEvent[] {
  const filterKey = options.indicatorFilter?.trim().toLowerCase() || null;
  const order = options.order ?? 'asc';
  const events: IocTimelineEvent[] = [];
  const seenKeys = new Set<string>();

  for (const res of results) {
    if (!res || !res.indicator) continue;
    if (filterKey && res.indicator.trim().toLowerCase() !== filterKey) continue;

    const details = res.details || {};
    for (const [detailKey, rawVal] of Object.entries(details)) {
      const normKey = detailKey.trim().toLowerCase().replace(/[_-]+/g, ' ');
      const spec = DETAIL_TIME_SPECS.find((s) => s.match(normKey));
      if (!spec) continue;

      const date = parseFlexibleTimestamp(rawVal);
      if (!date) continue;

      const timestampIso = date.toISOString();
      const dedupKey = `${res.indicator.toLowerCase()}|${res.sourceId}|${spec.category}|${timestampIso}`;
      if (seenKeys.has(dedupKey)) continue;
      seenKeys.add(dedupKey);

      events.push({
        id: `tl-${res.sourceId}-${spec.category}-${events.length}`,
        indicator: res.indicator,
        indicatorType: res.type,
        source: res.source,
        sourceId: res.sourceId,
        category: spec.category,
        label: spec.label,
        detailKey,
        timestampIso,
        displayTime: formatTimelineUtc(date),
        epochMs: date.getTime(),
        verdict: res.verdict,
        summary: res.summary,
      });
    }
  }

  events.sort((a, b) => {
    if (a.epochMs !== b.epochMs) {
      return order === 'asc' ? a.epochMs - b.epochMs : b.epochMs - a.epochMs;
    }
    return a.indicator.localeCompare(b.indicator) || a.source.localeCompare(b.source);
  });

  return events;
}
