import type { UnifiedBatchRow } from './bulkAnalysis';
import type { LookupResult, Verdict } from './indicators';
import { parseFlexibleTimestamp } from './iocTimeline';
import type { IocConfidenceSummary } from './riskScoring';

export type ResultsSortKey =
  | 'indicator'
  | 'type'
  | 'source'
  | 'verdict'
  | 'riskScore'
  | 'lastSeen'
  | 'score'
  | 'hits';

export type SortDirection = 'asc' | 'desc';

export interface ResultsSortState {
  key: ResultsSortKey;
  direction: SortDirection;
}

export interface LastSeenInfo {
  epochMs: number | null;
  displayUtc: string;
  isoTimestamp: string | null;
  fieldLabel: string | null;
}

const VERDICT_SEVERITY_RANK: Record<Verdict, number> = {
  Malicious: 4,
  Suspicious: 3,
  Clean: 2,
  Unknown: 1,
};

const LAST_SEEN_KEY_TIERS: Array<{ priority: number; match: (k: string) => boolean }> = [
  {
    priority: 0,
    match: (k) => k === 'last seen' || k === 'last_seen' || k === 'last submission',
  },
  {
    priority: 1,
    match: (k) => k === 'last reported' || k === 'last_reported' || k === 'reported at',
  },
  {
    priority: 2,
    match: (k) =>
      k === 'last analysis' ||
      k === 'last_analysis' ||
      k === 'scan time' ||
      k === 'scan date' ||
      k === 'latest scan',
  },
  {
    priority: 3,
    match: (k) => k === 'updated' || k === 'last modified' || k === 'last updated',
  },
];

const DEFAULT_DESC_KEYS = new Set<ResultsSortKey>([
  'riskScore',
  'lastSeen',
  'verdict',
  'score',
  'hits',
]);

export function getDefaultDirectionForSortKey(key: ResultsSortKey): SortDirection {
  return DEFAULT_DESC_KEYS.has(key) ? 'desc' : 'asc';
}

export function toggleResultsSortState(
  current: ResultsSortState | null,
  key: ResultsSortKey,
): ResultsSortState {
  if (current && current.key === key) {
    return {
      key,
      direction: current.direction === 'asc' ? 'desc' : 'asc',
    };
  }
  return {
    key,
    direction: getDefaultDirectionForSortKey(key),
  };
}

export function formatShortUtcTimestamp(date: Date): string {
  return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

export function extractResultLastSeen(result: LookupResult): LastSeenInfo {
  const details = result.details || {};
  let bestPriority = Number.POSITIVE_INFINITY;
  let bestDate: Date | null = null;
  let bestField: string | null = null;

  for (const [rawKey, rawValue] of Object.entries(details)) {
    const normKey = rawKey.trim().toLowerCase().replace(/[_-]+/g, ' ');
    const tier = LAST_SEEN_KEY_TIERS.find((t) => t.match(normKey));
    if (!tier) continue;

    const parsed = parseFlexibleTimestamp(rawValue);
    if (!parsed) continue;

    if (
      tier.priority < bestPriority ||
      (tier.priority === bestPriority && bestDate && parsed.getTime() > bestDate.getTime())
    ) {
      bestPriority = tier.priority;
      bestDate = parsed;
      bestField = rawKey;
    }
  }

  if (!bestDate) {
    return {
      epochMs: null,
      displayUtc: '—',
      isoTimestamp: null,
      fieldLabel: null,
    };
  }

  return {
    epochMs: bestDate.getTime(),
    displayUtc: formatShortUtcTimestamp(bestDate),
    isoTimestamp: bestDate.toISOString(),
    fieldLabel: bestField,
  };
}

export function buildLastSeenByIndicatorMap(results: LookupResult[]): Map<string, LastSeenInfo> {
  const map = new Map<string, LastSeenInfo>();
  for (const r of results) {
    const key = r.indicator.trim().toLowerCase();
    if (!key) continue;
    const candidate = extractResultLastSeen(r);
    if (candidate.epochMs === null) {
      if (!map.has(key)) map.set(key, candidate);
      continue;
    }
    const existing = map.get(key);
    if (!existing || existing.epochMs === null || candidate.epochMs > existing.epochMs) {
      map.set(key, candidate);
    }
  }
  return map;
}

export function parseComparableScoreValue(rawScore: string, status: LookupResult['status']): number | null {
  if (status !== 'ok') return null;
  const trimmed = (rawScore || '').trim();
  if (!trimmed || /^n\/a$/i.test(trimmed) || trimmed === '—') return null;

  const ratioMatch = trimmed.match(/^(-?\d+(?:\.\d+)?)\s*\/\s*(\d+(?:\.\d+)?)$/);
  if (ratioMatch) {
    const num = Number(ratioMatch[1]);
    const den = Number(ratioMatch[2]);
    if (Number.isFinite(num) && Number.isFinite(den) && den > 0) {
      return (num / den) * 100;
    }
  }

  const leadingNum = trimmed.match(/^(-?\d+(?:\.\d+)?)/);
  if (leadingNum) {
    const parsed = Number(leadingNum[1]);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function compareNullableNumbers(
  a: number | null | undefined,
  b: number | null | undefined,
  direction: SortDirection,
): number {
  const aValid = typeof a === 'number' && Number.isFinite(a);
  const bValid = typeof b === 'number' && Number.isFinite(b);
  if (!aValid && !bValid) return 0;
  if (!aValid) return 1; // Always push missing/N/A metrics to bottom
  if (!bValid) return -1;
  return direction === 'asc' ? a - b : b - a;
}

function compareStrings(a: string, b: string, direction: SortDirection): number {
  const cmp = a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
  return direction === 'asc' ? cmp : -cmp;
}

export function sortLookupResults(
  rows: LookupResult[],
  sort: ResultsSortState | null,
  confidenceByIndicator: Map<string, IocConfidenceSummary>,
): LookupResult[] {
  if (!sort) return rows;

  const lastSeenCache = rows.map((r) => extractResultLastSeen(r));
  const indexed = rows.map((row, idx) => ({
    row,
    idx,
    lastSeen: lastSeenCache[idx],
    confidence: confidenceByIndicator.get(row.indicator.trim().toLowerCase())?.confidenceScore ?? null,
    numericScore: parseComparableScoreValue(row.score, row.status),
  }));

  indexed.sort((a, b) => {
    let cmp = 0;
    switch (sort.key) {
      case 'indicator':
        cmp = compareStrings(a.row.indicator, b.row.indicator, sort.direction);
        break;
      case 'type':
        cmp = compareStrings(a.row.type, b.row.type, sort.direction);
        break;
      case 'source':
        cmp = compareStrings(a.row.source, b.row.source, sort.direction);
        break;
      case 'verdict': {
        const aRank = a.row.status === 'ok' ? VERDICT_SEVERITY_RANK[a.row.verdict] ?? 0 : 0;
        const bRank = b.row.status === 'ok' ? VERDICT_SEVERITY_RANK[b.row.verdict] ?? 0 : 0;
        cmp = sort.direction === 'asc' ? aRank - bRank : bRank - aRank;
        break;
      }
      case 'riskScore':
        cmp = compareNullableNumbers(a.confidence, b.confidence, sort.direction);
        break;
      case 'lastSeen':
        cmp = compareNullableNumbers(a.lastSeen.epochMs, b.lastSeen.epochMs, sort.direction);
        break;
      case 'score':
        cmp = compareNullableNumbers(a.numericScore, b.numericScore, sort.direction);
        break;
      default:
        cmp = 0;
    }

    if (cmp !== 0) return cmp;
    const indTie = a.row.indicator.localeCompare(b.row.indicator, undefined, {
      numeric: true,
      sensitivity: 'base',
    });
    if (indTie !== 0) return indTie;
    return a.idx - b.idx;
  });

  return indexed.map((item) => item.row);
}

export function sortUnifiedBatchRows(
  rows: UnifiedBatchRow[],
  sort: ResultsSortState | null,
  lastSeenByIndicator: Map<string, LastSeenInfo>,
): UnifiedBatchRow[] {
  if (!sort) return rows;

  const indexed = rows.map((row, idx) => ({
    row,
    idx,
    lastSeenEpoch: lastSeenByIndicator.get(row.indicator.trim().toLowerCase())?.epochMs ?? null,
  }));

  indexed.sort((a, b) => {
    let cmp = 0;
    switch (sort.key) {
      case 'indicator':
        cmp = compareStrings(a.row.indicator, b.row.indicator, sort.direction);
        break;
      case 'type':
        cmp = compareStrings(a.row.type, b.row.type, sort.direction);
        break;
      case 'verdict': {
        const aRank = VERDICT_SEVERITY_RANK[a.row.overallVerdict] ?? 0;
        const bRank = VERDICT_SEVERITY_RANK[b.row.overallVerdict] ?? 0;
        cmp = sort.direction === 'asc' ? aRank - bRank : bRank - aRank;
        break;
      }
      case 'riskScore':
        cmp = compareNullableNumbers(a.row.confidenceScore, b.row.confidenceScore, sort.direction);
        break;
      case 'lastSeen':
        cmp = compareNullableNumbers(a.lastSeenEpoch, b.lastSeenEpoch, sort.direction);
        break;
      case 'hits':
        cmp = compareNullableNumbers(
          a.row.maliciousHits + a.row.suspiciousHits,
          b.row.maliciousHits + b.row.suspiciousHits,
          sort.direction,
        );
        break;
      default:
        cmp = 0;
    }

    if (cmp !== 0) return cmp;
    const indTie = a.row.indicator.localeCompare(b.row.indicator, undefined, {
      numeric: true,
      sensitivity: 'base',
    });
    if (indTie !== 0) return indTie;
    return a.idx - b.idx;
  });

  return indexed.map((item) => item.row);
}
