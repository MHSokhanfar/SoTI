import { preprocessInputForLookup, type LookupResult } from './indicators';

export const LIVE_POLL_INTERVAL_OPTIONS = [
  { seconds: 15, label: '15s' },
  { seconds: 30, label: '30s' },
  { seconds: 60, label: '60s' },
  { seconds: 300, label: '5m' },
] as const;

export const DEFAULT_LIVE_POLL_SECONDS = 30;

export function normalizeLivePollInterval(raw: unknown): number {
  const num = Number(raw);
  if (LIVE_POLL_INTERVAL_OPTIONS.some((opt) => opt.seconds === num)) {
    return num;
  }
  return DEFAULT_LIVE_POLL_SECONDS;
}

export function extractActiveIndicatorsForPolling(
  results: LookupResult[],
  rawInput: string,
): string[] {
  const seen = new Set<string>();
  const active: string[] = [];

  for (const r of results) {
    const cleaned = (r.indicator || '').trim();
    const key = cleaned.toLowerCase();
    if (cleaned && !seen.has(key)) {
      seen.add(key);
      active.push(cleaned);
    }
  }

  if (active.length > 0) {
    return active;
  }

  const prep = preprocessInputForLookup(rawInput);
  for (const item of prep.validIndicators) {
    const key = item.cleaned.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      active.push(item.cleaned);
    }
  }
  return active;
}

export function formatLiveCountdown(remainingSeconds: number): string {
  const clamped = Math.max(0, Math.ceil(remainingSeconds));
  if (clamped < 60) {
    return `${clamped}s`;
  }
  const mins = Math.floor(clamped / 60);
  const secs = clamped % 60;
  return `${mins}m ${String(secs).padStart(2, '0')}s`;
}

export function formatUtcClockTime(epochMs: number): string {
  const date = new Date(epochMs);
  if (!Number.isFinite(date.getTime())) return '—';
  return `${date.toISOString().slice(11, 19)} UTC`;
}

export interface LivePollDeltaSummary {
  changedCount: number;
  escalatedCount: number;
  totalResults: number;
  checkedAtIso: string;
}

const VERDICT_RANK: Record<LookupResult['verdict'], number> = {
  Unknown: 0,
  Clean: 1,
  Suspicious: 2,
  Malicious: 3,
};

export function computeLivePollDelta(
  prevResults: LookupResult[],
  nextResults: LookupResult[],
  nowIso: string = new Date().toISOString(),
): LivePollDeltaSummary {
  const prevByKey = new Map<string, LookupResult>();
  for (const row of prevResults) {
    const key = `${row.indicator.trim().toLowerCase()}|${row.sourceId}`;
    prevByKey.set(key, row);
  }

  let changedCount = 0;
  let escalatedCount = 0;

  for (const row of nextResults) {
    const key = `${row.indicator.trim().toLowerCase()}|${row.sourceId}`;
    const prev = prevByKey.get(key);
    if (!prev) {
      changedCount += 1;
      continue;
    }
    if (
      prev.verdict !== row.verdict ||
      prev.score !== row.score ||
      prev.status !== row.status
    ) {
      changedCount += 1;
      if (VERDICT_RANK[row.verdict] > VERDICT_RANK[prev.verdict]) {
        escalatedCount += 1;
      }
    }
  }

  return {
    changedCount,
    escalatedCount,
    totalResults: nextResults.length,
    checkedAtIso: nowIso,
  };
}
