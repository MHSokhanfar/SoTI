import type { LookupResult, SourceSelection } from './indicators';

export const RECENT_INVESTIGATIONS_STORAGE_KEY = 'soti_recent_investigations_v1';
export const MAX_RECENT_INVESTIGATIONS = 20;

export interface RecentVerdictSummary {
  malicious: number;
  suspicious: number;
  clean: number;
  unknown: number;
  other: number;
}

export interface RecentQuotaSkippedItem {
  providerId: string;
  name: string;
  used: number;
  limit: number;
  reason: string;
}

export interface RecentInvestigationEntry {
  id: string;
  createdAt: string;
  rawInput: string;
  normalizedInput: string;
  indicators: string[];
  indicatorCount: number;
  source: SourceSelection;
  customSources: string[];
  useCustomSources: boolean;
  sourceLabels: string[];
  mode: 'sample' | 'live';
  verdictSummary: RecentVerdictSummary;
  results: LookupResult[];
  invalidTokens: string[];
  quotaSkipped: RecentQuotaSkippedItem[];
  reportFile: string | null;
}

export interface StorageLike {
  getItem: (key: string) => string | null;
  setItem: (key: string, value: string) => void;
  removeItem?: (key: string) => void;
}

export function summarizeLookupVerdicts(results: LookupResult[]): RecentVerdictSummary {
  const summary: RecentVerdictSummary = {
    malicious: 0,
    suspicious: 0,
    clean: 0,
    unknown: 0,
    other: 0,
  };

  for (const r of results) {
    if (r.status !== 'ok') {
      summary.other += 1;
      continue;
    }
    if (r.verdict === 'Malicious') summary.malicious += 1;
    else if (r.verdict === 'Suspicious') summary.suspicious += 1;
    else if (r.verdict === 'Clean') summary.clean += 1;
    else summary.unknown += 1;
  }
  return summary;
}

export function getPrimaryVerdictBadge(summary: RecentVerdictSummary): {
  label: string;
  tone: 'malicious' | 'suspicious' | 'clean' | 'neutral';
} {
  if (summary.malicious > 0) {
    return { label: `${summary.malicious} malicious`, tone: 'malicious' };
  }
  if (summary.suspicious > 0) {
    return { label: `${summary.suspicious} suspicious`, tone: 'suspicious' };
  }
  if (summary.clean > 0) {
    return { label: `${summary.clean} clean`, tone: 'clean' };
  }
  if (summary.unknown > 0) {
    return { label: `${summary.unknown} unknown`, tone: 'neutral' };
  }
  if (summary.other > 0) {
    return { label: `${summary.other} status`, tone: 'neutral' };
  }
  return { label: '0 results', tone: 'neutral' };
}

export function formatInvestigationTitle(indicators: string[], fallbackRaw: string): string {
  if (indicators.length === 1) return indicators[0];
  if (indicators.length > 1) return `${indicators[0]} +${indicators.length - 1} more`;
  const trimmed = fallbackRaw.trim();
  return trimmed.length > 36 ? `${trimmed.slice(0, 33)}...` : trimmed || 'Empty query';
}

export function buildRecentInvestigationEntry(params: {
  rawInput: string;
  normalizedInput: string;
  indicators: string[];
  source: SourceSelection;
  customSources: string[];
  useCustomSources: boolean;
  sourceLabels: string[];
  mode: 'sample' | 'live';
  results: LookupResult[];
  invalidTokens: string[];
  quotaSkipped: RecentQuotaSkippedItem[];
  reportFile: string | null;
  now?: Date;
  id?: string;
}): RecentInvestigationEntry {
  const now = params.now ?? new Date();
  const createdAt = now.toISOString();
  const id =
    params.id ||
    `inv_${now.getTime()}_${Math.random().toString(16).slice(2, 8)}`;

  const uniqueIndicators = Array.from(
    new Set(params.indicators.map((ind) => ind.trim()).filter(Boolean)),
  );

  return {
    id,
    createdAt,
    rawInput: params.rawInput,
    normalizedInput: params.normalizedInput,
    indicators: uniqueIndicators,
    indicatorCount: uniqueIndicators.length,
    source: params.source,
    customSources: [...params.customSources],
    useCustomSources: params.useCustomSources,
    sourceLabels: [...params.sourceLabels],
    mode: params.mode,
    verdictSummary: summarizeLookupVerdicts(params.results),
    results: params.results,
    invalidTokens: [...params.invalidTokens],
    quotaSkipped: [...params.quotaSkipped],
    reportFile: params.reportFile,
  };
}

export function prependRecentInvestigation(
  current: RecentInvestigationEntry[],
  entry: RecentInvestigationEntry,
  maxItems: number = MAX_RECENT_INVESTIGATIONS,
): RecentInvestigationEntry[] {
  const limit = Math.max(1, Math.floor(maxItems));
  const filtered = current.filter((item) => item.id !== entry.id);
  return [entry, ...filtered].slice(0, limit);
}

export function removeRecentInvestigation(
  current: RecentInvestigationEntry[],
  id: string,
): RecentInvestigationEntry[] {
  return current.filter((item) => item.id !== id);
}

function isValidRecentEntry(candidate: unknown): candidate is RecentInvestigationEntry {
  if (!candidate || typeof candidate !== 'object') return false;
  const obj = candidate as Record<string, unknown>;
  return (
    typeof obj.id === 'string' &&
    obj.id.length > 0 &&
    typeof obj.createdAt === 'string' &&
    typeof obj.rawInput === 'string' &&
    typeof obj.normalizedInput === 'string' &&
    Array.isArray(obj.indicators) &&
    Array.isArray(obj.results) &&
    (obj.mode === 'sample' || obj.mode === 'live')
  );
}

export function loadRecentInvestigations(storage?: StorageLike | null): RecentInvestigationEntry[] {
  if (!storage) return [];
  try {
    const raw = storage.getItem(RECENT_INVESTIGATIONS_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isValidRecentEntry).slice(0, MAX_RECENT_INVESTIGATIONS);
  } catch {
    return [];
  }
}

export function saveRecentInvestigations(
  storage: StorageLike | null | undefined,
  entries: RecentInvestigationEntry[],
): boolean {
  if (!storage) return false;
  try {
    if (entries.length === 0 && typeof storage.removeItem === 'function') {
      storage.removeItem(RECENT_INVESTIGATIONS_STORAGE_KEY);
      return true;
    }
    const trimmed = entries.slice(0, MAX_RECENT_INVESTIGATIONS);
    storage.setItem(RECENT_INVESTIGATIONS_STORAGE_KEY, JSON.stringify(trimmed));
    return true;
  } catch {
    return false;
  }
}

export function clearRecentInvestigations(storage?: StorageLike | null): boolean {
  if (!storage) return false;
  try {
    if (typeof storage.removeItem === 'function') {
      storage.removeItem(RECENT_INVESTIGATIONS_STORAGE_KEY);
    } else {
      storage.setItem(RECENT_INVESTIGATIONS_STORAGE_KEY, '[]');
    }
    return true;
  } catch {
    return false;
  }
}

export function formatRelativeTime(iso: string, now: Date = new Date()): string {
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return 'Unknown';
  const diffSec = Math.max(0, Math.floor((now.getTime() - ts) / 1000));
  if (diffSec < 45) return 'Just now';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return new Date(ts).toISOString().slice(5, 16).replace('T', ' ') + ' UTC';
}
