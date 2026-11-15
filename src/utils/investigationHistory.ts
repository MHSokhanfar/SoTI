import type { LookupResult, SourceSelection } from './indicators';

export const RECENT_INVESTIGATIONS_STORAGE_KEY = 'soti_recent_investigations_v1';
export const MAX_RECENT_INVESTIGATIONS = 20;
export const MAX_INVESTIGATION_NOTES_LENGTH = 5000;
export const MAX_INVESTIGATION_TITLE_LENGTH = 120;

export function normalizeInvestigationNotes(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  return raw.replace(/\r\n?/g, '\n').trim().slice(0, MAX_INVESTIGATION_NOTES_LENGTH);
}

export function normalizeInvestigationTitle(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  return raw.replace(/\s+/g, ' ').trim().slice(0, MAX_INVESTIGATION_TITLE_LENGTH);
}

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
  includeThreatFox?: boolean | null;
  includeUrlscan?: boolean | null;
  sourceLabels: string[];
  mode: 'sample' | 'live';
  verdictSummary: RecentVerdictSummary;
  results: LookupResult[];
  invalidTokens: string[];
  quotaSkipped: RecentQuotaSkippedItem[];
  reportFile: string | null;
  tags?: string[];
  notes?: string;
  notesUpdatedAt?: string;
  pinned?: boolean;
  pinnedAt?: string;
  customTitle?: string;
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

export function getInvestigationDisplayTitle(
  entry: Pick<RecentInvestigationEntry, 'customTitle' | 'indicators' | 'normalizedInput' | 'rawInput'>,
): string {
  const custom = normalizeInvestigationTitle(entry.customTitle);
  if (custom.length > 0) return custom;
  return formatInvestigationTitle(entry.indicators, entry.normalizedInput || entry.rawInput);
}

export function buildRecentInvestigationEntry(params: {
  rawInput: string;
  normalizedInput: string;
  indicators: string[];
  source: SourceSelection;
  customSources: string[];
  useCustomSources: boolean;
  includeThreatFox?: boolean | null;
  includeUrlscan?: boolean | null;
  sourceLabels: string[];
  mode: 'sample' | 'live';
  results: LookupResult[];
  invalidTokens: string[];
  quotaSkipped: RecentQuotaSkippedItem[];
  reportFile: string | null;
  tags?: string[];
  notes?: string;
  notesUpdatedAt?: string;
  pinned?: boolean;
  pinnedAt?: string;
  customTitle?: string;
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
  const cleanTags = Array.isArray(params.tags)
    ? Array.from(new Set(params.tags.map((t) => String(t).trim()).filter(Boolean)))
    : undefined;
  const cleanNotes = normalizeInvestigationNotes(params.notes);
  const cleanTitle = normalizeInvestigationTitle(params.customTitle);

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
    ...(params.includeThreatFox !== undefined ? { includeThreatFox: params.includeThreatFox } : {}),
    ...(params.includeUrlscan !== undefined ? { includeUrlscan: params.includeUrlscan } : {}),
    sourceLabels: [...params.sourceLabels],
    mode: params.mode,
    verdictSummary: summarizeLookupVerdicts(params.results),
    results: params.results,
    invalidTokens: [...params.invalidTokens],
    quotaSkipped: [...params.quotaSkipped],
    reportFile: params.reportFile,
    ...(cleanTags && cleanTags.length > 0 ? { tags: cleanTags } : {}),
    ...(cleanNotes.length > 0
      ? {
          notes: cleanNotes,
          notesUpdatedAt:
            typeof params.notesUpdatedAt === 'string' && params.notesUpdatedAt.trim()
              ? params.notesUpdatedAt
              : createdAt,
        }
      : {}),
    ...(params.pinned
      ? {
          pinned: true,
          pinnedAt:
            typeof params.pinnedAt === 'string' && params.pinnedAt.trim()
              ? params.pinnedAt
              : createdAt,
        }
      : {}),
    ...(cleanTitle.length > 0 ? { customTitle: cleanTitle } : {}),
  };
}

export function updateRecentInvestigationNotes(
  current: RecentInvestigationEntry[],
  entryId: string,
  notes: string,
  now: Date = new Date(),
): RecentInvestigationEntry[] {
  const cleanNotes = normalizeInvestigationNotes(notes);
  const updatedAt = now.toISOString();
  let changed = false;

  const next = current.map((entry) => {
    if (entry.id !== entryId) return entry;
    const prevNotes = normalizeInvestigationNotes(entry.notes);
    if (prevNotes === cleanNotes) return entry;
    changed = true;
    const rest: RecentInvestigationEntry = { ...entry };
    if (cleanNotes.length > 0) {
      rest.notes = cleanNotes;
      rest.notesUpdatedAt = updatedAt;
    } else {
      delete rest.notes;
      delete rest.notesUpdatedAt;
    }
    return rest;
  });

  return changed ? next : current;
}

export function sortRecentInvestigations(
  entries: RecentInvestigationEntry[],
): RecentInvestigationEntry[] {
  if (entries.length <= 1) return entries;
  const pinned: RecentInvestigationEntry[] = [];
  const unpinned: RecentInvestigationEntry[] = [];
  for (const item of entries) {
    if (item.pinned) pinned.push(item);
    else unpinned.push(item);
  }
  if (pinned.length === 0) return entries;
  pinned.sort((a, b) => {
    const tsA = Date.parse(a.pinnedAt || a.createdAt) || 0;
    const tsB = Date.parse(b.pinnedAt || b.createdAt) || 0;
    return tsB - tsA;
  });
  return [...pinned, ...unpinned];
}

export function togglePinRecentInvestigation(
  current: RecentInvestigationEntry[],
  entryId: string,
  now: Date = new Date(),
): RecentInvestigationEntry[] {
  let changed = false;
  const pinnedAt = now.toISOString();
  const next = current.map((entry) => {
    if (entry.id !== entryId) return entry;
    changed = true;
    const copy: RecentInvestigationEntry = { ...entry };
    if (copy.pinned) {
      delete copy.pinned;
      delete copy.pinnedAt;
    } else {
      copy.pinned = true;
      copy.pinnedAt = pinnedAt;
    }
    return copy;
  });
  return changed ? sortRecentInvestigations(next) : current;
}

export function renameRecentInvestigation(
  current: RecentInvestigationEntry[],
  entryId: string,
  nextTitle: string,
): RecentInvestigationEntry[] {
  const cleanTitle = normalizeInvestigationTitle(nextTitle);
  let changed = false;
  const next = current.map((entry) => {
    if (entry.id !== entryId) return entry;
    const prevTitle = normalizeInvestigationTitle(entry.customTitle);
    if (prevTitle === cleanTitle) return entry;
    changed = true;
    const copy: RecentInvestigationEntry = { ...entry };
    if (cleanTitle.length > 0) {
      copy.customTitle = cleanTitle;
    } else {
      delete copy.customTitle;
    }
    return copy;
  });
  return changed ? next : current;
}

export function prependRecentInvestigation(
  current: RecentInvestigationEntry[],
  entry: RecentInvestigationEntry,
  maxItems: number = MAX_RECENT_INVESTIGATIONS,
): RecentInvestigationEntry[] {
  const limit = Math.max(1, Math.floor(maxItems));
  const filtered = current.filter((item) => item.id !== entry.id);
  const combined = sortRecentInvestigations([entry, ...filtered]);
  if (combined.length <= limit) return combined;

  // Prefer evicting oldest unpinned items when enforcing history limit
  const pinned = combined.filter((item) => item.pinned);
  const unpinned = combined.filter((item) => !item.pinned);
  const unpinnedBudget = Math.max(0, limit - pinned.length);
  return [...pinned.slice(0, limit), ...unpinned.slice(0, unpinnedBudget)];
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
    const entries = parsed
      .filter(isValidRecentEntry)
      .slice(0, MAX_RECENT_INVESTIGATIONS)
      .map((entry) => {
        const cleanTags = Array.isArray(entry.tags)
          ? Array.from(
              new Set(
                entry.tags
                  .filter((t): t is string => typeof t === 'string')
                  .map((t) => t.trim())
                  .filter(Boolean),
              ),
            )
          : undefined;
        const cleanNotes = normalizeInvestigationNotes(entry.notes);
        const cleanTitle = normalizeInvestigationTitle(entry.customTitle);
        const sanitized: RecentInvestigationEntry = { ...entry };
        if (cleanTags) {
          sanitized.tags = cleanTags;
        }
        if (cleanNotes.length > 0) {
          sanitized.notes = cleanNotes;
          if (typeof entry.notesUpdatedAt === 'string' && entry.notesUpdatedAt.trim()) {
            sanitized.notesUpdatedAt = entry.notesUpdatedAt;
          }
        } else {
          delete sanitized.notes;
          delete sanitized.notesUpdatedAt;
        }
        if (entry.pinned === true) {
          sanitized.pinned = true;
          if (typeof entry.pinnedAt === 'string' && entry.pinnedAt.trim()) {
            sanitized.pinnedAt = entry.pinnedAt;
          }
        } else {
          delete sanitized.pinned;
          delete sanitized.pinnedAt;
        }
        if (cleanTitle.length > 0) {
          sanitized.customTitle = cleanTitle;
        } else {
          delete sanitized.customTitle;
        }
        return sanitized;
      });
    return sortRecentInvestigations(entries);
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
