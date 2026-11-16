import {
  preprocessInputForLookup,
  type IndicatorType,
  type LookupResult,
  type Verdict,
} from './indicators';
import type { StorageLike } from './investigationHistory';
import { computeAllIocConfidenceScores } from './riskScoring';

export const WATCHLIST_STORAGE_KEY = 'soti_ioc_watchlist_v1';
export const SIDEBAR_TAB_STORAGE_KEY = 'soti_sidebar_active_tab_v1';
export const MAX_WATCHLIST_HISTORY = 10;

export type SidebarTabId = 'recent' | 'watchlist';

export interface WatchlistStatusChange {
  id: string;
  detectedAt: string;
  previousVerdict: Verdict | null;
  newVerdict: Verdict;
  previousScore: number | null;
  newScore: number | null;
  summary: string;
}

export interface WatchlistItem {
  indicator: string;
  type: IndicatorType;
  addedAt: string;
  lastCheckedAt: string | null;
  lastVerdict: Verdict | null;
  lastConfidenceScore: number | null;
  unreadUpdateCount: number;
  lastChange: WatchlistStatusChange | null;
  history: WatchlistStatusChange[];
}

function normalizeKey(indicator: string): string {
  return (indicator || '').trim().toLowerCase();
}

function deriveOverallVerdict(items: readonly LookupResult[]): Verdict {
  const okItems = items.filter((r) => r.status === 'ok');
  if (okItems.some((r) => r.verdict === 'Malicious')) return 'Malicious';
  if (okItems.some((r) => r.verdict === 'Suspicious')) return 'Suspicious';
  if (okItems.some((r) => r.verdict === 'Clean')) return 'Clean';
  return 'Unknown';
}

export function isWatchlistIndicator(
  items: readonly WatchlistItem[],
  indicator: string,
): boolean {
  const key = normalizeKey(indicator);
  if (!key) return false;
  return items.some((item) => normalizeKey(item.indicator) === key);
}

export function addIocToWatchlist(
  items: readonly WatchlistItem[],
  params: {
    indicator: string;
    type?: IndicatorType;
    verdict?: Verdict | null;
    confidenceScore?: number | null;
    now?: Date;
  },
): { next: WatchlistItem[]; added: WatchlistItem | null; invalid: string[] } {
  const prep = preprocessInputForLookup(params.indicator);
  const firstValid = prep.validIndicators[0];
  if (!firstValid || !firstValid.type) {
    return {
      next: [...items],
      added: null,
      invalid: prep.invalidTokens,
    };
  }

  const key = normalizeKey(firstValid.cleaned);
  if (items.some((item) => normalizeKey(item.indicator) === key)) {
    return { next: [...items], added: null, invalid: [] };
  }

  const nowIso = (params.now ?? new Date()).toISOString();
  const hasBaseline = params.verdict !== undefined && params.verdict !== null;

  const newItem: WatchlistItem = {
    indicator: firstValid.cleaned,
    type: params.type ?? firstValid.type,
    addedAt: nowIso,
    lastCheckedAt: hasBaseline ? nowIso : null,
    lastVerdict: params.verdict ?? null,
    lastConfidenceScore:
      typeof params.confidenceScore === 'number' && Number.isFinite(params.confidenceScore)
        ? Math.max(0, Math.min(100, Math.round(params.confidenceScore)))
        : null,
    unreadUpdateCount: 0,
    lastChange: null,
    history: [],
  };

  return {
    next: [newItem, ...items],
    added: newItem,
    invalid: [],
  };
}

export function removeIocFromWatchlist(
  items: readonly WatchlistItem[],
  indicator: string,
): WatchlistItem[] {
  const key = normalizeKey(indicator);
  return items.filter((item) => normalizeKey(item.indicator) !== key);
}

export function evaluateWatchlistUpdates(
  items: readonly WatchlistItem[],
  results: readonly LookupResult[],
  checkedAtIso: string = new Date().toISOString(),
): { next: WatchlistItem[]; changedIndicators: string[] } {
  if (items.length === 0 || results.length === 0) {
    return { next: [...items], changedIndicators: [] };
  }

  const groupedByKey = new Map<string, LookupResult[]>();
  for (const r of results) {
    const k = normalizeKey(r.indicator);
    if (!k) continue;
    const list = groupedByKey.get(k) ?? [];
    list.push(r);
    groupedByKey.set(k, list);
  }

  const confByKey = computeAllIocConfidenceScores([...results]);
  const changedIndicators: string[] = [];

  const next = items.map((item) => {
    const key = normalizeKey(item.indicator);
    const matchingResults = groupedByKey.get(key);
    if (!matchingResults || matchingResults.length === 0) {
      return item;
    }

    const nextVerdict = deriveOverallVerdict(matchingResults);
    const nextScore = confByKey.get(key)?.confidenceScore ?? null;

    // First-ever baseline capture: establish baseline without generating false change notification
    if (item.lastCheckedAt === null && item.lastVerdict === null) {
      return {
        ...item,
        lastCheckedAt: checkedAtIso,
        lastVerdict: nextVerdict,
        lastConfidenceScore: nextScore,
      };
    }

    const prevVerdict = item.lastVerdict;
    const prevScore = item.lastConfidenceScore;
    const verdictChanged = prevVerdict !== null && prevVerdict !== nextVerdict;
    const scoreChanged =
      prevScore !== null &&
      nextScore !== null &&
      Math.abs(nextScore - prevScore) >= 5;
    const gainedScore = prevScore === null && nextScore !== null;

    if (!verdictChanged && !scoreChanged && !gainedScore) {
      return {
        ...item,
        lastCheckedAt: checkedAtIso,
      };
    }

    const parts: string[] = [];
    if (verdictChanged) {
      parts.push(`Verdict ${prevVerdict} -> ${nextVerdict}`);
    }
    if (scoreChanged && prevScore !== null && nextScore !== null) {
      const diff = nextScore - prevScore;
      parts.push(`Score ${prevScore} -> ${nextScore} (${diff >= 0 ? `+${diff}` : diff})`);
    } else if (gainedScore && nextScore !== null) {
      parts.push(`Score ${nextScore}/100`);
    }

    const changeRecord: WatchlistStatusChange = {
      id: `wl_${Date.parse(checkedAtIso) || Date.now()}_${Math.random().toString(16).slice(2, 6)}`,
      detectedAt: checkedAtIso,
      previousVerdict: prevVerdict,
      newVerdict: nextVerdict,
      previousScore: prevScore,
      newScore: nextScore,
      summary: parts.join(' · ') || `Updated (${nextVerdict})`,
    };

    changedIndicators.push(item.indicator);
    return {
      ...item,
      lastCheckedAt: checkedAtIso,
      lastVerdict: nextVerdict,
      lastConfidenceScore: nextScore,
      unreadUpdateCount: item.unreadUpdateCount + 1,
      lastChange: changeRecord,
      history: [changeRecord, ...item.history].slice(0, MAX_WATCHLIST_HISTORY),
    };
  });

  return { next, changedIndicators };
}

export function markWatchlistItemSeen(
  items: readonly WatchlistItem[],
  indicator: string,
): WatchlistItem[] {
  const key = normalizeKey(indicator);
  return items.map((item) =>
    normalizeKey(item.indicator) === key
      ? { ...item, unreadUpdateCount: 0 }
      : item,
  );
}

export function markAllWatchlistUpdatesSeen(
  items: readonly WatchlistItem[],
): WatchlistItem[] {
  return items.map((item) =>
    item.unreadUpdateCount > 0 ? { ...item, unreadUpdateCount: 0 } : item,
  );
}

export function countUnreadWatchlistUpdates(items: readonly WatchlistItem[]): number {
  return items.reduce((sum, item) => sum + Math.max(0, item.unreadUpdateCount || 0), 0);
}

export function loadWatchlist(storage?: StorageLike | null): WatchlistItem[] {
  if (!storage) return [];
  try {
    const raw = storage.getItem(WATCHLIST_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    const clean: WatchlistItem[] = [];
    for (const entry of parsed) {
      if (!entry || typeof entry !== 'object') continue;
      const obj = entry as Partial<WatchlistItem>;
      if (typeof obj.indicator !== 'string' || !obj.indicator.trim()) continue;
      clean.push({
        indicator: obj.indicator.trim(),
        type:
          obj.type === 'ip' || obj.type === 'domain' || obj.type === 'hash'
            ? obj.type
            : 'ip',
        addedAt: typeof obj.addedAt === 'string' ? obj.addedAt : new Date().toISOString(),
        lastCheckedAt: typeof obj.lastCheckedAt === 'string' ? obj.lastCheckedAt : null,
        lastVerdict:
          obj.lastVerdict === 'Malicious' ||
          obj.lastVerdict === 'Suspicious' ||
          obj.lastVerdict === 'Clean' ||
          obj.lastVerdict === 'Unknown'
            ? obj.lastVerdict
            : null,
        lastConfidenceScore:
          typeof obj.lastConfidenceScore === 'number' && Number.isFinite(obj.lastConfidenceScore)
            ? obj.lastConfidenceScore
            : null,
        unreadUpdateCount:
          typeof obj.unreadUpdateCount === 'number' && obj.unreadUpdateCount >= 0
            ? Math.floor(obj.unreadUpdateCount)
            : 0,
        lastChange: obj.lastChange && typeof obj.lastChange === 'object' ? obj.lastChange : null,
        history: Array.isArray(obj.history) ? obj.history.slice(0, MAX_WATCHLIST_HISTORY) : [],
      });
    }
    return clean;
  } catch {
    return [];
  }
}

export function saveWatchlist(
  storage: StorageLike | null | undefined,
  items: readonly WatchlistItem[],
): boolean {
  if (!storage) return false;
  try {
    storage.setItem(WATCHLIST_STORAGE_KEY, JSON.stringify(items));
    return true;
  } catch {
    return false;
  }
}

export function loadSidebarTab(storage?: StorageLike | null): SidebarTabId {
  if (!storage) return 'recent';
  const raw = storage.getItem(SIDEBAR_TAB_STORAGE_KEY);
  return raw === 'watchlist' ? 'watchlist' : 'recent';
}

export function saveSidebarTab(
  storage: StorageLike | null | undefined,
  tab: SidebarTabId,
): void {
  if (!storage) return;
  try {
    storage.setItem(SIDEBAR_TAB_STORAGE_KEY, tab);
  } catch {
    // ignore
  }
}
