import type { RecentInvestigationEntry, StorageLike } from './investigationHistory';

export const IOC_TAGS_STORAGE_KEY = 'soti_ioc_tags_v1';

export const SUGGESTED_IOC_TAGS = [
  'Phishing',
  'Malware',
  'Critical',
  'C2',
  'Ransomware',
  'False Positive',
] as const;

export type IndicatorTagMap = Record<string, string[]>;

export function normalizeIndicatorKey(indicator: string): string {
  return (indicator || '').trim().toLowerCase();
}

export function normalizeTagLabel(rawTag: string): string | null {
  const cleaned = String(rawTag ?? '')
    .replace(/[\r\n,]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!cleaned) return null;
  return cleaned.slice(0, 28);
}

export function deduplicateTags(tags: readonly string[]): string[] {
  const seenLower = new Set<string>();
  const result: string[] = [];
  for (const raw of tags) {
    const normalized = normalizeTagLabel(raw);
    if (!normalized) continue;
    const key = normalized.toLowerCase();
    if (seenLower.has(key)) continue;
    seenLower.add(key);
    result.push(normalized);
  }
  return result;
}

export function getTagsForIndicator(tagMap: IndicatorTagMap, indicator: string): string[] {
  const key = normalizeIndicatorKey(indicator);
  if (!key) return [];
  const rawList = tagMap[key];
  return Array.isArray(rawList) ? deduplicateTags(rawList) : [];
}

export function addTagToIndicator(
  tagMap: IndicatorTagMap,
  indicator: string,
  rawTag: string,
): IndicatorTagMap {
  const indKey = normalizeIndicatorKey(indicator);
  const tag = normalizeTagLabel(rawTag);
  if (!indKey || !tag) return tagMap;

  const existing = getTagsForIndicator(tagMap, indKey);
  if (existing.some((t) => t.toLowerCase() === tag.toLowerCase())) {
    return tagMap;
  }

  return {
    ...tagMap,
    [indKey]: [...existing, tag],
  };
}

export function removeTagFromIndicator(
  tagMap: IndicatorTagMap,
  indicator: string,
  tagToRemove: string,
): IndicatorTagMap {
  const indKey = normalizeIndicatorKey(indicator);
  if (!indKey) return tagMap;

  const existing = getTagsForIndicator(tagMap, indKey);
  const removeLower = (tagToRemove || '').trim().toLowerCase();
  const nextTags = existing.filter((t) => t.toLowerCase() !== removeLower);
  if (nextTags.length === existing.length) return tagMap;

  const nextMap = { ...tagMap };
  if (nextTags.length === 0) {
    delete nextMap[indKey];
  } else {
    nextMap[indKey] = nextTags;
  }
  return nextMap;
}

export function collectTagsForIndicators(
  tagMap: IndicatorTagMap,
  indicators: readonly string[],
  explicitTags: readonly string[] = [],
): string[] {
  const collected: string[] = [...explicitTags];
  for (const ind of indicators) {
    for (const tag of getTagsForIndicator(tagMap, ind)) {
      collected.push(tag);
    }
  }
  return deduplicateTags(collected);
}

export function syncRecentInvestigationsTags(
  entries: RecentInvestigationEntry[],
  tagMap: IndicatorTagMap,
): RecentInvestigationEntry[] {
  return entries.map((entry) => {
    const syncedTags = collectTagsForIndicators(tagMap, entry.indicators);
    return {
      ...entry,
      tags: syncedTags,
    };
  });
}

export function getResolvedEntryTags(
  entry: RecentInvestigationEntry,
  tagMap: IndicatorTagMap = {},
): string[] {
  return collectTagsForIndicators(tagMap, entry.indicators, entry.tags || []);
}

export function getAllUniqueTags(
  entries: RecentInvestigationEntry[],
  tagMap: IndicatorTagMap = {},
): string[] {
  const all: string[] = [];
  for (const entry of entries) {
    for (const t of getResolvedEntryTags(entry, tagMap)) {
      all.push(t);
    }
  }
  return deduplicateTags(all).sort((a, b) => a.localeCompare(b));
}

export function filterRecentInvestigationsByTag(
  entries: RecentInvestigationEntry[],
  selectedTag: string,
  tagMap: IndicatorTagMap = {},
): RecentInvestigationEntry[] {
  const normalizedFilter = normalizeTagLabel(selectedTag);
  if (!normalizedFilter || normalizedFilter.toLowerCase() === 'all') {
    return entries;
  }
  const targetLower = normalizedFilter.toLowerCase();
  return entries.filter((entry) =>
    getResolvedEntryTags(entry, tagMap).some((tag) => tag.toLowerCase() === targetLower),
  );
}

export function loadIndicatorTags(storage?: StorageLike | null): IndicatorTagMap {
  if (!storage) return {};
  try {
    const raw = storage.getItem(IOC_TAGS_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};

    const cleanMap: IndicatorTagMap = {};
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      const key = normalizeIndicatorKey(k);
      if (!key || !Array.isArray(v)) continue;
      const tags = deduplicateTags(v.filter((item): item is string => typeof item === 'string'));
      if (tags.length > 0) {
        cleanMap[key] = tags;
      }
    }
    return cleanMap;
  } catch {
    return {};
  }
}

export function saveIndicatorTags(
  storage: StorageLike | null | undefined,
  tagMap: IndicatorTagMap,
): boolean {
  if (!storage) return false;
  try {
    const keys = Object.keys(tagMap);
    if (keys.length === 0 && typeof storage.removeItem === 'function') {
      storage.removeItem(IOC_TAGS_STORAGE_KEY);
      return true;
    }
    storage.setItem(IOC_TAGS_STORAGE_KEY, JSON.stringify(tagMap));
    return true;
  } catch {
    return false;
  }
}
