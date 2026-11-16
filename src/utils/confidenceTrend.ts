import type { LookupResult } from './indicators';
import type { RecentInvestigationEntry, StorageLike } from './investigationHistory';
import { computeIndicatorConfidenceMap } from './reportsAnalytics';
import { computeAllIocConfidenceScores } from './riskScoring';

export const CONFIDENCE_SNAPSHOTS_STORAGE_KEY = 'soti_confidence_snapshots_v1';
export const MAX_SNAPSHOTS_PER_INDICATOR = 20;

export type ConfidencePointSource = 'report' | 'history' | 'live-poll' | 'current';

export interface ConfidenceTrendPoint {
  timestamp: string;
  label: string;
  score: number;
  runSource: ConfidencePointSource;
}

export type ConfidenceTrendDirection = 'rising' | 'falling' | 'steady' | 'single';

export interface IndicatorConfidenceTrend {
  indicator: string;
  points: ConfidenceTrendPoint[];
  latestScore: number | null;
  previousScore: number | null;
  netDelta: number | null;
  recentDelta: number | null;
  direction: ConfidenceTrendDirection;
  emergingThreat: boolean;
}

export type ConfidenceSnapshotMap = Record<string, ConfidenceTrendPoint[]>;

function normalizeKey(indicator: string): string {
  return (indicator || '').trim().toLowerCase();
}

export function normalizeTimestampToIso(raw: string | undefined | null): string | null {
  const trimmed = (raw || '').trim();
  if (!trimmed) return null;

  // Handle "YYYY-MM-DD HH:MM:SS" from CSV reports
  const spaceDateMatch = trimmed.match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z)?$/i);
  const candidate = spaceDateMatch ? `${spaceDateMatch[1]}T${spaceDateMatch[2]}Z` : trimmed;
  const ms = Date.parse(candidate);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString();
}

export function parseTimestampFromReportFilename(reportName: string | undefined | null): string | null {
  const match = (reportName || '').trim().match(/soti_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})\.csv$/i);
  if (!match) return null;
  const [, yyyy, mm, dd, hh, min, sec] = match;
  const iso = `${yyyy}-${mm}-${dd}T${hh}:${min}:${sec}Z`;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

export function formatTrendPointLabel(iso: string): string {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return iso;
  const d = new Date(ms);
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const min = String(d.getUTCMinutes()).padStart(2, '0');
  return `${mm}-${dd} ${hh}:${min} UTC`;
}

export function loadConfidenceSnapshots(storage?: StorageLike | null): ConfidenceSnapshotMap {
  if (!storage) return {};
  try {
    const raw = storage.getItem(CONFIDENCE_SNAPSHOTS_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};

    const clean: ConfidenceSnapshotMap = {};
    for (const [k, list] of Object.entries(parsed as Record<string, unknown>)) {
      const key = normalizeKey(k);
      if (!key || !Array.isArray(list)) continue;
      const validPoints: ConfidenceTrendPoint[] = [];
      for (const item of list) {
        if (!item || typeof item !== 'object') continue;
        const obj = item as Partial<ConfidenceTrendPoint>;
        const iso = normalizeTimestampToIso(obj.timestamp);
        if (!iso || typeof obj.score !== 'number' || !Number.isFinite(obj.score)) continue;
        validPoints.push({
          timestamp: iso,
          label: typeof obj.label === 'string' && obj.label ? obj.label : formatTrendPointLabel(iso),
          score: Math.max(0, Math.min(100, Math.round(obj.score))),
          runSource:
            obj.runSource === 'report' ||
            obj.runSource === 'history' ||
            obj.runSource === 'live-poll' ||
            obj.runSource === 'current'
              ? obj.runSource
              : 'history',
        });
      }
      if (validPoints.length > 0) {
        clean[key] = validPoints.slice(-MAX_SNAPSHOTS_PER_INDICATOR);
      }
    }
    return clean;
  } catch {
    return {};
  }
}

export function saveConfidenceSnapshots(
  storage: StorageLike | null | undefined,
  snapshots: ConfidenceSnapshotMap,
): boolean {
  if (!storage) return false;
  try {
    const keys = Object.keys(snapshots);
    if (keys.length === 0 && typeof storage.removeItem === 'function') {
      storage.removeItem(CONFIDENCE_SNAPSHOTS_STORAGE_KEY);
      return true;
    }
    storage.setItem(CONFIDENCE_SNAPSHOTS_STORAGE_KEY, JSON.stringify(snapshots));
    return true;
  } catch {
    return false;
  }
}

export function appendConfidenceSnapshot(
  prevSnapshots: ConfidenceSnapshotMap,
  results: readonly LookupResult[],
  timestampIso: string = new Date().toISOString(),
  runSource: ConfidencePointSource = 'history',
): ConfidenceSnapshotMap {
  if (!results.length) return prevSnapshots;
  const iso = normalizeTimestampToIso(timestampIso) ?? new Date().toISOString();
  const scoresByIndicator = computeAllIocConfidenceScores([...results]);
  const next: ConfidenceSnapshotMap = { ...prevSnapshots };
  let mutated = false;

  for (const [key, summary] of scoresByIndicator.entries()) {
    if (summary.confidenceScore === null) continue;
    const existing = next[key] ? [...next[key]] : [];
    const last = existing[existing.length - 1];
    // Avoid recording identical back-to-back snapshot within 1 second if score matches
    if (
      last &&
      Math.abs(Date.parse(iso) - Date.parse(last.timestamp)) < 1000 &&
      last.score === summary.confidenceScore
    ) {
      continue;
    }
    existing.push({
      timestamp: iso,
      label: formatTrendPointLabel(iso),
      score: summary.confidenceScore,
      runSource,
    });
    next[key] = existing.slice(-MAX_SNAPSHOTS_PER_INDICATOR);
    mutated = true;
  }

  return mutated ? next : prevSnapshots;
}

function mergeChronologicalPoints(rawPoints: ConfidenceTrendPoint[]): ConfidenceTrendPoint[] {
  const sorted = [...rawPoints].sort(
    (a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp),
  );
  const deduped: ConfidenceTrendPoint[] = [];

  for (const pt of sorted) {
    const ptMs = Date.parse(pt.timestamp);
    if (!Number.isFinite(ptMs)) continue;
    const prev = deduped[deduped.length - 1];
    if (prev) {
      const prevMs = Date.parse(prev.timestamp);
      // Merge redundant points within 2 seconds that reflect the exact same run/score
      if (Math.abs(ptMs - prevMs) <= 2000 && prev.score === pt.score) {
        continue;
      }
      // If same exact timestamp down to the second with updated score, prefer latest source
      if (Math.abs(ptMs - prevMs) <= 1000) {
        deduped[deduped.length - 1] = pt;
        continue;
      }
    }
    deduped.push(pt);
  }

  return deduped.slice(-MAX_SNAPSHOTS_PER_INDICATOR);
}

export function classifyTrendDirection(points: readonly ConfidenceTrendPoint[]): {
  latestScore: number | null;
  previousScore: number | null;
  netDelta: number | null;
  recentDelta: number | null;
  direction: ConfidenceTrendDirection;
  emergingThreat: boolean;
} {
  if (points.length === 0) {
    return {
      latestScore: null,
      previousScore: null,
      netDelta: null,
      recentDelta: null,
      direction: 'single',
      emergingThreat: false,
    };
  }
  const latest = points[points.length - 1].score;
  if (points.length === 1) {
    return {
      latestScore: latest,
      previousScore: null,
      netDelta: 0,
      recentDelta: 0,
      direction: 'single',
      emergingThreat: false,
    };
  }

  const previous = points[points.length - 2].score;
  const earliest = points[0].score;
  const recentDelta = latest - previous;
  const netDelta = latest - earliest;

  let direction: ConfidenceTrendDirection = 'steady';
  if (recentDelta >= 5 || (recentDelta >= 0 && netDelta >= 5)) {
    direction = 'rising';
  } else if (recentDelta <= -5 || (recentDelta <= 0 && netDelta <= -5)) {
    direction = 'falling';
  }

  const emergingThreat = direction === 'rising' && (latest >= 50 || netDelta >= 15);
  return {
    latestScore: latest,
    previousScore: previous,
    netDelta,
    recentDelta,
    direction,
    emergingThreat,
  };
}

export function buildConfidenceTrendsMap(params: {
  reportRows?: readonly Record<string, string>[];
  recentHistory?: readonly RecentInvestigationEntry[];
  liveSnapshots?: ConfidenceSnapshotMap;
  currentResults?: readonly LookupResult[];
  currentTimestamp?: string;
}): Map<string, IndicatorConfidenceTrend> {
  const byIndicator = new Map<string, ConfidenceTrendPoint[]>();
  const displayNameByKey = new Map<string, string>();

  const pushPoint = (indRaw: string, pt: ConfidenceTrendPoint) => {
    const key = normalizeKey(indRaw);
    if (!key) return;
    if (!displayNameByKey.has(key)) {
      displayNameByKey.set(key, indRaw.trim());
    }
    const list = byIndicator.get(key) ?? [];
    list.push(pt);
    byIndicator.set(key, list);
  };

  // 1. Historical CSV reports (/api/reports/all-rows)
  if (params.reportRows && params.reportRows.length > 0) {
    const runBuckets = new Map<
      string,
      { timestamp: string; rows: Record<string, string>[] }
    >();
    for (const row of params.reportRows) {
      const indKey = normalizeKey(row.indicator || '');
      if (!indKey) continue;
      const resolvedIso =
        normalizeTimestampToIso(row.timestamp) ??
        parseTimestampFromReportFilename(row.reportName) ??
        null;
      if (!resolvedIso) continue;
      const bucketId = `${row.reportName || resolvedIso.slice(0, 19)}`;
      const bucket = runBuckets.get(bucketId) ?? { timestamp: resolvedIso, rows: [] };
      bucket.rows.push(row);
      runBuckets.set(bucketId, bucket);
    }

    for (const bucket of runBuckets.values()) {
      const confMap = computeIndicatorConfidenceMap(bucket.rows);
      for (const [indKey, conf] of confMap.entries()) {
        if (conf.score === null) continue;
        pushPoint(indKey, {
          timestamp: bucket.timestamp,
          label: formatTrendPointLabel(bucket.timestamp),
          score: conf.score,
          runSource: 'report',
        });
      }
    }
  }

  // 2. Local Recent Investigations history
  if (params.recentHistory && params.recentHistory.length > 0) {
    for (const entry of params.recentHistory) {
      const iso = normalizeTimestampToIso(entry.createdAt);
      if (!iso || !entry.results?.length) continue;
      const confMap = computeAllIocConfidenceScores(entry.results);
      for (const summary of confMap.values()) {
        if (summary.confidenceScore === null) continue;
        pushPoint(summary.indicator, {
          timestamp: iso,
          label: formatTrendPointLabel(iso),
          score: summary.confidenceScore,
          runSource: 'history',
        });
      }
    }
  }

  // 3. Persistent Live Mode / session poll snapshots
  if (params.liveSnapshots) {
    for (const [key, list] of Object.entries(params.liveSnapshots)) {
      if (!Array.isArray(list)) continue;
      for (const pt of list) {
        const iso = normalizeTimestampToIso(pt.timestamp);
        if (!iso || typeof pt.score !== 'number') continue;
        pushPoint(key, {
          timestamp: iso,
          label: pt.label || formatTrendPointLabel(iso),
          score: Math.max(0, Math.min(100, Math.round(pt.score))),
          runSource: pt.runSource ?? 'live-poll',
        });
      }
    }
  }

  // 4. Current active results table
  if (params.currentResults && params.currentResults.length > 0) {
    const nowIso = normalizeTimestampToIso(params.currentTimestamp) ?? new Date().toISOString();
    const confMap = computeAllIocConfidenceScores([...params.currentResults]);
    for (const summary of confMap.values()) {
      if (summary.confidenceScore === null) continue;
      pushPoint(summary.indicator, {
        timestamp: nowIso,
        label: formatTrendPointLabel(nowIso),
        score: summary.confidenceScore,
        runSource: 'current',
      });
    }
  }

  const trends = new Map<string, IndicatorConfidenceTrend>();
  for (const [key, rawList] of byIndicator.entries()) {
    const points = mergeChronologicalPoints(rawList);
    const stats = classifyTrendDirection(points);
    trends.set(key, {
      indicator: displayNameByKey.get(key) || key,
      points,
      ...stats,
    });
  }

  return trends;
}
