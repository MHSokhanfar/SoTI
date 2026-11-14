import { cleanIndicator, detectIndicatorType, type IndicatorType } from './indicators';

export interface VerdictCounts {
  malicious: number;
  clean: number;
  suspicious: number;
  unknown: number;
  other: number;
}

export interface ReportMeta {
  name: string;
  sizeBytes: number;
  modifiedAt: string;
  rowCount: number;
  verdicts: VerdictCounts;
  indicators?: string[];
}

export type VerdictFilterOption = 'All' | 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown';

export interface HistoricalRunPoint {
  name: string;
  label: string;
  malicious: number;
  clean: number;
  suspicious: number;
  unknown: number;
  other: number;
  total: number;
}

export interface HistoricalTotals {
  runs: number;
  malicious: number;
  clean: number;
  suspicious: number;
  unknown: number;
  totalChecks: number;
}

export function summarizeReportVerdicts(rows: Record<string, string>[]): VerdictCounts {
  const counts: VerdictCounts = {
    malicious: 0,
    clean: 0,
    suspicious: 0,
    unknown: 0,
    other: 0,
  };

  for (const row of rows) {
    const status = (row.status || '').trim().toLowerCase();
    const verdict = (row.verdict || '').trim().toLowerCase();
    if (status && status !== 'ok') {
      counts.other += 1;
      continue;
    }
    if (verdict === 'malicious') counts.malicious += 1;
    else if (verdict === 'clean') counts.clean += 1;
    else if (verdict === 'suspicious') counts.suspicious += 1;
    else counts.unknown += 1;
  }

  return counts;
}

export function formatRunLabel(filename: string, modifiedAt: string): string {
  const match = filename.match(/(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/);
  if (match) {
    const [, , month, day, hour, minute, second] = match;
    return `${month}/${day} ${hour}:${minute}:${second}`;
  }
  const d = new Date(modifiedAt);
  if (!Number.isNaN(d.getTime())) {
    return d.toISOString().slice(5, 19).replace('T', ' ');
  }
  return filename.replace(/\.csv$/i, '');
}

export function buildHistoricalChartData(reports: ReportMeta[]): {
  series: HistoricalRunPoint[];
  totals: HistoricalTotals;
} {
  // Reports come newest-first from the API; reverse so charts read left-to-right chronologically
  const chronological = [...reports].reverse();

  const totals: HistoricalTotals = {
    runs: reports.length,
    malicious: 0,
    clean: 0,
    suspicious: 0,
    unknown: 0,
    totalChecks: 0,
  };

  const series: HistoricalRunPoint[] = chronological.map((rep) => {
    const v = rep.verdicts || { malicious: 0, clean: 0, suspicious: 0, unknown: 0, other: 0 };
    totals.malicious += v.malicious;
    totals.clean += v.clean;
    totals.suspicious += v.suspicious;
    totals.unknown += v.unknown;
    totals.totalChecks += rep.rowCount;

    return {
      name: rep.name,
      label: formatRunLabel(rep.name, rep.modifiedAt),
      malicious: v.malicious,
      clean: v.clean,
      suspicious: v.suspicious,
      unknown: v.unknown,
      other: v.other,
      total: rep.rowCount,
    };
  });

  return { series, totals };
}

export interface ThreatAlertTrendPoint {
  dateKey: string;
  label: string;
  displayDate: string;
  malicious: number;
  suspicious: number;
  threatAlerts: number;
  runs: number;
  totalLookups: number;
  latestReportName: string | null;
}

export interface ThreatAlertTrendSummary {
  totalAlerts: number;
  maliciousAlerts: number;
  suspiciousAlerts: number;
  activeAlertDays: number;
  peakAlerts: number;
  peakDateLabel: string;
}

const SHORT_MONTHS = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'May',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec',
];

export function getReportDateKey(filename: string, modifiedAt: string): string | null {
  const match = filename.match(/(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/);
  if (match) {
    const [, year, month, day] = match;
    return `${year}-${month}-${day}`;
  }
  const d = new Date(modifiedAt);
  if (!Number.isNaN(d.getTime())) {
    return d.toISOString().slice(0, 10);
  }
  return null;
}

export function buildThreatAlertTrend30Days(
  reports: ReportMeta[],
  referenceDate: Date = new Date(),
): {
  series: ThreatAlertTrendPoint[];
  summary: ThreatAlertTrendSummary;
} {
  const endUtcMidnight = Date.UTC(
    referenceDate.getUTCFullYear(),
    referenceDate.getUTCMonth(),
    referenceDate.getUTCDate(),
  );
  const DAY_MS = 24 * 60 * 60 * 1000;

  const bucketMap = new Map<string, ThreatAlertTrendPoint>();
  const series: ThreatAlertTrendPoint[] = [];

  for (let offset = 29; offset >= 0; offset -= 1) {
    const dayDate = new Date(endUtcMidnight - offset * DAY_MS);
    const yyyy = dayDate.getUTCFullYear();
    const mm = String(dayDate.getUTCMonth() + 1).padStart(2, '0');
    const dd = String(dayDate.getUTCDate()).padStart(2, '0');
    const dateKey = `${yyyy}-${mm}-${dd}`;
    const point: ThreatAlertTrendPoint = {
      dateKey,
      label: `${mm}/${dd}`,
      displayDate: `${SHORT_MONTHS[dayDate.getUTCMonth()]} ${dayDate.getUTCDate()}, ${yyyy}`,
      malicious: 0,
      suspicious: 0,
      threatAlerts: 0,
      runs: 0,
      totalLookups: 0,
      latestReportName: null,
    };
    bucketMap.set(dateKey, point);
    series.push(point);
  }

  for (const rep of reports) {
    const key = getReportDateKey(rep.name, rep.modifiedAt);
    if (!key) continue;
    const bucket = bucketMap.get(key);
    if (!bucket) continue;

    const v = rep.verdicts || { malicious: 0, clean: 0, suspicious: 0, unknown: 0, other: 0 };
    bucket.malicious += v.malicious;
    bucket.suspicious += v.suspicious;
    bucket.threatAlerts += v.malicious + v.suspicious;
    bucket.runs += 1;
    bucket.totalLookups += rep.rowCount;
    if (!bucket.latestReportName || rep.name > bucket.latestReportName) {
      bucket.latestReportName = rep.name;
    }
  }

  let totalAlerts = 0;
  let maliciousAlerts = 0;
  let suspiciousAlerts = 0;
  let activeAlertDays = 0;
  let peakAlerts = 0;
  let peakDateLabel = '—';

  for (const point of series) {
    totalAlerts += point.threatAlerts;
    maliciousAlerts += point.malicious;
    suspiciousAlerts += point.suspicious;
    if (point.threatAlerts > 0) {
      activeAlertDays += 1;
    }
    if (point.threatAlerts >= peakAlerts && point.threatAlerts > 0) {
      peakAlerts = point.threatAlerts;
      peakDateLabel = point.label;
    }
  }

  return {
    series,
    summary: {
      totalAlerts,
      maliciousAlerts,
      suspiciousAlerts,
      activeAlertDays,
      peakAlerts,
      peakDateLabel,
    },
  };
}

function escapeCsvField(value: string): string {
  if (/[",\n\r]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export function serializeHistoricalSummaryCsv(reports: ReportMeta[]): string {
  const headers = [
    'report_file',
    'run_label',
    'modified_at',
    'total_rows',
    'malicious',
    'clean',
    'suspicious',
    'unknown',
    'other',
  ];
  const lines = [headers.join(',')];
  for (const rep of [...reports].reverse()) {
    const v = rep.verdicts || { malicious: 0, clean: 0, suspicious: 0, unknown: 0, other: 0 };
    lines.push(
      [
        rep.name,
        formatRunLabel(rep.name, rep.modifiedAt),
        rep.modifiedAt,
        String(rep.rowCount),
        String(v.malicious),
        String(v.clean),
        String(v.suspicious),
        String(v.unknown),
        String(v.other),
      ]
        .map(escapeCsvField)
        .join(','),
    );
  }
  return '\ufeff' + lines.join('\r\n') + '\r\n';
}

export function mergeHistoricalCsvRows(
  reportEntries: { name: string; rows: Record<string, string>[] }[],
): string {
  const headers = [
    'report_file',
    'timestamp',
    'source',
    'indicator',
    'type',
    'status',
    'verdict',
    'score',
    'summary',
    'details',
    'link',
  ];
  const lines = [headers.join(',')];
  for (const entry of reportEntries) {
    for (const row of entry.rows) {
      const cells = [
        entry.name,
        row.timestamp ?? '',
        row.source ?? '',
        row.indicator ?? '',
        row.type ?? '',
        row.status ?? '',
        row.verdict ?? '',
        row.score ?? '',
        row.summary ?? '',
        row.details ?? '',
        row.link ?? '',
      ].map((c) => escapeCsvField(String(c)));
      lines.push(cells.join(','));
    }
  }
  return '\ufeff' + lines.join('\r\n') + '\r\n';
}

function normalizeQueryTokens(searchQuery: string): { raw: string; refanged: string } {
  const raw = searchQuery.trim().toLowerCase();
  const refanged = raw ? cleanIndicator(raw).toLowerCase() : '';
  return { raw, refanged };
}

export function filterReportList(
  reports: ReportMeta[],
  searchQuery: string,
  verdictFilter: VerdictFilterOption,
): ReportMeta[] {
  const { raw, refanged } = normalizeQueryTokens(searchQuery);

  return reports.filter((rep) => {
    if (verdictFilter !== 'All') {
      const v = rep.verdicts || { malicious: 0, clean: 0, suspicious: 0, unknown: 0, other: 0 };
      const key = verdictFilter.toLowerCase() as keyof Pick<
        VerdictCounts,
        'malicious' | 'clean' | 'suspicious' | 'unknown'
      >;
      if ((v[key] || 0) === 0) {
        return false;
      }
    }

    if (raw) {
      const nameMatch = rep.name.toLowerCase().includes(raw);
      const indicatorMatch = (rep.indicators || []).some((ind) => {
        const lower = ind.toLowerCase();
        return lower.includes(raw) || (refanged.length > 0 && lower.includes(refanged));
      });
      if (!nameMatch && !indicatorMatch) {
        return false;
      }
    }

    return true;
  });
}

export function filterReportRows(
  rows: Record<string, string>[],
  searchQuery: string,
  verdictFilter: VerdictFilterOption,
): Record<string, string>[] {
  const { raw, refanged } = normalizeQueryTokens(searchQuery);

  return rows.filter((row) => {
    if (verdictFilter !== 'All') {
      const status = (row.status || '').trim().toLowerCase();
      const verdict = (row.verdict || '').trim().toLowerCase();
      if (status !== 'ok' || verdict !== verdictFilter.toLowerCase()) {
        return false;
      }
    }

    if (raw) {
      const haystack = [
        row.indicator || '',
        row.type || '',
        row.source || '',
        row.summary || '',
      ]
        .join(' ')
        .toLowerCase();
      if (!haystack.includes(raw) && !(refanged.length > 0 && haystack.includes(refanged))) {
        return false;
      }
    }

    return true;
  });
}

export interface SourceConfidenceContribution {
  source: string;
  normalizedScore: number;
  weight: number;
}

export interface IndicatorConfidence {
  score: number | null;
  sourceCount: number;
  contributions: SourceConfidenceContribution[];
  tooltip: string;
}

const SOURCE_WEIGHTS = {
  virustotal: 0.5,
  abuseipdb: 0.3,
  alienvault: 0.2,
  other: 0.2,
} as const;

type CanonicalSource = keyof typeof SOURCE_WEIGHTS;

export function getCanonicalSource(sourceName: string): CanonicalSource {
  const lower = (sourceName || '').trim().toLowerCase();
  if (lower.includes('virustotal')) return 'virustotal';
  if (lower.includes('abuseipdb')) return 'abuseipdb';
  if (lower.includes('alienvault') || lower.includes('otx')) return 'alienvault';
  return 'other';
}

export function normalizeSourceThreatScore(row: Record<string, string>): number | null {
  const status = (row.status || '').trim().toLowerCase();
  if (status && status !== 'ok') {
    return null;
  }

  const canonical = getCanonicalSource(row.source || '');
  const scoreStr = (row.score || '').trim();
  const verdict = (row.verdict || '').trim().toLowerCase();

  if (canonical === 'virustotal') {
    const ratioMatch = scoreStr.match(/^(\d+)\s*\/\s*(\d+)$/);
    if (ratioMatch) {
      const malicious = Number.parseInt(ratioMatch[1], 10);
      const total = Number.parseInt(ratioMatch[2], 10);
      if (total > 0) {
        if (malicious === 0) {
          return verdict === 'suspicious' ? 25 : 0;
        }
        const ratioPct = (malicious / total) * 100;
        const calibrated =
          malicious >= 5
            ? 65 + Math.min(35, (malicious - 5) * 1.2)
            : 25 + malicious * 8;
        return Math.min(100, Math.round(Math.max(ratioPct, calibrated)));
      }
    }
  }

  if (canonical === 'abuseipdb') {
    const pctMatch = scoreStr.match(/^(\d+(?:\.\d+)?)\s*%$/);
    if (pctMatch) {
      return Math.max(0, Math.min(100, Math.round(Number.parseFloat(pctMatch[1]))));
    }
  }

  if (canonical === 'alienvault') {
    const pulseMatch = scoreStr.match(/^(\d+)\s*pulses?$/i);
    if (pulseMatch) {
      const pulses = Number.parseInt(pulseMatch[1], 10);
      if (pulses === 0) return 0;
      if (pulses < 5) return 20 + pulses * 10;
      return Math.min(100, Math.round(65 + Math.min(35, (pulses - 5) * 1.5)));
    }
  }

  const genericPct = scoreStr.match(/^(\d+(?:\.\d+)?)\s*%$/);
  if (genericPct) {
    return Math.max(0, Math.min(100, Math.round(Number.parseFloat(genericPct[1]))));
  }
  const genericRatio = scoreStr.match(/^(\d+)\s*\/\s*(\d+)$/);
  if (genericRatio) {
    const num = Number.parseInt(genericRatio[1], 10);
    const den = Number.parseInt(genericRatio[2], 10);
    if (den > 0) {
      return Math.max(0, Math.min(100, Math.round((num / den) * 100)));
    }
  }

  if (verdict === 'malicious') return 85;
  if (verdict === 'suspicious') return 50;
  if (verdict === 'clean') return 0;
  return null;
}

export function computeIndicatorConfidenceMap(
  rows: Record<string, string>[],
): Map<string, IndicatorConfidence> {
  const grouped = new Map<string, Map<CanonicalSource, SourceConfidenceContribution>>();

  for (const row of rows) {
    const indicatorKey = (row.indicator || '').trim().toLowerCase();
    if (!indicatorKey) continue;

    if (!grouped.has(indicatorKey)) {
      grouped.set(indicatorKey, new Map());
    }

    const normalizedScore = normalizeSourceThreatScore(row);
    if (normalizedScore === null) continue;

    const canonical = getCanonicalSource(row.source || '');
    const weight = SOURCE_WEIGHTS[canonical];
    const sourceLabel = (row.source || canonical).trim();

    grouped.get(indicatorKey)!.set(canonical, {
      source: sourceLabel,
      normalizedScore,
      weight,
    });
  }

  const result = new Map<string, IndicatorConfidence>();
  for (const [indicatorKey, sourceMap] of grouped.entries()) {
    const contributions = Array.from(sourceMap.values());
    if (contributions.length === 0) {
      result.set(indicatorKey, {
        score: null,
        sourceCount: 0,
        contributions: [],
        tooltip: 'No active source scores available for weighted calculation',
      });
      continue;
    }

    let weightedSum = 0;
    let totalWeight = 0;
    for (const item of contributions) {
      weightedSum += item.normalizedScore * item.weight;
      totalWeight += item.weight;
    }

    const score = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : null;
    const breakdown = contributions
      .map((c) => {
        const effectiveShare = Math.round((c.weight / totalWeight) * 100);
        return `${c.source}: ${c.normalizedScore}% (${effectiveShare}% wt)`;
      })
      .join(', ');

    result.set(indicatorKey, {
      score,
      sourceCount: contributions.length,
      contributions,
      tooltip: `Weighted avg across ${contributions.length} source${contributions.length === 1 ? '' : 's'} — ${breakdown}`,
    });
  }

  return result;
}

export interface ReportsQuickStats {
  totalThreatsAnalyzed: number;
  uniqueIndicatorsCount: number;
  totalRuns: number;
  maliciousCount: number;
  evaluatedVerdictsCount: number;
  maliciousPercentage: number;
  topIndicatorType: IndicatorType | null;
  topIndicatorLabel: string;
  topIndicatorShare: number;
  typeCounts: Record<IndicatorType, number>;
}

const INDICATOR_TYPE_LABELS: Record<IndicatorType, string> = {
  ip: 'IP Address',
  domain: 'Domain',
  hash: 'File Hash',
};

export function computeReportsQuickStats(reports: ReportMeta[]): ReportsQuickStats {
  let totalThreatsAnalyzed = 0;
  let maliciousCount = 0;
  let evaluatedVerdictsCount = 0;
  const uniqueIndicators = new Set<string>();
  const typeCounts: Record<IndicatorType, number> = { ip: 0, domain: 0, hash: 0 };

  for (const rep of reports) {
    totalThreatsAnalyzed += rep.rowCount || 0;
    const v = rep.verdicts || { malicious: 0, clean: 0, suspicious: 0, unknown: 0, other: 0 };
    maliciousCount += v.malicious || 0;
    evaluatedVerdictsCount +=
      (v.malicious || 0) + (v.clean || 0) + (v.suspicious || 0) + (v.unknown || 0);

    for (const rawInd of rep.indicators || []) {
      const cleaned = cleanIndicator(rawInd);
      if (!cleaned) continue;
      uniqueIndicators.add(cleaned.toLowerCase());
      const itype = detectIndicatorType(cleaned);
      if (itype) {
        typeCounts[itype] += 1;
      }
    }
  }

  const maliciousPercentage =
    evaluatedVerdictsCount > 0
      ? Math.round((maliciousCount / evaluatedVerdictsCount) * 1000) / 10
      : 0;

  const totalTyped = typeCounts.ip + typeCounts.domain + typeCounts.hash;
  let topIndicatorType: IndicatorType | null = null;
  let topCount = 0;
  for (const candidate of ['ip', 'domain', 'hash'] as IndicatorType[]) {
    if (typeCounts[candidate] > topCount) {
      topCount = typeCounts[candidate];
      topIndicatorType = candidate;
    }
  }

  const topIndicatorShare =
    totalTyped > 0 && topCount > 0 ? Math.round((topCount / totalTyped) * 1000) / 10 : 0;

  return {
    totalThreatsAnalyzed,
    uniqueIndicatorsCount: uniqueIndicators.size,
    totalRuns: reports.length,
    maliciousCount,
    evaluatedVerdictsCount,
    maliciousPercentage,
    topIndicatorType,
    topIndicatorLabel: topIndicatorType ? INDICATOR_TYPE_LABELS[topIndicatorType] : '—',
    topIndicatorShare,
    typeCounts,
  };
}

export function sanitizeSelectedReportNames(
  names: string[],
  availableCsvNames?: string[],
): string[] {
  const allowedSet = availableCsvNames ? new Set(availableCsvNames) : null;
  const seen = new Set<string>();
  const result: string[] = [];

  for (const raw of names) {
    const trimmed = String(raw || '').trim();
    if (!trimmed) continue;
    // Reject path separators and traversal segments
    if (trimmed.includes('/') || trimmed.includes('\\') || trimmed.includes('..')) {
      continue;
    }
    if (!trimmed.toLowerCase().endsWith('.csv')) continue;
    if (allowedSet && !allowedSet.has(trimmed)) continue;
    if (!seen.has(trimmed)) {
      seen.add(trimmed);
      result.push(trimmed);
    }
  }

  return result;
}

export function toggleReportSelection(current: string[], reportName: string): string[] {
  if (!reportName) return current;
  if (current.includes(reportName)) {
    return current.filter((item) => item !== reportName);
  }
  return [...current, reportName];
}

export function areAllVisibleReportsSelected(
  selected: string[],
  visibleReports: ReportMeta[],
): boolean {
  if (visibleReports.length === 0) return false;
  const selectedSet = new Set(selected);
  return visibleReports.every((rep) => selectedSet.has(rep.name));
}

export function toggleSelectAllReports(
  current: string[],
  visibleReports: ReportMeta[],
): string[] {
  if (visibleReports.length === 0) return current;
  const visibleNames = visibleReports.map((r) => r.name);
  const visibleSet = new Set(visibleNames);

  if (areAllVisibleReportsSelected(current, visibleReports)) {
    return current.filter((name) => !visibleSet.has(name));
  }

  const next = [...current];
  const existingSet = new Set(current);
  for (const name of visibleNames) {
    if (!existingSet.has(name)) {
      existingSet.add(name);
      next.push(name);
    }
  }
  return next;
}

export function pruneReportSelection(
  current: string[],
  reports: ReportMeta[],
): string[] {
  const availableSet = new Set(reports.map((r) => r.name));
  return current.filter((name) => availableSet.has(name));
}

export function buildAggregatedCsvFilename(
  selectedCount: number,
  now: Date = new Date(),
): string {
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(now.getUTCDate()).padStart(2, '0');
  const count = Math.max(0, Math.floor(selectedCount));
  const label = count === 1 ? '1run' : `${count}runs`;
  return `soti_aggregated_reports_${label}_${yyyy}${mm}${dd}.csv`;
}

export const DEFAULT_REPORTS_REFRESH_SECONDS = 60;
export const REPORTS_REFRESH_INTERVAL_OPTIONS = [15, 30, 60, 120, 300] as const;

export function normalizeRefreshIntervalSeconds(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  if (
    Number.isFinite(parsed) &&
    (REPORTS_REFRESH_INTERVAL_OPTIONS as readonly number[]).includes(parsed)
  ) {
    return parsed;
  }
  return DEFAULT_REPORTS_REFRESH_SECONDS;
}

export function formatRefreshIntervalLabel(seconds: number): string {
  const normalized = normalizeRefreshIntervalSeconds(seconds);
  if (normalized >= 60 && normalized % 60 === 0) {
    return normalized === 60 ? '60s' : `${normalized / 60}m`;
  }
  return `${normalized}s`;
}

export function buildPrintDocumentTitle(
  selectedName?: string | null,
  date: Date = new Date(),
): string {
  const stamp = date.toISOString().slice(0, 10);
  const rawStem = (selectedName || '')
    .trim()
    .replace(/\.csv$/i, '')
    .replace(/[^a-zA-Z0-9_-]+/g, '_')
    .replace(/^_+|_+$/g, '');

  if (rawStem) {
    return `${rawStem}_report_${stamp}`;
  }
  return `soti_threat_report_${stamp}`;
}

export type TableDensity = 'compact' | 'normal' | 'spacious';

export interface TableDensitySpec {
  id: TableDensity;
  label: string;
  headerPaddingClass: string;
  cellPaddingClass: string;
  fontSizeClass: string;
}

export const DEFAULT_TABLE_DENSITY: TableDensity = 'normal';

export const TABLE_DENSITY_OPTIONS: readonly TableDensitySpec[] = [
  {
    id: 'compact',
    label: 'Compact',
    headerPaddingClass: 'px-3.5 py-1.5',
    cellPaddingClass: 'px-3.5 py-1.5',
    fontSizeClass: 'text-[11px]',
  },
  {
    id: 'normal',
    label: 'Normal',
    headerPaddingClass: 'px-4 py-2.5',
    cellPaddingClass: 'px-4 py-2.5',
    fontSizeClass: 'text-xs',
  },
  {
    id: 'spacious',
    label: 'Spacious',
    headerPaddingClass: 'px-4 py-3.5',
    cellPaddingClass: 'px-4 py-4',
    fontSizeClass: 'text-xs',
  },
] as const;

export function normalizeTableDensity(value: unknown): TableDensity {
  const normalized = String(value ?? '').trim().toLowerCase();
  if (normalized === 'compact' || normalized === 'normal' || normalized === 'spacious') {
    return normalized;
  }
  return DEFAULT_TABLE_DENSITY;
}

export function getTableDensitySpec(density: TableDensity): TableDensitySpec {
  return (
    TABLE_DENSITY_OPTIONS.find((opt) => opt.id === density) ||
    TABLE_DENSITY_OPTIONS[1]
  );
}


