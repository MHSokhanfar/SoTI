import { cleanIndicator, detectIndicatorType, type IndicatorType, type LookupResult } from './indicators';
import { csvRowsToLookupResults } from './heatmapAnalytics';
import type { ReportMeta } from './reportsAnalytics';
import { computeAllIocConfidenceScores, type ConfidenceRiskLevel } from './riskScoring';

export type RiskBandId = 'High' | 'Medium' | 'Low';
export type RiskHeatmapViewMode = 'investigations' | 'indicator_type';

export type PostureRating = 'Critical' | 'Elevated' | 'Moderate' | 'Low' | 'No Data';

export interface RiskHeatmapBucketItem {
  indicator: string;
  type: IndicatorType;
  confidenceScore: number;
  riskLevel: ConfidenceRiskLevel;
  riskBand: RiskBandId;
  verdictSummary: string;
  sources: string[];
}

export interface RiskHeatmapColumn {
  key: string;
  label: string;
  shortLabel: string;
  modifiedAt: string;
  totalEvaluated: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  criticalCount: number;
  avgScore: number | null;
}

export interface RiskHeatmapCell {
  colKey: string;
  colLabel: string;
  band: RiskBandId;
  count: number;
  percentageOfColumn: number;
  avgScore: number;
  maxScore: number;
  criticalCount: number;
  items: RiskHeatmapBucketItem[];
}

export interface RiskBandSummaryEntry {
  band: RiskBandId;
  count: number;
  percentage: number;
  criticalCount: number;
}

export interface RiskScoreHeatmapModel {
  mode: RiskHeatmapViewMode;
  bands: RiskBandId[];
  columns: RiskHeatmapColumn[];
  cells: RiskHeatmapCell[];
  maxCellCount: number;
  totalInvestigationsProcessed: number;
  displayedInvestigationsCount: number;
  totalEvaluatedIndicators: number;
  uniqueEvaluatedIndicators: number;
  unscoredIndicatorsCount: number;
  postureRating: PostureRating;
  bandSummary: Record<RiskBandId, RiskBandSummaryEntry>;
}

export const RISK_HEATMAP_BANDS: RiskBandId[] = ['High', 'Medium', 'Low'];

export type RiskHeatmapLegendId = RiskBandId | 'Zero';

export interface RiskHeatmapLegendDescriptor {
  id: RiskHeatmapLegendId;
  band: RiskBandId | null;
  title: string;
  scoreRange: string;
  minScore: number | null;
  maxScore: number | null;
  subTiers: string;
  classificationRule: string;
  calculationFormula: string;
}

export const RISK_HEATMAP_LEGEND_ITEMS: readonly RiskHeatmapLegendDescriptor[] = [
  {
    id: 'Zero',
    band: null,
    title: '0 IOCs (Unpopulated)',
    scoreRange: '0 matches',
    minScore: null,
    maxScore: null,
    subTiers: 'Empty cell bucket (count = 0)',
    classificationRule:
      'Shown when zero scored IOCs in the column fell inside that risk band. Indicators returning only Error or Unsupported across all providers are excluded from scored buckets.',
    calculationFormula:
      'Populated cells scale color saturation from 28% (1 IOC) up to 100% at the highest column bucket count.',
  },
  {
    id: 'High',
    band: 'High',
    title: 'High Risk',
    scoreRange: '50–100',
    minScore: 50,
    maxScore: 100,
    subTiers: 'Critical: 75–100 · High: 50–74',
    classificationRule:
      'Includes every IOC with a weighted confidence score of 50 or above; scores of 75–100 are additionally counted as Critical in Posture metrics.',
    calculationFormula:
      'Confidence = Sum(providerScore x effectiveWeight) / Sum(effectiveWeight) across VirusTotal (0.35), AbuseIPDB (0.25), ThreatFox (0.20), URLScan (0.18), OTX (0.15), and Shodan (0.12).',
  },
  {
    id: 'Medium',
    band: 'Medium',
    title: 'Medium Risk',
    scoreRange: '25–49',
    minScore: 25,
    maxScore: 49,
    subTiers: 'Moderate / Suspicious: 25–49',
    classificationRule:
      'Includes indicators scoring 25–49 from partial suspicious detections, low-volume OTX pulses, or exposed service ports without confirmed malware.',
    calculationFormula:
      'Weighted 0–100 average where confirmed findings carry 1.0x weight and clean/not-found specialty feeds carry 0.5x weight.',
  },
  {
    id: 'Low',
    band: 'Low',
    title: 'Low Risk',
    scoreRange: '0–24',
    minScore: 0,
    maxScore: 24,
    subTiers: 'Low / Benign: 0–24',
    classificationRule:
      'Includes clean or benign indicators scoring 0–24 with zero malicious detections or negligible telemetry signal.',
    calculationFormula:
      'Unmatched lookups (not_found) contribute 0 risk at 0.5x weight so negative specialty checks never mask confirmed threats.',
  },
];

export function getRiskHeatmapLegendDescriptor(
  id: RiskHeatmapLegendId | null | undefined,
): RiskHeatmapLegendDescriptor | null {
  if (!id) return null;
  return RISK_HEATMAP_LEGEND_ITEMS.find((item) => item.id === id) ?? null;
}

export function classifyRiskBand(confidenceScore: number | null | undefined): RiskBandId | null {
  if (typeof confidenceScore !== 'number' || !Number.isFinite(confidenceScore)) {
    return null;
  }
  if (confidenceScore >= 50) return 'High';
  if (confidenceScore >= 25) return 'Medium';
  return 'Low';
}

export function formatShortRunTimestampLabel(reportName: string, modifiedAt?: string): string {
  const m = reportName.match(/(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/);
  if (m) {
    const [, , month, day, hour, minute] = m;
    return `${month}/${day} ${hour}:${minute}`;
  }
  if (modifiedAt) {
    const d = new Date(modifiedAt);
    if (!Number.isNaN(d.getTime())) {
      return d.toISOString().slice(5, 16).replace('T', ' ');
    }
  }
  return reportName.replace(/\.csv$/i, '').slice(-14);
}

function resolveWorstVerdict(items: LookupResult[]): string {
  let hasMal = false;
  let hasSusp = false;
  let hasClean = false;
  for (const r of items) {
    if (r.status !== 'ok') continue;
    if (r.verdict === 'Malicious') hasMal = true;
    else if (r.verdict === 'Suspicious') hasSusp = true;
    else if (r.verdict === 'Clean') hasClean = true;
  }
  if (hasMal) return 'Malicious';
  if (hasSusp) return 'Suspicious';
  if (hasClean) return 'Clean';
  return 'Unknown';
}

function computePostureRating(
  totalEvaluated: number,
  highCount: number,
  mediumCount: number,
  criticalCount: number,
): PostureRating {
  if (totalEvaluated === 0) return 'No Data';
  const highPct = (highCount / totalEvaluated) * 100;
  const criticalPct = (criticalCount / totalEvaluated) * 100;
  const elevatedPct = ((highCount + mediumCount) / totalEvaluated) * 100;
  if (criticalPct >= 35 || highPct >= 60) return 'Critical';
  if (highPct >= 30 || criticalCount > 0) return 'Elevated';
  if (elevatedPct >= 25) return 'Moderate';
  return 'Low';
}

function evaluateRunIndicators(
  lookupResults: LookupResult[],
): { items: RiskHeatmapBucketItem[]; unscoredCount: number } {
  if (lookupResults.length === 0) {
    return { items: [], unscoredCount: 0 };
  }

  const confidenceByIndicator = computeAllIocConfidenceScores(lookupResults);
  const byIndicator = new Map<string, LookupResult[]>();

  for (const r of lookupResults) {
    const key = r.indicator.trim().toLowerCase();
    if (!key) continue;
    const list = byIndicator.get(key);
    if (list) list.push(r);
    else byIndicator.set(key, [r]);
  }

  const items: RiskHeatmapBucketItem[] = [];
  let unscoredCount = 0;

  for (const [key, group] of byIndicator.entries()) {
    const summary = confidenceByIndicator.get(key);
    const band = classifyRiskBand(summary?.confidenceScore ?? null);
    if (!summary || summary.confidenceScore === null || !band) {
      unscoredCount += 1;
      continue;
    }

    const displayIndicator = group[0].indicator;
    const cleaned = cleanIndicator(displayIndicator) || displayIndicator;
    const inferredType: IndicatorType =
      group[0].type || detectIndicatorType(cleaned) || 'domain';

    const sources = Array.from(new Set(group.map((g) => g.source).filter(Boolean)));
    items.push({
      indicator: displayIndicator,
      type: inferredType,
      confidenceScore: summary.confidenceScore,
      riskLevel: summary.riskLevel,
      riskBand: band,
      verdictSummary: resolveWorstVerdict(group),
      sources,
    });
  }

  items.sort((a, b) => b.confidenceScore - a.confidenceScore || a.indicator.localeCompare(b.indicator));
  return { items, unscoredCount };
}

function buildBandSummary(
  items: RiskHeatmapBucketItem[],
): Record<RiskBandId, RiskBandSummaryEntry> {
  const counts: Record<RiskBandId, { count: number; criticalCount: number }> = {
    High: { count: 0, criticalCount: 0 },
    Medium: { count: 0, criticalCount: 0 },
    Low: { count: 0, criticalCount: 0 },
  };
  for (const item of items) {
    counts[item.riskBand].count += 1;
    if (item.confidenceScore >= 75) {
      counts[item.riskBand].criticalCount += 1;
    }
  }
  const total = items.length;
  const pct = (count: number) =>
    total > 0 ? Math.round((count / total) * 1000) / 10 : 0;

  return {
    High: {
      band: 'High',
      count: counts.High.count,
      percentage: pct(counts.High.count),
      criticalCount: counts.High.criticalCount,
    },
    Medium: {
      band: 'Medium',
      count: counts.Medium.count,
      percentage: pct(counts.Medium.count),
      criticalCount: 0,
    },
    Low: {
      band: 'Low',
      count: counts.Low.count,
      percentage: pct(counts.Low.count),
      criticalCount: 0,
    },
  };
}

export function buildRiskScoreHeatmap(params: {
  reports: ReportMeta[];
  allRunRows: Record<string, string>[];
  currentResults?: LookupResult[];
  mode?: RiskHeatmapViewMode;
  maxRuns?: number;
}): RiskScoreHeatmapModel {
  const mode: RiskHeatmapViewMode = params.mode ?? 'investigations';
  const maxRuns = Math.max(1, params.maxRuns ?? 14);
  const reports = params.reports || [];
  const allRunRows = params.allRunRows || [];
  const currentResults = params.currentResults || [];

  // Group archived rows by CSV filename
  const rowsByReport = new Map<string, Record<string, string>[]>();
  for (const row of allRunRows) {
    const repName = (row.reportName || row.report_file || '').trim();
    if (!repName) continue;
    const list = rowsByReport.get(repName);
    if (list) list.push(row);
    else rowsByReport.set(repName, [row]);
  }

  const reportMetaMap = new Map<string, ReportMeta>();
  for (const r of reports) {
    reportMetaMap.set(r.name, r);
  }

  // Chronological run order (oldest -> newest)
  const orderedRunNames: string[] = [];
  if (reports.length > 0) {
    for (const rep of [...reports].reverse()) {
      if (rowsByReport.has(rep.name) || allRunRows.length === 0) {
        orderedRunNames.push(rep.name);
      }
    }
  }
  for (const name of Array.from(rowsByReport.keys()).sort()) {
    if (!orderedRunNames.includes(name)) {
      orderedRunNames.push(name);
    }
  }

  // Evaluate each investigation run
  const runEvaluations: Array<{
    key: string;
    label: string;
    shortLabel: string;
    modifiedAt: string;
    items: RiskHeatmapBucketItem[];
    unscoredCount: number;
  }> = [];

  for (const runName of orderedRunNames) {
    const rawRows = rowsByReport.get(runName) || [];
    const lookupRows = csvRowsToLookupResults(rawRows);
    const { items, unscoredCount } = evaluateRunIndicators(lookupRows);
    const meta = reportMetaMap.get(runName);
    runEvaluations.push({
      key: runName,
      label: runName,
      shortLabel: formatShortRunTimestampLabel(runName, meta?.modifiedAt),
      modifiedAt: meta?.modifiedAt || '',
      items,
      unscoredCount,
    });
  }

  // Fallback to current live investigation results if no historical run rows are available yet
  if (runEvaluations.length === 0 && currentResults.length > 0) {
    const { items, unscoredCount } = evaluateRunIndicators(currentResults);
    runEvaluations.push({
      key: 'active-session',
      label: 'Active Session',
      shortLabel: 'Active Run',
      modifiedAt: new Date().toISOString(),
      items,
      unscoredCount,
    });
  }

  const allEvaluatedItems: RiskHeatmapBucketItem[] = [];
  const uniqueLatestByIndicator = new Map<string, RiskHeatmapBucketItem>();
  let totalUnscored = 0;

  for (const run of runEvaluations) {
    totalUnscored += run.unscoredCount;
    for (const item of run.items) {
      allEvaluatedItems.push(item);
      uniqueLatestByIndicator.set(item.indicator.trim().toLowerCase(), item);
    }
  }

  const uniqueItemsList = Array.from(uniqueLatestByIndicator.values());
  const bandSummary = buildBandSummary(allEvaluatedItems);
  const totalEvaluated = allEvaluatedItems.length;
  const criticalTotal = allEvaluatedItems.filter((i) => i.confidenceScore >= 75).length;
  const postureRating = computePostureRating(
    totalEvaluated,
    bandSummary.High.count,
    bandSummary.Medium.count,
    criticalTotal,
  );

  // Build columns & cells depending on selected mode
  const columns: RiskHeatmapColumn[] = [];
  const cells: RiskHeatmapCell[] = [];
  let maxCellCount = 0;

  if (mode === 'investigations') {
    const recentRuns = runEvaluations.slice(-maxRuns);
    for (const run of recentRuns) {
      const highItems = run.items.filter((i) => i.riskBand === 'High');
      const medItems = run.items.filter((i) => i.riskBand === 'Medium');
      const lowItems = run.items.filter((i) => i.riskBand === 'Low');
      const totalRun = run.items.length;
      const avgScore =
        totalRun > 0
          ? Math.round(run.items.reduce((acc, i) => acc + i.confidenceScore, 0) / totalRun)
          : null;

      columns.push({
        key: run.key,
        label: run.label,
        shortLabel: run.shortLabel,
        modifiedAt: run.modifiedAt,
        totalEvaluated: totalRun,
        highCount: highItems.length,
        mediumCount: medItems.length,
        lowCount: lowItems.length,
        criticalCount: highItems.filter((i) => i.confidenceScore >= 75).length,
        avgScore,
      });

      const byBand: Record<RiskBandId, RiskHeatmapBucketItem[]> = {
        High: highItems,
        Medium: medItems,
        Low: lowItems,
      };

      for (const band of RISK_HEATMAP_BANDS) {
        const items = byBand[band];
        const count = items.length;
        if (count > maxCellCount) maxCellCount = count;
        cells.push({
          colKey: run.key,
          colLabel: run.shortLabel,
          band,
          count,
          percentageOfColumn: totalRun > 0 ? Math.round((count / totalRun) * 100) : 0,
          avgScore:
            count > 0
              ? Math.round(items.reduce((s, i) => s + i.confidenceScore, 0) / count)
              : 0,
          maxScore: count > 0 ? Math.max(...items.map((i) => i.confidenceScore)) : 0,
          criticalCount: items.filter((i) => i.confidenceScore >= 75).length,
          items,
        });
      }
    }

    return {
      mode,
      bands: RISK_HEATMAP_BANDS,
      columns,
      cells,
      maxCellCount,
      totalInvestigationsProcessed: Math.max(reports.length, runEvaluations.length),
      displayedInvestigationsCount: recentRuns.length,
      totalEvaluatedIndicators: totalEvaluated,
      uniqueEvaluatedIndicators: uniqueItemsList.length,
      unscoredIndicatorsCount: totalUnscored,
      postureRating,
      bandSummary,
    };
  }

  // 'indicator_type' mode: aggregate across total investigations processed by IP / Domain / Hash
  const typeSpecs: Array<{ key: IndicatorType; label: string; shortLabel: string }> = [
    { key: 'ip', label: 'IP Addresses', shortLabel: 'IP Addresses' },
    { key: 'domain', label: 'Domains & URLs', shortLabel: 'Domains' },
    { key: 'hash', label: 'File Hashes', shortLabel: 'File Hashes' },
  ];

  for (const spec of typeSpecs) {
    const matching = allEvaluatedItems.filter((i) => i.type === spec.key);
    const highItems = matching.filter((i) => i.riskBand === 'High');
    const medItems = matching.filter((i) => i.riskBand === 'Medium');
    const lowItems = matching.filter((i) => i.riskBand === 'Low');
    const totalType = matching.length;
    const avgScore =
      totalType > 0
        ? Math.round(matching.reduce((acc, i) => acc + i.confidenceScore, 0) / totalType)
        : null;

    columns.push({
      key: spec.key,
      label: spec.label,
      shortLabel: spec.shortLabel,
      modifiedAt: '',
      totalEvaluated: totalType,
      highCount: highItems.length,
      mediumCount: medItems.length,
      lowCount: lowItems.length,
      criticalCount: highItems.filter((i) => i.confidenceScore >= 75).length,
      avgScore,
    });

    const byBand: Record<RiskBandId, RiskHeatmapBucketItem[]> = {
      High: highItems,
      Medium: medItems,
      Low: lowItems,
    };

    for (const band of RISK_HEATMAP_BANDS) {
      const items = byBand[band];
      const count = items.length;
      if (count > maxCellCount) maxCellCount = count;
      cells.push({
        colKey: spec.key,
        colLabel: spec.label,
        band,
        count,
        percentageOfColumn: totalType > 0 ? Math.round((count / totalType) * 100) : 0,
        avgScore:
          count > 0
            ? Math.round(items.reduce((s, i) => s + i.confidenceScore, 0) / count)
            : 0,
        maxScore: count > 0 ? Math.max(...items.map((i) => i.confidenceScore)) : 0,
        criticalCount: items.filter((i) => i.confidenceScore >= 75).length,
        items,
      });
    }
  }

  return {
    mode,
    bands: RISK_HEATMAP_BANDS,
    columns,
    cells,
    maxCellCount,
    totalInvestigationsProcessed: Math.max(reports.length, runEvaluations.length),
    displayedInvestigationsCount: runEvaluations.length,
    totalEvaluatedIndicators: totalEvaluated,
    uniqueEvaluatedIndicators: uniqueItemsList.length,
    unscoredIndicatorsCount: totalUnscored,
    postureRating,
    bandSummary,
  };
}
