import type { LookupResult, Verdict } from './indicators';
import {
  computeAllIocConfidenceScores,
  type ConfidenceRiskLevel,
} from './riskScoring';

export const RESULTS_EXPORT_SCHEMA = 'soti.analysis_results.v1' as const;

export interface ConfidenceLegendTier {
  level: ConfidenceRiskLevel;
  rangeLabel: string;
  description: string;
  swatchClass: string;
  textClass: string;
}

export const CONFIDENCE_SCORE_LEGEND: readonly ConfidenceLegendTier[] = [
  {
    level: 'Low',
    rangeLabel: '0–24',
    description: 'Clean or minimal benign variance across active sources',
    swatchClass: 'bg-emerald-500',
    textClass: 'text-emerald-700 dark:text-emerald-400',
  },
  {
    level: 'Medium',
    rangeLabel: '25–49',
    description: 'Low-volume suspicious flags or heuristic caution',
    swatchClass: 'bg-amber-500',
    textClass: 'text-amber-700 dark:text-amber-400',
  },
  {
    level: 'High',
    rangeLabel: '50–74',
    description: 'Elevated multi-source threat detections requiring review',
    swatchClass: 'bg-orange-500',
    textClass: 'text-orange-700 dark:text-orange-400',
  },
  {
    level: 'Critical',
    rangeLabel: '75–100',
    description: 'High-confidence malicious consensus across weighted feeds',
    swatchClass: 'bg-red-600 dark:bg-red-500',
    textClass: 'text-red-700 dark:text-red-400',
  },
  {
    level: 'Unknown',
    rangeLabel: 'N/A',
    description: 'No active scored provider responses available',
    swatchClass: 'bg-slate-400 dark:bg-slate-500',
    textClass: 'text-slate-600 dark:text-slate-400',
  },
];

export interface StructuredResultRow extends LookupResult {
  confidenceScore: number | null;
  riskLevel: ConfidenceRiskLevel;
}

export interface StructuredResultsJsonPayload {
  schema: typeof RESULTS_EXPORT_SCHEMA;
  exportedAt: string;
  mode: 'sample' | 'live' | null;
  verdictFilter: 'All' | Verdict;
  indicatorCount: number;
  rowCount: number;
  confidenceScores: Record<
    string,
    {
      confidenceScore: number | null;
      riskLevel: ConfidenceRiskLevel;
      activeProviderCount: number;
      explanation: string;
    }
  >;
  results: StructuredResultRow[];
}

export function buildResultsJsonFilename(
  verdictFilter: 'All' | Verdict = 'All',
  now: Date = new Date(),
): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  const stamp =
    `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}_` +
    `${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}`;
  const scope = verdictFilter === 'All' ? '' : `_${verdictFilter.toLowerCase()}`;
  return `soti_results${scope}_${stamp}.json`;
}

export function buildStructuredResultsJsonPayload(params: {
  allResults: LookupResult[];
  visibleResults: LookupResult[];
  verdictFilter?: 'All' | Verdict;
  mode?: 'sample' | 'live' | null;
  now?: Date;
}): StructuredResultsJsonPayload {
  const now = params.now ?? new Date();
  const verdictFilter = params.verdictFilter ?? 'All';
  const confidenceByIndicator = computeAllIocConfidenceScores(params.allResults);

  const uniqueIndicators = new Set<string>();
  const confidenceScores: StructuredResultsJsonPayload['confidenceScores'] = {};

  const enrichedResults: StructuredResultRow[] = params.visibleResults.map((row) => {
    const key = row.indicator.trim().toLowerCase();
    if (row.indicator.trim()) {
      uniqueIndicators.add(key);
    }
    const conf = confidenceByIndicator.get(key);
    if (conf && !(row.indicator in confidenceScores)) {
      confidenceScores[row.indicator] = {
        confidenceScore: conf.confidenceScore,
        riskLevel: conf.riskLevel,
        activeProviderCount: conf.activeProviderCount,
        explanation: conf.explanation,
      };
    }
    return {
      ...row,
      confidenceScore: conf?.confidenceScore ?? null,
      riskLevel: conf?.riskLevel ?? 'Unknown',
    };
  });

  return {
    schema: RESULTS_EXPORT_SCHEMA,
    exportedAt: now.toISOString(),
    mode: params.mode ?? null,
    verdictFilter,
    indicatorCount: uniqueIndicators.size,
    rowCount: enrichedResults.length,
    confidenceScores,
    results: enrichedResults,
  };
}

export function serializeStructuredResultsJson(payload: StructuredResultsJsonPayload): string {
  return `${JSON.stringify(payload, null, 2)}\n`;
}
