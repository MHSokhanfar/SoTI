import {
  preprocessInputForLookup,
  type IndicatorType,
  type LookupResult,
  type Verdict,
} from './indicators';
import { getTagsForIndicator, type IndicatorTagMap } from './iocTags';
import { computeAllIocConfidenceScores, type ConfidenceRiskLevel } from './riskScoring';

export type InvestigationAnalysisMode = 'standard' | 'bulk';
export type BatchProcessingStrategy = 'concurrent' | 'sequential';

export const BATCH_STRATEGY_STORAGE_KEY = 'soti_batch_processing_strategy_v1';

export function normalizeBatchStrategy(raw: unknown): BatchProcessingStrategy {
  return raw === 'sequential' ? 'sequential' : 'concurrent';
}

export function resolveInitialBatchStrategy(
  storage?: Pick<Storage, 'getItem'> | null,
): BatchProcessingStrategy {
  if (!storage) return 'concurrent';
  try {
    return normalizeBatchStrategy(storage.getItem(BATCH_STRATEGY_STORAGE_KEY));
  } catch {
    return 'concurrent';
  }
}

export function saveBatchStrategy(
  storage: Pick<Storage, 'setItem'> | null | undefined,
  strategy: BatchProcessingStrategy,
): void {
  if (!storage) return;
  try {
    storage.setItem(BATCH_STRATEGY_STORAGE_KEY, normalizeBatchStrategy(strategy));
  } catch {
    // ignore storage errors
  }
}

export function shouldRunParallelLookup(strategy: BatchProcessingStrategy): boolean {
  return normalizeBatchStrategy(strategy) === 'concurrent';
}

export function describeBatchStrategy(strategy: BatchProcessingStrategy): string {
  return normalizeBatchStrategy(strategy) === 'sequential'
    ? 'Slower, one request at a time (better for rate-limited API keys)'
    : 'Fast, parallel multi-provider requests (higher API load)';
}

export const BULK_SAMPLE_BATCH = [
  '1[.]2[.]3[.]4',
  '8.8.8.8',
  '185.220.101.5',
  'hxxp://evil[.]com/login',
  'google.com',
  '44d88612fea8a8f36de82e1278abb02f',
].join('\n');

export interface BulkInputStats {
  totalValid: number;
  lineCount: number;
  ipCount: number;
  domainCount: number;
  hashCount: number;
  invalidCount: number;
  defangedCount: number;
}

export interface ProviderColumnSpec {
  sourceId: string;
  source: string;
}

export interface UnifiedBatchRow {
  indicator: string;
  type: IndicatorType;
  overallVerdict: Verdict;
  confidenceScore: number | null;
  riskLevel: ConfidenceRiskLevel;
  confidenceExplanation: string;
  maliciousHits: number;
  suspiciousHits: number;
  cleanHits: number;
  respondedCount: number;
  totalProvidersQueried: number;
  tags: string[];
  providerCells: Record<string, LookupResult>;
  results: LookupResult[];
}

export interface UnifiedBatchTableData {
  providerColumns: ProviderColumnSpec[];
  rows: UnifiedBatchRow[];
  summary: {
    totalIndicators: number;
    maliciousCount: number;
    suspiciousCount: number;
    cleanCount: number;
    unknownCount: number;
    totalProviderLookups: number;
  };
}

const VERDICT_SEVERITY_RANK: Record<Verdict, number> = {
  Malicious: 3,
  Suspicious: 2,
  Clean: 1,
  Unknown: 0,
};

const PROVIDER_DISPLAY_ORDER = [
  'virustotal',
  'abuseipdb',
  'alienvault',
  'shodan',
  'threatfox',
  'urlscan',
];

export function summarizeBulkInputStats(rawInput: string): BulkInputStats {
  const prep = preprocessInputForLookup(rawInput);
  const lineCount = rawInput
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean).length;
  let ipCount = 0;
  let domainCount = 0;
  let hashCount = 0;

  for (const item of prep.validIndicators) {
    if (item.type === 'ip') ipCount += 1;
    else if (item.type === 'domain') domainCount += 1;
    else if (item.type === 'hash') hashCount += 1;
  }

  return {
    totalValid: prep.validIndicators.length,
    lineCount,
    ipCount,
    domainCount,
    hashCount,
    invalidCount: prep.invalidTokens.length,
    defangedCount: prep.defangedCount,
  };
}

export function formatIndicatorsAsNewlines(rawInput: string): string {
  const prep = preprocessInputForLookup(rawInput);
  if (prep.parsed.length === 0) return '';
  const uniqueTokens: string[] = [];
  const seen = new Set<string>();
  for (const item of prep.parsed) {
    const token = (item.original || '').trim();
    const key = (item.cleaned || token).toLowerCase();
    if (token && !seen.has(key)) {
      seen.add(key);
      uniqueTokens.push(token);
    }
  }
  return uniqueTokens.join('\n');
}

export function deduplicateBulkInputLines(rawInput: string): string {
  const prep = preprocessInputForLookup(rawInput);
  return prep.validIndicators.map((v) => v.cleaned).join('\n');
}

export function computeOverallBatchVerdict(results: LookupResult[]): Verdict {
  let best: Verdict = 'Unknown';
  for (const r of results) {
    if (r.status !== 'ok') continue;
    if (VERDICT_SEVERITY_RANK[r.verdict] > VERDICT_SEVERITY_RANK[best]) {
      best = r.verdict;
    }
  }
  return best;
}

export function buildUnifiedBatchTable(
  results: LookupResult[],
  indicatorTags: IndicatorTagMap = {},
): UnifiedBatchTableData {
  const confidenceByIndicator = computeAllIocConfidenceScores(results);

  const providerMap = new Map<string, string>();
  const byIndicator = new Map<
    string,
    { indicator: string; type: IndicatorType; items: LookupResult[] }
  >();

  for (const r of results) {
    if (r.sourceId && !providerMap.has(r.sourceId)) {
      providerMap.set(r.sourceId, r.source || r.sourceId);
    }
    const key = r.indicator.trim().toLowerCase();
    if (!key) continue;
    const existing = byIndicator.get(key);
    if (existing) {
      existing.items.push(r);
    } else {
      byIndicator.set(key, {
        indicator: r.indicator,
        type: r.type,
        items: [r],
      });
    }
  }

  const providerColumns: ProviderColumnSpec[] = Array.from(providerMap.entries())
    .map(([sourceId, source]) => ({ sourceId, source }))
    .sort((a, b) => {
      const idxA = PROVIDER_DISPLAY_ORDER.indexOf(a.sourceId.toLowerCase());
      const idxB = PROVIDER_DISPLAY_ORDER.indexOf(b.sourceId.toLowerCase());
      if (idxA !== -1 && idxB !== -1) return idxA - idxB;
      if (idxA !== -1) return -1;
      if (idxB !== -1) return 1;
      return a.source.localeCompare(b.source);
    });

  let maliciousCount = 0;
  let suspiciousCount = 0;
  let cleanCount = 0;
  let unknownCount = 0;

  const rows: UnifiedBatchRow[] = Array.from(byIndicator.entries()).map(
    ([indKey, group]) => {
      const overallVerdict = computeOverallBatchVerdict(group.items);
      if (overallVerdict === 'Malicious') maliciousCount += 1;
      else if (overallVerdict === 'Suspicious') suspiciousCount += 1;
      else if (overallVerdict === 'Clean') cleanCount += 1;
      else unknownCount += 1;

      const conf = confidenceByIndicator.get(indKey);
      const providerCells: Record<string, LookupResult> = {};
      let maliciousHits = 0;
      let suspiciousHits = 0;
      let cleanHits = 0;
      let respondedCount = 0;

      for (const item of group.items) {
        providerCells[item.sourceId] = item;
        if (item.status === 'ok') {
          respondedCount += 1;
          if (item.verdict === 'Malicious') maliciousHits += 1;
          else if (item.verdict === 'Suspicious') suspiciousHits += 1;
          else if (item.verdict === 'Clean') cleanHits += 1;
        }
      }

      return {
        indicator: group.indicator,
        type: group.type,
        overallVerdict,
        confidenceScore: conf?.confidenceScore ?? null,
        riskLevel: conf?.riskLevel ?? 'Unknown',
        confidenceExplanation: conf?.explanation ?? '',
        maliciousHits,
        suspiciousHits,
        cleanHits,
        respondedCount,
        totalProvidersQueried: group.items.length,
        tags: getTagsForIndicator(indicatorTags, group.indicator),
        providerCells,
        results: group.items,
      };
    },
  );

  return {
    providerColumns,
    rows,
    summary: {
      totalIndicators: rows.length,
      maliciousCount,
      suspiciousCount,
      cleanCount,
      unknownCount,
      totalProviderLookups: results.length,
    },
  };
}

export function filterUnifiedBatchRows(
  rows: UnifiedBatchRow[],
  verdictFilter: 'All' | Verdict,
): UnifiedBatchRow[] {
  if (verdictFilter === 'All') return rows;
  return rows.filter((row) => row.overallVerdict === verdictFilter);
}

export function formatUnifiedBatchRowClipboard(
  row: UnifiedBatchRow,
  providerColumns: ProviderColumnSpec[],
): string {
  const confText =
    row.confidenceScore !== null ? `${row.confidenceScore}/100 (${row.riskLevel})` : 'N/A';
  const providerSummary = providerColumns
    .map((col) => {
      const cell = row.providerCells[col.sourceId];
      if (!cell) return null;
      if (cell.status !== 'ok') {
        return `${col.source}: ${cell.status.toUpperCase()}`;
      }
      return `${col.source}: ${cell.verdict}${cell.score ? ` (${cell.score})` : ''}`;
    })
    .filter(Boolean)
    .join(' | ');
  const tagsPart = row.tags.length > 0 ? ` | Tags: ${row.tags.join(', ')}` : '';
  return `${row.indicator} (${row.type.toUpperCase()}) | Overall: ${row.overallVerdict} | Confidence: ${confText}${tagsPart}${providerSummary ? ` | ${providerSummary}` : ''}`;
}
