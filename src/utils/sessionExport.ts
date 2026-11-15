import {
  preprocessInputForLookup,
  type LookupResult,
  type SourceSelection,
} from './indicators';
import {
  normalizeInvestigationNotes,
  summarizeLookupVerdicts,
  type RecentQuotaSkippedItem,
  type RecentVerdictSummary,
} from './investigationHistory';
import { getTagsForIndicator, type IndicatorTagMap } from './iocTags';
import {
  computeAllIocConfidenceScores,
  type ConfidenceRiskLevel,
} from './riskScoring';
import type { InvestigationAnalysisMode } from './bulkAnalysis';

export const SESSION_EXPORT_SCHEMA = 'soti.investigation_session.v1' as const;

export interface ExportedInvestigationSession {
  schema: typeof SESSION_EXPORT_SCHEMA;
  exportedAt: string;
  sessionId: string | null;
  investigation: {
    analysisMode: InvestigationAnalysisMode;
    executionMode: 'sample' | 'live';
    lastRunMode: 'sample' | 'live' | null;
    reportFile: string | null;
    rawInput: string;
    normalizedInput: string;
    indicators: string[];
    invalidTokens: string[];
    sourceSelection: SourceSelection;
    effectiveSources: string[];
    customSources: string[];
    useCustomSources: boolean;
    includeThreatFox: boolean | null;
    includeUrlscan: boolean | null;
  };
  summary: {
    totalIndicators: number;
    totalProviderLookups: number;
    verdicts: RecentVerdictSummary;
    quotaSkipped: RecentQuotaSkippedItem[];
  };
  confidenceScores: Record<
    string,
    {
      confidenceScore: number | null;
      riskLevel: ConfidenceRiskLevel;
      activeProviderCount: number;
      explanation: string;
    }
  >;
  tags: {
    byIndicator: Record<string, string[]>;
    uniqueTags: string[];
  };
  researcherNotes: {
    text: string;
    updatedAt: string | null;
  };
  results: LookupResult[];
}

export function buildSessionExportFilename(now: Date = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  const stamp =
    `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}_` +
    `${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}`;
  return `soti_session_${stamp}.json`;
}

export function buildExportedSessionPayload(params: {
  sessionId: string | null;
  analysisMode: InvestigationAnalysisMode;
  executionMode: 'sample' | 'live';
  lastRunMode: 'sample' | 'live' | null;
  reportFile: string | null;
  rawInput: string;
  invalidTokens: string[];
  sourceSelection: SourceSelection;
  effectiveSources: string[];
  customSources: string[];
  useCustomSources: boolean;
  includeThreatFox: boolean | null;
  includeUrlscan: boolean | null;
  quotaSkipped: RecentQuotaSkippedItem[];
  results: LookupResult[];
  indicatorTags: IndicatorTagMap;
  researcherNotes: string;
  notesUpdatedAt?: string | null;
  now?: Date;
}): ExportedInvestigationSession {
  const now = params.now ?? new Date();
  const preprocessed = preprocessInputForLookup(params.rawInput);

  // Merge indicators parsed from rawInput and indicators returned in results cleanly
  const indicatorSet = new Set<string>();
  for (const item of preprocessed.validIndicators) {
    indicatorSet.add(item.cleaned);
  }
  for (const r of params.results) {
    if (r.indicator.trim()) {
      indicatorSet.add(r.indicator.trim());
    }
  }
  const indicators = Array.from(indicatorSet);

  const byIndicator: Record<string, string[]> = {};
  const uniqueTagSet = new Set<string>();
  for (const ind of indicators) {
    const tags = getTagsForIndicator(params.indicatorTags, ind);
    if (tags.length > 0) {
      byIndicator[ind] = tags;
      for (const t of tags) uniqueTagSet.add(t);
    }
  }

  const confMap = computeAllIocConfidenceScores(params.results);
  const confidenceScores: ExportedInvestigationSession['confidenceScores'] = {};
  for (const [indKey, conf] of confMap.entries()) {
    confidenceScores[indKey] = {
      confidenceScore: conf.confidenceScore,
      riskLevel: conf.riskLevel,
      activeProviderCount: conf.activeProviderCount,
      explanation: conf.explanation,
    };
  }

  const cleanNotes = normalizeInvestigationNotes(params.researcherNotes);

  return {
    schema: SESSION_EXPORT_SCHEMA,
    exportedAt: now.toISOString(),
    sessionId: params.sessionId,
    investigation: {
      analysisMode: params.analysisMode,
      executionMode: params.executionMode,
      lastRunMode: params.lastRunMode,
      reportFile: params.reportFile,
      rawInput: params.rawInput,
      normalizedInput: preprocessed.apiReadyInput,
      indicators,
      invalidTokens: [...params.invalidTokens],
      sourceSelection: params.sourceSelection,
      effectiveSources: [...params.effectiveSources],
      customSources: [...params.customSources],
      useCustomSources: params.useCustomSources,
      includeThreatFox: params.includeThreatFox,
      includeUrlscan: params.includeUrlscan,
    },
    summary: {
      totalIndicators: indicators.length,
      totalProviderLookups: params.results.length,
      verdicts: summarizeLookupVerdicts(params.results),
      quotaSkipped: [...params.quotaSkipped],
    },
    confidenceScores,
    tags: {
      byIndicator,
      uniqueTags: Array.from(uniqueTagSet).sort(),
    },
    researcherNotes: {
      text: cleanNotes,
      updatedAt: cleanNotes.length > 0 ? (params.notesUpdatedAt ?? now.toISOString()) : null,
    },
    results: params.results,
  };
}

export function serializeExportedSessionJson(payload: ExportedInvestigationSession): string {
  return `${JSON.stringify(payload, null, 2)}\n`;
}
