import type { InvestigationAnalysisMode } from './bulkAnalysis';
import type {
  IndicatorType,
  LookupResult,
  LookupStatus,
  SourceSelection,
  Verdict,
} from './indicators';
import type { RecentQuotaSkippedItem } from './investigationHistory';
import type { IndicatorTagMap } from './iocTags';
import type { ResultsSortKey, ResultsSortState, SortDirection } from './resultsTable';

export const SESSION_SNAPSHOT_PARAM = 'soti_snapshot';
export const SESSION_SNAPSHOT_PREFIX = 'soti1.';
export const MAX_SNAPSHOT_TOKEN_LENGTH = 140_000;

export interface SessionSnapshotInput {
  analysisMode: InvestigationAnalysisMode;
  mode: 'sample' | 'live';
  lastRunMode: 'sample' | 'live' | null;
  rawInput: string;
  source: SourceSelection;
  customSources: string[];
  useCustomSources: boolean;
  includeThreatFox: boolean | null;
  includeUrlscan: boolean | null;
  invalidTokens: string[];
  quotaSkipped: RecentQuotaSkippedItem[];
  lastReportFile: string | null;
  researcherNotes: string;
  indicatorTags: IndicatorTagMap;
  verdictFilter?: 'All' | Verdict;
  riskThreshold?: number;
  tableSort?: ResultsSortState | null;
  results: LookupResult[];
  createdAt?: string;
}

export interface DecodedSessionSnapshot {
  createdAt: string;
  analysisMode: InvestigationAnalysisMode;
  mode: 'sample' | 'live';
  lastRunMode: 'sample' | 'live' | null;
  rawInput: string;
  source: SourceSelection;
  customSources: string[];
  useCustomSources: boolean;
  includeThreatFox: boolean | null;
  includeUrlscan: boolean | null;
  invalidTokens: string[];
  quotaSkipped: RecentQuotaSkippedItem[];
  lastReportFile: string | null;
  researcherNotes: string;
  indicatorTags: IndicatorTagMap;
  verdictFilter: 'All' | Verdict;
  riskThreshold: number;
  tableSort: ResultsSortState | null;
  results: LookupResult[];
  indicatorCount: number;
  truncatedDetails: boolean;
}

interface CompactLookupResult {
  i: string;
  ot?: string;
  t: IndicatorType;
  s: string;
  sid: string;
  st: LookupStatus;
  v: Verdict;
  sc: string;
  sum: string;
  d: Record<string, string | number | boolean | null>;
  l: string;
}

interface WireSessionSnapshotV1 {
  v: 1;
  ca: string;
  am: InvestigationAnalysisMode;
  m: 'sample' | 'live';
  lm: 'sample' | 'live' | null;
  raw: string;
  src: SourceSelection;
  cs: string[];
  ucs: boolean;
  tf: boolean | null;
  us: boolean | null;
  it: string[];
  qs: RecentQuotaSkippedItem[];
  rf: string | null;
  rn: string;
  tags: IndicatorTagMap;
  vf: 'All' | Verdict;
  rt: number;
  ts: ResultsSortState | null;
  td?: boolean;
  res: CompactLookupResult[];
}

function encodeUtf8Base64Url(text: string): string {
  const bytes = new TextEncoder().encode(text);
  const chunkSize = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeUtf8Base64Url(encoded: string): string {
  const padded = encoded.replace(/-/g, '+').replace(/_/g, '/');
  const mod = padded.length % 4;
  const base64 = mod === 0 ? padded : padded + '='.repeat(4 - mod);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

const VALID_TYPES = new Set<IndicatorType>(['ip', 'domain', 'hash']);
const VALID_STATUSES = new Set<LookupStatus>([
  'ok',
  'not_found',
  'unsupported',
  'error',
]);
const VALID_VERDICTS = new Set<Verdict>(['Malicious', 'Suspicious', 'Clean', 'Unknown']);
const VALID_SOURCES = new Set<SourceSelection>([
  'all',
  'virustotal',
  'abuseipdb',
  'alienvault',
]);
const VALID_SORT_KEYS = new Set<ResultsSortKey>([
  'indicator',
  'type',
  'source',
  'verdict',
  'riskScore',
  'lastSeen',
  'score',
  'hits',
]);

function scopeTagsToResults(
  tagsMap: IndicatorTagMap,
  results: LookupResult[],
): IndicatorTagMap {
  const resultKeys = new Set(results.map((r) => r.indicator.trim().toLowerCase()).filter(Boolean));
  const scoped: IndicatorTagMap = {};
  for (const [key, tags] of Object.entries(tagsMap || {})) {
    const norm = key.trim().toLowerCase();
    if (!norm || !Array.isArray(tags) || tags.length === 0) continue;
    if (resultKeys.size === 0 || resultKeys.has(norm)) {
      scoped[norm] = tags.filter((t) => typeof t === 'string' && t.trim().length > 0);
    }
  }
  return scoped;
}

function compactResults(
  results: LookupResult[],
  detailLimitPerResult: number | null,
): CompactLookupResult[] {
  return results.map((r) => {
    const cleanDetails: Record<string, string | number | boolean | null> = {};
    const entries = Object.entries(r.details || {});
    const sliced = detailLimitPerResult === null ? entries : entries.slice(0, detailLimitPerResult);
    for (const [k, v] of sliced) {
      if (typeof v === 'string') {
        cleanDetails[k] = v.length > 180 ? `${v.slice(0, 177)}...` : v;
      } else if (
        (typeof v === 'number' && Number.isFinite(v)) ||
        typeof v === 'boolean' ||
        v === null
      ) {
        cleanDetails[k] = v;
      }
    }
    const item: CompactLookupResult = {
      i: r.indicator,
      t: r.type,
      s: r.source,
      sid: r.sourceId,
      st: r.status,
      v: r.verdict,
      sc: r.score,
      sum: r.summary,
      d: cleanDetails,
      l: r.link || '',
    };
    if (r.originalToken && r.originalToken !== r.indicator) {
      item.ot = r.originalToken;
    }
    return item;
  });
}

export function encodeSessionSnapshot(input: SessionSnapshotInput): {
  token: string;
  truncatedDetails: boolean;
} {
  const createdAt = input.createdAt || new Date().toISOString();
  const baseWire: Omit<WireSessionSnapshotV1, 'res' | 'td'> = {
    v: 1,
    ca: createdAt,
    am: input.analysisMode === 'bulk' ? 'bulk' : 'standard',
    m: input.mode === 'live' ? 'live' : 'sample',
    lm: input.lastRunMode ?? null,
    raw: input.rawInput || '',
    src: VALID_SOURCES.has(input.source) ? input.source : 'all',
    cs: Array.isArray(input.customSources) ? input.customSources.filter(Boolean) : [],
    ucs: Boolean(input.useCustomSources),
    tf: input.includeThreatFox ?? null,
    us: input.includeUrlscan ?? null,
    it: Array.isArray(input.invalidTokens) ? input.invalidTokens.slice(0, 50) : [],
    qs: Array.isArray(input.quotaSkipped) ? input.quotaSkipped.slice(0, 20) : [],
    rf: input.lastReportFile ?? null,
    rn: (input.researcherNotes || '').slice(0, 4000),
    tags: scopeTagsToResults(input.indicatorTags, input.results),
    vf: input.verdictFilter || 'All',
    rt:
      typeof input.riskThreshold === 'number' && Number.isFinite(input.riskThreshold)
        ? Math.max(0, Math.min(100, Math.round(input.riskThreshold)))
        : 0,
    ts: input.tableSort ?? null,
  };

  let truncatedDetails = false;
  let wire: WireSessionSnapshotV1 = {
    ...baseWire,
    res: compactResults(input.results, null),
  };
  let token = `${SESSION_SNAPSHOT_PREFIX}${encodeUtf8Base64Url(JSON.stringify(wire))}`;

  // Trim verbose provider detail maps only if snapshot exceeds generous URL hash budget
  if (token.length > 48_000) {
    truncatedDetails = true;
    wire = {
      ...baseWire,
      td: true,
      res: compactResults(input.results, 4),
    };
    token = `${SESSION_SNAPSHOT_PREFIX}${encodeUtf8Base64Url(JSON.stringify(wire))}`;
  }

  return { token, truncatedDetails };
}

export function buildSessionSnapshotUrl(
  baseHref: string,
  input: SessionSnapshotInput,
): {
  url: string;
  token: string;
  byteLength: number;
  truncatedDetails: boolean;
} {
  const { token, truncatedDetails } = encodeSessionSnapshot(input);
  let urlStr: string;
  try {
    const parsed = new URL(baseHref);
    parsed.searchParams.delete('share');
    parsed.searchParams.delete(SESSION_SNAPSHOT_PARAM);
    parsed.hash = `${SESSION_SNAPSHOT_PARAM}=${token}`;
    urlStr = parsed.toString();
  } catch {
    const cleanBase = baseHref.split('#')[0];
    urlStr = `${cleanBase}#${SESSION_SNAPSHOT_PARAM}=${token}`;
  }

  return {
    url: urlStr,
    token,
    byteLength: token.length,
    truncatedDetails,
  };
}

export function parseSessionSnapshotTokenFromLocation(
  search: string,
  hash: string,
): string | null {
  const checkParams = (raw: string): string | null => {
    const cleaned = raw.replace(/^[?#]/, '');
    if (!cleaned) return null;
    const params = new URLSearchParams(cleaned);
    const val = params.get(SESSION_SNAPSHOT_PARAM);
    return val && val.trim().length > 0 ? val.trim() : null;
  };

  return checkParams(hash) ?? checkParams(search);
}

export function decodeSessionSnapshot(rawToken: string): DecodedSessionSnapshot | null {
  const trimmed = (rawToken || '').trim();
  if (!trimmed || trimmed.length > MAX_SNAPSHOT_TOKEN_LENGTH) {
    return null;
  }
  if (!trimmed.startsWith(SESSION_SNAPSHOT_PREFIX)) {
    return null;
  }
  const encodedBody = trimmed.slice(SESSION_SNAPSHOT_PREFIX.length);
  if (!encodedBody) return null;

  try {
    const jsonText = decodeUtf8Base64Url(encodedBody);
    const parsed = JSON.parse(jsonText) as Partial<WireSessionSnapshotV1>;
    if (!parsed || parsed.v !== 1 || !Array.isArray(parsed.res)) {
      return null;
    }

    const results: LookupResult[] = [];
    for (const item of parsed.res) {
      if (!item || typeof item.i !== 'string' || typeof item.s !== 'string') continue;
      const details: Record<string, string | number | boolean | null> = {};
      if (item.d && typeof item.d === 'object') {
        for (const [k, v] of Object.entries(item.d)) {
          if (
            typeof v === 'string' ||
            (typeof v === 'number' && Number.isFinite(v)) ||
            typeof v === 'boolean' ||
            v === null
          ) {
            details[k] = v;
          }
        }
      }
      results.push({
        indicator: item.i,
        originalToken: typeof item.ot === 'string' && item.ot ? item.ot : item.i,
        type: VALID_TYPES.has(item.t) ? item.t : 'domain',
        source: item.s,
        sourceId: typeof item.sid === 'string' ? item.sid : 'custom',
        status: VALID_STATUSES.has(item.st) ? item.st : 'ok',
        verdict: VALID_VERDICTS.has(item.v) ? item.v : 'Unknown',
        score: typeof item.sc === 'string' ? item.sc : 'N/A',
        summary: typeof item.sum === 'string' ? item.sum : '',
        details,
        link: typeof item.l === 'string' ? item.l : '',
      });
    }

    let tableSort: ResultsSortState | null = null;
    if (
      parsed.ts &&
      typeof parsed.ts === 'object' &&
      VALID_SORT_KEYS.has(parsed.ts.key) &&
      (parsed.ts.direction === 'asc' || parsed.ts.direction === 'desc')
    ) {
      tableSort = {
        key: parsed.ts.key,
        direction: parsed.ts.direction as SortDirection,
      };
    }

    const tags: IndicatorTagMap = {};
    if (parsed.tags && typeof parsed.tags === 'object') {
      for (const [k, arr] of Object.entries(parsed.tags)) {
        if (Array.isArray(arr)) {
          const valid = arr.filter((t): t is string => typeof t === 'string' && t.trim().length > 0);
          if (valid.length > 0) tags[k.toLowerCase()] = valid;
        }
      }
    }

    const uniqueIndicators = new Set(
      results.map((r) => r.indicator.trim().toLowerCase()).filter(Boolean),
    );

    const verdictFilter =
      parsed.vf === 'All' || (parsed.vf && VALID_VERDICTS.has(parsed.vf))
        ? parsed.vf
        : 'All';

    return {
      createdAt:
        typeof parsed.ca === 'string' && parsed.ca ? parsed.ca : new Date().toISOString(),
      analysisMode: parsed.am === 'bulk' ? 'bulk' : 'standard',
      mode: parsed.m === 'live' ? 'live' : 'sample',
      lastRunMode:
        parsed.lm === 'live' || parsed.lm === 'sample' ? parsed.lm : null,
      rawInput: typeof parsed.raw === 'string' ? parsed.raw : '',
      source: parsed.src && VALID_SOURCES.has(parsed.src) ? parsed.src : 'all',
      customSources: Array.isArray(parsed.cs)
        ? parsed.cs.filter((s): s is string => typeof s === 'string')
        : [],
      useCustomSources: Boolean(parsed.ucs),
      includeThreatFox: typeof parsed.tf === 'boolean' ? parsed.tf : null,
      includeUrlscan: typeof parsed.us === 'boolean' ? parsed.us : null,
      invalidTokens: Array.isArray(parsed.it)
        ? parsed.it.filter((s): s is string => typeof s === 'string')
        : [],
      quotaSkipped: Array.isArray(parsed.qs) ? parsed.qs : [],
      lastReportFile: typeof parsed.rf === 'string' ? parsed.rf : null,
      researcherNotes: typeof parsed.rn === 'string' ? parsed.rn : '',
      indicatorTags: tags,
      verdictFilter,
      riskThreshold:
        typeof parsed.rt === 'number' && Number.isFinite(parsed.rt)
          ? Math.max(0, Math.min(100, Math.round(parsed.rt)))
          : 0,
      tableSort,
      results,
      indicatorCount: uniqueIndicators.size,
      truncatedDetails: Boolean(parsed.td),
    };
  } catch {
    return null;
  }
}

export function stripSessionSnapshotFromUrl(href: string): string {
  try {
    const parsed = new URL(href);
    parsed.searchParams.delete(SESSION_SNAPSHOT_PARAM);
    if (parsed.hash) {
      const hashRaw = parsed.hash.replace(/^#/, '');
      const hashParams = new URLSearchParams(hashRaw);
      if (hashParams.has(SESSION_SNAPSHOT_PARAM)) {
        hashParams.delete(SESSION_SNAPSHOT_PARAM);
        const remaining = hashParams.toString();
        parsed.hash = remaining ? `#${remaining}` : '';
      }
    }
    return parsed.toString();
  } catch {
    return href.split('#')[0];
  }
}

export function formatSnapshotPayloadSize(chars: number): string {
  if (chars < 1024) return `${chars} B`;
  return `${(chars / 1024).toFixed(1)} KB`;
}
