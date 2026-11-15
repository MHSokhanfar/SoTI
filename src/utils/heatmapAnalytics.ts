import type { LookupResult, LookupStatus, Verdict } from './indicators';
import { computeAllIocConfidenceScores, type ConfidenceRiskLevel } from './riskScoring';

export type HeatmapDimension = 'region' | 'network';
export type HeatmapThresholdFilter = 'high_confidence' | 'critical_only' | 'all';

export type RiskTierBucketId = 'Critical' | 'High' | 'Medium' | 'Low';

export interface HeatmapIocItem {
  indicator: string;
  type: string;
  confidenceScore: number;
  riskLevel: ConfidenceRiskLevel;
  countryCode: string | null;
  regionLabel: string;
  networkSegment: string;
  sources: string[];
}

export interface HeatmapCell {
  rowKey: string;
  colKey: RiskTierBucketId;
  count: number;
  maxScore: number;
  avgScore: number;
  indicators: HeatmapIocItem[];
}

export interface HeatmapRowMeta {
  key: string;
  totalCount: number;
  highConfidenceCount: number;
  criticalCount: number;
}

export interface HeatmapMatrixData {
  dimension: HeatmapDimension;
  thresholdFilter: HeatmapThresholdFilter;
  columns: RiskTierBucketId[];
  rows: HeatmapRowMeta[];
  cells: HeatmapCell[];
  maxCellCount: number;
  totalHighConfidenceIocs: number;
  totalEvaluatedIocs: number;
}

const REGION_BY_COUNTRY: Record<string, string> = {
  US: 'North America · US',
  CA: 'North America · CA',
  MX: 'North America · MX',
  BR: 'South America · BR',
  AR: 'South America · AR',
  GB: 'Western Europe · GB',
  UK: 'Western Europe · GB',
  DE: 'Western Europe · DE',
  NL: 'Western Europe · NL',
  FR: 'Western Europe · FR',
  CH: 'Western Europe · CH',
  SE: 'Northern Europe · SE',
  FI: 'Northern Europe · FI',
  NO: 'Northern Europe · NO',
  PL: 'Eastern Europe · PL',
  UA: 'Eastern Europe · UA',
  RO: 'Eastern Europe · RO',
  BG: 'Eastern Europe · BG',
  RU: 'Eurasia · RU',
  TR: 'Eurasia · TR',
  CN: 'East Asia · CN',
  HK: 'East Asia · HK',
  JP: 'East Asia · JP',
  KR: 'East Asia · KR',
  TW: 'East Asia · TW',
  SG: 'Southeast Asia · SG',
  VN: 'Southeast Asia · VN',
  ID: 'Southeast Asia · ID',
  IN: 'South Asia · IN',
  AU: 'Oceania · AU',
  NZ: 'Oceania · NZ',
  ZA: 'Africa · ZA',
  AE: 'Middle East · AE',
  IL: 'Middle East · IL',
};

const COUNTRY_NAME_TO_CODE: Record<string, string> = {
  'united states': 'US',
  'united states of america': 'US',
  usa: 'US',
  canada: 'CA',
  mexico: 'MX',
  brazil: 'BR',
  'united kingdom': 'GB',
  germany: 'DE',
  netherlands: 'NL',
  'the netherlands': 'NL',
  france: 'FR',
  switzerland: 'CH',
  sweden: 'SE',
  finland: 'FI',
  norway: 'NO',
  poland: 'PL',
  ukraine: 'UA',
  romania: 'RO',
  bulgaria: 'BG',
  russia: 'RU',
  'russian federation': 'RU',
  turkey: 'TR',
  china: 'CN',
  'hong kong': 'HK',
  japan: 'JP',
  'south korea': 'KR',
  taiwan: 'TW',
  singapore: 'SG',
  vietnam: 'VN',
  indonesia: 'ID',
  india: 'IN',
  australia: 'AU',
  'new zealand': 'NZ',
  'south africa': 'ZA',
};

export function normalizeCountryCode(raw: string | null | undefined): string | null {
  const trimmed = String(raw ?? '').trim();
  if (!trimmed || /^n\/a$/i.test(trimmed) || trimmed === 'Unknown') return null;

  const upper = trimmed.toUpperCase();
  if (/^[A-Z]{2}$/.test(upper)) {
    return upper === 'UK' ? 'GB' : upper;
  }

  const lower = trimmed.toLowerCase();
  if (lower in COUNTRY_NAME_TO_CODE) {
    return COUNTRY_NAME_TO_CODE[lower];
  }
  return trimmed.slice(0, 24);
}

export function formatGeographicRegion(countryRaw: string | null | undefined): {
  code: string | null;
  regionLabel: string;
} {
  const code = normalizeCountryCode(countryRaw);
  if (!code) {
    return { code: null, regionLabel: 'Unattributed / Hash & Domain' };
  }
  if (code in REGION_BY_COUNTRY) {
    return { code, regionLabel: REGION_BY_COUNTRY[code] };
  }
  if (/^[A-Z]{2}$/.test(code)) {
    return { code, regionLabel: `Region · ${code}` };
  }
  return { code, regionLabel: code };
}

export function deriveIpSubnetSegment(indicator: string): string | null {
  const ipv4Match = indicator.trim().match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
  if (ipv4Match) {
    return `${ipv4Match[1]}.${ipv4Match[2]}.0.0/16`;
  }
  return null;
}

export function formatNetworkSegment(
  indicator: string,
  itype: string,
  detailsList: Record<string, unknown>[],
): string {
  let asnNum: string | null = null;
  let owner: string | null = null;
  let usageType: string | null = null;
  let resolvedIp: string | null = null;

  for (const details of detailsList) {
    if (!details || typeof details !== 'object') continue;
    const rawAsn = details.ASN ?? details.asn;
    if (!asnNum && rawAsn !== undefined && rawAsn !== null) {
      const s = String(rawAsn).trim();
      if (s && !/^n\/a$/i.test(s) && s !== 'ASNone') {
        const numMatch = s.match(/AS?\s*(\d+)/i);
        if (numMatch) {
          asnNum = `AS${numMatch[1]}`;
          const rest = s.replace(/^AS?\s*\d+\s*/i, '').trim();
          if (rest && !owner) owner = rest;
        } else if (/^\d+$/.test(s)) {
          asnNum = `AS${s}`;
        }
      }
    }

    const rawOwner = details['AS Owner'] ?? details.ISP ?? details.Registrar;
    if (!owner && typeof rawOwner === 'string') {
      const s = rawOwner.trim();
      if (s && !/^n\/a$/i.test(s) && s !== 'Unknown') {
        owner = s;
      }
    }

    const rawUsage = details['Usage Type'];
    if (!usageType && typeof rawUsage === 'string' && rawUsage.trim() && !/^n\/a$/i.test(rawUsage)) {
      usageType = rawUsage.trim().split('/')[0].trim();
    }

    const rawRelatedIp = details['Page IP'] ?? details['Resolved IP'] ?? details['Related IP'];
    if (!resolvedIp && typeof rawRelatedIp === 'string' && rawRelatedIp.trim()) {
      resolvedIp = rawRelatedIp.trim().split(',')[0].trim();
    }
  }

  if (asnNum) {
    const cleanOwner = owner ? owner.replace(/\s+/g, ' ').slice(0, 22) : null;
    return cleanOwner ? `${asnNum} · ${cleanOwner}` : asnNum;
  }

  if (owner) {
    return owner.slice(0, 28);
  }

  const subnet = deriveIpSubnetSegment(indicator) ?? (resolvedIp ? deriveIpSubnetSegment(resolvedIp) : null);
  if (subnet) {
    return usageType ? `${subnet} (${usageType})` : `Prefix ${subnet}`;
  }

  if (itype === 'domain') {
    const tldMatch = indicator.trim().toLowerCase().match(/\.([a-z0-9-]{2,20})$/);
    return tldMatch ? `Domain Segment (.${tldMatch[1]})` : 'Domain Infrastructure';
  }

  if (itype === 'hash') {
    return 'Endpoint / Payload Hashes';
  }

  return 'Unclassified Segment';
}

export function parseRowDetailsObject(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
  if (typeof raw === 'string' && raw.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return {};
    }
  }
  return {};
}

export function inferSourceIdFromName(sourceName: string): string {
  const lower = (sourceName || '').trim().toLowerCase();
  if (lower.includes('virustotal')) return 'virustotal';
  if (lower.includes('abuseipdb')) return 'abuseipdb';
  if (lower.includes('alienvault') || lower.includes('otx')) return 'alienvault';
  if (lower.includes('threatfox')) return 'threatfox';
  if (lower.includes('urlscan')) return 'urlscan';
  if (lower.includes('shodan')) return 'shodan';
  return lower.replace(/\s+/g, '-') || 'custom';
}

export function csvRowsToLookupResults(rows: Record<string, string>[]): LookupResult[] {
  const converted: LookupResult[] = [];
  for (const row of rows) {
    const indicator = (row.indicator || '').trim();
    const source = (row.source || '').trim();
    if (!indicator || !source) continue;

    const rawType = (row.type || '').trim().toLowerCase();
    const itype: LookupResult['type'] =
      rawType === 'ip' || rawType === 'domain' || rawType === 'hash' ? rawType : 'domain';

    const rawStatus = (row.status || 'ok').trim().toLowerCase();
    const status: LookupStatus =
      rawStatus === 'ok' || rawStatus === 'not_found' || rawStatus === 'unsupported' || rawStatus === 'error'
        ? rawStatus
        : 'ok';

    const rawVerdict = (row.verdict || 'Unknown').trim();
    const verdict: Verdict =
      rawVerdict === 'Malicious' ||
      rawVerdict === 'Suspicious' ||
      rawVerdict === 'Clean' ||
      rawVerdict === 'Unknown'
        ? rawVerdict
        : 'Unknown';

    const parsedDetails = parseRowDetailsObject(row.details);
    const normalizedDetails: Record<string, string | number | boolean | null> = {};
    for (const [k, v] of Object.entries(parsedDetails)) {
      if (
        typeof v === 'string' ||
        typeof v === 'number' ||
        typeof v === 'boolean' ||
        v === null
      ) {
        normalizedDetails[k] = v;
      } else {
        normalizedDetails[k] = String(v);
      }
    }

    converted.push({
      source,
      sourceId: inferSourceIdFromName(source),
      indicator,
      originalToken: indicator,
      type: itype,
      status,
      verdict,
      score: (row.score || '').trim(),
      summary: (row.summary || '').trim(),
      details: normalizedDetails,
      link: (row.link || '').trim(),
    });
  }
  return converted;
}

const ALL_COLUMNS: RiskTierBucketId[] = ['Critical', 'High', 'Medium', 'Low'];
const HIGH_CONF_COLUMNS: RiskTierBucketId[] = ['Critical', 'High'];
const CRITICAL_COLUMNS: RiskTierBucketId[] = ['Critical'];

export function getColumnsForThresholdFilter(
  filter: HeatmapThresholdFilter,
): RiskTierBucketId[] {
  if (filter === 'critical_only') return CRITICAL_COLUMNS;
  if (filter === 'high_confidence') return HIGH_CONF_COLUMNS;
  return ALL_COLUMNS;
}

export function buildIocHeatmapMatrix(
  lookupResults: LookupResult[],
  options: {
    dimension?: HeatmapDimension;
    thresholdFilter?: HeatmapThresholdFilter;
    maxRows?: number;
  } = {},
): HeatmapMatrixData {
  const dimension: HeatmapDimension = options.dimension ?? 'region';
  const thresholdFilter: HeatmapThresholdFilter = options.thresholdFilter ?? 'high_confidence';
  const maxRows = options.maxRows ?? 8;
  const columns = getColumnsForThresholdFilter(thresholdFilter);

  const confidenceByIndicator = computeAllIocConfidenceScores(lookupResults);

  // Group lookup results by lowercase unique indicator
  const byIndicator = new Map<string, LookupResult[]>();
  for (const r of lookupResults) {
    const key = r.indicator.trim().toLowerCase();
    if (!key) continue;
    const list = byIndicator.get(key) || [];
    list.push(r);
    byIndicator.set(key, list);
  }

  let totalEvaluatedIocs = 0;
  let totalHighConfidenceIocs = 0;

  // Map: rowKey -> colKey -> Map<indicatorLower, HeatmapIocItem>
  const bucketMap = new Map<string, Map<RiskTierBucketId, Map<string, HeatmapIocItem>>>();
  const rowStats = new Map<
    string,
    { total: Set<string>; highConf: Set<string>; critical: Set<string> }
  >();

  for (const [indKey, rows] of byIndicator.entries()) {
    const conf = confidenceByIndicator.get(indKey);
    if (!conf || conf.confidenceScore === null || conf.riskLevel === 'Unknown') {
      continue;
    }

    totalEvaluatedIocs += 1;
    const score = conf.confidenceScore;
    if (score >= 50) {
      totalHighConfidenceIocs += 1;
    }

    if (thresholdFilter === 'high_confidence' && score < 50) continue;
    if (thresholdFilter === 'critical_only' && score < 75) continue;

    const bucketCol = conf.riskLevel as RiskTierBucketId;
    if (!columns.includes(bucketCol)) continue;

    const primaryIndicator = rows[0].indicator;
    const primaryType = rows[0].type;
    const sources = Array.from(new Set(rows.map((r) => r.source).filter(Boolean)));
    const detailsList = rows.map((r) => r.details || {});

    const networkSegment = formatNetworkSegment(primaryIndicator, primaryType, detailsList);

    // Collect distinct countries/regions reported across providers for this IOC
    const seenRegionLabels = new Set<string>();
    const regionPairs: { code: string | null; regionLabel: string }[] = [];
    for (const details of detailsList) {
      const countryRaw = details.Country ?? details.country;
      if (countryRaw !== undefined && countryRaw !== null && String(countryRaw).trim() !== '') {
        const formatted = formatGeographicRegion(String(countryRaw));
        if (formatted.code && !seenRegionLabels.has(formatted.regionLabel)) {
          seenRegionLabels.add(formatted.regionLabel);
          regionPairs.push(formatted);
        }
      }
    }
    if (regionPairs.length === 0) {
      regionPairs.push({ code: null, regionLabel: 'Unattributed / Hash & Domain' });
    }

    const rowAssignments =
      dimension === 'region'
        ? regionPairs.map((rp) => ({ rowKey: rp.regionLabel, geo: rp }))
        : [{ rowKey: networkSegment, geo: regionPairs[0] }];

    for (const assignment of rowAssignments) {
      const { rowKey, geo } = assignment;
      if (!bucketMap.has(rowKey)) {
        bucketMap.set(rowKey, new Map());
      }
      const colMap = bucketMap.get(rowKey)!;
      if (!colMap.has(bucketCol)) {
        colMap.set(bucketCol, new Map());
      }

      colMap.get(bucketCol)!.set(indKey, {
        indicator: primaryIndicator,
        type: primaryType,
        confidenceScore: score,
        riskLevel: conf.riskLevel,
        countryCode: geo.code,
        regionLabel: geo.regionLabel,
        networkSegment,
        sources,
      });

      if (!rowStats.has(rowKey)) {
        rowStats.set(rowKey, {
          total: new Set(),
          highConf: new Set(),
          critical: new Set(),
        });
      }
      const stats = rowStats.get(rowKey)!;
      stats.total.add(indKey);
      if (score >= 50) stats.highConf.add(indKey);
      if (score >= 75) stats.critical.add(indKey);
    }
  }

  const sortedRowMetas: HeatmapRowMeta[] = Array.from(rowStats.entries())
    .map(([key, stats]) => ({
      key,
      totalCount: stats.total.size,
      highConfidenceCount: stats.highConf.size,
      criticalCount: stats.critical.size,
    }))
    .sort((a, b) => {
      if (b.criticalCount !== a.criticalCount) return b.criticalCount - a.criticalCount;
      if (b.highConfidenceCount !== a.highConfidenceCount) {
        return b.highConfidenceCount - a.highConfidenceCount;
      }
      if (b.totalCount !== a.totalCount) return b.totalCount - a.totalCount;
      return a.key.localeCompare(b.key);
    })
    .slice(0, maxRows);

  const cells: HeatmapCell[] = [];
  let maxCellCount = 0;

  for (const rowMeta of sortedRowMetas) {
    const colMap = bucketMap.get(rowMeta.key);
    for (const colKey of columns) {
      const itemsMap = colMap?.get(colKey);
      const indicators = itemsMap
        ? Array.from(itemsMap.values()).sort((a, b) => b.confidenceScore - a.confidenceScore)
        : [];
      const count = indicators.length;
      if (count > maxCellCount) maxCellCount = count;
      const maxScore = count > 0 ? Math.max(...indicators.map((i) => i.confidenceScore)) : 0;
      const avgScore =
        count > 0
          ? Math.round(indicators.reduce((acc, i) => acc + i.confidenceScore, 0) / count)
          : 0;
      cells.push({
        rowKey: rowMeta.key,
        colKey,
        count,
        maxScore,
        avgScore,
        indicators,
      });
    }
  }

  return {
    dimension,
    thresholdFilter,
    columns,
    rows: sortedRowMetas,
    cells,
    maxCellCount,
    totalHighConfidenceIocs,
    totalEvaluatedIocs,
  };
}
