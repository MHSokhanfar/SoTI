import type { LookupResult } from './indicators';

export type ConfidenceRiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown';

export interface ProviderRiskContribution {
  sourceId: string;
  source: string;
  status: LookupResult['status'];
  verdict: LookupResult['verdict'];
  normalizedScore: number;
  baseWeight: number;
  effectiveWeight: number;
  sharePercent: number;
  rationale: string;
}

export interface IocConfidenceSummary {
  indicator: string;
  confidenceScore: number | null;
  riskLevel: ConfidenceRiskLevel;
  activeProviderCount: number;
  totalResultCount: number;
  breakdown: ProviderRiskContribution[];
  summaryText: string;
  explanation: string;
}

export const PROVIDER_BASE_WEIGHTS: Readonly<Record<string, number>> = {
  virustotal: 0.35,
  abuseipdb: 0.25,
  threatfox: 0.2,
  urlscan: 0.18,
  alienvault: 0.15,
  shodan: 0.12,
};

export const DEFAULT_PROVIDER_WEIGHT = 0.15;

export function getProviderBaseWeight(sourceId: string): number {
  const key = (sourceId || '').trim().toLowerCase();
  if (key in PROVIDER_BASE_WEIGHTS) {
    return PROVIDER_BASE_WEIGHTS[key];
  }
  if (key.includes('virustotal')) return PROVIDER_BASE_WEIGHTS.virustotal;
  if (key.includes('abuseipdb')) return PROVIDER_BASE_WEIGHTS.abuseipdb;
  if (key.includes('threatfox')) return PROVIDER_BASE_WEIGHTS.threatfox;
  if (key.includes('urlscan')) return PROVIDER_BASE_WEIGHTS.urlscan;
  if (key.includes('alienvault') || key.includes('otx')) return PROVIDER_BASE_WEIGHTS.alienvault;
  if (key.includes('shodan')) return PROVIDER_BASE_WEIGHTS.shodan;
  return DEFAULT_PROVIDER_WEIGHT;
}

function clampScore(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

function parseFirstIntDetail(
  details: LookupResult['details'],
  keys: string[],
): number | null {
  for (const key of keys) {
    const val = details?.[key];
    if (typeof val === 'number' && Number.isFinite(val)) {
      return val;
    }
    if (typeof val === 'string') {
      const m = val.match(/(\d+)/);
      if (m) return Number.parseInt(m[1], 10);
    }
  }
  return null;
}

export function normalizeProviderRiskScore(
  result: LookupResult,
): { score: number; weightMultiplier: number; rationale: string } | null {
  if (result.status === 'unsupported' || result.status === 'error') {
    return null;
  }

  const sourceId = (result.sourceId || '').trim().toLowerCase();
  const scoreStr = (result.score || '').trim();
  const details = result.details || {};

  // Negative lookup ("not_found"): indicator checked cleanly without threat records.
  // Contributes 0 risk with a 0.5x confidence multiplier so unindexed hashes/IOCs in
  // specialty feeds do not mask confirmed hits from multi-engine scanners.
  if (result.status === 'not_found') {
    return {
      score: 0,
      weightMultiplier: 0.5,
      rationale: 'No threat matches observed (not found)',
    };
  }

  // 1. VirusTotal: multi-engine detection ratio
  if (sourceId === 'virustotal' || sourceId.includes('virustotal')) {
    let malicious = parseFirstIntDetail(details, ['Malicious']);
    let suspicious = parseFirstIntDetail(details, ['Suspicious']) ?? 0;
    let total = parseFirstIntDetail(details, ['Total Engines', 'Total']);

    const ratioMatch = scoreStr.match(/^(\d+)\s*\/\s*(\d+)$/);
    if (ratioMatch) {
      if (malicious === null) malicious = Number.parseInt(ratioMatch[1], 10);
      if (total === null) total = Number.parseInt(ratioMatch[2], 10);
    }

    if (malicious !== null && (total === null || total > 0)) {
      if (malicious === 0) {
        if (suspicious > 0 || result.verdict === 'Suspicious') {
          const s = clampScore(25 + Math.min(20, suspicious * 5));
          return {
            score: s,
            weightMultiplier: 1,
            rationale: `${suspicious || 1} suspicious engine detection(s)`,
          };
        }
        return {
          score: 0,
          weightMultiplier: 1,
          rationale: `0/${total ?? '?'} malicious detections`,
        };
      }
      const ratioPct = total && total > 0 ? (malicious / total) * 100 : 0;
      const calibrated =
        malicious >= 5
          ? 65 + Math.min(35, (malicious - 5) * 1.2)
          : 25 + malicious * 8;
      const score = clampScore(Math.max(ratioPct, calibrated));
      return {
        score,
        weightMultiplier: 1,
        rationale: `${malicious}/${total ?? '?'} engines flagged malicious`,
      };
    }
  }

  // 2. AbuseIPDB: direct abuse confidence percentage
  if (sourceId === 'abuseipdb' || sourceId.includes('abuseipdb')) {
    const pctMatch = scoreStr.match(/^(\d+(?:\.\d+)?)\s*%$/);
    if (pctMatch) {
      const score = clampScore(Number.parseFloat(pctMatch[1]));
      return {
        score,
        weightMultiplier: 1,
        rationale: `${score}% abuse confidence score`,
      };
    }
    const detailConf = parseFirstIntDetail(details, ['Abuse Confidence', 'Abuse Confidence Score']);
    if (detailConf !== null) {
      const score = clampScore(detailConf);
      return {
        score,
        weightMultiplier: 1,
        rationale: `${score}% abuse confidence score`,
      };
    }
  }

  // 3. ThreatFox (abuse.ch): IOC match confidence percentage
  if (sourceId === 'threatfox' || sourceId.includes('threatfox')) {
    const confDetail = parseFirstIntDetail(details, ['Confidence']);
    const pctMatch = scoreStr.match(/(\d+(?:\.\d+)?)\s*%/);
    const parsedConf = confDetail ?? (pctMatch ? Number.parseFloat(pctMatch[1]) : null);
    if (parsedConf !== null) {
      const score = clampScore(parsedConf);
      return {
        score,
        weightMultiplier: 1,
        rationale: `${score}% ThreatFox IOC confidence`,
      };
    }
  }

  // 4. urlscan.io: verdict score + malicious historical scan count
  if (sourceId === 'urlscan' || sourceId.includes('urlscan')) {
    let verdictScore: number | null = null;
    const rawVerdictDetail = details['Verdict Score'];
    if (typeof rawVerdictDetail === 'string') {
      const vm = rawVerdictDetail.match(/(\d+(?:\.\d+)?)\s*(?:\/\s*100)?/);
      if (vm) verdictScore = Number.parseFloat(vm[1]);
    } else if (typeof rawVerdictDetail === 'number' && Number.isFinite(rawVerdictDetail)) {
      verdictScore = rawVerdictDetail;
    }

    let maliciousScans = parseFirstIntDetail(details, ['Flagged Malicious']);
    let totalScans = parseFirstIntDetail(details, ['Total Scans']);
    const scanMatch = scoreStr.match(/^(\d+)\s*\/\s*(\d+)\s*scans?$/i);
    if (scanMatch) {
      if (maliciousScans === null) maliciousScans = Number.parseInt(scanMatch[1], 10);
      if (totalScans === null) totalScans = Number.parseInt(scanMatch[2], 10);
    }

    if (maliciousScans !== null && maliciousScans > 0) {
      const ratioPct = totalScans && totalScans > 0 ? (maliciousScans / totalScans) * 100 : 0;
      const calibrated = Math.min(100, 65 + maliciousScans * 8);
      const score = clampScore(Math.max(verdictScore ?? 0, ratioPct, calibrated));
      return {
        score,
        weightMultiplier: 1,
        rationale: `${maliciousScans}/${totalScans ?? '?'} malicious scans`,
      };
    }

    if (verdictScore !== null) {
      const score = clampScore(verdictScore);
      return {
        score,
        weightMultiplier: 1,
        rationale: `urlscan verdict score ${score}/100`,
      };
    }
  }

  // 5. AlienVault OTX: active threat intelligence pulses
  if (sourceId === 'alienvault' || sourceId.includes('alienvault') || sourceId.includes('otx')) {
    const pulseMatch = scoreStr.match(/^(\d+)\s*pulses?$/i);
    const pulses = pulseMatch
      ? Number.parseInt(pulseMatch[1], 10)
      : parseFirstIntDetail(details, ['Pulses']);
    if (pulses !== null) {
      const score =
        pulses === 0
          ? 0
          : pulses < 5
            ? clampScore(20 + pulses * 10)
            : clampScore(65 + Math.min(35, (pulses - 5) * 1.5));
      return {
        score,
        weightMultiplier: 1,
        rationale: `${pulses} OTX threat pulse${pulses === 1 ? '' : 's'}`,
      };
    }
  }

  // 6. Shodan: exposed services and known CVEs
  if (sourceId === 'shodan' || sourceId.includes('shodan')) {
    const cveMatch = scoreStr.match(/(\d+)\s*CVEs?/i);
    const portMatch = scoreStr.match(/(\d+)\s*ports?/i);
    const cves = cveMatch ? Number.parseInt(cveMatch[1], 10) : parseFirstIntDetail(details, ['CVEs']);
    const ports = portMatch ? Number.parseInt(portMatch[1], 10) : null;

    if (cves !== null || ports !== null) {
      const cveCount = cves ?? 0;
      const portCount = ports ?? 0;
      let raw = 0;
      if (cveCount >= 5) {
        raw = 90;
      } else if (cveCount >= 1) {
        raw = 55 + Math.min(30, cveCount * 7);
      } else if (portCount >= 8) {
        raw = 35;
      } else if (portCount > 0) {
        raw = 15;
      }
      if (result.verdict === 'Malicious') raw = Math.max(raw, 80);
      else if (result.verdict === 'Suspicious') raw = Math.max(raw, 45);
      const score = clampScore(raw);
      return {
        score,
        weightMultiplier: 1,
        rationale: `${portCount} open ports, ${cveCount} CVEs`,
      };
    }
  }

  // 7. Generic custom provider parsing: percentage -> ratio -> verdict fallback
  const genericPct = scoreStr.match(/(\d+(?:\.\d+)?)\s*%/);
  if (genericPct) {
    const score = clampScore(Number.parseFloat(genericPct[1]));
    return {
      score,
      weightMultiplier: 1,
      rationale: `${score}% provider score`,
    };
  }

  const genericRatio = scoreStr.match(/^(\d+)\s*\/\s*(\d+)/);
  if (genericRatio) {
    const num = Number.parseInt(genericRatio[1], 10);
    const den = Number.parseInt(genericRatio[2], 10);
    if (den > 0) {
      const score = clampScore((num / den) * 100);
      return {
        score,
        weightMultiplier: 1,
        rationale: `Ratio ${num}/${den}`,
      };
    }
  }

  if (result.verdict === 'Malicious') {
    return { score: 85, weightMultiplier: 1, rationale: 'Malicious verdict' };
  }
  if (result.verdict === 'Suspicious') {
    return { score: 50, weightMultiplier: 1, rationale: 'Suspicious verdict' };
  }
  if (result.verdict === 'Clean') {
    return { score: 0, weightMultiplier: 1, rationale: 'Clean verdict' };
  }
  return { score: 15, weightMultiplier: 0.6, rationale: 'Unknown verdict' };
}

export function classifyConfidenceRiskLevel(score: number | null): ConfidenceRiskLevel {
  if (score === null || !Number.isFinite(score)) return 'Unknown';
  if (score >= 75) return 'Critical';
  if (score >= 50) return 'High';
  if (score >= 25) return 'Medium';
  return 'Low';
}

export function computeIocConfidenceScore(
  indicator: string,
  resultsForIndicator: LookupResult[],
): IocConfidenceSummary {
  // Deduplicate by sourceId (keeping the latest result if repeated)
  const bySource = new Map<string, LookupResult>();
  for (const r of resultsForIndicator) {
    const key = (r.sourceId || r.source || '').trim().toLowerCase();
    if (!key) continue;
    bySource.set(key, r);
  }

  const rawEntries: {
    sourceId: string;
    source: string;
    status: LookupResult['status'];
    verdict: LookupResult['verdict'];
    normalizedScore: number;
    baseWeight: number;
    effectiveWeight: number;
    rationale: string;
  }[] = [];

  for (const r of bySource.values()) {
    const normalized = normalizeProviderRiskScore(r);
    if (!normalized) continue;
    const baseWeight = getProviderBaseWeight(r.sourceId || r.source);
    const effectiveWeight = baseWeight * normalized.weightMultiplier;
    rawEntries.push({
      sourceId: r.sourceId,
      source: r.source,
      status: r.status,
      verdict: r.verdict,
      normalizedScore: normalized.score,
      baseWeight,
      effectiveWeight,
      rationale: normalized.rationale,
    });
  }

  if (rawEntries.length === 0) {
    return {
      indicator,
      confidenceScore: null,
      riskLevel: 'Unknown',
      activeProviderCount: 0,
      totalResultCount: resultsForIndicator.length,
      breakdown: [],
      summaryText: 'No active provider scores available',
      explanation: 'All selected providers returned unsupported or error statuses for this indicator.',
    };
  }

  let weightedSum = 0;
  let totalWeight = 0;
  for (const item of rawEntries) {
    weightedSum += item.normalizedScore * item.effectiveWeight;
    totalWeight += item.effectiveWeight;
  }

  const confidenceScore = totalWeight > 0 ? clampScore(weightedSum / totalWeight) : null;
  const riskLevel = classifyConfidenceRiskLevel(confidenceScore);

  const breakdown: ProviderRiskContribution[] = rawEntries
    .map((item) => ({
      ...item,
      sharePercent: totalWeight > 0 ? Math.round((item.effectiveWeight / totalWeight) * 100) : 0,
    }))
    .sort((a, b) => b.sharePercent - a.sharePercent);

  const explanation = breakdown
    .map((b) => `${b.source}: ${b.normalizedScore}/100 (${b.sharePercent}% wt)`)
    .join(' · ');

  const summaryText =
    confidenceScore !== null
      ? `${confidenceScore}/100 · ${riskLevel} (${breakdown.length} active provider${breakdown.length === 1 ? '' : 's'})`
      : 'Confidence unavailable';

  return {
    indicator,
    confidenceScore,
    riskLevel,
    activeProviderCount: breakdown.length,
    totalResultCount: resultsForIndicator.length,
    breakdown,
    summaryText,
    explanation,
  };
}

export function computeAllIocConfidenceScores(
  results: LookupResult[],
): Map<string, IocConfidenceSummary> {
  const grouped = new Map<string, { displayIndicator: string; items: LookupResult[] }>();
  for (const r of results) {
    const key = r.indicator.trim().toLowerCase();
    if (!key) continue;
    const existing = grouped.get(key);
    if (existing) {
      existing.items.push(r);
    } else {
      grouped.set(key, { displayIndicator: r.indicator, items: [r] });
    }
  }

  const map = new Map<string, IocConfidenceSummary>();
  for (const [key, group] of grouped.entries()) {
    const summary = computeIocConfidenceScore(group.displayIndicator, group.items);
    map.set(key, summary);
    // Also index by exact casing if different for convenience
    if (group.displayIndicator !== key) {
      map.set(group.displayIndicator, summary);
    }
  }
  return map;
}

export const RISK_THRESHOLD_STORAGE_KEY = 'soti_investigate_risk_threshold_v1';

export function normalizeRiskThreshold(value: unknown): number {
  const num = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(num)) return 0;
  return Math.max(0, Math.min(100, Math.round(num)));
}

export function passesRiskThreshold(
  confidenceScore: number | null | undefined,
  minThreshold: number,
): boolean {
  const threshold = normalizeRiskThreshold(minThreshold);
  if (threshold <= 0) return true;
  return (
    typeof confidenceScore === 'number' &&
    Number.isFinite(confidenceScore) &&
    confidenceScore >= threshold
  );
}

export function loadRiskThreshold(
  storage?: { getItem: (key: string) => string | null } | null,
): number {
  if (!storage) return 0;
  try {
    const raw = storage.getItem(RISK_THRESHOLD_STORAGE_KEY);
    if (!raw) return 0;
    return normalizeRiskThreshold(Number(raw));
  } catch {
    return 0;
  }
}

export function saveRiskThreshold(
  storage: { setItem: (key: string, value: string) => void } | null | undefined,
  threshold: number,
): void {
  if (!storage) return;
  try {
    storage.setItem(RISK_THRESHOLD_STORAGE_KEY, String(normalizeRiskThreshold(threshold)));
  } catch {
    // ignore storage errors
  }
}
