export type IndicatorType = 'ip' | 'domain' | 'hash';
export type SourceId = 'virustotal' | 'abuseipdb' | 'alienvault';
export type SourceSelection = SourceId | 'all';
export type LookupStatus = 'ok' | 'not_found' | 'unsupported' | 'error';
export type Verdict = 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown';

export interface LookupResult {
  source: string;
  sourceId: string;
  indicator: string;
  originalToken: string;
  type: IndicatorType;
  status: LookupStatus;
  verdict: Verdict;
  score: string;
  summary: string;
  details: Record<string, string | number | boolean | null>;
  link: string;
}

export interface ParsedIndicator {
  original: string;
  cleaned: string;
  type: IndicatorType | null;
}

const HASH_RE = /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
// Covers standard compressed and full IPv6 literals
const IPV6_RE = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^((?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::((?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?$/;

export function cleanIndicator(value: string): string {
  let v = value.trim().replace(/^['"<>]+|['"<>]+$/g, '');
  v = v.replace(/\[\.\]|\(\.\)|\[dot\]|\(dot\)/gi, '.');
  v = v.replace(/\[:\]|\(:|:\)/g, ':');
  v = v.replace(/\[:\/\/\]/g, '://');
  v = v.replace(/^hxxps?/i, (m) => (m.toLowerCase().endsWith('s') ? 'https' : 'http'));

  if (v.includes('://')) {
    try {
      const parsed = new URL(v);
      if (parsed.hostname) {
        v = parsed.hostname;
      }
    } catch {
      // keep best-effort stripped value
    }
  } else if (v.split(':').length === 2 && !v.startsWith('[')) {
    const [hostPart, portPart] = v.split(':');
    if (/^\d+/.test(portPart.split('/')[0])) {
      v = hostPart;
    }
  } else if (v.includes('/')) {
    try {
      const parsed = new URL(`http://${v}`);
      if (parsed.hostname) {
        v = parsed.hostname;
      }
    } catch {
      // ignore
    }
  }

  v = v.replace(/^\[+|\]+$/g, '');
  if (HASH_RE.test(v) || DOMAIN_RE.test(v)) {
    v = v.toLowerCase();
  }
  return v;
}

export function detectIndicatorType(value: string): IndicatorType | null {
  if (!value) return null;
  if (IPV4_RE.test(value)) return 'ip';
  if (value.includes(':') && IPV6_RE.test(value)) return 'ip';
  if (HASH_RE.test(value)) return 'hash';
  if (DOMAIN_RE.test(value)) return 'domain';
  return null;
}

export function parseIndicators(raw: string): ParsedIndicator[] {
  const tokens = raw
    .split(/[,\s;]+/)
    .map((t) => t.trim())
    .filter(Boolean);

  const seen = new Set<string>();
  const parsed: ParsedIndicator[] = [];
  for (const token of tokens) {
    const cleaned = cleanIndicator(token);
    const type = detectIndicatorType(cleaned);
    const dedupKey = `${type ?? 'invalid'}:${cleaned}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);
    parsed.push({ original: token, cleaned, type });
  }
  return parsed;
}

export function computeVirusTotalVerdict(malicious: number, suspicious: number, total: number): Verdict {
  if (malicious >= 5) return 'Malicious';
  if (malicious > 0 || suspicious > 0) return 'Suspicious';
  if (total > 0) return 'Clean';
  return 'Unknown';
}

export function computeAbuseIpdbVerdict(confidenceScore: number): Verdict {
  if (confidenceScore >= 75) return 'Malicious';
  if (confidenceScore >= 25) return 'Suspicious';
  return 'Clean';
}

export function computeOtxVerdict(pulses: number): Verdict {
  if (pulses >= 5) return 'Malicious';
  if (pulses >= 1) return 'Suspicious';
  return 'Unknown';
}

export function escapeCsvCell(value: string): string {
  if (/[",\n\r]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export function serializeResultsToCsv(results: LookupResult[], timestampIso: string): string {
  const headers = [
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
  for (const r of results) {
    const row = [
      timestampIso,
      r.source,
      r.indicator,
      r.type,
      r.status,
      r.verdict,
      r.score,
      r.summary,
      JSON.stringify(r.details),
      r.link,
    ].map((cell) => escapeCsvCell(String(cell ?? '')));
    lines.push(row.join(','));
  }
  return '\ufeff' + lines.join('\r\n') + '\r\n';
}
