export const SHARE_TTL_OPTIONS = [
  { hours: 1, label: '1 hour' },
  { hours: 24, label: '24 hours' },
  { hours: 72, label: '3 days' },
  { hours: 168, label: '7 days' },
] as const;

export interface SharedReportIndicatorSummary {
  indicator: string;
  type: string;
  confidenceScore: number | null;
  verdictSummary: string;
}

export interface SharedReportSnapshot {
  token: string;
  createdAt: string;
  expiresAt: string;
  ttlHours: number;
  reportName: string | null;
  searchQuery: string;
  verdictFilter: string;
  quickStats: {
    totalThreatsAnalyzed: number;
    uniqueIndicatorsCount: number;
    maliciousPercentage: number;
    maliciousCount: number;
    evaluatedVerdictsCount: number;
  };
  totals: {
    runs: number;
    malicious: number;
    suspicious: number;
    clean: number;
    unknown: number;
  };
  topIndicators: SharedReportIndicatorSummary[];
  executiveSummary?: string | null;
}

export function normalizeShareTtlHours(raw: unknown): number {
  const num = Number(raw);
  if (!Number.isFinite(num)) return 24;
  const rounded = Math.round(num);
  if (rounded < 1) return 1;
  if (rounded > 168) return 168;
  return rounded;
}

export function isShareSnapshotExpired(
  expiresAt: string,
  now: Date = new Date(),
): boolean {
  const ts = Date.parse(expiresAt);
  if (!Number.isFinite(ts)) return true;
  return now.getTime() >= ts;
}

export function parseShareTokenFromUrl(
  search: string = '',
  hash: string = '',
): string | null {
  try {
    if (search) {
      const params = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search);
      const token = (params.get('share') || '').trim();
      if (/^[A-Za-z0-9_-]{8,64}$/.test(token)) {
        return token;
      }
    }
    if (hash) {
      const hashQueryIdx = hash.indexOf('share=');
      if (hashQueryIdx !== -1) {
        const sub = hash.slice(hashQueryIdx);
        const params = new URLSearchParams(sub);
        const token = (params.get('share') || '').trim();
        if (/^[A-Za-z0-9_-]{8,64}$/.test(token)) {
          return token;
        }
      }
    }
  } catch {
    return null;
  }
  return null;
}

export function buildShareReportMessage(
  snapshot: Pick<
    SharedReportSnapshot,
    | 'reportName'
    | 'expiresAt'
    | 'quickStats'
    | 'totals'
    | 'topIndicators'
    | 'verdictFilter'
    | 'executiveSummary'
  >,
  shareUrl: string,
): string {
  const lines: string[] = [
    `[SoTI Threat Intelligence Report]${snapshot.reportName ? ` ${snapshot.reportName}` : ''}`,
    `Summary: ${snapshot.quickStats.uniqueIndicatorsCount} unique IOCs across ${snapshot.totals.runs} run(s) · ${snapshot.totals.malicious} Malicious · ${snapshot.totals.suspicious} Suspicious · ${snapshot.totals.clean} Clean (${snapshot.quickStats.maliciousPercentage}% malicious rate)`,
  ];

  if (snapshot.verdictFilter && snapshot.verdictFilter !== 'All') {
    lines.push(`Active Filter: ${snapshot.verdictFilter}`);
  }

  if (snapshot.topIndicators.length > 0) {
    lines.push(
      'Top Indicators: ' +
        snapshot.topIndicators
          .slice(0, 5)
          .map((item) =>
            item.confidenceScore !== null
              ? `${item.indicator} (${item.confidenceScore}/100, ${item.verdictSummary})`
              : `${item.indicator} (${item.verdictSummary})`,
          )
          .join('; '),
    );
  }

  if (snapshot.executiveSummary && snapshot.executiveSummary.trim()) {
    const firstSentence = snapshot.executiveSummary.trim().replace(/\s+/g, ' ').slice(0, 220);
    lines.push(`AI Brief: ${firstSentence}${snapshot.executiveSummary.trim().length > 220 ? '...' : ''}`);
  }

  const expiryDisplay = Number.isFinite(Date.parse(snapshot.expiresAt))
    ? `${new Date(snapshot.expiresAt).toISOString().slice(0, 16).replace('T', ' ')} UTC`
    : snapshot.expiresAt;

  lines.push(`Temporary Report Link (expires ${expiryDisplay}): ${shareUrl}`);
  return lines.join('\n');
}
