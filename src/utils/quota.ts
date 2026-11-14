export interface ProviderQuotaEntry {
  used: number;
  limit: number;
  exhausted: boolean;
  exhaustedReason?: string | null;
  upstreamRemaining?: number | null;
  lastUpdatedAt: string | null;
}

export interface DailyQuotaLedger {
  date: string; // YYYY-MM-DD (UTC)
  usage: Record<string, ProviderQuotaEntry>;
}

export interface ProviderQuotaSnapshot {
  providerId: string;
  name: string;
  used: number;
  limit: number;
  remaining: number;
  percentUsed: number;
  exhausted: boolean;
  exhaustedReason: string | null;
  upstreamRemaining: number | null;
  lastUpdatedAt: string | null;
}

export const DEFAULT_DAILY_QUOTA_LIMITS: Record<string, number> = {
  virustotal: 500,
  abuseipdb: 1000,
  alienvault: 10000,
  shodan: 100,
  threatfox: 2000,
  urlscan: 1000,
};

export function getUtcDateKey(d: Date = new Date()): string {
  return d.toISOString().slice(0, 10);
}

export function normalizeQuotaLedger(
  raw: unknown,
  limits: Record<string, number>,
  now: Date = new Date(),
): DailyQuotaLedger {
  const today = getUtcDateKey(now);
  const candidate = (raw && typeof raw === 'object' ? raw : {}) as Partial<DailyQuotaLedger>;
  const isSameDay = candidate.date === today;
  const rawUsage = isSameDay && candidate.usage && typeof candidate.usage === 'object' ? candidate.usage : {};

  const usage: Record<string, ProviderQuotaEntry> = {};
  for (const [providerId, limitVal] of Object.entries(limits)) {
    const safeLimit = Math.max(1, Math.round(Number(limitVal) || 500));
    const existing = (rawUsage as Record<string, Partial<ProviderQuotaEntry>>)[providerId];
    const used = Math.max(0, Math.round(Number(existing?.used ?? 0) || 0));
    const exhausted = Boolean(existing?.exhausted) || used >= safeLimit;
    usage[providerId] = {
      used,
      limit: safeLimit,
      exhausted,
      exhaustedReason:
        exhausted
          ? existing?.exhaustedReason || `Daily quota reached (${used}/${safeLimit})`
          : null,
      upstreamRemaining:
        typeof existing?.upstreamRemaining === 'number' && Number.isFinite(existing.upstreamRemaining)
          ? Math.max(0, Math.round(existing.upstreamRemaining))
          : null,
      lastUpdatedAt: typeof existing?.lastUpdatedAt === 'string' ? existing.lastUpdatedAt : null,
    };
  }

  return { date: today, usage };
}

export function recordQuotaConsumption(
  ledger: DailyQuotaLedger,
  providerId: string,
  limit: number,
  options: {
    httpStatus?: number;
    upstreamRemainingHeader?: number | null;
    upstreamLimitHeader?: number | null;
    now?: Date;
  } = {},
): DailyQuotaLedger {
  const now = options.now ?? new Date();
  const today = getUtcDateKey(now);
  const currentLedger =
    ledger.date === today ? ledger : normalizeQuotaLedger(null, { [providerId]: limit }, now);

  const safeLimit =
    typeof options.upstreamLimitHeader === 'number' && options.upstreamLimitHeader > 0
      ? Math.round(options.upstreamLimitHeader)
      : Math.max(1, Math.round(limit));

  const prev = currentLedger.usage[providerId] ?? {
    used: 0,
    limit: safeLimit,
    exhausted: false,
    exhaustedReason: null,
    upstreamRemaining: null,
    lastUpdatedAt: null,
  };

  const nextUsed = prev.used + 1;
  const hit429 = options.httpStatus === 429;
  const upstreamRemaining =
    typeof options.upstreamRemainingHeader === 'number' && Number.isFinite(options.upstreamRemainingHeader)
      ? Math.max(0, Math.round(options.upstreamRemainingHeader))
      : prev.upstreamRemaining;

  const exhausted = hit429 || nextUsed >= safeLimit || upstreamRemaining === 0;
  const exhaustedReason = hit429
    ? 'HTTP 429 daily/rate limit returned by provider'
    : nextUsed >= safeLimit
      ? `Daily quota limit reached (${nextUsed}/${safeLimit})`
      : upstreamRemaining === 0
        ? 'Upstream API reported 0 remaining quota'
        : null;

  return {
    date: today,
    usage: {
      ...currentLedger.usage,
      [providerId]: {
        used: nextUsed,
        limit: safeLimit,
        exhausted,
        exhaustedReason,
        upstreamRemaining: hit429 ? 0 : upstreamRemaining ?? null,
        lastUpdatedAt: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
      },
    },
  };
}

export function isProviderQuotaExhausted(ledger: DailyQuotaLedger, providerId: string, limit: number): boolean {
  const entry = ledger.usage[providerId];
  if (!entry) return false;
  return entry.exhausted || entry.used >= Math.max(1, limit);
}

export function partitionSourcesByQuota(
  selectedSources: string[],
  ledger: DailyQuotaLedger,
  limits: Record<string, number>,
): {
  availableSources: string[];
  exhaustedSources: { providerId: string; used: number; limit: number; reason: string }[];
} {
  const availableSources: string[] = [];
  const exhaustedSources: { providerId: string; used: number; limit: number; reason: string }[] = [];

  for (const id of selectedSources) {
    const limit = Math.max(1, Math.round(limits[id] ?? DEFAULT_DAILY_QUOTA_LIMITS[id] ?? 500));
    const entry = ledger.usage[id];
    const used = entry?.used ?? 0;
    const exhausted = Boolean(entry?.exhausted) || used >= limit;

    if (exhausted) {
      exhaustedSources.push({
        providerId: id,
        used,
        limit,
        reason: entry?.exhaustedReason || `Daily quota reached (${used}/${limit})`,
      });
    } else {
      availableSources.push(id);
    }
  }

  return { availableSources, exhaustedSources };
}

export function buildQuotaSnapshots(
  ledger: DailyQuotaLedger,
  providers: { id: string; name: string; limit: number }[],
): ProviderQuotaSnapshot[] {
  return providers.map((p) => {
    const limit = Math.max(1, Math.round(p.limit));
    const entry = ledger.usage[p.id];
    const used = entry?.used ?? 0;
    const exhausted = Boolean(entry?.exhausted) || used >= limit;
    const computedRemaining = Math.max(0, limit - used);
    const remaining =
      exhausted
        ? 0
        : entry?.upstreamRemaining !== null && entry?.upstreamRemaining !== undefined
          ? Math.min(computedRemaining, entry.upstreamRemaining)
          : computedRemaining;
    const percentUsed = Math.min(100, Math.round((used / limit) * 1000) / 10);

    return {
      providerId: p.id,
      name: p.name,
      used,
      limit,
      remaining,
      percentUsed,
      exhausted,
      exhaustedReason: exhausted ? entry?.exhaustedReason || `Daily quota reached (${used}/${limit})` : null,
      upstreamRemaining: entry?.upstreamRemaining ?? null,
      lastUpdatedAt: entry?.lastUpdatedAt ?? null,
    };
  });
}

export function getQuotaWarningProviders(
  snapshots: ProviderQuotaSnapshot[],
  thresholdPercent = 80,
  relevantProviderIds?: Iterable<string>,
): ProviderQuotaSnapshot[] {
  const relevantSet = relevantProviderIds ? new Set(relevantProviderIds) : null;
  return snapshots.filter((p) => {
    if (p.exhausted) return false;
    if (relevantSet && !relevantSet.has(p.providerId) && p.used === 0) {
      return false;
    }
    return p.percentUsed > thresholdPercent;
  });
}

