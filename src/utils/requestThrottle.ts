export type GlobalThrottlePreset = 'off' | 'balanced' | 'conservative' | 'strict' | 'custom';

export interface GlobalThrottleConfig {
  enabled: boolean;
  minIntervalMs: number;
  preset: GlobalThrottlePreset;
}

export interface ThrottleSlotResult {
  waitMs: number;
  scheduledAtMs: number;
  minIntervalMs: number;
}

export interface GlobalThrottleStats {
  totalAcquired: number;
  pacedCount: number;
  totalWaitMs: number;
  lastDispatchedAtMs: number | null;
}

export interface GlobalApiThrottleTelemetry {
  enabled: boolean;
  minIntervalMs: number;
  requestsPaced: number;
  totalWaitMs: number;
}

export const GLOBAL_THROTTLE_STORAGE_KEY = 'soti_global_api_throttle_v1';
export const DEFAULT_THROTTLE_INTERVAL_MS = 200;
export const MAX_THROTTLE_INTERVAL_MS = 5000;

export const GLOBAL_THROTTLE_PRESETS: Array<{
  id: Exclude<GlobalThrottlePreset, 'custom'>;
  label: string;
  minIntervalMs: number;
  shortSpec: string;
}> = [
  { id: 'off', label: 'Off', minIntervalMs: 0, shortSpec: 'Unpaced' },
  { id: 'balanced', label: 'Balanced', minIntervalMs: 200, shortSpec: '5 req/s · 200ms' },
  { id: 'conservative', label: 'Safe', minIntervalMs: 500, shortSpec: '2 req/s · 500ms' },
  { id: 'strict', label: 'Strict', minIntervalMs: 1000, shortSpec: '1 req/s · 1000ms' },
];

export function clampThrottleIntervalMs(
  value: unknown,
  fallback = DEFAULT_THROTTLE_INTERVAL_MS,
): number {
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.max(0, Math.min(MAX_THROTTLE_INTERVAL_MS, Math.round(num)));
}

export function resolveThrottlePreset(minIntervalMs: number): GlobalThrottlePreset {
  const clamped = clampThrottleIntervalMs(minIntervalMs);
  if (clamped === 0) return 'off';
  const match = GLOBAL_THROTTLE_PRESETS.find((p) => p.minIntervalMs === clamped);
  return match ? match.id : 'custom';
}

export function createThrottleConfig(minIntervalMs: number): GlobalThrottleConfig {
  const clamped = clampThrottleIntervalMs(minIntervalMs);
  return {
    enabled: clamped > 0,
    minIntervalMs: clamped,
    preset: resolveThrottlePreset(clamped),
  };
}

export function normalizeGlobalThrottleConfig(raw: unknown): GlobalThrottleConfig {
  if (!raw || typeof raw !== 'object') {
    return createThrottleConfig(DEFAULT_THROTTLE_INTERVAL_MS);
  }
  const candidate = raw as { enabled?: unknown; minIntervalMs?: unknown; preset?: unknown };
  if (candidate.enabled === false || candidate.preset === 'off') {
    return createThrottleConfig(0);
  }
  const ms = clampThrottleIntervalMs(
    candidate.minIntervalMs !== undefined ? candidate.minIntervalMs : DEFAULT_THROTTLE_INTERVAL_MS,
    DEFAULT_THROTTLE_INTERVAL_MS,
  );
  return createThrottleConfig(ms);
}

export function loadGlobalThrottleConfig(
  storage?: Pick<Storage, 'getItem'> | null,
): GlobalThrottleConfig {
  if (!storage) return createThrottleConfig(DEFAULT_THROTTLE_INTERVAL_MS);
  try {
    const raw = storage.getItem(GLOBAL_THROTTLE_STORAGE_KEY);
    if (!raw) return createThrottleConfig(DEFAULT_THROTTLE_INTERVAL_MS);
    return normalizeGlobalThrottleConfig(JSON.parse(raw));
  } catch {
    return createThrottleConfig(DEFAULT_THROTTLE_INTERVAL_MS);
  }
}

export function saveGlobalThrottleConfig(
  storage: Pick<Storage, 'setItem'> | null | undefined,
  config: GlobalThrottleConfig,
): void {
  if (!storage) return;
  try {
    const normalized = normalizeGlobalThrottleConfig(config);
    storage.setItem(GLOBAL_THROTTLE_STORAGE_KEY, JSON.stringify(normalized));
  } catch {
    // ignore storage errors
  }
}

export function formatMaxRps(minIntervalMs: number): string {
  const clamped = clampThrottleIntervalMs(minIntervalMs, 0);
  if (clamped <= 0) return 'Unlimited';
  const rps = 1000 / clamped;
  return rps >= 10 ? `${Math.round(rps)} req/s` : `${rps.toFixed(1)} req/s`;
}

export function describeThrottleConfig(config: GlobalThrottleConfig): string {
  const normalized = normalizeGlobalThrottleConfig(config);
  if (!normalized.enabled || normalized.minIntervalMs <= 0) {
    return 'Throttling off — immediate bursts (higher 429 risk on large batches)';
  }
  return `Global ceiling: max ${formatMaxRps(normalized.minIntervalMs)} (${normalized.minIntervalMs}ms spacing across lookups)`;
}

export function chunkLookupIndicators<T>(items: readonly T[], maxChunkSize = 25): T[][] {
  const safeSize = Math.max(1, Math.floor(maxChunkSize));
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += safeSize) {
    chunks.push(items.slice(i, i + safeSize));
  }
  return chunks;
}

export class GlobalApiRequestThrottle {
  private readonly defaultIntervalMs: number;
  private readonly nowFn: () => number;
  private readonly sleepFn: (ms: number) => Promise<void>;
  private tail: Promise<void> = Promise.resolve();
  private nextAvailableAtMs = 0;
  private totalAcquired = 0;
  private pacedCount = 0;
  private totalWaitMs = 0;
  private lastDispatchedAtMs: number | null = null;

  constructor(options?: {
    defaultIntervalMs?: number;
    nowFn?: () => number;
    sleepFn?: (ms: number) => Promise<void>;
  }) {
    this.defaultIntervalMs = clampThrottleIntervalMs(
      options?.defaultIntervalMs ?? DEFAULT_THROTTLE_INTERVAL_MS,
      DEFAULT_THROTTLE_INTERVAL_MS,
    );
    this.nowFn = options?.nowFn ?? (() => Date.now());
    this.sleepFn =
      options?.sleepFn ??
      ((ms: number) =>
        new Promise((resolve) => {
          setTimeout(resolve, ms);
        }));
  }

  acquire(minIntervalMsOverride?: number): Promise<ThrottleSlotResult> {
    const intervalMs =
      minIntervalMsOverride !== undefined
        ? clampThrottleIntervalMs(minIntervalMsOverride, this.defaultIntervalMs)
        : this.defaultIntervalMs;

    const task = this.tail.then(async (): Promise<ThrottleSlotResult> => {
      const now = this.nowFn();
      this.totalAcquired += 1;

      if (intervalMs <= 0) {
        this.lastDispatchedAtMs = now;
        return { waitMs: 0, scheduledAtMs: now, minIntervalMs: 0 };
      }

      const scheduledAtMs = Math.max(now, this.nextAvailableAtMs);
      const waitMs = Math.max(0, scheduledAtMs - now);
      this.nextAvailableAtMs = scheduledAtMs + intervalMs;

      if (waitMs > 0) {
        this.pacedCount += 1;
        this.totalWaitMs += waitMs;
        await this.sleepFn(waitMs);
      }

      this.lastDispatchedAtMs = this.nowFn();
      return { waitMs, scheduledAtMs, minIntervalMs: intervalMs };
    });

    // Keep serial reservation mutex intact even if a downstream consumer rejects
    this.tail = task.then(
      () => undefined,
      () => undefined,
    );
    return task;
  }

  async run<T>(
    fn: () => Promise<T>,
    minIntervalMsOverride?: number,
  ): Promise<{ result: T; slot: ThrottleSlotResult }> {
    const slot = await this.acquire(minIntervalMsOverride);
    const result = await fn();
    return { result, slot };
  }

  getStats(): GlobalThrottleStats {
    return {
      totalAcquired: this.totalAcquired,
      pacedCount: this.pacedCount,
      totalWaitMs: this.totalWaitMs,
      lastDispatchedAtMs: this.lastDispatchedAtMs,
    };
  }

  reset(): void {
    this.tail = Promise.resolve();
    this.nextAvailableAtMs = 0;
    this.totalAcquired = 0;
    this.pacedCount = 0;
    this.totalWaitMs = 0;
    this.lastDispatchedAtMs = null;
  }
}
