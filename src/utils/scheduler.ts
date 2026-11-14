import { parseIndicators, type IndicatorType, type SourceId, type SourceSelection } from './indicators';

export type ScheduleStatus = 'idle' | 'success' | 'partial' | 'error';

export interface ScheduledJob {
  id: string;
  name: string;
  indicators: string[];
  source: SourceSelection;
  sources: SourceId[];
  intervalMinutes: number;
  enabled: boolean;
  mode: 'live' | 'sample';
  createdAt: string;
  updatedAt: string;
  lastRunAt: string | null;
  nextRunAt: string | null;
  lastStatus: ScheduleStatus;
  lastReportFile: string | null;
  lastSummary: string | null;
  runCount: number;
}

export interface ScheduleSummary {
  total: number;
  active: number;
  paused: number;
  dueNow: number;
  totalRuns: number;
}

export const MIN_SCHEDULE_INTERVAL_MINUTES = 5;
export const MAX_SCHEDULE_INTERVAL_MINUTES = 43_200; // 30 days

export const SCHEDULE_INTERVAL_PRESETS: { label: string; minutes: number }[] = [
  { label: 'Every 15 minutes', minutes: 15 },
  { label: 'Hourly (60 min)', minutes: 60 },
  { label: 'Every 6 hours', minutes: 360 },
  { label: 'Daily (24 hours)', minutes: 1440 },
  { label: 'Weekly (7 days)', minutes: 10080 },
];

export function computeNextRunIso(from: Date, intervalMinutes: number): string {
  const next = new Date(from.getTime() + intervalMinutes * 60_000);
  return next.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function isScheduleDue(job: Pick<ScheduledJob, 'enabled' | 'nextRunAt'>, now: Date = new Date()): boolean {
  if (!job.enabled) return false;
  if (!job.nextRunAt) return true;
  const parsed = Date.parse(job.nextRunAt);
  if (Number.isNaN(parsed)) return true;
  return parsed <= now.getTime();
}

export function formatIntervalLabel(intervalMinutes: number): string {
  if (intervalMinutes % 10080 === 0) {
    const weeks = intervalMinutes / 10080;
    return weeks === 1 ? 'Weekly' : `Every ${weeks} weeks`;
  }
  if (intervalMinutes % 1440 === 0) {
    const days = intervalMinutes / 1440;
    return days === 1 ? 'Daily' : `Every ${days} days`;
  }
  if (intervalMinutes >= 60 && intervalMinutes % 60 === 0) {
    const hours = intervalMinutes / 60;
    return hours === 1 ? 'Hourly' : `Every ${hours}h`;
  }
  return `Every ${intervalMinutes} min`;
}

export function formatRelativeScheduleTime(iso: string | null, now: Date = new Date()): string {
  if (!iso) return 'Not scheduled';
  const targetMs = Date.parse(iso);
  if (Number.isNaN(targetMs)) return 'Invalid time';
  const diffMin = Math.round((targetMs - now.getTime()) / 60_000);
  if (diffMin === 0) return 'Due now';
  if (diffMin < 0) {
    const abs = Math.abs(diffMin);
    if (abs < 60) return `${abs}m ago`;
    const hours = Math.round(abs / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.round(hours / 24)}d ago`;
  }
  if (diffMin < 60) return `In ${diffMin}m`;
  const hours = Math.round(diffMin / 60);
  if (hours < 24) return `In ${hours}h`;
  return `In ${Math.round(hours / 24)}d`;
}

export function summarizeSchedules(jobs: ScheduledJob[], now: Date = new Date()): ScheduleSummary {
  let active = 0;
  let paused = 0;
  let dueNow = 0;
  let totalRuns = 0;

  for (const job of jobs) {
    if (job.enabled) {
      active++;
      if (isScheduleDue(job, now)) {
        dueNow++;
      }
    } else {
      paused++;
    }
    totalRuns += Number.isFinite(job.runCount) ? job.runCount : 0;
  }

  return {
    total: jobs.length,
    active,
    paused,
    dueNow,
    totalRuns,
  };
}

export interface NormalizedScheduleInput {
  name: string;
  indicators: string[];
  source: SourceSelection;
  sources: SourceId[];
  intervalMinutes: number;
  enabled: boolean;
  mode: 'live' | 'sample';
}

export function validateAndNormalizeScheduleInput(
  input: unknown,
): { ok: true; data: NormalizedScheduleInput } | { ok: false; error: string } {
  if (!input || typeof input !== 'object') {
    return { ok: false, error: 'Invalid schedule payload.' };
  }

  const raw = input as Record<string, unknown>;
  const name = typeof raw.name === 'string' ? raw.name.trim() : '';
  if (!name) {
    return { ok: false, error: 'Schedule name is required.' };
  }
  if (name.length > 80) {
    return { ok: false, error: 'Schedule name must be 80 characters or fewer.' };
  }

  const rawIndicatorText = Array.isArray(raw.indicators)
    ? raw.indicators.map((x) => String(x)).join(', ')
    : typeof raw.indicators === 'string'
      ? raw.indicators
      : '';

  const parsed = parseIndicators(rawIndicatorText);
  const validTokens = parsed.filter(
    (p): p is { original: string; cleaned: string; type: IndicatorType } => p.type !== null,
  );
  if (validTokens.length === 0) {
    return { ok: false, error: 'Provide at least one valid IP, domain, or MD5/SHA1/SHA256 indicator.' };
  }

  const intervalNum = Number(raw.intervalMinutes ?? 60);
  if (
    !Number.isFinite(intervalNum) ||
    !Number.isInteger(intervalNum) ||
    intervalNum < MIN_SCHEDULE_INTERVAL_MINUTES ||
    intervalNum > MAX_SCHEDULE_INTERVAL_MINUTES
  ) {
    return {
      ok: false,
      error: `Check frequency must be a whole number between ${MIN_SCHEDULE_INTERVAL_MINUTES} and ${MAX_SCHEDULE_INTERVAL_MINUTES} minutes.`,
    };
  }

  const rawSource = typeof raw.source === 'string' ? raw.source.trim().toLowerCase() : 'all';
  const source: SourceSelection =
    rawSource === 'virustotal' || rawSource === 'abuseipdb' || rawSource === 'alienvault' || rawSource === 'all'
      ? rawSource
      : 'all';

  let sources: SourceId[] = [];
  if (Array.isArray(raw.sources)) {
    for (const s of raw.sources) {
      if ((s === 'virustotal' || s === 'abuseipdb' || s === 'alienvault') && !sources.includes(s)) {
        sources.push(s);
      }
    }
  }
  if (sources.length === 0) {
    sources = source === 'all' ? ['virustotal', 'abuseipdb', 'alienvault'] : [source];
  }

  const mode: 'live' | 'sample' = raw.mode === 'sample' ? 'sample' : 'live';
  const enabled = raw.enabled === undefined ? true : Boolean(raw.enabled);

  return {
    ok: true,
    data: {
      name,
      indicators: validTokens.map((t) => t.cleaned),
      source,
      sources,
      intervalMinutes: intervalNum,
      enabled,
      mode,
    },
  };
}

export function buildCliAddScheduleCommand(job: {
  name: string;
  indicators: string[];
  source: SourceSelection;
  intervalMinutes: number;
}): string {
  const safeName = job.name.replace(/"/g, '\\"') || 'My Scheduled Check';
  const safeIndicators = job.indicators.join(', ').replace(/"/g, '\\"') || '8.8.8.8';
  return `python3 main.py --add-schedule --schedule-name "${safeName}" --source ${job.source} --interval ${job.intervalMinutes} --indicators "${safeIndicators}"`;
}
