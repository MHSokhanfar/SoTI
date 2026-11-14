import type { QuotaState } from '../App';
import type { ProviderQuotaSnapshot } from './quota';

export const QUOTA_ALERT_THRESHOLD_PERCENT = 90;

export type NotificationSeverity = 'warning' | 'critical';

export interface QuotaNotificationAlert {
  id: string;
  date: string;
  providerId: string;
  providerName: string;
  used: number;
  limit: number;
  remaining: number;
  percentUsed: number;
  exhausted: boolean;
  severity: NotificationSeverity;
  title: string;
  message: string;
  createdAt: string;
  read: boolean;
}

export function buildProviderQuotaKey(date: string, providerId: string): string {
  return `${date}:${providerId}`;
}

export function createQuotaAlert(
  snapshot: ProviderQuotaSnapshot,
  date: string,
  thresholdPercent: number = QUOTA_ALERT_THRESHOLD_PERCENT,
  now: Date = new Date(),
): QuotaNotificationAlert {
  const isCritical = snapshot.exhausted || snapshot.percentUsed >= 100;
  const severity: NotificationSeverity = isCritical ? 'critical' : 'warning';
  const createdAt = now.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const uniqueSuffix = `${now.getTime()}-${Math.random().toString(16).slice(2, 6)}`;

  const title = isCritical
    ? `${snapshot.name} daily quota reached (${snapshot.percentUsed}%)`
    : `${snapshot.name} crossed ${thresholdPercent}% quota (${snapshot.percentUsed}%)`;

  const message = isCritical
    ? `${snapshot.used}/${snapshot.limit} daily requests used — automatic failover active for other available APIs.`
    : `${snapshot.used}/${snapshot.limit} daily requests used (${snapshot.remaining} remaining before automatic failover).`;

  return {
    id: `quota-${date}-${snapshot.providerId}-${uniqueSuffix}`,
    date,
    providerId: snapshot.providerId,
    providerName: snapshot.name,
    used: snapshot.used,
    limit: snapshot.limit,
    remaining: snapshot.remaining,
    percentUsed: snapshot.percentUsed,
    exhausted: snapshot.exhausted,
    severity,
    title,
    message,
    createdAt,
    read: false,
  };
}

export function detectQuotaThresholdCrossings(
  quotaState: QuotaState,
  previousPercentByKey: Record<string, number>,
  thresholdPercent: number = QUOTA_ALERT_THRESHOLD_PERCENT,
  now: Date = new Date(),
): {
  alertsToPush: QuotaNotificationAlert[];
  nextPercentByKey: Record<string, number>;
} {
  if (!quotaState?.providers || quotaState.providers.length === 0) {
    return {
      alertsToPush: [],
      nextPercentByKey: { ...previousPercentByKey },
    };
  }

  const nextPercentByKey: Record<string, number> = { ...previousPercentByKey };
  const alertsToPush: QuotaNotificationAlert[] = [];

  for (const snapshot of quotaState.providers) {
    const key = buildProviderQuotaKey(quotaState.date, snapshot.providerId);
    const prevPercent = previousPercentByKey[key];
    const nextPercent = Number.isFinite(snapshot.percentUsed) ? snapshot.percentUsed : 0;

    const wasBelowThreshold = prevPercent === undefined || prevPercent < thresholdPercent;
    const isNowAtOrAbove = nextPercent >= thresholdPercent;

    if (wasBelowThreshold && isNowAtOrAbove) {
      alertsToPush.push(createQuotaAlert(snapshot, quotaState.date, thresholdPercent, now));
    }

    nextPercentByKey[key] = nextPercent;
  }

  return { alertsToPush, nextPercentByKey };
}

export function mergeNotificationAlerts(
  existing: QuotaNotificationAlert[],
  incoming: QuotaNotificationAlert[],
  maxItems = 30,
): QuotaNotificationAlert[] {
  if (incoming.length === 0) return existing;
  const combined = [...incoming, ...existing];
  return combined.slice(0, Math.max(1, maxItems));
}

export function countUnreadNotifications(alerts: QuotaNotificationAlert[]): number {
  let count = 0;
  for (const item of alerts) {
    if (!item.read) count += 1;
  }
  return count;
}

export function markNotificationRead(
  alerts: QuotaNotificationAlert[],
  id: string,
): QuotaNotificationAlert[] {
  return alerts.map((item) => (item.id === id ? { ...item, read: true } : item));
}

export function markAllNotificationsRead(
  alerts: QuotaNotificationAlert[],
): QuotaNotificationAlert[] {
  return alerts.map((item) => (item.read ? item : { ...item, read: true }));
}

export function dismissNotificationAlert(
  alerts: QuotaNotificationAlert[],
  id: string,
): QuotaNotificationAlert[] {
  return alerts.filter((item) => item.id !== id);
}

export function formatAlertTimestamp(isoString: string): string {
  const m = isoString.match(/T(\d{2}:\d{2})/);
  return m ? `${m[1]} UTC` : isoString;
}
