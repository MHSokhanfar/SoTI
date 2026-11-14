import test from 'node:test';
import assert from 'node:assert/strict';
import {
  countUnreadNotifications,
  detectQuotaThresholdCrossings,
  dismissNotificationAlert,
  formatAlertTimestamp,
  markAllNotificationsRead,
  markNotificationRead,
  mergeNotificationAlerts,
} from './notifications';
import type { ProviderQuotaSnapshot } from './quota';

function makeSnapshot(
  providerId: string,
  name: string,
  used: number,
  limit: number,
  exhausted = false,
): ProviderQuotaSnapshot {
  const remaining = exhausted ? 0 : Math.max(0, limit - used);
  const percentUsed = Math.min(100, Math.round((used / limit) * 1000) / 10);
  return {
    providerId,
    name,
    used,
    limit,
    remaining,
    percentUsed,
    exhausted: exhausted || used >= limit,
    exhaustedReason: exhausted || used >= limit ? 'Limit reached' : null,
    upstreamRemaining: null,
    lastUpdatedAt: '2026-11-14T05:00:00Z',
  };
}

test('detectQuotaThresholdCrossings stays silent below 90% and pushes alert once crossing >= 90%', () => {
  const t1 = new Date('2026-11-14T05:00:00Z');
  const first = detectQuotaThresholdCrossings(
    {
      date: '2026-11-14',
      providers: [
        makeSnapshot('virustotal', 'VirusTotal', 89, 100), // 89% -> below threshold
        makeSnapshot('abuseipdb', 'AbuseIPDB', 80, 100), // 80% -> below threshold
      ],
    },
    {},
    90,
    t1,
  );
  assert.equal(first.alertsToPush.length, 0);

  // VirusTotal reaches exact 90% -> must push alert
  const t2 = new Date('2026-11-14T05:01:00Z');
  const second = detectQuotaThresholdCrossings(
    {
      date: '2026-11-14',
      providers: [
        makeSnapshot('virustotal', 'VirusTotal', 90, 100),
        makeSnapshot('abuseipdb', 'AbuseIPDB', 85, 100),
      ],
    },
    first.nextPercentByKey,
    90,
    t2,
  );
  assert.equal(second.alertsToPush.length, 1);
  assert.equal(second.alertsToPush[0].providerId, 'virustotal');
  assert.equal(second.alertsToPush[0].severity, 'warning');
  assert.equal(second.alertsToPush[0].percentUsed, 90);
  assert.equal(second.alertsToPush[0].read, false);

  // VirusTotal increments from 90% to 92% -> should NOT duplicate alert while staying >= 90%
  const t3 = new Date('2026-11-14T05:02:00Z');
  const third = detectQuotaThresholdCrossings(
    {
      date: '2026-11-14',
      providers: [
        makeSnapshot('virustotal', 'VirusTotal', 92, 100),
        makeSnapshot('abuseipdb', 'AbuseIPDB', 85, 100),
      ],
    },
    second.nextPercentByKey,
    90,
    t3,
  );
  assert.equal(third.alertsToPush.length, 0);
});

test('detectQuotaThresholdCrossings pushes critical alert at 100% and re-arms after reset or new UTC day', () => {
  const t1 = new Date('2026-11-14T05:10:00Z');
  // Initial hydration already at 100% (or jumped directly from 0 to 100%)
  const initialExhausted = detectQuotaThresholdCrossings(
    {
      date: '2026-11-14',
      providers: [makeSnapshot('shodan', 'Shodan', 100, 100, true)],
    },
    {},
    90,
    t1,
  );
  assert.equal(initialExhausted.alertsToPush.length, 1);
  assert.equal(initialExhausted.alertsToPush[0].severity, 'critical');

  // Quota is reset -> drops back to 0%
  const afterReset = detectQuotaThresholdCrossings(
    {
      date: '2026-11-14',
      providers: [makeSnapshot('shodan', 'Shodan', 0, 100, false)],
    },
    initialExhausted.nextPercentByKey,
    90,
    t1,
  );
  assert.equal(afterReset.alertsToPush.length, 0);

  // Crosses 90% again after reset -> triggers a fresh alert
  const reCrossed = detectQuotaThresholdCrossings(
    {
      date: '2026-11-14',
      providers: [makeSnapshot('shodan', 'Shodan', 95, 100, false)],
    },
    afterReset.nextPercentByKey,
    90,
    t1,
  );
  assert.equal(reCrossed.alertsToPush.length, 1);
  assert.equal(reCrossed.alertsToPush[0].severity, 'warning');

  // Next UTC day starts with Shodan crossing >= 90% again -> fresh key triggers alert
  const nextDay = detectQuotaThresholdCrossings(
    {
      date: '2026-11-15',
      providers: [makeSnapshot('shodan', 'Shodan', 91, 100, false)],
    },
    reCrossed.nextPercentByKey,
    90,
    new Date('2026-11-15T01:00:00Z'),
  );
  assert.equal(nextDay.alertsToPush.length, 1);
});

test('notification state helpers count unread, mark read, dismiss, merge, and format timestamps', () => {
  const { alertsToPush } = detectQuotaThresholdCrossings(
    {
      date: '2026-11-14',
      providers: [
        makeSnapshot('virustotal', 'VirusTotal', 94, 100),
        makeSnapshot('abuseipdb', 'AbuseIPDB', 98, 100),
      ],
    },
    {},
    90,
    new Date('2026-11-14T14:25:00Z'),
  );

  const list = mergeNotificationAlerts([], alertsToPush, 10);
  assert.equal(list.length, 2);
  assert.equal(countUnreadNotifications(list), 2);
  assert.equal(formatAlertTimestamp(list[0].createdAt), '14:25 UTC');

  const oneRead = markNotificationRead(list, list[0].id);
  assert.equal(countUnreadNotifications(oneRead), 1);

  const allRead = markAllNotificationsRead(oneRead);
  assert.equal(countUnreadNotifications(allRead), 0);

  const dismissed = dismissNotificationAlert(allRead, list[0].id);
  assert.equal(dismissed.length, 1);
});
