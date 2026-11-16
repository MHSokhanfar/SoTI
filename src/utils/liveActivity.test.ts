import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildActivityFromEmailAlert,
  buildActivityFromRecentInvestigation,
  buildActivityFromReportMeta,
  filterLiveActivityEvents,
  formatActivityUtcTime,
  mergeLiveActivityEvents,
  parseLogLineToActivity,
  summarizeLiveActivity,
} from './liveActivity';

test('parseLogLineToActivity classifies system events, quota failover, and saved CSV investigations', () => {
  const quotaLine =
    '2026-11-16 03:51:10,125 | WARNING | QUOTA FAILOVER | VirusTotal daily quota reached (500/500) — continuing with available APIs';
  const quotaEv = parseLogLineToActivity(quotaLine);
  assert.ok(quotaEv);
  assert.equal(quotaEv.category, 'system_event');
  assert.equal(quotaEv.severity, 'warning');
  assert.equal(quotaEv.title, 'Provider Quota Failover');
  assert.equal(quotaEv.timestamp, '2026-11-16T03:51:10.125Z');

  const reportLine =
    '2026-11-16 03:52:48,010 | INFO | Saved CSV report with 12 rows to soti_20261116_035248.csv';
  const reportEv = parseLogLineToActivity(reportLine);
  assert.ok(reportEv);
  assert.equal(reportEv.category, 'investigation');
  assert.equal(reportEv.severity, 'success');
  assert.equal(reportEv.reportName, 'soti_20261116_035248.csv');

  const vtLine = '2026-11-16 03:52:49,500 | INFO | VirusTotal | 1.2.3.4 | HTTP 200';
  const vtEv = parseLogLineToActivity(vtLine);
  assert.ok(vtEv);
  assert.equal(vtEv.source, 'VirusTotal');
  assert.equal(vtEv.indicator, '1.2.3.4');
});

test('buildActivityFromEmailAlert, ReportMeta, and RecentInvestigation produce structured events', () => {
  const alertEv = buildActivityFromEmailAlert({
    id: 'email-1',
    createdAt: '2026-11-16T04:00:00.000Z',
    mode: 'live',
    deliveryMethod: 'local_outbox',
    deliveryStatus: 'queued',
    statusDetail: 'Saved to local outbox',
    recipients: ['soc@example.com'],
    thresholdScore: 75,
    subject: 'Critical IOC Alert',
    textBody: 'Body',
    emlContent: 'EML',
    triggeredIndicators: [
      {
        indicator: '1.2.3.4',
        confidenceScore: 84,
        riskLevel: 'Critical',
        activeProviderCount: 2,
        explanation: 'Malicious across VT + AbuseIPDB',
      },
    ],
  });
  assert.equal(alertEv.category, 'threat_alert');
  assert.equal(alertEv.severity, 'critical');
  assert.equal(alertEv.indicator, '1.2.3.4');
  assert.equal(alertEv.confidenceScore, 84);

  const reportEv = buildActivityFromReportMeta({
    name: 'soti_20261116_035248.csv',
    sizeBytes: 2048,
    modifiedAt: '2026-11-16T03:52:48.000Z',
    rowCount: 12,
    verdicts: { malicious: 4, suspicious: 2, clean: 6, unknown: 0, other: 0 },
    indicators: ['1.2.3.4', 'evil.com'],
  });
  assert.equal(reportEv.category, 'threat_alert');
  assert.equal(reportEv.severity, 'critical');
  assert.equal(reportEv.reportName, 'soti_20261116_035248.csv');

  const recentEv = buildActivityFromRecentInvestigation({
    id: 'hist-1',
    createdAt: '2026-11-16T04:05:00.000Z',
    rawInput: '8.8.8.8',
    normalizedInput: '8.8.8.8',
    indicators: ['8.8.8.8'],
    indicatorCount: 1,
    source: 'all',
    customSources: ['virustotal'],
    useCustomSources: false,
    sourceLabels: ['VirusTotal'],
    mode: 'sample',
    reportFile: null,
    results: [],
    invalidTokens: [],
    quotaSkipped: [],
    verdictSummary: { malicious: 0, suspicious: 0, clean: 3, unknown: 0, other: 0 },
  });
  assert.equal(recentEv.category, 'investigation');
  assert.equal(recentEv.severity, 'success');
  assert.equal(recentEv.indicator, '8.8.8.8');
});

test('mergeLiveActivityEvents deduplicates, orders newest-first, filters, and summarizes cleanly', () => {
  const older = parseLogLineToActivity('2026-11-16 03:50:00,000 | INFO | VirusTotal | 8.8.8.8 | HTTP 200')!;
  const newer = buildActivityFromRecentInvestigation({
    id: 'hist-2',
    createdAt: '2026-11-16T04:10:00.000Z',
    rawInput: 'evil.com',
    normalizedInput: 'evil.com',
    indicators: ['evil.com'],
    indicatorCount: 1,
    source: 'all',
    customSources: ['virustotal'],
    useCustomSources: false,
    sourceLabels: ['VirusTotal'],
    mode: 'sample',
    reportFile: 'soti_20261116_041000.csv',
    results: [],
    invalidTokens: [],
    quotaSkipped: [],
    verdictSummary: { malicious: 2, suspicious: 0, clean: 0, unknown: 0, other: 0 },
  });

  const merged = mergeLiveActivityEvents([older], [newer, older]);
  assert.equal(merged.length, 2);
  assert.equal(merged[0].id, newer.id);
  assert.equal(formatActivityUtcTime(newer.timestamp), '04:10:00 UTC');

  const onlyInvestigations = filterLiveActivityEvents(merged, { category: 'investigation' });
  assert.equal(onlyInvestigations.length, 1);
  assert.equal(onlyInvestigations[0].indicator, 'evil.com');

  const byQuery = filterLiveActivityEvents(merged, { searchQuery: '8.8.8.8' });
  assert.equal(byQuery.length, 1);

  const summary = summarizeLiveActivity(merged);
  assert.deepEqual(summary, {
    total: 2,
    threatAlerts: 0,
    investigations: 1,
    systemEvents: 1,
    criticalCount: 0,
  });
});
