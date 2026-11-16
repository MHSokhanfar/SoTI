import assert from 'node:assert/strict';
import test from 'node:test';
import type { LookupResult } from './indicators';
import { buildRecentInvestigationEntry, type StorageLike } from './investigationHistory';
import {
  appendConfidenceSnapshot,
  buildConfidenceTrendsMap,
  classifyTrendDirection,
  CONFIDENCE_SNAPSHOTS_STORAGE_KEY,
  loadConfidenceSnapshots,
  parseTimestampFromReportFilename,
  saveConfidenceSnapshots,
} from './confidenceTrend';

function createMemoryStorage(): StorageLike {
  const store = new Map<string, string>();
  return {
    getItem: (k) => store.get(k) ?? null,
    setItem: (k, v) => {
      store.set(k, v);
    },
    removeItem: (k) => {
      store.delete(k);
    },
  };
}

function makeVtResult(indicator: string, detections: number): LookupResult {
  return {
    indicator,
    originalToken: indicator,
    type: 'ip',
    source: 'VirusTotal',
    sourceId: 'virustotal',
    verdict: detections >= 5 ? 'Malicious' : detections >= 1 ? 'Suspicious' : 'Clean',
    score: `${detections}/91`,
    summary: `${detections} engines flagged`,
    status: 'ok',
    link: `https://www.virustotal.com/gui/ip-address/${indicator}`,
    details: {},
  };
}

test('parseTimestampFromReportFilename extracts UTC ISO timestamps from standard report filenames', () => {
  assert.equal(
    parseTimestampFromReportFilename('soti_20261115_192700.csv'),
    '2026-11-15T19:27:00.000Z',
  );
  assert.equal(parseTimestampFromReportFilename('random.csv'), null);
});

test('buildConfidenceTrendsMap merges CSV report rows, history, snapshots, and current results chronologically', () => {
  const reportRows: Record<string, string>[] = [
    {
      reportName: 'soti_20261110_100000.csv',
      timestamp: '2026-11-10 10:00:00',
      indicator: '1.2.3.4',
      source: 'VirusTotal',
      verdict: 'Clean',
      score: '0/91',
      status: 'ok',
    },
    {
      reportName: 'soti_20261112_120000.csv',
      timestamp: '2026-11-12 12:00:00',
      indicator: '1.2.3.4',
      source: 'VirusTotal',
      verdict: 'Suspicious',
      score: '3/91',
      status: 'ok',
    },
  ];

  const historyEntry = buildRecentInvestigationEntry({
    id: 'hist-1',
    rawInput: '1.2.3.4',
    normalizedInput: '1.2.3.4',
    indicators: ['1.2.3.4'],
    source: 'virustotal',
    customSources: [],
    useCustomSources: false,
    sourceLabels: ['VirusTotal'],
    mode: 'sample',
    results: [makeVtResult('1.2.3.4', 10)],
    invalidTokens: [],
    quotaSkipped: [],
    reportFile: null,
    now: new Date('2026-11-14T15:00:00Z'),
  });

  const trends = buildConfidenceTrendsMap({
    reportRows,
    recentHistory: [historyEntry],
    currentResults: [makeVtResult('1.2.3.4', 25)],
    currentTimestamp: '2026-11-15T19:30:00Z',
  });

  const ipTrend = trends.get('1.2.3.4');
  assert.ok(ipTrend);
  assert.equal(ipTrend.points.length, 4);
  assert.equal(ipTrend.direction, 'rising');
  assert.equal(ipTrend.emergingThreat, true);
  assert.ok((ipTrend.netDelta ?? 0) > 50);
  assert.equal(ipTrend.points[0].score, 0);
  assert.equal(ipTrend.points[ipTrend.points.length - 1].score, ipTrend.latestScore);
});

test('classifyTrendDirection distinguishes rising, falling, steady, and single-run series', () => {
  assert.equal(
    classifyTrendDirection([
      { timestamp: '2026-11-15T01:00:00Z', label: '01:00', score: 85, runSource: 'report' },
      { timestamp: '2026-11-15T02:00:00Z', label: '02:00', score: 20, runSource: 'current' },
    ]).direction,
    'falling',
  );

  assert.equal(
    classifyTrendDirection([
      { timestamp: '2026-11-15T01:00:00Z', label: '01:00', score: 40, runSource: 'report' },
      { timestamp: '2026-11-15T02:00:00Z', label: '02:00', score: 42, runSource: 'current' },
    ]).direction,
    'steady',
  );

  const single = classifyTrendDirection([
    { timestamp: '2026-11-15T01:00:00Z', label: '01:00', score: 75, runSource: 'current' },
  ]);
  assert.equal(single.direction, 'single');
  assert.equal(single.emergingThreat, false);
});

test('appendConfidenceSnapshot, saveConfidenceSnapshots, and loadConfidenceSnapshots persist cleanly', () => {
  const storage = createMemoryStorage();
  let snapshots = appendConfidenceSnapshot(
    {},
    [makeVtResult('8.8.8.8', 0)],
    '2026-11-15T10:00:00Z',
    'live-poll',
  );
  snapshots = appendConfidenceSnapshot(
    snapshots,
    [makeVtResult('8.8.8.8', 12)],
    '2026-11-15T10:01:00Z',
    'live-poll',
  );

  assert.equal(snapshots['8.8.8.8'].length, 2);
  assert.equal(saveConfidenceSnapshots(storage, snapshots), true);
  assert.ok(storage.getItem(CONFIDENCE_SNAPSHOTS_STORAGE_KEY));

  const reloaded = loadConfidenceSnapshots(storage);
  assert.equal(reloaded['8.8.8.8'].length, 2);
  assert.equal(reloaded['8.8.8.8'][0].score, 0);
  assert.ok(reloaded['8.8.8.8'][1].score > 50);
});
