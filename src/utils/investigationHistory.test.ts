import test from 'node:test';
import assert from 'node:assert/strict';
import type { LookupResult } from './indicators';
import {
  buildRecentInvestigationEntry,
  clearRecentInvestigations,
  formatInvestigationTitle,
  formatRelativeTime,
  getPrimaryVerdictBadge,
  loadRecentInvestigations,
  prependRecentInvestigation,
  RECENT_INVESTIGATIONS_STORAGE_KEY,
  removeRecentInvestigation,
  saveRecentInvestigations,
  summarizeLookupVerdicts,
  type StorageLike,
} from './investigationHistory';

function makeResult(overrides: Partial<LookupResult> = {}): LookupResult {
  return {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: '1.2.3.4',
    originalToken: '1.2.3.4',
    type: 'ip',
    status: 'ok',
    verdict: 'Clean',
    score: '0/80',
    summary: 'No detections',
    details: {},
    link: '',
    ...overrides,
  };
}

function createMemoryStorage(): StorageLike {
  const map = new Map<string, string>();
  return {
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => {
      map.set(k, v);
    },
    removeItem: (k) => {
      map.delete(k);
    },
  };
}

test('summarizeLookupVerdicts and getPrimaryVerdictBadge summarize verdicts accurately', () => {
  const results: LookupResult[] = [
    makeResult({ verdict: 'Malicious' }),
    makeResult({ verdict: 'Suspicious', sourceId: 'abuseipdb' }),
    makeResult({ verdict: 'Clean', sourceId: 'alienvault' }),
    makeResult({ status: 'error', verdict: 'Unknown', indicator: '8.8.8.8' }),
  ];

  const summary = summarizeLookupVerdicts(results);
  assert.deepEqual(summary, {
    malicious: 1,
    suspicious: 1,
    clean: 1,
    unknown: 0,
    other: 1,
  });

  assert.deepEqual(getPrimaryVerdictBadge(summary), {
    label: '1 malicious',
    tone: 'malicious',
  });
  assert.deepEqual(
    getPrimaryVerdictBadge({ malicious: 0, suspicious: 0, clean: 3, unknown: 0, other: 0 }),
    { label: '3 clean', tone: 'clean' },
  );
});

test('buildRecentInvestigationEntry, prepend, remove, and storage roundtrip cleanly', () => {
  const storage = createMemoryStorage();
  const t1 = new Date('2026-11-14T19:50:00.000Z');
  const t2 = new Date('2026-11-14T19:52:00.000Z');

  const e1 = buildRecentInvestigationEntry({
    id: 'run-1',
    rawInput: '1[.]2[.]3[.]4',
    normalizedInput: '1.2.3.4',
    indicators: ['1.2.3.4'],
    source: 'all',
    customSources: [],
    useCustomSources: false,
    sourceLabels: ['VirusTotal', 'AbuseIPDB'],
    mode: 'sample',
    results: [makeResult({ verdict: 'Malicious' })],
    invalidTokens: [],
    quotaSkipped: [],
    reportFile: 'soti_20261114_195000.csv',
    now: t1,
  });

  const e2 = buildRecentInvestigationEntry({
    id: 'run-2',
    rawInput: '8.8.8.8, evil.com',
    normalizedInput: '8.8.8.8, evil.com',
    indicators: ['8.8.8.8', 'evil.com'],
    source: 'virustotal',
    customSources: [],
    useCustomSources: false,
    sourceLabels: ['VirusTotal'],
    mode: 'live',
    results: [makeResult({ indicator: '8.8.8.8', verdict: 'Clean' })],
    invalidTokens: [],
    quotaSkipped: [],
    reportFile: 'soti_20261114_195200.csv',
    now: t2,
  });

  let history = prependRecentInvestigation([], e1, 2);
  history = prependRecentInvestigation(history, e2, 2);
  assert.equal(history.length, 2);
  assert.equal(history[0].id, 'run-2');

  const saved = saveRecentInvestigations(storage, history);
  assert.equal(saved, true);
  assert.ok(storage.getItem(RECENT_INVESTIGATIONS_STORAGE_KEY));

  const reloaded = loadRecentInvestigations(storage);
  assert.equal(reloaded.length, 2);
  assert.equal(reloaded[0].normalizedInput, '8.8.8.8, evil.com');
  assert.equal(reloaded[1].verdictSummary.malicious, 1);

  const afterRemove = removeRecentInvestigation(reloaded, 'run-2');
  assert.equal(afterRemove.length, 1);
  assert.equal(afterRemove[0].id, 'run-1');

  const cleared = clearRecentInvestigations(storage);
  assert.equal(cleared, true);
  assert.equal(storage.getItem(RECENT_INVESTIGATIONS_STORAGE_KEY), null);
  assert.deepEqual(loadRecentInvestigations(storage), []);
});

test('loadRecentInvestigations safely handles corrupt JSON and invalid items', () => {
  const storage = createMemoryStorage();
  storage.setItem(RECENT_INVESTIGATIONS_STORAGE_KEY, '{corrupt json');
  assert.deepEqual(loadRecentInvestigations(storage), []);

  storage.setItem(RECENT_INVESTIGATIONS_STORAGE_KEY, JSON.stringify([{ bad: true }]));
  assert.deepEqual(loadRecentInvestigations(storage), []);
});

test('formatInvestigationTitle and formatRelativeTime produce concise labels', () => {
  assert.equal(formatInvestigationTitle(['8.8.8.8'], '8.8.8.8'), '8.8.8.8');
  assert.equal(formatInvestigationTitle(['1.2.3.4', 'evil.com', '8.8.8.8'], ''), '1.2.3.4 +2 more');

  const now = new Date('2026-11-14T20:00:00.000Z');
  assert.equal(formatRelativeTime('2026-11-14T19:59:30.000Z', now), 'Just now');
  assert.equal(formatRelativeTime('2026-11-14T19:55:00.000Z', now), '5m ago');
  assert.equal(formatRelativeTime('2026-11-14T17:00:00.000Z', now), '3h ago');
});
