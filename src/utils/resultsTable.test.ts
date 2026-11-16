import test from 'node:test';
import assert from 'node:assert/strict';
import type { LookupResult } from './indicators';
import type { UnifiedBatchRow } from './bulkAnalysis';
import { computeAllIocConfidenceScores } from './riskScoring';
import {
  buildLastSeenByIndicatorMap,
  extractResultLastSeen,
  parseComparableScoreValue,
  sortLookupResults,
  sortUnifiedBatchRows,
  toggleResultsSortState,
} from './resultsTable';

function makeResult(overrides: Partial<LookupResult>): LookupResult {
  return {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: '1.2.3.4',
    originalToken: '1.2.3.4',
    type: 'ip',
    status: 'ok',
    verdict: 'Malicious',
    score: '10/90',
    summary: 'Flagged by 10 engines',
    details: {},
    link: 'https://www.virustotal.com',
    ...overrides,
  };
}

test('toggleResultsSortState starts risk/lastSeen descending and indicator ascending, flipping on repeat clicks', () => {
  const firstRisk = toggleResultsSortState(null, 'riskScore');
  assert.deepEqual(firstRisk, { key: 'riskScore', direction: 'desc' });
  assert.deepEqual(toggleResultsSortState(firstRisk, 'riskScore'), {
    key: 'riskScore',
    direction: 'asc',
  });

  const firstInd = toggleResultsSortState(firstRisk, 'indicator');
  assert.deepEqual(firstInd, { key: 'indicator', direction: 'asc' });
  assert.deepEqual(toggleResultsSortState(firstInd, 'indicator'), {
    key: 'indicator',
    direction: 'desc',
  });
});

test('extractResultLastSeen prefers Last Seen, then Last Reported, then Last Analysis', () => {
  const withLastSeen = makeResult({
    details: {
      'Last Analysis': '2026-11-10 12:00 UTC',
      'Last Seen': '2026-11-15T18:30:00Z',
    },
  });
  const info1 = extractResultLastSeen(withLastSeen);
  assert.equal(info1.displayUtc, '2026-11-15 18:30 UTC');
  assert.equal(info1.fieldLabel, 'Last Seen');

  const withLastReported = makeResult({
    sourceId: 'abuseipdb',
    details: { 'Last Reported': '2026-11-13T21:14:00+00:00' },
  });
  assert.equal(extractResultLastSeen(withLastReported).displayUtc, '2026-11-13 21:14 UTC');

  const withoutDates = makeResult({ details: { 'Last Reported': 'Never' } });
  assert.equal(extractResultLastSeen(withoutDates).epochMs, null);
  assert.equal(extractResultLastSeen(withoutDates).displayUtc, '—');
});

test('sortLookupResults orders Indicator, Risk Score, and Last Seen while pushing missing metrics to bottom', () => {
  const rHigh = makeResult({
    indicator: 'evil.com',
    type: 'domain',
    verdict: 'Malicious',
    score: '60/90',
    details: { 'Last Seen': '2026-11-12T08:00:00Z' },
  });
  const rMid = makeResult({
    indicator: '1.2.3.4',
    type: 'ip',
    source: 'AbuseIPDB',
    sourceId: 'abuseipdb',
    verdict: 'Suspicious',
    score: '40%',
    details: { 'Last Reported': '2026-11-15T09:00:00Z' },
  });
  const rLowNoDate = makeResult({
    indicator: '8.8.8.8',
    type: 'ip',
    verdict: 'Clean',
    score: '0/90',
    details: {},
  });

  const rows = [rLowNoDate, rHigh, rMid];
  const conf = computeAllIocConfidenceScores(rows);

  const byRiskDesc = sortLookupResults(rows, { key: 'riskScore', direction: 'desc' }, conf);
  assert.deepEqual(
    byRiskDesc.map((r) => r.indicator),
    ['evil.com', '1.2.3.4', '8.8.8.8'],
  );

  const byRiskAsc = sortLookupResults(rows, { key: 'riskScore', direction: 'asc' }, conf);
  assert.deepEqual(
    byRiskAsc.map((r) => r.indicator),
    ['8.8.8.8', '1.2.3.4', 'evil.com'],
  );

  const byIndAsc = sortLookupResults(rows, { key: 'indicator', direction: 'asc' }, conf);
  assert.deepEqual(
    byIndAsc.map((r) => r.indicator),
    ['1.2.3.4', '8.8.8.8', 'evil.com'],
  );

  const byLastSeenDesc = sortLookupResults(rows, { key: 'lastSeen', direction: 'desc' }, conf);
  assert.deepEqual(
    byLastSeenDesc.map((r) => r.indicator),
    ['1.2.3.4', 'evil.com', '8.8.8.8'],
  );

  // Even on ascending Last Seen sort, missing dates stay at bottom
  const byLastSeenAsc = sortLookupResults(rows, { key: 'lastSeen', direction: 'asc' }, conf);
  assert.deepEqual(
    byLastSeenAsc.map((r) => r.indicator),
    ['evil.com', '1.2.3.4', '8.8.8.8'],
  );
});

test('parseComparableScoreValue handles ratios, percentages, pulse counts, and N/A', () => {
  assert.equal(parseComparableScoreValue('9/90', 'ok'), 10);
  assert.equal(parseComparableScoreValue('87%', 'ok'), 87);
  assert.equal(parseComparableScoreValue('12 pulses', 'ok'), 12);
  assert.equal(parseComparableScoreValue('N/A', 'unsupported'), null);
});

test('sortUnifiedBatchRows sorts batch summary rows by Risk Score and aggregated Last Seen', () => {
  const results: LookupResult[] = [
    makeResult({
      indicator: 'alpha.org',
      type: 'domain',
      details: { 'Last Analysis': '2026-11-01T00:00:00Z' },
    }),
    makeResult({
      indicator: 'beta.net',
      type: 'domain',
      details: { 'Last Seen': '2026-11-15T12:00:00Z' },
    }),
  ];
  const lastSeenMap = buildLastSeenByIndicatorMap(results);

  const batchRows: UnifiedBatchRow[] = [
    {
      indicator: 'alpha.org',
      type: 'domain',
      overallVerdict: 'Clean',
      confidenceScore: 12,
      riskLevel: 'Low',
      confidenceExplanation: '',
      maliciousHits: 0,
      suspiciousHits: 0,
      cleanHits: 2,
      respondedCount: 2,
      totalProvidersQueried: 2,
      tags: [],
      providerCells: {},
      results: [results[0]],
    },
    {
      indicator: 'beta.net',
      type: 'domain',
      overallVerdict: 'Malicious',
      confidenceScore: 88,
      riskLevel: 'Critical',
      confidenceExplanation: '',
      maliciousHits: 2,
      suspiciousHits: 0,
      cleanHits: 0,
      respondedCount: 2,
      totalProvidersQueried: 2,
      tags: [],
      providerCells: {},
      results: [results[1]],
    },
  ];

  const sortedByLastSeen = sortUnifiedBatchRows(
    batchRows,
    { key: 'lastSeen', direction: 'desc' },
    lastSeenMap,
  );
  assert.deepEqual(
    sortedByLastSeen.map((r) => r.indicator),
    ['beta.net', 'alpha.org'],
  );

  const sortedByRiskAsc = sortUnifiedBatchRows(
    batchRows,
    { key: 'riskScore', direction: 'asc' },
    lastSeenMap,
  );
  assert.deepEqual(
    sortedByRiskAsc.map((r) => r.indicator),
    ['alpha.org', 'beta.net'],
  );
});
