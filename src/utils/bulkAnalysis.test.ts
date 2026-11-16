import test from 'node:test';
import assert from 'node:assert/strict';
import type { LookupResult } from './indicators';
import {
  buildUnifiedBatchTable,
  deduplicateBulkInputLines,
  filterUnifiedBatchRows,
  formatIndicatorsAsNewlines,
  formatUnifiedBatchRowClipboard,
  summarizeBulkInputStats,
} from './bulkAnalysis';

function makeResult(overrides: Partial<LookupResult> = {}): LookupResult {
  return {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: '1.2.3.4',
    originalToken: '1.2.3.4',
    type: 'ip',
    status: 'ok',
    verdict: 'Clean',
    score: '0/90',
    summary: 'No detections',
    details: {},
    link: '',
    ...overrides,
  };
}

test('summarizeBulkInputStats, formatIndicatorsAsNewlines, and deduplicateBulkInputLines work cleanly', () => {
  const raw = '1[.]2[.]3[.]4\n1.2.3.4\nevil.com\n44d88612fea8a8f36de82e1278abb02f\nnot_an_ioc';
  const stats = summarizeBulkInputStats(raw);
  assert.deepEqual(stats, {
    totalValid: 3,
    lineCount: 5,
    ipCount: 1,
    domainCount: 1,
    hashCount: 1,
    invalidCount: 1,
    defangedCount: 1,
  });

  assert.equal(
    formatIndicatorsAsNewlines('1[.]2[.]3[.]4, 8.8.8.8, evil.com'),
    '1[.]2[.]3[.]4\n8.8.8.8\nevil.com',
  );

  assert.equal(
    deduplicateBulkInputLines(raw),
    '1.2.3.4\nevil.com\n44d88612fea8a8f36de82e1278abb02f',
  );
});

test('buildUnifiedBatchTable aggregates per-IOC multi-provider columns, verdicts, and tags', () => {
  const results: LookupResult[] = [
    makeResult({
      source: 'VirusTotal',
      sourceId: 'virustotal',
      indicator: '1.2.3.4',
      verdict: 'Malicious',
      score: '25/90',
      details: { Malicious: 25, 'Total Engines': 90 },
    }),
    makeResult({
      source: 'AbuseIPDB',
      sourceId: 'abuseipdb',
      indicator: '1.2.3.4',
      verdict: 'Malicious',
      score: '95%',
      details: { Confidence: '95%' },
    }),
    makeResult({
      source: 'AlienVault OTX',
      sourceId: 'alienvault',
      indicator: '1.2.3.4',
      verdict: 'Clean',
      score: '0 pulses',
    }),
    makeResult({
      source: 'VirusTotal',
      sourceId: 'virustotal',
      indicator: '8.8.8.8',
      verdict: 'Clean',
      score: '0/90',
      details: { Malicious: 0, 'Total Engines': 90 },
    }),
    makeResult({
      source: 'AbuseIPDB',
      sourceId: 'abuseipdb',
      indicator: '8.8.8.8',
      verdict: 'Clean',
      score: '0%',
      details: { Confidence: '0%' },
    }),
  ];

  const table = buildUnifiedBatchTable(results, { '1.2.3.4': ['C2', 'Critical'] });
  assert.deepEqual(
    table.providerColumns.map((c) => c.sourceId),
    ['virustotal', 'abuseipdb', 'alienvault'],
  );
  assert.equal(table.rows.length, 2);
  assert.equal(table.summary.maliciousCount, 1);
  assert.equal(table.summary.cleanCount, 1);
  assert.equal(table.summary.totalProviderLookups, 5);

  const first = table.rows[0];
  assert.equal(first.indicator, '1.2.3.4');
  assert.equal(first.overallVerdict, 'Malicious');
  assert.equal(first.maliciousHits, 2);
  assert.equal(first.cleanHits, 1);
  assert.deepEqual(first.tags, ['C2', 'Critical']);
  assert.equal(first.confidenceScore, 73);
  assert.equal(first.riskLevel, 'High');

  const malOnly = filterUnifiedBatchRows(table.rows, 'Malicious');
  assert.equal(malOnly.length, 1);
  assert.equal(malOnly[0].indicator, '1.2.3.4');

  const clipboardText = formatUnifiedBatchRowClipboard(first, table.providerColumns);
  assert.ok(clipboardText.includes('1.2.3.4 (IP)'));
  assert.ok(clipboardText.includes('VirusTotal: Malicious (25/90)'));
  assert.ok(clipboardText.includes('Tags: C2, Critical'));
});
