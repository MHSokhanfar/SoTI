import assert from 'node:assert/strict';
import test from 'node:test';
import type { LookupResult } from './indicators';
import {
  buildResultsJsonFilename,
  buildStructuredResultsJsonPayload,
  CONFIDENCE_SCORE_LEGEND,
  RESULTS_EXPORT_SCHEMA,
  serializeStructuredResultsJson,
} from './resultsExport';

function makeRow(overrides: Partial<LookupResult>): LookupResult {
  return {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: '1.2.3.4',
    originalToken: '1.2.3.4',
    type: 'ip',
    status: 'ok',
    verdict: 'Malicious',
    score: '22/90',
    summary: '22 malicious engines',
    details: { Malicious: 22, Suspicious: 0, 'Total Engines': 90 },
    link: 'https://www.virustotal.com/gui/ip-address/1.2.3.4',
    ...overrides,
  };
}

test('CONFIDENCE_SCORE_LEGEND covers all five confidence tiers cleanly', () => {
  assert.deepEqual(
    CONFIDENCE_SCORE_LEGEND.map((t) => t.level),
    ['Low', 'Medium', 'High', 'Critical', 'Unknown'],
  );
  assert.equal(CONFIDENCE_SCORE_LEGEND.find((t) => t.level === 'Critical')?.rangeLabel, '75–100');
});

test('buildStructuredResultsJsonPayload enriches visible rows with confidence scores and builds valid JSON', () => {
  const vtRow = makeRow({ indicator: '1.2.3.4', sourceId: 'virustotal' });
  const cleanRow = makeRow({
    indicator: '8.8.8.8',
    verdict: 'Clean',
    score: '0/90',
    summary: '0 malicious',
    details: { Malicious: 0, Suspicious: 0, 'Total Engines': 90 },
  });

  const payload = buildStructuredResultsJsonPayload({
    allResults: [vtRow, cleanRow],
    visibleResults: [vtRow],
    verdictFilter: 'Malicious',
    mode: 'sample',
    now: new Date('2026-11-15T12:30:45.000Z'),
  });

  assert.equal(payload.schema, RESULTS_EXPORT_SCHEMA);
  assert.equal(payload.verdictFilter, 'Malicious');
  assert.equal(payload.indicatorCount, 1);
  assert.equal(payload.rowCount, 1);
  assert.ok(payload.results[0].confidenceScore !== null && payload.results[0].confidenceScore >= 75);
  assert.equal(payload.results[0].riskLevel, 'Critical');
  assert.equal(
    buildResultsJsonFilename('Malicious', new Date('2026-11-15T12:30:45.000Z')),
    'soti_results_malicious_20261115_123045.json',
  );

  const parsed = JSON.parse(serializeStructuredResultsJson(payload));
  assert.equal(parsed.rowCount, 1);
});
