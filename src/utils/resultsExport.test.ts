import assert from 'node:assert/strict';
import test from 'node:test';
import type { LookupResult } from './indicators';
import {
  buildFormattedResultsTxtReport,
  buildResultsJsonFilename,
  buildResultsTxtFilename,
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

test('buildFormattedResultsTxtReport formats metadata, sort state, Last Seen, tags, and notes for manual reading', () => {
  const row = makeRow({
    indicator: 'evil.com',
    type: 'domain',
    details: { Malicious: 22, Suspicious: 0, 'Total Engines': 90, 'Last Seen': '2026-11-15T10:15:00Z' },
  });
  const fixedDate = new Date('2026-11-15T12:30:45.000Z');

  assert.equal(
    buildResultsTxtFilename('All', fixedDate),
    'soti_report_20261115_123045.txt',
  );

  const txt = buildFormattedResultsTxtReport({
    allResults: [row],
    visibleResults: [row],
    verdictFilter: 'All',
    tagFilter: 'All',
    riskThreshold: 50,
    sortState: { key: 'riskScore', direction: 'desc' },
    indicatorTags: { 'evil.com': ['Phishing', 'C2'] },
    researcherNotes: 'Confirmed C2 domain during shift handoff.',
    mode: 'sample',
    now: fixedDate,
  });

  assert.match(txt, /SoTI — THREAT INTELLIGENCE INVESTIGATION REPORT/);
  assert.match(txt, /Sort Order\s+:\s+riskScore \(DESC\)/);
  assert.match(txt, /\[1\] evil\.com \(DOMAIN\) — VirusTotal/);
  assert.match(txt, /Last Seen\s+:\s+2026-11-15 10:15 UTC/);
  assert.match(txt, /Tags\s+:\s+Phishing, C2/);
  assert.match(txt, /RESEARCHER NOTES[\s\S]+Confirmed C2 domain during shift handoff\./);
});

