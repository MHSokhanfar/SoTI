import test from 'node:test';
import assert from 'node:assert/strict';
import type { LookupResult } from './indicators';
import {
  buildExportedSessionPayload,
  buildSessionExportFilename,
  serializeExportedSessionJson,
  SESSION_EXPORT_SCHEMA,
} from './sessionExport';

function makeResult(overrides: Partial<LookupResult> = {}): LookupResult {
  return {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: '1.2.3.4',
    originalToken: '1[.]2[.]3[.]4',
    type: 'ip',
    status: 'ok',
    verdict: 'Malicious',
    score: '30/90',
    summary: '30 malicious detections',
    details: { Malicious: 30, 'Total Engines': 90 },
    link: 'https://virustotal.com',
    ...overrides,
  };
}

test('buildSessionExportFilename formats UTC timestamp safely', () => {
  const dt = new Date('2026-11-14T21:05:09.000Z');
  assert.equal(buildSessionExportFilename(dt), 'soti_session_20261114_210509.json');
});

test('buildExportedSessionPayload bundles rawInput, results, researcher notes, confidence scores, and tags cleanly', () => {
  const now = new Date('2026-11-14T21:06:00.000Z');
  const payload = buildExportedSessionPayload({
    sessionId: 'inv_123',
    analysisMode: 'bulk',
    executionMode: 'sample',
    lastRunMode: 'sample',
    reportFile: 'soti_20261114_210600.csv',
    rawInput: '1[.]2[.]3[.]4\nevil.com',
    invalidTokens: [],
    sourceSelection: 'all',
    effectiveSources: ['virustotal', 'abuseipdb', 'alienvault'],
    customSources: [],
    useCustomSources: false,
    includeThreatFox: false,
    includeUrlscan: false,
    quotaSkipped: [],
    results: [
      makeResult(),
      makeResult({
        indicator: 'evil.com',
        originalToken: 'evil.com',
        type: 'domain',
        verdict: 'Clean',
        score: '0/90',
        details: { Malicious: 0, 'Total Engines': 90 },
      }),
    ],
    indicatorTags: {
      '1.2.3.4': ['C2', 'Critical'],
      'unrelated.org': ['Ignored'],
    },
    researcherNotes: 'Confirmed Cobalt Strike teamserver.\nBlocked at firewall.',
    notesUpdatedAt: '2026-11-14T21:05:30.000Z',
    now,
  });

  assert.equal(payload.schema, SESSION_EXPORT_SCHEMA);
  assert.equal(payload.sessionId, 'inv_123');
  assert.equal(payload.investigation.analysisMode, 'bulk');
  assert.equal(payload.investigation.rawInput, '1[.]2[.]3[.]4\nevil.com');
  assert.deepEqual(payload.investigation.indicators, ['1.2.3.4', 'evil.com']);
  assert.equal(payload.summary.totalIndicators, 2);
  assert.equal(payload.summary.totalProviderLookups, 2);
  assert.deepEqual(payload.tags.byIndicator, { '1.2.3.4': ['C2', 'Critical'] });
  assert.deepEqual(payload.tags.uniqueTags, ['C2', 'Critical']);
  assert.equal(
    payload.researcherNotes.text,
    'Confirmed Cobalt Strike teamserver.\nBlocked at firewall.',
  );
  assert.equal(payload.researcherNotes.updatedAt, '2026-11-14T21:05:30.000Z');
  assert.ok(payload.confidenceScores['1.2.3.4'].confidenceScore !== null);

  const json = serializeExportedSessionJson(payload);
  const reparsed = JSON.parse(json);
  assert.equal(reparsed.schema, SESSION_EXPORT_SCHEMA);
  assert.equal(reparsed.results.length, 2);
});
