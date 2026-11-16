import assert from 'node:assert/strict';
import test from 'node:test';
import type { LookupResult } from './indicators';
import { extractIocTimelineEvents, parseFlexibleTimestamp } from './iocTimeline';

function makeResult(overrides: Partial<LookupResult>): LookupResult {
  return {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: 'evil.com',
    originalToken: 'evil.com',
    type: 'domain',
    status: 'ok',
    verdict: 'Malicious',
    score: '20/90',
    summary: '20 malicious',
    details: {},
    link: '',
    ...overrides,
  };
}

test('parseFlexibleTimestamp parses UTC, ISO, Unix seconds, and skips placeholders', () => {
  assert.equal(parseFlexibleTimestamp('Never'), null);
  assert.equal(parseFlexibleTimestamp('N/A'), null);
  assert.equal(parseFlexibleTimestamp(false), null);

  const utcDate = parseFlexibleTimestamp('2026-11-12 08:42:10 UTC');
  assert.ok(utcDate);
  assert.equal(utcDate.toISOString(), '2026-11-12T08:42:10.000Z');

  const isoDate = parseFlexibleTimestamp('2026-11-13T21:14:00+00:00');
  assert.ok(isoDate);
  assert.equal(isoDate.toISOString(), '2026-11-13T21:14:00.000Z');

  const unixSec = parseFlexibleTimestamp(1763000000);
  assert.ok(unixSec);
  assert.equal(unixSec.getUTCFullYear(), 2025);
});

test('extractIocTimelineEvents orders chronological activity events from oldest to newest', () => {
  const results: LookupResult[] = [
    makeResult({
      source: 'AbuseIPDB',
      sourceId: 'abuseipdb',
      indicator: '1.2.3.4',
      type: 'ip',
      details: { 'Last Reported': '2026-11-14T21:14:00+00:00' },
    }),
    makeResult({
      source: 'ThreatFox (abuse.ch)',
      sourceId: 'threatfox',
      indicator: 'evil.com',
      details: { 'First Seen': '2026-11-12 08:42:10 UTC' },
    }),
    makeResult({
      source: 'VirusTotal',
      sourceId: 'virustotal',
      indicator: 'evil.com',
      details: {
        'Creation Date': '2024-03-18 00:00 UTC',
        'Last Analysis': '2026-11-15 10:05 UTC',
      },
    }),
    makeResult({
      source: 'AbuseIPDB',
      sourceId: 'abuseipdb',
      indicator: '8.8.8.8',
      type: 'ip',
      verdict: 'Clean',
      details: { 'Last Reported': 'Never' },
    }),
  ];

  const allEvents = extractIocTimelineEvents(results);
  assert.equal(allEvents.length, 4);
  assert.equal(allEvents[0].category, 'registered');
  assert.equal(allEvents[1].category, 'first_seen');
  assert.equal(allEvents[2].category, 'reported');
  assert.equal(allEvents[3].category, 'analysis');

  const evilOnly = extractIocTimelineEvents(results, { indicatorFilter: 'evil.com' });
  assert.equal(evilOnly.length, 3);
  assert.ok(evilOnly.every((e) => e.indicator === 'evil.com'));
});
