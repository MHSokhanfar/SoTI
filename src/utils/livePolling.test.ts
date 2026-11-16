import assert from 'node:assert/strict';
import test from 'node:test';
import type { LookupResult } from './indicators';
import {
  computeLivePollDelta,
  DEFAULT_LIVE_POLL_SECONDS,
  extractActiveIndicatorsForPolling,
  formatLiveCountdown,
  formatUtcClockTime,
  normalizeLivePollInterval,
} from './livePolling';

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
    summary: 'Clean',
    details: {},
    link: '',
    ...overrides,
  };
}

test('normalizeLivePollInterval validates allowed intervals and falls back safely', () => {
  assert.equal(normalizeLivePollInterval(15), 15);
  assert.equal(normalizeLivePollInterval('60'), 60);
  assert.equal(normalizeLivePollInterval(300), 300);
  assert.equal(normalizeLivePollInterval(42), DEFAULT_LIVE_POLL_SECONDS);
  assert.equal(normalizeLivePollInterval(null), DEFAULT_LIVE_POLL_SECONDS);
});

test('extractActiveIndicatorsForPolling prefers active results and falls back to parsed input', () => {
  const active = extractActiveIndicatorsForPolling(
    [
      makeResult({ indicator: '1.2.3.4', sourceId: 'virustotal' }),
      makeResult({ indicator: '1.2.3.4', sourceId: 'abuseipdb' }),
      makeResult({ indicator: 'evil.com', sourceId: 'virustotal', type: 'domain' }),
    ],
    '8.8.8.8',
  );
  assert.deepEqual(active, ['1.2.3.4', 'evil.com']);

  const fromInput = extractActiveIndicatorsForPolling([], '1[.]2[.]3[.]4\n8.8.8.8\ninvalid');
  assert.deepEqual(fromInput, ['1.2.3.4', '8.8.8.8']);
});

test('formatLiveCountdown and formatUtcClockTime render deterministic tabular strings', () => {
  assert.equal(formatLiveCountdown(0), '0s');
  assert.equal(formatLiveCountdown(28.2), '29s');
  assert.equal(formatLiveCountdown(65), '1m 05s');
  assert.equal(formatLiveCountdown(300), '5m 00s');

  const sampleEpoch = Date.UTC(2026, 10, 16, 3, 15, 7);
  assert.equal(formatUtcClockTime(sampleEpoch), '03:15:07 UTC');
});

test('computeLivePollDelta detects verdict escalations and score updates cleanly', () => {
  const prev = [
    makeResult({ indicator: '1.2.3.4', verdict: 'Clean', score: '0/90' }),
    makeResult({ indicator: '8.8.8.8', verdict: 'Clean', score: '0/90' }),
  ];
  const next = [
    makeResult({ indicator: '1.2.3.4', verdict: 'Malicious', score: '12/90' }),
    makeResult({ indicator: '8.8.8.8', verdict: 'Clean', score: '0/90' }),
  ];

  const delta = computeLivePollDelta(prev, next, '2026-11-16T03:15:07.000Z');
  assert.deepEqual(delta, {
    changedCount: 1,
    escalatedCount: 1,
    totalResults: 2,
    checkedAtIso: '2026-11-16T03:15:07.000Z',
  });
});
