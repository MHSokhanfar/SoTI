import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildShareReportMessage,
  isShareSnapshotExpired,
  normalizeShareTtlHours,
  parseShareTokenFromUrl,
  type SharedReportSnapshot,
} from './reportSharing';

test('parseShareTokenFromUrl extracts valid share token from query string or hash', () => {
  assert.equal(parseShareTokenFromUrl('?share=abcDEF12_34-xy', ''), 'abcDEF12_34-xy');
  assert.equal(parseShareTokenFromUrl('', '#reports?share=token123456'), 'token123456');
  assert.equal(parseShareTokenFromUrl('?share=bad!token', ''), null);
  assert.equal(parseShareTokenFromUrl('', ''), null);
});

test('normalizeShareTtlHours and isShareSnapshotExpired enforce bounds and expiration', () => {
  assert.equal(normalizeShareTtlHours(0), 1);
  assert.equal(normalizeShareTtlHours(24), 24);
  assert.equal(normalizeShareTtlHours(500), 168);
  assert.equal(normalizeShareTtlHours('not-a-num'), 24);

  assert.equal(
    isShareSnapshotExpired('2026-11-16T00:00:00.000Z', new Date('2026-11-15T12:00:00.000Z')),
    false,
  );
  assert.equal(
    isShareSnapshotExpired('2026-11-15T00:00:00.000Z', new Date('2026-11-15T12:00:00.000Z')),
    true,
  );
});

test('buildShareReportMessage creates pre-populated clipboard message with stats, indicators, and temporary URL', () => {
  const snapshot: SharedReportSnapshot = {
    token: 'shareToken99',
    createdAt: '2026-11-15T10:00:00.000Z',
    expiresAt: '2026-11-16T10:00:00.000Z',
    ttlHours: 24,
    reportName: 'soti_20261115_100000.csv',
    searchQuery: '',
    verdictFilter: 'All',
    quickStats: {
      totalThreatsAnalyzed: 12,
      uniqueIndicatorsCount: 4,
      maliciousPercentage: 50,
      maliciousCount: 6,
      evaluatedVerdictsCount: 12,
    },
    totals: { runs: 3, malicious: 6, suspicious: 2, clean: 4, unknown: 0 },
    topIndicators: [
      {
        indicator: '1.2.3.4',
        type: 'ip',
        confidenceScore: 92,
        verdictSummary: 'Malicious',
      },
    ],
    executiveSummary: 'High confidence malicious C2 IP cluster observed.',
  };

  const msg = buildShareReportMessage(snapshot, 'http://localhost:3000/?share=shareToken99');
  assert.ok(msg.includes('soti_20261115_100000.csv'));
  assert.ok(msg.includes('1.2.3.4 (92/100, Malicious)'));
  assert.ok(msg.includes('http://localhost:3000/?share=shareToken99'));
  assert.ok(msg.includes('2026-11-16 10:00 UTC'));
});
