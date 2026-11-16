import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildSessionSnapshotUrl,
  decodeSessionSnapshot,
  formatSnapshotPayloadSize,
  parseSessionSnapshotTokenFromLocation,
  stripSessionSnapshotFromUrl,
} from './sessionSnapshot';

test('buildSessionSnapshotUrl and decodeSessionSnapshot round-trip full investigation state and UTF-8 notes', () => {
  const built = buildSessionSnapshotUrl('http://localhost:3000/?share=old#investigate', {
    analysisMode: 'bulk',
    mode: 'sample',
    lastRunMode: 'sample',
    rawInput: '1[.]2[.]3[.]4\nevil.com',
    source: 'all',
    customSources: ['virustotal', 'abuseipdb', 'alienvault'],
    useCustomSources: false,
    includeThreatFox: true,
    includeUrlscan: false,
    invalidTokens: ['not_an_ioc'],
    quotaSkipped: [],
    lastReportFile: 'soti_20261116_110000.csv',
    researcherNotes: 'Confirmed C2 beacon — pivot to ASN 49505 🚨',
    indicatorTags: {
      '1.2.3.4': ['C2', 'Critical'],
      'unrelated.org': ['Ignored'],
    },
    verdictFilter: 'Malicious',
    riskThreshold: 50,
    tableSort: { key: 'riskScore', direction: 'desc' },
    createdAt: '2026-11-16T11:05:00.000Z',
    results: [
      {
        indicator: '1.2.3.4',
        originalToken: '1[.]2[.]3[.]4',
        type: 'ip',
        source: 'VirusTotal',
        sourceId: 'virustotal',
        status: 'ok',
        verdict: 'Malicious',
        score: '14 / 94',
        summary: '14 malicious detections',
        details: {
          Country: 'NL',
          'Last Seen': '2026-11-16 09:00 UTC',
          ASN: 'AS49505',
        },
        link: 'https://www.virustotal.com/gui/ip-address/1.2.3.4',
      },
      {
        indicator: 'evil.com',
        originalToken: 'evil.com',
        type: 'domain',
        source: 'AlienVault OTX',
        sourceId: 'alienvault',
        status: 'ok',
        verdict: 'Suspicious',
        score: '3 pulses',
        summary: '3 OTX pulses',
        details: { 'Pulse Count': 3 },
        link: '',
      },
    ],
  });

  assert.equal(built.url.startsWith('http://localhost:3000/#soti_snapshot=soti1.'), true);
  assert.equal(built.url.includes('?share=old'), false);

  const hashPart = `#${built.url.split('#')[1]}`;
  const extractedToken = parseSessionSnapshotTokenFromLocation('', hashPart);
  assert.equal(extractedToken, built.token);

  const decoded = decodeSessionSnapshot(extractedToken!);
  assert.ok(decoded);
  assert.equal(decoded.analysisMode, 'bulk');
  assert.equal(decoded.lastRunMode, 'sample');
  assert.equal(decoded.rawInput, '1[.]2[.]3[.]4\nevil.com');
  assert.equal(decoded.researcherNotes, 'Confirmed C2 beacon — pivot to ASN 49505 🚨');
  assert.deepEqual(decoded.indicatorTags, { '1.2.3.4': ['C2', 'Critical'] });
  assert.equal(decoded.verdictFilter, 'Malicious');
  assert.equal(decoded.riskThreshold, 50);
  assert.deepEqual(decoded.tableSort, { key: 'riskScore', direction: 'desc' });
  assert.equal(decoded.indicatorCount, 2);
  assert.equal(decoded.results.length, 2);
  assert.equal(decoded.results[0].details['Last Seen'], '2026-11-16 09:00 UTC');
  assert.equal(decoded.results[0].link, 'https://www.virustotal.com/gui/ip-address/1.2.3.4');

  const stripped = stripSessionSnapshotFromUrl(built.url);
  assert.equal(stripped, 'http://localhost:3000/');
});

test('decodeSessionSnapshot rejects malformed, empty, or wrong-prefix tokens cleanly', () => {
  assert.equal(decodeSessionSnapshot(''), null);
  assert.equal(decodeSessionSnapshot('other_prefix.abc'), null);
  assert.equal(decodeSessionSnapshot('soti1.!!!not_base64!!!'), null);
  assert.equal(formatSnapshotPayloadSize(512), '512 B');
  assert.equal(formatSnapshotPayloadSize(2048), '2.0 KB');
});
