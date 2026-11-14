import test from 'node:test';
import assert from 'node:assert/strict';
import {
  cleanIndicator,
  computeAbuseIpdbVerdict,
  computeOtxVerdict,
  computeVirusTotalVerdict,
  detectIndicatorType,
  parseIndicators,
  serializeResultsToCsv,
  type LookupResult,
} from './indicators';

test('cleanIndicator refangs bracketed IPs, hxxp URLs, and ports', () => {
  assert.equal(cleanIndicator('1[.]2[.]3[.]4'), '1.2.3.4');
  assert.equal(cleanIndicator('1(.)2(.)3(.)4'), '1.2.3.4');
  assert.equal(cleanIndicator('hxxp://evil[.]com/login?next=1'), 'evil.com');
  assert.equal(cleanIndicator('hxxps[://]c2[dot]bad[.]org[:]8443/beacon'), 'c2.bad.org');
});

test('detectIndicatorType distinguishes IPv4, IPv6, MD5, SHA1, SHA256, domain, and invalid', () => {
  assert.equal(detectIndicatorType('8.8.8.8'), 'ip');
  assert.equal(detectIndicatorType('2001:4860:4860::8888'), 'ip');
  assert.equal(detectIndicatorType('44d88612fea8a8f36de82e1278abb02f'), 'hash');
  assert.equal(detectIndicatorType('356a192b7913b04c54574d18c28d46e6395428ab'), 'hash');
  assert.equal(
    detectIndicatorType('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'),
    'hash',
  );
  assert.equal(detectIndicatorType('sub.example.com'), 'domain');
  assert.equal(detectIndicatorType('not_valid_ioc'), null);
});

test('parseIndicators splits comma/space/semicolon and deduplicates', () => {
  const parsed = parseIndicators('1[.]2[.]3[.]4, 1.2.3.4; hxxp://evil[.]com bad_value');
  assert.equal(parsed.length, 3);
  assert.deepEqual(
    parsed.map((p) => [p.cleaned, p.type]),
    [
      ['1.2.3.4', 'ip'],
      ['evil.com', 'domain'],
      ['bad_value', null],
    ],
  );
});

test('verdict thresholds match VirusTotal, AbuseIPDB, and OTX specifications', () => {
  assert.equal(computeVirusTotalVerdict(5, 0, 90), 'Malicious');
  assert.equal(computeVirusTotalVerdict(1, 0, 90), 'Suspicious');
  assert.equal(computeVirusTotalVerdict(0, 2, 90), 'Suspicious');
  assert.equal(computeVirusTotalVerdict(0, 0, 90), 'Clean');
  assert.equal(computeVirusTotalVerdict(0, 0, 0), 'Unknown');

  assert.equal(computeAbuseIpdbVerdict(75), 'Malicious');
  assert.equal(computeAbuseIpdbVerdict(40), 'Suspicious');
  assert.equal(computeAbuseIpdbVerdict(10), 'Clean');

  assert.equal(computeOtxVerdict(5), 'Malicious');
  assert.equal(computeOtxVerdict(2), 'Suspicious');
  assert.equal(computeOtxVerdict(0), 'Unknown');
});

test('serializeResultsToCsv produces UTF-8 BOM Excel-safe CSV', () => {
  const sample: LookupResult[] = [
    {
      source: 'VirusTotal',
      sourceId: 'virustotal',
      indicator: '8.8.8.8',
      originalToken: '8.8.8.8',
      type: 'ip',
      status: 'ok',
      verdict: 'Clean',
      score: '0/90',
      summary: '0 malicious, 0 suspicious out of 90 engines',
      details: { Country: 'US' },
      link: 'https://www.virustotal.com/gui/ip-address/8.8.8.8',
    },
  ];
  const csvText = serializeResultsToCsv(sample, '2026-11-14T03:30:00');
  assert.ok(csvText.startsWith('\ufefftimestamp,source,indicator'));
  assert.ok(csvText.includes('VirusTotal,8.8.8.8,ip,ok,Clean,0/90'));
});
