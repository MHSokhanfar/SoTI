import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildInvestigationCsvFilename,
  cleanIndicator,
  computeAbuseIpdbVerdict,
  computeOtxVerdict,
  computeVirusTotalVerdict,
  detectDefangPatterns,
  detectIndicatorType,
  extractRefangedUrl,
  parseIndicators,
  preprocessInputForLookup,
  refangInputPreservingUrls,
  serializeResultsToCsv,
  type LookupResult,
} from './indicators';

test('cleanIndicator refangs bracketed IPs, hxxp URLs, and extended defang patterns', () => {
  assert.equal(cleanIndicator('1[.]2[.]3[.]4'), '1.2.3.4');
  assert.equal(cleanIndicator('1(.)2(.)3(.)4'), '1.2.3.4');
  assert.equal(cleanIndicator('1{.}2{.}3{.}4'), '1.2.3.4');
  assert.equal(cleanIndicator('1\\.2\\.3\\.4'), '1.2.3.4');
  assert.equal(cleanIndicator('hxxp://evil[.]com/login?next=1'), 'evil.com');
  assert.equal(cleanIndicator('hXXps[://]c2[dot]bad[.]org[:]8443/beacon'), 'c2.bad.org');
  assert.equal(cleanIndicator('fxp://drop{dot}bad[.]net/payload'), 'drop.bad.net');
  assert.equal(cleanIndicator('user[at]phish[dot]example'), 'phish.example');
  assert.equal(extractRefangedUrl('hxxp://evil[.]com/login?next=1'), 'http://evil.com/login?next=1');
  assert.equal(extractRefangedUrl('8.8.8.8'), null);
});

test('detectDefangPatterns and preprocessInputForLookup detect and strip defangs before API dispatch', () => {
  const raw = '1[.]2[.]3[.]4, 8.8.8.8, hxxp://evil[dot]com/login, 192\\.168\\.1\\.1';
  const patterns = detectDefangPatterns(raw);
  assert.ok(patterns.includes('[.]'));
  assert.ok(patterns.includes('[dot]'));
  assert.ok(patterns.includes('hxxp'));
  assert.ok(patterns.includes('\\.'));

  const preprocessed = preprocessInputForLookup(raw);
  assert.equal(preprocessed.apiReadyInput, '1.2.3.4, 8.8.8.8, evil.com, 192.168.1.1');
  assert.equal(
    refangInputPreservingUrls(raw),
    '1.2.3.4, 8.8.8.8, http://evil.com/login, 192.168.1.1',
  );
  assert.equal(preprocessed.validIndicators.length, 4);
  assert.equal(preprocessed.invalidTokens.length, 0);
  assert.equal(preprocessed.defangedCount, 3);
  assert.ok(!preprocessed.apiReadyInput.includes('[.]'));
  assert.ok(!preprocessed.apiReadyInput.includes('hxxp'));
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

  const fixedNow = new Date('2026-11-15T04:15:09.000Z');
  assert.equal(
    buildInvestigationCsvFilename('All', fixedNow),
    'soti_investigation_20261115_041509.csv',
  );
  assert.equal(
    buildInvestigationCsvFilename('Malicious', fixedNow),
    'soti_investigation_malicious_20261115_041509.csv',
  );
});
