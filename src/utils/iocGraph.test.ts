import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildIocGraphData,
  formatIocClipboardText,
  formatIocGroupClipboardText,
} from './iocGraph';
import type { LookupResult } from './indicators';

const SAMPLE_RESULTS: LookupResult[] = [
  {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: '1.2.3.4',
    originalToken: '1[.]2[.]3[.]4',
    type: 'ip',
    status: 'ok',
    verdict: 'Malicious',
    score: '18/91',
    summary: '18 malicious, 1 suspicious out of 91 engines',
    details: {
      ASN: 49505,
      'AS Owner': 'Selectel',
      'Communicating File': '44d88612fea8a8f36de82e1278abb02f',
    },
    link: 'https://www.virustotal.com/gui/ip-address/1.2.3.4',
  },
  {
    source: 'AbuseIPDB',
    sourceId: 'abuseipdb',
    indicator: '1.2.3.4',
    originalToken: '1[.]2[.]3[.]4',
    type: 'ip',
    status: 'ok',
    verdict: 'Malicious',
    score: '95%',
    summary: '45 reports in last 90 days',
    details: {
      Domain: 'hosting-node.example',
      ISP: 'Stark Industries',
    },
    link: 'https://www.abuseipdb.com/check/1.2.3.4',
  },
  {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: 'evil.com',
    originalToken: 'hxxp://evil[.]com/login',
    type: 'domain',
    status: 'ok',
    verdict: 'Malicious',
    score: '22/91',
    summary: '22 malicious, 2 suspicious out of 91 engines',
    details: {
      'Resolved IP': '1.2.3.4',
      'Communicating File': '44d88612fea8a8f36de82e1278abb02f',
    },
    link: 'https://www.virustotal.com/gui/domain/evil.com',
  },
  {
    source: 'AlienVault OTX',
    sourceId: 'alienvault',
    indicator: 'evil.com',
    originalToken: 'hxxp://evil[.]com/login',
    type: 'domain',
    status: 'ok',
    verdict: 'Malicious',
    score: '10 pulses',
    summary: 'Found in 10 OTX pulse(s)',
    details: {
      'Malware Families': 'LummaStealer, CobaltStrike',
    },
    link: 'https://otx.alienvault.com/indicator/domain/evil.com',
  },
  {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: '44d88612fea8a8f36de82e1278abb02f',
    originalToken: '44d88612fea8a8f36de82e1278abb02f',
    type: 'hash',
    status: 'ok',
    verdict: 'Malicious',
    score: '62/91',
    summary: '62 malicious, 0 suspicious out of 91 engines',
    details: {
      Name: 'eicar.com',
      'Threat Label': 'eicar.test.file',
      'Contacted Domain': 'evil.com',
      'Contacted IP': '1.2.3.4',
    },
    link: 'https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f',
  },
];

test('buildIocGraphData connects queried IPs, domains, files, infra, and malware without duplicate IOC nodes', () => {
  const graph = buildIocGraphData(SAMPLE_RESULTS);

  assert.deepEqual(graph.queriedIndicators, [
    '1.2.3.4',
    'evil.com',
    '44d88612fea8a8f36de82e1278abb02f',
  ]);

  const ipNode = graph.nodes.find((n) => n.id === 'ip:1.2.3.4');
  assert.ok(ipNode);
  assert.equal(ipNode.queried, true);
  assert.deepEqual(ipNode.sources, ['VirusTotal', 'AbuseIPDB']);

  const fileNode = graph.nodes.find((n) => n.id === 'file:44d88612fea8a8f36de82e1278abb02f');
  assert.ok(fileNode);
  assert.equal(fileNode.subLabel, 'eicar.com');

  const hostingDomain = graph.nodes.find((n) => n.id === 'domain:hosting-node.example');
  assert.ok(hostingDomain);
  assert.equal(hostingDomain.queried, false);

  const asnNode = graph.nodes.find((n) => n.id === 'infra:as49505');
  assert.ok(asnNode);
  assert.equal(asnNode.label, 'AS49505');

  const malwareNodes = graph.nodes.filter((n) => n.type === 'malware');
  assert.equal(malwareNodes.length, 3);

  assert.ok(
    graph.links.some(
      (l) =>
        l.sourceId === 'domain:evil.com' &&
        l.targetId === 'ip:1.2.3.4' &&
        l.relation === 'resolves_to',
    ),
  );
  assert.ok(
    graph.links.some(
      (l) =>
        l.sourceId === 'ip:1.2.3.4' &&
        l.targetId === 'file:44d88612fea8a8f36de82e1278abb02f' &&
        l.relation === 'communicates_with',
    ),
  );
  assert.ok(
    graph.links.some(
      (l) =>
        l.sourceId === 'file:44d88612fea8a8f36de82e1278abb02f' &&
        l.targetId === 'domain:evil.com' &&
        l.relation === 'communicates_with',
    ),
  );
});

test('buildIocGraphData focusIndicator scopes to the focused IOC neighborhood', () => {
  const withIsolatedClean: LookupResult[] = [
    ...SAMPLE_RESULTS,
    {
      source: 'VirusTotal',
      sourceId: 'virustotal',
      indicator: '8.8.8.8',
      originalToken: '8.8.8.8',
      type: 'ip',
      status: 'ok',
      verdict: 'Clean',
      score: '0/91',
      summary: '0 malicious, 0 suspicious out of 91 engines',
      details: { ASN: 15169, 'AS Owner': 'Google LLC' },
      link: 'https://www.virustotal.com/gui/ip-address/8.8.8.8',
    },
  ];

  const scoped = buildIocGraphData(withIsolatedClean, { focusIndicator: '8.8.8.8' });
  const ids = new Set(scoped.nodes.map((n) => n.id));
  assert.ok(ids.has('ip:8.8.8.8'));
  assert.ok(ids.has('infra:as15169'));
  assert.equal(ids.has('domain:evil.com'), false);
  assert.equal(ids.has('ip:1.2.3.4'), false);
});

test('buildIocGraphData ignores N/A, None, and ASNone metadata values and merges matching ASNs', () => {
  const minimal: LookupResult[] = [
    {
      source: 'VirusTotal',
      sourceId: 'virustotal',
      indicator: '8.8.8.8',
      originalToken: '8.8.8.8',
      type: 'ip',
      status: 'ok',
      verdict: 'Clean',
      score: '0/91',
      summary: '0 malicious',
      details: { ASN: 15169 },
      link: '',
    },
    {
      source: 'AlienVault OTX',
      sourceId: 'alienvault',
      indicator: '8.8.8.8',
      originalToken: '8.8.8.8',
      type: 'ip',
      status: 'ok',
      verdict: 'Clean',
      score: '0 pulses',
      summary: '0 pulses',
      details: { ASN: 'AS15169 Google LLC' },
      link: '',
    },
    {
      source: 'AbuseIPDB',
      sourceId: 'abuseipdb',
      indicator: '198.51.100.5',
      originalToken: '198.51.100.5',
      type: 'ip',
      status: 'ok',
      verdict: 'Clean',
      score: '0%',
      summary: '0 reports',
      details: { Domain: 'N/A', ISP: 'None', ASN: 'ASNone' },
      link: '',
    },
  ];
  const graph = buildIocGraphData(minimal);
  const infraNodes = graph.nodes.filter((n) => n.type === 'infra');
  assert.equal(infraNodes.length, 1);
  assert.equal(infraNodes[0].id, 'infra:as15169');
  assert.equal(infraNodes[0].label, 'AS15169 Google LLC');
});

test('formatIocClipboardText and formatIocGroupClipboardText produce concise analyst payloads', () => {
  const single = formatIocClipboardText(SAMPLE_RESULTS[0]);
  assert.equal(
    single,
    '1.2.3.4 [IP] | VirusTotal: Malicious (18/91) | 18 malicious, 1 suspicious out of 91 engines | https://www.virustotal.com/gui/ip-address/1.2.3.4',
  );

  const grouped = formatIocGroupClipboardText('1.2.3.4', 'ip', SAMPLE_RESULTS.slice(0, 2));
  assert.ok(grouped.startsWith('1.2.3.4 [IP]\n- VirusTotal: Malicious (18/91)'));
  assert.ok(grouped.includes('- AbuseIPDB: Malicious (95%)'));
});
