import assert from 'node:assert/strict';
import test from 'node:test';
import type { LookupResult } from './indicators';
import {
  buildIocHeatmapMatrix,
  csvRowsToLookupResults,
  formatGeographicRegion,
  formatNetworkSegment,
} from './heatmapAnalytics';

function makeResult(overrides: Partial<LookupResult>): LookupResult {
  return {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: '1.2.3.4',
    originalToken: '1.2.3.4',
    type: 'ip',
    status: 'ok',
    verdict: 'Malicious',
    score: '20/90',
    summary: 'Malicious',
    details: { Country: 'RU', ASN: 49590, 'AS Owner': 'Selectel' },
    link: '',
    ...overrides,
  };
}

test('formatGeographicRegion and formatNetworkSegment normalize country codes and ASN/subnet labels', () => {
  assert.deepEqual(formatGeographicRegion('RU'), { code: 'RU', regionLabel: 'Eurasia · RU' });
  assert.deepEqual(formatGeographicRegion('United States'), {
    code: 'US',
    regionLabel: 'North America · US',
  });
  assert.deepEqual(formatGeographicRegion('N/A'), {
    code: null,
    regionLabel: 'Unattributed / Hash & Domain',
  });

  assert.equal(
    formatNetworkSegment('1.2.3.4', 'ip', [{ ASN: 49505, 'AS Owner': 'Selectel Ltd' }]),
    'AS49505 · Selectel Ltd',
  );
  assert.equal(
    formatNetworkSegment('198.51.100.42', 'ip', [{ 'Usage Type': 'Data Center/Web Hosting' }]),
    '198.51.0.0/16 (Data Center)',
  );
  assert.equal(
    formatNetworkSegment('evil.com', 'domain', []),
    'Domain Segment (.com)',
  );
});

test('buildIocHeatmapMatrix aggregates high-confidence IOCs across geographic regions and network segments', () => {
  const sampleResults: LookupResult[] = [
    makeResult({
      indicator: '1.2.3.4',
      sourceId: 'virustotal',
      source: 'VirusTotal',
      score: '25/90',
      details: { Malicious: 25, Suspicious: 0, 'Total Engines': 90, Country: 'RU', ASN: 49590, 'AS Owner': 'Selectel' },
    }),
    makeResult({
      indicator: '1.2.3.4',
      sourceId: 'abuseipdb',
      source: 'AbuseIPDB',
      score: '92%',
      details: { Country: 'DE', ISP: 'Stark Hosting' },
    }),
    makeResult({
      indicator: 'evil.com',
      type: 'domain',
      sourceId: 'threatfox',
      source: 'ThreatFox (abuse.ch)',
      score: '2 IOC match(es) · 95%',
      details: { Confidence: '95%', Country: 'RU', ASN: 'AS49505 Selectel' },
    }),
    makeResult({
      indicator: '8.8.8.8',
      sourceId: 'virustotal',
      source: 'VirusTotal',
      verdict: 'Clean',
      score: '0/90',
      details: { Malicious: 0, Suspicious: 0, 'Total Engines': 90, Country: 'US', ASN: 15169, 'AS Owner': 'Google LLC' },
    }),
  ];

  // High-confidence filter (>= 50): includes 1.2.3.4 and evil.com, excludes 8.8.8.8
  const regionHeatmap = buildIocHeatmapMatrix(sampleResults, {
    dimension: 'region',
    thresholdFilter: 'high_confidence',
  });

  assert.equal(regionHeatmap.totalEvaluatedIocs, 3);
  assert.equal(regionHeatmap.totalHighConfidenceIocs, 2);
  assert.deepEqual(regionHeatmap.columns, ['Critical', 'High']);
  assert.ok(regionHeatmap.rows.some((r) => r.key === 'Eurasia · RU' && r.criticalCount === 2));
  assert.ok(regionHeatmap.rows.some((r) => r.key === 'Western Europe · DE' && r.criticalCount === 1));
  assert.equal(regionHeatmap.rows.some((r) => r.key === 'North America · US'), false);

  // Switching to "all" tiers should include US / Google LLC clean bucket under Low
  const allTiersNetHeatmap = buildIocHeatmapMatrix(sampleResults, {
    dimension: 'network',
    thresholdFilter: 'all',
  });
  assert.deepEqual(allTiersNetHeatmap.columns, ['Critical', 'High', 'Medium', 'Low']);
  assert.ok(allTiersNetHeatmap.rows.some((r) => r.key.includes('AS15169')));
});

test('csvRowsToLookupResults converts CSV rows with JSON details safely', () => {
  const rows: Record<string, string>[] = [
    {
      source: 'VirusTotal',
      indicator: '1.2.3.4',
      type: 'ip',
      status: 'ok',
      verdict: 'Malicious',
      score: '15/90',
      summary: '15 malicious',
      details: JSON.stringify({ Country: 'DE', ASN: 12345 }),
      link: 'https://example.com',
    },
  ];
  const converted = csvRowsToLookupResults(rows);
  assert.equal(converted.length, 1);
  assert.equal(converted[0].sourceId, 'virustotal');
  assert.equal(converted[0].details.Country, 'DE');
});
