import test from 'node:test';
import assert from 'node:assert/strict';
import * as d3 from 'd3';
import type { LookupResult } from './indicators';
import {
  aggregateThreatLandscape,
  resolveCountryGeo,
  WORLD_LAND_GEOJSON,
} from './threatLandscape';

function makeResult(overrides: Partial<LookupResult> = {}): LookupResult {
  return {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: '1.2.3.4',
    originalToken: '1.2.3.4',
    type: 'ip',
    status: 'ok',
    verdict: 'Malicious',
    score: '30/90',
    summary: 'Malicious detections',
    details: {},
    link: '',
    ...overrides,
  };
}

test('resolveCountryGeo normalizes codes, aliases, and invalid markers cleanly', () => {
  assert.equal(resolveCountryGeo('RU')?.countryName, 'Russia');
  assert.equal(resolveCountryGeo('United States')?.code, 'US');
  assert.equal(resolveCountryGeo('Netherlands')?.code, 'NL');
  assert.equal(resolveCountryGeo('UK')?.code, 'GB');
  assert.equal(resolveCountryGeo('N/A'), null);
  assert.equal(resolveCountryGeo(''), null);
});

test('WORLD_LAND_GEOJSON renders valid paths via d3.geoNaturalEarth1 without external network dependencies', () => {
  const projection = d3.geoNaturalEarth1().fitExtent(
    [
      [10, 10],
      [630, 310],
    ],
    WORLD_LAND_GEOJSON as unknown as d3.GeoPermissibleObjects,
  );
  const pathGen = d3.geoPath(projection);
  for (const feature of WORLD_LAND_GEOJSON.features) {
    const area = d3.geoArea(feature as unknown as d3.GeoPermissibleObjects);
    assert.ok(
      area > 0.001 && area < Math.PI,
      `Expected small positive spherical area (< PI) for ${feature.id}, got ${area}`,
    );
    const d = pathGen(feature as unknown as d3.GeoPermissibleObjects);
    assert.ok(d && d.startsWith('M'), `Expected valid SVG path for ${feature.id}`);
  }
});

test('aggregateThreatLandscape clusters high-confidence IOCs by country and macro-region', () => {
  const results: LookupResult[] = [
    // Critical RU IP #1
    makeResult({
      source: 'VirusTotal',
      sourceId: 'virustotal',
      indicator: '185.220.101.5',
      verdict: 'Malicious',
      score: '45/90',
      details: { Malicious: 45, 'Total Engines': 90, Country: 'RU', ASN: 'AS49590 Selectel' },
    }),
    makeResult({
      source: 'AbuseIPDB',
      sourceId: 'abuseipdb',
      indicator: '185.220.101.5',
      verdict: 'Malicious',
      score: '98%',
      details: { Confidence: '98%', Country: 'RU' },
    }),
    // Critical RU IP #2
    makeResult({
      source: 'AbuseIPDB',
      sourceId: 'abuseipdb',
      indicator: '91.199.212.40',
      verdict: 'Malicious',
      score: '92%',
      details: { Confidence: '92%', Country: 'Russia' },
    }),
    // High DE IP #3 (score 62 -> High tier 50..74, included in high_confidence, excluded from critical_only)
    makeResult({
      source: 'AbuseIPDB',
      sourceId: 'abuseipdb',
      indicator: '45.95.147.200',
      verdict: 'Suspicious',
      score: '62%',
      details: { Confidence: '62%', Country: 'DE' },
    }),
    // Clean US IP #4 -> filtered out under high_confidence, included under all
    makeResult({
      source: 'VirusTotal',
      sourceId: 'virustotal',
      indicator: '8.8.8.8',
      verdict: 'Clean',
      score: '0/90',
      details: { Malicious: 0, 'Total Engines': 90, Country: 'United States' },
    }),
    // Critical domain without country -> counted in unattributedCount
    makeResult({
      source: 'VirusTotal',
      sourceId: 'virustotal',
      indicator: 'evil-c2.example',
      type: 'domain',
      verdict: 'Malicious',
      score: '55/90',
      details: { Malicious: 55, 'Total Engines': 90 },
    }),
  ];

  const highConf = aggregateThreatLandscape(results, {
    thresholdFilter: 'high_confidence',
  });

  assert.equal(highConf.totalEvaluatedIocs, 5);
  assert.equal(highConf.totalMatchedIocs, 4);
  assert.equal(highConf.geolocatedIocCount, 3);
  assert.equal(highConf.unattributedCount, 1);
  assert.equal(highConf.clusters.length, 2);

  assert.equal(highConf.topCluster?.countryCode, 'RU');
  assert.equal(highConf.topCluster?.count, 2);
  assert.equal(highConf.topCluster?.criticalCount, 2);
  assert.equal(highConf.topCluster?.dominantTier, 'Critical');
  assert.equal(highConf.clusters[1].countryCode, 'DE');
  assert.equal(highConf.clusters[1].count, 1);

  assert.equal(highConf.macroRegions[0].macroRegion, 'Eurasia');
  assert.equal(highConf.macroRegions[0].count, 2);

  const allTiers = aggregateThreatLandscape(results, { thresholdFilter: 'all' });
  assert.equal(allTiers.totalMatchedIocs, 5);
  assert.equal(allTiers.clusters.length, 3);
  assert.ok(allTiers.clusters.some((c) => c.countryCode === 'US'));

  const criticalOnly = aggregateThreatLandscape(results, {
    thresholdFilter: 'critical_only',
  });
  assert.equal(criticalOnly.clusters.length, 1);
  assert.equal(criticalOnly.clusters[0].countryCode, 'RU');
});
