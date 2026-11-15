import assert from 'node:assert/strict';
import test from 'node:test';
import type { LookupResult } from './indicators';
import {
  classifyConfidenceRiskLevel,
  computeAllIocConfidenceScores,
  computeIocConfidenceScore,
  normalizeProviderRiskScore,
} from './riskScoring';

function makeResult(overrides: Partial<LookupResult>): LookupResult {
  return {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: '1.2.3.4',
    originalToken: '1.2.3.4',
    type: 'ip',
    status: 'ok',
    verdict: 'Malicious',
    score: '10/90',
    summary: 'summary',
    details: {},
    link: '',
    ...overrides,
  };
}

test('normalizeProviderRiskScore handles all active intelligence providers', () => {
  const vtMal = normalizeProviderRiskScore(
    makeResult({
      sourceId: 'virustotal',
      source: 'VirusTotal',
      score: '20/90',
      details: { Malicious: 20, Suspicious: 2, 'Total Engines': 90 },
    }),
  );
  assert.ok(vtMal && vtMal.score >= 80 && vtMal.weightMultiplier === 1);

  const vtClean = normalizeProviderRiskScore(
    makeResult({
      sourceId: 'virustotal',
      source: 'VirusTotal',
      verdict: 'Clean',
      score: '0/90',
      details: { Malicious: 0, Suspicious: 0, 'Total Engines': 90 },
    }),
  );
  assert.equal(vtClean?.score, 0);

  const abuse = normalizeProviderRiskScore(
    makeResult({
      sourceId: 'abuseipdb',
      source: 'AbuseIPDB',
      score: '92%',
    }),
  );
  assert.equal(abuse?.score, 92);

  const tf = normalizeProviderRiskScore(
    makeResult({
      sourceId: 'threatfox',
      source: 'ThreatFox (abuse.ch)',
      score: '3 IOC match(es) · 95%',
      details: { Confidence: '95%' },
    }),
  );
  assert.equal(tf?.score, 95);

  const urlscan = normalizeProviderRiskScore(
    makeResult({
      sourceId: 'urlscan',
      source: 'urlscan.io',
      score: '4/10 scans',
      details: { 'Flagged Malicious': 4, 'Total Scans': 10, 'Verdict Score': '85/100' },
    }),
  );
  assert.ok(urlscan && urlscan.score >= 85);

  const otx = normalizeProviderRiskScore(
    makeResult({
      sourceId: 'alienvault',
      source: 'AlienVault OTX',
      score: '15 pulses',
    }),
  );
  assert.ok(otx && otx.score >= 75);

  const shodan = normalizeProviderRiskScore(
    makeResult({
      sourceId: 'shodan',
      source: 'Shodan',
      verdict: 'Suspicious',
      score: '4 ports / 2 CVEs',
    }),
  );
  assert.ok(shodan && shodan.score >= 60);

  // Unsupported and error entries are excluded
  assert.equal(
    normalizeProviderRiskScore(makeResult({ sourceId: 'abuseipdb', status: 'unsupported', score: 'N/A' })),
    null,
  );
  assert.equal(
    normalizeProviderRiskScore(makeResult({ sourceId: 'threatfox', status: 'error', score: 'N/A' })),
    null,
  );
});

test('computeIocConfidenceScore aggregates weights across all active providers without overwriting extra sources', () => {
  const multiProviderResults: LookupResult[] = [
    makeResult({
      source: 'VirusTotal',
      sourceId: 'virustotal',
      verdict: 'Malicious',
      score: '15/90',
      details: { Malicious: 15, Suspicious: 1, 'Total Engines': 90 },
    }),
    makeResult({
      source: 'AbuseIPDB',
      sourceId: 'abuseipdb',
      verdict: 'Malicious',
      score: '90%',
    }),
    makeResult({
      source: 'AlienVault OTX',
      sourceId: 'alienvault',
      verdict: 'Malicious',
      score: '12 pulses',
    }),
    makeResult({
      source: 'ThreatFox (abuse.ch)',
      sourceId: 'threatfox',
      verdict: 'Malicious',
      score: '2 IOC match(es) · 95%',
      details: { Confidence: '95%' },
    }),
    makeResult({
      source: 'urlscan.io',
      sourceId: 'urlscan',
      verdict: 'Malicious',
      score: '3/9 scans',
      details: { 'Flagged Malicious': 3, 'Total Scans': 9, 'Verdict Score': '85/100' },
    }),
  ];

  const summary = computeIocConfidenceScore('1.2.3.4', multiProviderResults);
  assert.equal(summary.activeProviderCount, 5);
  assert.equal(summary.breakdown.length, 5);
  assert.ok(summary.confidenceScore !== null && summary.confidenceScore >= 75);
  assert.equal(summary.riskLevel, 'Critical');

  const totalShare = summary.breakdown.reduce((acc, b) => acc + b.sharePercent, 0);
  assert.ok(totalShare >= 98 && totalShare <= 102);
});

test('computeAllIocConfidenceScores separates clean, malicious, and all-unsupported IOCs', () => {
  const results: LookupResult[] = [
    makeResult({
      indicator: '8.8.8.8',
      source: 'VirusTotal',
      sourceId: 'virustotal',
      verdict: 'Clean',
      score: '0/90',
      details: { Malicious: 0, Suspicious: 0, 'Total Engines': 90 },
    }),
    makeResult({
      indicator: '8.8.8.8',
      source: 'AbuseIPDB',
      sourceId: 'abuseipdb',
      verdict: 'Clean',
      score: '0%',
    }),
    makeResult({
      indicator: '8.8.8.8',
      source: 'ThreatFox (abuse.ch)',
      sourceId: 'threatfox',
      status: 'not_found',
      verdict: 'Unknown',
      score: '0 matches',
    }),
    makeResult({
      indicator: 'evil.com',
      type: 'domain',
      source: 'AbuseIPDB',
      sourceId: 'abuseipdb',
      status: 'unsupported',
      verdict: 'Unknown',
      score: 'N/A',
    }),
  ];

  const map = computeAllIocConfidenceScores(results);
  const cleanSummary = map.get('8.8.8.8');
  assert.ok(cleanSummary);
  assert.equal(cleanSummary.confidenceScore, 0);
  assert.equal(cleanSummary.riskLevel, 'Low');

  const unsupportedOnly = map.get('evil.com');
  assert.ok(unsupportedOnly);
  assert.equal(unsupportedOnly.confidenceScore, null);
  assert.equal(unsupportedOnly.riskLevel, 'Unknown');

  assert.equal(classifyConfidenceRiskLevel(80), 'Critical');
  assert.equal(classifyConfidenceRiskLevel(55), 'High');
  assert.equal(classifyConfidenceRiskLevel(30), 'Medium');
  assert.equal(classifyConfidenceRiskLevel(10), 'Low');
  assert.equal(classifyConfidenceRiskLevel(null), 'Unknown');
});
