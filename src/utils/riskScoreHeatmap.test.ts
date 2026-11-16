import test from 'node:test';
import assert from 'node:assert/strict';
import type { ReportMeta } from './reportsAnalytics';
import {
  buildRiskScoreHeatmap,
  classifyRiskBand,
  formatShortRunTimestampLabel,
} from './riskScoreHeatmap';

const SAMPLE_REPORTS: ReportMeta[] = [
  {
    name: 'soti_20261116_050000.csv',
    sizeBytes: 1200,
    modifiedAt: '2026-11-16T05:00:00.000Z',
    rowCount: 6,
    verdicts: { malicious: 3, clean: 2, suspicious: 1, unknown: 0, other: 0 },
  },
  {
    name: 'soti_20261115_120000.csv',
    sizeBytes: 900,
    modifiedAt: '2026-11-15T12:00:00.000Z',
    rowCount: 4,
    verdicts: { malicious: 0, clean: 3, suspicious: 1, unknown: 0, other: 0 },
  },
];

const SAMPLE_ALL_ROWS: Record<string, string>[] = [
  // Run 1 (oldest): soti_20261115_120000.csv -> 1 Medium (evil-check.com), 1 Low (8.8.8.8)
  {
    reportName: 'soti_20261115_120000.csv',
    source: 'VirusTotal',
    indicator: '8.8.8.8',
    type: 'ip',
    status: 'ok',
    verdict: 'Clean',
    score: '0/90',
    summary: 'Clean DNS resolver',
    details: JSON.stringify({ Malicious: 0, Suspicious: 0, 'Total Engines': 90 }),
  },
  {
    reportName: 'soti_20261115_120000.csv',
    source: 'VirusTotal',
    indicator: 'suspicious.example',
    type: 'domain',
    status: 'ok',
    verdict: 'Suspicious',
    score: '1/90',
    summary: '1 engine flagged',
    details: JSON.stringify({ Malicious: 1, Suspicious: 0, 'Total Engines': 90 }),
  },
  // Run 2 (newest): soti_20261116_050000.csv -> 1 High (1.2.3.4), 1 Critical/High (44d8...hash), 1 Low (1.1.1.1)
  {
    reportName: 'soti_20261116_050000.csv',
    source: 'VirusTotal',
    indicator: '1.2.3.4',
    type: 'ip',
    status: 'ok',
    verdict: 'Malicious',
    score: '18/90',
    summary: '18 engines flagged',
    details: JSON.stringify({ Malicious: 18, Suspicious: 0, 'Total Engines': 90 }),
  },
  {
    reportName: 'soti_20261116_050000.csv',
    source: 'AbuseIPDB',
    indicator: '1.2.3.4',
    type: 'ip',
    status: 'ok',
    verdict: 'Malicious',
    score: '92%',
    summary: '92% abuse confidence',
    details: JSON.stringify({ 'Abuse Confidence Score': 92 }),
  },
  {
    reportName: 'soti_20261116_050000.csv',
    source: 'VirusTotal',
    indicator: '44d88612fea8a8f36de82e1278abb02f',
    type: 'hash',
    status: 'ok',
    verdict: 'Malicious',
    score: '63/74',
    summary: '63 engines flagged',
    details: JSON.stringify({ Malicious: 63, Suspicious: 0, 'Total Engines': 74 }),
  },
  {
    reportName: 'soti_20261116_050000.csv',
    source: 'AbuseIPDB',
    indicator: '1.1.1.1',
    type: 'ip',
    status: 'ok',
    verdict: 'Clean',
    score: '0%',
    summary: 'Clean resolver',
    details: JSON.stringify({ 'Abuse Confidence Score': 0 }),
  },
];

test('classifyRiskBand maps score ranges into High (>=50), Medium (25-49), and Low (0-24)', () => {
  assert.equal(classifyRiskBand(95), 'High');
  assert.equal(classifyRiskBand(50), 'High');
  assert.equal(classifyRiskBand(49), 'Medium');
  assert.equal(classifyRiskBand(25), 'Medium');
  assert.equal(classifyRiskBand(24), 'Low');
  assert.equal(classifyRiskBand(0), 'Low');
  assert.equal(classifyRiskBand(null), null);
});

test('formatShortRunTimestampLabel extracts compact MM/DD HH:MM label from soti report filename', () => {
  assert.equal(formatShortRunTimestampLabel('soti_20261116_050000.csv'), '11/16 05:00');
});

test('buildRiskScoreHeatmap aggregates High/Medium/Low distribution across chronological investigations', () => {
  const model = buildRiskScoreHeatmap({
    reports: SAMPLE_REPORTS,
    allRunRows: SAMPLE_ALL_ROWS,
    mode: 'investigations',
  });

  assert.equal(model.totalInvestigationsProcessed, 2);
  assert.equal(model.columns.length, 2);
  // Oldest first: soti_20261115_120000.csv then soti_20261116_050000.csv
  assert.equal(model.columns[0].key, 'soti_20261115_120000.csv');
  assert.equal(model.columns[0].mediumCount, 1);
  assert.equal(model.columns[0].lowCount, 1);
  assert.equal(model.columns[0].highCount, 0);

  assert.equal(model.columns[1].key, 'soti_20261116_050000.csv');
  assert.equal(model.columns[1].highCount, 2);
  assert.equal(model.columns[1].lowCount, 1);

  assert.equal(model.totalEvaluatedIndicators, 5);
  assert.equal(model.bandSummary.High.count, 2);
  assert.equal(model.bandSummary.Medium.count, 1);
  assert.equal(model.bandSummary.Low.count, 2);
  assert.equal(model.bandSummary.High.percentage, 40);
  assert.equal(model.bandSummary.Medium.percentage, 20);
  assert.equal(model.bandSummary.Low.percentage, 40);
  assert.equal(model.postureRating, 'Critical');
});

test('buildRiskScoreHeatmap groups across IP, Domain, and Hash in indicator_type mode', () => {
  const model = buildRiskScoreHeatmap({
    reports: SAMPLE_REPORTS,
    allRunRows: SAMPLE_ALL_ROWS,
    mode: 'indicator_type',
  });

  assert.equal(model.columns.length, 3);
  const ipCol = model.columns.find((c) => c.key === 'ip');
  const domainCol = model.columns.find((c) => c.key === 'domain');
  const hashCol = model.columns.find((c) => c.key === 'hash');

  assert.equal(ipCol?.highCount, 1);
  assert.equal(ipCol?.lowCount, 2);
  assert.equal(domainCol?.mediumCount, 1);
  assert.equal(hashCol?.highCount, 1);
});

test('buildRiskScoreHeatmap falls back cleanly to active currentResults when CSV archive is empty', () => {
  const model = buildRiskScoreHeatmap({
    reports: [],
    allRunRows: [],
    currentResults: [
      {
        source: 'AbuseIPDB',
        sourceId: 'abuseipdb',
        indicator: '1.2.3.4',
        originalToken: '1.2.3.4',
        type: 'ip',
        status: 'ok',
        verdict: 'Malicious',
        score: '88%',
        summary: 'Malicious',
        details: { 'Abuse Confidence Score': 88 },
        link: '',
      },
    ],
  });

  assert.equal(model.totalInvestigationsProcessed, 1);
  assert.equal(model.bandSummary.High.count, 1);
  assert.equal(model.bandSummary.High.percentage, 100);
});
