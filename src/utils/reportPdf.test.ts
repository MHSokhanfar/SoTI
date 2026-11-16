import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildDashboardSummaryPdfData,
  buildPdfDocumentData,
  buildPdfReportFilename,
  buildSummaryPdfFilename,
  extractTopMaliciousIndicators,
  mapDarkSvgColorToPdfLight,
  sanitizePdfCell,
} from './reportPdf';
import {
  buildHistoricalChartData,
  buildThreatAlertTrend30Days,
  computeIndicatorConfidenceMap,
  computeReportsQuickStats,
  type ReportMeta,
} from './reportsAnalytics';
import type { LookupResult } from './indicators';

test('sanitizePdfCell normalizes whitespace, handles blanks, and truncates cleanly', () => {
  assert.equal(sanitizePdfCell(''), '—');
  assert.equal(sanitizePdfCell(null), '—');
  assert.equal(sanitizePdfCell('  line1\n\tline2   end  '), 'line1 line2 end');
  assert.equal(sanitizePdfCell('abcdefghij', 6), 'abcde…');
});

test('buildPdfReportFilename formats selected run names and dates safely', () => {
  const fixedDate = new Date('2026-11-14T04:00:00Z');
  assert.equal(
    buildPdfReportFilename('soti_20261113_120000.csv', fixedDate),
    'soti_20261113_120000_report_2026-11-14.pdf',
  );
  assert.equal(
    buildPdfReportFilename('../odd file?.csv', fixedDate),
    'odd_file_report_2026-11-14.pdf',
  );
  assert.equal(
    buildPdfReportFilename(null, fixedDate),
    'soti_threat_report_2026-11-14.pdf',
  );
});

test('buildPdfDocumentData structures KPIs, historical runs, confidence scores, and active filters', () => {
  const reports: ReportMeta[] = [
    {
      name: 'soti_20261113_140000.csv',
      sizeBytes: 512,
      modifiedAt: '2026-11-13T14:00:00Z',
      rowCount: 3,
      verdicts: { malicious: 2, clean: 1, suspicious: 0, unknown: 0, other: 0 },
      indicators: ['1.2.3.4', 'evil.com', '8.8.8.8'],
    },
    {
      name: 'soti_20261112_100000.csv',
      sizeBytes: 400,
      modifiedAt: '2026-11-12T10:00:00Z',
      rowCount: 2,
      verdicts: { malicious: 0, clean: 2, suspicious: 0, unknown: 0, other: 0 },
      indicators: ['8.8.8.8', '1.1.1.1'],
    },
  ];

  const rows: Record<string, string>[] = [
    {
      indicator: '1.2.3.4',
      type: 'ip',
      source: 'VirusTotal',
      status: 'ok',
      verdict: 'Malicious',
      score: '12/90',
      summary: '12 security vendors flagged 1.2.3.4 as malicious',
    },
    {
      indicator: '1.2.3.4',
      type: 'ip',
      source: 'AbuseIPDB',
      status: 'ok',
      verdict: 'Malicious',
      score: '95%',
      summary: '95% abuse confidence score',
    },
    {
      indicator: '8.8.8.8',
      type: 'ip',
      source: 'VirusTotal',
      status: 'ok',
      verdict: 'Clean',
      score: '0/90',
      summary: 'No security vendors flagged 8.8.8.8',
    },
  ];

  const filteredRows = rows.filter((r) => r.verdict === 'Malicious');
  const confidenceMap = computeIndicatorConfidenceMap(rows);
  const quickStats = computeReportsQuickStats(reports);
  const { totals } = buildHistoricalChartData(reports);
  const { summary: trendSummary } = buildThreatAlertTrend30Days(
    reports,
    new Date('2026-11-13T18:00:00Z'),
  );

  const docData = buildPdfDocumentData({
    reports,
    filteredReports: [reports[0]],
    selectedName: 'soti_20261113_140000.csv',
    allRowsCount: rows.length,
    filteredRows,
    confidenceMap,
    searchQuery: '1.2.3.4',
    verdictFilter: 'Malicious',
    quickStats,
    totals,
    trendSummary,
    generatedAt: new Date('2026-11-14T04:15:00Z'),
  });

  assert.equal(docData.generatedDisplay, '2026-11-14 04:15 UTC');
  assert.match(docData.filterSummary, /Verdict: Malicious/);
  assert.match(docData.filterSummary, /Query: "1\.2\.3\.4"/);
  assert.equal(docData.runRows.length, 1);
  assert.equal(docData.runRows[0].selected, true);
  assert.equal(docData.indicatorRows.length, 2);
  assert.equal(docData.indicatorRows[0].verdictLabel, 'Malicious');
  assert.match(docData.indicatorRows[0].confidenceLabel, /81% \(2 src\)/);
});

test('mapDarkSvgColorToPdfLight maps dark theme chart colors to crisp light-paper ink', () => {
  assert.equal(mapDarkSvgColorToPdfLight('#1E293B'), '#e2e8f0');
  assert.equal(mapDarkSvgColorToPdfLight('#94A3B8'), '#475569');
  assert.equal(mapDarkSvgColorToPdfLight('rgb(15, 23, 42)'), '#ffffff');
  assert.equal(mapDarkSvgColorToPdfLight('#DC2626'), null);
});

test('buildSummaryPdfFilename generates a deterministic consolidated summary filename', () => {
  assert.equal(
    buildSummaryPdfFilename(new Date('2026-11-16T08:30:00Z')),
    'soti_risk_summary_2026-11-16.pdf',
  );
});

test('extractTopMaliciousIndicators ranks, deduplicates, and masks sensitive IOCs in Privacy Mode', () => {
  const allRunRows: Record<string, string>[] = [
    {
      indicator: '1.2.3.4',
      type: 'ip',
      source: 'VirusTotal',
      status: 'ok',
      verdict: 'Malicious',
      score: '20/90',
      summary: '20 vendors flagged 1.2.3.4 for C2 traffic',
    },
    {
      indicator: '1.2.3.4',
      type: 'ip',
      source: 'AbuseIPDB',
      status: 'ok',
      verdict: 'Malicious',
      score: '98%',
      summary: '98% abuse confidence for 1.2.3.4',
    },
    {
      indicator: '8.8.8.8',
      type: 'ip',
      source: 'VirusTotal',
      status: 'ok',
      verdict: 'Clean',
      score: '0/90',
      summary: 'Clean resolver',
    },
  ];

  const currentResults: LookupResult[] = [
    {
      source: 'AlienVault OTX',
      sourceId: 'alienvault',
      indicator: 'evil.com',
      originalToken: 'evil.com',
      type: 'domain',
      status: 'ok',
      verdict: 'Suspicious',
      score: '4 pulses',
      summary: 'Linked to phishing kit on evil.com',
      details: {},
      link: '',
    },
    // Duplicate of 1.2.3.4 from VirusTotal should be deduplicated
    {
      source: 'VirusTotal',
      sourceId: 'virustotal',
      indicator: '1.2.3.4',
      originalToken: '1.2.3.4',
      type: 'ip',
      status: 'ok',
      verdict: 'Malicious',
      score: '20/90',
      summary: '20 vendors flagged 1.2.3.4 for C2 traffic',
      details: {},
      link: '',
    },
  ];

  const top = extractTopMaliciousIndicators({
    allRunRows,
    currentResults,
    maxItems: 5,
    privacyMode: false,
  });

  assert.equal(top.length, 2);
  assert.equal(top[0].rank, 1);
  assert.equal(top[0].indicator, '1.2.3.4');
  assert.equal(top[0].verdictLabel, 'Malicious');
  assert.equal(top[0].hitCount, 2);
  assert.equal(top[1].indicator, 'evil.com');
  assert.equal(top[1].verdictLabel, 'Suspicious');

  const maskedTop = extractTopMaliciousIndicators({
    allRunRows,
    currentResults,
    maxItems: 5,
    privacyMode: true,
  });
  assert.equal(maskedTop[0].indicator, '[REDACTED-IP]');
  assert.match(maskedTop[0].summary, /\[REDACTED-IP\]/);
  assert.equal(maskedTop[1].indicator, '[REDACTED-DOMAIN]');
});

test('buildDashboardSummaryPdfData combines risk trendline, heatmap distributions, AI brief, and top threats', () => {
  const reports: ReportMeta[] = [
    {
      name: 'soti_20261115_120000.csv',
      sizeBytes: 640,
      modifiedAt: '2026-11-15T12:00:00Z',
      rowCount: 3,
      verdicts: { malicious: 2, clean: 1, suspicious: 0, unknown: 0, other: 0 },
      indicators: ['1.2.3.4', '8.8.8.8'],
    },
  ];

  const allRunRows: Record<string, string>[] = [
    {
      reportName: 'soti_20261115_120000.csv',
      indicator: '1.2.3.4',
      type: 'ip',
      source: 'VirusTotal',
      status: 'ok',
      verdict: 'Malicious',
      score: '18/90',
      summary: 'High confidence malware host 1.2.3.4',
    },
    {
      reportName: 'soti_20261115_120000.csv',
      indicator: '8.8.8.8',
      type: 'ip',
      source: 'VirusTotal',
      status: 'ok',
      verdict: 'Clean',
      score: '0/90',
      summary: 'No malicious detections',
    },
  ];

  const quickStats = computeReportsQuickStats(reports);
  const { totals } = buildHistoricalChartData(reports);
  const { series: trendSeries, summary: trendSummary } = buildThreatAlertTrend30Days(
    reports,
    new Date('2026-11-16T00:00:00Z'),
  );

  const summaryData = buildDashboardSummaryPdfData({
    reports,
    allRunRows,
    quickStats,
    totals,
    trendSeries,
    trendSummary,
    aiSummary: '## Executive Brief\nPrimary risk stems from **1.2.3.4** C2 activity.',
    privacyMode: true,
    generatedAt: new Date('2026-11-16T08:00:00Z'),
  });

  assert.equal(summaryData.generatedDisplay, '2026-11-16 08:00 UTC');
  assert.match(summaryData.scopeSummary, /1 archived run/);
  assert.match(summaryData.scopeSummary, /Privacy Mode Redacted/);
  assert.equal(summaryData.heatmapModel.uniqueEvaluatedIndicators, 2);
  assert.equal(summaryData.typeHeatmapModel.columns.length, 3);
  assert.equal(summaryData.topMaliciousIndicators[0].indicator, '[REDACTED-IP]');
  assert.match(summaryData.aiSummaryExcerpt || '', /\[REDACTED-IP\]/);
  assert.ok(summaryData.recentTrendPoints.length >= 1);
});

