import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildPdfDocumentData,
  buildPdfReportFilename,
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

