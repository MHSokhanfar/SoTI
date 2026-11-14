import test from 'node:test';
import assert from 'node:assert/strict';
import {
  areAllVisibleReportsSelected,
  buildAggregatedCsvFilename,
  buildHistoricalChartData,
  buildPrintDocumentTitle,
  buildThreatAlertTrend30Days,
  computeIndicatorConfidenceMap,
  computeReportsQuickStats,
  DEFAULT_REPORTS_REFRESH_SECONDS,
  DEFAULT_TABLE_DENSITY,
  filterReportList,
  filterReportRows,
  formatRefreshIntervalLabel,
  getTableDensitySpec,
  normalizeRefreshIntervalSeconds,
  normalizeTableDensity,
  formatRunLabel,
  getReportDateKey,
  mergeHistoricalCsvRows,
  normalizeSourceThreatScore,
  pruneReportSelection,
  sanitizeSelectedReportNames,
  serializeHistoricalSummaryCsv,
  summarizeReportVerdicts,
  toggleReportSelection,
  toggleSelectAllReports,
  type ReportMeta,
} from './reportsAnalytics';

test('summarizeReportVerdicts counts ok verdicts and separates non-ok statuses', () => {
  const counts = summarizeReportVerdicts([
    { status: 'ok', verdict: 'Malicious' },
    { status: 'ok', verdict: 'Malicious' },
    { status: 'ok', verdict: 'Clean' },
    { status: 'ok', verdict: 'Suspicious' },
    { status: 'ok', verdict: 'Unknown' },
    { status: 'unsupported', verdict: 'Unknown' },
    { status: 'error', verdict: 'Unknown' },
  ]);

  assert.deepEqual(counts, {
    malicious: 2,
    clean: 1,
    suspicious: 1,
    unknown: 1,
    other: 2,
  });
});

test('formatRunLabel extracts concise timestamp from soti_YYYYMMDD_HHMMSS.csv', () => {
  assert.equal(formatRunLabel('soti_20261114_034658.csv', '2026-11-14T03:46:58Z'), '11/14 03:46:58');
});

test('buildHistoricalChartData orders runs chronologically and computes totals', () => {
  const reportsNewestFirst: ReportMeta[] = [
    {
      name: 'soti_20261114_040000.csv',
      sizeBytes: 1200,
      modifiedAt: '2026-11-14T04:00:00Z',
      rowCount: 6,
      verdicts: { malicious: 2, clean: 3, suspicious: 1, unknown: 0, other: 0 },
    },
    {
      name: 'soti_20261114_030000.csv',
      sizeBytes: 900,
      modifiedAt: '2026-11-14T03:00:00Z',
      rowCount: 4,
      verdicts: { malicious: 3, clean: 1, suspicious: 0, unknown: 0, other: 0 },
    },
  ];

  const { series, totals } = buildHistoricalChartData(reportsNewestFirst);

  assert.equal(series.length, 2);
  assert.equal(series[0].name, 'soti_20261114_030000.csv');
  assert.equal(series[1].name, 'soti_20261114_040000.csv');
  assert.deepEqual(totals, {
    runs: 2,
    malicious: 5,
    clean: 4,
    suspicious: 1,
    unknown: 0,
    totalChecks: 10,
  });
});

test('mergeHistoricalCsvRows and serializeHistoricalSummaryCsv output UTF-8 BOM CSV', () => {
  const merged = mergeHistoricalCsvRows([
    {
      name: 'soti_20261114_030000.csv',
      rows: [
        {
          timestamp: '2026-11-14T03:00:00',
          source: 'VirusTotal',
          indicator: '8.8.8.8',
          type: 'ip',
          status: 'ok',
          verdict: 'Clean',
          score: '0/90',
          summary: '0 malicious, 0 suspicious',
          details: '{"Country":"US"}',
          link: 'https://www.virustotal.com/gui/ip-address/8.8.8.8',
        },
      ],
    },
  ]);

  assert.ok(merged.startsWith('\ufeffreport_file,timestamp,source,indicator'));
  assert.ok(merged.includes('soti_20261114_030000.csv,2026-11-14T03:00:00,VirusTotal,8.8.8.8,ip,ok,Clean,0/90'));

  const summary = serializeHistoricalSummaryCsv([
    {
      name: 'soti_20261114_030000.csv',
      sizeBytes: 900,
      modifiedAt: '2026-11-14T03:00:00Z',
      rowCount: 4,
      verdicts: { malicious: 3, clean: 1, suspicious: 0, unknown: 0, other: 0 },
    },
  ]);
  assert.ok(summary.startsWith('\ufeffreport_file,run_label,modified_at,total_rows,malicious,clean'));
  assert.ok(summary.includes('soti_20261114_030000.csv,11/14 03:00:00,2026-11-14T03:00:00Z,4,3,1,0,0,0'));
});

test('filterReportList and filterReportRows handle defanged IOC search and verdict filtering', () => {
  const reports: ReportMeta[] = [
    {
      name: 'soti_20261114_040000.csv',
      sizeBytes: 1000,
      modifiedAt: '2026-11-14T04:00:00Z',
      rowCount: 3,
      verdicts: { malicious: 2, clean: 0, suspicious: 1, unknown: 0, other: 0 },
      indicators: ['1.2.3.4', 'evil.com'],
    },
    {
      name: 'soti_20261114_030000.csv',
      sizeBytes: 900,
      modifiedAt: '2026-11-14T03:00:00Z',
      rowCount: 2,
      verdicts: { malicious: 0, clean: 2, suspicious: 0, unknown: 0, other: 0 },
      indicators: ['8.8.8.8'],
    },
  ];

  assert.equal(filterReportList(reports, '8[.]8[.]8[.]8', 'All').length, 1);
  assert.equal(filterReportList(reports, '', 'Clean')[0].name, 'soti_20261114_030000.csv');

  const rows = [
    { indicator: '1.2.3.4', type: 'ip', source: 'VirusTotal', status: 'ok', verdict: 'Malicious', summary: '14 malicious' },
    { indicator: '8.8.8.8', type: 'ip', source: 'AbuseIPDB', status: 'ok', verdict: 'Clean', summary: '0 reports' },
    { indicator: 'evil.com', type: 'domain', source: 'AbuseIPDB', status: 'unsupported', verdict: 'Unknown', summary: 'unsupported' },
  ];

  assert.equal(filterReportRows(rows, '1[.]2[.]3[.]4', 'Malicious').length, 1);
  assert.equal(filterReportRows(rows, '', 'Clean').length, 1);
  assert.equal(filterReportRows(rows, '', 'Unknown').length, 0);
});

test('buildThreatAlertTrend30Days builds 30-day window and aggregates malicious + suspicious alerts', () => {
  assert.equal(getReportDateKey('soti_20261114_035601.csv', '2026-11-14T03:56:01Z'), '2026-11-14');
  assert.equal(getReportDateKey('custom_export.csv', '2026-11-10T18:00:00Z'), '2026-11-10');

  const refDate = new Date('2026-11-14T12:00:00Z');
  const reports: ReportMeta[] = [
    {
      name: 'soti_20261114_040000.csv',
      sizeBytes: 1200,
      modifiedAt: '2026-11-14T04:00:00Z',
      rowCount: 6,
      verdicts: { malicious: 3, clean: 2, suspicious: 1, unknown: 0, other: 0 },
    },
    {
      name: 'soti_20261114_020000.csv',
      sizeBytes: 900,
      modifiedAt: '2026-11-14T02:00:00Z',
      rowCount: 4,
      verdicts: { malicious: 2, clean: 2, suspicious: 0, unknown: 0, other: 0 },
    },
    {
      name: 'custom_export.csv',
      sizeBytes: 500,
      modifiedAt: '2026-10-20T09:00:00Z',
      rowCount: 5,
      verdicts: { malicious: 1, clean: 2, suspicious: 2, unknown: 0, other: 0 },
    },
    {
      // Outside 30-day window (2026-10-16 .. 2026-11-14)
      name: 'soti_20261001_080000.csv',
      sizeBytes: 400,
      modifiedAt: '2026-10-01T08:00:00Z',
      rowCount: 3,
      verdicts: { malicious: 5, clean: 0, suspicious: 0, unknown: 0, other: 0 },
    },
  ];

  const { series, summary } = buildThreatAlertTrend30Days(reports, refDate);

  assert.equal(series.length, 30);
  assert.equal(series[0].dateKey, '2026-10-16');
  assert.equal(series[29].dateKey, '2026-11-14');

  const oct20 = series.find((d) => d.dateKey === '2026-10-20');
  assert.equal(oct20?.threatAlerts, 3);
  assert.equal(oct20?.runs, 1);

  const nov14 = series[29];
  assert.equal(nov14.malicious, 5);
  assert.equal(nov14.suspicious, 1);
  assert.equal(nov14.threatAlerts, 6);
  assert.equal(nov14.runs, 2);
  assert.equal(nov14.latestReportName, 'soti_20261114_040000.csv');

  assert.deepEqual(summary, {
    totalAlerts: 9,
    maliciousAlerts: 6,
    suspiciousAlerts: 3,
    activeAlertDays: 2,
    peakAlerts: 6,
    peakDateLabel: '11/14',
  });
});

test('computeIndicatorConfidenceMap computes weighted average across multiple intelligence sources', () => {
  assert.equal(
    normalizeSourceThreatScore({ source: 'VirusTotal', status: 'ok', verdict: 'Malicious', score: '14/91' }),
    76,
  );
  assert.equal(
    normalizeSourceThreatScore({ source: 'AbuseIPDB', status: 'ok', verdict: 'Malicious', score: '89%' }),
    89,
  );
  assert.equal(
    normalizeSourceThreatScore({ source: 'AlienVault OTX', status: 'ok', verdict: 'Suspicious', score: '3 pulses' }),
    50,
  );
  assert.equal(
    normalizeSourceThreatScore({ source: 'AbuseIPDB', status: 'unsupported', verdict: 'Unknown', score: 'N/A' }),
    null,
  );

  const rows = [
    // 1.2.3.4: 3 active sources -> (0.5*76 + 0.3*89 + 0.2*50) / 1.0 = 74.7 -> 75%
    { indicator: '1.2.3.4', source: 'VirusTotal', status: 'ok', verdict: 'Malicious', score: '14/91' },
    { indicator: '1.2.3.4', source: 'AbuseIPDB', status: 'ok', verdict: 'Malicious', score: '89%' },
    { indicator: '1.2.3.4', source: 'AlienVault OTX', status: 'ok', verdict: 'Suspicious', score: '3 pulses' },
    // 8.8.8.8: 3 active sources -> (0.5*33 + 0.3*0 + 0.2*0) / 1.0 = 16.5 -> 17%
    { indicator: '8.8.8.8', source: 'VirusTotal', status: 'ok', verdict: 'Suspicious', score: '1/92' },
    { indicator: '8.8.8.8', source: 'AbuseIPDB', status: 'ok', verdict: 'Clean', score: '0%' },
    { indicator: '8.8.8.8', source: 'AlienVault OTX', status: 'ok', verdict: 'Unknown', score: '0 pulses' },
    // evil.com: 2 active sources (AbuseIPDB unsupported -> renormalized 0.5 & 0.2) -> (0.5*76 + 0.2*50) / 0.7 = 68.57 -> 69%
    { indicator: 'evil.com', source: 'VirusTotal', status: 'ok', verdict: 'Malicious', score: '14/91' },
    { indicator: 'evil.com', source: 'AbuseIPDB', status: 'unsupported', verdict: 'Unknown', score: 'N/A' },
    { indicator: 'evil.com', source: 'AlienVault OTX', status: 'ok', verdict: 'Suspicious', score: '3 pulses' },
    // errored.example: 0 active sources -> null
    { indicator: 'errored.example', source: 'VirusTotal', status: 'error', verdict: 'Unknown', score: 'N/A' },
  ];

  const map = computeIndicatorConfidenceMap(rows);

  const ipConf = map.get('1.2.3.4');
  assert.equal(ipConf?.score, 75);
  assert.equal(ipConf?.sourceCount, 3);
  assert.ok(ipConf?.tooltip.includes('Weighted avg across 3 sources'));

  const cleanIpConf = map.get('8.8.8.8');
  assert.equal(cleanIpConf?.score, 17);
  assert.equal(cleanIpConf?.sourceCount, 3);

  const domainConf = map.get('evil.com');
  assert.equal(domainConf?.score, 69);
  assert.equal(domainConf?.sourceCount, 2);

  const errorConf = map.get('errored.example');
  assert.equal(errorConf?.score, null);
  assert.equal(errorConf?.sourceCount, 0);
});

test('computeReportsQuickStats computes total analyzed, malicious percentage, and top queried indicator type', () => {
  const emptyStats = computeReportsQuickStats([]);
  assert.equal(emptyStats.totalThreatsAnalyzed, 0);
  assert.equal(emptyStats.maliciousPercentage, 0);
  assert.equal(emptyStats.topIndicatorType, null);
  assert.equal(emptyStats.topIndicatorLabel, '—');

  const reports: ReportMeta[] = [
    {
      name: 'soti_20261114_040000.csv',
      sizeBytes: 1200,
      modifiedAt: '2026-11-14T04:00:00Z',
      rowCount: 12,
      verdicts: { malicious: 5, clean: 4, suspicious: 1, unknown: 0, other: 2 },
      indicators: ['1[.]2[.]3[.]4', '8.8.8.8', 'evil.com', '44d88612fea8a8f36de82e1278abb02f'],
    },
    {
      name: 'soti_20261114_030000.csv',
      sizeBytes: 800,
      modifiedAt: '2026-11-14T03:00:00Z',
      rowCount: 6,
      verdicts: { malicious: 2, clean: 3, suspicious: 0, unknown: 1, other: 0 },
      indicators: ['1.2.3.4', '9.9.9.9'],
    },
  ];

  const stats = computeReportsQuickStats(reports);
  assert.equal(stats.totalThreatsAnalyzed, 18);
  assert.equal(stats.uniqueIndicatorsCount, 5); // 1.2.3.4, 8.8.8.8, evil.com, hash, 9.9.9.9
  assert.equal(stats.totalRuns, 2);
  assert.equal(stats.maliciousCount, 7);
  assert.equal(stats.evaluatedVerdictsCount, 16); // 5+4+1+0 + 2+3+0+1
  assert.equal(stats.maliciousPercentage, 43.8);
  assert.equal(stats.topIndicatorType, 'ip');
  assert.equal(stats.topIndicatorLabel, 'IP Address');
  assert.equal(stats.topIndicatorShare, 66.7); // 4 IPs out of 6 typed entries
  assert.deepEqual(stats.typeCounts, { ip: 4, domain: 1, hash: 1 });
});

test('multi-report selection helpers toggle, select-all/clear filtered entries, prune, and sanitize names', () => {
  const mkMeta = (name: string): ReportMeta => ({
    name,
    sizeBytes: 500,
    modifiedAt: '2026-11-14T04:00:00Z',
    rowCount: 3,
    verdicts: { malicious: 1, clean: 2, suspicious: 0, unknown: 0, other: 0 },
  });

  const allReports = [
    mkMeta('soti_20261114_040000.csv'),
    mkMeta('soti_20261114_030000.csv'),
    mkMeta('soti_20261114_020000.csv'),
  ];
  const filtered = allReports.slice(0, 2);

  let selected = toggleReportSelection([], 'soti_20261114_040000.csv');
  assert.deepEqual(selected, ['soti_20261114_040000.csv']);
  selected = toggleReportSelection(selected, 'soti_20261114_020000.csv');
  assert.deepEqual(selected, ['soti_20261114_040000.csv', 'soti_20261114_020000.csv']);
  assert.equal(areAllVisibleReportsSelected(selected, filtered), false);

  // Select all currently visible (adds missing 030000 without dropping already-selected 020000)
  selected = toggleSelectAllReports(selected, filtered);
  assert.deepEqual(selected, [
    'soti_20261114_040000.csv',
    'soti_20261114_020000.csv',
    'soti_20261114_030000.csv',
  ]);
  assert.equal(areAllVisibleReportsSelected(selected, filtered), true);

  // Calling toggleSelectAllReports again unselects only the visible subset
  selected = toggleSelectAllReports(selected, filtered);
  assert.deepEqual(selected, ['soti_20261114_020000.csv']);

  // Pruning removes reports no longer returned by server
  assert.deepEqual(pruneReportSelection(['soti_20261114_020000.csv', 'deleted.csv'], allReports), [
    'soti_20261114_020000.csv',
  ]);

  // Sanitizing strips traversal/non-csv/unavailable entries and deduplicates
  assert.deepEqual(
    sanitizeSelectedReportNames(
      [
        'soti_20261114_040000.csv',
        '../etc/passwd',
        'nested/evil.csv',
        'notes.txt',
        'soti_20261114_040000.csv',
        'missing.csv',
      ],
      allReports.map((r) => r.name),
    ),
    ['soti_20261114_040000.csv'],
  );

  assert.equal(
    buildAggregatedCsvFilename(1, new Date('2026-11-14T12:00:00Z')),
    'soti_aggregated_reports_1run_20261114.csv',
  );
  assert.equal(
    buildAggregatedCsvFilename(3, new Date('2026-11-14T12:00:00Z')),
    'soti_aggregated_reports_3runs_20261114.csv',
  );
});

test('auto-refresh interval helpers default to 60s and build print document titles cleanly', () => {
  assert.equal(DEFAULT_REPORTS_REFRESH_SECONDS, 60);
  assert.equal(normalizeRefreshIntervalSeconds(undefined), 60);
  assert.equal(normalizeRefreshIntervalSeconds(45), 60);
  assert.equal(normalizeRefreshIntervalSeconds(120), 120);
  assert.equal(normalizeRefreshIntervalSeconds('30'), 30);

  assert.equal(formatRefreshIntervalLabel(30), '30s');
  assert.equal(formatRefreshIntervalLabel(60), '60s');
  assert.equal(formatRefreshIntervalLabel(120), '2m');
  assert.equal(formatRefreshIntervalLabel(300), '5m');

  assert.equal(
    buildPrintDocumentTitle('soti_20261114_040000.csv', new Date('2026-11-14T08:00:00Z')),
    'soti_20261114_040000_report_2026-11-14',
  );
  assert.equal(
    buildPrintDocumentTitle(null, new Date('2026-11-14T08:00:00Z')),
    'soti_threat_report_2026-11-14',
  );
});

test('table density helpers default to normal and return distinct Compact, Normal, Spacious specs', () => {
  assert.equal(DEFAULT_TABLE_DENSITY, 'normal');
  assert.equal(normalizeTableDensity('compact'), 'compact');
  assert.equal(normalizeTableDensity('SPACIOUS'), 'spacious');
  assert.equal(normalizeTableDensity('invalid'), 'normal');
  assert.equal(normalizeTableDensity(undefined), 'normal');

  const compact = getTableDensitySpec('compact');
  const normal = getTableDensitySpec('normal');
  const spacious = getTableDensitySpec('spacious');
  assert.equal(compact.label, 'Compact');
  assert.equal(normal.label, 'Normal');
  assert.equal(spacious.label, 'Spacious');
  assert.notEqual(compact.cellPaddingClass, normal.cellPaddingClass);
  assert.notEqual(normal.cellPaddingClass, spacious.cellPaddingClass);
});



