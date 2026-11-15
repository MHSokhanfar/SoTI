import test from 'node:test';
import assert from 'node:assert/strict';
import { cloneDefaultApiSettings } from './apiConfig';
import {
  buildGlobalSearchIndex,
  normalizeGlobalSearchQuery,
  searchGlobalEntries,
} from './globalSearch';
import type { LookupResult } from './indicators';
import type { RecentInvestigationEntry } from './investigationHistory';
import type { ReportMeta } from './reportsAnalytics';
import type { ScheduledJob } from './scheduler';

function makeFixtures() {
  const currentResults: LookupResult[] = [
    {
      source: 'VirusTotal',
      sourceId: 'virustotal',
      indicator: '1.2.3.4',
      originalToken: '1[.]2[.]3[.]4',
      type: 'ip',
      status: 'ok',
      verdict: 'Malicious',
      score: '12/90',
      summary: '12 vendors flagged 1.2.3.4',
      details: {},
      link: '',
    },
    {
      source: 'AlienVault OTX',
      sourceId: 'alienvault',
      indicator: 'evil.com',
      originalToken: 'evil.com',
      type: 'domain',
      status: 'ok',
      verdict: 'Suspicious',
      score: '3 pulses',
      summary: 'Observed in phishing campaign',
      details: {},
      link: '',
    },
  ];

  const recentInvestigations: RecentInvestigationEntry[] = [
    {
      id: 'inv-1',
      createdAt: '2026-11-14T08:00:00Z',
      rawInput: '9.9.9.9',
      normalizedInput: '9.9.9.9',
      indicators: ['9.9.9.9'],
      indicatorCount: 1,
      source: 'all',
      customSources: ['virustotal'],
      useCustomSources: false,
      sourceLabels: ['VirusTotal'],
      mode: 'sample',
      verdictSummary: { malicious: 0, suspicious: 0, clean: 1, unknown: 0, other: 0 },
      results: [],
      invalidTokens: [],
      quotaSkipped: [],
      reportFile: 'soti_20261114_080000.csv',
    },
  ];

  const reports: ReportMeta[] = [
    {
      name: 'soti_20261114_090000.csv',
      sizeBytes: 1024,
      modifiedAt: '2026-11-14T09:00:00Z',
      rowCount: 4,
      verdicts: { malicious: 2, clean: 2, suspicious: 0, unknown: 0, other: 0 },
      indicators: ['1.2.3.4', '8.8.8.8'],
    },
  ];

  const schedules: ScheduledJob[] = [
    {
      id: 'sched-1',
      name: 'Perimeter Watchlist',
      indicators: ['1.2.3.4', 'c2.badactor.org'],
      source: 'all',
      sources: ['virustotal', 'abuseipdb'],
      intervalMinutes: 60,
      mode: 'sample',
      enabled: true,
      createdAt: '2026-11-14T00:00:00Z',
      updatedAt: '2026-11-14T09:00:00Z',
      nextRunAt: '2026-11-14T10:00:00Z',
      lastRunAt: '2026-11-14T09:00:00Z',
      lastStatus: 'success',
      lastSummary: '2 lookups completed',
      lastReportFile: 'soti_20261114_090000.csv',
      runCount: 3,
    },
  ];

  const logLines = [
    '2026-11-14 09:00:01 [INFO] Saved report soti_20261114_090000.csv for 1.2.3.4',
    '2026-11-14 08:45:10 [WARN] VirusTotal rate limit approached',
  ];

  const apiSettings = cloneDefaultApiSettings();

  return buildGlobalSearchIndex({
    currentResults,
    recentInvestigations,
    reports,
    schedules,
    logLines,
    apiSettings,
  });
}

test('normalizeGlobalSearchQuery normalizes defanged IOCs into clean searchable terms', () => {
  const res = normalizeGlobalSearchQuery('1[.]2[.]3[.]4');
  assert.equal(res.rawLower, '1[.]2[.]3[.]4');
  assert.equal(res.cleanedLower, '1.2.3.4');
  assert.equal(res.terms.length, 1);
  assert.match(res.terms[0], /1\.2\.3\.4/);

  const urlRes = normalizeGlobalSearchQuery('hxxp://evil[.]com/login');
  assert.equal(urlRes.cleanedLower, 'evil.com');
});

test('searchGlobalEntries finds matching IOCs across Investigate, Reports, Scheduled, and Logs even with defanged query', () => {
  const index = makeFixtures();
  const hits = searchGlobalEntries(index, '1[.]2[.]3[.]4');

  const tabs = new Set(hits.map((h) => h.tab));
  assert.equal(tabs.has('investigate'), true);
  assert.equal(tabs.has('reports'), true);
  assert.equal(tabs.has('scheduled'), true);
  assert.equal(tabs.has('logs'), true);
  assert.equal(hits[0].indicator, '1.2.3.4');
});

test('searchGlobalEntries supports filtering by tab and matching report filenames or providers', () => {
  const index = makeFixtures();

  const reportOnly = searchGlobalEntries(index, 'soti_20261114', { tabFilter: 'reports' });
  assert.equal(reportOnly.length >= 1, true);
  assert.equal(reportOnly.every((h) => h.tab === 'reports'), true);
  assert.equal(reportOnly[0].reportName, 'soti_20261114_090000.csv');

  const cliHits = searchGlobalEntries(index, 'virustotal', { tabFilter: 'cli' });
  assert.equal(cliHits.length, 1);
  assert.equal(cliHits[0].title, 'VirusTotal');

  const scheduleHits = searchGlobalEntries(index, 'badactor');
  assert.equal(scheduleHits.length, 1);
  assert.equal(scheduleHits[0].tab, 'scheduled');
  assert.equal(scheduleHits[0].scheduleId, 'sched-1');
});
