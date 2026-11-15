import { EXTRA_PROVIDER_META, type ApiSettings } from './apiConfig';
import { cleanIndicator, type LookupResult } from './indicators';
import type { RecentInvestigationEntry } from './investigationHistory';
import { formatRunLabel, type ReportMeta } from './reportsAnalytics';
import { formatIntervalLabel, type ScheduledJob } from './scheduler';

export type SearchableTab = 'investigate' | 'reports' | 'scheduled' | 'logs' | 'cli';

export type GlobalSearchKind =
  | 'ioc'
  | 'history'
  | 'report'
  | 'schedule'
  | 'log'
  | 'provider';

export type VerdictTone = 'malicious' | 'suspicious' | 'clean' | 'neutral';

export interface GlobalSearchEntry {
  id: string;
  tab: SearchableTab;
  tabLabel: string;
  kind: GlobalSearchKind;
  title: string;
  subtitle: string;
  searchText: string;
  verdictTone?: VerdictTone;
  indicator?: string;
  historyEntryId?: string;
  reportName?: string;
  scheduleId?: string;
  logQuery?: string;
  providerId?: string;
}

export interface GlobalSearchIndexParams {
  currentResults: LookupResult[];
  recentInvestigations: RecentInvestigationEntry[];
  reports: ReportMeta[];
  schedules: ScheduledJob[];
  logLines: string[];
  apiSettings: ApiSettings;
}

const TAB_LABELS: Record<SearchableTab, string> = {
  investigate: 'Investigate',
  reports: 'Reports',
  scheduled: 'Scheduled',
  logs: 'Logs',
  cli: 'CLI & APIs',
};

const CORE_PROVIDERS: { id: string; name: string; envVar: string; support: string }[] = [
  { id: 'virustotal', name: 'VirusTotal', envVar: 'VT_API_KEY', support: 'IP, Domain, Hash' },
  { id: 'abuseipdb', name: 'AbuseIPDB', envVar: 'ABUSEIPDB_API_KEY', support: 'IP only' },
  { id: 'alienvault', name: 'AlienVault OTX', envVar: 'OTX_API_KEY', support: 'IP, Domain, Hash' },
];

function verdictToTone(verdict: string | undefined, status?: string): VerdictTone {
  if (status && status !== 'ok') return 'neutral';
  const v = (verdict || '').trim().toLowerCase();
  if (v === 'malicious') return 'malicious';
  if (v === 'suspicious') return 'suspicious';
  if (v === 'clean') return 'clean';
  return 'neutral';
}

function highestTone(a: VerdictTone, b: VerdictTone): VerdictTone {
  const rank: Record<VerdictTone, number> = {
    malicious: 3,
    suspicious: 2,
    clean: 1,
    neutral: 0,
  };
  return rank[b] > rank[a] ? b : a;
}

function verdictSummaryToTone(summary: {
  malicious: number;
  suspicious: number;
  clean: number;
}): VerdictTone {
  if (summary.malicious > 0) return 'malicious';
  if (summary.suspicious > 0) return 'suspicious';
  if (summary.clean > 0) return 'clean';
  return 'neutral';
}

export function normalizeGlobalSearchQuery(rawQuery: string): {
  rawLower: string;
  cleanedLower: string;
  terms: string[];
} {
  const trimmed = rawQuery.trim();
  if (!trimmed) {
    return { rawLower: '', cleanedLower: '', terms: [] };
  }
  const rawLower = trimmed.toLowerCase();
  const cleanedToken = cleanIndicator(trimmed).toLowerCase();
  const cleanedLower = cleanedToken || rawLower;
  const terms = rawLower
    .split(/\s+/)
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => ({
      raw: part,
      cleaned: cleanIndicator(part).toLowerCase(),
    }));

  // Deduplicate expanded term representations cleanly while keeping each space-separated token
  return {
    rawLower,
    cleanedLower,
    terms: terms.map((t) => (t.cleaned && t.cleaned !== t.raw ? `${t.raw}|${t.cleaned}` : t.raw)),
  };
}

export function buildGlobalSearchIndex({
  currentResults,
  recentInvestigations,
  reports,
  schedules,
  logLines,
  apiSettings,
}: GlobalSearchIndexParams): GlobalSearchEntry[] {
  const entries: GlobalSearchEntry[] = [];

  // 1. Active Investigate results grouped by unique indicator
  const currentByIndicator = new Map<string, LookupResult[]>();
  for (const res of currentResults) {
    const key = res.indicator.trim();
    if (!key) continue;
    const list = currentByIndicator.get(key) || [];
    list.push(res);
    currentByIndicator.set(key, list);
  }

  for (const [indicator, rows] of currentByIndicator.entries()) {
    let tone: VerdictTone = 'neutral';
    const sources: string[] = [];
    const verdicts: string[] = [];
    const summaries: string[] = [];
    for (const r of rows) {
      tone = highestTone(tone, verdictToTone(r.verdict, r.status));
      if (r.source && !sources.includes(r.source)) sources.push(r.source);
      if (r.status === 'ok' && r.verdict) verdicts.push(`${r.source}: ${r.verdict}`);
      if (r.summary) summaries.push(r.summary);
    }
    const primaryType = (rows[0]?.type || 'ioc').toUpperCase();
    const topLabel =
      tone === 'malicious'
        ? 'Malicious'
        : tone === 'suspicious'
          ? 'Suspicious'
          : tone === 'clean'
            ? 'Clean'
            : 'Unknown';

    entries.push({
      id: `inv-current:${indicator}`,
      tab: 'investigate',
      tabLabel: TAB_LABELS.investigate,
      kind: 'ioc',
      title: indicator,
      subtitle: `Active lookup · ${primaryType} · ${topLabel} · ${sources.join(', ')}`,
      searchText: `${indicator} ${primaryType} ${sources.join(' ')} ${verdicts.join(' ')} ${summaries.join(' ')}`.toLowerCase(),
      verdictTone: tone,
      indicator,
    });
  }

  // 2. Saved localStorage Recent Investigations
  for (const inv of recentInvestigations) {
    const title =
      inv.indicators.length > 0
        ? inv.indicators.join(', ')
        : inv.normalizedInput || inv.rawInput;
    const tone = verdictSummaryToTone(inv.verdictSummary);
    const vParts: string[] = [];
    if (inv.verdictSummary.malicious > 0) vParts.push(`${inv.verdictSummary.malicious} malicious`);
    if (inv.verdictSummary.suspicious > 0) vParts.push(`${inv.verdictSummary.suspicious} suspicious`);
    if (inv.verdictSummary.clean > 0) vParts.push(`${inv.verdictSummary.clean} clean`);
    if (vParts.length === 0) vParts.push(`${inv.results.length} results`);

    entries.push({
      id: `inv-history:${inv.id}`,
      tab: 'investigate',
      tabLabel: TAB_LABELS.investigate,
      kind: 'history',
      title: title.length > 56 ? `${title.slice(0, 53)}...` : title,
      subtitle: `Recent session · ${vParts.join(' · ')}${inv.reportFile ? ` · ${inv.reportFile}` : ''}`,
      searchText: `${inv.rawInput} ${inv.normalizedInput} ${inv.indicators.join(' ')} ${inv.sourceLabels.join(' ')} ${inv.reportFile || ''}`.toLowerCase(),
      verdictTone: tone,
      historyEntryId: inv.id,
      indicator: inv.indicators[0],
    });
  }

  // 3. Historical CSV Reports & Indicators inside Reports
  for (const rep of reports) {
    const v = rep.verdicts || { malicious: 0, clean: 0, suspicious: 0, unknown: 0, other: 0 };
    const tone = verdictSummaryToTone(v);
    const indicators = Array.isArray(rep.indicators) ? rep.indicators : [];
    const runLabel = formatRunLabel(rep.name, rep.modifiedAt);

    entries.push({
      id: `report:${rep.name}`,
      tab: 'reports',
      tabLabel: TAB_LABELS.reports,
      kind: 'report',
      title: rep.name,
      subtitle: `${runLabel} · ${rep.rowCount} rows · ${v.malicious} mal / ${v.clean} clean`,
      searchText: `${rep.name} ${runLabel} ${indicators.join(' ')}`.toLowerCase(),
      verdictTone: tone,
      reportName: rep.name,
    });

    for (const ind of indicators) {
      entries.push({
        id: `report-ioc:${rep.name}:${ind}`,
        tab: 'reports',
        tabLabel: TAB_LABELS.reports,
        kind: 'ioc',
        title: ind,
        subtitle: `In report ${rep.name} · ${runLabel}`,
        searchText: `${ind} ${rep.name} ${runLabel}`.toLowerCase(),
        verdictTone: tone,
        reportName: rep.name,
        indicator: ind,
      });
    }
  }

  // 4. Scheduled Jobs
  for (const job of schedules) {
    const tone: VerdictTone =
      job.lastStatus === 'error'
        ? 'malicious'
        : job.lastStatus === 'partial'
          ? 'suspicious'
          : job.enabled
            ? 'clean'
            : 'neutral';

    entries.push({
      id: `schedule:${job.id}`,
      tab: 'scheduled',
      tabLabel: TAB_LABELS.scheduled,
      kind: 'schedule',
      title: job.name,
      subtitle: `${job.enabled ? 'Active' : 'Paused'} · ${formatIntervalLabel(job.intervalMinutes)} · ${job.indicators.join(', ')}`,
      searchText: `${job.name} ${job.indicators.join(' ')} ${job.sources.join(' ')} ${job.lastSummary || ''} ${job.lastReportFile || ''}`.toLowerCase(),
      verdictTone: tone,
      scheduleId: job.id,
      indicator: job.indicators[0],
    });
  }

  // 5. Audit Logs (newest 120 lines)
  for (let i = 0; i < Math.min(logLines.length, 120); i += 1) {
    const line = logLines[i];
    if (!line || !line.trim()) continue;
    const upper = line.toUpperCase();
    const tone: VerdictTone = upper.includes('ERROR')
      ? 'malicious'
      : upper.includes('WARN')
        ? 'suspicious'
        : 'neutral';

    entries.push({
      id: `log:${i}:${line.slice(0, 24)}`,
      tab: 'logs',
      tabLabel: TAB_LABELS.logs,
      kind: 'log',
      title: line.length > 74 ? `${line.slice(0, 71)}...` : line,
      subtitle: `Audit log entry · logs/soti.log`,
      searchText: line.toLowerCase(),
      verdictTone: tone,
      logQuery: line,
    });
  }

  // 6. Configured Threat Intelligence Providers (CLI & APIs tab)
  for (const core of CORE_PROVIDERS) {
    const cfg = apiSettings.providers[core.id as keyof typeof apiSettings.providers];
    const enabled = cfg ? cfg.enabled : true;
    entries.push({
      id: `provider:${core.id}`,
      tab: 'cli',
      tabLabel: TAB_LABELS.cli,
      kind: 'provider',
      title: core.name,
      subtitle: `${enabled ? 'Enabled' : 'Disabled'} · ${core.support} · ${core.envVar}`,
      searchText: `${core.name} ${core.id} ${core.envVar} ${core.support} ${cfg?.baseUrl || ''}`.toLowerCase(),
      verdictTone: enabled ? 'clean' : 'neutral',
      providerId: core.id,
    });
  }

  for (const [id, meta] of Object.entries(EXTRA_PROVIDER_META)) {
    const cfg = apiSettings.extraProviders?.[id as keyof typeof apiSettings.extraProviders];
    const enabled = Boolean(cfg?.enabled);
    entries.push({
      id: `provider:${id}`,
      tab: 'cli',
      tabLabel: TAB_LABELS.cli,
      kind: 'provider',
      title: meta.name,
      subtitle: `${enabled ? 'Enabled' : 'Disabled'} · ${meta.support} · ${meta.envVar}`,
      searchText: `${meta.name} ${id} ${meta.envVar} ${meta.support} ${cfg?.baseUrl || ''}`.toLowerCase(),
      verdictTone: enabled ? 'clean' : 'neutral',
      providerId: id,
    });
  }

  for (const custom of apiSettings.customProviders || []) {
    const supportedList = Array.isArray(custom.supportedTypes)
      ? custom.supportedTypes.join(', ').toUpperCase()
      : 'IP, DOMAIN, HASH';
    entries.push({
      id: `provider:custom:${custom.id}`,
      tab: 'cli',
      tabLabel: TAB_LABELS.cli,
      kind: 'provider',
      title: custom.name,
      subtitle: `${custom.enabled ? 'Enabled' : 'Disabled'} · Custom provider · ${supportedList}`,
      searchText: `${custom.name} ${custom.id} ${custom.envVarName || ''} ${custom.endpointTemplate || ''} ${supportedList}`.toLowerCase(),
      verdictTone: custom.enabled ? 'clean' : 'neutral',
      providerId: custom.id,
    });
  }

  return entries;
}

const KIND_PRIORITY: Record<GlobalSearchKind, number> = {
  ioc: 5,
  report: 4,
  schedule: 3,
  history: 2,
  provider: 1,
  log: 0,
};

function scoreEntry(
  entry: GlobalSearchEntry,
  rawLower: string,
  cleanedLower: string,
  terms: string[],
): number {
  const titleLower = entry.title.toLowerCase();
  const indicatorLower = (entry.indicator || '').toLowerCase();

  for (const termSpec of terms) {
    const parts = termSpec.split('|');
    const matchesAnyPart = parts.some((p) => entry.searchText.includes(p));
    if (!matchesAnyPart) {
      return -1;
    }
  }

  let score = 10 + KIND_PRIORITY[entry.kind];

  if (titleLower === rawLower || titleLower === cleanedLower) {
    score += 100;
  } else if (indicatorLower && (indicatorLower === rawLower || indicatorLower === cleanedLower)) {
    score += 90;
  } else if (titleLower.startsWith(rawLower) || titleLower.startsWith(cleanedLower)) {
    score += 55;
  } else if (titleLower.includes(rawLower) || titleLower.includes(cleanedLower)) {
    score += 35;
  } else if (indicatorLower && (indicatorLower.includes(rawLower) || indicatorLower.includes(cleanedLower))) {
    score += 28;
  }

  return score;
}

export function searchGlobalEntries(
  entries: GlobalSearchEntry[],
  rawQuery: string,
  options: {
    tabFilter?: 'all' | SearchableTab;
    limit?: number;
  } = {},
): GlobalSearchEntry[] {
  const tabFilter = options.tabFilter ?? 'all';
  const limit = options.limit ?? 14;
  const scoped = tabFilter === 'all' ? entries : entries.filter((e) => e.tab === tabFilter);

  const { rawLower, cleanedLower, terms } = normalizeGlobalSearchQuery(rawQuery);
  if (terms.length === 0) {
    // When focused with an empty query, show helpful quick jumps (recent IOCs, reports, schedules)
    return scoped
      .filter((e) => e.kind !== 'log')
      .slice(0, Math.min(limit, 8));
  }

  const scored: { entry: GlobalSearchEntry; score: number }[] = [];
  for (const entry of scoped) {
    const s = scoreEntry(entry, rawLower, cleanedLower, terms);
    if (s >= 0) {
      scored.push({ entry, score: s });
    }
  }

  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, limit).map((item) => item.entry);
}
