import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardList,
  ExternalLink,
  HelpCircle,
  Search,
  Settings2,
  ShieldAlert,
  X,
  XCircle,
} from 'lucide-react';
import {
  parseIndicators,
  type LookupResult,
  type SourceSelection,
  type Verdict,
} from '../utils/indicators';
import {
  BUILTIN_EXTRA_IDS,
  EXTRA_PROVIDER_META,
  getAllEnabledProviderIds,
  type ApiSettings,
} from '../utils/apiConfig';
import {
  IndicatorFileUpload,
  type IndicatorFileSummary,
} from './IndicatorFileUpload';
import { getQuotaWarningProviders } from '../utils/quota';
import type { QuotaState } from '../App';

export interface QuotaSkippedEntry {
  providerId: string;
  name: string;
  used: number;
  limit: number;
  reason: string;
}

export interface InvestigationState {
  rawInput: string;
  source: SourceSelection;
  customSources: string[];
  useCustomSources: boolean;
  mode: 'sample' | 'live';
  results: LookupResult[];
  invalidTokens: string[];
  quotaSkipped: QuotaSkippedEntry[];
  lastReportFile: string | null;
  lastRunMode: 'sample' | 'live' | null;
}

interface InvestigateViewProps {
  state: InvestigationState;
  apiSettings: ApiSettings;
  quota: QuotaState;
  onChangeState: (updater: (prev: InvestigationState) => InvestigationState) => void;
  onQuotaChange: (next: QuotaState) => void;
  onReportCreated: (reportFile: string) => void;
  onOpenApiConfig: () => void;
}

const CORE_LABELS: Record<string, string> = {
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
  alienvault: 'AlienVault OTX',
  shodan: EXTRA_PROVIDER_META.shodan.name,
  threatfox: EXTRA_PROVIDER_META.threatfox.name,
  urlscan: EXTRA_PROVIDER_META.urlscan.name,
};

const SOURCE_OPTIONS: { id: SourceSelection; label: string }[] = [
  { id: 'all', label: 'All Enabled' },
  { id: 'virustotal', label: 'VirusTotal' },
  { id: 'abuseipdb', label: 'AbuseIPDB' },
  { id: 'alienvault', label: 'AlienVault OTX' },
];

const VERDICT_FILTERS: ('All' | Verdict)[] = [
  'All',
  'Malicious',
  'Suspicious',
  'Clean',
  'Unknown',
];

export const SAMPLE_BATCH =
  '1[.]2[.]3[.]4, 8.8.8.8, hxxp://evil[.]com/login, 44d88612fea8a8f36de82e1278abb02f';

function VerdictIndicator({ verdict, status }: { verdict: Verdict; status: LookupResult['status'] }) {
  if (status !== 'ok') {
    const label = status.replace('_', ' ').toUpperCase();
    const colorClass =
      status === 'error'
        ? 'text-red-700 dark:text-red-400'
        : status === 'not_found'
          ? 'text-sky-700 dark:text-sky-400'
          : 'text-slate-500 dark:text-slate-400';
    return (
      <span className={`inline-flex items-center gap-1.5 font-mono text-xs font-medium ${colorClass}`}>
        <XCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span>{label}</span>
      </span>
    );
  }

  switch (verdict) {
    case 'Malicious':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-700 dark:text-red-400">
          <ShieldAlert className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>Malicious</span>
        </span>
      );
    case 'Suspicious':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-700 dark:text-amber-400">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>Suspicious</span>
        </span>
      );
    case 'Clean':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
          <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>Clean</span>
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 dark:text-slate-400">
          <HelpCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>Unknown</span>
        </span>
      );
  }
}

export function InvestigateView({
  state,
  apiSettings,
  quota,
  onChangeState,
  onQuotaChange,
  onReportCreated,
  onOpenApiConfig,
}: InvestigateViewProps) {
  const [verdictFilter, setVerdictFilter] = useState<'All' | Verdict>('All');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [dismissedQuotaSignature, setDismissedQuotaSignature] = useState<string | null>(null);
  const [fileImportSummary, setFileImportSummary] = useState<IndicatorFileSummary | null>(null);

  const parsedPreview = useMemo(() => parseIndicators(state.rawInput), [state.rawInput]);
  const enabledSourceIds = useMemo(() => getAllEnabledProviderIds(apiSettings), [apiSettings]);

  const warningProviders = useMemo(
    () => getQuotaWarningProviders(quota.providers, 80, enabledSourceIds),
    [quota.providers, enabledSourceIds],
  );
  const warningSignature = useMemo(
    () => warningProviders.map((p) => `${p.providerId}:${p.used}/${p.limit}`).join('|'),
    [warningProviders],
  );
  const showThresholdWarning =
    warningProviders.length > 0 && dismissedQuotaSignature !== warningSignature;

  const allKnownProviders = useMemo(() => {
    const base: { id: string; name: string; enabled: boolean }[] = [
      { id: 'virustotal', name: 'VirusTotal', enabled: apiSettings.providers.virustotal.enabled },
      { id: 'abuseipdb', name: 'AbuseIPDB', enabled: apiSettings.providers.abuseipdb.enabled },
      { id: 'alienvault', name: 'AlienVault OTX', enabled: apiSettings.providers.alienvault.enabled },
      ...BUILTIN_EXTRA_IDS.map((id) => ({
        id,
        name: EXTRA_PROVIDER_META[id].name,
        enabled: Boolean(apiSettings.extraProviders?.[id]?.enabled),
      })),
      ...(apiSettings.customProviders || []).map((cp) => ({
        id: cp.id,
        name: cp.name,
        enabled: cp.enabled,
      })),
    ];
    return base;
  }, [apiSettings]);

  const providerNameMap = useMemo(() => {
    const map: Record<string, string> = { ...CORE_LABELS };
    for (const cp of apiSettings.customProviders || []) {
      map[cp.id] = cp.name;
    }
    return map;
  }, [apiSettings]);

  const quotaById = useMemo(() => {
    const map = new Map(quota.providers.map((p) => [p.providerId, p]));
    return map;
  }, [quota.providers]);

  const effectiveSources: string[] = useMemo(() => {
    if (state.useCustomSources) {
      return state.customSources;
    }
    if (state.source === 'all') {
      return enabledSourceIds;
    }
    return [state.source];
  }, [state.useCustomSources, state.customSources, state.source, enabledSourceIds]);

  const visibleQuotaSnapshots = useMemo(() => {
    const ids = new Set(enabledSourceIds);
    for (const q of quota.providers) {
      if (q.used > 0 || q.exhausted) ids.add(q.providerId);
    }
    return quota.providers.filter((q) => ids.has(q.providerId));
  }, [quota.providers, enabledSourceIds]);

  function toggleCustomSource(id: string) {
    onChangeState((prev) => {
      const exists = prev.customSources.includes(id);
      const next = exists
        ? prev.customSources.filter((s) => s !== id)
        : [...prev.customSources, id];
      return {
        ...prev,
        useCustomSources: true,
        customSources: next,
      };
    });
  }

  function handleFileExtracted(summary: IndicatorFileSummary) {
    setErrorMsg(null);
    onChangeState((prev) => ({
      ...prev,
      rawInput: summary.parsed.rawText,
      invalidTokens: [],
    }));
    setFileImportSummary(summary);
  }

  function handleFileError(message: string) {
    setFileImportSummary(null);
    setErrorMsg(message);
  }

  const filteredResults = useMemo(() => {
    if (verdictFilter === 'All') return state.results;
    return state.results.filter((r) => r.status === 'ok' && r.verdict === verdictFilter);
  }, [state.results, verdictFilter]);

  const groupedByIndicator = useMemo(() => {
    const groups = new Map<string, { indicator: string; type: string; items: LookupResult[] }>();
    for (const r of filteredResults) {
      const existing = groups.get(r.indicator);
      if (existing) {
        existing.items.push(r);
      } else {
        groups.set(r.indicator, { indicator: r.indicator, type: r.type, items: [r] });
      }
    }
    return Array.from(groups.values());
  }, [filteredResults]);

  async function handleRunLookup(e: React.FormEvent) {
    e.preventDefault();
    setErrorMsg(null);

    if (!state.rawInput.trim()) {
      setErrorMsg('Enter at least one IP, domain, or file hash (MD5, SHA1, or SHA256).');
      return;
    }

    if (effectiveSources.length === 0) {
      setErrorMsg('Select at least one intelligence API to run enrichment.');
      return;
    }

    setLoading(true);
    try {
      const payload: Record<string, unknown> = {
        raw: state.rawInput,
        source: state.source,
        mode: state.mode,
      };
      if (state.useCustomSources) {
        payload.sources = state.customSources;
      }
      const resp = await fetch('/api/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setErrorMsg(data.error || 'Enrichment lookup failed.');
        if (Array.isArray(data.invalid)) {
          onChangeState((prev) => ({ ...prev, invalidTokens: data.invalid }));
        }
        return;
      }

      onChangeState((prev) => ({
        ...prev,
        results: data.results || [],
        invalidTokens: data.invalid || [],
        quotaSkipped: Array.isArray(data.quotaSkipped) ? data.quotaSkipped : [],
        lastReportFile: data.reportFile || null,
        lastRunMode: data.mode || prev.mode,
      }));
      if (data.quota?.date && Array.isArray(data.quota?.providers)) {
        onQuotaChange(data.quota);
      }
      setVerdictFilter('All');
      if (data.reportFile) {
        onReportCreated(data.reportFile);
      }
    } catch {
      setErrorMsg('Unable to reach the enrichment backend.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-8">
      {showThresholdWarning && (
        <div
          role="alert"
          data-testid="quota-threshold-warning"
          className="flex flex-col gap-3 rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 px-5 py-4 text-xs text-amber-950 dark:text-amber-100 sm:flex-row sm:items-center sm:justify-between"
        >
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-700 dark:text-amber-400" aria-hidden="true" />
            <div className="space-y-0.5">
              <p className="text-sm font-semibold text-amber-950 dark:text-amber-100">
                Daily Quota Warning (&gt;80% Used)
              </p>
              <p className="text-xs text-amber-900 dark:text-amber-200/90">
                Approaching daily limit on{' '}
                <span className="font-mono font-medium">
                  {warningProviders
                    .map((p) => `${p.name}: ${p.used}/${p.limit} (${p.percentUsed}% — ${p.remaining} left)`)
                    .join(' · ')}
                </span>
                . Enable backup APIs or increase limits before exhaustion triggers automatic failover.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={onOpenApiConfig}
              className="rounded-lg border border-amber-300 dark:border-amber-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-amber-950 dark:text-amber-200 hover:bg-amber-100 dark:hover:bg-amber-900/40 whitespace-nowrap shrink-0 cursor-pointer"
            >
              Manage APIs &amp; Quotas
            </button>
            <button
              type="button"
              onClick={() => setDismissedQuotaSignature(warningSignature)}
              aria-label="Dismiss daily quota warning"
              className="rounded-lg p-1.5 text-amber-800 dark:text-amber-300 hover:bg-amber-100 dark:hover:bg-amber-900/50 cursor-pointer"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        </div>
      )}

      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 md:p-6">
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-950 dark:text-slate-50 text-balance">
              Threat Intelligence Enrichment
            </h1>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
              Query normal or defanged IPs, domains, and hashes individually or via bulk CSV / TXT file upload, with automatic daily quota failover.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <div className="inline-flex items-center rounded-lg bg-slate-100 dark:bg-slate-800 p-1" role="group" aria-label="Execution mode">
              <button
                type="button"
                onClick={() => onChangeState((prev) => ({ ...prev, mode: 'sample' }))}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  state.mode === 'sample'
                    ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                }`}
              >
                Sample Data
              </button>
              <button
                type="button"
                onClick={() => onChangeState((prev) => ({ ...prev, mode: 'live' }))}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  state.mode === 'live'
                    ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                }`}
              >
                Live API
              </button>
            </div>
          </div>
        </div>

        {visibleQuotaSnapshots.length > 0 && (
          <div
            data-testid="daily-quota-strip"
            className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-slate-100 dark:border-slate-800 pt-3 text-xs text-slate-600 dark:text-slate-400"
          >
            <span className="font-semibold text-slate-700 dark:text-slate-300">Daily API Quota ({quota.date}):</span>
            {visibleQuotaSnapshots.map((q) => {
              const isApproaching = !q.exhausted && q.percentUsed > 80;
              return (
                <span
                  key={q.providerId}
                  className={`inline-flex items-center gap-1.5 font-mono tabular-nums ${
                    q.exhausted
                      ? 'font-semibold text-red-700 dark:text-red-400'
                      : isApproaching
                        ? 'font-semibold text-amber-700 dark:text-amber-400'
                        : 'text-slate-700 dark:text-slate-300'
                  }`}
                >
                  <span className="font-sans font-medium">{q.name}:</span>
                  <span>
                    {q.used}/{q.limit}
                  </span>
                  <span className="text-slate-400 dark:text-slate-600">/</span>
                  <span
                    className={
                      q.exhausted
                        ? 'text-red-700 dark:text-red-400'
                        : isApproaching
                          ? 'text-amber-700 dark:text-amber-400'
                          : 'text-slate-500 dark:text-slate-400'
                    }
                  >
                    {q.exhausted
                      ? 'Exhausted (failover ready)'
                      : isApproaching
                        ? `${q.percentUsed}% used · ${q.remaining} left`
                        : `${q.remaining} left`}
                  </span>
                </span>
              );
            })}
          </div>
        )}

        <form onSubmit={handleRunLookup} className="mt-6 space-y-5">
          <div>
            <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
              <label htmlFor="ioc-input" className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                Indicators (comma, space, newline, or semicolon separated)
              </label>

              <div className="flex flex-wrap items-center gap-3 shrink-0">
                <button
                  type="button"
                  onClick={() => {
                    onChangeState((prev) => ({ ...prev, rawInput: SAMPLE_BATCH }));
                    setFileImportSummary(null);
                    setErrorMsg(null);
                  }}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <ClipboardList className="h-3.5 w-3.5" aria-hidden="true" />
                  Load Sample IOCs
                </button>
              </div>
            </div>
            <textarea
              id="ioc-input"
              rows={3}
              value={state.rawInput}
              onChange={(e) => onChangeState((prev) => ({ ...prev, rawInput: e.target.value }))}
              placeholder="e.g. 1[.]2[.]3[.]4, hxxp://evil[.]com, 44d88612fea8a8f36de82e1278abb02f"
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-800/70 px-3.5 py-2.5 font-mono text-sm text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
            />
          </div>

          <IndicatorFileUpload
            summary={fileImportSummary}
            onIndicatorsExtracted={handleFileExtracted}
            onError={handleFileError}
            onDismissSummary={() => setFileImportSummary(null)}
          />

          {parsedPreview.length > 0 && (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-slate-600 dark:text-slate-400">
              <span className="font-medium text-slate-500 dark:text-slate-400">Detected ({parsedPreview.length}):</span>
              {parsedPreview.slice(0, 12).map((item, idx) => (
                <span key={`${item.cleaned}-${idx}`} className="inline-flex items-center gap-1.5 font-mono">
                  <span className={item.type ? 'text-slate-900 dark:text-slate-100' : 'text-red-600 dark:text-red-400 line-through'}>
                    {item.cleaned}
                  </span>
                  <span className="text-slate-400 dark:text-slate-600">/</span>
                  <span className={item.type ? 'text-slate-600 dark:text-slate-400' : 'text-red-600 dark:text-red-400'}>
                    {item.type ?? 'invalid'}
                  </span>
                </span>
              ))}
              {parsedPreview.length > 12 && (
                <span className="font-mono text-slate-500 dark:text-slate-400">+{parsedPreview.length - 12} more</span>
              )}
            </div>
          )}

          <div className="space-y-3 border-t border-slate-100 dark:border-slate-800 pt-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex flex-wrap items-center gap-2">
                <div
                  className="grid grid-cols-2 gap-1 rounded-lg bg-slate-100 dark:bg-slate-800 p-1 sm:inline-flex sm:flex-wrap sm:items-center"
                  role="group"
                  aria-label="Intelligence source"
                >
                  {SOURCE_OPTIONS.map((opt) => {
                    const isActive = !state.useCustomSources && state.source === opt.id;
                    const isDisabledInSettings =
                      opt.id !== 'all' && !apiSettings.providers[opt.id].enabled;
                    return (
                      <button
                        key={opt.id}
                        type="button"
                        onClick={() =>
                          onChangeState((prev) => ({
                            ...prev,
                            useCustomSources: false,
                            source: opt.id,
                          }))
                        }
                        className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          isActive
                            ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                            : isDisabledInSettings
                              ? 'text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                              : 'text-slate-600 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white'
                        }`}
                      >
                        {opt.label}
                        {opt.id === 'all' ? ` (${enabledSourceIds.length})` : ''}
                      </button>
                    );
                  })}
                  <button
                    type="button"
                    onClick={() =>
                      onChangeState((prev) => ({
                        ...prev,
                        useCustomSources: true,
                        customSources:
                          prev.customSources.length > 0 ? prev.customSources : [...enabledSourceIds],
                      }))
                    }
                    className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      state.useCustomSources
                        ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                        : 'text-slate-600 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white'
                    }`}
                  >
                    Custom
                  </button>
                </div>

                <button
                  type="button"
                  onClick={onOpenApiConfig}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Settings2 className="h-3.5 w-3.5" aria-hidden="true" />
                  Configure APIs
                </button>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-red-600 px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-red-700 disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
              >
                <Search className="h-4 w-4" aria-hidden="true" />
                {loading ? 'Enriching...' : 'Run Enrichment'}
              </button>
            </div>

            {state.useCustomSources ? (
              <div className="flex flex-wrap items-center gap-4 text-xs text-slate-700 dark:text-slate-300" role="group" aria-label="Custom API selection">
                <span className="font-medium text-slate-500 dark:text-slate-400">Select APIs:</span>
                {allKnownProviders.map((prov) => {
                  const checked = state.customSources.includes(prov.id);
                  const q = quotaById.get(prov.id);
                  return (
                    <label key={prov.id} className="inline-flex items-center gap-2 font-medium text-slate-800 dark:text-slate-200 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggleCustomSource(prov.id)}
                        className="h-3.5 w-3.5 rounded border-slate-300 dark:border-slate-600 text-red-600 focus:ring-red-600"
                      />
                      <span>{prov.name}</span>
                      {q?.exhausted && (
                        <span className="font-mono text-[11px] text-red-700 dark:text-red-400">(quota reached)</span>
                      )}
                    </label>
                  );
                })}
              </div>
            ) : (
              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                <span>Active APIs:</span>
                <span className="font-mono text-slate-700 dark:text-slate-300">
                  {effectiveSources.length > 0
                    ? effectiveSources.map((id) => providerNameMap[id] || id).join(' · ')
                    : 'None enabled'}
                </span>
              </div>
            )}
          </div>
        </form>

        {errorMsg && (
          <div role="alert" className="mt-4 rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/40 px-4 py-3 text-sm text-red-800 dark:text-red-200">
            {errorMsg}
          </div>
        )}

        {state.quotaSkipped.length > 0 && !errorMsg && (
          <div
            role="status"
            data-testid="quota-failover-banner"
            className="mt-4 rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 px-4 py-3 text-xs text-amber-950 dark:text-amber-100"
          >
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-700 dark:text-amber-400" aria-hidden="true" />
              <div>
                <p className="font-semibold">
                  Daily quota failover applied — enrichment continued on remaining available APIs
                </p>
                <p className="mt-0.5 text-amber-900 dark:text-amber-200/90">
                  Skipped:{' '}
                  {state.quotaSkipped
                    .map((s) => `${s.name} (${s.used}/${s.limit}: ${s.reason})`)
                    .join(' · ')}
                </p>
              </div>
            </div>
          </div>
        )}

        {state.invalidTokens.length > 0 && !errorMsg && (
          <div className="mt-4 rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 px-4 py-2.5 text-xs text-amber-900 dark:text-amber-200">
            Skipped invalid indicator(s): <span className="font-mono">{state.invalidTokens.join(', ')}</span>
          </div>
        )}
      </section>

      {state.results.length > 0 ? (
        <section className="space-y-6">
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
            <div className="flex flex-col gap-3 border-b border-slate-200 dark:border-slate-800 px-5 py-4 sm:flex-row sm:items-center sm:justify-between md:px-6">
              <div>
                <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">Summary Matrix</h2>
                <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                  {state.results.length} lookup{state.results.length === 1 ? '' : 's'}
                  {state.lastRunMode ? ` · ${state.lastRunMode === 'sample' ? 'Sample Data' : 'Live API'}` : ''}
                  {state.lastReportFile ? ` · Saved to reports/${state.lastReportFile}` : ''}
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-1 rounded-lg bg-slate-100 dark:bg-slate-800 p-1" role="group" aria-label="Filter by verdict">
                {VERDICT_FILTERS.map((v) => (
                  <button
                    key={v}
                    type="button"
                    onClick={() => setVerdictFilter(v)}
                    className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      verdictFilter === v
                        ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                    }`}
                  >
                    {v}
                  </button>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/60 text-xs font-semibold text-slate-600 dark:text-slate-300">
                    <th className="px-6 py-3">Indicator</th>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Source</th>
                    <th className="px-4 py-3">Verdict</th>
                    <th className="px-4 py-3 text-right">Score</th>
                    <th className="px-6 py-3">Summary</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {filteredResults.map((r, i) => (
                    <tr key={`${r.indicator}-${r.sourceId}-${i}`} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/50">
                      <td className="px-6 py-3 font-mono text-xs font-medium text-slate-900 dark:text-slate-100 break-all">
                        {r.indicator}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-500 dark:text-slate-400">{r.type}</td>
                      <td className="px-4 py-3 text-xs font-medium text-slate-800 dark:text-slate-200 whitespace-nowrap">
                        {r.source}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <VerdictIndicator verdict={r.verdict} status={r.status} />
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-xs text-slate-900 dark:text-slate-100 tabular-nums whitespace-nowrap">
                        {r.score}
                      </td>
                      <td className="px-6 py-3 text-xs text-slate-600 dark:text-slate-300">{r.summary}</td>
                    </tr>
                  ))}
                  {filteredResults.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-6 py-8 text-center text-sm text-slate-500 dark:text-slate-400">
                        No results match the selected verdict filter.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="space-y-6">
            {groupedByIndicator.map((group) => (
              <div key={group.indicator} className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 md:p-6">
                <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-4">
                  <div className="flex items-baseline gap-3">
                    <h3 className="font-mono text-base font-semibold text-slate-950 dark:text-slate-50 break-all">
                      {group.indicator}
                    </h3>
                    <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{group.type}</span>
                  </div>
                  <span className="text-xs text-slate-500 dark:text-slate-400">
                    {group.items.length} source{group.items.length === 1 ? '' : 's'}
                  </span>
                </div>

                <div className="mt-4 grid gap-6 md:grid-cols-3">
                  {group.items.map((item) => (
                    <div key={item.sourceId} className="space-y-3">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">{item.source}</span>
                        <VerdictIndicator verdict={item.verdict} status={item.status} />
                      </div>

                      <p className="text-xs text-slate-600 dark:text-slate-300">{item.summary}</p>

                      {Object.keys(item.details).length > 0 && (
                        <dl className="divide-y divide-slate-100 dark:divide-slate-800 border-t border-slate-100 dark:border-slate-800 text-xs">
                          {Object.entries(item.details).map(([k, v]) => (
                            <div key={k} className="flex items-baseline justify-between gap-4 py-1.5">
                              <dt className="text-slate-500 dark:text-slate-400 shrink-0">{k}</dt>
                              <dd className="text-right font-mono text-slate-800 dark:text-slate-200 tabular-nums break-all">
                                {String(v)}
                              </dd>
                            </div>
                          ))}
                        </dl>
                      )}

                      {item.link && (
                        <a
                          href={item.link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-xs font-medium text-red-700 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 hover:underline"
                        >
                          Open in {item.source}
                          <ExternalLink className="h-3 w-3" aria-hidden="true" />
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>
      ) : (
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-6 py-12 text-center">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">Ready to enrich indicators</h2>
          <p className="mx-auto mt-1.5 max-w-lg text-sm text-slate-600 dark:text-slate-400">
            Click Run Enrichment above to inspect the sample batch, paste your own IPs, domains, and hashes, or upload a CSV/TXT file for bulk feeds. Every run automatically saves a UTF-8 CSV report and writes audit logs.
          </p>
        </section>
      )}
    </div>
  );
}
