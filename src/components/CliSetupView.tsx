import { useEffect, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  Gauge,
  HelpCircle,
  Mail,
  Plus,
  RotateCcw,
  Save,
  SlidersHorizontal,
  Terminal,
  Trash2,
  XCircle,
} from 'lucide-react';
import {
  BUILTIN_EXTRA_IDS,
  DEFAULT_API_SETTINGS,
  EXTRA_PROVIDER_META,
  validateAndNormalizeApiSettings,
  validateCustomThreatProvider,
  validateSingleProviderUrl,
  type ApiSettings,
  type BuiltinExtraSourceId,
  type CustomThreatProvider,
} from '../utils/apiConfig';
import type { EmailAlertRecord } from '../utils/emailAlerts';
import type { IndicatorType, SourceId } from '../utils/indicators';
import type { ProviderQuotaSnapshot } from '../utils/quota';
import type { QuotaState } from '../App';
import { EmailAlertSettingsPanel } from './EmailAlertSettingsPanel';

interface CliSetupViewProps {
  keyStatus: {
    virustotal: boolean;
    abuseipdb: boolean;
    alienvault: boolean;
  };
  extraKeyStatus: Record<BuiltinExtraSourceId, boolean>;
  customKeyStatus: Record<string, boolean>;
  apiSettings: ApiSettings;
  quota: QuotaState;
  emailAlertsRefreshNonce?: number;
  onApiSettingsChange: (next: ApiSettings) => void;
  onQuotaChange: (next: QuotaState) => void;
  onConnectionTestResult?: (provider: string, ok: boolean) => void;
  onConnectionOverridesReset?: () => void;
  onOpenHelp?: () => void;
  onEmailAlertDispatched?: (record: EmailAlertRecord) => void;
}

interface ConnectionTestResult {
  ok: boolean;
  httpStatus: number;
  latencyMs: number;
  message: string;
}

const CORE_PROVIDER_META: {
  id: SourceId;
  name: string;
  envVar: string;
  support: string;
}[] = [
  { id: 'virustotal', name: 'VirusTotal', envVar: 'VT_API_KEY', support: 'IP, Domain, Hash' },
  { id: 'abuseipdb', name: 'AbuseIPDB', envVar: 'ABUSEIPDB_API_KEY', support: 'IP only' },
  { id: 'alienvault', name: 'AlienVault OTX', envVar: 'OTX_API_KEY', support: 'IP, Domain, Hash' },
];

const ALL_IOC_TYPES: IndicatorType[] = ['ip', 'domain', 'hash'];

function QuotaMeter({
  snapshot,
  onReset,
  resetting,
}: {
  snapshot?: ProviderQuotaSnapshot;
  onReset: () => void;
  resetting: boolean;
}) {
  if (!snapshot) return null;
  const barColor = snapshot.exhausted
    ? 'bg-red-600'
    : snapshot.percentUsed >= 80
      ? 'bg-amber-500'
      : 'bg-emerald-600';

  return (
    <div className="mt-2.5 space-y-1">
      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
        <div className="flex items-center gap-2 font-mono tabular-nums text-slate-700 dark:text-slate-300">
          <span className="font-sans font-medium text-slate-600 dark:text-slate-400">Daily Quota:</span>
          <span>
            {snapshot.used} / {snapshot.limit} used
          </span>
          <span className="text-slate-400 dark:text-slate-600">·</span>
          <span className={snapshot.exhausted ? 'font-semibold text-red-700 dark:text-red-400' : 'text-slate-600 dark:text-slate-400'}>
            {snapshot.exhausted ? 'Quota reached (failover active)' : `${snapshot.remaining} remaining`}
          </span>
        </div>
        {snapshot.used > 0 && (
          <button
            type="button"
            onClick={onReset}
            disabled={resetting}
            className="text-[11px] font-medium text-slate-600 dark:text-slate-400 hover:text-red-700 dark:hover:text-red-400 hover:underline disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
          >
            Reset Counter
          </button>
        )}
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
        <div
          className={`h-full transition-all ${barColor}`}
          style={{ width: `${Math.min(100, snapshot.percentUsed)}%` }}
        />
      </div>
    </div>
  );
}

export function CliSetupView({
  keyStatus,
  extraKeyStatus,
  customKeyStatus,
  apiSettings,
  quota,
  emailAlertsRefreshNonce = 0,
  onApiSettingsChange,
  onQuotaChange,
  onConnectionTestResult,
  onConnectionOverridesReset,
  onOpenHelp,
  onEmailAlertDispatched,
}: CliSetupViewProps) {
  const [draft, setDraft] = useState<ApiSettings>(apiSettings);
  const [saving, setSaving] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [resettingQuotaId, setResettingQuotaId] = useState<string | null>(null);
  const [testingMap, setTestingMap] = useState<Record<string, boolean>>({});
  const [testResults, setTestResults] = useState<Record<string, ConnectionTestResult>>({});
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // New Custom Provider Form State (metadata + env var NAME only, zero secret values)
  const [customName, setCustomName] = useState('');
  const [customEndpoint, setCustomEndpoint] = useState('');
  const [customAuthHeader, setCustomAuthHeader] = useState('X-API-Key');
  const [customAuthPrefix, setCustomAuthPrefix] = useState('');
  const [customEnvVar, setCustomEnvVar] = useState('CUSTOM_THREAT_API_KEY');
  const [customQuotaLimit, setCustomQuotaLimit] = useState(1000);
  const [customSupportedTypes, setCustomSupportedTypes] = useState<IndicatorType[]>(['ip', 'domain', 'hash']);
  const [customFormError, setCustomFormError] = useState<string | null>(null);

  useEffect(() => {
    setDraft(apiSettings);
  }, [apiSettings]);

  const quotaMap = new Map(quota.providers.map((p) => [p.providerId, p]));

  function updateCoreProvider(
    id: SourceId,
    patch: Partial<{ enabled: boolean; baseUrl: string; dailyQuotaLimit: number }>,
  ) {
    setErrorMsg(null);
    setSuccessMsg(null);
    if (patch.baseUrl !== undefined) {
      setTestResults((prev) => {
        if (!prev[id]) return prev;
        const copy = { ...prev };
        delete copy[id];
        return copy;
      });
    }
    setDraft((prev) => ({
      ...prev,
      providers: {
        ...prev.providers,
        [id]: {
          ...prev.providers[id],
          ...patch,
        },
      },
    }));
  }

  function updateExtraProvider(
    id: BuiltinExtraSourceId,
    patch: Partial<{ enabled: boolean; baseUrl: string; dailyQuotaLimit: number }>,
  ) {
    setErrorMsg(null);
    setSuccessMsg(null);
    if (patch.baseUrl !== undefined) {
      setTestResults((prev) => {
        if (!prev[id]) return prev;
        const copy = { ...prev };
        delete copy[id];
        return copy;
      });
    }
    setDraft((prev) => ({
      ...prev,
      extraProviders: {
        ...prev.extraProviders,
        [id]: {
          ...prev.extraProviders[id],
          ...patch,
        },
      },
    }));
  }

  function updateCustomProvider(id: string, patch: Partial<CustomThreatProvider>) {
    setErrorMsg(null);
    setSuccessMsg(null);
    setDraft((prev) => ({
      ...prev,
      customProviders: (prev.customProviders || []).map((cp) =>
        cp.id === id ? { ...cp, ...patch } : cp,
      ),
    }));
  }

  async function persistSettings(candidate: ApiSettings, message: string) {
    const check = validateAndNormalizeApiSettings(candidate);
    if (!check.ok) {
      setErrorMsg(check.error);
      return false;
    }

    setSaving(true);
    try {
      const resp = await fetch('/api/config/apis', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(check.settings),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setErrorMsg(data.error || 'Failed to save API configuration.');
        return false;
      }
      onApiSettingsChange(data.settings);
      setDraft(data.settings);
      if (data.quota?.date && Array.isArray(data.quota?.providers)) {
        onQuotaChange(data.quota);
      }
      setSuccessMsg(message);
      return true;
    } catch {
      setErrorMsg('Unable to reach server to save API settings.');
      return false;
    } finally {
      setSaving(false);
    }
  }

  async function handleAddCustomProvider(e: React.FormEvent) {
    e.preventDefault();
    setCustomFormError(null);
    setErrorMsg(null);
    setSuccessMsg(null);

    const check = validateCustomThreatProvider({
      name: customName,
      enabled: true,
      endpointTemplate: customEndpoint,
      authHeader: customAuthHeader,
      authPrefix: customAuthPrefix,
      envVarName: customEnvVar,
      supportedTypes: customSupportedTypes,
      dailyQuotaLimit: customQuotaLimit,
    });
    if (!check.ok) {
      setCustomFormError(check.error);
      return;
    }

    const updatedDraft: ApiSettings = {
      ...draft,
      customProviders: [...(draft.customProviders || []), check.provider],
    };
    const ok = await persistSettings(
      updatedDraft,
      `Added custom threat intelligence API "${check.provider.name}". Set ${check.provider.envVarName} in .env for live requests.`,
    );
    if (ok) {
      setCustomName('');
      setCustomEndpoint('');
      setCustomAuthHeader('X-API-Key');
      setCustomAuthPrefix('');
      setCustomEnvVar('CUSTOM_THREAT_API_KEY');
      setCustomQuotaLimit(1000);
      setCustomSupportedTypes(['ip', 'domain', 'hash']);
    }
  }

  async function handleRemoveCustomProvider(id: string) {
    const target = (draft.customProviders || []).find((c) => c.id === id);
    const updatedDraft: ApiSettings = {
      ...draft,
      customProviders: (draft.customProviders || []).filter((c) => c.id !== id),
    };
    await persistSettings(
      updatedDraft,
      `Removed custom API integration${target ? ` "${target.name}"` : ''}.`,
    );
  }

  async function handleTestConnection(id: string, baseUrlOverride?: string) {
    setErrorMsg(null);
    setSuccessMsg(null);

    const isCoreOrExtra =
      id === 'virustotal' ||
      id === 'abuseipdb' ||
      id === 'alienvault' ||
      id === 'shodan' ||
      id === 'threatfox' ||
      id === 'urlscan';

    let payloadUrl: string | undefined;
    if (isCoreOrExtra && baseUrlOverride) {
      const urlCheck = validateSingleProviderUrl(baseUrlOverride, id);
      if (!urlCheck.ok) {
        setTestResults((prev) => ({
          ...prev,
          [id]: { ok: false, httpStatus: 0, latencyMs: 0, message: urlCheck.error },
        }));
        onConnectionTestResult?.(id, false);
        return;
      }
      payloadUrl = urlCheck.url;
    }

    setTestingMap((prev) => ({ ...prev, [id]: true }));
    try {
      const resp = await fetch('/api/config/apis/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: id,
          baseUrl: payloadUrl,
          timeoutSeconds: draft.timeoutSeconds,
        }),
      });
      const data = await resp.json();
      const ok = Boolean(data.ok);
      setTestResults((prev) => ({
        ...prev,
        [id]: {
          ok,
          httpStatus: Number(data.httpStatus || 0),
          latencyMs: Number(data.latencyMs || 0),
          message: data.message || data.error || 'Heartbeat check completed.',
        },
      }));
      if (data.quota?.date && Array.isArray(data.quota?.providers)) {
        onQuotaChange(data.quota);
      }
      onConnectionTestResult?.(id, ok);
    } catch {
      setTestResults((prev) => ({
        ...prev,
        [id]: {
          ok: false,
          httpStatus: 0,
          latencyMs: 0,
          message: 'Unable to reach local server for heartbeat check.',
        },
      }));
      onConnectionTestResult?.(id, false);
    } finally {
      setTestingMap((prev) => ({ ...prev, [id]: false }));
    }
  }

  async function handleSaveSettings(e: React.FormEvent) {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);
    await persistSettings(
      draft,
      'API configuration and daily quota limits saved and applied to live enrichment lookups.',
    );
  }

  async function handleResetDefaults() {
    setErrorMsg(null);
    setSuccessMsg(null);
    setResetting(true);
    try {
      const resp = await fetch('/api/config/apis/reset', { method: 'POST' });
      const data = await resp.json();
      if (!resp.ok) {
        setErrorMsg(data.error || 'Failed to reset API settings.');
        return;
      }
      onApiSettingsChange(data.settings);
      setDraft(data.settings);
      if (data.quota?.date && Array.isArray(data.quota?.providers)) {
        onQuotaChange(data.quota);
      }
      setTestResults({});
      onConnectionOverridesReset?.();
      setSuccessMsg('Restored default endpoints, enabled states, and request limits.');
    } catch {
      setErrorMsg('Unable to reach server to reset API settings.');
    } finally {
      setResetting(false);
    }
  }

  async function handleResetQuota(providerId?: string) {
    setErrorMsg(null);
    setSuccessMsg(null);
    setResettingQuotaId(providerId || 'all');
    try {
      const resp = await fetch('/api/quota/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(providerId ? { providerId } : {}),
      });
      const data = await resp.json();
      if (resp.ok && data?.date && Array.isArray(data?.providers)) {
        onQuotaChange({ date: data.date, providers: data.providers });
        setSuccessMsg(
          providerId
            ? `Reset today's quota usage counter for ${providerId}.`
            : 'Reset today’s daily quota counters for all threat intelligence APIs.',
        );
      }
    } catch {
      setErrorMsg('Unable to reset daily quota ledger.');
    } finally {
      setResettingQuotaId(null);
    }
  }

  function toggleNewCustomType(t: IndicatorType) {
    setCustomSupportedTypes((prev) =>
      prev.includes(t) ? prev.filter((item) => item !== t) : [...prev, t],
    );
  }

  const exhaustedCount = quota.providers.filter((p) => p.exhausted).length;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-950 dark:text-slate-50">
            API Configuration, Quotas &amp; Integrations
          </h1>
          <p className="mt-0.5 text-sm text-slate-600 dark:text-slate-400">
            Manage core and additional threat intelligence APIs, monitor daily request quotas with automatic failover, or run{' '}
            <code className="font-mono text-xs">main.py</code>.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs shrink-0">
          <span className="inline-flex items-center gap-1.5 font-mono tabular-nums text-slate-600 dark:text-slate-400">
            <Gauge className="h-3.5 w-3.5 text-slate-500 dark:text-slate-400" aria-hidden="true" />
            <span>UTC Ledger: {quota.date}</span>
            {exhaustedCount > 0 && (
              <>
                <span aria-hidden="true">·</span>
                <span className="font-semibold text-red-700 dark:text-red-400">{exhaustedCount} exhausted</span>
              </>
            )}
          </span>
          <button
            type="button"
            onClick={() => handleResetQuota()}
            disabled={resettingQuotaId !== null}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
            {resettingQuotaId === 'all' ? 'Resetting Quotas...' : 'Reset Daily Quotas'}
          </button>
          {onOpenHelp && (
            <button
              type="button"
              onClick={onOpenHelp}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <HelpCircle className="h-3.5 w-3.5" aria-hidden="true" />
              API Key Guide
            </button>
          )}
        </div>
      </div>

      <section
        aria-label="Threat Intelligence API Settings"
        className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6"
      >
        <form onSubmit={handleSaveSettings} className="space-y-6">
          <div className="flex flex-col gap-3 border-b border-slate-100 dark:border-slate-800 pb-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="flex items-center gap-2">
                <SlidersHorizontal className="h-4 w-4 text-slate-700 dark:text-slate-300" aria-hidden="true" />
                <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">Core &amp; Built-In Threat Intelligence APIs</h2>
              </div>
              <p className="mt-0.5 text-xs text-slate-600 dark:text-slate-400">
                Set server env keys in <code className="font-mono">.env</code> (API secrets never enter the browser). When an API hits its daily quota limit or HTTP 429, lookups automatically fail over to remaining available APIs.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2.5 shrink-0">
              <button
                type="button"
                onClick={handleResetDefaults}
                disabled={resetting || saving}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3.5 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                {resetting ? 'Resetting...' : 'Reset Defaults'}
              </button>
              <button
                type="submit"
                disabled={saving || resetting}
                className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white hover:bg-red-700 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
              >
                <Save className="h-3.5 w-3.5" aria-hidden="true" />
                {saving ? 'Saving...' : 'Save API Settings'}
              </button>
            </div>
          </div>

          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            {CORE_PROVIDER_META.map((p) => {
              const cfg = draft.providers[p.id];
              const isConfigured = keyStatus[p.id];
              const defaultUrl = DEFAULT_API_SETTINGS.providers[p.id].baseUrl;
              const isTesting = Boolean(testingMap[p.id]);
              const testResult = testResults[p.id];
              const snapshot = quotaMap.get(p.id);

              return (
                <div
                  key={p.id}
                  className="grid gap-4 py-4 md:grid-cols-[260px_1fr] md:items-start"
                >
                  <div className="min-w-0 space-y-1 pt-1">
                    <label
                      htmlFor={`enable-api-${p.id}`}
                      className="inline-flex items-center gap-2.5 text-sm font-semibold text-slate-950 dark:text-slate-50 cursor-pointer"
                    >
                      <input
                        id={`enable-api-${p.id}`}
                        type="checkbox"
                        checked={cfg.enabled}
                        onChange={(e) => updateCoreProvider(p.id, { enabled: e.target.checked })}
                        className="h-4 w-4 rounded border-slate-300 dark:border-slate-700 dark:bg-slate-950 text-red-600 focus:ring-red-600"
                      />
                      <span>{p.name}</span>
                    </label>
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 pl-6.5 text-xs text-slate-500 dark:text-slate-400">
                      <span className="font-mono">{p.envVar}</span>
                      <span aria-hidden="true">·</span>
                      <span>{p.support}</span>
                      <span aria-hidden="true">·</span>
                      {isConfigured ? (
                        <span className="inline-flex items-center gap-1 font-medium text-emerald-700 dark:text-emerald-400">
                          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                          Key ready
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 font-medium text-slate-500 dark:text-slate-400">
                          <XCircle className="h-3.5 w-3.5" aria-hidden="true" />
                          Key not set
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="min-w-0">
                    <div className="grid gap-2.5 sm:grid-cols-[1fr_140px]">
                      <div className="min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <label htmlFor={`api-url-${p.id}`} className="text-xs font-medium text-slate-700 dark:text-slate-300 shrink-0">
                            {p.name} API Base URL
                          </label>
                          <span className="font-mono text-[11px] text-slate-400 dark:text-slate-500 truncate max-w-[200px]">
                            {defaultUrl}
                          </span>
                        </div>
                        <div className="mt-1 flex flex-col gap-2 sm:flex-row sm:items-center">
                          <input
                            id={`api-url-${p.id}`}
                            type="url"
                            value={cfg.baseUrl}
                            onChange={(e) => updateCoreProvider(p.id, { baseUrl: e.target.value })}
                            disabled={!cfg.enabled}
                            placeholder={defaultUrl}
                            className="flex-1 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none disabled:opacity-50"
                          />
                          <button
                            type="button"
                            onClick={() => handleTestConnection(p.id, cfg.baseUrl)}
                            disabled={isTesting || saving || resetting}
                            className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3.5 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-100"
                          >
                            <Activity className="h-3.5 w-3.5" aria-hidden="true" />
                            <span>{isTesting ? 'Testing...' : 'Test Connection'}</span>
                            <span className="sr-only"> for {p.name}</span>
                          </button>
                        </div>
                      </div>

                      <div>
                        <label
                          htmlFor={`quota-limit-${p.id}`}
                          className="block text-xs font-medium text-slate-700 dark:text-slate-300"
                        >
                          Daily Quota
                        </label>
                        <input
                          id={`quota-limit-${p.id}`}
                          type="number"
                          min={1}
                          max={1000000}
                          value={cfg.dailyQuotaLimit}
                          onChange={(e) =>
                            updateCoreProvider(p.id, {
                              dailyQuotaLimit: Number.parseInt(e.target.value || '500', 10),
                            })
                          }
                          className="mt-1 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 tabular-nums focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
                        />
                      </div>
                    </div>

                    <QuotaMeter
                      snapshot={snapshot}
                      onReset={() => handleResetQuota(p.id)}
                      resetting={resettingQuotaId === p.id}
                    />

                    {testResult && (
                      <div
                        data-testid={`test-result-${p.id}`}
                        className={`mt-2 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs ${
                          testResult.ok ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'
                        }`}
                      >
                        {testResult.ok ? (
                          <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        )}
                        <span className="font-medium">{testResult.message}</span>
                        {testResult.httpStatus > 0 && (
                          <span className="font-mono text-[11px] opacity-80 tabular-nums">
                            · HTTP {testResult.httpStatus} · {testResult.latencyMs} ms
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}

            {BUILTIN_EXTRA_IDS.map((id) => {
              const meta = EXTRA_PROVIDER_META[id];
              const cfg = draft.extraProviders?.[id] || DEFAULT_API_SETTINGS.extraProviders[id];
              const isConfigured = extraKeyStatus[id];
              const isTesting = Boolean(testingMap[id]);
              const testResult = testResults[id];
              const snapshot = quotaMap.get(id);

              return (
                <div
                  key={id}
                  className="grid gap-4 py-4 md:grid-cols-[260px_1fr] md:items-start"
                >
                  <div className="min-w-0 space-y-1 pt-1">
                    <label
                      htmlFor={`enable-api-${id}`}
                      className="inline-flex items-center gap-2.5 text-sm font-semibold text-slate-950 dark:text-slate-50 cursor-pointer"
                    >
                      <input
                        id={`enable-api-${id}`}
                        type="checkbox"
                        checked={cfg.enabled}
                        onChange={(e) => updateExtraProvider(id, { enabled: e.target.checked })}
                        className="h-4 w-4 rounded border-slate-300 dark:border-slate-700 dark:bg-slate-950 text-red-600 focus:ring-red-600"
                      />
                      <span>{meta.name}</span>
                    </label>
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 pl-6.5 text-xs text-slate-500 dark:text-slate-400">
                      <span className="font-mono">{meta.envVar}</span>
                      <span aria-hidden="true">·</span>
                      <span>{meta.support}</span>
                      <span aria-hidden="true">·</span>
                      {isConfigured ? (
                        <span className="inline-flex items-center gap-1 font-medium text-emerald-700 dark:text-emerald-400">
                          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                          Key ready
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 font-medium text-slate-500 dark:text-slate-400">
                          <XCircle className="h-3.5 w-3.5" aria-hidden="true" />
                          Key not set
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="min-w-0">
                    <div className="grid gap-2.5 sm:grid-cols-[1fr_140px]">
                      <div className="min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <label htmlFor={`api-url-${id}`} className="text-xs font-medium text-slate-700 dark:text-slate-300 shrink-0">
                            {meta.name} API Base URL
                          </label>
                          <span className="font-mono text-[11px] text-slate-400 dark:text-slate-500 truncate max-w-[200px]">
                            {meta.defaultUrl}
                          </span>
                        </div>
                        <div className="mt-1 flex flex-col gap-2 sm:flex-row sm:items-center">
                          <input
                            id={`api-url-${id}`}
                            type="url"
                            value={cfg.baseUrl}
                            onChange={(e) => updateExtraProvider(id, { baseUrl: e.target.value })}
                            disabled={!cfg.enabled}
                            placeholder={meta.defaultUrl}
                            className="flex-1 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none disabled:opacity-50"
                          />
                          <button
                            type="button"
                            onClick={() => handleTestConnection(id, cfg.baseUrl)}
                            disabled={isTesting || saving || resetting}
                            className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3.5 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-100"
                          >
                            <Activity className="h-3.5 w-3.5" aria-hidden="true" />
                            <span>{isTesting ? 'Testing...' : 'Test Connection'}</span>
                            <span className="sr-only"> for {meta.name}</span>
                          </button>
                        </div>
                      </div>

                      <div>
                        <label
                          htmlFor={`quota-limit-${id}`}
                          className="block text-xs font-medium text-slate-700 dark:text-slate-300"
                        >
                          Daily Quota
                        </label>
                        <input
                          id={`quota-limit-${id}`}
                          type="number"
                          min={1}
                          max={1000000}
                          value={cfg.dailyQuotaLimit}
                          onChange={(e) =>
                            updateExtraProvider(id, {
                              dailyQuotaLimit: Number.parseInt(e.target.value || String(meta.defaultQuota), 10),
                            })
                          }
                          className="mt-1 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 tabular-nums focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
                        />
                      </div>
                    </div>

                    <QuotaMeter
                      snapshot={snapshot}
                      onReset={() => handleResetQuota(id)}
                      resetting={resettingQuotaId === id}
                    />

                    {testResult && (
                      <div
                        data-testid={`test-result-${id}`}
                        className={`mt-2 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs ${
                          testResult.ok ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'
                        }`}
                      >
                        {testResult.ok ? (
                          <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        )}
                        <span className="font-medium">{testResult.message}</span>
                        {testResult.httpStatus > 0 && (
                          <span className="font-mono text-[11px] opacity-80 tabular-nums">
                            · HTTP {testResult.httpStatus} · {testResult.latencyMs} ms
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="grid gap-4 border-t border-slate-100 dark:border-slate-800 pt-4 sm:grid-cols-2">
            <div>
              <label htmlFor="api-timeout-seconds" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                Request Timeout (seconds)
              </label>
              <input
                id="api-timeout-seconds"
                type="number"
                min={5}
                max={60}
                value={draft.timeoutSeconds}
                onChange={(e) => {
                  setErrorMsg(null);
                  setSuccessMsg(null);
                  setDraft((prev) => ({
                    ...prev,
                    timeoutSeconds: Number.parseInt(e.target.value || '20', 10),
                  }));
                }}
                className="mt-1.5 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 tabular-nums focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
              />
              <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">Allowed range: 5–60 seconds (default: 20).</p>
            </div>

            <div>
              <label htmlFor="abuseipdb-max-age" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                AbuseIPDB Report Window (days)
              </label>
              <input
                id="abuseipdb-max-age"
                type="number"
                min={1}
                max={365}
                value={draft.abuseMaxAgeDays}
                onChange={(e) => {
                  setErrorMsg(null);
                  setSuccessMsg(null);
                  setDraft((prev) => ({
                    ...prev,
                    abuseMaxAgeDays: Number.parseInt(e.target.value || '90', 10),
                  }));
                }}
                className="mt-1.5 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 tabular-nums focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
              />
              <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">Allowed range: 1–365 days (default: 90).</p>
            </div>
          </div>

          {errorMsg && (
            <div role="alert" className="rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/50 px-4 py-2.5 text-xs text-red-800 dark:text-red-200">
              {errorMsg}
            </div>
          )}

          {successMsg && (
            <div role="status" className="rounded-lg border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50 dark:bg-emerald-950/50 px-4 py-2.5 text-xs text-emerald-800 dark:text-emerald-200">
              {successMsg}
            </div>
          )}
        </form>
      </section>

      <section
        aria-label="Custom Threat Intelligence Integrations"
        className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-6"
      >
        <div className="border-b border-slate-100 dark:border-slate-800 pb-4">
          <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">Add Custom Threat Intelligence API</h2>
          <p className="mt-0.5 text-xs text-slate-600 dark:text-slate-400">
            Connect any third-party threat intel endpoint (e.g. GreyNoise, Pulsedive, IPQualityScore). Reference the server environment variable name where the secret key lives in <code className="font-mono">.env</code>.
          </p>
        </div>

        {(draft.customProviders || []).length > 0 ? (
          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            {(draft.customProviders || []).map((cp) => {
              const isConfigured = Boolean(customKeyStatus[cp.id]);
              const isTesting = Boolean(testingMap[cp.id]);
              const testResult = testResults[cp.id];
              const snapshot = quotaMap.get(cp.id);

              return (
                <div key={cp.id} className="grid gap-4 py-4 md:grid-cols-[260px_1fr] md:items-start">
                  <div className="min-w-0 space-y-1 pt-1">
                    <label
                      htmlFor={`enable-custom-${cp.id}`}
                      className="inline-flex items-center gap-2.5 text-sm font-semibold text-slate-950 dark:text-slate-50 cursor-pointer"
                    >
                      <input
                        id={`enable-custom-${cp.id}`}
                        type="checkbox"
                        checked={cp.enabled}
                        onChange={(e) => updateCustomProvider(cp.id, { enabled: e.target.checked })}
                        className="h-4 w-4 rounded border-slate-300 dark:border-slate-700 dark:bg-slate-950 text-red-600 focus:ring-red-600"
                      />
                      <span>{cp.name}</span>
                    </label>
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 pl-6.5 text-xs text-slate-500 dark:text-slate-400">
                      <span className="font-mono">{cp.envVarName}</span>
                      <span aria-hidden="true">·</span>
                      <span>{cp.supportedTypes.join(', ').toUpperCase()}</span>
                      <span aria-hidden="true">·</span>
                      {isConfigured ? (
                        <span className="inline-flex items-center gap-1 font-medium text-emerald-700 dark:text-emerald-400">
                          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                          Key ready
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 font-medium text-slate-500 dark:text-slate-400">
                          <XCircle className="h-3.5 w-3.5" aria-hidden="true" />
                          Key not set
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="font-mono text-xs text-slate-700 dark:text-slate-300 break-all">
                        {cp.endpointTemplate}{' '}
                        <span className="text-slate-400 dark:text-slate-500">
                          ({cp.authHeader}
                          {cp.authPrefix ? `: ${cp.authPrefix} <key>` : ''})
                        </span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          type="button"
                          onClick={() => handleTestConnection(cp.id)}
                          disabled={isTesting || saving}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          <Activity className="h-3.5 w-3.5" aria-hidden="true" />
                          {isTesting ? 'Testing...' : 'Test Connection'}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleRemoveCustomProvider(cp.id)}
                          disabled={saving}
                          aria-label={`Remove ${cp.name}`}
                          className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-1.5 text-xs font-medium text-red-700 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                          Remove
                        </button>
                      </div>
                    </div>

                    <QuotaMeter
                      snapshot={snapshot}
                      onReset={() => handleResetQuota(cp.id)}
                      resetting={resettingQuotaId === cp.id}
                    />

                    {testResult && (
                      <div
                        data-testid={`test-result-${cp.id}`}
                        className={`mt-2 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs ${
                          testResult.ok ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'
                        }`}
                      >
                        {testResult.ok ? (
                          <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        )}
                        <span className="font-medium">{testResult.message}</span>
                        {testResult.httpStatus > 0 && (
                          <span className="font-mono text-[11px] opacity-80 tabular-nums">
                            · HTTP {testResult.httpStatus} · {testResult.latencyMs} ms
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <p className="text-xs text-slate-500 dark:text-slate-400">
            No custom external APIs added yet. Use the form below to register an additional threat intelligence feed.
          </p>
        )}

        <form onSubmit={handleAddCustomProvider} className="space-y-4 border-t border-slate-100 dark:border-slate-800 pt-5">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <div>
              <label htmlFor="custom-provider-name" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                Provider Name
              </label>
              <input
                id="custom-provider-name"
                type="text"
                value={customName}
                onChange={(e) => setCustomName(e.target.value)}
                placeholder="e.g. GreyNoise Community"
                className="mt-1.5 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
              />
            </div>

            <div className="sm:col-span-2">
              <label htmlFor="custom-endpoint-template" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                Endpoint URL Template (<code className="font-mono">{'{indicator}'}</code>)
              </label>
              <input
                id="custom-endpoint-template"
                type="url"
                value={customEndpoint}
                onChange={(e) => setCustomEndpoint(e.target.value)}
                placeholder="https://api.greynoise.io/v3/community/{indicator}"
                className="mt-1.5 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
              />
            </div>

            <div>
              <label htmlFor="custom-env-var" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                Server Env Variable Name
              </label>
              <input
                id="custom-env-var"
                type="text"
                value={customEnvVar}
                onChange={(e) => setCustomEnvVar(e.target.value.toUpperCase())}
                placeholder="CUSTOM_THREAT_API_KEY"
                className="mt-1.5 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
              />
              <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                Define the secret value in server <code className="font-mono">.env</code> under this variable name.
              </p>
            </div>

            <div>
              <label htmlFor="custom-auth-header" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                Auth Header &amp; Optional Prefix
              </label>
              <div className="mt-1.5 grid grid-cols-2 gap-2">
                <input
                  id="custom-auth-header"
                  type="text"
                  value={customAuthHeader}
                  onChange={(e) => setCustomAuthHeader(e.target.value)}
                  placeholder="X-API-Key"
                  aria-label="Auth header name"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
                />
                <input
                  type="text"
                  value={customAuthPrefix}
                  onChange={(e) => setCustomAuthPrefix(e.target.value)}
                  placeholder="Prefix (e.g. Bearer)"
                  aria-label="Auth header prefix"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label htmlFor="custom-quota-limit" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                Daily Quota Limit
              </label>
              <input
                id="custom-quota-limit"
                type="number"
                min={1}
                max={1000000}
                value={customQuotaLimit}
                onChange={(e) => setCustomQuotaLimit(Number.parseInt(e.target.value || '1000', 10))}
                className="mt-1.5 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 tabular-nums focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
              />
            </div>
          </div>

          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-wrap items-center gap-4 text-xs" role="group" aria-label="Supported indicator types">
              <span className="font-medium text-slate-700 dark:text-slate-300">Supported IOC Types:</span>
              {ALL_IOC_TYPES.map((t) => (
                <label key={t} className="inline-flex items-center gap-1.5 font-mono uppercase text-slate-700 dark:text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={customSupportedTypes.includes(t)}
                    onChange={() => toggleNewCustomType(t)}
                    className="h-3.5 w-3.5 rounded border-slate-300 dark:border-slate-700 dark:bg-slate-950 text-red-600 focus:ring-red-600"
                  />
                  <span>{t}</span>
                </label>
              ))}
            </div>

            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-slate-900 dark:bg-slate-100 px-4 py-2 text-xs font-semibold text-white dark:text-slate-950 hover:bg-slate-800 dark:hover:bg-slate-200 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Plus className="h-3.5 w-3.5" aria-hidden="true" />
              Add Threat Intel API
            </button>
          </div>

          {customFormError && (
            <div role="alert" className="rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/50 px-4 py-2 text-xs text-red-800 dark:text-red-200">
              {customFormError}
            </div>
          )}
        </form>
      </section>

      <section
        aria-label="Threshold Email Notifications"
        data-testid="cli-email-alerts-section"
        className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-5"
      >
        <div className="border-b border-slate-100 dark:border-slate-800 pb-4">
          <div className="flex items-center gap-2">
            <Mail className="h-4 w-4 text-slate-700 dark:text-slate-300" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">
              Email Threshold Notifications
            </h2>
          </div>
          <p className="mt-0.5 text-xs text-slate-600 dark:text-slate-400">
            Automatically dispatch threshold alerts whenever any investigated or scheduled IOC exceeds a configured weighted Confidence Score (e.g., Critical ≥ 75/100). Optional SMTP relay settings live in server <code className="font-mono">.env</code> (<code className="font-mono">SMTP_HOST</code>, <code className="font-mono">SMTP_PORT</code>, <code className="font-mono">SMTP_USER</code>, <code className="font-mono">SMTP_PASS</code>).
          </p>
        </div>

        <EmailAlertSettingsPanel
          refreshNonce={emailAlertsRefreshNonce}
          onAlertDispatched={onEmailAlertDispatched}
        />
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="min-w-0 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 sm:p-6">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-slate-700 dark:text-slate-300" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-slate-950 dark:text-slate-50">CLI Usage</h2>
          </div>

          <pre className="mt-4 overflow-x-auto rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-xs leading-relaxed text-slate-200">
{`# Interactive terminal menu
cp .env.example .env
pip install -r requirements.txt
python3 main.py

# One-line batch enrichment (defanged IOCs supported)
python3 main.py --source all --indicators "1[.]2[.]3[.]4, hxxp://evil[.]com"

# Recurring check scheduling (synced with config/schedules.json)
python3 main.py --add-schedule --schedule-name "DNS Watch" --interval 60 --indicators "8.8.8.8, 1.1.1.1"
python3 main.py --list-schedules
python3 main.py --run-due`}
          </pre>
        </section>

        <section className="min-w-0 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 sm:p-6">
          <h2 className="text-sm font-semibold text-slate-950 dark:text-slate-50">Verdict Normalization Rules</h2>
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300">
                  <th className="py-2 pr-4">Source</th>
                  <th className="py-2 px-4">Malicious</th>
                  <th className="py-2 px-4">Suspicious</th>
                  <th className="py-2 pl-4">Clean / Unknown</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-slate-700 dark:text-slate-300">
                <tr>
                  <td className="py-2.5 pr-4 font-semibold text-slate-900 dark:text-slate-100">VirusTotal</td>
                  <td className="py-2.5 px-4 font-mono">&ge; 5 engines</td>
                  <td className="py-2.5 px-4 font-mono">1-4 malicious or suspicious</td>
                  <td className="py-2.5 pl-4 font-mono">0 = Clean</td>
                </tr>
                <tr>
                  <td className="py-2.5 pr-4 font-semibold text-slate-900 dark:text-slate-100">AbuseIPDB</td>
                  <td className="py-2.5 px-4 font-mono">confidence &ge; 75%</td>
                  <td className="py-2.5 px-4 font-mono">25% - 74%</td>
                  <td className="py-2.5 pl-4 font-mono">&lt; 25% = Clean</td>
                </tr>
                <tr>
                  <td className="py-2.5 pr-4 font-semibold text-slate-900 dark:text-slate-100">AlienVault OTX</td>
                  <td className="py-2.5 px-4 font-mono">&ge; 5 pulses</td>
                  <td className="py-2.5 px-4 font-mono">1-4 pulses</td>
                  <td className="py-2.5 pl-4 font-mono">0 = Unknown</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}
