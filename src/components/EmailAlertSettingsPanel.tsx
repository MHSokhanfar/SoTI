import { useEffect, useState } from 'react';
import {
  CheckCircle2,
  Download,
  Loader2,
  Mail,
  Send,
  Trash2,
  XCircle,
} from 'lucide-react';
import {
  DEFAULT_EMAIL_ALERT_CONFIG,
  thresholdFromTierPreset,
  type EmailAlertConfig,
  type EmailAlertRecord,
  type EmailAlertTierPreset,
} from '../utils/emailAlerts';
import { maskSensitiveText } from '../utils/privacyMode';
import { usePrivacyMode } from './PrivacyModeContext';

export interface SmtpPublicStatus {
  configured: boolean;
  hostLabel: string | null;
  secure: boolean;
  fromAddress: string;
}

interface EmailAlertSettingsPanelProps {
  compact?: boolean;
  refreshNonce?: number;
  onAlertDispatched?: (record: EmailAlertRecord) => void;
}

function downloadEmlFile(record: EmailAlertRecord) {
  const blob = new Blob([record.emlContent], { type: 'message/rfc822;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${record.id}.eml`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function EmailAlertSettingsPanel({
  compact = false,
  refreshNonce = 0,
  onAlertDispatched,
}: EmailAlertSettingsPanelProps) {
  const privacyMode = usePrivacyMode();
  const [config, setConfig] = useState<EmailAlertConfig>(DEFAULT_EMAIL_ALERT_CONFIG);
  const [recipientsInput, setRecipientsInput] = useState('');
  const [smtp, setSmtp] = useState<SmtpPublicStatus>({
    configured: false,
    hostLabel: null,
    secure: false,
    fromAddress: 'soti-alerts@soti.local',
  });
  const [history, setHistory] = useState<EmailAlertRecord[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [clearingHistory, setClearingHistory] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  async function loadAll() {
    try {
      const [cfgResp, histResp] = await Promise.all([
        fetch('/api/alerts/email/config'),
        fetch('/api/alerts/email/history'),
      ]);
      if (cfgResp.ok) {
        const cfgData = await cfgResp.json();
        if (cfgData?.config) {
          setConfig(cfgData.config);
          setRecipientsInput((cfgData.config.recipients || []).join(', '));
        }
        if (cfgData?.smtp) setSmtp(cfgData.smtp);
      }
      if (histResp.ok) {
        const histData = await histResp.json();
        if (Array.isArray(histData?.records)) {
          setHistory(histData.records);
        }
        if (histData?.smtp) setSmtp(histData.smtp);
      }
    } catch {
      setErrorMsg('Unable to load email threshold alert settings.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAll();
  }, [refreshNonce]);

  function handlePresetChange(preset: EmailAlertTierPreset) {
    setErrorMsg(null);
    setStatusMsg(null);
    setConfig((prev) => ({
      ...prev,
      riskTierPreset: preset,
      minConfidenceScore:
        preset === 'Custom' ? prev.minConfidenceScore : thresholdFromTierPreset(preset),
    }));
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setErrorMsg(null);
    setStatusMsg(null);
    setSaving(true);
    try {
      const resp = await fetch('/api/alerts/email/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...config,
          recipientsInput,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setErrorMsg(data?.error || 'Failed to save email alert rule.');
        return;
      }
      if (data?.config) {
        setConfig(data.config);
        setRecipientsInput((data.config.recipients || []).join(', '));
      }
      if (data?.smtp) setSmtp(data.smtp);
      setStatusMsg(
        data.config?.enabled
          ? `Threshold alerts enabled (${data.config.riskTierPreset} ≥ ${data.config.minConfidenceScore}/100) for ${data.config.recipients.length} recipient(s).`
          : 'Threshold email alert preferences saved (paused).',
      );
    } catch {
      setErrorMsg('Network error while saving email alert configuration.');
    } finally {
      setSaving(false);
    }
  }

  async function handleSendTest() {
    setErrorMsg(null);
    setStatusMsg(null);
    setTesting(true);
    try {
      const resp = await fetch('/api/alerts/email/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...config,
          recipientsInput,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setErrorMsg(data?.error || 'Failed to dispatch test alert email.');
        return;
      }
      if (data?.record) {
        setHistory((prev) => [data.record, ...prev].slice(0, 50));
        onAlertDispatched?.(data.record);
        setStatusMsg(
          data.record.deliveryStatus === 'sent'
            ? `Test alert sent to ${data.record.recipients.join(', ')}.`
            : `Test alert composed & saved to outbox for ${data.record.recipients.join(', ')} (.eml ready to download).`,
        );
      }
    } catch {
      setErrorMsg('Network error while sending test alert.');
    } finally {
      setTesting(false);
    }
  }

  async function handleClearHistory() {
    setClearingHistory(true);
    setErrorMsg(null);
    try {
      const resp = await fetch('/api/alerts/email/history', { method: 'DELETE' });
      if (resp.ok) {
        setHistory([]);
        setExpandedId(null);
      }
    } finally {
      setClearingHistory(false);
    }
  }

  if (loading) {
    return (
      <div className={compact ? 'p-4 text-xs text-slate-500 dark:text-slate-400' : 'p-6 text-sm text-slate-500 dark:text-slate-400'}>
        Loading email threshold alert configuration...
      </div>
    );
  }

  return (
    <div
      data-testid="email-alert-settings-panel"
      className={compact ? 'space-y-4 p-4' : 'space-y-6'}
    >
      <form onSubmit={handleSave} className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <label
            htmlFor={compact ? 'compact-email-alerts-enabled' : 'full-email-alerts-enabled'}
            className="inline-flex items-center gap-2.5 text-xs font-semibold text-slate-950 dark:text-slate-50 cursor-pointer select-none"
          >
            <input
              id={compact ? 'compact-email-alerts-enabled' : 'full-email-alerts-enabled'}
              data-testid="email-alerts-enabled-checkbox"
              type="checkbox"
              checked={config.enabled}
              onChange={(e) => {
                setErrorMsg(null);
                setStatusMsg(null);
                setConfig((prev) => ({ ...prev, enabled: e.target.checked }));
              }}
              className="h-4 w-4 rounded border-slate-300 dark:border-slate-700 dark:bg-slate-950 text-red-600 focus:ring-red-600"
            />
            <span>Enable automated IOC threshold email alerts</span>
          </label>

          <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
            {smtp.configured
              ? `SMTP Relay: ${smtp.hostLabel}`
              : 'Local Outbox (.eml) — set SMTP_HOST in .env for mail relay'}
          </span>
        </div>

        <div>
          <label
            htmlFor={compact ? 'compact-email-recipients' : 'full-email-recipients'}
            className="block text-xs font-medium text-slate-700 dark:text-slate-300"
          >
            Recipient Email Address(es)
          </label>
          <input
            id={compact ? 'compact-email-recipients' : 'full-email-recipients'}
            data-testid="email-alerts-recipients-input"
            type="text"
            value={recipientsInput}
            onChange={(e) => {
              setErrorMsg(null);
              setStatusMsg(null);
              setRecipientsInput(e.target.value);
            }}
            placeholder="soc-oncall@company.com, ir-lead@company.com"
            className="mt-1 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
          />
          <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
            Comma-separated addresses alerted whenever an investigated IOC meets the configured confidence threshold.
          </p>
        </div>

        <div className={compact ? 'grid gap-3 grid-cols-2' : 'grid gap-4 sm:grid-cols-3'}>
          <div>
            <label
              htmlFor={compact ? 'compact-email-tier' : 'full-email-tier'}
              className="block text-xs font-medium text-slate-700 dark:text-slate-300"
            >
              Trigger Tier Preset
            </label>
            <select
              id={compact ? 'compact-email-tier' : 'full-email-tier'}
              data-testid="email-alerts-preset-select"
              value={config.riskTierPreset}
              onChange={(e) => handlePresetChange(e.target.value as EmailAlertTierPreset)}
              className="mt-1 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-2 text-xs font-medium text-slate-900 dark:text-slate-100 focus:border-red-600 focus:outline-none cursor-pointer"
            >
              <option value="Critical">Critical (≥ 75/100)</option>
              <option value="High">High (≥ 50/100)</option>
              <option value="Medium">Medium (≥ 25/100)</option>
              <option value="Custom">Custom Threshold</option>
            </select>
          </div>

          <div>
            <label
              htmlFor={compact ? 'compact-email-score' : 'full-email-score'}
              className="block text-xs font-medium text-slate-700 dark:text-slate-300"
            >
              Min Confidence (1–100)
            </label>
            <input
              id={compact ? 'compact-email-score' : 'full-email-score'}
              data-testid="email-alerts-score-input"
              type="number"
              min={1}
              max={100}
              value={config.minConfidenceScore}
              onChange={(e) => {
                const val = Number.parseInt(e.target.value || '75', 10);
                setErrorMsg(null);
                setStatusMsg(null);
                setConfig((prev) => ({
                  ...prev,
                  riskTierPreset: 'Custom',
                  minConfidenceScore: Number.isFinite(val) ? val : 75,
                }));
              }}
              className="mt-1 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 tabular-nums focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
            />
          </div>

          <div className={compact ? 'col-span-2' : ''}>
            <label
              htmlFor={compact ? 'compact-email-cooldown' : 'full-email-cooldown'}
              className="block text-xs font-medium text-slate-700 dark:text-slate-300"
            >
              Per-IOC Cooldown (minutes)
            </label>
            <input
              id={compact ? 'compact-email-cooldown' : 'full-email-cooldown'}
              data-testid="email-alerts-cooldown-input"
              type="number"
              min={0}
              max={1440}
              value={config.cooldownMinutes}
              onChange={(e) => {
                const val = Number.parseInt(e.target.value || '0', 10);
                setErrorMsg(null);
                setStatusMsg(null);
                setConfig((prev) => ({
                  ...prev,
                  cooldownMinutes: Number.isFinite(val) ? val : 0,
                }));
              }}
              className="mt-1 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-xs text-slate-900 dark:text-slate-100 tabular-nums focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
            />
          </div>
        </div>

        <label className="inline-flex items-center gap-2 text-xs text-slate-600 dark:text-slate-300 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={config.triggerOnSampleRuns}
            onChange={(e) => {
              setErrorMsg(null);
              setStatusMsg(null);
              setConfig((prev) => ({ ...prev, triggerOnSampleRuns: e.target.checked }));
            }}
            className="h-3.5 w-3.5 rounded border-slate-300 dark:border-slate-700 dark:bg-slate-950 text-red-600 focus:ring-red-600"
          />
          <span>Evaluate alerts on Sample Data runs as well as Live API lookups</span>
        </label>

        {errorMsg && (
          <div
            role="alert"
            data-testid="email-alerts-error"
            className="rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/50 px-3 py-2 text-xs text-red-800 dark:text-red-200"
          >
            {errorMsg}
          </div>
        )}

        {statusMsg && (
          <div
            role="status"
            data-testid="email-alerts-status"
            className="rounded-lg border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50 dark:bg-emerald-950/50 px-3 py-2 text-xs text-emerald-800 dark:text-emerald-200"
          >
            {maskSensitiveText(statusMsg, privacyMode)}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="submit"
            data-testid="email-alerts-save-btn"
            disabled={saving || testing}
            className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3.5 py-2 text-xs font-semibold text-white transition-colors hover:bg-red-700 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
          >
            {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />}
            <span>{saving ? 'Saving Rule...' : 'Save Alert Rule'}</span>
          </button>

          <button
            type="button"
            data-testid="email-alerts-test-btn"
            onClick={handleSendTest}
            disabled={testing || saving}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3.5 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
          >
            {testing ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            ) : (
              <Send className="h-3.5 w-3.5" aria-hidden="true" />
            )}
            <span>{testing ? 'Sending Test...' : 'Send Test Alert'}</span>
          </button>
        </div>
      </form>

      <div className="border-t border-slate-100 dark:border-slate-800 pt-4">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Mail className="h-3.5 w-3.5 text-slate-600 dark:text-slate-400" aria-hidden="true" />
            <h3 className="text-xs font-semibold text-slate-950 dark:text-slate-50">
              Dispatch Outbox &amp; Alert History
            </h3>
            <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
              ({history.length})
            </span>
          </div>

          {history.length > 0 && (
            <button
              type="button"
              data-testid="email-alerts-clear-history-btn"
              onClick={handleClearHistory}
              disabled={clearingHistory}
              className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-500 dark:text-slate-400 hover:text-red-700 dark:hover:text-red-400 cursor-pointer"
            >
              <Trash2 className="h-3 w-3" aria-hidden="true" />
              Clear History
            </button>
          )}
        </div>

        {history.length === 0 ? (
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            No threshold alert emails dispatched yet. Save a rule and run an enrichment or click &ldquo;Send Test Alert&rdquo;.
          </p>
        ) : (
          <div
            data-testid="email-alerts-history-list"
            className="mt-2.5 divide-y divide-slate-100 dark:divide-slate-800 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50"
          >
            {history.slice(0, compact ? 5 : 15).map((rec) => {
              const isExpanded = expandedId === rec.id;
              return (
                <div key={rec.id} className="px-3 py-2.5 text-xs">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        {rec.deliveryStatus === 'failed' ? (
                          <XCircle className="h-3.5 w-3.5 text-red-600 dark:text-red-400 shrink-0" aria-hidden="true" />
                        ) : (
                          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" aria-hidden="true" />
                        )}
                        <span className="font-semibold text-slate-950 dark:text-slate-50 truncate">
                          {maskSensitiveText(rec.subject, privacyMode)}
                        </span>
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                        <span className="font-mono">{rec.recipients.join(', ')}</span>
                        <span aria-hidden="true">·</span>
                        <span>
                          {rec.deliveryStatus === 'sent'
                            ? 'SMTP Sent'
                            : rec.deliveryStatus === 'failed'
                              ? 'SMTP Failed'
                              : 'Queued (.eml)'}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span className="font-mono">
                          {rec.triggeredIndicators.length} IOC(s) ≥ {rec.thresholdScore}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span className="font-mono">{rec.createdAt.slice(0, 19).replace('T', ' ')}Z</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        type="button"
                        onClick={() => setExpandedId(isExpanded ? null : rec.id)}
                        className="text-[11px] font-medium text-slate-600 dark:text-slate-300 hover:underline whitespace-nowrap cursor-pointer"
                      >
                        {isExpanded ? 'Hide' : 'Preview'}
                      </button>
                      <button
                        type="button"
                        data-testid={`download-eml-${rec.id}`}
                        onClick={() => downloadEmlFile(rec)}
                        className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap cursor-pointer"
                      >
                        <Download className="h-3 w-3" aria-hidden="true" />
                        .eml
                      </button>
                    </div>
                  </div>

                  {isExpanded && (
                    <pre className="mt-2 max-h-48 overflow-auto rounded-md border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-2.5 font-mono text-[11px] leading-relaxed text-slate-700 dark:text-slate-300 whitespace-pre-wrap">
                      {maskSensitiveText(rec.textBody, privacyMode)}
                    </pre>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
