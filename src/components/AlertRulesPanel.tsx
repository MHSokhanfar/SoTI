import { useEffect, useState, type FormEvent } from 'react';
import {
  Bell,
  BellRing,
  CheckCircle2,
  Edit3,
  Mail,
  Play,
  Plus,
  ShieldAlert,
  Trash2,
  Zap,
} from 'lucide-react';
import type { LookupResult } from '../utils/indicators';
import {
  describeAlertRuleSummary,
  validateAndNormalizeAlertRuleDraft,
  type AlertRuleChannel,
  type AlertRuleIndicatorScope,
  type AlertRuleTriggerHistoryEntry,
  type AlertRuleVerdictScope,
  type CustomAlertRule,
} from '../utils/alertRules';
import { maskIndicatorValue, maskSensitiveText } from '../utils/privacyMode';
import { usePrivacyMode } from './PrivacyModeContext';

interface AlertRulesPanelProps {
  compact?: boolean;
  rules: CustomAlertRule[];
  history: AlertRuleTriggerHistoryEntry[];
  currentResults?: readonly LookupResult[];
  onSaveRule: (rule: CustomAlertRule) => void;
  onToggleRule: (ruleId: string) => void;
  onDeleteRule: (ruleId: string) => void;
  onTestRule: (rule: CustomAlertRule) => Promise<{ ok: boolean; message: string }>;
  onEvaluateCurrentResults?: () => { matchedRules: number; message: string };
  onClearHistory?: () => void;
}

const INDICATOR_TYPE_OPTIONS: { value: AlertRuleIndicatorScope; label: string }[] = [
  { value: 'all', label: 'All Indicator Types' },
  { value: 'domain', label: 'Domain' },
  { value: 'ip', label: 'IP Address' },
  { value: 'hash', label: 'File Hash' },
  { value: 'url', label: 'URL' },
];

const VERDICT_SCOPE_OPTIONS: { value: AlertRuleVerdictScope; label: string }[] = [
  { value: 'any', label: 'Any Verdict' },
  { value: 'malicious_or_suspicious', label: 'Malicious or Suspicious' },
  { value: 'malicious_only', label: 'Malicious Only' },
];

const CHANNEL_OPTIONS: { value: AlertRuleChannel; label: string }[] = [
  { value: 'desktop', label: 'Desktop Notification' },
  { value: 'email', label: 'Email Notification' },
  { value: 'both', label: 'Desktop + Email' },
];

const SCORE_PRESETS = [25, 50, 75, 90];

function formatRuleTimestamp(iso: string | null): string {
  if (!iso) return 'Never triggered';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}

export function AlertRulesPanel({
  compact = false,
  rules,
  history,
  currentResults = [],
  onSaveRule,
  onToggleRule,
  onDeleteRule,
  onTestRule,
  onEvaluateCurrentResults,
  onClearHistory,
}: AlertRulesPanelProps) {
  const privacyMode = usePrivacyMode();

  const [formOpen, setFormOpen] = useState(false);
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [indicatorType, setIndicatorType] = useState<AlertRuleIndicatorScope>('domain');
  const [minRiskScore, setMinRiskScore] = useState<number>(50);
  const [verdictScope, setVerdictScope] = useState<AlertRuleVerdictScope>('any');
  const [patternFilter, setPatternFilter] = useState('');
  const [channel, setChannel] = useState<AlertRuleChannel>('both');
  const [emailRecipientsInput, setEmailRecipientsInput] = useState('');
  const [triggerOnSampleRuns, setTriggerOnSampleRuns] = useState(true);

  const [formError, setFormError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);
  const [testingRuleId, setTestingRuleId] = useState<string | null>(null);
  const [browserPermission, setBrowserPermission] = useState<string>(() => {
    if (typeof window !== 'undefined' && 'Notification' in window) {
      return window.Notification.permission;
    }
    return 'unsupported';
  });

  useEffect(() => {
    if (typeof window !== 'undefined' && 'Notification' in window) {
      setBrowserPermission(window.Notification.permission);
    }
  }, []);

  function resetForm() {
    setEditingRuleId(null);
    setName('');
    setIndicatorType('domain');
    setMinRiskScore(50);
    setVerdictScope('any');
    setPatternFilter('');
    setChannel('both');
    setEmailRecipientsInput('');
    setTriggerOnSampleRuns(true);
    setFormError(null);
  }

  function openNewRuleForm() {
    resetForm();
    setFormOpen(true);
    setFeedback(null);
  }

  function openEditRuleForm(rule: CustomAlertRule) {
    setEditingRuleId(rule.id);
    setName(rule.name);
    setIndicatorType(rule.indicatorType);
    setMinRiskScore(rule.minRiskScore);
    setVerdictScope(rule.verdictScope);
    setPatternFilter(rule.patternFilter);
    setChannel(rule.channel);
    setEmailRecipientsInput(rule.emailRecipients.join(', '));
    setTriggerOnSampleRuns(rule.triggerOnSampleRuns);
    setFormError(null);
    setFeedback(null);
    setFormOpen(true);
  }

  async function handleRequestBrowserPermission() {
    if (typeof window === 'undefined' || !('Notification' in window)) {
      setBrowserPermission('unsupported');
      return;
    }
    try {
      const perm = await window.Notification.requestPermission();
      setBrowserPermission(perm);
      setFeedback({
        ok: perm === 'granted',
        text:
          perm === 'granted'
            ? 'Browser desktop notifications enabled.'
            : perm === 'denied'
              ? 'Browser notifications blocked — in-app toast banners and Notification Center alerts remain active.'
              : 'Notification permission dismissed — in-app desktop banners remain active.',
      });
    } catch {
      setFeedback({
        ok: false,
        text: 'Unable to request browser permission; in-app toast alerts remain active.',
      });
    }
  }

  function handleFormSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    setFeedback(null);

    const existing = editingRuleId ? rules.find((r) => r.id === editingRuleId) : undefined;
    const validated = validateAndNormalizeAlertRuleDraft({
      id: editingRuleId ?? undefined,
      name,
      enabled: existing ? existing.enabled : true,
      indicatorType,
      minRiskScore,
      verdictScope,
      patternFilter,
      channel,
      emailRecipientsInput,
      triggerOnSampleRuns,
    });

    if (validated.ok === false) {
      setFormError(validated.error);
      return;
    }

    const finalRule: CustomAlertRule = existing
      ? {
          ...validated.rule,
          createdAt: existing.createdAt,
          lastTriggeredAt: existing.lastTriggeredAt,
          triggerCount: existing.triggerCount,
        }
      : validated.rule;

    onSaveRule(finalRule);
    setFormOpen(false);
    resetForm();
    setFeedback({
      ok: true,
      text: editingRuleId
        ? `Updated rule "${finalRule.name}".`
        : `Created alert rule "${finalRule.name}".`,
    });
  }

  async function handleRunTest(rule: CustomAlertRule) {
    setTestingRuleId(rule.id);
    setFeedback(null);
    try {
      const outcome = await onTestRule(rule);
      setFeedback({ ok: outcome.ok, text: outcome.message });
    } finally {
      setTestingRuleId(null);
    }
  }

  function handleRunCurrentBatchEval() {
    if (!onEvaluateCurrentResults) return;
    const res = onEvaluateCurrentResults();
    setFeedback({ ok: res.matchedRules > 0, text: res.message });
  }

  const activeCount = rules.filter((r) => r.enabled).length;

  return (
    <div
      data-testid={compact ? 'alert-rules-panel-compact' : 'alert-rules-panel'}
      className={compact ? 'p-4 space-y-4' : 'space-y-5'}
    >
      {/* Top Control Header */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 border-b border-slate-100 dark:border-slate-800 pb-3">
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-300 tabular-nums">
          <span className="font-semibold text-slate-900 dark:text-slate-100">
            {activeCount} active
          </span>
          <span className="text-slate-300 dark:text-slate-700" aria-hidden="true">
            ·
          </span>
          <span>{rules.length} configured rules</span>
          {browserPermission !== 'unsupported' && (
            <>
              <span className="text-slate-300 dark:text-slate-700" aria-hidden="true">
                ·
              </span>
              {browserPermission === 'granted' ? (
                <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400 font-medium">
                  <BellRing className="h-3 w-3" aria-hidden="true" />
                  Desktop OS alerts ready
                </span>
              ) : (
                <button
                  type="button"
                  data-testid="enable-browser-notifications-btn"
                  onClick={handleRequestBrowserPermission}
                  className="inline-flex items-center gap-1 font-medium text-red-700 dark:text-red-400 hover:underline cursor-pointer"
                >
                  <Bell className="h-3 w-3" aria-hidden="true" />
                  Enable Browser Notifications
                </button>
              )}
            </>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {currentResults.length > 0 && onEvaluateCurrentResults && (
            <button
              type="button"
              data-testid="evaluate-alert-rules-now-btn"
              onClick={handleRunCurrentBatchEval}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Zap className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" aria-hidden="true" />
              Run Against Active Results
            </button>
          )}
          <button
            type="button"
            data-testid="add-alert-rule-btn"
            onClick={() => {
              if (formOpen && !editingRuleId) {
                setFormOpen(false);
              } else {
                openNewRuleForm();
              }
            }}
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 dark:bg-slate-100 px-3 py-1.5 text-xs font-semibold text-white dark:text-slate-950 hover:bg-slate-800 dark:hover:bg-slate-200 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            <span>{formOpen && !editingRuleId ? 'Close Form' : 'New Alert Rule'}</span>
          </button>
        </div>
      </div>

      {feedback && (
        <div
          role="status"
          data-testid="alert-rules-feedback"
          className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs ${
            feedback.ok
              ? 'border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/70 dark:bg-emerald-950/30 text-emerald-900 dark:text-emerald-200'
              : 'border-amber-200 dark:border-amber-900/60 bg-amber-50/70 dark:bg-amber-950/30 text-amber-900 dark:text-amber-200'
          }`}
        >
          <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>{maskSensitiveText(feedback.text, privacyMode)}</span>
        </div>
      )}

      {/* Create / Edit Rule Form */}
      {formOpen && (
        <form
          onSubmit={handleFormSubmit}
          data-testid="alert-rule-form"
          className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950/70 p-4 space-y-3.5"
        >
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-xs font-semibold text-slate-950 dark:text-slate-50">
              {editingRuleId ? 'Edit Alert Rule' : 'Create Custom Alert Rule'}
            </h3>
            <button
              type="button"
              onClick={() => {
                setFormOpen(false);
                resetForm();
              }}
              className="text-[11px] font-medium text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
            >
              Cancel
            </button>
          </div>

          <div className={`grid gap-3 ${compact ? 'grid-cols-1' : 'sm:grid-cols-2 lg:grid-cols-3'}`}>
            <div>
              <label
                htmlFor="alert-rule-name"
                className="block text-[11px] font-medium text-slate-700 dark:text-slate-300"
              >
                Rule Name
              </label>
              <input
                id="alert-rule-name"
                data-testid="alert-rule-name-input"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. High-Risk Domain Escalation"
                className="mt-1 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100 focus:border-red-600 focus:outline-none"
              />
            </div>

            <div>
              <label
                htmlFor="alert-rule-type"
                className="block text-[11px] font-medium text-slate-700 dark:text-slate-300"
              >
                Indicator Type
              </label>
              <select
                id="alert-rule-type"
                data-testid="alert-rule-type-select"
                value={indicatorType}
                onChange={(e) => setIndicatorType(e.target.value as AlertRuleIndicatorScope)}
                className="mt-1 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100 focus:border-red-600 focus:outline-none cursor-pointer"
              >
                {INDICATOR_TYPE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                htmlFor="alert-rule-score"
                className="block text-[11px] font-medium text-slate-700 dark:text-slate-300"
              >
                Min Risk Score (1–100)
              </label>
              <div className="mt-1 flex items-center gap-1.5">
                <input
                  id="alert-rule-score"
                  data-testid="alert-rule-score-input"
                  type="number"
                  min={1}
                  max={100}
                  value={minRiskScore}
                  onChange={(e) => setMinRiskScore(Number.parseInt(e.target.value || '50', 10))}
                  className="w-20 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1.5 font-mono text-xs text-slate-900 dark:text-slate-100 tabular-nums focus:border-red-600 focus:outline-none"
                />
                <div className="flex items-center gap-1">
                  {SCORE_PRESETS.map((preset) => (
                    <button
                      key={preset}
                      type="button"
                      onClick={() => setMinRiskScore(preset)}
                      className={`rounded px-2 py-1 font-mono text-[11px] tabular-nums cursor-pointer transition-colors ${
                        minRiskScore === preset
                          ? 'bg-red-600 text-white font-semibold'
                          : 'border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                      }`}
                    >
                      {preset}+
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div>
              <label
                htmlFor="alert-rule-verdict"
                className="block text-[11px] font-medium text-slate-700 dark:text-slate-300"
              >
                Verdict Filter
              </label>
              <select
                id="alert-rule-verdict"
                data-testid="alert-rule-verdict-select"
                value={verdictScope}
                onChange={(e) => setVerdictScope(e.target.value as AlertRuleVerdictScope)}
                className="mt-1 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100 focus:border-red-600 focus:outline-none cursor-pointer"
              >
                {VERDICT_SCOPE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                htmlFor="alert-rule-channel"
                className="block text-[11px] font-medium text-slate-700 dark:text-slate-300"
              >
                Notification Action
              </label>
              <select
                id="alert-rule-channel"
                data-testid="alert-rule-channel-select"
                value={channel}
                onChange={(e) => setChannel(e.target.value as AlertRuleChannel)}
                className="mt-1 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100 focus:border-red-600 focus:outline-none cursor-pointer"
              >
                {CHANNEL_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                htmlFor="alert-rule-pattern"
                className="block text-[11px] font-medium text-slate-700 dark:text-slate-300"
              >
                Indicator Substring Filter (Optional)
              </label>
              <input
                id="alert-rule-pattern"
                type="text"
                value={patternFilter}
                onChange={(e) => setPatternFilter(e.target.value)}
                placeholder="e.g. .ru or login"
                className="mt-1 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 font-mono text-xs text-slate-900 dark:text-slate-100 focus:border-red-600 focus:outline-none"
              />
            </div>
          </div>

          {(channel === 'email' || channel === 'both') && (
            <div>
              <label
                htmlFor="alert-rule-recipients"
                className="block text-[11px] font-medium text-slate-700 dark:text-slate-300"
              >
                Email Recipients (comma-separated — leave blank to use global Email Rules recipients)
              </label>
              <input
                id="alert-rule-recipients"
                data-testid="alert-rule-recipients-input"
                type="text"
                value={emailRecipientsInput}
                onChange={(e) => setEmailRecipientsInput(e.target.value)}
                placeholder="soc-alerts@example.com, ir-lead@example.com"
                className="mt-1 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 font-mono text-xs text-slate-900 dark:text-slate-100 focus:border-red-600 focus:outline-none"
              />
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <label className="inline-flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={triggerOnSampleRuns}
                onChange={(e) => setTriggerOnSampleRuns(e.target.checked)}
                className="h-3.5 w-3.5 rounded border-slate-300 dark:border-slate-700 text-red-600 focus:ring-red-600"
              />
              <span>Evaluate on Sample Data runs as well as Live API lookups</span>
            </label>

            <button
              type="submit"
              data-testid="save-alert-rule-btn"
              className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-1.5 text-xs font-semibold text-white hover:bg-red-700 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <span>{editingRuleId ? 'Update Rule' : 'Save Alert Rule'}</span>
            </button>
          </div>

          {formError && (
            <div
              role="alert"
              className="rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/40 px-3 py-2 text-xs text-red-800 dark:text-red-200"
            >
              {formError}
            </div>
          )}
        </form>
      )}

      {/* Rules List */}
      {rules.length === 0 ? (
        <div className="rounded-lg border border-dashed border-slate-200 dark:border-slate-800 px-4 py-6 text-center">
          <ShieldAlert className="mx-auto h-5 w-5 text-slate-400 dark:text-slate-500" aria-hidden="true" />
          <p className="mt-2 text-xs font-medium text-slate-800 dark:text-slate-200">
            No custom alert rules configured yet
          </p>
          <p className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
            Create a rule to trigger desktop notifications or dispatch alert emails when an IOC matches your threshold.
          </p>
        </div>
      ) : (
        <div
          data-testid="alert-rules-list"
          className="divide-y divide-slate-100 dark:divide-slate-800 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900"
        >
          {rules.map((rule) => {
            const isTesting = testingRuleId === rule.id;
            return (
              <div
                key={rule.id}
                data-testid={`alert-rule-row-${rule.id}`}
                className="flex flex-col gap-2.5 px-3.5 py-3 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="flex items-start gap-3 min-w-0">
                  <label className="mt-0.5 inline-flex items-center cursor-pointer shrink-0">
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      onChange={() => onToggleRule(rule.id)}
                      aria-label={`Enable rule ${rule.name}`}
                      data-testid={`toggle-alert-rule-${rule.id}`}
                      className="h-4 w-4 rounded border-slate-300 dark:border-slate-700 text-red-600 focus:ring-red-600 cursor-pointer"
                    />
                  </label>

                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`text-xs font-semibold ${
                          rule.enabled
                            ? 'text-slate-950 dark:text-slate-50'
                            : 'text-slate-500 dark:text-slate-400 line-through'
                        }`}
                      >
                        {rule.name}
                      </span>
                      <span className="text-[11px] text-slate-400 dark:text-slate-500" aria-hidden="true">
                        ·
                      </span>
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-600 dark:text-slate-300">
                        {rule.channel === 'email' ? (
                          <Mail className="h-3 w-3 text-red-600 dark:text-red-400" aria-hidden="true" />
                        ) : (
                          <Bell className="h-3 w-3 text-amber-600 dark:text-amber-400" aria-hidden="true" />
                        )}
                        {rule.enabled ? 'Active' : 'Paused'}
                      </span>
                    </div>

                    <p className="mt-0.5 font-mono text-[11px] text-slate-600 dark:text-slate-300 tabular-nums">
                      {describeAlertRuleSummary(rule)}
                      {rule.patternFilter ? ` · Filter: "${rule.patternFilter}"` : ''}
                    </p>

                    <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                      <span>Triggers: {rule.triggerCount || 0}</span>
                      <span aria-hidden="true">·</span>
                      <span>Last: {formatRuleTimestamp(rule.lastTriggeredAt)}</span>
                      {rule.emailRecipients.length > 0 && (
                        <>
                          <span aria-hidden="true">·</span>
                          <span className="font-mono truncate max-w-[260px]">
                            To: {rule.emailRecipients.join(', ')}
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-1.5 shrink-0 self-end sm:self-center">
                  <button
                    type="button"
                    data-testid={`test-alert-rule-${rule.id}`}
                    disabled={isTesting}
                    onClick={() => handleRunTest(rule)}
                    aria-label={`Test rule ${rule.name}`}
                    className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap cursor-pointer"
                  >
                    <Play className="h-3 w-3 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
                    <span>{isTesting ? 'Testing' : 'Test'}</span>
                  </button>
                  <button
                    type="button"
                    data-testid={`edit-alert-rule-${rule.id}`}
                    onClick={() => openEditRuleForm(rule)}
                    aria-label={`Edit rule ${rule.name}`}
                    className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap cursor-pointer"
                  >
                    <Edit3 className="h-3 w-3" aria-hidden="true" />
                    <span>Edit</span>
                  </button>
                  <button
                    type="button"
                    data-testid={`delete-alert-rule-${rule.id}`}
                    onClick={() => onDeleteRule(rule.id)}
                    aria-label={`Delete rule ${rule.name}`}
                    className="rounded-md p-1.5 text-slate-400 dark:text-slate-500 hover:bg-red-50 dark:hover:bg-red-950/40 hover:text-red-700 dark:hover:text-red-400 cursor-pointer"
                  >
                    <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Trigger History */}
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
            Rule Trigger History ({history.length})
          </h3>
          {history.length > 0 && onClearHistory && (
            <button
              type="button"
              onClick={onClearHistory}
              className="text-[11px] font-medium text-slate-500 dark:text-slate-400 hover:text-red-700 dark:hover:text-red-400 cursor-pointer"
            >
              Clear Log
            </button>
          )}
        </div>

        {history.length === 0 ? (
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            No rule triggers recorded in this browser yet. Run an enrichment or click Test on any rule above.
          </p>
        ) : (
          <div
            data-testid="alert-rule-trigger-history"
            className="max-h-48 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900"
          >
            {history.slice(0, 15).map((entry) => (
              <div key={entry.id} className="px-3 py-2 text-[11px]">
                <div className="flex flex-wrap items-center justify-between gap-1.5">
                  <span className="font-semibold text-slate-900 dark:text-slate-100">
                    {entry.ruleName}
                  </span>
                  <span className="font-mono text-slate-500 dark:text-slate-400 tabular-nums">
                    {formatRuleTimestamp(entry.createdAt)} · {entry.mode.toUpperCase()}
                  </span>
                </div>
                <p className="mt-0.5 text-slate-600 dark:text-slate-300">
                  {entry.deliverySummary} —{' '}
                  <span className="font-mono">
                    {entry.topIndicators
                      .map(
                        (item) =>
                          `${maskIndicatorValue(item.indicator, item.type, privacyMode)} (${item.confidenceScore}/100)`,
                      )
                      .join(', ')}
                  </span>
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
