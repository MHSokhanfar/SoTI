import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  CalendarClock,
  CheckCircle2,
  Download,
  Pause,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Terminal,
  Trash2,
  XCircle,
} from 'lucide-react';
import { ALL_SOURCE_IDS } from '../utils/apiConfig';
import { parseIndicators, type SourceId } from '../utils/indicators';
import {
  buildCliAddScheduleCommand,
  formatIntervalLabel,
  formatRelativeScheduleTime,
  SCHEDULE_INTERVAL_PRESETS,
  summarizeSchedules,
  validateAndNormalizeScheduleInput,
  type ScheduledJob,
} from '../utils/scheduler';
import type { EmailAlertRecord } from '../utils/emailAlerts';
import type { QuotaState } from '../App';

export interface ScheduledNavigationTarget {
  scheduleId?: string | null;
  searchQuery?: string;
  nonce: number;
}

interface ScheduledViewProps {
  onReportCreated?: (filename: string) => void;
  onQuotaChange?: (next: QuotaState) => void;
  onEmailAlertTriggered?: (record: EmailAlertRecord) => void;
  navigationTarget?: ScheduledNavigationTarget | null;
}

const SOURCE_NAMES: Record<SourceId, string> = {
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
  alienvault: 'AlienVault OTX',
};

const PRESET_VALUES = new Set(SCHEDULE_INTERVAL_PRESETS.map((p) => p.minutes));

export function ScheduledView({
  onReportCreated,
  onQuotaChange,
  onEmailAlertTriggered,
  navigationTarget,
}: ScheduledViewProps) {
  const [jobs, setJobs] = useState<ScheduledJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [highlightedJobId, setHighlightedJobId] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

  const [formName, setFormName] = useState('');
  const [formIndicators, setFormIndicators] = useState('');
  const [formPreset, setFormPreset] = useState<string>('60');
  const [formIntervalMinutes, setFormIntervalMinutes] = useState<number>(60);
  const [formSources, setFormSources] = useState<SourceId[]>([...ALL_SOURCE_IDS]);
  const [formMode, setFormMode] = useState<'live' | 'sample'>('live');
  const [formEnabled, setFormEnabled] = useState(true);
  const [savingForm, setSavingForm] = useState(false);

  const [feedback, setFeedback] = useState<{ type: 'ok' | 'error'; text: string } | null>(null);

  const loadJobs = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    try {
      const resp = await fetch('/api/schedules');
      const data = await resp.json();
      if (Array.isArray(data?.jobs)) {
        setJobs(data.jobs);
      }
    } catch {
      setFeedback({ type: 'error', text: 'Failed to load scheduled checks from server.' });
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadJobs(false);
    const timer = setInterval(() => loadJobs(false), 15_000);
    return () => clearInterval(timer);
  }, [loadJobs]);

  useEffect(() => {
    if (!navigationTarget) return;
    if (navigationTarget.scheduleId) {
      setHighlightedJobId(navigationTarget.scheduleId);
    } else if (navigationTarget.searchQuery) {
      const q = navigationTarget.searchQuery.trim().toLowerCase();
      const match = jobs.find(
        (j) =>
          j.name.toLowerCase().includes(q) ||
          j.indicators.some((ind) => ind.toLowerCase().includes(q)),
      );
      setHighlightedJobId(match?.id ?? null);
    }
  }, [navigationTarget?.nonce, jobs]);

  const summary = useMemo(() => summarizeSchedules(jobs), [jobs]);
  const parsedPreview = useMemo(() => parseIndicators(formIndicators), [formIndicators]);
  const validPreviewTokens = useMemo(
    () => parsedPreview.filter((p) => p.type !== null),
    [parsedPreview],
  );

  function openCreateForm() {
    setEditingId(null);
    setFormName('');
    setFormIndicators('');
    setFormPreset('60');
    setFormIntervalMinutes(60);
    setFormSources([...ALL_SOURCE_IDS]);
    setFormMode('live');
    setFormEnabled(true);
    setFeedback(null);
    setShowForm(true);
  }

  function openEditForm(job: ScheduledJob) {
    setEditingId(job.id);
    setFormName(job.name);
    setFormIndicators(job.indicators.join(', '));
    setFormPreset(PRESET_VALUES.has(job.intervalMinutes) ? String(job.intervalMinutes) : 'custom');
    setFormIntervalMinutes(job.intervalMinutes);
    setFormSources(job.sources.length > 0 ? [...job.sources] : [...ALL_SOURCE_IDS]);
    setFormMode(job.mode);
    setFormEnabled(job.enabled);
    setFeedback(null);
    setShowForm(true);
  }

  function toggleSourceCheckbox(id: SourceId) {
    setFormSources((prev) => {
      if (prev.includes(id)) {
        return prev.length > 1 ? prev.filter((s) => s !== id) : prev;
      }
      return [...prev, id];
    });
  }

  async function handleSubmitForm(e: React.FormEvent) {
    e.preventDefault();
    setFeedback(null);

    const sourceValue =
      formSources.length === 3 ? 'all' : formSources.length === 1 ? formSources[0] : 'all';

    const check = validateAndNormalizeScheduleInput({
      name: formName,
      indicators: formIndicators,
      source: sourceValue,
      sources: formSources,
      intervalMinutes: formIntervalMinutes,
      mode: formMode,
      enabled: formEnabled,
    });
    if (!check.ok) {
      setFeedback({ type: 'error', text: check.error });
      return;
    }

    setSavingForm(true);
    try {
      const url = editingId ? `/api/schedules/${encodeURIComponent(editingId)}` : '/api/schedules';
      const method = editingId ? 'PATCH' : 'POST';
      const resp = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(check.data),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setFeedback({ type: 'error', text: data.error || 'Unable to save scheduled check.' });
        return;
      }
      await loadJobs(false);
      setShowForm(false);
      setEditingId(null);
      setFeedback({
        type: 'ok',
        text: editingId
          ? `Updated schedule "${data.job.name}".`
          : `Scheduled recurring check "${data.job.name}".`,
      });
    } catch {
      setFeedback({ type: 'error', text: 'Network error while saving schedule.' });
    } finally {
      setSavingForm(false);
    }
  }

  async function handleRunNow(job: ScheduledJob) {
    setFeedback(null);
    setRunningId(job.id);
    try {
      const resp = await fetch(`/api/schedules/${encodeURIComponent(job.id)}/run`, {
        method: 'POST',
      });
      const data = await resp.json();
      if (!resp.ok) {
        setFeedback({ type: 'error', text: data.error || `Failed to run "${job.name}".` });
        return;
      }
      if (data.reportFile) {
        onReportCreated?.(data.reportFile);
      }
      if (data.quota?.date && Array.isArray(data.quota?.providers)) {
        onQuotaChange?.(data.quota);
      }
      if (data.emailAlert?.triggered && data.emailAlert?.record) {
        onEmailAlertTriggered?.(data.emailAlert.record);
      }
      await loadJobs(false);
      setFeedback({
        type: 'ok',
        text: `Executed "${job.name}" — saved report ${data.reportFile}.`,
      });
    } catch {
      setFeedback({ type: 'error', text: `Unable to execute "${job.name}".` });
    } finally {
      setRunningId(null);
    }
  }

  async function handleToggleEnabled(job: ScheduledJob) {
    setFeedback(null);
    setBusyId(job.id);
    try {
      const resp = await fetch(`/api/schedules/${encodeURIComponent(job.id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !job.enabled }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setFeedback({ type: 'error', text: data.error || 'Failed to update schedule state.' });
        return;
      }
      await loadJobs(false);
    } catch {
      setFeedback({ type: 'error', text: 'Unable to update schedule state.' });
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(job: ScheduledJob) {
    setFeedback(null);
    setBusyId(job.id);
    try {
      const resp = await fetch(`/api/schedules/${encodeURIComponent(job.id)}`, {
        method: 'DELETE',
      });
      if (!resp.ok) {
        const data = await resp.json();
        setFeedback({ type: 'error', text: data.error || 'Failed to delete schedule.' });
        return;
      }
      await loadJobs(false);
      setFeedback({ type: 'ok', text: `Removed schedule "${job.name}".` });
    } catch {
      setFeedback({ type: 'error', text: 'Unable to delete schedule.' });
    } finally {
      setBusyId(null);
    }
  }

  const cliCommandPreview = buildCliAddScheduleCommand({
    name: formName.trim() || 'Perimeter Watchlist',
    indicators: validPreviewTokens.length > 0 ? validPreviewTokens.map((t) => t.cleaned) : ['8.8.8.8'],
    source: formSources.length === 1 ? formSources[0] : 'all',
    intervalMinutes: Number.isFinite(formIntervalMinutes) ? formIntervalMinutes : 60,
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-950 dark:text-slate-50">Scheduled Threat Checks</h1>
          <p className="mt-0.5 text-sm text-slate-600 dark:text-slate-400">
            Recurring automated IOC checks synced with <code className="font-mono text-xs">config/schedules.json</code> and{' '}
            <code className="font-mono text-xs">config/scheduler.py</code>.
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={() => loadJobs(true)}
            disabled={refreshing}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-3.5 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
            Refresh
          </button>
          <button
            type="button"
            onClick={() => (showForm && !editingId ? setShowForm(false) : openCreateForm())}
            className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white hover:bg-red-700 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            {showForm && !editingId ? 'Close Form' : 'New Schedule'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-4 py-3.5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Total Jobs</div>
          <div className="mt-1 text-2xl font-bold tracking-tight text-slate-950 dark:text-slate-50 tabular-nums">
            {summary.total}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-4 py-3.5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Active</div>
          <div className="mt-1 text-2xl font-bold tracking-tight text-emerald-700 dark:text-emerald-400 tabular-nums">
            {summary.active}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-4 py-3.5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Paused</div>
          <div className="mt-1 text-2xl font-bold tracking-tight text-slate-700 dark:text-slate-300 tabular-nums">
            {summary.paused}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-4 py-3.5">
          <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Automated Runs</div>
          <div className="mt-1 text-2xl font-bold tracking-tight text-slate-950 dark:text-slate-50 tabular-nums">
            {summary.totalRuns}
          </div>
        </div>
      </div>

      {feedback && (
        <div
          role={feedback.type === 'error' ? 'alert' : 'status'}
          className={`flex items-center gap-2 rounded-lg border px-4 py-2.5 text-xs ${
            feedback.type === 'error'
              ? 'border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/50 text-red-800 dark:text-red-200'
              : 'border-emerald-200 dark:border-emerald-900/60 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-800 dark:text-emerald-200'
          }`}
        >
          {feedback.type === 'error' ? (
            <XCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
          ) : (
            <CheckCircle2 className="h-4 w-4 shrink-0" aria-hidden="true" />
          )}
          <span>{feedback.text}</span>
        </div>
      )}

      {showForm && (
        <section
          aria-label={editingId ? 'Edit Scheduled Check' : 'Create Scheduled Check'}
          className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6"
        >
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-4">
            <div className="flex items-center gap-2">
              <CalendarClock className="h-4 w-4 text-slate-700 dark:text-slate-300" aria-hidden="true" />
              <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">
                {editingId ? 'Edit Scheduled Check' : 'Define Recurring Threat Check'}
              </h2>
            </div>
            <button
              type="button"
              onClick={() => {
                setShowForm(false);
                setEditingId(null);
              }}
              className="text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 cursor-pointer"
            >
              Cancel
            </button>
          </div>

          <form onSubmit={handleSubmitForm} className="mt-4 space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label htmlFor="schedule-name-input" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                  Schedule Name
                </label>
                <input
                  id="schedule-name-input"
                  type="text"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder="e.g. Core C2 & DNS Watchlist"
                  maxLength={80}
                  className="mt-1.5 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 text-sm text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label htmlFor="schedule-preset-select" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                    Frequency
                  </label>
                  <select
                    id="schedule-preset-select"
                    value={formPreset}
                    onChange={(e) => {
                      const val = e.target.value;
                      setFormPreset(val);
                      if (val !== 'custom') {
                        setFormIntervalMinutes(Number.parseInt(val, 10));
                      }
                    }}
                    className="mt-1.5 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 text-sm text-slate-900 dark:text-slate-100 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
                  >
                    {SCHEDULE_INTERVAL_PRESETS.map((preset) => (
                      <option key={preset.minutes} value={String(preset.minutes)}>
                        {preset.label}
                      </option>
                    ))}
                    <option value="custom">Custom interval (min)</option>
                  </select>
                </div>

                <div>
                  <label htmlFor="schedule-interval-input" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                    Interval (minutes)
                  </label>
                  <input
                    id="schedule-interval-input"
                    type="number"
                    min={5}
                    max={43200}
                    value={formIntervalMinutes}
                    onChange={(e) => {
                      const parsed = Number.parseInt(e.target.value || '60', 10);
                      setFormIntervalMinutes(parsed);
                      setFormPreset(PRESET_VALUES.has(parsed) ? String(parsed) : 'custom');
                    }}
                    className="mt-1.5 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 px-3 py-2 font-mono text-sm text-slate-900 dark:text-slate-100 tabular-nums focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
                  />
                </div>
              </div>
            </div>

            <div>
              <label htmlFor="schedule-indicators-input" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                Indicators to Monitor (IPv4/IPv6, Domain, MD5/SHA1/SHA256 — supports defanged IOCs)
              </label>
              <textarea
                id="schedule-indicators-input"
                rows={2}
                value={formIndicators}
                onChange={(e) => setFormIndicators(e.target.value)}
                placeholder="8.8.8.8, 1[.]2[.]3[.]4, hxxp://evil[.]com"
                className="mt-1.5 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 p-3 font-mono text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
              />
              {parsedPreview.length > 0 && (
                <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
                  <span className="font-medium text-slate-700 dark:text-slate-300">Detected IOCs:</span>
                  {parsedPreview.map((tok, idx) => (
                    <span key={`${tok.original}-${idx}`} className="font-mono">
                      <span className={tok.type ? 'text-slate-900 dark:text-slate-100 font-semibold' : 'text-red-600 dark:text-red-400 line-through'}>
                        {tok.cleaned}
                      </span>{' '}
                      <span className="text-slate-400 dark:text-slate-500">/ {tok.type ?? 'invalid'}</span>
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div className="flex flex-col gap-4 border-t border-slate-100 dark:border-slate-800 pt-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex flex-wrap items-center gap-4">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Sources:</span>
                {ALL_SOURCE_IDS.map((srcId) => (
                  <label
                    key={srcId}
                    className="inline-flex items-center gap-1.5 text-xs text-slate-800 dark:text-slate-200 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={formSources.includes(srcId)}
                      onChange={() => toggleSourceCheckbox(srcId)}
                      className="h-3.5 w-3.5 rounded border-slate-300 dark:border-slate-700 dark:bg-slate-950 text-red-600 focus:ring-red-600"
                    />
                    {SOURCE_NAMES[srcId]}
                  </label>
                ))}
              </div>

              <div className="flex flex-wrap items-center gap-4">
                <label className="inline-flex items-center gap-1.5 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
                  <span>Mode:</span>
                  <select
                    value={formMode}
                    onChange={(e) => setFormMode(e.target.value === 'sample' ? 'sample' : 'live')}
                    className="rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-2 py-1 text-xs text-slate-800 dark:text-slate-200"
                  >
                    <option value="live">Live API</option>
                    <option value="sample">Sample Data</option>
                  </select>
                </label>

                <label className="inline-flex items-center gap-1.5 text-xs text-slate-800 dark:text-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formEnabled}
                    onChange={(e) => setFormEnabled(e.target.checked)}
                    className="h-3.5 w-3.5 rounded border-slate-300 dark:border-slate-700 dark:bg-slate-950 text-red-600 focus:ring-red-600"
                  />
                  Active immediately
                </label>
              </div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-950 px-3.5 py-2.5 text-slate-300">
              <div className="flex items-center gap-1.5 text-[11px] font-medium text-slate-400">
                <Terminal className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Equivalent CLI command</span>
              </div>
              <code className="mt-1 block overflow-x-auto font-mono text-[11px] text-slate-200 whitespace-nowrap">
                {cliCommandPreview}
              </code>
            </div>

            <div className="flex justify-end gap-2">
              <button
                type="submit"
                disabled={savingForm}
                className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white hover:bg-red-700 disabled:opacity-50 cursor-pointer"
              >
                {savingForm ? 'Saving...' : editingId ? 'Save Changes' : 'Create Schedule'}
              </button>
            </div>
          </form>
        </section>
      )}

      <section
        aria-label="Configured Scheduled Checks"
        className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900"
      >
        {loading ? (
          <div className="p-8 text-center text-sm text-slate-500 dark:text-slate-400">Loading scheduled checks...</div>
        ) : jobs.length === 0 ? (
          <div className="p-10 text-center">
            <CalendarClock className="mx-auto h-7 w-7 text-slate-400 dark:text-slate-500" aria-hidden="true" />
            <h2 className="mt-2 text-sm font-semibold text-slate-900 dark:text-slate-100">No scheduled checks configured</h2>
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              Create a recurring check above or add one via <code className="font-mono">python3 main.py --add-schedule</code>.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-800/60 text-slate-600 dark:text-slate-300">
                  <th className="py-3 pl-5 pr-3 font-semibold">Job &amp; Indicators</th>
                  <th className="py-3 px-3 font-semibold">Frequency</th>
                  <th className="py-3 px-3 font-semibold">Timing</th>
                  <th className="py-3 px-3 font-semibold">Last Outcome</th>
                  <th className="py-3 px-3 font-semibold text-right">Runs</th>
                  <th className="py-3 pl-3 pr-5 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {jobs.map((job) => {
                  const isRunning = runningId === job.id;
                  const isBusy = busyId === job.id || isRunning;

                  const outcomeColor =
                    job.lastStatus === 'success'
                      ? 'text-emerald-700 dark:text-emerald-400'
                      : job.lastStatus === 'partial'
                        ? 'text-amber-700 dark:text-amber-400'
                        : job.lastStatus === 'error'
                          ? 'text-red-700 dark:text-red-400'
                          : 'text-slate-500 dark:text-slate-400';

                  const isHighlighted = highlightedJobId === job.id;
                  return (
                    <tr
                      key={job.id}
                      data-testid={`schedule-row-${job.id}`}
                      data-highlighted={isHighlighted ? 'true' : undefined}
                      className={`align-top transition-colors ${
                        isHighlighted
                          ? 'bg-red-50/60 dark:bg-red-950/30'
                          : 'hover:bg-slate-50/60 dark:hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="py-3.5 pl-5 pr-3">
                        <div className="flex items-center gap-2">
                          <span
                            aria-hidden="true"
                            className={`h-2 w-2 rounded-full shrink-0 ${
                              job.enabled ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600'
                            }`}
                          />
                          <span className="font-semibold text-slate-950 dark:text-slate-50">{job.name}</span>
                          <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400">
                            {job.enabled ? 'Active' : 'Paused'}
                          </span>
                        </div>
                        <div className="mt-1 font-mono text-[11px] text-slate-700 dark:text-slate-300">
                          {job.indicators.join(', ')}
                        </div>
                        <div className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
                          Sources: {job.sources.map((s) => SOURCE_NAMES[s] || s).join(' · ')}
                        </div>
                      </td>

                      <td className="py-3.5 px-3 whitespace-nowrap">
                        <div className="font-medium text-slate-900 dark:text-slate-100">
                          {formatIntervalLabel(job.intervalMinutes)}
                        </div>
                        <div className="mt-0.5 font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                          {job.intervalMinutes} min · {job.mode}
                        </div>
                      </td>

                      <td className="py-3.5 px-3 whitespace-nowrap">
                        <div className="text-slate-900 dark:text-slate-100 tabular-nums">
                          Next:{' '}
                          <span className="font-medium">
                            {job.enabled ? formatRelativeScheduleTime(job.nextRunAt) : 'Paused'}
                          </span>
                        </div>
                        <div className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                          Last: {job.lastRunAt ? formatRelativeScheduleTime(job.lastRunAt) : 'Never'}
                        </div>
                      </td>

                      <td className="py-3.5 px-3 max-w-[240px]">
                        <div className={`font-semibold capitalize ${outcomeColor}`}>
                          {job.lastStatus}
                        </div>
                        {job.lastSummary && (
                          <div className="mt-0.5 text-[11px] text-slate-600 dark:text-slate-300 line-clamp-2">
                            {job.lastSummary}
                          </div>
                        )}
                        {job.lastReportFile && (
                          <a
                            href={`/api/reports/${encodeURIComponent(job.lastReportFile)}?download=1`}
                            className="mt-1 inline-flex items-center gap-1 font-mono text-[11px] font-medium text-red-700 dark:text-red-400 hover:underline"
                          >
                            <Download className="h-3 w-3" aria-hidden="true" />
                            {job.lastReportFile}
                          </a>
                        )}
                      </td>

                      <td className="py-3.5 px-3 text-right font-mono font-semibold text-slate-900 dark:text-slate-100 tabular-nums">
                        {job.runCount}
                      </td>

                      <td className="py-3.5 pl-3 pr-5 text-right whitespace-nowrap">
                        <div className="inline-flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => handleRunNow(job)}
                            disabled={isBusy}
                            title={`Run ${job.name} now`}
                            className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-2.5 py-1.5 text-[11px] font-medium text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
                          >
                            <Play className="h-3 w-3 text-red-600 dark:text-red-400" aria-hidden="true" />
                            {isRunning ? 'Running...' : 'Run Now'}
                          </button>
                          <button
                            type="button"
                            onClick={() => handleToggleEnabled(job)}
                            disabled={isBusy}
                            title={job.enabled ? 'Pause schedule' : 'Resume schedule'}
                            className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-2 py-1.5 text-[11px] font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
                          >
                            {job.enabled ? (
                              <>
                                <Pause className="h-3 w-3" aria-hidden="true" />
                                Pause
                              </>
                            ) : (
                              <>
                                <Play className="h-3 w-3 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
                                Resume
                              </>
                            )}
                          </button>
                          <button
                            type="button"
                            onClick={() => openEditForm(job)}
                            disabled={isBusy}
                            aria-label={`Edit ${job.name}`}
                            className="inline-flex items-center rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 p-1.5 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100 disabled:opacity-50 cursor-pointer"
                          >
                            <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDelete(job)}
                            disabled={isBusy}
                            aria-label={`Delete ${job.name}`}
                            className="inline-flex items-center rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 p-1.5 text-slate-600 dark:text-slate-300 hover:border-red-200 dark:hover:border-red-900/60 hover:bg-red-50 dark:hover:bg-red-950/50 hover:text-red-700 dark:hover:text-red-400 disabled:opacity-50 cursor-pointer"
                          >
                            <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
