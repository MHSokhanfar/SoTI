import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { EyeOff } from 'lucide-react';
import { TopBar, type ActiveTab } from './components/TopBar';
import {
  InvestigateView,
  SAMPLE_BATCH,
  type InvestigateNavigationTarget,
  type InvestigationState,
} from './components/InvestigateView';
import { ReportsView, type ReportsNavigationTarget } from './components/ReportsView';
import { LogsView, type LogsNavigationTarget } from './components/LogsView';
import { ScheduledView, type ScheduledNavigationTarget } from './components/ScheduledView';
import { CliSetupView } from './components/CliSetupView';
import { HelpModal } from './components/HelpModal';
import { KeyboardShortcutsModal } from './components/KeyboardShortcutsModal';
import { NotificationCenter, type NotificationCenterTab } from './components/NotificationCenter';
import { PrivacyModeContext } from './components/PrivacyModeContext';
import { QuickNotesSidebarPanel } from './components/QuickNotesSidebarPanel';
import {
  ALL_SOURCE_IDS,
  EXTRA_PROVIDER_META,
  cloneDefaultApiSettings,
  mergeConfigAndConnectionStatus,
  type ApiKeyStatus,
  type ApiSettings,
  type BuiltinExtraSourceId,
  type ProviderLatencySnapshot,
} from './utils/apiConfig';
import {
  buildGlobalSearchIndex,
  type GlobalSearchEntry,
} from './utils/globalSearch';
import type { SourceId } from './utils/indicators';
import {
  clearRecentInvestigations,
  loadRecentInvestigations,
  type RecentInvestigationEntry,
} from './utils/investigationHistory';
import type { ProviderQuotaSnapshot } from './utils/quota';
import type { EmailAlertRecord } from './utils/emailAlerts';
import type { ReportMeta } from './utils/reportsAnalytics';
import { parseShareTokenFromUrl, type SharedReportSnapshot } from './utils/reportSharing';
import type { ScheduledJob } from './utils/scheduler';
import { matchGlobalKeyboardShortcut } from './utils/keyboardShortcuts';
import {
  createEmptyNotesAutoSaveState,
  loadNotesAutoSaveState,
  saveNotesAutoSaveState,
} from './utils/notesAutoSave';
import { DEFAULT_LIVE_POLL_SECONDS } from './utils/livePolling';
import {
  clearQuickNotesState,
  DEFAULT_QUICK_NOTES_STATE,
  loadQuickNotes,
  saveQuickNotes,
  toggleQuickNotesCollapsed,
  updateQuickNotesText,
  type QuickNotesState,
} from './utils/quickNotes';
import {
  decodeSessionSnapshot,
  parseSessionSnapshotTokenFromLocation,
  stripSessionSnapshotFromUrl,
  type DecodedSessionSnapshot,
} from './utils/sessionSnapshot';
import {
  applyThemeToDocument,
  resolveInitialTheme,
  THEME_STORAGE_KEY,
  toggleThemeMode,
  type ThemeMode,
} from './utils/theme';
import {
  addIocToWatchlist,
  evaluateWatchlistUpdates,
  loadWatchlist,
  markAllWatchlistUpdatesSeen,
  markWatchlistItemSeen,
  removeIocFromWatchlist,
  saveWatchlist,
  toggleIocInWatchlist,
  type WatchlistItem,
} from './utils/watchlist';
import {
  buildAlertRuleHistoryEntries,
  buildDesktopNotificationsFromHits,
  clampAlertConfidenceThreshold,
  evaluateCustomAlertRules,
  formatDesktopBrowserNotificationContent,
  loadAlertConfidenceThreshold,
  loadAlertRuleHistory,
  loadCustomAlertRules,
  loadDesktopRuleNotifications,
  saveAlertConfidenceThreshold,
  saveAlertRuleHistory,
  saveCustomAlertRules,
  saveDesktopRuleNotifications,
  type AlertRuleEvaluationHit,
  type AlertRuleTriggerHistoryEntry,
  type CustomAlertRule,
  type DesktopRuleNotification,
} from './utils/alertRules';
import { resolveInitialBatchStrategy, saveBatchStrategy } from './utils/bulkAnalysis';
import {
  loadPrivacyMode,
  maskIndicatorValue,
  savePrivacyMode,
} from './utils/privacyMode';
import type { IndicatorType, LookupResult, Verdict } from './utils/indicators';

interface ConfigStatus {
  keys: ApiKeyStatus;
  extraKeys: Record<BuiltinExtraSourceId, boolean>;
  customKeys: Record<string, boolean>;
  maskedHints: Record<string, string>;
  anyKeyConfigured: boolean;
}

export interface QuotaState {
  date: string;
  providers: ProviderQuotaSnapshot[];
}

export default function App() {
  const [theme, setTheme] = useState<ThemeMode>(() => {
    try {
      const saved = window.localStorage.getItem(THEME_STORAGE_KEY);
      const prefersDark = Boolean(
        window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches,
      );
      return resolveInitialTheme(saved, prefersDark);
    } catch {
      return 'light';
    }
  });
  const [activeTab, setActiveTab] = useState<ActiveTab>('investigate');
  const [helpOpen, setHelpOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [searchFocusNonce, setSearchFocusNonce] = useState(0);
  const [investigateFocusNonce, setInvestigateFocusNonce] = useState(0);
  const [recentRegionFilter, setRecentRegionFilter] = useState<string | null>(null);
  const [sharedReportSnapshot, setSharedReportSnapshot] = useState<SharedReportSnapshot | null>(null);
  const [sharedReportError, setSharedReportError] = useState<string | null>(null);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [notificationRequestedTab, setNotificationRequestedTab] =
    useState<NotificationCenterTab | null>(null);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const [privacyMode, setPrivacyMode] = useState<boolean>(() =>
    typeof window !== 'undefined' ? loadPrivacyMode(window.localStorage) : false,
  );
  const [alertRules, setAlertRules] = useState<CustomAlertRule[]>(() =>
    typeof window !== 'undefined' ? loadCustomAlertRules(window.localStorage) : [],
  );
  const [alertConfidenceThreshold, setAlertConfidenceThreshold] = useState<number>(() =>
    typeof window !== 'undefined' ? loadAlertConfidenceThreshold(window.localStorage) : 0,
  );
  const [desktopRuleAlerts, setDesktopRuleAlerts] = useState<DesktopRuleNotification[]>(() =>
    typeof window !== 'undefined' ? loadDesktopRuleNotifications(window.localStorage) : [],
  );
  const [activeDesktopToastIds, setActiveDesktopToastIds] = useState<string[]>([]);
  const [alertRuleHistory, setAlertRuleHistory] = useState<AlertRuleTriggerHistoryEntry[]>(() =>
    typeof window !== 'undefined' ? loadAlertRuleHistory(window.localStorage) : [],
  );
  const desktopToastTimersRef = useRef<Map<string, number>>(new Map());
  const [dispatchedEmailAlerts, setDispatchedEmailAlerts] = useState<EmailAlertRecord[]>([]);
  const [emailAlertsRefreshNonce, setEmailAlertsRefreshNonce] = useState(0);
  const [latestReport, setLatestReport] = useState<string | null>(null);
  const [searchReports, setSearchReports] = useState<ReportMeta[]>([]);
  const [searchSchedules, setSearchSchedules] = useState<ScheduledJob[]>([]);
  const [searchLogLines, setSearchLogLines] = useState<string[]>([]);
  const [recentHistory, setRecentHistory] = useState<RecentInvestigationEntry[]>(() =>
    typeof window !== 'undefined' ? loadRecentInvestigations(window.localStorage) : [],
  );
  const [watchlistItems, setWatchlistItems] = useState<WatchlistItem[]>(() =>
    typeof window !== 'undefined' ? loadWatchlist(window.localStorage) : [],
  );
  const [quickNotes, setQuickNotes] = useState<QuickNotesState>(() =>
    typeof window !== 'undefined'
      ? loadQuickNotes(window.localStorage)
      : { ...DEFAULT_QUICK_NOTES_STATE },
  );
  const [quickNotesDrawerOpen, setQuickNotesDrawerOpen] = useState(false);
  const [loadedSessionSnapshot, setLoadedSessionSnapshot] =
    useState<DecodedSessionSnapshot | null>(null);
  const [sessionSnapshotError, setSessionSnapshotError] = useState<string | null>(null);
  const lastSearchSyncRef = useRef<number>(0);

  const [investigateNav, setInvestigateNav] = useState<InvestigateNavigationTarget | null>(null);
  const [reportsNav, setReportsNav] = useState<ReportsNavigationTarget | null>(null);
  const [scheduledNav, setScheduledNav] = useState<ScheduledNavigationTarget | null>(null);
  const [logsNav, setLogsNav] = useState<LogsNavigationTarget | null>(null);

  const [apiSettings, setApiSettings] = useState<ApiSettings>(() => cloneDefaultApiSettings());
  const [configStatus, setConfigStatus] = useState<ConfigStatus>({
    keys: { virustotal: false, abuseipdb: false, alienvault: false },
    extraKeys: { shodan: false, threatfox: false, urlscan: false },
    customKeys: {},
    maskedHints: {},
    anyKeyConfigured: false,
  });
  const [quotaState, setQuotaState] = useState<QuotaState>({
    date: new Date().toISOString().slice(0, 10),
    providers: [],
  });
  const [connectionOverrides, setConnectionOverrides] = useState<Record<string, boolean>>({});
  const [providerLatencies, setProviderLatencies] = useState<
    Record<string, ProviderLatencySnapshot>
  >({});
  const [lastApiLatency, setLastApiLatency] = useState<ProviderLatencySnapshot | null>(null);
  const [clearHistoryNonce, setClearHistoryNonce] = useState(0);
  const [investigationState, setInvestigationState] = useState<InvestigationState>({
    rawInput: SAMPLE_BATCH,
    source: 'all',
    customSources: [...ALL_SOURCE_IDS],
    useCustomSources: false,
    includeThreatFox: null,
    includeUrlscan: null,
    mode: 'sample',
    results: [],
    invalidTokens: [],
    quotaSkipped: [],
    lastReportFile: null,
    lastRunMode: null,
    activeHistoryId: null,
    researcherNotes:
      typeof window !== 'undefined' ? loadNotesAutoSaveState(window.localStorage).draftNotes : '',
    analysisMode: 'standard',
    batchStrategy:
      typeof window !== 'undefined' ? resolveInitialBatchStrategy(window.localStorage) : 'concurrent',
    livePollingEnabled: false,
    livePollIntervalSec: DEFAULT_LIVE_POLL_SECONDS,
  });

  const refreshConfigStatus = useCallback(() => {
    fetch('/api/config/status')
      .then((r) => r.json())
      .then((data) => {
        if (data?.keys) {
          setConfigStatus({
            keys: data.keys,
            extraKeys: data.extraKeys || { shodan: false, threatfox: false, urlscan: false },
            customKeys: data.customKeys || {},
            maskedHints: data.maskedHints || {},
            anyKeyConfigured: Boolean(data.anyKeyConfigured),
          });
          if (data.anyKeyConfigured) {
            setInvestigationState((prev) => ({
              ...prev,
              mode: prev.results.length === 0 ? 'live' : prev.mode,
            }));
          }
        }
      })
      .catch(() => {});
  }, []);

  function refreshQuotaState() {
    fetch('/api/quota')
      .then((r) => r.json())
      .then((data) => {
        if (data?.date && Array.isArray(data?.providers)) {
          setQuotaState({ date: data.date, providers: data.providers });
        }
      })
      .catch(() => {});
  }

  const refreshGlobalSearchData = useCallback((force = false) => {
    const now = Date.now();
    if (!force && now - lastSearchSyncRef.current < 4000) return;
    lastSearchSyncRef.current = now;

    fetch('/api/reports')
      .then((r) => r.json())
      .then((data) => {
        if (Array.isArray(data?.reports)) {
          setSearchReports(data.reports);
          if (data.reports.length > 0) {
            setLatestReport(data.reports[0].name);
          }
        }
      })
      .catch(() => {});

    fetch('/api/schedules')
      .then((r) => r.json())
      .then((data) => {
        if (Array.isArray(data?.jobs)) {
          setSearchSchedules(data.jobs);
        }
      })
      .catch(() => {});

    fetch('/api/logs')
      .then((r) => r.json())
      .then((data) => {
        if (Array.isArray(data?.lines)) {
          setSearchLogLines(data.lines);
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    refreshConfigStatus();
    refreshQuotaState();
    refreshGlobalSearchData(true);

    fetch('/api/config/apis')
      .then((r) => r.json())
      .then((data) => {
        if (data?.settings?.providers) {
          setApiSettings(data.settings);
        }
      })
      .catch(() => {});

    const quotaPollTimer = window.setInterval(refreshQuotaState, 15_000);
    window.addEventListener('focus', refreshQuotaState);
    return () => {
      window.clearInterval(quotaPollTimer);
      window.removeEventListener('focus', refreshQuotaState);
    };
  }, [refreshGlobalSearchData]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const shareToken = parseShareTokenFromUrl(window.location.search, window.location.hash);
    if (!shareToken) return;
    setActiveTab('reports');
    fetch(`/api/reports/share/${encodeURIComponent(shareToken)}`)
      .then(async (r) => {
        const data = await r.json();
        if (!r.ok) {
          setSharedReportError(data?.error || 'Unable to load shared report link.');
          return;
        }
        if (data?.snapshot) {
          setSharedReportSnapshot(data.snapshot);
          if (data.snapshot.reportName || data.snapshot.searchQuery) {
            setReportsNav({
              reportName: data.snapshot.reportName,
              searchQuery: data.snapshot.searchQuery || '',
              nonce: Date.now(),
            });
          }
        }
      })
      .catch(() => {
        setSharedReportError('Unable to reach server to load shared report snapshot.');
      });
  }, []);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      saveQuickNotes(window.localStorage, quickNotes);
    }
  }, [quickNotes]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      saveWatchlist(window.localStorage, watchlistItems);
    }
  }, [watchlistItems]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      savePrivacyMode(window.localStorage, privacyMode);
    }
  }, [privacyMode]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      saveCustomAlertRules(window.localStorage, alertRules);
    }
  }, [alertRules]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      saveAlertConfidenceThreshold(window.localStorage, alertConfidenceThreshold);
    }
  }, [alertConfidenceThreshold]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      saveBatchStrategy(window.localStorage, investigationState.batchStrategy);
    }
  }, [investigationState.batchStrategy]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      saveDesktopRuleNotifications(window.localStorage, desktopRuleAlerts);
    }
  }, [desktopRuleAlerts]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      saveAlertRuleHistory(window.localStorage, alertRuleHistory);
    }
  }, [alertRuleHistory]);

  useEffect(() => {
    return () => {
      for (const timer of desktopToastTimersRef.current.values()) {
        window.clearTimeout(timer);
      }
      desktopToastTimersRef.current.clear();
    };
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const snapshotToken = parseSessionSnapshotTokenFromLocation(
      window.location.search,
      window.location.hash,
    );
    if (!snapshotToken) return;
    const decoded = decodeSessionSnapshot(snapshotToken);
    setActiveTab('investigate');
    if (!decoded) {
      setSessionSnapshotError('Unable to restore Session Snapshot: the link is invalid or corrupted.');
      return;
    }
    setSessionSnapshotError(null);
    setLoadedSessionSnapshot(decoded);
    setInvestigationState((prev) => ({
      ...prev,
      rawInput: decoded.rawInput || prev.rawInput,
      source: decoded.source,
      customSources: decoded.customSources.length > 0 ? decoded.customSources : prev.customSources,
      useCustomSources: decoded.useCustomSources,
      includeThreatFox: decoded.includeThreatFox,
      includeUrlscan: decoded.includeUrlscan,
      mode: decoded.mode,
      lastRunMode: decoded.lastRunMode,
      results: decoded.results,
      invalidTokens: decoded.invalidTokens,
      quotaSkipped: decoded.quotaSkipped,
      lastReportFile: decoded.lastReportFile,
      researcherNotes: decoded.researcherNotes,
      analysisMode: decoded.analysisMode,
      batchStrategy: decoded.batchStrategy,
      activeHistoryId: null,
      livePollingEnabled: false,
    }));
  }, []);

  useEffect(() => {
    function handleGlobalKeyDown(event: KeyboardEvent) {
      const action = matchGlobalKeyboardShortcut(event);
      if (!action) return;

      if (action === 'escape') {
        if (shortcutsOpen) setShortcutsOpen(false);
        if (helpOpen) setHelpOpen(false);
        if (notificationsOpen) setNotificationsOpen(false);
        if (quickNotesDrawerOpen) setQuickNotesDrawerOpen(false);
        return;
      }

      event.preventDefault();
      switch (action) {
        case 'focus_search':
          setSearchFocusNonce((n) => n + 1);
          break;
        case 'goto_investigate':
          setActiveTab('investigate');
          setInvestigateFocusNonce((n) => n + 1);
          break;
        case 'goto_reports':
          setActiveTab('reports');
          break;
        case 'goto_scheduled':
          setActiveTab('scheduled');
          break;
        case 'goto_logs':
          setActiveTab('logs');
          break;
        case 'goto_cli':
          setActiveTab('cli');
          break;
        case 'toggle_theme':
          setTheme((prev) => toggleThemeMode(prev));
          break;
        case 'toggle_shortcuts_help':
          setShortcutsOpen((prev) => !prev);
          break;
      }
    }

    document.addEventListener('keydown', handleGlobalKeyDown);
    return () => {
      document.removeEventListener('keydown', handleGlobalKeyDown);
    };
  }, [shortcutsOpen, helpOpen, notificationsOpen, quickNotesDrawerOpen]);

  useEffect(() => {
    applyThemeToDocument(theme);
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // ignore storage errors
    }
  }, [theme]);

  const effectiveApiStatus = mergeConfigAndConnectionStatus(configStatus.keys, connectionOverrides);

  const globalSearchEntries = useMemo(
    () =>
      buildGlobalSearchIndex({
        currentResults: investigationState.results,
        recentInvestigations: recentHistory,
        reports: searchReports,
        schedules: searchSchedules,
        logLines: searchLogLines,
        apiSettings,
      }),
    [
      investigationState.results,
      recentHistory,
      searchReports,
      searchSchedules,
      searchLogLines,
      apiSettings,
    ],
  );

  function handleSelectGlobalSearchResult(entry: GlobalSearchEntry, query: string) {
    const nonce = Date.now();
    if (entry.tab === 'investigate') {
      setActiveTab('investigate');
      setInvestigateNav({
        indicator: entry.indicator,
        historyEntryId: entry.historyEntryId,
        nonce,
      });
      return;
    }

    if (entry.tab === 'reports') {
      setActiveTab('reports');
      setReportsNav({
        reportName: entry.reportName,
        searchQuery: entry.kind === 'ioc' ? (entry.indicator || query.trim()) : '',
        nonce,
      });
      return;
    }

    if (entry.tab === 'scheduled') {
      setActiveTab('scheduled');
      setScheduledNav({
        scheduleId: entry.scheduleId,
        searchQuery: entry.indicator || query.trim(),
        nonce,
      });
      return;
    }

    if (entry.tab === 'logs') {
      setActiveTab('logs');
      setLogsNav({
        query: query.trim() || entry.title,
        nonce,
      });
      return;
    }

    setActiveTab('cli');
  }

  const handleEmailAlertDispatched = useCallback((record: EmailAlertRecord) => {
    setDispatchedEmailAlerts((prev) => [
      record,
      ...prev.filter((item) => item.id !== record.id),
    ].slice(0, 25));
    setEmailAlertsRefreshNonce((n) => n + 1);
  }, []);

  const pushDesktopToastIds = useCallback((items: readonly DesktopRuleNotification[]) => {
    if (items.length === 0) return;
    setActiveDesktopToastIds((prev) => [
      ...items.map((i) => i.id),
      ...prev.filter((id) => !items.some((i) => i.id === id)),
    ].slice(0, 3));

    for (const item of items) {
      const existingTimer = desktopToastTimersRef.current.get(item.id);
      if (existingTimer !== undefined) {
        window.clearTimeout(existingTimer);
      }
      const timer = window.setTimeout(() => {
        setActiveDesktopToastIds((prev) => prev.filter((id) => id !== item.id));
        desktopToastTimersRef.current.delete(item.id);
      }, 9000);
      desktopToastTimersRef.current.set(item.id, timer);

      if (
        typeof window !== 'undefined' &&
        'Notification' in window &&
        window.Notification.permission === 'granted'
      ) {
        try {
          const { title, body } = formatDesktopBrowserNotificationContent(
            item,
            (val, kind) => maskIndicatorValue(val, kind, privacyMode),
          );
          new window.Notification(title, { body });
        } catch {
          // ignore desktop OS notification failures in sandboxed contexts
        }
      }
    }
  }, [privacyMode]);

  const dispatchHits = useCallback(
    async (
      hits: AlertRuleEvaluationHit[],
      mode: 'sample' | 'live' | 'test',
      reportFile?: string | null,
    ) => {
      if (hits.length === 0) return;
      const nowIso = new Date().toISOString();
      const desktopItems = buildDesktopNotificationsFromHits(hits, nowIso);
      if (desktopItems.length > 0) {
        setDesktopRuleAlerts((prev) => [...desktopItems, ...prev].slice(0, 30));
        pushDesktopToastIds(desktopItems);
      }

      const deliverySummaryByRuleId: Record<string, string> = {};
      for (const hit of hits) {
        if (hit.rule.channel === 'email' || hit.rule.channel === 'both') {
          try {
            const resp = await fetch('/api/alerts/rules/dispatch', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                ruleName: hit.rule.name,
                minRiskScore: hit.rule.minRiskScore,
                recipients: hit.rule.emailRecipients,
                matches: hit.matches,
                mode,
                reportFile: reportFile ?? null,
              }),
            });
            const data = await resp.json();
            if (resp.ok && data?.record) {
              handleEmailAlertDispatched(data.record);
              deliverySummaryByRuleId[hit.rule.id] =
                hit.rule.channel === 'both'
                  ? `Desktop toast + Email (${data.record.deliveryStatus})`
                  : `Email (${data.record.deliveryStatus})`;
            } else {
              deliverySummaryByRuleId[hit.rule.id] =
                hit.rule.channel === 'both'
                  ? `Desktop alert fired · Email skipped (${data?.error || 'no recipients'})`
                  : `Email failed (${data?.error || 'no recipients'})`;
            }
          } catch {
            deliverySummaryByRuleId[hit.rule.id] =
              hit.rule.channel === 'both'
                ? 'Desktop alert fired · Email dispatch unreachable'
                : 'Email dispatch failed';
          }
        }
      }

      const entries = buildAlertRuleHistoryEntries(
        hits,
        mode,
        nowIso,
        deliverySummaryByRuleId,
      );
      setAlertRuleHistory((prev) => [...entries, ...prev].slice(0, 40));
    },
    [handleEmailAlertDispatched, pushDesktopToastIds],
  );

  const handleEvaluateAlertRules = useCallback(
    (
      results: readonly LookupResult[],
      mode: 'sample' | 'live',
      reportFile?: string | null,
    ): { matchedRules: number; message: string } => {
      if (results.length === 0) {
        return { matchedRules: 0, message: 'No investigation results available to evaluate.' };
      }
      const evaluation = evaluateCustomAlertRules({
        rules: alertRules,
        results,
        globalConfidenceThreshold: alertConfidenceThreshold,
        mode,
      });
      setAlertRules(evaluation.updatedRules);
      if (evaluation.hits.length > 0) {
        void dispatchHits(evaluation.hits, mode, reportFile);
        return {
          matchedRules: evaluation.hits.length,
          message: `Matched ${evaluation.hits.length} alert rule(s) across results meeting ≥ ${alertConfidenceThreshold}/100 confidence.`,
        };
      }
      return {
        matchedRules: 0,
        message:
          alertConfidenceThreshold > 0
            ? `Evaluated active rules — no indicators met the ≥ ${alertConfidenceThreshold}/100 confidence threshold and rule criteria.`
            : 'Evaluated active rules — no indicators met custom rule criteria.',
      };
    },
    [alertRules, alertConfidenceThreshold, dispatchHits],
  );

  const handleSaveAlertRule = useCallback((rule: CustomAlertRule) => {
    setAlertRules((prev) => {
      const idx = prev.findIndex((r) => r.id === rule.id);
      if (idx === -1) return [rule, ...prev];
      const next = [...prev];
      next[idx] = rule;
      return next;
    });
  }, []);

  const handleToggleAlertRule = useCallback((ruleId: string) => {
    setAlertRules((prev) =>
      prev.map((r) => (r.id === ruleId ? { ...r, enabled: !r.enabled } : r)),
    );
  }, []);

  const handleDeleteAlertRule = useCallback((ruleId: string) => {
    setAlertRules((prev) => prev.filter((r) => r.id !== ruleId));
  }, []);

  const handleTestAlertRule = useCallback(
    async (rule: CustomAlertRule): Promise<{ ok: boolean; message: string }> => {
      const sampleIndicator =
        rule.indicatorType === 'ip'
          ? '185.220.101.44'
          : rule.indicatorType === 'hash'
            ? '44d88612fea8a8f36de82e1278abb02f'
            : rule.indicatorType === 'url'
              ? 'https://login-check.example/auth'
              : 'evil-test.example';
      const nowIso = new Date().toISOString();
      const updatedRule: CustomAlertRule = {
        ...rule,
        lastTriggeredAt: nowIso,
        triggerCount: (rule.triggerCount || 0) + 1,
      };
      setAlertRules((prev) => prev.map((r) => (r.id === rule.id ? updatedRule : r)));
      const hit: AlertRuleEvaluationHit = {
        rule: updatedRule,
        matches: [
          {
            indicator: sampleIndicator,
            type: rule.indicatorType === 'all' ? 'domain' : rule.indicatorType,
            confidenceScore: Math.max(88, rule.minRiskScore),
            riskLevel: rule.minRiskScore >= 75 ? 'Critical' : 'High',
            overallVerdict: 'Malicious',
            activeProviderCount: 3,
            explanation: `Rule "${rule.name}" test trigger (score >= ${rule.minRiskScore})`,
          },
        ],
      };
      await dispatchHits([hit], 'test', null);
      return {
        ok: true,
        message: `Test alert triggered for "${rule.name}" via ${rule.channel === 'both' ? 'Desktop + Email' : rule.channel}.`,
      };
    },
    [dispatchHits],
  );

  const handleToggleWatchIoc = useCallback(
    (
      indicator: string,
      type: IndicatorType,
      verdict?: Verdict | null,
      confidenceScore?: number | null,
    ) => {
      setWatchlistItems((prev) =>
        toggleIocInWatchlist(prev, {
          indicator,
          type,
          verdict: verdict ?? null,
          confidenceScore: confidenceScore ?? null,
        }).next,
      );
    },
    [],
  );

  const handleAddWatchlistIndicator = useCallback(
    (
      rawInput: string,
      options?: { verdict?: Verdict | null; confidenceScore?: number | null },
    ): { added: boolean; error?: string } => {
      const normalizedKey = rawInput.trim().toLowerCase();
      if (watchlistItems.some((item) => item.indicator.trim().toLowerCase() === normalizedKey)) {
        return {
          added: false,
          error: 'Indicator is already monitored on your Watchlist.',
        };
      }
      const res = addIocToWatchlist(watchlistItems, {
        indicator: rawInput,
        verdict: options?.verdict ?? null,
        confidenceScore: options?.confidenceScore ?? null,
      });
      if (!res.added) {
        return {
          added: false,
          error:
            res.invalid.length > 0
              ? `Unsupported indicator format: ${res.invalid[0]}`
              : 'Indicator is already monitored or invalid.',
        };
      }
      setWatchlistItems(res.next);
      return { added: true };
    },
    [watchlistItems],
  );

  const handleRemoveWatchlistIndicator = useCallback((indicator: string) => {
    setWatchlistItems((prev) => removeIocFromWatchlist(prev, indicator));
  }, []);

  const handleAcknowledgeWatchlistItem = useCallback((indicator: string) => {
    setWatchlistItems((prev) => markWatchlistItemSeen(prev, indicator));
  }, []);

  const handleAcknowledgeAllWatchlist = useCallback(() => {
    setWatchlistItems((prev) => markAllWatchlistUpdatesSeen(prev));
  }, []);

  const handleEvaluateWatchlistResults = useCallback(
    (results: readonly LookupResult[], checkedAtIso: string) => {
      setWatchlistItems((prev) => evaluateWatchlistUpdates(prev, results, checkedAtIso).next);
    },
    [],
  );

  const resolveProviderDisplayLabel = useCallback(
    (providerId: string): string => {
      if (providerId === 'virustotal') return 'VirusTotal';
      if (providerId === 'abuseipdb') return 'AbuseIPDB';
      if (providerId === 'alienvault') return 'AlienVault OTX';
      if (providerId === 'shodan' || providerId === 'threatfox' || providerId === 'urlscan') {
        return EXTRA_PROVIDER_META[providerId].name;
      }
      const customMatch = (apiSettings.customProviders || []).find((cp) => cp.id === providerId);
      return customMatch?.name || providerId;
    },
    [apiSettings.customProviders],
  );

  const recordProviderLatency = useCallback(
    (providerId: string, ok: boolean, latencyMs?: number) => {
      if (typeof latencyMs !== 'number' || !Number.isFinite(latencyMs) || latencyMs <= 0) return;
      const snapshot: ProviderLatencySnapshot = {
        providerId,
        providerLabel: resolveProviderDisplayLabel(providerId),
        latencyMs: Math.round(latencyMs),
        ok,
        checkedAt: new Date().toISOString(),
      };
      setProviderLatencies((prev) => ({ ...prev, [providerId]: snapshot }));
      setLastApiLatency(snapshot);
    },
    [resolveProviderDisplayLabel],
  );

  const handleClearRecentHistoryFromSearch = useCallback(() => {
    setRecentHistory([]);
    setClearHistoryNonce((prev) => prev + 1);
    setInvestigationState((prev) => ({ ...prev, activeHistoryId: null }));
    if (typeof window !== 'undefined') {
      clearRecentInvestigations(window.localStorage);
      saveNotesAutoSaveState(window.localStorage, createEmptyNotesAutoSaveState());
    }
  }, []);

  const handleTestProviderFromTopBar = useCallback(
    async (
      providerId: string,
    ): Promise<{ ok: boolean; message?: string; latencyMs?: number }> => {
      const clientStart = performance.now();
      try {
        const resp = await fetch('/api/config/apis/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            provider: providerId,
            timeoutSeconds: apiSettings.timeoutSeconds,
          }),
        });
        const data = await resp.json();
        const ok = Boolean(data?.ok);
        const clientElapsed = Math.max(1, Math.round(performance.now() - clientStart));
        const measuredLatency =
          typeof data?.latencyMs === 'number' && data.latencyMs > 0
            ? Math.round(data.latencyMs)
            : clientElapsed;
        setConnectionOverrides((prev) => ({ ...prev, [providerId]: ok }));
        recordProviderLatency(providerId, ok, measuredLatency);
        if (data?.quota?.date && Array.isArray(data?.quota?.providers)) {
          setQuotaState(data.quota);
        }
        return {
          ok,
          latencyMs: measuredLatency,
          message: data?.message || data?.error || (ok ? 'Verified' : 'Check failed'),
        };
      } catch {
        const clientElapsed = Math.max(1, Math.round(performance.now() - clientStart));
        setConnectionOverrides((prev) => ({ ...prev, [providerId]: false }));
        recordProviderLatency(providerId, false, clientElapsed);
        return { ok: false, latencyMs: clientElapsed, message: 'Server unreachable' };
      }
    },
    [apiSettings.timeoutSeconds, recordProviderLatency],
  );

  return (
    <PrivacyModeContext.Provider value={privacyMode}>
      <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 transition-colors">
        <TopBar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          latestReport={latestReport}
          apiStatus={effectiveApiStatus}
          extraKeyStatus={configStatus.extraKeys}
          customKeyStatus={configStatus.customKeys}
          apiSettings={apiSettings}
          connectionOverrides={connectionOverrides}
          providerLatencies={providerLatencies}
          lastApiLatency={lastApiLatency}
          onTestProvider={handleTestProviderFromTopBar}
          onOpenHelp={() => setHelpOpen(true)}
          onOpenShortcuts={() => setShortcutsOpen(true)}
          theme={theme}
          onToggleTheme={() => setTheme((prev) => toggleThemeMode(prev))}
          notificationCount={unreadNotifications}
          notificationsOpen={notificationsOpen}
          onToggleNotifications={() => {
            setNotificationRequestedTab(null);
            setNotificationsOpen((prev) => !prev);
          }}
          searchEntries={globalSearchEntries}
          recentHistoryCount={recentHistory.length}
          onClearRecentHistory={handleClearRecentHistoryFromSearch}
          searchFocusNonce={searchFocusNonce}
          onSearchFocus={() => refreshGlobalSearchData(false)}
          onSelectSearchResult={handleSelectGlobalSearchResult}
          quickNotesOpen={quickNotesDrawerOpen}
          quickNotesHasContent={quickNotes.text.trim().length > 0}
          onToggleQuickNotes={() => setQuickNotesDrawerOpen((prev) => !prev)}
          privacyMode={privacyMode}
          onTogglePrivacyMode={() => setPrivacyMode((prev) => !prev)}
        />

        <NotificationCenter
          quotaState={quotaState}
          emailAlerts={dispatchedEmailAlerts}
          emailAlertsRefreshNonce={emailAlertsRefreshNonce}
          alertRules={alertRules}
          confidenceThreshold={alertConfidenceThreshold}
          onChangeConfidenceThreshold={(nextVal) =>
            setAlertConfidenceThreshold(clampAlertConfidenceThreshold(nextVal, 0))
          }
          desktopRuleAlerts={desktopRuleAlerts}
          activeDesktopToastIds={activeDesktopToastIds}
          alertRuleHistory={alertRuleHistory}
          currentResults={investigationState.results}
          isOpen={notificationsOpen}
          requestedTab={notificationRequestedTab}
          onOpenPanel={() => setNotificationsOpen(true)}
          onClosePanel={() => setNotificationsOpen(false)}
          onUnreadCountChange={setUnreadNotifications}
          onNavigateToApis={() => {
            setNotificationsOpen(false);
            setActiveTab('cli');
          }}
          onEmailAlertDispatched={handleEmailAlertDispatched}
          onClearEmailAlerts={() => setDispatchedEmailAlerts([])}
          onSaveAlertRule={handleSaveAlertRule}
          onToggleAlertRule={handleToggleAlertRule}
          onDeleteAlertRule={handleDeleteAlertRule}
          onTestAlertRule={handleTestAlertRule}
          onEvaluateAlertRulesNow={() =>
            handleEvaluateAlertRules(
              investigationState.results,
              investigationState.lastRunMode ?? investigationState.mode,
              investigationState.lastReportFile,
            )
          }
          onClearAlertRuleHistory={() => setAlertRuleHistory([])}
          onMarkDesktopAlertRead={(id) =>
            setDesktopRuleAlerts((prev) =>
              prev.map((a) => (a.id === id ? { ...a, read: true } : a)),
            )
          }
          onDismissDesktopAlert={(id) => {
            setActiveDesktopToastIds((prev) => prev.filter((item) => item !== id));
            setDesktopRuleAlerts((prev) => prev.filter((a) => a.id !== id));
          }}
          onMarkAllDesktopAlertsRead={() =>
            setDesktopRuleAlerts((prev) => prev.map((a) => ({ ...a, read: true })))
          }
          onClearDesktopAlerts={() => {
            setActiveDesktopToastIds([]);
            setDesktopRuleAlerts([]);
          }}
          onDismissDesktopToast={(id) => {
            const timer = desktopToastTimersRef.current.get(id);
            if (timer !== undefined) {
              window.clearTimeout(timer);
              desktopToastTimersRef.current.delete(id);
            }
            setActiveDesktopToastIds((prev) => prev.filter((item) => item !== id));
          }}
        />

        {quickNotesDrawerOpen && (
          <div className="fixed inset-0 z-50 flex justify-end print:hidden" role="dialog" aria-modal="true" aria-label="Quick Notes sidebar">
            <div
              className="fixed inset-0 bg-slate-950/35 backdrop-blur-[1px]"
              onClick={() => setQuickNotesDrawerOpen(false)}
            />
            <aside className="relative z-10 h-full w-full max-w-sm border-l border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl">
              <QuickNotesSidebarPanel
                variant="drawer"
                notesState={quickNotes}
                onChangeText={(nextText) =>
                  setQuickNotes((prev) => updateQuickNotesText(prev, nextText))
                }
                onClearText={() => setQuickNotes((prev) => clearQuickNotesState(prev))}
                onCloseDrawer={() => setQuickNotesDrawerOpen(false)}
              />
            </aside>
          </div>
        )}

        <main className="mx-auto max-w-[1280px] px-4 py-6 md:px-6 md:py-8">
          {privacyMode && (
            <div
              role="status"
              data-testid="privacy-mode-banner"
              className="mb-5 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-300 dark:border-amber-800/80 bg-amber-50/90 dark:bg-amber-950/35 px-4 py-2 text-xs text-amber-950 dark:text-amber-200 print:hidden"
            >
              <div className="flex items-center gap-2">
                <EyeOff className="h-3.5 w-3.5 text-amber-700 dark:text-amber-400 shrink-0" aria-hidden="true" />
                <span>
                  <strong>Privacy Mode Active:</strong> Sensitive IOC values (IPs, domains, URLs, and hashes) are masked across all views for safe screen sharing.
                </span>
              </div>
              <button
                type="button"
                onClick={() => setPrivacyMode(false)}
                className="font-semibold text-amber-900 dark:text-amber-300 hover:underline whitespace-nowrap cursor-pointer"
              >
                Reveal Original IOCs
              </button>
            </div>
          )}
        {activeTab === 'investigate' && (
          <InvestigateView
            state={investigationState}
            apiSettings={apiSettings}
            extraKeyStatus={configStatus.extraKeys}
            quota={quotaState}
            theme={theme}
            onChangeState={setInvestigationState}
            onQuotaChange={setQuotaState}
            onReportCreated={(name) => {
              setLatestReport(name);
              refreshGlobalSearchData(true);
            }}
            onOpenApiConfig={() => setActiveTab('cli')}
            onEmailAlertTriggered={handleEmailAlertDispatched}
            onOpenEmailAlertRules={() => {
              setNotificationRequestedTab('email_rules');
              setNotificationsOpen(true);
            }}
            onOpenAlertRules={() => {
              setNotificationRequestedTab('alert_rules');
              setNotificationsOpen(true);
            }}
            onEvaluateAlertRules={handleEvaluateAlertRules}
            navigationTarget={investigateNav}
            focusInputNonce={investigateFocusNonce}
            recentRegionFilter={recentRegionFilter}
            onClearRecentRegionFilter={() => setRecentRegionFilter(null)}
            onRecentHistoryChange={setRecentHistory}
            clearHistoryNonce={clearHistoryNonce}
            watchlistItems={watchlistItems}
            onToggleWatchIoc={handleToggleWatchIoc}
            onAddWatchlistIndicator={handleAddWatchlistIndicator}
            onRemoveWatchlistIndicator={handleRemoveWatchlistIndicator}
            onAcknowledgeWatchlistItem={handleAcknowledgeWatchlistItem}
            onAcknowledgeAllWatchlist={handleAcknowledgeAllWatchlist}
            onEvaluateWatchlistResults={handleEvaluateWatchlistResults}
            quickNotesState={quickNotes}
            onChangeQuickNotesText={(nextText) =>
              setQuickNotes((prev) => updateQuickNotesText(prev, nextText))
            }
            onClearQuickNotes={() => setQuickNotes((prev) => clearQuickNotesState(prev))}
            onToggleQuickNotesCollapsed={() =>
              setQuickNotes((prev) => toggleQuickNotesCollapsed(prev))
            }
            loadedSessionSnapshot={loadedSessionSnapshot}
            sessionSnapshotError={sessionSnapshotError}
            onDismissSessionSnapshot={() => {
              setLoadedSessionSnapshot(null);
              setSessionSnapshotError(null);
              if (typeof window !== 'undefined') {
                const cleanedHref = stripSessionSnapshotFromUrl(window.location.href);
                window.history.replaceState({}, '', cleanedHref);
              }
            }}
          />
        )}
        {activeTab === 'reports' && (
          <ReportsView
            theme={theme}
            navigationTarget={reportsNav}
            currentResults={investigationState.results}
            recentInvestigations={recentHistory}
            dispatchedEmailAlerts={dispatchedEmailAlerts}
            activeRegionFilter={recentRegionFilter}
            onFilterRecentByRegion={(regionLabel, options) => {
              setRecentRegionFilter(regionLabel);
              if (options?.navigate && regionLabel) {
                setActiveTab('investigate');
              }
            }}
            sharedReportSnapshot={sharedReportSnapshot}
            sharedReportError={sharedReportError}
            onDismissSharedReport={() => {
              setSharedReportSnapshot(null);
              setSharedReportError(null);
              if (typeof window !== 'undefined' && window.location.search.includes('share=')) {
                const url = new URL(window.location.href);
                url.searchParams.delete('share');
                window.history.replaceState({}, '', url.toString());
              }
            }}
            onOpenInvestigation={(entry) => {
              setActiveTab('investigate');
              setInvestigateNav({
                historyEntryId: entry.id,
                nonce: Date.now(),
              });
            }}
            onNavigateToInvestigate={() => {
              setActiveTab('investigate');
              setInvestigateFocusNonce((n) => n + 1);
            }}
          />
        )}
        {activeTab === 'scheduled' && (
          <ScheduledView
            onReportCreated={(name) => {
              setLatestReport(name);
              refreshGlobalSearchData(true);
            }}
            onQuotaChange={setQuotaState}
            onEmailAlertTriggered={handleEmailAlertDispatched}
            onEvaluateAlertRules={handleEvaluateAlertRules}
            navigationTarget={scheduledNav}
          />
        )}
        {activeTab === 'logs' && <LogsView navigationTarget={logsNav} />}
        {activeTab === 'cli' && (
          <CliSetupView
            keyStatus={configStatus.keys}
            extraKeyStatus={configStatus.extraKeys}
            customKeyStatus={configStatus.customKeys}
            maskedKeyHints={configStatus.maskedHints}
            apiSettings={apiSettings}
            quota={quotaState}
            emailAlertsRefreshNonce={emailAlertsRefreshNonce}
            alertRules={alertRules}
            alertConfidenceThreshold={alertConfidenceThreshold}
            onChangeAlertConfidenceThreshold={(nextVal) =>
              setAlertConfidenceThreshold(clampAlertConfidenceThreshold(nextVal, 0))
            }
            alertRuleHistory={alertRuleHistory}
            currentResults={investigationState.results}
            onApiSettingsChange={(next) => {
              setApiSettings(next);
              refreshConfigStatus();
            }}
            onKeyStatusUpdated={refreshConfigStatus}
            onQuotaChange={setQuotaState}
            onConnectionTestResult={(provider, ok, latencyMs) => {
              setConnectionOverrides((prev) => ({ ...prev, [provider]: ok }));
              recordProviderLatency(provider, ok, latencyMs);
            }}
            onConnectionOverridesReset={() => setConnectionOverrides({})}
            onOpenHelp={() => setHelpOpen(true)}
            onEmailAlertDispatched={handleEmailAlertDispatched}
            onSaveAlertRule={handleSaveAlertRule}
            onToggleAlertRule={handleToggleAlertRule}
            onDeleteAlertRule={handleDeleteAlertRule}
            onTestAlertRule={handleTestAlertRule}
            onEvaluateAlertRulesNow={() =>
              handleEvaluateAlertRules(
                investigationState.results,
                investigationState.lastRunMode ?? investigationState.mode,
                investigationState.lastReportFile,
              )
            }
            onClearAlertRuleHistory={() => setAlertRuleHistory([])}
          />
        )}
      </main>

      <footer
        data-testid="keyboard-shortcut-hints"
        className="border-t border-slate-200 dark:border-slate-800 bg-white/70 dark:bg-slate-950/80 print:hidden"
      >
        <div className="mx-auto flex max-w-[1280px] flex-wrap items-center justify-between gap-2 px-4 py-2.5 text-[11px] text-slate-500 dark:text-slate-400 md:px-6">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span>
              <kbd className="rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-1 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-200">
                Ctrl+K
              </kbd>{' '}
              / <kbd className="rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-1 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-200">/</kbd> Search
            </span>
            <span>
              <kbd className="rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-1 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-200">
                Ctrl+I
              </kbd>{' '}
              Investigate
            </span>
            <span className="hidden sm:inline">
              <kbd className="rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-1 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-200">
                Alt+1–5
              </kbd>{' '}
              Switch Tabs
            </span>
            <span className="hidden md:inline">
              <kbd className="rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-1 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-200">
                Alt+T
              </kbd>{' '}
              Theme
            </span>
          </div>

          <button
            type="button"
            onClick={() => setShortcutsOpen(true)}
            className="inline-flex items-center gap-1 font-medium text-slate-600 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white cursor-pointer"
          >
            <span>Press</span>
            <kbd className="rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-700 dark:text-slate-200">
              ?
            </kbd>
            <span>for all shortcuts</span>
          </button>
        </div>
      </footer>

      <HelpModal
        open={helpOpen}
        onClose={() => setHelpOpen(false)}
        onOpenApiSettings={() => setActiveTab('cli')}
        keyStatus={effectiveApiStatus}
        extraKeyStatus={configStatus.extraKeys}
      />

      <KeyboardShortcutsModal
        open={shortcutsOpen}
        onClose={() => setShortcutsOpen(false)}
      />
      </div>
    </PrivacyModeContext.Provider>
  );
}
