import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
import { NotificationCenter } from './components/NotificationCenter';
import {
  ALL_SOURCE_IDS,
  cloneDefaultApiSettings,
  mergeConfigAndConnectionStatus,
  type ApiKeyStatus,
  type ApiSettings,
  type BuiltinExtraSourceId,
} from './utils/apiConfig';
import {
  buildGlobalSearchIndex,
  type GlobalSearchEntry,
} from './utils/globalSearch';
import type { SourceId } from './utils/indicators';
import {
  loadRecentInvestigations,
  type RecentInvestigationEntry,
} from './utils/investigationHistory';
import type { ProviderQuotaSnapshot } from './utils/quota';
import type { EmailAlertRecord } from './utils/emailAlerts';
import type { ReportMeta } from './utils/reportsAnalytics';
import { parseShareTokenFromUrl, type SharedReportSnapshot } from './utils/reportSharing';
import type { ScheduledJob } from './utils/scheduler';
import { matchGlobalKeyboardShortcut } from './utils/keyboardShortcuts';
import { DEFAULT_LIVE_POLL_SECONDS } from './utils/livePolling';
import {
  applyThemeToDocument,
  resolveInitialTheme,
  THEME_STORAGE_KEY,
  toggleThemeMode,
  type ThemeMode,
} from './utils/theme';

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
  const [notificationRequestedTab, setNotificationRequestedTab] = useState<'alerts' | 'email_rules' | null>(null);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const [dispatchedEmailAlerts, setDispatchedEmailAlerts] = useState<EmailAlertRecord[]>([]);
  const [emailAlertsRefreshNonce, setEmailAlertsRefreshNonce] = useState(0);
  const [latestReport, setLatestReport] = useState<string | null>(null);
  const [searchReports, setSearchReports] = useState<ReportMeta[]>([]);
  const [searchSchedules, setSearchSchedules] = useState<ScheduledJob[]>([]);
  const [searchLogLines, setSearchLogLines] = useState<string[]>([]);
  const [recentHistory, setRecentHistory] = useState<RecentInvestigationEntry[]>(() =>
    typeof window !== 'undefined' ? loadRecentInvestigations(window.localStorage) : [],
  );
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
  const [connectionOverrides, setConnectionOverrides] = useState<Partial<Record<SourceId, boolean>>>({});
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
    researcherNotes: '',
    analysisMode: 'standard',
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
    function handleGlobalKeyDown(event: KeyboardEvent) {
      const action = matchGlobalKeyboardShortcut(event);
      if (!action) return;

      if (action === 'escape') {
        if (shortcutsOpen) setShortcutsOpen(false);
        if (helpOpen) setHelpOpen(false);
        if (notificationsOpen) setNotificationsOpen(false);
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
  }, [shortcutsOpen, helpOpen, notificationsOpen]);

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

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 transition-colors">
      <TopBar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        latestReport={latestReport}
        apiStatus={effectiveApiStatus}
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
        searchFocusNonce={searchFocusNonce}
        onSearchFocus={() => refreshGlobalSearchData(false)}
        onSelectSearchResult={handleSelectGlobalSearchResult}
      />

      <NotificationCenter
        quotaState={quotaState}
        emailAlerts={dispatchedEmailAlerts}
        emailAlertsRefreshNonce={emailAlertsRefreshNonce}
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
      />

      <main className="mx-auto max-w-[1280px] px-4 py-6 md:px-6 md:py-8">
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
            navigationTarget={investigateNav}
            focusInputNonce={investigateFocusNonce}
            recentRegionFilter={recentRegionFilter}
            onClearRecentRegionFilter={() => setRecentRegionFilter(null)}
            onRecentHistoryChange={setRecentHistory}
          />
        )}
        {activeTab === 'reports' && (
          <ReportsView
            theme={theme}
            navigationTarget={reportsNav}
            currentResults={investigationState.results}
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
            onApiSettingsChange={(next) => {
              setApiSettings(next);
              refreshConfigStatus();
            }}
            onKeyStatusUpdated={refreshConfigStatus}
            onQuotaChange={setQuotaState}
            onConnectionTestResult={(provider, ok) => {
              if (provider === 'virustotal' || provider === 'abuseipdb' || provider === 'alienvault') {
                setConnectionOverrides((prev) => ({ ...prev, [provider]: ok }));
              }
            }}
            onConnectionOverridesReset={() => setConnectionOverrides({})}
            onOpenHelp={() => setHelpOpen(true)}
            onEmailAlertDispatched={handleEmailAlertDispatched}
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
  );
}
