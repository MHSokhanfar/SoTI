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
import type { ScheduledJob } from './utils/scheduler';
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
  });

  function refreshConfigStatus() {
    fetch('/api/config/status')
      .then((r) => r.json())
      .then((data) => {
        if (data?.keys) {
          setConfigStatus({
            keys: data.keys,
            extraKeys: data.extraKeys || { shodan: false, threatfox: false, urlscan: false },
            customKeys: data.customKeys || {},
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
  }

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
        theme={theme}
        onToggleTheme={() => setTheme((prev) => toggleThemeMode(prev))}
        notificationCount={unreadNotifications}
        notificationsOpen={notificationsOpen}
        onToggleNotifications={() => {
          setNotificationRequestedTab(null);
          setNotificationsOpen((prev) => !prev);
        }}
        searchEntries={globalSearchEntries}
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
            onRecentHistoryChange={setRecentHistory}
          />
        )}
        {activeTab === 'reports' && (
          <ReportsView
            theme={theme}
            navigationTarget={reportsNav}
            currentResults={investigationState.results}
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
            apiSettings={apiSettings}
            quota={quotaState}
            emailAlertsRefreshNonce={emailAlertsRefreshNonce}
            onApiSettingsChange={(next) => {
              setApiSettings(next);
              refreshConfigStatus();
            }}
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

      <HelpModal
        open={helpOpen}
        onClose={() => setHelpOpen(false)}
        onOpenApiSettings={() => setActiveTab('cli')}
        keyStatus={effectiveApiStatus}
        extraKeyStatus={configStatus.extraKeys}
      />
    </div>
  );
}
