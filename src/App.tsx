import { useEffect, useState } from 'react';
import { TopBar, type ActiveTab } from './components/TopBar';
import {
  InvestigateView,
  SAMPLE_BATCH,
  type InvestigationState,
} from './components/InvestigateView';
import { ReportsView } from './components/ReportsView';
import { LogsView } from './components/LogsView';
import { ScheduledView } from './components/ScheduledView';
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
import type { SourceId } from './utils/indicators';
import type { ProviderQuotaSnapshot } from './utils/quota';
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
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const [latestReport, setLatestReport] = useState<string | null>(null);
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
    mode: 'sample',
    results: [],
    invalidTokens: [],
    quotaSkipped: [],
    lastReportFile: null,
    lastRunMode: null,
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

  useEffect(() => {
    refreshConfigStatus();
    refreshQuotaState();

    fetch('/api/config/apis')
      .then((r) => r.json())
      .then((data) => {
        if (data?.settings?.providers) {
          setApiSettings(data.settings);
        }
      })
      .catch(() => {});

    fetch('/api/reports')
      .then((r) => r.json())
      .then((data) => {
        if (Array.isArray(data?.reports) && data.reports.length > 0) {
          setLatestReport(data.reports[0].name);
        }
      })
      .catch(() => {});

    const quotaPollTimer = window.setInterval(refreshQuotaState, 15_000);
    window.addEventListener('focus', refreshQuotaState);
    return () => {
      window.clearInterval(quotaPollTimer);
      window.removeEventListener('focus', refreshQuotaState);
    };
  }, []);

  useEffect(() => {
    applyThemeToDocument(theme);
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // ignore storage errors
    }
  }, [theme]);

  const effectiveApiStatus = mergeConfigAndConnectionStatus(configStatus.keys, connectionOverrides);

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
        onToggleNotifications={() => setNotificationsOpen((prev) => !prev)}
      />

      <NotificationCenter
        quotaState={quotaState}
        isOpen={notificationsOpen}
        onOpenPanel={() => setNotificationsOpen(true)}
        onClosePanel={() => setNotificationsOpen(false)}
        onUnreadCountChange={setUnreadNotifications}
        onNavigateToApis={() => {
          setNotificationsOpen(false);
          setActiveTab('cli');
        }}
      />

      <main className="mx-auto max-w-[1280px] px-4 py-6 md:px-6 md:py-8">
        {activeTab === 'investigate' && (
          <InvestigateView
            state={investigationState}
            apiSettings={apiSettings}
            quota={quotaState}
            onChangeState={setInvestigationState}
            onQuotaChange={setQuotaState}
            onReportCreated={(name) => setLatestReport(name)}
            onOpenApiConfig={() => setActiveTab('cli')}
          />
        )}
        {activeTab === 'reports' && <ReportsView theme={theme} />}
        {activeTab === 'scheduled' && (
          <ScheduledView
            onReportCreated={(name) => setLatestReport(name)}
            onQuotaChange={setQuotaState}
          />
        )}
        {activeTab === 'logs' && <LogsView />}
        {activeTab === 'cli' && (
          <CliSetupView
            keyStatus={configStatus.keys}
            extraKeyStatus={configStatus.extraKeys}
            customKeyStatus={configStatus.customKeys}
            apiSettings={apiSettings}
            quota={quotaState}
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
