import { Bell, Download, HelpCircle, Moon, Sun } from 'lucide-react';
import type { ApiKeyStatus } from '../utils/apiConfig';
import type { SourceId } from '../utils/indicators';
import type { ThemeMode } from '../utils/theme';

export type ActiveTab = 'investigate' | 'reports' | 'scheduled' | 'logs' | 'cli';

interface TopBarProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
  latestReport: string | null;
  apiStatus: ApiKeyStatus;
  onOpenHelp: () => void;
  theme: ThemeMode;
  onToggleTheme: () => void;
  notificationCount: number;
  notificationsOpen: boolean;
  onToggleNotifications: () => void;
}

const NAV_ITEMS: { id: ActiveTab; label: string }[] = [
  { id: 'investigate', label: 'Investigate' },
  { id: 'reports', label: 'Reports' },
  { id: 'scheduled', label: 'Scheduled' },
  { id: 'logs', label: 'Logs' },
  { id: 'cli', label: 'CLI & APIs' },
];

const API_DOT_ITEMS: { id: SourceId; fullLabel: string; shortLabel: string }[] = [
  { id: 'virustotal', fullLabel: 'VirusTotal', shortLabel: 'VT' },
  { id: 'abuseipdb', fullLabel: 'AbuseIPDB', shortLabel: 'Abuse' },
  { id: 'alienvault', fullLabel: 'AlienVault', shortLabel: 'OTX' },
];

export function TopBar({
  activeTab,
  onSelectTab,
  latestReport,
  apiStatus,
  onOpenHelp,
  theme,
  onToggleTheme,
  notificationCount,
  notificationsOpen,
  onToggleNotifications,
}: TopBarProps) {
  const isDark = theme === 'dark';

  return (
    <header className="md:sticky md:top-0 z-30 border-b border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-950/90 backdrop-blur transition-colors">
      <div className="mx-auto flex max-w-[1280px] flex-wrap items-center justify-between gap-y-2 gap-x-2 px-3 py-2.5 sm:px-4 md:flex-nowrap md:gap-8 md:px-6 md:py-3.5">
        <a
          href="#investigate"
          onClick={(e) => {
            e.preventDefault();
            onSelectTab('investigate');
          }}
          className="text-lg font-bold tracking-tight text-slate-950 dark:text-slate-50 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-red-600"
        >
          SoTI
        </a>

        <nav
          aria-label="Primary"
          className="order-3 flex w-full items-center justify-between gap-2 border-t border-slate-100 dark:border-slate-800 pt-2 md:order-none md:w-auto md:justify-start md:gap-6 md:border-t-0 md:pt-0"
        >
          {NAV_ITEMS.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectTab(item.id)}
                className={`relative py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer md:text-sm focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-red-600 ${
                  isActive
                    ? 'text-slate-950 dark:text-slate-50 after:absolute after:inset-x-0 after:-bottom-[9px] md:after:-bottom-[15px] after:h-0.5 after:bg-red-600'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        <div className="flex items-center gap-1.5 sm:gap-2.5 shrink-0">
          <button
            type="button"
            onClick={() => onSelectTab('cli')}
            aria-label={`API connection status: ${API_DOT_ITEMS.map(
              (item) => `${item.fullLabel} ${apiStatus[item.id] ? 'valid' : 'invalid'}`,
            ).join(', ')}. Open API settings`}
            className="flex items-center gap-1.5 sm:gap-3 py-1 text-[11px] font-medium whitespace-nowrap shrink-0 cursor-pointer rounded focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-red-600"
          >
            {API_DOT_ITEMS.map((item) => {
              const isValid = apiStatus[item.id];
              return (
                <span
                  key={item.id}
                  data-testid={`api-status-dot-${item.id}`}
                  data-status={isValid ? 'valid' : 'invalid'}
                  title={`${item.fullLabel}: ${isValid ? 'Valid' : 'Invalid'}`}
                  className={`inline-flex items-center gap-1 sm:gap-1.5 whitespace-nowrap ${
                    isValid ? 'text-slate-700 dark:text-slate-300' : 'text-red-700 dark:text-red-400'
                  }`}
                >
                  <span
                    aria-hidden="true"
                    className={`h-2 w-2 rounded-full shrink-0 ${
                      isValid ? 'bg-emerald-500' : 'bg-red-600 dark:bg-red-500'
                    }`}
                  />
                  <span className="hidden lg:inline">{item.fullLabel}</span>
                  <span className="lg:hidden">{item.shortLabel}</span>
                </span>
              );
            })}
          </button>

          <span
            className="hidden sm:block h-4 w-px bg-slate-200 dark:bg-slate-800 shrink-0"
            aria-hidden="true"
          />

          <button
            type="button"
            onClick={onToggleNotifications}
            data-testid="notification-center-toggle"
            aria-expanded={notificationsOpen}
            aria-label={
              notificationCount > 0
                ? `Open notification center (${notificationCount} unread quota alerts)`
                : 'Open notification center'
            }
            title={
              notificationCount > 0
                ? `${notificationCount} unread quota alert${notificationCount === 1 ? '' : 's'}`
                : 'Notification center'
            }
            className={`inline-flex items-center justify-center rounded-lg border p-1.5 sm:px-2.5 sm:py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200 ${
              notificationsOpen
                ? 'border-slate-300 dark:border-slate-600 bg-slate-100 dark:bg-slate-800 text-slate-950 dark:text-white'
                : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-950 dark:hover:text-white'
            }`}
          >
            <Bell
              className={`h-3.5 w-3.5 ${
                notificationCount > 0 ? 'text-red-600 dark:text-red-400' : ''
              }`}
              aria-hidden="true"
            />
            {notificationCount > 0 && (
              <span
                data-testid="notification-unread-count"
                className="ml-1 font-mono text-[11px] font-bold text-red-700 dark:text-red-400 tabular-nums"
              >
                {notificationCount}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={onToggleTheme}
            data-testid="theme-toggle"
            aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            aria-pressed={isDark}
            title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-1.5 sm:px-2.5 sm:py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-950 dark:hover:text-white whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
          >
            {isDark ? (
              <Sun className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
            ) : (
              <Moon className="h-3.5 w-3.5 text-slate-600" aria-hidden="true" />
            )}
            <span className="hidden xl:inline">{isDark ? 'Light' : 'Dark'}</span>
          </button>

          <button
            type="button"
            onClick={onOpenHelp}
            aria-label="Open API key documentation help"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-1.5 sm:px-2.5 sm:py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-950 dark:hover:text-white whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
          >
            <HelpCircle className="h-3.5 w-3.5" aria-hidden="true" />
            <span className="hidden sm:inline">Help</span>
          </button>

          {latestReport ? (
            <a
              href={`/api/reports/${encodeURIComponent(latestReport)}?download=1`}
              className="inline-flex items-center gap-1 sm:gap-2 rounded-lg bg-red-600 px-2 py-1.5 text-[11px] sm:px-3.5 sm:py-2 sm:text-xs font-semibold text-white transition-colors hover:bg-red-700 whitespace-nowrap shrink-0 md:px-4 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              Export CSV
            </a>
          ) : (
            <button
              type="button"
              onClick={() => onSelectTab('reports')}
              className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 dark:bg-slate-100 px-2.5 py-1.5 text-[11px] sm:px-3.5 sm:py-2 sm:text-xs font-semibold text-white dark:text-slate-950 transition-colors hover:bg-slate-800 dark:hover:bg-white whitespace-nowrap shrink-0 md:px-4 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
            >
              View Reports
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
