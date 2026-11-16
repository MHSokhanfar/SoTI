import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Bell,
  CalendarClock,
  Download,
  FileSpreadsheet,
  HelpCircle,
  History,
  Keyboard,
  Moon,
  ScrollText,
  Search,
  Server,
  ShieldAlert,
  Sun,
  X,
} from 'lucide-react';
import type { ApiKeyStatus } from '../utils/apiConfig';
import {
  searchGlobalEntries,
  type GlobalSearchEntry,
  type GlobalSearchKind,
  type SearchableTab,
  type VerdictTone,
} from '../utils/globalSearch';
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
  searchEntries: GlobalSearchEntry[];
  searchFocusNonce?: number;
  onSearchFocus?: () => void;
  onOpenShortcuts?: () => void;
  onSelectSearchResult: (entry: GlobalSearchEntry, query: string) => void;
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

const SEARCH_TAB_FILTERS: { id: 'all' | SearchableTab; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'investigate', label: 'Investigate' },
  { id: 'reports', label: 'Reports' },
  { id: 'scheduled', label: 'Scheduled' },
  { id: 'logs', label: 'Logs' },
  { id: 'cli', label: 'CLI & APIs' },
];

function KindIcon({ kind }: { kind: GlobalSearchKind }) {
  switch (kind) {
    case 'report':
      return <FileSpreadsheet className="h-3.5 w-3.5 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />;
    case 'schedule':
      return <CalendarClock className="h-3.5 w-3.5 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />;
    case 'history':
      return <History className="h-3.5 w-3.5 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />;
    case 'log':
      return <ScrollText className="h-3.5 w-3.5 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />;
    case 'provider':
      return <Server className="h-3.5 w-3.5 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />;
    default:
      return <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />;
  }
}

function getToneAccentClass(tone?: VerdictTone): string {
  switch (tone) {
    case 'malicious':
      return 'text-red-700 dark:text-red-400';
    case 'suspicious':
      return 'text-amber-700 dark:text-amber-400';
    case 'clean':
      return 'text-emerald-700 dark:text-emerald-400';
    default:
      return 'text-slate-600 dark:text-slate-400';
  }
}

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
  searchEntries,
  searchFocusNonce = 0,
  onSearchFocus,
  onOpenShortcuts,
  onSelectSearchResult,
}: TopBarProps) {
  const isDark = theme === 'dark';
  const [searchQuery, setSearchQuery] = useState('');
  const [searchOpen, setSearchOpen] = useState(false);
  const [tabFilter, setTabFilter] = useState<'all' | SearchableTab>('all');
  const [activeIndex, setActiveIndex] = useState(0);

  const searchContainerRef = useRef<HTMLDivElement | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const onSearchFocusRef = useRef(onSearchFocus);
  onSearchFocusRef.current = onSearchFocus;
  const lastHandledFocusNonceRef = useRef(searchFocusNonce);

  const filteredResults = useMemo(
    () => searchGlobalEntries(searchEntries, searchQuery, { tabFilter, limit: 14 }),
    [searchEntries, searchQuery, tabFilter],
  );

  useEffect(() => {
    setActiveIndex(0);
  }, [searchQuery, tabFilter, filteredResults.length]);

  useEffect(() => {
    setSearchOpen(false);
    if (document.activeElement === searchInputRef.current) {
      searchInputRef.current?.blur();
    }
  }, [activeTab]);

  useEffect(() => {
    if (searchFocusNonce > 0 && searchFocusNonce !== lastHandledFocusNonceRef.current) {
      lastHandledFocusNonceRef.current = searchFocusNonce;
      searchInputRef.current?.focus();
      setSearchOpen(true);
      onSearchFocusRef.current?.();
    }
  }, [searchFocusNonce]);

  useEffect(() => {
    function handleOutsideMouseDown(event: MouseEvent) {
      if (
        searchContainerRef.current &&
        !searchContainerRef.current.contains(event.target as Node)
      ) {
        setSearchOpen(false);
      }
    }

    function handleEscapeClose(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setSearchOpen(false);
      }
    }

    document.addEventListener('mousedown', handleOutsideMouseDown);
    document.addEventListener('keydown', handleEscapeClose);
    return () => {
      document.removeEventListener('mousedown', handleOutsideMouseDown);
      document.removeEventListener('keydown', handleEscapeClose);
    };
  }, []);

  function handleSelectEntry(entry: GlobalSearchEntry) {
    setSearchOpen(false);
    onSelectSearchResult(entry, searchQuery);
  }

  function handleSearchKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Escape') {
      setSearchOpen(false);
      searchInputRef.current?.blur();
      return;
    }
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setSearchOpen(true);
      setActiveIndex((prev) =>
        filteredResults.length > 0 ? (prev + 1) % filteredResults.length : 0,
      );
      return;
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault();
      setSearchOpen(true);
      setActiveIndex((prev) =>
        filteredResults.length > 0
          ? (prev - 1 + filteredResults.length) % filteredResults.length
          : 0,
      );
      return;
    }
    if (event.key === 'Enter' && filteredResults.length > 0) {
      event.preventDefault();
      const target = filteredResults[activeIndex] || filteredResults[0];
      if (target) {
        handleSelectEntry(target);
      }
    }
  }

  return (
    <header className="relative z-40 md:sticky md:top-0 border-b border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-950/90 backdrop-blur transition-colors">
      <div className="mx-auto flex max-w-[1280px] flex-wrap items-center justify-between gap-y-2 gap-x-2 px-3 py-2.5 sm:px-4 md:flex-nowrap md:gap-3 xl:gap-5 md:px-4 xl:px-6 md:py-3">
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
          className="order-3 flex w-full items-center justify-between gap-2 border-t border-slate-100 dark:border-slate-800 pt-2 md:order-none md:w-auto md:justify-start md:gap-3 xl:gap-5 md:border-t-0 md:pt-0"
        >
          {NAV_ITEMS.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectTab(item.id)}
                className={`relative py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer xl:text-sm focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-red-600 ${
                  isActive
                    ? 'text-slate-950 dark:text-slate-50 after:absolute after:inset-x-0 after:-bottom-[9px] md:after:-bottom-[13px] after:h-0.5 after:bg-red-600'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        <div
          ref={searchContainerRef}
          className="order-2 relative w-full md:order-none md:w-40 lg:w-44 xl:w-60 shrink-0"
        >
          <div className="relative flex items-center">
            <Search
              className="pointer-events-none absolute left-2.5 h-3.5 w-3.5 text-slate-400 dark:text-slate-500"
              aria-hidden="true"
            />
            <input
              ref={searchInputRef}
              type="text"
              inputMode="search"
              autoComplete="off"
              spellCheck={false}
              role="combobox"
              aria-expanded={searchOpen}
              aria-controls="global-search-listbox"
              aria-label="Global search across IOCs, reports, schedules, and logs"
              data-testid="global-search-input"
              value={searchQuery}
              onFocus={() => {
                setSearchOpen(true);
                onSearchFocus?.();
              }}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                if (!searchOpen) setSearchOpen(true);
              }}
              onKeyDown={handleSearchKeyDown}
              placeholder="Search IOCs, reports..."
              className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/80 dark:bg-slate-900 py-1.5 pl-8 pr-8 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 transition-colors focus:border-red-600 focus:bg-white dark:focus:bg-slate-950 focus:outline-none"
            />
            {searchQuery ? (
              <button
                type="button"
                aria-label="Clear global search"
                data-testid="global-search-clear"
                onClick={() => {
                  setSearchQuery('');
                  searchInputRef.current?.focus();
                }}
                className="absolute right-2 rounded p-0.5 text-slate-400 hover:text-slate-700 dark:text-slate-500 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            ) : (
              <kbd className="pointer-events-none hidden xl:inline-flex items-center rounded border border-slate-200 dark:border-slate-700 px-1.5 py-0.5 font-mono text-[10px] text-slate-400 dark:text-slate-500 absolute right-2">
                /
              </kbd>
            )}
          </div>

          {searchOpen && (
            <div
              data-testid="global-search-results"
              className="absolute left-0 right-0 md:left-auto md:right-0 md:w-[460px] lg:w-[520px] top-full mt-2 z-50 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 shadow-xl overflow-hidden"
            >
              <div
                role="tablist"
                aria-label="Filter global search by tab"
                className="flex flex-wrap items-center gap-1 border-b border-slate-100 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60 px-2.5 py-2"
              >
                {SEARCH_TAB_FILTERS.map((tabOpt) => {
                  const active = tabFilter === tabOpt.id;
                  return (
                    <button
                      key={tabOpt.id}
                      type="button"
                      role="tab"
                      aria-selected={active}
                      data-testid={`global-search-filter-${tabOpt.id}`}
                      onClick={() => setTabFilter(tabOpt.id)}
                      className={`rounded-md px-2 py-1 text-[11px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        active
                          ? 'bg-white dark:bg-slate-800 text-slate-950 dark:text-slate-50 shadow-xs'
                          : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                      }`}
                    >
                      {tabOpt.label}
                    </button>
                  );
                })}
              </div>

              {filteredResults.length === 0 ? (
                <div className="px-4 py-6 text-center">
                  <p className="text-xs font-medium text-slate-800 dark:text-slate-200">
                    No matching items found
                  </p>
                  <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                    Try an IP, domain, hash, report filename, schedule name, or log keyword.
                  </p>
                </div>
              ) : (
                <ul
                  id="global-search-listbox"
                  role="listbox"
                  aria-label="Global search results"
                  className="max-h-[340px] overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800"
                >
                  {filteredResults.map((entry, idx) => {
                    const isHighlighted = idx === activeIndex;
                    return (
                      <li key={entry.id} role="option" aria-selected={isHighlighted}>
                        <button
                          type="button"
                          data-testid="global-search-item"
                          data-tab={entry.tab}
                          onMouseEnter={() => setActiveIndex(idx)}
                          onClick={() => handleSelectEntry(entry)}
                          className={`flex w-full items-start gap-2.5 px-3.5 py-2.5 text-left transition-colors cursor-pointer ${
                            isHighlighted
                              ? 'bg-slate-100 dark:bg-slate-800/80'
                              : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                          }`}
                        >
                          <div className="mt-0.5">
                            <KindIcon kind={entry.kind} />
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-baseline justify-between gap-2">
                              <span
                                className={`truncate font-mono text-xs font-semibold ${
                                  entry.kind === 'ioc' || entry.kind === 'report'
                                    ? 'text-slate-950 dark:text-slate-50'
                                    : 'font-sans text-slate-900 dark:text-slate-100'
                                }`}
                              >
                                {entry.title}
                              </span>
                              <span
                                className={`text-[11px] font-medium whitespace-nowrap shrink-0 ${getToneAccentClass(entry.verdictTone)}`}
                              >
                                {entry.tabLabel}
                              </span>
                            </div>
                            <p className="mt-0.5 truncate text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                              {entry.subtitle}
                            </p>
                          </div>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}

              <div className="flex items-center justify-between border-t border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 px-3 py-1.5 text-[11px] text-slate-500 dark:text-slate-400">
                <span>Supports defanged IOCs (e.g. 1[.]2[.]3[.]4)</span>
                <span className="hidden sm:inline font-mono">↑↓ Navigate · Enter Open · Esc Close</span>
              </div>
            </div>
          )}
        </div>

        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
          <button
            type="button"
            onClick={() => onSelectTab('cli')}
            aria-label={`API connection status: ${API_DOT_ITEMS.map(
              (item) => `${item.fullLabel} ${apiStatus[item.id] ? 'valid' : 'invalid'}`,
            ).join(', ')}. Open API settings`}
            className="flex items-center gap-1.5 sm:gap-2.5 py-1 text-[11px] font-medium whitespace-nowrap shrink-0 cursor-pointer rounded focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-red-600"
          >
            {API_DOT_ITEMS.map((item) => {
              const isValid = apiStatus[item.id];
              return (
                <span
                  key={item.id}
                  data-testid={`api-status-dot-${item.id}`}
                  data-status={isValid ? 'valid' : 'invalid'}
                  title={`${item.fullLabel}: ${isValid ? 'Valid' : 'Invalid'}`}
                  className={`inline-flex items-center gap-1 whitespace-nowrap ${
                    isValid ? 'text-slate-700 dark:text-slate-300' : 'text-red-700 dark:text-red-400'
                  }`}
                >
                  <span
                    aria-hidden="true"
                    className={`h-2 w-2 rounded-full shrink-0 ${
                      isValid ? 'bg-emerald-500' : 'bg-red-600 dark:bg-red-500'
                    }`}
                  />
                  <span className="hidden 2xl:inline">{item.fullLabel}</span>
                  <span className="2xl:hidden">{item.shortLabel}</span>
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
            className={`inline-flex items-center justify-center rounded-lg border p-1.5 sm:px-2 sm:py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200 ${
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
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-1.5 sm:px-2 sm:py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-950 dark:hover:text-white whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
          >
            {isDark ? (
              <Sun className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
            ) : (
              <Moon className="h-3.5 w-3.5 text-slate-600" aria-hidden="true" />
            )}
            <span className="hidden 2xl:inline">{isDark ? 'Light' : 'Dark'}</span>
          </button>

          {onOpenShortcuts && (
            <button
              type="button"
              data-testid="shortcuts-modal-button"
              onClick={onOpenShortcuts}
              aria-label="Open keyboard shortcuts guide"
              title="Keyboard shortcuts (?)"
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-1.5 sm:px-2 sm:py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-950 dark:hover:text-white whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
            >
              <Keyboard className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="sr-only">Shortcuts</span>
            </button>
          )}

          <button
            type="button"
            onClick={onOpenHelp}
            aria-label="Open API key documentation help"
            title="API key documentation & help"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-1.5 sm:px-2 sm:py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-950 dark:hover:text-white whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
          >
            <HelpCircle className="h-3.5 w-3.5" aria-hidden="true" />
            <span className="hidden 2xl:inline">Help</span>
          </button>

          {latestReport ? (
            <a
              href={`/api/reports/${encodeURIComponent(latestReport)}?download=1`}
              className="inline-flex items-center gap-1 sm:gap-1.5 rounded-lg bg-red-600 px-2 py-1.5 text-[11px] sm:px-3 sm:py-1.5 sm:text-xs font-semibold text-white transition-colors hover:bg-red-700 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="hidden sm:inline">Export CSV</span>
              <span className="sm:hidden">CSV</span>
            </a>
          ) : (
            <button
              type="button"
              onClick={() => onSelectTab('reports')}
              className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 dark:bg-slate-100 px-2.5 py-1.5 text-[11px] sm:px-3 sm:py-1.5 sm:text-xs font-semibold text-white dark:text-slate-950 transition-colors hover:bg-slate-800 dark:hover:bg-white whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
            >
              Reports
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
