import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Check,
  CheckCircle2,
  ChevronDown,
  ClipboardCopy,
  ClipboardList,
  Clock,
  Copy,
  Download,
  ExternalLink,
  Eye,
  FileJson,
  FilePenLine,
  FileText,
  HelpCircle,
  Layers,
  Link2,
  Mail,
  Printer,
  Radio,
  RefreshCw,
  Save,
  Search,
  Settings2,
  ShieldAlert,
  SlidersHorizontal,
  Sparkles,
  Tag,
  Upload,
  X,
  XCircle,
} from 'lucide-react';
import {
  buildInvestigationCsvFilename,
  preprocessInputForLookup,
  refangInputPreservingUrls,
  serializeResultsToCsv,
  type IndicatorType,
  type LookupResult,
  type SourceSelection,
  type Verdict,
} from '../utils/indicators';
import {
  BUILTIN_EXTRA_IDS,
  EXTRA_PROVIDER_META,
  getAllEnabledProviderIds,
  type ApiSettings,
  type BuiltinExtraSourceId,
} from '../utils/apiConfig';
import {
  IndicatorFileUpload,
  type IndicatorFileSummary,
} from './IndicatorFileUpload';
import { RecentInvestigationsSidebar } from './RecentInvestigationsSidebar';
import { QuickNotesSidebarPanel } from './QuickNotesSidebarPanel';
import { WatchlistSidebarTab } from './WatchlistSidebarTab';
import { IocNetworkGraph } from './IocNetworkGraph';
import { IocEventTimeline } from './IocEventTimeline';
import {
  buildRecentInvestigationEntry,
  clearRecentInvestigations,
  loadRecentInvestigations,
  MAX_INVESTIGATION_NOTES_LENGTH,
  normalizeInvestigationNotes,
  prependRecentInvestigation,
  removeRecentInvestigation,
  renameRecentInvestigation,
  saveRecentInvestigations,
  togglePinRecentInvestigation,
  updateRecentInvestigationNotes,
  type RecentInvestigationEntry,
} from '../utils/investigationHistory';
import { ConfidenceSparkline } from './ConfidenceSparkline';
import {
  addTagToIndicator,
  collectTagsForIndicators,
  getTagsForIndicator,
  getUniqueTagsForIndicators,
  indicatorMatchesTagFilter,
  loadIndicatorTags,
  removeTagFromIndicator,
  saveIndicatorTags,
  SUGGESTED_IOC_TAGS,
  syncRecentInvestigationsTags,
  type IndicatorTagMap,
} from '../utils/iocTags';
import {
  appendConfidenceSnapshot,
  buildConfidenceTrendsMap,
  loadConfidenceSnapshots,
  saveConfidenceSnapshots,
  type ConfidenceSnapshotMap,
} from '../utils/confidenceTrend';
import {
  computeAllIocConfidenceScores,
  loadRiskThreshold,
  normalizeRiskThreshold,
  passesRiskThreshold,
  saveRiskThreshold,
  type ConfidenceRiskLevel,
} from '../utils/riskScoring';
import { formatIocClipboardText, formatIocGroupClipboardText } from '../utils/iocGraph';
import {
  BULK_SAMPLE_BATCH,
  buildUnifiedBatchTable,
  deduplicateBulkInputLines,
  filterUnifiedBatchRows,
  formatIndicatorsAsNewlines,
  formatUnifiedBatchRowClipboard,
  summarizeBulkInputStats,
  type InvestigationAnalysisMode,
} from '../utils/bulkAnalysis';
import {
  computeLivePollDelta,
  extractActiveIndicatorsForPolling,
  formatLiveCountdown,
  formatUtcClockTime,
  LIVE_POLL_INTERVAL_OPTIONS,
  normalizeLivePollInterval,
  type LivePollDeltaSummary,
} from '../utils/livePolling';
import {
  buildExportedSessionPayload,
  buildSessionExportFilename,
  serializeExportedSessionJson,
} from '../utils/sessionExport';
import {
  DEFAULT_QUICK_NOTES_STATE,
  type QuickNotesState,
} from '../utils/quickNotes';
import {
  buildSessionSnapshotUrl,
  formatSnapshotPayloadSize,
  type DecodedSessionSnapshot,
} from '../utils/sessionSnapshot';
import {
  createEmptyNotesAutoSaveState,
  formatAutoSaveUtcTimestamp,
  loadNotesAutoSaveState,
  NOTES_AUTOSAVE_DEBOUNCE_MS,
  NOTES_AUTOSAVE_INTERVAL_MS,
  removeEntryFromAutoSaveDrafts,
  resolveRestoredNotesForEntry,
  saveNotesAutoSaveState,
  upsertNotesAutoSaveDraft,
  type NotesAutoSaveState,
} from '../utils/notesAutoSave';
import {
  buildFormattedResultsTxtReport,
  buildResultsJsonFilename,
  buildResultsTxtFilename,
  buildStructuredResultsJsonPayload,
  CONFIDENCE_SCORE_LEGEND,
  serializeStructuredResultsJson,
} from '../utils/resultsExport';
import {
  buildLastSeenByIndicatorMap,
  extractResultLastSeen,
  sortLookupResults,
  sortUnifiedBatchRows,
  toggleResultsSortState,
  type ResultsSortKey,
  type ResultsSortState,
} from '../utils/resultsTable';
import { copyToClipboard } from '../utils/clipboard';
import { getQuotaWarningProviders } from '../utils/quota';
import {
  addIocToWatchlist,
  countUnreadWatchlistUpdates,
  evaluateWatchlistUpdates,
  isWatchlistIndicator,
  loadSidebarTab,
  loadWatchlist,
  markAllWatchlistUpdatesSeen,
  markWatchlistItemSeen,
  removeIocFromWatchlist,
  saveSidebarTab,
  saveWatchlist,
  toggleIocInWatchlist,
  type SidebarTabId,
  type WatchlistItem,
} from '../utils/watchlist';
import type { EmailAlertRecord } from '../utils/emailAlerts';
import type { ThemeMode } from '../utils/theme';
import type { QuotaState } from '../App';

export interface QuotaSkippedEntry {
  providerId: string;
  name: string;
  used: number;
  limit: number;
  reason: string;
}

export interface InvestigationState {
  rawInput: string;
  source: SourceSelection;
  customSources: string[];
  useCustomSources: boolean;
  includeThreatFox: boolean | null;
  includeUrlscan: boolean | null;
  mode: 'sample' | 'live';
  results: LookupResult[];
  invalidTokens: string[];
  quotaSkipped: QuotaSkippedEntry[];
  lastReportFile: string | null;
  lastRunMode: 'sample' | 'live' | null;
  activeHistoryId: string | null;
  researcherNotes: string;
  analysisMode: InvestigationAnalysisMode;
  livePollingEnabled: boolean;
  livePollIntervalSec: number;
}

export interface InvestigateNavigationTarget {
  indicator?: string;
  historyEntryId?: string;
  nonce: number;
}

interface InvestigateViewProps {
  state: InvestigationState;
  apiSettings: ApiSettings;
  extraKeyStatus?: Record<BuiltinExtraSourceId, boolean>;
  quota: QuotaState;
  theme?: ThemeMode;
  onChangeState: (updater: (prev: InvestigationState) => InvestigationState) => void;
  onQuotaChange: (next: QuotaState) => void;
  onReportCreated: (reportFile: string) => void;
  onOpenApiConfig: () => void;
  onEmailAlertTriggered?: (record: EmailAlertRecord) => void;
  onOpenEmailAlertRules?: () => void;
  navigationTarget?: InvestigateNavigationTarget | null;
  focusInputNonce?: number;
  recentRegionFilter?: string | null;
  onClearRecentRegionFilter?: () => void;
  onRecentHistoryChange?: (entries: RecentInvestigationEntry[]) => void;
  quickNotesState?: QuickNotesState;
  onChangeQuickNotesText?: (nextText: string) => void;
  onClearQuickNotes?: () => void;
  onToggleQuickNotesCollapsed?: () => void;
  loadedSessionSnapshot?: DecodedSessionSnapshot | null;
  sessionSnapshotError?: string | null;
  onDismissSessionSnapshot?: () => void;
  watchlistItems?: WatchlistItem[];
  onToggleWatchIoc?: (
    indicator: string,
    type: IndicatorType,
    verdict?: Verdict | null,
    confidenceScore?: number | null,
  ) => void;
  onAddWatchlistIndicator?: (
    rawInput: string,
    options?: { verdict?: Verdict | null; confidenceScore?: number | null },
  ) => { added: boolean; error?: string };
  onRemoveWatchlistIndicator?: (indicator: string) => void;
  onAcknowledgeWatchlistItem?: (indicator: string) => void;
  onAcknowledgeAllWatchlist?: () => void;
  onEvaluateWatchlistResults?: (results: readonly LookupResult[], checkedAtIso: string) => void;
}

const CORE_LABELS: Record<string, string> = {
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
  alienvault: 'AlienVault OTX',
  shodan: EXTRA_PROVIDER_META.shodan.name,
  threatfox: EXTRA_PROVIDER_META.threatfox.name,
  urlscan: EXTRA_PROVIDER_META.urlscan.name,
};

const SOURCE_OPTIONS: { id: SourceSelection; label: string }[] = [
  { id: 'all', label: 'All Enabled' },
  { id: 'virustotal', label: 'VirusTotal' },
  { id: 'abuseipdb', label: 'AbuseIPDB' },
  { id: 'alienvault', label: 'AlienVault OTX' },
];

const VERDICT_FILTERS: ('All' | Verdict)[] = [
  'All',
  'Malicious',
  'Suspicious',
  'Clean',
  'Unknown',
];

export const SAMPLE_BATCH =
  '1[.]2[.]3[.]4, 8.8.8.8, hxxp://evil[.]com/login, 44d88612fea8a8f36de82e1278abb02f';

function VerdictIndicator({ verdict, status }: { verdict: Verdict; status: LookupResult['status'] }) {
  if (status !== 'ok') {
    const label = status.replace('_', ' ').toUpperCase();
    const colorClass =
      status === 'error'
        ? 'text-red-700 dark:text-red-400'
        : status === 'not_found'
          ? 'text-sky-700 dark:text-sky-400'
          : 'text-slate-500 dark:text-slate-400';
    return (
      <span className={`inline-flex items-center gap-1.5 font-mono text-xs font-medium ${colorClass}`}>
        <XCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span>{label}</span>
      </span>
    );
  }

  switch (verdict) {
    case 'Malicious':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-700 dark:text-red-400">
          <ShieldAlert className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>Malicious</span>
        </span>
      );
    case 'Suspicious':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-700 dark:text-amber-400">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>Suspicious</span>
        </span>
      );
    case 'Clean':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
          <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>Clean</span>
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 dark:text-slate-400">
          <HelpCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>Unknown</span>
        </span>
      );
  }
}

function getConfidenceToneClass(level: ConfidenceRiskLevel): string {
  switch (level) {
    case 'Critical':
      return 'text-red-700 dark:text-red-400';
    case 'High':
      return 'text-orange-700 dark:text-orange-400';
    case 'Medium':
      return 'text-amber-700 dark:text-amber-400';
    case 'Low':
      return 'text-emerald-700 dark:text-emerald-400';
    default:
      return 'text-slate-500 dark:text-slate-400';
  }
}

interface SortableColumnHeaderProps {
  label: string;
  sortKey: ResultsSortKey;
  sortState: ResultsSortState | null;
  onSort: (key: ResultsSortKey) => void;
  align?: 'left' | 'right';
  title?: string;
  className?: string;
}

function SortableColumnHeader({
  label,
  sortKey,
  sortState,
  onSort,
  align = 'left',
  title,
  className = '',
}: SortableColumnHeaderProps) {
  const isActive = sortState?.key === sortKey;
  const ariaSort = isActive
    ? sortState.direction === 'asc'
      ? 'ascending'
      : 'descending'
    : 'none';
  return (
    <th
      aria-sort={ariaSort}
      title={title || `Click to sort by ${label}`}
      className={className}
    >
      <button
        type="button"
        data-testid={`sort-col-${sortKey}`}
        onClick={() => onSort(sortKey)}
        className={`group inline-flex items-center gap-0.5 font-semibold transition-colors whitespace-nowrap select-none cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200 ${
          align === 'right' ? 'justify-end ml-auto' : ''
        } ${
          isActive
            ? 'text-slate-950 dark:text-white'
            : 'text-slate-600 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white'
        }`}
      >
        <span>{label}</span>
        {isActive ? (
          sortState.direction === 'asc' ? (
            <ArrowUp
              className="h-3.5 w-3.5 shrink-0 text-red-600 dark:text-red-400 print:hidden"
              aria-hidden="true"
            />
          ) : (
            <ArrowDown
              className="h-3.5 w-3.5 shrink-0 text-red-600 dark:text-red-400 print:hidden"
              aria-hidden="true"
            />
          )
        ) : (
          <ArrowUpDown
            className="h-3 w-3 shrink-0 opacity-45 group-hover:opacity-100 print:hidden"
            aria-hidden="true"
          />
        )}
      </button>
    </th>
  );
}

export function InvestigateView({
  state,
  apiSettings,
  extraKeyStatus,
  quota,
  theme = 'light',
  onChangeState,
  onQuotaChange,
  onReportCreated,
  onOpenApiConfig,
  onEmailAlertTriggered,
  onOpenEmailAlertRules,
  navigationTarget,
  focusInputNonce = 0,
  recentRegionFilter = null,
  onClearRecentRegionFilter,
  onRecentHistoryChange,
  quickNotesState = DEFAULT_QUICK_NOTES_STATE,
  onChangeQuickNotesText = () => {},
  onClearQuickNotes = () => {},
  onToggleQuickNotesCollapsed = () => {},
  loadedSessionSnapshot = null,
  sessionSnapshotError = null,
  onDismissSessionSnapshot,
  watchlistItems: controlledWatchlistItems,
  onToggleWatchIoc,
  onAddWatchlistIndicator,
  onRemoveWatchlistIndicator,
  onAcknowledgeWatchlistItem,
  onAcknowledgeAllWatchlist,
  onEvaluateWatchlistResults,
}: InvestigateViewProps) {
  const [verdictFilter, setVerdictFilter] = useState<'All' | Verdict>('All');
  const [resultsTagFilter, setResultsTagFilter] = useState<string>('All');
  const [riskThreshold, setRiskThreshold] = useState<number>(() =>
    typeof window !== 'undefined' ? loadRiskThreshold(window.localStorage) : 0,
  );
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [dismissedQuotaSignature, setDismissedQuotaSignature] = useState<string | null>(null);
  const [lastEmailAlert, setLastEmailAlert] = useState<EmailAlertRecord | null>(null);
  const [fileImportSummary, setFileImportSummary] = useState<IndicatorFileSummary | null>(null);
  const [recentHistory, setRecentHistory] = useState<RecentInvestigationEntry[]>(() =>
    typeof window !== 'undefined' ? loadRecentInvestigations(window.localStorage) : [],
  );
  const [indicatorTags, setIndicatorTags] = useState<IndicatorTagMap>(() =>
    typeof window !== 'undefined' ? loadIndicatorTags(window.localStorage) : {},
  );
  const [taggingIndicator, setTaggingIndicator] = useState<string | null>(null);
  const [customTagInput, setCustomTagInput] = useState('');
  const [tableTaggingIndicator, setTableTaggingIndicator] = useState<string | null>(null);
  const [tableCustomTagInput, setTableCustomTagInput] = useState('');
  const [historicalReportRows, setHistoricalReportRows] = useState<Record<string, string>[]>([]);
  const [confidenceSnapshots, setConfidenceSnapshots] = useState<ConfidenceSnapshotMap>(() =>
    typeof window !== 'undefined' ? loadConfidenceSnapshots(window.localStorage) : {},
  );
  const [graphFocusedIndicator, setGraphFocusedIndicator] = useState<string | null>(null);
  const [notesSaveStatus, setNotesSaveStatus] = useState<'idle' | 'saved'>('idle');
  const [notesAutoSave, setNotesAutoSave] = useState<NotesAutoSaveState>(() =>
    typeof window !== 'undefined'
      ? loadNotesAutoSaveState(window.localStorage)
      : createEmptyNotesAutoSaveState(),
  );
  const [bulkTableStyle, setBulkTableStyle] = useState<'unified' | 'detailed'>('unified');
  const [tableSort, setTableSort] = useState<ResultsSortState | null>(null);
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const [sessionExportedFile, setSessionExportedFile] = useState<string | null>(null);
  const [snapshotModalOpen, setSnapshotModalOpen] = useState(false);
  const [snapshotUrl, setSnapshotUrl] = useState<string>('');
  const [snapshotSizeLabel, setSnapshotSizeLabel] = useState<string>('');
  const [snapshotTruncated, setSnapshotTruncated] = useState(false);
  const [snapshotCopied, setSnapshotCopied] = useState(false);
  const [appliedSnapshotCreatedAt, setAppliedSnapshotCreatedAt] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isBackgroundPolling, setIsBackgroundPolling] = useState(false);
  const [nextPollAtMs, setNextPollAtMs] = useState<number | null>(null);
  const [nowTickMs, setNowTickMs] = useState<number>(() => Date.now());
  const [lastPollDelta, setLastPollDelta] = useState<LivePollDeltaSummary | null>(null);
  const [livePollError, setLivePollError] = useState<string | null>(null);
  const [sidebarTab, setSidebarTab] = useState<SidebarTabId>(() =>
    typeof window !== 'undefined' ? loadSidebarTab(window.localStorage) : 'recent',
  );
  const [internalWatchlistItems, setInternalWatchlistItems] = useState<WatchlistItem[]>(() =>
    controlledWatchlistItems ??
    (typeof window !== 'undefined' ? loadWatchlist(window.localStorage) : []),
  );
  const watchlistItems = controlledWatchlistItems ?? internalWatchlistItems;
  const [checkingWatchlist, setCheckingWatchlist] = useState(false);
  const [watchlistLastCheckedUtc, setWatchlistLastCheckedUtc] = useState<string | null>(null);
  const copyTimerRef = useRef<number | null>(null);
  const sessionExportTimerRef = useRef<number | null>(null);
  const exportDropdownRef = useRef<HTMLDivElement | null>(null);
  const csvFileInputRef = useRef<HTMLInputElement | null>(null);
  const iocInputRef = useRef<HTMLTextAreaElement | null>(null);
  const isBackgroundPollingRef = useRef(false);
  const latestStateRef = useRef(state);
  latestStateRef.current = state;
  const notesAutoSaveRef = useRef(notesAutoSave);
  notesAutoSaveRef.current = notesAutoSave;
  const runEnrichmentRef = useRef<
    (override?: {
      rawInput: string;
      source: SourceSelection;
      customSources: string[];
      useCustomSources: boolean;
      includeThreatFox: boolean | null;
      includeUrlscan: boolean | null;
      mode: 'sample' | 'live';
      analysisMode?: InvestigationAnalysisMode;
      preserveNotes?: string;
      backgroundPoll?: boolean;
    }) => Promise<void>
  >(async () => {});
  const activeHistoryId = state.activeHistoryId;

  useEffect(() => {
    if (focusInputNonce > 0) {
      iocInputRef.current?.focus();
    }
  }, [focusInputNonce]);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      if (sessionExportTimerRef.current !== null) {
        window.clearTimeout(sessionExportTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (!exportMenuOpen) return;
    function handleOutside(e: MouseEvent) {
      if (
        exportDropdownRef.current &&
        !exportDropdownRef.current.contains(e.target as Node)
      ) {
        setExportMenuOpen(false);
      }
    }
    function handleEsc(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setExportMenuOpen(false);
      }
    }
    document.addEventListener('mousedown', handleOutside);
    document.addEventListener('keydown', handleEsc);
    return () => {
      document.removeEventListener('mousedown', handleOutside);
      document.removeEventListener('keydown', handleEsc);
    };
  }, [exportMenuOpen]);

  useEffect(() => {
    if (!loadedSessionSnapshot || appliedSnapshotCreatedAt === loadedSessionSnapshot.createdAt) {
      return;
    }
    setAppliedSnapshotCreatedAt(loadedSessionSnapshot.createdAt);
    setVerdictFilter(loadedSessionSnapshot.verdictFilter);
    setRiskThreshold(loadedSessionSnapshot.riskThreshold);
    setTableSort(loadedSessionSnapshot.tableSort);
    if (Object.keys(loadedSessionSnapshot.indicatorTags).length > 0) {
      setIndicatorTags((prev) => ({
        ...prev,
        ...loadedSessionSnapshot.indicatorTags,
      }));
    }
  }, [loadedSessionSnapshot, appliedSnapshotCreatedAt]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      saveRecentInvestigations(window.localStorage, recentHistory);
    }
    onRecentHistoryChange?.(recentHistory);
  }, [recentHistory, onRecentHistoryChange]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      saveIndicatorTags(window.localStorage, indicatorTags);
    }
  }, [indicatorTags]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      saveConfidenceSnapshots(window.localStorage, confidenceSnapshots);
    }
  }, [confidenceSnapshots]);

  useEffect(() => {
    if (controlledWatchlistItems !== undefined || typeof window === 'undefined') {
      return;
    }
    saveWatchlist(window.localStorage, internalWatchlistItems);
  }, [controlledWatchlistItems, internalWatchlistItems]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      saveSidebarTab(window.localStorage, sidebarTab);
    }
  }, [sidebarTab]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      saveRiskThreshold(window.localStorage, riskThreshold);
    }
  }, [riskThreshold]);

  useEffect(() => {
    if (recentRegionFilter && recentRegionFilter.trim().toLowerCase() !== 'all') {
      setSidebarTab('recent');
    }
  }, [recentRegionFilter]);

  useEffect(() => {
    let cancelled = false;
    async function fetchHistoricalRows() {
      try {
        const res = await fetch('/api/reports/all-rows');
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled && Array.isArray(data?.rows)) {
          setHistoricalReportRows(data.rows);
        }
      } catch {
        // Non-blocking fallback when offline or server unavailable
      }
    }
    void fetchHistoricalRows();
    return () => {
      cancelled = true;
    };
  }, [state.lastReportFile]);

  useEffect(() => {
    if (!navigationTarget) return;
    setVerdictFilter('All');
    setResultsTagFilter('All');
    setGraphFocusedIndicator(null);
    if (navigationTarget.historyEntryId) {
      const match = recentHistory.find((item) => item.id === navigationTarget.historyEntryId);
      if (match) {
        handleViewRecentDetails(match);
        return;
      }
    }
    if (navigationTarget.indicator) {
      const inCurrent = state.results.some(
        (r) => r.indicator.toLowerCase() === navigationTarget.indicator?.toLowerCase(),
      );
      if (!inCurrent) {
        onChangeState((prev) => ({ ...prev, rawInput: navigationTarget.indicator || prev.rawInput }));
      } else {
        setGraphFocusedIndicator(navigationTarget.indicator);
      }
    }
  }, [navigationTarget?.nonce]);

  const preprocessedInput = useMemo(
    () => preprocessInputForLookup(state.rawInput),
    [state.rawInput],
  );
  const parsedPreview = preprocessedInput.parsed;
  const enabledSourceIds = useMemo(() => getAllEnabledProviderIds(apiSettings), [apiSettings]);

  const warningProviders = useMemo(
    () => getQuotaWarningProviders(quota.providers, 80, enabledSourceIds),
    [quota.providers, enabledSourceIds],
  );
  const warningSignature = useMemo(
    () => warningProviders.map((p) => `${p.providerId}:${p.used}/${p.limit}`).join('|'),
    [warningProviders],
  );
  const showThresholdWarning =
    warningProviders.length > 0 && dismissedQuotaSignature !== warningSignature;

  const allKnownProviders = useMemo(() => {
    const base: { id: string; name: string; enabled: boolean }[] = [
      { id: 'virustotal', name: 'VirusTotal', enabled: apiSettings.providers.virustotal.enabled },
      { id: 'abuseipdb', name: 'AbuseIPDB', enabled: apiSettings.providers.abuseipdb.enabled },
      { id: 'alienvault', name: 'AlienVault OTX', enabled: apiSettings.providers.alienvault.enabled },
      ...BUILTIN_EXTRA_IDS.map((id) => ({
        id,
        name: EXTRA_PROVIDER_META[id].name,
        enabled: Boolean(apiSettings.extraProviders?.[id]?.enabled),
      })),
      ...(apiSettings.customProviders || []).map((cp) => ({
        id: cp.id,
        name: cp.name,
        enabled: cp.enabled,
      })),
    ];
    return base;
  }, [apiSettings]);

  const providerNameMap = useMemo(() => {
    const map: Record<string, string> = { ...CORE_LABELS };
    for (const cp of apiSettings.customProviders || []) {
      map[cp.id] = cp.name;
    }
    return map;
  }, [apiSettings]);

  const quotaById = useMemo(() => {
    const map = new Map(quota.providers.map((p) => [p.providerId, p]));
    return map;
  }, [quota.providers]);

  const threatfoxChecked =
    state.includeThreatFox ?? Boolean(apiSettings.extraProviders?.threatfox?.enabled);
  const urlscanChecked =
    state.includeUrlscan ?? Boolean(apiSettings.extraProviders?.urlscan?.enabled);

  const isBulkMode = state.analysisMode === 'bulk';

  const bulkStats = useMemo(
    () => summarizeBulkInputStats(state.rawInput),
    [state.rawInput],
  );

  const livePollIntervalSec = normalizeLivePollInterval(state.livePollIntervalSec);
  const activePollIndicators = useMemo(
    () => extractActiveIndicatorsForPolling(state.results, state.rawInput),
    [state.results, state.rawInput],
  );
  const remainingPollSeconds = useMemo(() => {
    if (!state.livePollingEnabled || !nextPollAtMs) return livePollIntervalSec;
    return Math.max(0, (nextPollAtMs - nowTickMs) / 1000);
  }, [state.livePollingEnabled, nextPollAtMs, nowTickMs, livePollIntervalSec]);

  const effectiveSources: string[] = useMemo(() => {
    if (isBulkMode) {
      const base = [...enabledSourceIds];
      if (state.includeThreatFox === true && !base.includes('threatfox')) base.push('threatfox');
      if (state.includeUrlscan === true && !base.includes('urlscan')) base.push('urlscan');
      return base;
    }
    if (state.useCustomSources) {
      return state.customSources;
    }
    const base =
      state.source === 'all'
        ? enabledSourceIds.filter((id) => id !== 'threatfox' && id !== 'urlscan')
        : [state.source];
    if (threatfoxChecked && !base.includes('threatfox')) {
      base.push('threatfox');
    }
    if (urlscanChecked && !base.includes('urlscan')) {
      base.push('urlscan');
    }
    return base;
  }, [
    isBulkMode,
    state.useCustomSources,
    state.customSources,
    state.source,
    state.includeThreatFox,
    state.includeUrlscan,
    enabledSourceIds,
    threatfoxChecked,
    urlscanChecked,
  ]);

  const visibleQuotaSnapshots = useMemo(() => {
    const ids = new Set([...enabledSourceIds, ...effectiveSources]);
    for (const q of quota.providers) {
      if (q.used > 0 || q.exhausted) ids.add(q.providerId);
    }
    return quota.providers.filter((q) => ids.has(q.providerId));
  }, [quota.providers, enabledSourceIds, effectiveSources]);

  function toggleCustomSource(id: string) {
    onChangeState((prev) => {
      const exists = prev.customSources.includes(id);
      const next = exists
        ? prev.customSources.filter((s) => s !== id)
        : [...prev.customSources, id];
      return {
        ...prev,
        useCustomSources: true,
        customSources: next,
      };
    });
  }

  function handleFileExtracted(summary: IndicatorFileSummary) {
    setErrorMsg(null);
    onChangeState((prev) => ({
      ...prev,
      rawInput: summary.parsed.rawText,
      invalidTokens: [],
    }));
    setFileImportSummary(summary);
  }

  function handleFileError(message: string) {
    setFileImportSummary(null);
    setErrorMsg(message);
  }

  const resultIndicatorsList = useMemo(
    () => Array.from(new Set(state.results.map((r) => r.indicator))),
    [state.results],
  );

  const availableResultTags = useMemo(
    () => getUniqueTagsForIndicators(indicatorTags, resultIndicatorsList),
    [indicatorTags, resultIndicatorsList],
  );

  useEffect(() => {
    if (
      resultsTagFilter !== 'All' &&
      !availableResultTags.some((t) => t.toLowerCase() === resultsTagFilter.toLowerCase())
    ) {
      setResultsTagFilter('All');
    }
  }, [availableResultTags, resultsTagFilter]);

  const confidenceByIndicator = useMemo(
    () => computeAllIocConfidenceScores(state.results),
    [state.results],
  );

  const filteredResults = useMemo(() => {
    return state.results.filter((r) => {
      if (verdictFilter !== 'All' && !(r.status === 'ok' && r.verdict === verdictFilter)) {
        return false;
      }
      if (resultsTagFilter !== 'All' && !indicatorMatchesTagFilter(indicatorTags, r.indicator, resultsTagFilter)) {
        return false;
      }
      if (riskThreshold > 0) {
        const conf = confidenceByIndicator.get(r.indicator.trim().toLowerCase());
        if (!passesRiskThreshold(conf?.confidenceScore, riskThreshold)) {
          return false;
        }
      }
      return true;
    });
  }, [state.results, verdictFilter, resultsTagFilter, indicatorTags, riskThreshold, confidenceByIndicator]);

  const sortedResults = useMemo(
    () => sortLookupResults(filteredResults, tableSort, confidenceByIndicator),
    [filteredResults, tableSort, confidenceByIndicator],
  );

  const lastSeenByIndicator = useMemo(
    () => buildLastSeenByIndicatorMap(state.results),
    [state.results],
  );

  const riskHiddenIndicatorCount = useMemo(() => {
    if (riskThreshold <= 0 || state.results.length === 0) return 0;
    const seen = new Set<string>();
    let hidden = 0;
    for (const r of state.results) {
      const key = r.indicator.trim().toLowerCase();
      if (!key || seen.has(key)) continue;
      seen.add(key);
      const conf = confidenceByIndicator.get(key);
      if (!passesRiskThreshold(conf?.confidenceScore, riskThreshold)) {
        hidden += 1;
      }
    }
    return hidden;
  }, [riskThreshold, state.results, confidenceByIndicator]);

  const overallVerdictByIndicator = useMemo(() => {
    const map = new Map<string, Verdict>();
    const rank: Record<Verdict, number> = {
      Malicious: 4,
      Suspicious: 3,
      Clean: 2,
      Unknown: 1,
    };
    for (const r of state.results) {
      if (r.status !== 'ok') continue;
      const key = r.indicator.trim().toLowerCase();
      const prev = map.get(key);
      if (!prev || rank[r.verdict] > rank[prev]) {
        map.set(key, r.verdict);
      }
    }
    return map;
  }, [state.results]);

  const unreadWatchlistCount = useMemo(
    () => countUnreadWatchlistUpdates(watchlistItems),
    [watchlistItems],
  );

  const confidenceTrends = useMemo(
    () =>
      buildConfidenceTrendsMap({
        reportRows: historicalReportRows,
        recentHistory,
        liveSnapshots: confidenceSnapshots,
        currentResults: state.results,
      }),
    [historicalReportRows, recentHistory, confidenceSnapshots, state.results],
  );

  const groupedByIndicator = useMemo(() => {
    const groups = new Map<string, { indicator: string; type: string; items: LookupResult[] }>();
    for (const r of filteredResults) {
      const existing = groups.get(r.indicator);
      if (existing) {
        existing.items.push(r);
      } else {
        groups.set(r.indicator, { indicator: r.indicator, type: r.type, items: [r] });
      }
    }
    return Array.from(groups.values());
  }, [filteredResults]);

  const unifiedBatchTable = useMemo(
    () => buildUnifiedBatchTable(state.results, indicatorTags),
    [state.results, indicatorTags],
  );

  const filteredUnifiedBatchRows = useMemo(() => {
    const byVerdict = filterUnifiedBatchRows(unifiedBatchTable.rows, verdictFilter);
    return byVerdict.filter((row) => {
      if (
        resultsTagFilter !== 'All' &&
        !indicatorMatchesTagFilter(indicatorTags, row.indicator, resultsTagFilter)
      ) {
        return false;
      }
      if (riskThreshold > 0 && !passesRiskThreshold(row.confidenceScore, riskThreshold)) {
        return false;
      }
      return true;
    });
  }, [unifiedBatchTable.rows, verdictFilter, resultsTagFilter, indicatorTags, riskThreshold]);

  const sortedUnifiedBatchRows = useMemo(
    () => sortUnifiedBatchRows(filteredUnifiedBatchRows, tableSort, lastSeenByIndicator),
    [filteredUnifiedBatchRows, tableSort, lastSeenByIndicator],
  );

  const exportableVisibleResults = useMemo(() => {
    if (!isBulkMode || bulkTableStyle !== 'unified') {
      return sortedResults;
    }
    const orderIndex = new Map<string, number>();
    sortedUnifiedBatchRows.forEach((row, idx) => {
      orderIndex.set(row.indicator.trim().toLowerCase(), idx);
    });
    const allowed = new Set(orderIndex.keys());
    const matching = sortedResults.filter((r) => allowed.has(r.indicator.trim().toLowerCase()));
    return [...matching].sort((a, b) => {
      const idxA = orderIndex.get(a.indicator.trim().toLowerCase()) ?? Number.MAX_SAFE_INTEGER;
      const idxB = orderIndex.get(b.indicator.trim().toLowerCase()) ?? Number.MAX_SAFE_INTEGER;
      return idxA - idxB;
    });
  }, [isBulkMode, bulkTableStyle, sortedResults, sortedUnifiedBatchRows]);

  function handleToggleTableSort(key: ResultsSortKey) {
    setTableSort((prev) => toggleResultsSortState(prev, key));
  }

  function handleAddTag(indicator: string, rawTag: string) {
    setIndicatorTags((prev) => {
      const next = addTagToIndicator(prev, indicator, rawTag);
      if (next !== prev) {
        setRecentHistory((histPrev) => syncRecentInvestigationsTags(histPrev, next));
      }
      return next;
    });
  }

  function handleRemoveTag(indicator: string, tag: string) {
    setIndicatorTags((prev) => {
      const next = removeTagFromIndicator(prev, indicator, tag);
      if (next !== prev) {
        setRecentHistory((histPrev) => syncRecentInvestigationsTags(histPrev, next));
      }
      return next;
    });
  }

  function handleToggleWatchIoc(
    indicator: string,
    type: IndicatorType,
    verdict?: Verdict | null,
    confidenceScore?: number | null,
  ) {
    if (onToggleWatchIoc) {
      onToggleWatchIoc(indicator, type, verdict, confidenceScore);
      return;
    }
    setInternalWatchlistItems((prev) =>
      toggleIocInWatchlist(prev, {
        indicator,
        type,
        verdict: verdict ?? null,
        confidenceScore: confidenceScore ?? null,
      }).next,
    );
  }

  function handleAddToWatchlistFromSidebar(rawInput: string): { added: boolean; error?: string } {
    const normalizedKey = rawInput.trim().toLowerCase();
    const conf = confidenceByIndicator.get(normalizedKey);
    const verdict = overallVerdictByIndicator.get(normalizedKey) ?? null;
    if (onAddWatchlistIndicator) {
      return onAddWatchlistIndicator(rawInput, {
        verdict,
        confidenceScore: conf?.confidenceScore ?? null,
      });
    }
    const existing = watchlistItems.find(
      (item) => item.indicator.trim().toLowerCase() === normalizedKey,
    );
    if (existing) {
      return { added: false, error: 'Indicator is already monitored on your Watchlist.' };
    }
    const outcome = addIocToWatchlist(watchlistItems, {
      indicator: rawInput,
      verdict,
      confidenceScore: conf?.confidenceScore ?? null,
    });
    if (!outcome.added) {
      if (outcome.invalid.length > 0) {
        return { added: false, error: `Unsupported indicator format: ${outcome.invalid[0]}` };
      }
      return { added: false, error: 'Indicator is already monitored or invalid.' };
    }
    setInternalWatchlistItems(outcome.next);
    return { added: true };
  }

  function handleRemoveFromWatchlist(indicator: string) {
    if (onRemoveWatchlistIndicator) {
      onRemoveWatchlistIndicator(indicator);
      return;
    }
    setInternalWatchlistItems((prev) => removeIocFromWatchlist(prev, indicator));
  }

  function handleAcknowledgeWatchlistItem(indicator: string) {
    if (onAcknowledgeWatchlistItem) {
      onAcknowledgeWatchlistItem(indicator);
      return;
    }
    setInternalWatchlistItems((prev) => markWatchlistItemSeen(prev, indicator));
  }

  function handleAcknowledgeAllWatchlist() {
    if (onAcknowledgeAllWatchlist) {
      onAcknowledgeAllWatchlist();
      return;
    }
    setInternalWatchlistItems((prev) => markAllWatchlistUpdatesSeen(prev));
  }

  function handleInspectFromWatchlist(indicator: string) {
    handleAcknowledgeWatchlistItem(indicator);
    setErrorMsg(null);
    const matchesCurrent = state.results.some(
      (r) => r.indicator.trim().toLowerCase() === indicator.trim().toLowerCase(),
    );
    if (matchesCurrent) {
      setGraphFocusedIndicator(indicator);
      return;
    }
    onChangeState((prev) => ({
      ...prev,
      rawInput: indicator,
      analysisMode: 'standard',
    }));
    window.requestAnimationFrame(() => {
      iocInputRef.current?.focus();
    });
  }

  async function handleCheckWatchlistUpdates() {
    if (checkingWatchlist || watchlistItems.length === 0) return;
    setCheckingWatchlist(true);
    try {
      const indicatorsText = watchlistItems.map((item) => item.indicator).join('\n');
      const targetSources =
        enabledSourceIds.length > 0
          ? enabledSourceIds
          : ['virustotal', 'abuseipdb', 'alienvault'];
      const resp = await fetch('/api/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          raw: indicatorsText,
          source: 'all',
          sources: targetSources,
          mode: state.mode,
          parallel: true,
          backgroundPoll: true,
        }),
      });
      if (!resp.ok) return;
      const data = await resp.json();
      const fetchedResults: LookupResult[] = Array.isArray(data?.results) ? data.results : [];
      const checkedIso = new Date().toISOString();
      if (fetchedResults.length > 0) {
        if (onEvaluateWatchlistResults) {
          onEvaluateWatchlistResults(fetchedResults, checkedIso);
        } else {
          setInternalWatchlistItems((prev) =>
            evaluateWatchlistUpdates(prev, fetchedResults, checkedIso).next,
          );
        }
        setConfidenceSnapshots((prevSnaps) =>
          appendConfidenceSnapshot(prevSnaps, fetchedResults, checkedIso, 'live-poll'),
        );
      }
      setWatchlistLastCheckedUtc(formatUtcClockTime(Date.parse(checkedIso)));
      if (data.quota?.date && Array.isArray(data.quota?.providers)) {
        onQuotaChange(data.quota);
      }
      if (data.emailAlert?.triggered && data.emailAlert?.record) {
        setLastEmailAlert(data.emailAlert.record);
        onEmailAlertTriggered?.(data.emailAlert.record);
      }
    } catch {
      // Non-blocking background check error
    } finally {
      setCheckingWatchlist(false);
    }
  }

  const activeHistoryEntry = useMemo(
    () => (activeHistoryId ? recentHistory.find((e) => e.id === activeHistoryId) ?? null : null),
    [activeHistoryId, recentHistory],
  );

  const normalizedDraftNotes = normalizeInvestigationNotes(state.researcherNotes);
  const normalizedSavedNotes = normalizeInvestigationNotes(activeHistoryEntry?.notes);
  const normalizedAutoSavedDraft = normalizeInvestigationNotes(
    activeHistoryId
      ? notesAutoSave.entryDrafts[activeHistoryId]?.notes ?? notesAutoSave.draftNotes
      : notesAutoSave.draftNotes,
  );
  const hasPendingAutoSave =
    normalizedDraftNotes !== normalizedAutoSavedDraft ||
    (activeHistoryEntry !== null && normalizedDraftNotes !== normalizedSavedNotes);
  const hasUnsavedNotes = hasPendingAutoSave;

  const lastAutoSavedTimeLabel = useMemo(() => {
    const entryIso = activeHistoryId ? notesAutoSave.entryDrafts[activeHistoryId]?.updatedAt : null;
    return formatAutoSaveUtcTimestamp(entryIso || notesAutoSave.draftUpdatedAt || activeHistoryEntry?.notesUpdatedAt);
  }, [activeHistoryId, notesAutoSave, activeHistoryEntry?.notesUpdatedAt]);

  function persistNotesToHistory(targetEntryId: string | null, rawNotes: string) {
    const now = new Date();
    const nextAutoSave = upsertNotesAutoSaveDraft(notesAutoSaveRef.current, {
      entryId: targetEntryId,
      notes: rawNotes,
      now,
    });
    notesAutoSaveRef.current = nextAutoSave;
    setNotesAutoSave(nextAutoSave);
    if (typeof window !== 'undefined') {
      saveNotesAutoSaveState(window.localStorage, nextAutoSave);
    }
    if (targetEntryId) {
      setRecentHistory((prev) => updateRecentInvestigationNotes(prev, targetEntryId, rawNotes, now));
    }
    setNotesSaveStatus('saved');
  }

  const flushNotesAutoSaveRef = useRef<() => void>(() => {});
  flushNotesAutoSaveRef.current = () => {
    const cur = latestStateRef.current;
    persistNotesToHistory(cur.activeHistoryId, cur.researcherNotes);
  };

  // Fast debounced auto-save after analyst pauses typing
  useEffect(() => {
    if (!hasPendingAutoSave) return;
    const timer = window.setTimeout(() => {
      flushNotesAutoSaveRef.current();
    }, NOTES_AUTOSAVE_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [hasPendingAutoSave, state.researcherNotes, activeHistoryId]);

  // Periodic background auto-save interval (persists findings every 3s even during continuous editing)
  useEffect(() => {
    const interval = window.setInterval(() => {
      const cur = latestStateRef.current;
      const draftNorm = normalizeInvestigationNotes(cur.researcherNotes);
      const savedNorm = normalizeInvestigationNotes(
        cur.activeHistoryId
          ? notesAutoSaveRef.current.entryDrafts[cur.activeHistoryId]?.notes ??
              notesAutoSaveRef.current.draftNotes
          : notesAutoSaveRef.current.draftNotes,
      );
      if (draftNorm !== savedNorm) {
        flushNotesAutoSaveRef.current();
      }
    }, NOTES_AUTOSAVE_INTERVAL_MS);

    const handlePageHide = () => {
      const cur = latestStateRef.current;
      if (normalizeInvestigationNotes(cur.researcherNotes).length > 0) {
        const nextAuto = upsertNotesAutoSaveDraft(notesAutoSaveRef.current, {
          entryId: cur.activeHistoryId,
          notes: cur.researcherNotes,
        });
        saveNotesAutoSaveState(window.localStorage, nextAuto);
      }
    };

    window.addEventListener('beforeunload', handlePageHide);
    window.addEventListener('pagehide', handlePageHide);
    return () => {
      window.clearInterval(interval);
      window.removeEventListener('beforeunload', handlePageHide);
      window.removeEventListener('pagehide', handlePageHide);
    };
  }, []);

  async function runEnrichment(override?: {
    rawInput: string;
    source: SourceSelection;
    customSources: string[];
    useCustomSources: boolean;
    includeThreatFox: boolean | null;
    includeUrlscan: boolean | null;
    mode: 'sample' | 'live';
    analysisMode?: InvestigationAnalysisMode;
    preserveNotes?: string;
    backgroundPoll?: boolean;
  }) {
    const isBackground = Boolean(override?.backgroundPoll);
    if (isBackground && (isBackgroundPollingRef.current || loading)) {
      return;
    }

    if (!isBackground) {
      setErrorMsg(null);
      setLastEmailAlert(null);
    }
    setLivePollError(null);

    const targetRawInput = override ? override.rawInput : state.rawInput;
    const targetAnalysisMode: InvestigationAnalysisMode =
      override?.analysisMode ?? state.analysisMode;
    const targetIsBulk = targetAnalysisMode === 'bulk';
    const targetSource = targetIsBulk ? 'all' : (override ? override.source : state.source);
    const targetCustomSources = override ? override.customSources : state.customSources;
    const targetUseCustomSources = targetIsBulk
      ? false
      : override
        ? override.useCustomSources
        : state.useCustomSources;
    const targetIncludeThreatFox = override ? override.includeThreatFox : state.includeThreatFox;
    const targetIncludeUrlscan = override ? override.includeUrlscan : state.includeUrlscan;
    const targetMode = override ? override.mode : state.mode;

    const targetTfActive =
      targetIncludeThreatFox ?? Boolean(apiSettings.extraProviders?.threatfox?.enabled);
    const targetUrlscanActive =
      targetIncludeUrlscan ?? Boolean(apiSettings.extraProviders?.urlscan?.enabled);

    const targetEffectiveSources = (() => {
      if (targetIsBulk) {
        const base = [...enabledSourceIds];
        if (targetIncludeThreatFox === true && !base.includes('threatfox')) base.push('threatfox');
        if (targetIncludeUrlscan === true && !base.includes('urlscan')) base.push('urlscan');
        return base;
      }
      if (targetUseCustomSources) return targetCustomSources;
      const base =
        targetSource === 'all'
          ? enabledSourceIds.filter((id) => id !== 'threatfox' && id !== 'urlscan')
          : [targetSource];
      if (targetTfActive && !base.includes('threatfox')) base.push('threatfox');
      if (targetUrlscanActive && !base.includes('urlscan')) base.push('urlscan');
      return base;
    })();

    if (!targetRawInput.trim()) {
      if (!isBackground) {
        setErrorMsg('Enter at least one IP, domain, URL, or file hash (MD5, SHA1, or SHA256).');
      }
      return;
    }

    if (targetEffectiveSources.length === 0) {
      if (!isBackground) {
        setErrorMsg(
          targetIsBulk
            ? 'No intelligence APIs are enabled. Enable at least one API in CLI & APIs settings.'
            : 'Select at least one intelligence API to run enrichment.',
        );
      }
      return;
    }

    // Strip common defang patterns before API dispatch while preserving full URLs for URLScan
    const targetPreprocessed = preprocessInputForLookup(targetRawInput);
    const dispatchRaw =
      refangInputPreservingUrls(targetRawInput) ||
      targetPreprocessed.apiReadyInput ||
      targetRawInput.trim();

    const prevSnapshotResults = latestStateRef.current.results;

    if (isBackground) {
      isBackgroundPollingRef.current = true;
      setIsBackgroundPolling(true);
    } else {
      setLoading(true);
    }
    try {
      const payload: Record<string, unknown> = {
        raw: dispatchRaw,
        source: targetSource,
        sources: targetEffectiveSources,
        mode: targetMode,
        parallel: targetIsBulk || targetPreprocessed.validIndicators.length > 1,
        backgroundPoll: isBackground,
      };
      const resp = await fetch('/api/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      if (!resp.ok) {
        if (isBackground) {
          setLivePollError(data.error || 'Background refresh failed.');
        } else {
          setErrorMsg(data.error || 'Enrichment lookup failed.');
          if (Array.isArray(data.invalid)) {
            onChangeState((prev) => ({ ...prev, invalidTokens: data.invalid }));
          }
        }
        return;
      }

      const nextResults: LookupResult[] = data.results || [];
      const nextInvalid: string[] = data.invalid || [];
      const nextQuotaSkipped: QuotaSkippedEntry[] = Array.isArray(data.quotaSkipped)
        ? data.quotaSkipped
        : [];
      const nextReportFile: string | null = data.reportFile || null;
      const resolvedMode: 'sample' | 'live' = data.mode || targetMode;

      const delta = computeLivePollDelta(prevSnapshotResults, nextResults);
      setLastPollDelta(delta);
      setConfidenceSnapshots((prevSnaps) =>
        appendConfidenceSnapshot(
          prevSnaps,
          nextResults,
          delta.checkedAtIso,
          isBackground ? 'live-poll' : 'history',
        ),
      );
      if (onEvaluateWatchlistResults) {
        onEvaluateWatchlistResults(nextResults, delta.checkedAtIso);
      } else {
        setInternalWatchlistItems((prev) =>
          evaluateWatchlistUpdates(prev, nextResults, delta.checkedAtIso).next,
        );
      }

      if (isBackground) {
        onChangeState((prev) => ({
          ...prev,
          results: nextResults,
          invalidTokens: nextInvalid,
          quotaSkipped: nextQuotaSkipped,
          lastRunMode: resolvedMode,
        }));
        if (latestStateRef.current.activeHistoryId) {
          const targetId = latestStateRef.current.activeHistoryId;
          setRecentHistory((prev) =>
            prev.map((item) =>
              item.id === targetId
                ? {
                    ...item,
                    timestamp: delta.checkedAtIso,
                    results: nextResults,
                    quotaSkipped: nextQuotaSkipped,
                  }
                : item,
            ),
          );
        }
        if (data.quota?.date && Array.isArray(data.quota?.providers)) {
          onQuotaChange(data.quota);
        }
        if (data.emailAlert?.triggered && data.emailAlert?.record) {
          setLastEmailAlert(data.emailAlert.record);
          onEmailAlertTriggered?.(data.emailAlert.record);
        }
        if (latestStateRef.current.livePollingEnabled) {
          const nextSec = normalizeLivePollInterval(latestStateRef.current.livePollIntervalSec);
          setNextPollAtMs(Date.now() + nextSec * 1000);
        }
        return;
      }

      const initialRunNotes =
        override?.preserveNotes !== undefined
          ? override.preserveNotes
          : state.activeHistoryId === null
            ? state.researcherNotes
            : '';

      const batchIndicators = targetPreprocessed.validIndicators.map((v) => v.cleaned);
      const entry = buildRecentInvestigationEntry({
        rawInput: targetRawInput,
        normalizedInput: targetPreprocessed.apiReadyInput || dispatchRaw,
        indicators: batchIndicators,
        source: targetSource,
        customSources: targetCustomSources,
        useCustomSources: targetUseCustomSources,
        includeThreatFox: targetIncludeThreatFox,
        includeUrlscan: targetIncludeUrlscan,
        sourceLabels: targetEffectiveSources.map((id) => providerNameMap[id] || id),
        mode: resolvedMode,
        results: nextResults,
        invalidTokens: nextInvalid,
        quotaSkipped: nextQuotaSkipped,
        reportFile: nextReportFile,
        tags: collectTagsForIndicators(indicatorTags, batchIndicators),
        notes: initialRunNotes,
      });

      onChangeState((prev) => ({
        ...prev,
        rawInput: targetRawInput,
        source: targetSource,
        customSources: targetCustomSources,
        useCustomSources: targetUseCustomSources,
        includeThreatFox: targetIncludeThreatFox,
        includeUrlscan: targetIncludeUrlscan,
        mode: targetMode,
        results: nextResults,
        invalidTokens: nextInvalid,
        quotaSkipped: nextQuotaSkipped,
        lastReportFile: nextReportFile,
        lastRunMode: resolvedMode,
        activeHistoryId: entry.id,
        researcherNotes: entry.notes ?? '',
      }));
      if (data.quota?.date && Array.isArray(data.quota?.providers)) {
        onQuotaChange(data.quota);
      }
      setVerdictFilter('All');
      setResultsTagFilter('All');
      setGraphFocusedIndicator(null);
      setTaggingIndicator(null);
      setCustomTagInput('');
      setTableTaggingIndicator(null);
      setTableCustomTagInput('');
      setNotesSaveStatus(entry.notes ? 'saved' : 'idle');

      setRecentHistory((prev) => prependRecentInvestigation(prev, entry));

      if (data.emailAlert?.triggered && data.emailAlert?.record) {
        setLastEmailAlert(data.emailAlert.record);
        onEmailAlertTriggered?.(data.emailAlert.record);
      }

      if (nextReportFile) {
        onReportCreated(nextReportFile);
      }

      if (latestStateRef.current.livePollingEnabled) {
        const nextSec = normalizeLivePollInterval(latestStateRef.current.livePollIntervalSec);
        setNextPollAtMs(Date.now() + nextSec * 1000);
      }
    } catch {
      if (isBackground) {
        setLivePollError('Unable to reach backend during live refresh.');
      } else {
        setErrorMsg('Unable to reach the enrichment backend.');
      }
    } finally {
      if (isBackground) {
        isBackgroundPollingRef.current = false;
        setIsBackgroundPolling(false);
        if (latestStateRef.current.livePollingEnabled) {
          const nextSec = normalizeLivePollInterval(latestStateRef.current.livePollIntervalSec);
          setNextPollAtMs(Date.now() + nextSec * 1000);
        }
      } else {
        setLoading(false);
      }
    }
  }

  runEnrichmentRef.current = runEnrichment;

  useEffect(() => {
    if (!state.livePollingEnabled) {
      setNextPollAtMs(null);
      setLivePollError(null);
      return;
    }
    if (activePollIndicators.length === 0) {
      setNextPollAtMs(null);
      return;
    }

    const intervalMs = livePollIntervalSec * 1000;
    const now = Date.now();
    setNowTickMs(now);
    setNextPollAtMs((prev) => (prev && prev > now ? prev : now + intervalMs));

    const timer = window.setInterval(() => {
      const currentTick = Date.now();
      setNowTickMs(currentTick);
      setNextPollAtMs((prevNext) => {
        if (!prevNext) return currentTick + intervalMs;
        if (currentTick >= prevNext && !isBackgroundPollingRef.current) {
          const cur = latestStateRef.current;
          const indicators = extractActiveIndicatorsForPolling(cur.results, cur.rawInput);
          if (indicators.length > 0) {
            void runEnrichmentRef.current({
              rawInput: indicators.join('\n'),
              source: cur.source,
              customSources: cur.customSources,
              useCustomSources: cur.useCustomSources,
              includeThreatFox: cur.includeThreatFox,
              includeUrlscan: cur.includeUrlscan,
              mode: cur.mode,
              analysisMode: cur.analysisMode,
              backgroundPoll: true,
            });
          }
          return currentTick + intervalMs;
        }
        return prevNext;
      });
    }, 1000);

    return () => {
      window.clearInterval(timer);
    };
  }, [state.livePollingEnabled, livePollIntervalSec, activePollIndicators.length]);

  async function handleRunLookup(e: React.FormEvent) {
    e.preventDefault();
    await runEnrichment();
  }

  function handleViewRecentDetails(entry: RecentInvestigationEntry) {
    setErrorMsg(null);
    setFileImportSummary(null);
    setVerdictFilter('All');
    setGraphFocusedIndicator(null);
    const restored = resolveRestoredNotesForEntry(notesAutoSaveRef.current, entry.id, entry.notes);
    setNotesSaveStatus(restored.notes ? 'saved' : 'idle');
    onChangeState((prev) => ({
      ...prev,
      rawInput: entry.rawInput,
      source: entry.source,
      customSources: entry.customSources,
      useCustomSources: entry.useCustomSources,
      includeThreatFox: entry.includeThreatFox ?? null,
      includeUrlscan: entry.includeUrlscan ?? null,
      mode: entry.mode,
      results: entry.results,
      invalidTokens: entry.invalidTokens,
      quotaSkipped: entry.quotaSkipped,
      lastReportFile: entry.reportFile,
      lastRunMode: entry.mode,
      activeHistoryId: entry.id,
      researcherNotes: restored.notes,
    }));
  }

  async function handleRerunRecent(entry: RecentInvestigationEntry) {
    setFileImportSummary(null);
    const nextIncludeThreatFox = entry.includeThreatFox ?? null;
    const nextIncludeUrlscan = entry.includeUrlscan ?? null;
    onChangeState((prev) => ({
      ...prev,
      rawInput: entry.rawInput,
      source: entry.source,
      customSources: entry.customSources,
      useCustomSources: entry.useCustomSources,
      includeThreatFox: nextIncludeThreatFox,
      includeUrlscan: nextIncludeUrlscan,
      mode: entry.mode,
      activeHistoryId: entry.id,
      researcherNotes: entry.notes ?? '',
    }));
    await runEnrichment({
      rawInput: entry.rawInput,
      source: entry.source,
      customSources: entry.customSources,
      useCustomSources: entry.useCustomSources,
      includeThreatFox: nextIncludeThreatFox,
      includeUrlscan: nextIncludeUrlscan,
      mode: entry.mode,
      preserveNotes: entry.notes ?? '',
    });
  }

  function handleTogglePinRecent(id: string) {
    setRecentHistory((prev) => togglePinRecentInvestigation(prev, id));
  }

  function handleRenameRecent(id: string, nextTitle: string) {
    setRecentHistory((prev) => renameRecentInvestigation(prev, id, nextTitle));
  }

  function handleRemoveRecent(id: string) {
    setRecentHistory((prev) => removeRecentInvestigation(prev, id));
    const pruned = removeEntryFromAutoSaveDrafts(notesAutoSaveRef.current, id);
    notesAutoSaveRef.current = pruned;
    setNotesAutoSave(pruned);
    if (typeof window !== 'undefined') {
      saveNotesAutoSaveState(window.localStorage, pruned);
    }
    if (activeHistoryId === id) {
      onChangeState((prev) => ({ ...prev, activeHistoryId: null, researcherNotes: '' }));
      setNotesSaveStatus('idle');
    }
  }

  function handleClearRecent() {
    setRecentHistory([]);
    onChangeState((prev) => ({ ...prev, activeHistoryId: null }));
    const emptied = createEmptyNotesAutoSaveState();
    notesAutoSaveRef.current = emptied;
    setNotesAutoSave(emptied);
    setNotesSaveStatus('idle');
    if (typeof window !== 'undefined') {
      clearRecentInvestigations(window.localStorage);
      saveNotesAutoSaveState(window.localStorage, emptied);
    }
  }

  function handleExportResultsCsv() {
    if (exportableVisibleResults.length === 0) return;
    setExportMenuOpen(false);
    const csvContent = serializeResultsToCsv(exportableVisibleResults, new Date().toISOString());
    const filename = buildInvestigationCsvFilename(verdictFilter);
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function handleExportResultsJson() {
    if (exportableVisibleResults.length === 0) return;
    setExportMenuOpen(false);
    const payload = buildStructuredResultsJsonPayload({
      allResults: state.results,
      visibleResults: exportableVisibleResults,
      verdictFilter,
      mode: state.lastRunMode,
    });
    const jsonText = serializeStructuredResultsJson(payload);
    const filename = buildResultsJsonFilename(verdictFilter);
    const blob = new Blob([jsonText], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function handleExportResultsTxt() {
    if (exportableVisibleResults.length === 0) return;
    setExportMenuOpen(false);
    const txtContent = buildFormattedResultsTxtReport({
      allResults: state.results,
      visibleResults: exportableVisibleResults,
      verdictFilter,
      tagFilter: resultsTagFilter,
      riskThreshold,
      sortState: tableSort,
      indicatorTags,
      researcherNotes: state.researcherNotes,
      mode: state.lastRunMode,
    });
    const filename = buildResultsTxtFilename(verdictFilter);
    const blob = new Blob([txtContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function handleExportFullSession() {
    const payload = buildExportedSessionPayload({
      sessionId: activeHistoryId,
      analysisMode: state.analysisMode,
      executionMode: state.mode,
      lastRunMode: state.lastRunMode,
      reportFile: state.lastReportFile,
      rawInput: state.rawInput,
      invalidTokens: state.invalidTokens,
      sourceSelection: state.source,
      effectiveSources,
      customSources: state.customSources,
      useCustomSources: state.useCustomSources,
      includeThreatFox: state.includeThreatFox,
      includeUrlscan: state.includeUrlscan,
      quotaSkipped: state.quotaSkipped,
      results: state.results,
      indicatorTags,
      researcherNotes: state.researcherNotes,
      notesUpdatedAt: activeHistoryEntry?.notesUpdatedAt ?? null,
    });

    const jsonText = serializeExportedSessionJson(payload);
    const filename = buildSessionExportFilename();
    const blob = new Blob([jsonText], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);

    setSessionExportedFile(filename);
    if (sessionExportTimerRef.current !== null) {
      window.clearTimeout(sessionExportTimerRef.current);
    }
    sessionExportTimerRef.current = window.setTimeout(() => setSessionExportedFile(null), 3500);
  }

  async function handleCreateSessionSnapshot() {
    if (state.results.length === 0 || typeof window === 'undefined') return;
    const built = buildSessionSnapshotUrl(window.location.href, {
      analysisMode: state.analysisMode,
      mode: state.mode,
      lastRunMode: state.lastRunMode,
      rawInput: state.rawInput,
      source: state.source,
      customSources: state.customSources,
      useCustomSources: state.useCustomSources,
      includeThreatFox: state.includeThreatFox,
      includeUrlscan: state.includeUrlscan,
      invalidTokens: state.invalidTokens,
      quotaSkipped: state.quotaSkipped,
      lastReportFile: state.lastReportFile,
      researcherNotes: state.researcherNotes,
      indicatorTags,
      verdictFilter,
      riskThreshold,
      tableSort,
      results: state.results,
    });
    setSnapshotUrl(built.url);
    setSnapshotSizeLabel(formatSnapshotPayloadSize(built.byteLength));
    setSnapshotTruncated(built.truncatedDetails);
    setSnapshotModalOpen(true);

    const copied = await copyToClipboard(built.url);
    if (copied) {
      setSnapshotCopied(true);
      window.setTimeout(() => setSnapshotCopied(false), 2500);
    }
  }

  function handlePrintInvestigation() {
    if (typeof window === 'undefined') return;
    flushNotesAutoSaveRef.current();
    const prevTitle = document.title;
    const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-');
    document.title = `SoTI-Investigation-${stamp}`;
    const restoreTitle = () => {
      document.title = prevTitle;
      window.removeEventListener('afterprint', restoreTitle);
    };
    window.addEventListener('afterprint', restoreTitle);
    window.print();
    window.setTimeout(restoreTitle, 1000);
  }

  function handleSwitchAnalysisMode(nextMode: InvestigationAnalysisMode) {
    setErrorMsg(null);
    if (nextMode === 'bulk') {
      setBulkTableStyle('unified');
      onChangeState((prev) => {
        const nextRaw =
          prev.rawInput.trim() === SAMPLE_BATCH && prev.results.length === 0
            ? BULK_SAMPLE_BATCH
            : prev.rawInput.includes(',') && !prev.rawInput.includes('\n')
              ? formatIndicatorsAsNewlines(prev.rawInput) || prev.rawInput
              : prev.rawInput;
        return {
          ...prev,
          analysisMode: 'bulk',
          rawInput: nextRaw,
        };
      });
    } else {
      onChangeState((prev) => ({
        ...prev,
        analysisMode: 'standard',
        rawInput:
          prev.rawInput.trim() === BULK_SAMPLE_BATCH && prev.results.length === 0
            ? SAMPLE_BATCH
            : prev.rawInput,
      }));
    }
  }

  function handleToggleLivePolling() {
    const nextEnabled = !state.livePollingEnabled;
    onChangeState((prev) => ({
      ...prev,
      livePollingEnabled: nextEnabled,
    }));
    if (nextEnabled) {
      const indicators = extractActiveIndicatorsForPolling(state.results, state.rawInput);
      const intervalMs = livePollIntervalSec * 1000;
      const now = Date.now();
      setNowTickMs(now);
      setNextPollAtMs(indicators.length > 0 ? now + intervalMs : null);
      if (state.results.length === 0 && indicators.length > 0 && !loading) {
        void runEnrichment();
      }
    } else {
      setNextPollAtMs(null);
      setLivePollError(null);
    }
  }

  function handleTriggerManualPollNow() {
    const cur = latestStateRef.current;
    const indicators = extractActiveIndicatorsForPolling(cur.results, cur.rawInput);
    if (indicators.length === 0) return;
    void runEnrichment({
      rawInput: indicators.join('\n'),
      source: cur.source,
      customSources: cur.customSources,
      useCustomSources: cur.useCustomSources,
      includeThreatFox: cur.includeThreatFox,
      includeUrlscan: cur.includeUrlscan,
      mode: cur.mode,
      analysisMode: cur.analysisMode,
      backgroundPoll: cur.results.length > 0,
    });
  }

  async function triggerClipboardCopy(text: string, key: string) {
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopiedKey(key);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => setCopiedKey(null), 2000);
    }
  }

  return (
    <div className="space-y-8">
      {sessionSnapshotError && (
        <div
          role="alert"
          data-testid="session-snapshot-error-banner"
          className="flex items-center justify-between gap-3 rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 px-4 py-3 text-xs text-amber-950 dark:text-amber-100 print:hidden"
        >
          <span>{sessionSnapshotError}</span>
          {onDismissSessionSnapshot && (
            <button
              type="button"
              onClick={onDismissSessionSnapshot}
              aria-label="Dismiss session snapshot error"
              className="rounded p-1 hover:bg-amber-100 dark:hover:bg-amber-900/50 cursor-pointer"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          )}
        </div>
      )}

      {loadedSessionSnapshot && (
        <section
          aria-label="Restored Session Snapshot"
          data-testid="restored-session-snapshot-banner"
          className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-red-200 dark:border-red-900/60 bg-red-50/60 dark:bg-red-950/30 px-5 py-3.5 text-xs print:hidden"
        >
          <div className="flex items-start gap-2.5 min-w-0">
            <Link2 className="mt-0.5 h-4 w-4 shrink-0 text-red-600 dark:text-red-400" aria-hidden="true" />
            <div className="space-y-0.5 min-w-0">
              <p className="font-semibold text-slate-950 dark:text-slate-50">
                Restored Investigation from Session Snapshot
              </p>
              <p className="font-mono text-[11px] text-slate-600 dark:text-slate-300 tabular-nums">
                {loadedSessionSnapshot.indicatorCount} IOC{loadedSessionSnapshot.indicatorCount === 1 ? '' : 's'} ·{' '}
                {loadedSessionSnapshot.results.length} provider finding{loadedSessionSnapshot.results.length === 1 ? '' : 's'} · Captured{' '}
                {loadedSessionSnapshot.createdAt.slice(0, 16).replace('T', ' ')} UTC
                {loadedSessionSnapshot.researcherNotes ? ' · Notes restored' : ''}
              </p>
            </div>
          </div>
          {onDismissSessionSnapshot && (
            <button
              type="button"
              data-testid="dismiss-session-snapshot-banner"
              onClick={onDismissSessionSnapshot}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Dismiss Notice</span>
            </button>
          )}
        </section>
      )}

      {showThresholdWarning && (
        <div
          role="alert"
          data-testid="quota-threshold-warning"
          className="flex flex-col gap-3 rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 px-5 py-4 text-xs text-amber-950 dark:text-amber-100 sm:flex-row sm:items-center sm:justify-between"
        >
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-700 dark:text-amber-400" aria-hidden="true" />
            <div className="space-y-0.5">
              <p className="text-sm font-semibold text-amber-950 dark:text-amber-100">
                Daily Quota Warning (&gt;80% Used)
              </p>
              <p className="text-xs text-amber-900 dark:text-amber-200/90">
                Approaching daily limit on{' '}
                <span className="font-mono font-medium">
                  {warningProviders
                    .map((p) => `${p.name}: ${p.used}/${p.limit} (${p.percentUsed}% — ${p.remaining} left)`)
                    .join(' · ')}
                </span>
                . Enable backup APIs or increase limits before exhaustion triggers automatic failover.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={onOpenApiConfig}
              className="rounded-lg border border-amber-300 dark:border-amber-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-amber-950 dark:text-amber-200 hover:bg-amber-100 dark:hover:bg-amber-900/40 whitespace-nowrap shrink-0 cursor-pointer"
            >
              Manage APIs &amp; Quotas
            </button>
            <button
              type="button"
              onClick={() => setDismissedQuotaSignature(warningSignature)}
              aria-label="Dismiss daily quota warning"
              className="rounded-lg p-1.5 text-amber-800 dark:text-amber-300 hover:bg-amber-100 dark:hover:bg-amber-900/50 cursor-pointer"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-[minmax(0,1fr)_320px] print:block">
        <div className="min-w-0 space-y-6">
          <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 md:p-6 print:hidden">
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-950 dark:text-slate-50 text-balance">
              Threat Intelligence Enrichment
            </h1>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
              Query normal or defanged IPs, domains, and hashes individually or via bulk CSV / TXT file upload, with automatic daily quota failover.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 min-w-0 max-w-full">
            <div className="inline-flex items-center rounded-lg bg-slate-100 dark:bg-slate-800 p-1" role="group" aria-label="Investigation workflow mode">
              <button
                type="button"
                data-testid="investigate-mode-standard"
                onClick={() => handleSwitchAnalysisMode('standard')}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  !isBulkMode
                    ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                }`}
              >
                Standard
              </button>
              <button
                type="button"
                data-testid="investigate-mode-bulk"
                onClick={() => handleSwitchAnalysisMode('bulk')}
                className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  isBulkMode
                    ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                }`}
              >
                <Layers className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                Bulk Input
              </button>
            </div>

            <div className="inline-flex items-center rounded-lg bg-slate-100 dark:bg-slate-800 p-1" role="group" aria-label="Execution mode">
              <button
                type="button"
                onClick={() => onChangeState((prev) => ({ ...prev, mode: 'sample' }))}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  state.mode === 'sample'
                    ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                }`}
              >
                Sample Data
              </button>
              <button
                type="button"
                onClick={() => onChangeState((prev) => ({ ...prev, mode: 'live' }))}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  state.mode === 'live'
                    ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                }`}
              >
                Live API
              </button>
            </div>

            <div className="inline-flex items-center gap-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-800/60 px-2.5 py-1">
              <button
                type="button"
                role="switch"
                aria-checked={state.livePollingEnabled}
                aria-label="Toggle Live Mode periodic background polling"
                data-testid="live-mode-toggle"
                onClick={handleToggleLivePolling}
                className="inline-flex items-center gap-2 text-xs font-medium text-slate-800 dark:text-slate-200 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
              >
                <span
                  aria-hidden="true"
                  className={`relative inline-flex h-4 w-7 items-center rounded-full transition-colors ${
                    state.livePollingEnabled
                      ? 'bg-red-600'
                      : 'bg-slate-300 dark:bg-slate-600'
                  }`}
                >
                  <span
                    className={`inline-block h-3 w-3 transform rounded-full bg-white transition-transform ${
                      state.livePollingEnabled ? 'translate-x-3.5' : 'translate-x-0.5'
                    }`}
                  />
                </span>
                <span>Live Mode</span>
              </button>

              <select
                aria-label="Live Mode refresh interval"
                data-testid="live-mode-interval-select"
                value={livePollIntervalSec}
                onChange={(e) => {
                  const nextInterval = normalizeLivePollInterval(e.target.value);
                  onChangeState((prev) => ({
                    ...prev,
                    livePollIntervalSec: nextInterval,
                  }));
                  if (state.livePollingEnabled && activePollIndicators.length > 0) {
                    const now = Date.now();
                    setNowTickMs(now);
                    setNextPollAtMs(now + nextInterval * 1000);
                  }
                }}
                className="rounded border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] font-medium text-slate-700 dark:text-slate-200 focus:border-red-600 focus:outline-none cursor-pointer"
              >
                {LIVE_POLL_INTERVAL_OPTIONS.map((opt) => (
                  <option key={opt.seconds} value={opt.seconds}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {state.livePollingEnabled && (
          <div
            data-testid="live-mode-status-bar"
            role="status"
            aria-live="polite"
            className="mt-4 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t border-slate-100 dark:border-slate-800 pt-3 text-xs"
          >
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-slate-700 dark:text-slate-300">
              <span className="inline-flex items-center gap-1.5 font-semibold text-red-700 dark:text-red-400">
                <Radio className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span>Live Polling Active</span>
              </span>
              <span className="text-slate-400 dark:text-slate-600" aria-hidden="true">·</span>
              {activePollIndicators.length > 0 ? (
                <span className="font-mono tabular-nums">
                  Monitoring {activePollIndicators.length} active IOC{activePollIndicators.length === 1 ? '' : 's'}
                </span>
              ) : (
                <span className="text-slate-500 dark:text-slate-400">
                  Armed — run or paste indicators to begin background updates
                </span>
              )}
              {lastPollDelta && (
                <>
                  <span className="text-slate-400 dark:text-slate-600" aria-hidden="true">·</span>
                  <span
                    data-testid="live-mode-last-refresh"
                    className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums"
                  >
                    Updated {lastPollDelta.checkedAtIso.slice(11, 19)} UTC (
                    {lastPollDelta.changedCount === 0
                      ? 'no changes'
                      : `${lastPollDelta.changedCount} updated${
                          lastPollDelta.escalatedCount > 0
                            ? `, ${lastPollDelta.escalatedCount} escalated`
                            : ''
                        }`}
                    )
                  </span>
                </>
              )}
              {livePollError && (
                <>
                  <span className="text-slate-400 dark:text-slate-600" aria-hidden="true">·</span>
                  <span className="font-medium text-amber-700 dark:text-amber-400">
                    {livePollError}
                  </span>
                </>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-x-3 gap-y-2 max-w-full">
              <span
                data-testid="live-mode-next-refresh"
                className="font-mono text-xs text-slate-700 dark:text-slate-200 tabular-nums"
              >
                {isBackgroundPolling
                  ? 'Refreshing threat data...'
                  : nextPollAtMs && activePollIndicators.length > 0
                    ? `Next refresh in ${formatLiveCountdown(remainingPollSeconds)} (${formatUtcClockTime(nextPollAtMs)})`
                    : `Interval: ${livePollIntervalSec}s`}
              </span>
              <button
                type="button"
                data-testid="live-mode-refresh-now"
                disabled={isBackgroundPolling || loading || activePollIndicators.length === 0}
                onClick={handleTriggerManualPollNow}
                className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-45 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RefreshCw
                  className={`h-3 w-3 shrink-0 ${isBackgroundPolling ? 'animate-spin' : ''}`}
                  aria-hidden="true"
                />
                <span>Refresh Now</span>
              </button>
            </div>
          </div>
        )}

        {visibleQuotaSnapshots.length > 0 && (
          <div
            data-testid="daily-quota-strip"
            className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-slate-100 dark:border-slate-800 pt-3 text-xs text-slate-600 dark:text-slate-400"
          >
            <span className="font-semibold text-slate-700 dark:text-slate-300">Daily API Quota ({quota.date}):</span>
            {visibleQuotaSnapshots.map((q) => {
              const isApproaching = !q.exhausted && q.percentUsed > 80;
              return (
                <span
                  key={q.providerId}
                  className={`inline-flex items-center gap-1.5 font-mono tabular-nums ${
                    q.exhausted
                      ? 'font-semibold text-red-700 dark:text-red-400'
                      : isApproaching
                        ? 'font-semibold text-amber-700 dark:text-amber-400'
                        : 'text-slate-700 dark:text-slate-300'
                  }`}
                >
                  <span className="font-sans font-medium">{q.name}:</span>
                  <span>
                    {q.used}/{q.limit}
                  </span>
                  <span className="text-slate-400 dark:text-slate-600">/</span>
                  <span
                    className={
                      q.exhausted
                        ? 'text-red-700 dark:text-red-400'
                        : isApproaching
                          ? 'text-amber-700 dark:text-amber-400'
                          : 'text-slate-500 dark:text-slate-400'
                    }
                  >
                    {q.exhausted
                      ? 'Exhausted (failover ready)'
                      : isApproaching
                        ? `${q.percentUsed}% used · ${q.remaining} left`
                        : `${q.remaining} left`}
                  </span>
                </span>
              );
            })}
          </div>
        )}

        <form onSubmit={handleRunLookup} className="mt-6 space-y-5">
          <div>
            <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
              <label htmlFor="ioc-input" className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                {isBulkMode
                  ? 'Bulk Indicator List — IPs, domains, URLs, or hashes (one per line or comma-separated)'
                  : 'Indicators — IP, domain, URL, or hash'}
              </label>

              <div className="flex flex-wrap items-center gap-x-3 gap-y-2 min-w-0 max-w-full">
                {preprocessedInput.detectedPatterns.length > 0 && (
                  <button
                    type="button"
                    data-testid="strip-defang-button"
                    onClick={() => {
                      if (preprocessedInput.apiReadyInput) {
                        onChangeState((prev) => ({
                          ...prev,
                          rawInput: isBulkMode
                            ? deduplicateBulkInputLines(prev.rawInput)
                            : preprocessedInput.apiReadyInput,
                        }));
                      }
                    }}
                    className="inline-flex items-center gap-1.5 text-xs font-medium text-red-700 dark:text-red-400 hover:underline whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Sparkles className="h-3.5 w-3.5" aria-hidden="true" />
                    Strip defangs
                  </button>
                )}
                {isBulkMode && state.rawInput.includes(',') && (
                  <button
                    type="button"
                    data-testid="bulk-split-lines-button"
                    onClick={() => {
                      const next = formatIndicatorsAsNewlines(state.rawInput);
                      if (next) {
                        onChangeState((prev) => ({ ...prev, rawInput: next }));
                      }
                    }}
                    className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    Split to Lines
                  </button>
                )}
                {isBulkMode && (
                  <button
                    type="button"
                    data-testid="bulk-dedup-button"
                    onClick={() => {
                      const cleaned = deduplicateBulkInputLines(state.rawInput);
                      onChangeState((prev) => ({ ...prev, rawInput: cleaned }));
                    }}
                    className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    Clean &amp; Deduplicate
                  </button>
                )}
                <button
                  type="button"
                  data-testid="import-csv-button"
                  onClick={() => csvFileInputRef.current?.click()}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
                >
                  <Upload className="h-3.5 w-3.5" aria-hidden="true" />
                  Import CSV
                </button>
                <button
                  type="button"
                  onClick={() => {
                    onChangeState((prev) => ({
                      ...prev,
                      rawInput: isBulkMode ? BULK_SAMPLE_BATCH : SAMPLE_BATCH,
                    }));
                    setFileImportSummary(null);
                    setErrorMsg(null);
                  }}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <ClipboardList className="h-3.5 w-3.5" aria-hidden="true" />
                  {isBulkMode ? 'Load Bulk Sample' : 'Load Sample IOCs'}
                </button>
                {isBulkMode && state.rawInput.trim().length > 0 && (
                  <button
                    type="button"
                    data-testid="bulk-clear-button"
                    onClick={() => onChangeState((prev) => ({ ...prev, rawInput: '' }))}
                    className="text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-red-600 dark:hover:text-red-400 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>
            <textarea
              ref={iocInputRef}
              id="ioc-input"
              data-testid={isBulkMode ? 'bulk-ioc-textarea' : 'standard-ioc-textarea'}
              rows={isBulkMode ? 6 : 3}
              value={state.rawInput}
              onChange={(e) => onChangeState((prev) => ({ ...prev, rawInput: e.target.value }))}
              placeholder={
                isBulkMode
                  ? 'Paste a list of indicators separated by newlines (one per line):\n1[.]2[.]3[.]4\n8.8.8.8\nhxxp://evil[.]com/login\n44d88612fea8a8f36de82e1278abb02f'
                  : 'e.g. 1[.]2[.]3[.]4, hxxp://evil[.]com, 44d88612fea8a8f36de82e1278abb02f'
              }
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-800/70 px-3.5 py-2.5 font-mono text-sm text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-900 focus:outline-none"
            />
            {isBulkMode && (
              <div
                data-testid="bulk-input-stats"
                className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600 dark:text-slate-400"
              >
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono tabular-nums">
                  <span className="font-sans font-medium text-slate-700 dark:text-slate-300">
                    Batch Breakdown:
                  </span>
                  <span>{bulkStats.lineCount} line{bulkStats.lineCount === 1 ? '' : 's'}</span>
                  <span>·</span>
                  <span>{bulkStats.totalValid} valid</span>
                  <span>·</span>
                  <span>{bulkStats.ipCount} IP</span>
                  <span>·</span>
                  <span>{bulkStats.domainCount} Domain</span>
                  <span>·</span>
                  <span>{bulkStats.hashCount} Hash</span>
                  {bulkStats.invalidCount > 0 && (
                    <>
                      <span>·</span>
                      <span className="text-red-600 dark:text-red-400">
                        {bulkStats.invalidCount} invalid skipped
                      </span>
                    </>
                  )}
                </div>
                <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                  {effectiveSources.length} enabled provider{effectiveSources.length === 1 ? '' : 's'} × {bulkStats.totalValid} IOC{bulkStats.totalValid === 1 ? '' : 's'} = {effectiveSources.length * bulkStats.totalValid} simultaneous lookups
                </span>
              </div>
            )}
          </div>

          <IndicatorFileUpload
            summary={fileImportSummary}
            fileInputRef={csvFileInputRef}
            onIndicatorsExtracted={handleFileExtracted}
            onError={handleFileError}
            onDismissSummary={() => setFileImportSummary(null)}
          />

          {parsedPreview.length > 0 && (
            <div className="space-y-1.5" data-testid="detected-indicators-preview">
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-slate-600 dark:text-slate-400">
                <span className="font-medium text-slate-500 dark:text-slate-400">Detected ({parsedPreview.length}):</span>
                {parsedPreview.slice(0, 12).map((item, idx) => (
                  <span key={`${item.cleaned}-${idx}`} className="inline-flex flex-wrap items-center gap-1.5 font-mono max-w-full">
                    <span className={`break-all ${item.type ? 'text-slate-900 dark:text-slate-100' : 'text-red-600 dark:text-red-400 line-through'}`}>
                      {item.cleaned}
                    </span>
                    <span className="text-slate-400 dark:text-slate-600">/</span>
                    <span className={item.type ? 'text-slate-600 dark:text-slate-400' : 'text-red-600 dark:text-red-400'}>
                      {item.type ?? 'invalid'}
                    </span>
                  </span>
                ))}
                {parsedPreview.length > 12 && (
                  <span className="font-mono text-slate-500 dark:text-slate-400">+{parsedPreview.length - 12} more</span>
                )}
              </div>

              {preprocessedInput.detectedPatterns.length > 0 && (
                <p
                  data-testid="defang-detection-note"
                  className="text-[11px] text-slate-500 dark:text-slate-400"
                >
                  Defang patterns detected (
                  <span className="font-mono text-slate-700 dark:text-slate-300">
                    {preprocessedInput.detectedPatterns.join(', ')}
                  </span>
                  ) — automatically stripped before sending to API providers.
                </p>
              )}
            </div>
          )}

          {isBulkMode ? (
            <div className="space-y-3 border-t border-slate-100 dark:border-slate-800 pt-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div
                  data-testid="bulk-simultaneous-providers"
                  className="min-w-0 space-y-1"
                >
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="font-semibold text-slate-800 dark:text-slate-200">
                      Simultaneous Execution ({enabledSourceIds.length} enabled providers):
                    </span>
                    <span className="font-mono text-slate-600 dark:text-slate-300">
                      {enabledSourceIds.length > 0
                        ? enabledSourceIds.map((id) => providerNameMap[id] || id).join(' · ')
                        : 'No providers enabled'}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    All enabled threat intelligence APIs run concurrently per indicator and consolidate into a unified batch table.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={onOpenApiConfig}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Settings2 className="h-3.5 w-3.5" aria-hidden="true" />
                    Configure APIs
                  </button>

                  <button
                    type="submit"
                    data-testid="run-bulk-analysis-button"
                    disabled={loading}
                    className="inline-flex items-center justify-center gap-2 rounded-lg bg-red-600 px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-red-700 disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
                  >
                    <Layers className="h-4 w-4" aria-hidden="true" />
                    {loading ? 'Analyzing Batch...' : 'Run Bulk Analysis'}
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-3 border-t border-slate-100 dark:border-slate-800 pt-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex flex-wrap items-center gap-2">
                  <div
                    className="grid grid-cols-2 gap-1 rounded-lg bg-slate-100 dark:bg-slate-800 p-1 sm:inline-flex sm:flex-wrap sm:items-center"
                    role="group"
                    aria-label="Intelligence source"
                  >
                    {SOURCE_OPTIONS.map((opt) => {
                      const isActive = !state.useCustomSources && state.source === opt.id;
                      const isDisabledInSettings =
                        opt.id !== 'all' && !apiSettings.providers[opt.id].enabled;
                      return (
                        <button
                          key={opt.id}
                          type="button"
                          onClick={() =>
                            onChangeState((prev) => ({
                              ...prev,
                              useCustomSources: false,
                              source: opt.id,
                            }))
                          }
                          className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                            isActive
                              ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                              : isDisabledInSettings
                                ? 'text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                                : 'text-slate-600 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white'
                          }`}
                        >
                          {opt.label}
                          {opt.id === 'all' ? ` (${effectiveSources.length})` : ''}
                        </button>
                      );
                    })}
                    <button
                      type="button"
                      onClick={() =>
                        onChangeState((prev) => ({
                          ...prev,
                          useCustomSources: true,
                          customSources:
                            prev.customSources.length > 0 ? prev.customSources : [...effectiveSources],
                        }))
                      }
                      className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        state.useCustomSources
                          ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                          : 'text-slate-600 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white'
                      }`}
                    >
                      Custom
                    </button>
                  </div>

                  <button
                    type="button"
                    onClick={onOpenApiConfig}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Settings2 className="h-3.5 w-3.5" aria-hidden="true" />
                    Configure APIs
                  </button>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-red-600 px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-red-700 disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
                >
                  <Search className="h-4 w-4" aria-hidden="true" />
                  {loading ? 'Enriching...' : 'Run Enrichment'}
                </button>
              </div>

              {!state.useCustomSources && (
                <div
                  className="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-slate-700 dark:text-slate-300"
                  role="group"
                  aria-label="Additional enrichment providers"
                >
                  <span className="font-medium text-slate-500 dark:text-slate-400 whitespace-nowrap">
                    Additional Providers:
                  </span>

                  <label
                    htmlFor="investigate-toggle-threatfox"
                    className="inline-flex flex-wrap items-center gap-x-2 gap-y-0.5 max-w-full font-medium text-slate-800 dark:text-slate-200 cursor-pointer"
                  >
                    <input
                      id="investigate-toggle-threatfox"
                      type="checkbox"
                      data-testid="toggle-threatfox"
                      checked={threatfoxChecked}
                      onChange={(e) =>
                        onChangeState((prev) => ({
                          ...prev,
                          includeThreatFox: e.target.checked,
                        }))
                      }
                      className="h-3.5 w-3.5 rounded border-slate-300 dark:border-slate-600 text-red-600 focus:ring-red-600 shrink-0"
                    />
                    <span>ThreatFox</span>
                    <span className="font-mono text-[11px] font-normal text-slate-500 dark:text-slate-400">
                      THREATFOX_AUTH_KEY · {extraKeyStatus?.threatfox ? 'ready' : 'not set'}
                    </span>
                  </label>

                  <label
                    htmlFor="investigate-toggle-urlscan"
                    className="inline-flex flex-wrap items-center gap-x-2 gap-y-0.5 max-w-full font-medium text-slate-800 dark:text-slate-200 cursor-pointer"
                  >
                    <input
                      id="investigate-toggle-urlscan"
                      type="checkbox"
                      data-testid="toggle-urlscan"
                      checked={urlscanChecked}
                      onChange={(e) =>
                        onChangeState((prev) => ({
                          ...prev,
                          includeUrlscan: e.target.checked,
                        }))
                      }
                      className="h-3.5 w-3.5 rounded border-slate-300 dark:border-slate-600 text-red-600 focus:ring-red-600 shrink-0"
                    />
                    <span>URLScan</span>
                    <span className="font-mono text-[11px] font-normal text-slate-500 dark:text-slate-400">
                      Domain &amp; URL · URLSCAN_API_KEY · {extraKeyStatus?.urlscan ? 'ready' : 'not set'}
                    </span>
                  </label>
                </div>
              )}

              {state.useCustomSources ? (
                <div className="flex flex-wrap items-center gap-4 text-xs text-slate-700 dark:text-slate-300" role="group" aria-label="Custom API selection">
                  <span className="font-medium text-slate-500 dark:text-slate-400">Select APIs:</span>
                  {allKnownProviders.map((prov) => {
                    const checked = state.customSources.includes(prov.id);
                    const q = quotaById.get(prov.id);
                    return (
                      <label key={prov.id} className="inline-flex items-center gap-2 font-medium text-slate-800 dark:text-slate-200 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleCustomSource(prov.id)}
                          className="h-3.5 w-3.5 rounded border-slate-300 dark:border-slate-600 text-red-600 focus:ring-red-600"
                        />
                        <span>{prov.name}</span>
                        {q?.exhausted && (
                          <span className="font-mono text-[11px] text-red-700 dark:text-red-400">(quota reached)</span>
                        )}
                      </label>
                    );
                  })}
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                  <span>Active APIs:</span>
                  <span data-testid="active-apis-summary" className="font-mono text-slate-700 dark:text-slate-300">
                    {effectiveSources.length > 0
                      ? effectiveSources.map((id) => providerNameMap[id] || id).join(' · ')
                      : 'None enabled'}
                  </span>
                </div>
              )}
            </div>
          )}

          <div
            data-testid="risk-threshold-settings"
            className="flex flex-col gap-2.5 border-t border-slate-100 dark:border-slate-800/80 pt-3 text-xs sm:flex-row sm:flex-wrap sm:items-center sm:justify-between"
          >
            <div className="flex flex-wrap items-center gap-3 w-full sm:w-auto sm:min-w-0 sm:flex-1">
              <label
                htmlFor="investigate-risk-threshold-slider"
                className="inline-flex items-center gap-1.5 font-medium text-slate-700 dark:text-slate-200 whitespace-nowrap shrink-0"
              >
                <SlidersHorizontal className="h-3.5 w-3.5 text-slate-500 dark:text-slate-400" aria-hidden="true" />
                <span>Risk Threshold</span>
              </label>

              <div className="flex items-center gap-2.5 min-w-[160px] flex-1 sm:max-w-[260px]">
                <input
                  id="investigate-risk-threshold-slider"
                  type="range"
                  min={0}
                  max={100}
                  step={5}
                  value={riskThreshold}
                  data-testid="risk-threshold-slider"
                  aria-label="Minimum risk confidence threshold filter"
                  onChange={(e) => setRiskThreshold(normalizeRiskThreshold(e.target.value))}
                  className="h-1.5 w-full cursor-pointer accent-red-600 dark:accent-red-500"
                />
                <span
                  data-testid="risk-threshold-value"
                  className={`font-mono text-xs font-semibold tabular-nums whitespace-nowrap shrink-0 ${
                    riskThreshold > 0
                      ? 'text-red-700 dark:text-red-400'
                      : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  {riskThreshold === 0 ? 'All (0+)' : `≥ ${riskThreshold}/100`}
                </span>
              </div>

              <div className="inline-flex items-center gap-1 rounded-md bg-slate-100 dark:bg-slate-800 p-0.5 shrink-0" role="group" aria-label="Quick risk threshold presets">
                {[
                  { label: 'All', val: 0 },
                  { label: '25+', val: 25 },
                  { label: '50+', val: 50 },
                  { label: '75+', val: 75 },
                ].map((preset) => (
                  <button
                    key={preset.val}
                    type="button"
                    data-testid={`risk-threshold-preset-${preset.val}`}
                    onClick={() => setRiskThreshold(preset.val)}
                    className={`rounded px-1.5 py-0.5 font-mono text-[11px] font-medium transition-colors cursor-pointer ${
                      riskThreshold === preset.val
                        ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
                    }`}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-500 dark:text-slate-400 sm:shrink-0">
              {riskThreshold > 0 ? (
                <>
                  <span data-testid="risk-threshold-hidden-summary" className="font-mono tabular-nums">
                    {state.results.length > 0
                      ? `${riskHiddenIndicatorCount} IOC${riskHiddenIndicatorCount === 1 ? '' : 's'} hidden below ${riskThreshold}`
                      : `Hides IOCs scoring < ${riskThreshold}`}
                  </span>
                  <button
                    type="button"
                    data-testid="risk-threshold-reset-btn"
                    onClick={() => setRiskThreshold(0)}
                    className="font-medium text-red-700 dark:text-red-400 hover:underline cursor-pointer"
                  >
                    Reset
                  </button>
                </>
              ) : (
                <span>Slide to hide low-impact IOCs from results tables</span>
              )}
            </div>
          </div>
        </form>

        {errorMsg && (
          <div role="alert" className="mt-4 rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/40 px-4 py-3 text-sm text-red-800 dark:text-red-200">
            {errorMsg}
          </div>
        )}

        {state.quotaSkipped.length > 0 && !errorMsg && (
          <div
            role="status"
            data-testid="quota-failover-banner"
            className="mt-4 rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 px-4 py-3 text-xs text-amber-950 dark:text-amber-100"
          >
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-700 dark:text-amber-400" aria-hidden="true" />
              <div>
                <p className="font-semibold">
                  Daily quota failover applied — enrichment continued on remaining available APIs
                </p>
                <p className="mt-0.5 text-amber-900 dark:text-amber-200/90">
                  Skipped:{' '}
                  {state.quotaSkipped
                    .map((s) => `${s.name} (${s.used}/${s.limit}: ${s.reason})`)
                    .join(' · ')}
                </p>
              </div>
            </div>
          </div>
        )}

        {state.invalidTokens.length > 0 && !errorMsg && (
          <div className="mt-4 rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 px-4 py-2.5 text-xs text-amber-900 dark:text-amber-200">
            Skipped invalid indicator(s): <span className="font-mono">{state.invalidTokens.join(', ')}</span>
          </div>
        )}

        {lastEmailAlert && !errorMsg && (
          <div
            role="status"
            data-testid="investigate-email-alert-banner"
            className="mt-4 flex flex-col gap-3 rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50/80 dark:bg-red-950/35 px-4 py-3 text-xs text-red-950 dark:text-red-100 sm:flex-row sm:items-center sm:justify-between"
          >
            <div className="flex items-start gap-2.5 min-w-0">
              <Mail className="mt-0.5 h-4 w-4 shrink-0 text-red-700 dark:text-red-400" aria-hidden="true" />
              <div className="min-w-0">
                <p className="font-semibold">
                  Threshold Email Alert Dispatched ({lastEmailAlert.deliveryStatus === 'sent' ? 'SMTP Sent' : 'Outbox Queued'})
                </p>
                <p className="mt-0.5 text-red-900 dark:text-red-200/90">
                  Sent to <span className="font-mono">{lastEmailAlert.recipients.join(', ')}</span> for{' '}
                  <span className="font-mono font-medium">
                    {lastEmailAlert.triggeredIndicators
                      .map((t) => `${t.indicator} (${t.confidenceScore}/100 ${t.riskLevel})`)
                      .join(', ')}
                  </span>
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {onOpenEmailAlertRules && (
                <button
                  type="button"
                  data-testid="open-email-rules-from-banner"
                  onClick={onOpenEmailAlertRules}
                  className="rounded-lg border border-red-300 dark:border-red-800 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-red-900 dark:text-red-200 hover:bg-red-100 dark:hover:bg-red-900/40 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  View Email Outbox
                </button>
              )}
              <button
                type="button"
                onClick={() => setLastEmailAlert(null)}
                aria-label="Dismiss threshold email alert confirmation"
                className="rounded-md p-1 text-red-800 dark:text-red-300 hover:bg-red-100 dark:hover:bg-red-900/50 cursor-pointer"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </div>
          </div>
        )}
      </section>

      {state.results.length > 0 ? (
        <div className="space-y-6">
          <div
            data-testid="investigate-print-header"
            className="hidden print:block rounded-lg border border-slate-300 bg-white px-5 py-4 text-slate-900"
          >
            <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-200 pb-2">
              <h1 className="text-lg font-bold tracking-tight text-slate-950">
                SoTI — Threat Intelligence Investigation Report
              </h1>
              <span className="font-mono text-xs text-slate-600 tabular-nums">
                Generated {new Date().toISOString().slice(0, 19).replace('T', ' ')} UTC
              </span>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-xs text-slate-700">
              <span>Mode: {state.lastRunMode === 'live' ? 'Live API' : 'Sample Data'}</span>
              <span>·</span>
              <span>Indicators: {resultIndicatorsList.length}</span>
              <span>·</span>
              <span>Verdict filter: {verdictFilter}</span>
              {riskThreshold > 0 && (
                <>
                  <span>·</span>
                  <span>Min Confidence: {riskThreshold}/100</span>
                </>
              )}
              {state.lastReportFile && (
                <>
                  <span>·</span>
                  <span>CSV: reports/{state.lastReportFile}</span>
                </>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
            <div className="flex flex-col gap-3 border-b border-slate-200 dark:border-slate-800 px-5 py-4 md:px-6">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">
                      {isBulkMode && bulkTableStyle === 'unified'
                        ? 'Unified Batch Results'
                        : 'Summary Matrix'}
                    </h2>
                    {sessionExportedFile && (
                      <span
                        data-testid="session-export-confirmation"
                        className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700 dark:text-emerald-400 print:hidden"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        <span>Exported {sessionExportedFile}</span>
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums break-words">
                    {isBulkMode
                      ? `${unifiedBatchTable.summary.totalIndicators} unique IOCs · ${unifiedBatchTable.summary.maliciousCount} malicious · ${unifiedBatchTable.summary.suspiciousCount} suspicious · ${unifiedBatchTable.summary.cleanCount} clean · ${state.results.length} total lookups`
                      : `${state.results.length} lookup${state.results.length === 1 ? '' : 's'}${state.lastRunMode ? ` · ${state.lastRunMode === 'sample' ? 'Sample Data' : 'Live API'}` : ''}${state.lastReportFile ? ` · Saved to reports/${state.lastReportFile}` : ''}`}
                  </p>
                </div>

                <div
                  data-testid="download-results-controls"
                  className="flex flex-wrap items-center gap-2 min-w-0 max-w-full sm:shrink-0 print:hidden"
                >
                  <div ref={exportDropdownRef} className="relative">
                    <button
                      type="button"
                      data-testid="export-data-dropdown-button"
                      disabled={exportableVisibleResults.length === 0}
                      aria-haspopup="menu"
                      aria-expanded={exportMenuOpen}
                      aria-label="Export current table view as CSV, JSON, or TXT report"
                      onClick={() => setExportMenuOpen((open) => !open)}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
                    >
                      <Download className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>Export Data</span>
                      <ChevronDown
                        className={`h-3.5 w-3.5 transition-transform duration-150 ${exportMenuOpen ? 'rotate-180' : ''}`}
                        aria-hidden="true"
                      />
                    </button>

                    {exportMenuOpen && (
                      <div
                        role="menu"
                        data-testid="export-data-dropdown-menu"
                        aria-label="Choose data export format"
                        className="absolute right-0 z-30 mt-1.5 w-64 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 py-1.5 shadow-lg"
                      >
                        <button
                          type="button"
                          role="menuitem"
                          data-testid="export-results-csv-button"
                          onClick={handleExportResultsCsv}
                          className="flex w-full items-center justify-between gap-3 px-3.5 py-2 text-left text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap cursor-pointer"
                        >
                          <span className="inline-flex items-center gap-2 whitespace-nowrap">
                            <Download className="h-3.5 w-3.5 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />
                            <span>Export CSV (.csv)</span>
                          </span>
                          <span className="font-mono text-[10px] text-slate-400 dark:text-slate-500">
                            Spreadsheet
                          </span>
                        </button>
                        <button
                          type="button"
                          role="menuitem"
                          data-testid="export-results-json-button"
                          onClick={handleExportResultsJson}
                          className="flex w-full items-center justify-between gap-3 px-3.5 py-2 text-left text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap cursor-pointer"
                        >
                          <span className="inline-flex items-center gap-2 whitespace-nowrap">
                            <FileJson className="h-3.5 w-3.5 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />
                            <span>Export JSON (.json)</span>
                          </span>
                          <span className="font-mono text-[10px] text-slate-400 dark:text-slate-500">
                            Structured
                          </span>
                        </button>
                        <button
                          type="button"
                          role="menuitem"
                          data-testid="export-results-txt-button"
                          onClick={handleExportResultsTxt}
                          className="flex w-full items-center justify-between gap-3 px-3.5 py-2 text-left text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap cursor-pointer"
                        >
                          <span className="inline-flex items-center gap-2 whitespace-nowrap">
                            <FileText className="h-3.5 w-3.5 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />
                            <span>Export TXT Report (.txt)</span>
                          </span>
                          <span className="font-mono text-[10px] text-slate-400 dark:text-slate-500">
                            Readable
                          </span>
                        </button>
                      </div>
                    )}
                  </div>

                  <button
                    type="button"
                    data-testid="print-investigation-button"
                    onClick={handlePrintInvestigation}
                    aria-label="Print or export current investigation as PDF"
                    title="Open browser print dialog to print or save tables, notes, timeline, and charts as PDF"
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
                  >
                    <Printer className="h-3.5 w-3.5" aria-hidden="true" />
                    Print / PDF
                  </button>

                  <button
                    type="button"
                    data-testid="session-snapshot-button"
                    disabled={state.results.length === 0}
                    onClick={handleCreateSessionSnapshot}
                    aria-label="Create shareable browser Session Snapshot link"
                    title="Serialize current investigation results, tags, filters, and notes into a shareable browser link"
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
                  >
                    <Link2 className="h-3.5 w-3.5 text-red-600 dark:text-red-400" aria-hidden="true" />
                    <span>Session Snapshot</span>
                  </button>

                  <button
                    type="button"
                    data-testid="export-full-session-button"
                    onClick={handleExportFullSession}
                    aria-label="Export full investigation session as JSON"
                    title="Download complete portable JSON session (input, provider results, researcher notes, and tags)"
                    className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 dark:bg-slate-100 px-3 py-1.5 text-xs font-semibold text-white dark:text-slate-950 hover:bg-slate-800 dark:hover:bg-slate-200 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
                  >
                    <FileJson className="h-3.5 w-3.5" aria-hidden="true" />
                    Export Full Session
                  </button>
                </div>
              </div>

              <div
                data-testid="confidence-score-legend"
                aria-label="Confidence score color legend"
                className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-slate-100 dark:border-slate-800/80 pt-2.5 text-xs"
              >
                <span className="font-semibold text-slate-600 dark:text-slate-400">
                  Confidence Score Legend:
                </span>
                {CONFIDENCE_SCORE_LEGEND.map((tier) => (
                  <span
                    key={tier.level}
                    title={tier.description}
                    className="inline-flex items-center gap-1.5"
                  >
                    <span
                      aria-hidden="true"
                      className={`h-2 w-2 rounded-full shrink-0 ${tier.swatchClass}`}
                    />
                    <span className={`font-semibold ${tier.textClass}`}>{tier.level}</span>
                    <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                      ({tier.rangeLabel})
                    </span>
                  </span>
                ))}
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2.5 print:hidden">
                <div className="flex flex-wrap items-center gap-2 min-w-0 max-w-full">
                  {isBulkMode && (
                    <div
                      className="inline-flex items-center rounded-lg bg-slate-100 dark:bg-slate-800 p-1 max-w-full"
                      role="group"
                      aria-label="Bulk table presentation"
                    >
                      <button
                        type="button"
                        data-testid="bulk-view-unified-btn"
                        onClick={() => setBulkTableStyle('unified')}
                        className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          bulkTableStyle === 'unified'
                            ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                            : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                        }`}
                      >
                        Unified Batch
                      </button>
                      <button
                        type="button"
                        data-testid="bulk-view-detailed-btn"
                        onClick={() => setBulkTableStyle('detailed')}
                        className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          bulkTableStyle === 'detailed'
                            ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                            : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                        }`}
                      >
                        Detailed Rows
                      </button>
                    </div>
                  )}

                  {availableResultTags.length > 0 && (
                    <div
                      data-testid="results-tag-filter-bar"
                      role="group"
                      aria-label="Filter results by indicator tag"
                      className="flex flex-wrap items-center gap-1 rounded-lg bg-slate-100 dark:bg-slate-800 p-1 min-w-0 max-w-full"
                    >
                      <span className="inline-flex items-center gap-1 px-2 text-[11px] font-medium text-slate-500 dark:text-slate-400 whitespace-nowrap">
                        <Tag className="h-3 w-3" aria-hidden="true" />
                        Tag:
                      </span>
                      <button
                        type="button"
                        data-testid="results-tag-filter-all"
                        aria-pressed={resultsTagFilter === 'All'}
                        onClick={() => setResultsTagFilter('All')}
                        className={`rounded-md px-2 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          resultsTagFilter === 'All'
                            ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                            : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                        }`}
                      >
                        All Tags
                      </button>
                      {availableResultTags.map((tag) => {
                        const active = resultsTagFilter.toLowerCase() === tag.toLowerCase();
                        return (
                          <button
                            key={tag}
                            type="button"
                            data-testid={`results-tag-filter-${tag.toLowerCase().replace(/\s+/g, '-')}`}
                            aria-pressed={active}
                            onClick={() => setResultsTagFilter(active ? 'All' : tag)}
                            className={`rounded-md px-2 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                              active
                                ? 'bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-950 shadow-xs'
                                : 'text-slate-600 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white'
                            }`}
                          >
                            {tag}
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-2 min-w-0 max-w-full">
                  {riskThreshold > 0 && (
                    <span
                      data-testid="risk-threshold-active-pill"
                      className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50/70 dark:bg-red-950/35 px-2.5 py-1 font-mono text-xs font-medium text-red-700 dark:text-red-300 tabular-nums"
                    >
                      <span>Risk ≥ {riskThreshold}/100</span>
                      {riskHiddenIndicatorCount > 0 && (
                        <span className="opacity-80">({riskHiddenIndicatorCount} hidden)</span>
                      )}
                      <button
                        type="button"
                        onClick={() => setRiskThreshold(0)}
                        aria-label="Clear risk threshold filter"
                        className="hover:text-red-900 dark:hover:text-red-100 cursor-pointer"
                      >
                        <X className="h-3 w-3" aria-hidden="true" />
                      </button>
                    </span>
                  )}
                  <div className="flex flex-wrap items-center gap-1 rounded-lg bg-slate-100 dark:bg-slate-800 p-1 min-w-0 max-w-full" role="group" aria-label="Filter by verdict">
                    {VERDICT_FILTERS.map((v) => (
                      <button
                        key={v}
                        type="button"
                        onClick={() => setVerdictFilter(v)}
                        className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          verdictFilter === v
                            ? 'bg-white dark:bg-slate-700 text-slate-950 dark:text-white shadow-xs'
                            : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100'
                        }`}
                      >
                        {v}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {tableTaggingIndicator && (
                <div
                  data-testid="table-row-tag-composer"
                  className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/80 dark:bg-slate-800/70 p-3 space-y-2.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <Tag className="h-3.5 w-3.5 text-slate-500 dark:text-slate-400" aria-hidden="true" />
                      <span className="font-semibold text-slate-900 dark:text-slate-100">
                        Manage tags for
                      </span>
                      <span className="font-mono font-semibold text-slate-950 dark:text-white break-all">
                        {tableTaggingIndicator}
                      </span>
                    </div>
                    <button
                      type="button"
                      data-testid="table-row-tag-done"
                      onClick={() => {
                        setTableTaggingIndicator(null);
                        setTableCustomTagInput('');
                      }}
                      className="rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Done
                    </button>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400 mr-1">
                      Quick labels:
                    </span>
                    {SUGGESTED_IOC_TAGS.map((preset) => {
                      const activeTags = getTagsForIndicator(indicatorTags, tableTaggingIndicator);
                      const alreadyTagged = activeTags.some(
                        (t) => t.toLowerCase() === preset.toLowerCase(),
                      );
                      return (
                        <button
                          key={preset}
                          type="button"
                          data-testid={`table-preset-tag-${preset.toLowerCase().replace(/\s+/g, '-')}`}
                          onClick={() => {
                            if (alreadyTagged) {
                              handleRemoveTag(tableTaggingIndicator, preset);
                            } else {
                              handleAddTag(tableTaggingIndicator, preset);
                            }
                          }}
                          className={`rounded-md border px-2 py-0.5 text-[11px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                            alreadyTagged
                              ? 'border-slate-900 dark:border-slate-100 bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-950'
                              : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800'
                          }`}
                        >
                          {alreadyTagged ? `✓ ${preset}` : `+ ${preset}`}
                        </button>
                      );
                    })}
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <input
                      type="text"
                      data-testid="table-custom-tag-input"
                      value={tableCustomTagInput}
                      onChange={(e) => setTableCustomTagInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault();
                          if (tableCustomTagInput.trim()) {
                            handleAddTag(tableTaggingIndicator, tableCustomTagInput);
                            setTableCustomTagInput('');
                          }
                        } else if (e.key === 'Escape') {
                          setTableTaggingIndicator(null);
                          setTableCustomTagInput('');
                        }
                      }}
                      placeholder="Enter custom label (e.g. Apt29, False Positive, Triage)"
                      aria-label={`Custom tag for ${tableTaggingIndicator}`}
                      className="min-w-[210px] flex-1 rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:outline-none"
                    />
                    <button
                      type="button"
                      data-testid="table-submit-tag-button"
                      disabled={!tableCustomTagInput.trim()}
                      onClick={() => {
                        if (tableCustomTagInput.trim()) {
                          handleAddTag(tableTaggingIndicator, tableCustomTagInput);
                          setTableCustomTagInput('');
                        }
                      }}
                      className="rounded-md bg-slate-900 dark:bg-slate-100 px-3 py-1 text-xs font-semibold text-white dark:text-slate-950 hover:bg-slate-800 dark:hover:bg-slate-200 disabled:opacity-40 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Save Tag
                    </button>
                  </div>
                </div>
              )}
            </div>

            {isBulkMode && bulkTableStyle === 'unified' ? (
              <div className="overflow-x-auto print:overflow-visible">
                <table
                  data-testid="bulk-batch-results-table"
                  className="w-full text-left text-sm print:text-xs"
                >
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/60 text-xs font-semibold text-slate-600 dark:text-slate-300">
                      <SortableColumnHeader
                        label="Indicator"
                        sortKey="indicator"
                        sortState={tableSort}
                        onSort={handleToggleTableSort}
                        className="pl-3.5 pr-2 py-2.5 min-w-[140px]"
                      />
                      <SortableColumnHeader
                        label="Type"
                        sortKey="type"
                        sortState={tableSort}
                        onSort={handleToggleTableSort}
                        className="px-2 py-2.5"
                      />
                      <SortableColumnHeader
                        label="Verdict"
                        sortKey="verdict"
                        sortState={tableSort}
                        onSort={handleToggleTableSort}
                        className="px-2 py-2.5"
                      />
                      <SortableColumnHeader
                        label="Risk Score"
                        sortKey="riskScore"
                        sortState={tableSort}
                        onSort={handleToggleTableSort}
                        align="right"
                        title="Sort by weighted threat risk confidence score (0-100)"
                        className="px-2 py-2.5 text-right whitespace-nowrap"
                      />
                      <th className="px-2 py-2.5 whitespace-nowrap" title="Historical threat confidence trend across runs">
                        Trend
                      </th>
                      <SortableColumnHeader
                        label="Last Seen"
                        sortKey="lastSeen"
                        sortState={tableSort}
                        onSort={handleToggleTableSort}
                        title="Sort by latest observed threat intelligence timestamp (UTC)"
                        className="px-2 py-2.5 whitespace-nowrap"
                      />
                      {unifiedBatchTable.providerColumns.map((col) => (
                        <th key={col.sourceId} className="px-2 py-2.5 whitespace-nowrap">
                          {col.source === 'AlienVault OTX' ? 'OTX' : col.source}
                        </th>
                      ))}
                      <SortableColumnHeader
                        label="Hits"
                        sortKey="hits"
                        sortState={tableSort}
                        onSort={handleToggleTableSort}
                        align="right"
                        className="px-2 py-2.5 text-right whitespace-nowrap"
                      />
                      <th className="pl-2 pr-3.5 py-2.5 text-right print:hidden">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {sortedUnifiedBatchRows.map((row) => {
                      const batchRowKey = `batch:${row.indicator}`;
                      const batchValKey = `batch-val:${row.indicator}`;
                      const isBatchCopied = copiedKey === batchRowKey;
                      const isBatchValueCopied = copiedKey === batchValKey;
                      const confTone = getConfidenceToneClass(row.riskLevel);
                      const trend = confidenceTrends.get(row.indicator.trim().toLowerCase());
                      const rowLastSeen = lastSeenByIndicator.get(row.indicator.trim().toLowerCase());
                      const isRowTagOpen = tableTaggingIndicator === row.indicator;
                      return (
                        <tr
                          key={batchRowKey}
                          data-testid="bulk-batch-row"
                          className="hover:bg-slate-50/70 dark:hover:bg-slate-800/50"
                        >
                          <td className="pl-3.5 pr-2 py-2.5 min-w-[140px] max-w-[185px] font-mono text-xs font-medium text-slate-900 dark:text-slate-100">
                            <div className="flex items-start gap-1.5">
                              <span className="break-all">{row.indicator}</span>
                              <button
                                type="button"
                                data-testid="copy-indicator-value-btn"
                                data-copied={isBatchValueCopied ? 'true' : 'false'}
                                onClick={() => triggerClipboardCopy(row.indicator, batchValKey)}
                                aria-label={`Copy indicator value ${row.indicator} to clipboard`}
                                title={isBatchValueCopied ? `Copied ${row.indicator}` : `Copy ${row.indicator} to clipboard`}
                                className={`mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded border transition-colors cursor-pointer print:hidden ${
                                  isBatchValueCopied
                                    ? 'border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300'
                                    : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-500 dark:text-slate-400 hover:border-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
                                }`}
                              >
                                {isBatchValueCopied ? (
                                  <Check className="h-3 w-3" aria-hidden="true" />
                                ) : (
                                  <ClipboardCopy className="h-3 w-3" aria-hidden="true" />
                                )}
                              </button>
                            </div>
                            <div className="mt-1.5 flex flex-wrap items-center gap-1 font-sans">
                              {row.tags.map((tag) => (
                                <span
                                  key={tag}
                                  data-testid="table-assigned-tag"
                                  className="inline-flex items-center gap-1 whitespace-nowrap rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/70 px-1.5 py-0.5 text-[10px] font-medium text-slate-700 dark:text-slate-200"
                                >
                                  <span>{tag}</span>
                                  <button
                                    type="button"
                                    data-testid="row-remove-tag-btn"
                                    onClick={() => handleRemoveTag(row.indicator, tag)}
                                    aria-label={`Remove tag ${tag} from ${row.indicator}`}
                                    className="text-slate-400 hover:text-red-600 dark:hover:text-red-400 cursor-pointer print:hidden"
                                  >
                                    <X className="h-2.5 w-2.5" aria-hidden="true" />
                                  </button>
                                </span>
                              ))}
                              <button
                                type="button"
                                data-testid="row-add-tag-button"
                                aria-expanded={isRowTagOpen}
                                onClick={() => {
                                  setTableTaggingIndicator(isRowTagOpen ? null : row.indicator);
                                  setTableCustomTagInput('');
                                }}
                                className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer print:hidden ${
                                  isRowTagOpen
                                    ? 'border-slate-900 dark:border-slate-100 bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-950'
                                    : 'border-dashed border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:border-slate-400 dark:hover:border-slate-500'
                                }`}
                              >
                                <Tag className="h-2.5 w-2.5" aria-hidden="true" />
                                <span>+ Tag</span>
                              </button>
                              {(() => {
                                const isWatched = isWatchlistIndicator(watchlistItems, row.indicator);
                                return (
                                  <button
                                    type="button"
                                    data-testid="row-watch-toggle-btn"
                                    aria-pressed={isWatched}
                                    aria-label={
                                      isWatched
                                        ? `Remove ${row.indicator} from Watchlist`
                                        : `Add ${row.indicator} to Watchlist`
                                    }
                                    onClick={() =>
                                      handleToggleWatchIoc(
                                        row.indicator,
                                        row.type,
                                        row.overallVerdict,
                                        row.confidenceScore,
                                      )
                                    }
                                    className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer print:hidden ${
                                      isWatched
                                        ? 'border-red-300 dark:border-red-800 bg-red-50/70 dark:bg-red-950/40 text-red-700 dark:text-red-300'
                                        : 'border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:border-slate-400 dark:hover:border-slate-500'
                                    }`}
                                  >
                                    <Eye className="h-2.5 w-2.5" aria-hidden="true" />
                                    <span>{isWatched ? 'Watching' : 'Watch'}</span>
                                  </button>
                                );
                              })()}
                            </div>
                          </td>
                          <td className="px-2.5 py-3 font-mono text-xs uppercase text-slate-500 dark:text-slate-400 whitespace-nowrap">
                            {row.type}
                          </td>
                          <td className="px-2.5 py-3 whitespace-nowrap">
                            <VerdictIndicator verdict={row.overallVerdict} status="ok" />
                          </td>
                          <td
                            className="px-2.5 py-3 text-right whitespace-nowrap"
                            title={row.confidenceExplanation || 'No active scores'}
                          >
                            {row.confidenceScore !== null ? (
                              <div className="inline-flex items-baseline gap-1 font-mono text-xs tabular-nums">
                                <span className={`font-semibold ${confTone}`}>
                                  {row.confidenceScore}/100
                                </span>
                                <span className="font-sans text-[11px] font-medium text-slate-500 dark:text-slate-400">
                                  {row.riskLevel}
                                </span>
                              </div>
                            ) : (
                              <span className="font-mono text-xs text-slate-400 dark:text-slate-500">—</span>
                            )}
                          </td>
                          <td className="px-2.5 py-3 whitespace-nowrap">
                            <ConfidenceSparkline indicator={row.indicator} trend={trend} />
                          </td>
                          <td
                            data-testid="batch-last-seen-cell"
                            title={rowLastSeen?.fieldLabel ? `${rowLastSeen.fieldLabel}: ${rowLastSeen.displayUtc}` : 'No observation timestamp available'}
                            className="px-2.5 py-3 font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums whitespace-nowrap"
                          >
                            {rowLastSeen?.displayUtc ?? '—'}
                          </td>
                          {unifiedBatchTable.providerColumns.map((col) => {
                            const cell = row.providerCells[col.sourceId];
                            if (!cell) {
                              return (
                                <td
                                  key={col.sourceId}
                                  className="px-2.5 py-3 font-mono text-xs text-slate-400 dark:text-slate-500 whitespace-nowrap"
                                >
                                  —
                                </td>
                              );
                            }
                            return (
                              <td
                                key={col.sourceId}
                                className="px-2.5 py-3 whitespace-nowrap"
                                title={cell.summary}
                              >
                                <div className="space-y-0.5">
                                  <VerdictIndicator verdict={cell.verdict} status={cell.status} />
                                  {cell.score && cell.score !== 'N/A' && (
                                    <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                                      {cell.score}
                                    </div>
                                  )}
                                </div>
                              </td>
                            );
                          })}
                          <td className="px-2.5 py-3 text-right font-mono text-xs text-slate-700 dark:text-slate-300 tabular-nums whitespace-nowrap">
                            {row.maliciousHits + row.suspiciousHits}/{row.respondedCount}
                          </td>
                          <td className="pl-2.5 pr-4 py-3 text-right whitespace-nowrap print:hidden">
                            <button
                              type="button"
                              data-testid="copy-ioc-button"
                              onClick={() =>
                                triggerClipboardCopy(
                                  formatUnifiedBatchRowClipboard(
                                    row,
                                    unifiedBatchTable.providerColumns,
                                  ),
                                  batchRowKey,
                                )
                              }
                              aria-label={`Copy unified batch summary for ${row.indicator}`}
                              className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                                isBatchCopied
                                  ? 'border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300'
                                  : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700'
                              }`}
                            >
                              {isBatchCopied ? (
                                <>
                                  <Check className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                                  Copied
                                </>
                              ) : (
                                <>
                                  <Copy className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                                  Copy
                                </>
                              )}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                    {sortedUnifiedBatchRows.length === 0 && (
                      <tr>
                        <td
                          colSpan={8 + unifiedBatchTable.providerColumns.length}
                          className="px-6 py-8 text-center text-sm text-slate-500 dark:text-slate-400"
                        >
                          No indicators match the active verdict or tag filters.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            ) : (
            <div className="overflow-x-auto print:overflow-visible">
              <table data-testid="summary-matrix-table" className="w-full text-left text-xs print:text-[11px]">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/60 text-[11px] font-semibold text-slate-600 dark:text-slate-300">
                    <SortableColumnHeader
                      label="Indicator"
                      sortKey="indicator"
                      sortState={tableSort}
                      onSort={handleToggleTableSort}
                      className="pl-2.5 pr-1 py-2.5 min-w-[118px]"
                    />
                    <SortableColumnHeader
                      label="Type"
                      sortKey="type"
                      sortState={tableSort}
                      onSort={handleToggleTableSort}
                      className="px-1 py-2.5"
                    />
                    <SortableColumnHeader
                      label="Source"
                      sortKey="source"
                      sortState={tableSort}
                      onSort={handleToggleTableSort}
                      className="px-1 py-2.5"
                    />
                    <SortableColumnHeader
                      label="Verdict"
                      sortKey="verdict"
                      sortState={tableSort}
                      onSort={handleToggleTableSort}
                      className="px-1 py-2.5"
                    />
                    <SortableColumnHeader
                      label="Risk Score"
                      sortKey="riskScore"
                      sortState={tableSort}
                      onSort={handleToggleTableSort}
                      align="right"
                      title="Weighted Confidence Risk Score (0-100)"
                      className="px-1 py-2.5 text-right whitespace-nowrap"
                    />
                    <th className="px-1 py-2.5 whitespace-nowrap" title="Historical threat confidence trend across runs">
                      Trend
                    </th>
                    <SortableColumnHeader
                      label="Last Seen"
                      sortKey="lastSeen"
                      sortState={tableSort}
                      onSort={handleToggleTableSort}
                      title="Latest observation, abuse report, or scan timestamp (UTC)"
                      className="px-1 py-2.5 whitespace-nowrap"
                    />
                    <SortableColumnHeader
                      label="Score"
                      sortKey="score"
                      sortState={tableSort}
                      onSort={handleToggleTableSort}
                      align="right"
                      className="px-1 py-2.5 text-right"
                    />
                    <th className="px-1 py-2.5">Summary</th>
                    <th className="pl-1 pr-2.5 py-2.5 text-right print:hidden">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {sortedResults.map((r, i) => {
                    const rowKey = `row:${r.indicator}:${r.sourceId}:${i}`;
                    const valCopyKey = `row-val:${r.indicator}:${r.sourceId}:${i}`;
                    const isCopied = copiedKey === rowKey;
                    const isValueCopied = copiedKey === valCopyKey;
                    const confidence = confidenceByIndicator.get(r.indicator.trim().toLowerCase());
                    const trend = confidenceTrends.get(r.indicator.trim().toLowerCase());
                    const lastSeen = extractResultLastSeen(r);
                    const lastSeenParts =
                      lastSeen.displayUtc === '—' ? null : lastSeen.displayUtc.replace(' UTC', 'Z').split(' ');
                    const rowTags = getTagsForIndicator(indicatorTags, r.indicator);
                    const confTone = getConfidenceToneClass(confidence?.riskLevel ?? 'Unknown');
                    const isRowTagOpen = tableTaggingIndicator === r.indicator;
                    return (
                      <tr key={rowKey} data-testid="summary-matrix-row" className="hover:bg-slate-50/70 dark:hover:bg-slate-800/50">
                        <td className="pl-2.5 pr-1 py-2.5 min-w-[118px] max-w-[150px] font-mono text-xs font-medium text-slate-900 dark:text-slate-100">
                          <div className="flex items-start gap-1.5">
                            <span className="break-all">{r.indicator}</span>
                            <button
                              type="button"
                              data-testid="copy-indicator-value-btn"
                              data-copied={isValueCopied ? 'true' : 'false'}
                              onClick={() => triggerClipboardCopy(r.indicator, valCopyKey)}
                              aria-label={`Copy indicator value ${r.indicator} to clipboard`}
                              title={isValueCopied ? `Copied ${r.indicator}` : `Copy ${r.indicator} to clipboard`}
                              className={`mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded border transition-colors cursor-pointer print:hidden ${
                                isValueCopied
                                  ? 'border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300'
                                  : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-500 dark:text-slate-400 hover:border-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
                              }`}
                            >
                              {isValueCopied ? (
                                <Check className="h-3 w-3" aria-hidden="true" />
                              ) : (
                                <ClipboardCopy className="h-3 w-3" aria-hidden="true" />
                              )}
                            </button>
                          </div>
                          <div className="mt-1.5 flex flex-wrap items-center gap-1 font-sans">
                            {rowTags.map((tag) => (
                              <span
                                key={tag}
                                data-testid="table-assigned-tag"
                                className="inline-flex items-center gap-1 whitespace-nowrap rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/70 px-1.5 py-0.5 text-[10px] font-medium text-slate-700 dark:text-slate-200"
                              >
                                <span>{tag}</span>
                                <button
                                  type="button"
                                  data-testid="row-remove-tag-btn"
                                  onClick={() => handleRemoveTag(r.indicator, tag)}
                                  aria-label={`Remove tag ${tag} from ${r.indicator}`}
                                  className="text-slate-400 hover:text-red-600 dark:hover:text-red-400 cursor-pointer print:hidden"
                                >
                                  <X className="h-2.5 w-2.5" aria-hidden="true" />
                                </button>
                              </span>
                            ))}
                            <button
                              type="button"
                              data-testid="row-add-tag-button"
                              aria-expanded={isRowTagOpen}
                              onClick={() => {
                                setTableTaggingIndicator(isRowTagOpen ? null : r.indicator);
                                setTableCustomTagInput('');
                              }}
                              className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer print:hidden ${
                                isRowTagOpen
                                  ? 'border-slate-900 dark:border-slate-100 bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-950'
                                  : 'border-dashed border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:border-slate-400 dark:hover:border-slate-500'
                              }`}
                            >
                              <Tag className="h-2.5 w-2.5" aria-hidden="true" />
                              <span>+ Tag</span>
                            </button>
                            {(() => {
                              const key = r.indicator.trim().toLowerCase();
                              const isWatched = isWatchlistIndicator(watchlistItems, r.indicator);
                              const rowOverallVerdict =
                                overallVerdictByIndicator.get(key) ?? (r.status === 'ok' ? r.verdict : null);
                              return (
                                <button
                                  type="button"
                                  data-testid="row-watch-toggle-btn"
                                  aria-pressed={isWatched}
                                  aria-label={
                                    isWatched
                                      ? `Remove ${r.indicator} from Watchlist`
                                      : `Add ${r.indicator} to Watchlist`
                                  }
                                  onClick={() =>
                                    handleToggleWatchIoc(
                                      r.indicator,
                                      r.type,
                                      rowOverallVerdict,
                                      confidence?.confidenceScore ?? null,
                                    )
                                  }
                                  className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer print:hidden ${
                                    isWatched
                                      ? 'border-red-300 dark:border-red-800 bg-red-50/70 dark:bg-red-950/40 text-red-700 dark:text-red-300'
                                      : 'border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:border-slate-400 dark:hover:border-slate-500'
                                  }`}
                                >
                                  <Eye className="h-2.5 w-2.5" aria-hidden="true" />
                                  <span>{isWatched ? 'Watching' : 'Watch'}</span>
                                </button>
                              );
                            })()}
                          </div>
                        </td>
                        <td className="px-1 py-2.5 font-mono text-[11px] uppercase text-slate-500 dark:text-slate-400 whitespace-nowrap">{r.type}</td>
                        <td className="px-1 py-2.5 text-xs font-medium text-slate-800 dark:text-slate-200 whitespace-nowrap">
                          {r.source === 'AlienVault OTX' ? 'OTX' : r.source}
                        </td>
                        <td className="px-1 py-2.5 whitespace-nowrap">
                          <VerdictIndicator verdict={r.verdict} status={r.status} />
                        </td>
                        <td
                          className="px-1 py-2.5 text-right whitespace-nowrap"
                          title={confidence?.explanation || 'No active scores'}
                        >
                          {confidence && confidence.confidenceScore !== null ? (
                            <div className="inline-flex flex-col items-end leading-tight">
                              <span className={`font-mono text-xs font-semibold tabular-nums ${confTone}`}>
                                {confidence.confidenceScore}/100
                              </span>
                              <span className="font-sans text-[10px] font-medium text-slate-500 dark:text-slate-400">
                                {confidence.riskLevel}
                              </span>
                            </div>
                          ) : (
                            <span className="font-mono text-xs text-slate-400 dark:text-slate-500">—</span>
                          )}
                        </td>
                        <td className="px-1 py-2.5 whitespace-nowrap">
                          <ConfidenceSparkline indicator={r.indicator} trend={trend} />
                        </td>
                        <td
                          data-testid="summary-last-seen-cell"
                          title={lastSeen.fieldLabel ? `${lastSeen.fieldLabel}: ${lastSeen.displayUtc}` : 'No observation timestamp available'}
                          className="px-1 py-2.5 font-mono text-[10px] leading-tight text-slate-500 dark:text-slate-400 tabular-nums whitespace-nowrap"
                        >
                          {lastSeenParts ? (
                            <div className="flex flex-col">
                              <span>{lastSeenParts[0]}</span>
                              {lastSeenParts[1] && (
                                <span className="text-slate-400 dark:text-slate-500">{lastSeenParts[1]}</span>
                              )}
                            </div>
                          ) : (
                            '—'
                          )}
                        </td>
                        <td className="px-1 py-2.5 text-right font-mono text-xs text-slate-900 dark:text-slate-100 tabular-nums whitespace-nowrap">
                          {r.score}
                        </td>
                        <td className="px-1 py-2.5 text-[11px] text-slate-600 dark:text-slate-300 max-w-[116px] leading-snug">{r.summary}</td>
                        <td className="pl-1 pr-2.5 py-2.5 text-right whitespace-nowrap print:hidden">
                          <button
                            type="button"
                            data-testid="copy-ioc-button"
                            onClick={() => triggerClipboardCopy(formatIocClipboardText(r), rowKey)}
                            aria-label={`Copy ${r.indicator} (${r.source}) to clipboard`}
                            title="Copy to clipboard"
                            className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-1 text-[11px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                              isCopied
                                ? 'border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300'
                                : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700'
                            }`}
                          >
                            {isCopied ? (
                              <>
                                <Check className="h-3 w-3 shrink-0" aria-hidden="true" />
                                Copied
                              </>
                            ) : (
                              <>
                                <Copy className="h-3 w-3 shrink-0" aria-hidden="true" />
                                Copy
                              </>
                            )}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                  {sortedResults.length === 0 && (
                    <tr>
                      <td colSpan={10} className="px-6 py-8 text-center text-sm text-slate-500 dark:text-slate-400">
                        No results match the active verdict or tag filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            )}
          </div>

          <section
            aria-label="Researcher Notes"
            data-testid="researcher-notes-section"
            className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 md:p-6"
          >
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <FilePenLine className="h-4 w-4 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />
                  <label
                    htmlFor="researcher-notes-input"
                    className="text-base font-semibold text-slate-950 dark:text-slate-50"
                  >
                    Researcher Notes
                  </label>
                </div>
                <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                  Record triage findings, correlated TTPs, or containment decisions. Auto-saved periodically to local storage without manual save.
                </p>
              </div>

              <div className="flex items-center gap-3 text-xs shrink-0">
                {hasPendingAutoSave ? (
                  <span
                    data-testid="researcher-notes-status"
                    role="status"
                    aria-live="polite"
                    className="font-medium text-amber-700 dark:text-amber-400"
                  >
                    Auto-saving to local storage...
                  </span>
                ) : normalizedDraftNotes.length > 0 ? (
                  <span
                    data-testid="researcher-notes-status"
                    role="status"
                    aria-live="polite"
                    className="inline-flex items-center gap-1 font-medium text-emerald-700 dark:text-emerald-400"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                    <span>
                      Auto-saved to local storage
                      {lastAutoSavedTimeLabel ? ` · ${lastAutoSavedTimeLabel}` : ''}
                    </span>
                  </span>
                ) : notesSaveStatus === 'saved' ? (
                  <span
                    data-testid="researcher-notes-status"
                    role="status"
                    aria-live="polite"
                    className="font-medium text-slate-500 dark:text-slate-400"
                  >
                    Notes cleared
                  </span>
                ) : (
                  <span
                    data-testid="researcher-notes-status"
                    className="text-slate-500 dark:text-slate-400"
                  >
                    Auto-save ready (every 3s)
                  </span>
                )}

                <span className="font-mono text-[11px] text-slate-400 dark:text-slate-500 tabular-nums print:hidden">
                  {state.researcherNotes.length}/{MAX_INVESTIGATION_NOTES_LENGTH}
                </span>
              </div>
            </div>

            <textarea
              id="researcher-notes-input"
              data-testid="researcher-notes-textarea"
              rows={3}
              maxLength={MAX_INVESTIGATION_NOTES_LENGTH}
              value={state.researcherNotes}
              onChange={(e) => {
                const nextVal = e.target.value;
                setNotesSaveStatus('idle');
                onChangeState((prev) => ({ ...prev, researcherNotes: nextVal }));
              }}
              onBlur={() => {
                if (hasPendingAutoSave) {
                  persistNotesToHistory(activeHistoryId, state.researcherNotes);
                }
              }}
              placeholder="Document malware family attribution, passive DNS pivots, affected hosts, or containment actions..."
              className="mt-3 w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/50 dark:bg-slate-950/60 px-3.5 py-2.5 text-sm leading-relaxed text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-950 focus:outline-none print:hidden"
            />

            <div
              data-testid="researcher-notes-print-body"
              className="hidden print:block mt-3 whitespace-pre-wrap rounded-lg border border-slate-200 bg-slate-50/40 px-3.5 py-2.5 text-sm leading-relaxed text-slate-900"
            >
              {state.researcherNotes.trim() || 'No researcher notes recorded for this investigation.'}
            </div>

            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 print:hidden">
              <span className="text-[11px] text-slate-500 dark:text-slate-400">
                {activeHistoryEntry
                  ? `Synced to local storage & history entry: ${activeHistoryEntry.indicators.slice(0, 2).join(', ')}${activeHistoryEntry.indicators.length > 2 ? ` +${activeHistoryEntry.indicators.length - 2}` : ''}`
                  : 'Persists automatically to browser local storage every 3s.'}
              </span>

              <div className="flex items-center gap-2 shrink-0">
                {state.researcherNotes.trim().length > 0 && (
                  <button
                    type="button"
                    data-testid="clear-researcher-notes-btn"
                    onClick={() => {
                      onChangeState((prev) => ({ ...prev, researcherNotes: '' }));
                      persistNotesToHistory(activeHistoryId, '');
                    }}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    Clear
                  </button>
                )}

                <button
                  type="button"
                  data-testid="save-researcher-notes-btn"
                  disabled={!hasPendingAutoSave}
                  onClick={() => persistNotesToHistory(activeHistoryId, state.researcherNotes)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-45 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
                >
                  <Save className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  <span>{hasPendingAutoSave ? 'Save Now' : 'Synced'}</span>
                </button>
              </div>
            </div>
          </section>

          <IocEventTimeline results={state.results} />

          <IocNetworkGraph
            results={filteredResults}
            theme={theme}
            focusedIndicator={graphFocusedIndicator}
            onFocusIndicatorChange={setGraphFocusedIndicator}
          />

          <div className="space-y-6">
            {groupedByIndicator.map((group) => {
              const groupKey = `group:${group.indicator}`;
              const isGroupCopied = copiedKey === groupKey;
              const confidence = confidenceByIndicator.get(group.indicator.trim().toLowerCase());
              const confTone = getConfidenceToneClass(confidence?.riskLevel ?? 'Unknown');
              const iocTags = getTagsForIndicator(indicatorTags, group.indicator);
              const isTagComposerOpen = taggingIndicator === group.indicator;
              return (
              <div key={group.indicator} data-testid="ioc-result-card" className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 md:p-6">
                <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 dark:border-slate-800 pb-4">
                  <div className="min-w-0 space-y-2">
                    <div className="flex flex-wrap items-baseline gap-3">
                      <h3 className="font-mono text-base font-semibold text-slate-950 dark:text-slate-50 break-all">
                        {group.indicator}
                      </h3>
                      <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{group.type}</span>
                    </div>

                    <div
                      data-testid="ioc-card-tags"
                      className="flex flex-wrap items-center gap-1.5"
                    >
                      {iocTags.map((tag) => (
                        <span
                          key={tag}
                          data-testid="ioc-assigned-tag"
                          className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 px-2 py-0.5 text-[11px] font-medium text-slate-700 dark:text-slate-200"
                        >
                          <Tag className="h-3 w-3 text-slate-400 dark:text-slate-500" aria-hidden="true" />
                          <span>{tag}</span>
                          <button
                            type="button"
                            onClick={() => handleRemoveTag(group.indicator, tag)}
                            aria-label={`Remove tag ${tag} from ${group.indicator}`}
                            className="ml-0.5 rounded text-slate-400 hover:text-red-600 dark:hover:text-red-400 cursor-pointer print:hidden"
                          >
                            <X className="h-3 w-3" aria-hidden="true" />
                          </button>
                        </span>
                      ))}
                      <button
                        type="button"
                        data-testid="add-tag-button"
                        aria-expanded={isTagComposerOpen}
                        onClick={() => {
                          if (isTagComposerOpen) {
                            setTaggingIndicator(null);
                            setCustomTagInput('');
                          } else {
                            setTaggingIndicator(group.indicator);
                            setCustomTagInput('');
                          }
                        }}
                        className="inline-flex items-center gap-1 rounded-md border border-dashed border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-0.5 text-[11px] font-medium text-slate-600 dark:text-slate-300 hover:border-slate-400 dark:hover:border-slate-500 hover:text-slate-950 dark:hover:text-white whitespace-nowrap shrink-0 cursor-pointer print:hidden"
                      >
                        <Tag className="h-3 w-3" aria-hidden="true" />
                        <span>Add Tag</span>
                      </button>
                      {(() => {
                        const key = group.indicator.trim().toLowerCase();
                        const isWatched = isWatchlistIndicator(watchlistItems, group.indicator);
                        const cardVerdict = overallVerdictByIndicator.get(key) ?? null;
                        return (
                          <button
                            type="button"
                            data-testid="card-watch-toggle-btn"
                            aria-pressed={isWatched}
                            aria-label={
                              isWatched
                                ? `Remove ${group.indicator} from Watchlist`
                                : `Add ${group.indicator} to Watchlist`
                            }
                            onClick={() =>
                              handleToggleWatchIoc(
                                group.indicator,
                                group.type as IndicatorType,
                                cardVerdict,
                                confidence?.confidenceScore ?? null,
                              )
                            }
                            className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer print:hidden ${
                              isWatched
                                ? 'border-red-300 dark:border-red-800 bg-red-50/70 dark:bg-red-950/40 text-red-700 dark:text-red-300'
                                : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:border-slate-400 dark:hover:border-slate-500'
                            }`}
                          >
                            <Eye className="h-3 w-3" aria-hidden="true" />
                            <span>{isWatched ? 'Watching' : 'Watch'}</span>
                          </button>
                        );
                      })()}
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-4 shrink-0">
                    {confidence && (
                      <div
                        data-testid="ioc-confidence-score"
                        title={confidence.explanation}
                        className="text-right"
                      >
                        <div className="text-[11px] font-medium text-slate-500 dark:text-slate-400">
                          Confidence Score
                        </div>
                        <div className="font-mono text-sm font-bold tabular-nums">
                          {confidence.confidenceScore !== null ? (
                            <>
                              <span className={confTone}>{confidence.confidenceScore}/100</span>
                              <span className="ml-1.5 font-sans text-xs font-semibold text-slate-700 dark:text-slate-300">
                                · {confidence.riskLevel}
                              </span>
                            </>
                          ) : (
                            <span className="text-slate-400 dark:text-slate-500">N/A</span>
                          )}
                        </div>
                      </div>
                    )}

                    <span className="text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {group.items.length} source{group.items.length === 1 ? '' : 's'}
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        triggerClipboardCopy(
                          formatIocGroupClipboardText(group.indicator, group.type, group.items),
                          groupKey,
                        )
                      }
                      aria-label={`Copy full summary for ${group.indicator} to clipboard`}
                      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer print:hidden ${
                        isGroupCopied
                          ? 'border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300'
                          : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700'
                      }`}
                    >
                      {isGroupCopied ? (
                        <>
                          <Check className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                          Copied
                        </>
                      ) : (
                        <>
                          <Copy className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                          Copy IOC
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {isTagComposerOpen && (
                  <div
                    data-testid="tag-composer"
                    className="mt-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-800/60 p-3 space-y-2.5"
                  >
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400 mr-1">
                        Quick labels:
                      </span>
                      {SUGGESTED_IOC_TAGS.map((preset) => {
                        const alreadyTagged = iocTags.some(
                          (t) => t.toLowerCase() === preset.toLowerCase(),
                        );
                        return (
                          <button
                            key={preset}
                            type="button"
                            data-testid={`preset-tag-${preset.toLowerCase().replace(/\s+/g, '-')}`}
                            onClick={() => {
                              if (alreadyTagged) {
                                handleRemoveTag(group.indicator, preset);
                              } else {
                                handleAddTag(group.indicator, preset);
                              }
                            }}
                            className={`rounded-md border px-2 py-0.5 text-[11px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                              alreadyTagged
                                ? 'border-slate-900 dark:border-slate-100 bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-950'
                                : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800'
                            }`}
                          >
                            {alreadyTagged ? `✓ ${preset}` : `+ ${preset}`}
                          </button>
                        );
                      })}
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <input
                        type="text"
                        data-testid="custom-tag-input"
                        value={customTagInput}
                        onChange={(e) => setCustomTagInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            e.preventDefault();
                            if (customTagInput.trim()) {
                              handleAddTag(group.indicator, customTagInput);
                              setCustomTagInput('');
                            }
                          } else if (e.key === 'Escape') {
                            setTaggingIndicator(null);
                            setCustomTagInput('');
                          }
                        }}
                        placeholder="Enter custom tag (e.g. Apt29, Exfiltration)"
                        aria-label={`Custom tag for ${group.indicator}`}
                        className="min-w-[210px] flex-1 rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:outline-none"
                      />
                      <button
                        type="button"
                        data-testid="submit-tag-button"
                        disabled={!customTagInput.trim()}
                        onClick={() => {
                          if (customTagInput.trim()) {
                            handleAddTag(group.indicator, customTagInput);
                            setCustomTagInput('');
                          }
                        }}
                        className="rounded-md bg-slate-900 dark:bg-slate-100 px-3 py-1 text-xs font-semibold text-white dark:text-slate-950 hover:bg-slate-800 dark:hover:bg-slate-200 disabled:opacity-40 whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Save Tag
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setTaggingIndicator(null);
                          setCustomTagInput('');
                        }}
                        className="rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Done
                      </button>
                    </div>
                  </div>
                )}

                {confidence && confidence.breakdown.length > 0 && (
                  <div
                    data-testid="ioc-confidence-breakdown"
                    className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500 dark:text-slate-400"
                  >
                    <span className="font-medium text-slate-700 dark:text-slate-300">
                      Weighted Risk ({confidence.activeProviderCount} active):
                    </span>
                    <span className="font-mono tabular-nums">{confidence.explanation}</span>
                  </div>
                )}

                <div className="mt-4 grid gap-6 md:grid-cols-3">
                  {group.items.map((item) => (
                    <div key={item.sourceId} className="space-y-3">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">{item.source}</span>
                        <VerdictIndicator verdict={item.verdict} status={item.status} />
                      </div>

                      <p className="text-xs text-slate-600 dark:text-slate-300">{item.summary}</p>

                      {Object.keys(item.details).length > 0 && (
                        <dl className="divide-y divide-slate-100 dark:divide-slate-800 border-t border-slate-100 dark:border-slate-800 text-xs">
                          {Object.entries(item.details).map(([k, v]) => (
                            <div key={k} className="flex items-baseline justify-between gap-4 py-1.5">
                              <dt className="text-slate-500 dark:text-slate-400 shrink-0">{k}</dt>
                              <dd className="text-right font-mono text-slate-800 dark:text-slate-200 tabular-nums break-all">
                                {String(v)}
                              </dd>
                            </div>
                          ))}
                        </dl>
                      )}

                      {item.link && (
                        <a
                          href={item.link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-xs font-medium text-red-700 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 hover:underline"
                        >
                          Open in {item.source}
                          <ExternalLink className="h-3 w-3" aria-hidden="true" />
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              </div>
              );
            })}
          </div>
        </div>
      ) : (
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-6 py-12 text-center">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">Ready to enrich indicators</h2>
          <p className="mx-auto mt-1.5 max-w-lg text-sm text-slate-600 dark:text-slate-400">
            Click Run Enrichment above to inspect the sample batch, paste your own IPs, domains, and hashes, or upload a CSV/TXT file for bulk feeds. Every run automatically saves a UTF-8 CSV report and writes audit logs.
          </p>
        </section>
      )}
        </div>

        <div className="lg:sticky lg:top-20 space-y-4 print:hidden">
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden">
            <div
              role="tablist"
              aria-label="Investigation sidebar views"
              data-testid="sidebar-tab-switcher"
              className="grid grid-cols-2 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40"
            >
              <button
                type="button"
                role="tab"
                aria-selected={sidebarTab === 'recent'}
                data-testid="sidebar-tab-recent"
                onClick={() => setSidebarTab('recent')}
                className={`flex items-center justify-center gap-1.5 px-3 py-2.5 text-xs font-semibold transition-colors cursor-pointer border-b-2 ${
                  sidebarTab === 'recent'
                    ? 'border-red-600 text-slate-950 dark:text-slate-50 bg-white dark:bg-slate-900'
                    : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                <Clock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span>Recent</span>
                <span className="font-mono text-[11px] font-normal text-slate-400 dark:text-slate-500 tabular-nums">
                  ({recentHistory.length})
                </span>
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={sidebarTab === 'watchlist'}
                data-testid="sidebar-tab-watchlist"
                onClick={() => setSidebarTab('watchlist')}
                className={`flex items-center justify-center gap-1.5 px-3 py-2.5 text-xs font-semibold transition-colors cursor-pointer border-b-2 ${
                  sidebarTab === 'watchlist'
                    ? 'border-red-600 text-slate-950 dark:text-slate-50 bg-white dark:bg-slate-900'
                    : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                <Eye className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span>Watchlist</span>
                <span className="font-mono text-[11px] font-normal text-slate-400 dark:text-slate-500 tabular-nums">
                  ({watchlistItems.length})
                </span>
                {unreadWatchlistCount > 0 && (
                  <span
                    data-testid="watchlist-notification-badge"
                    aria-label={`${unreadWatchlistCount} unread watchlist updates`}
                    className="inline-flex min-w-[18px] items-center justify-center rounded-full bg-red-600 px-1.5 py-0.5 font-mono text-[10px] font-bold leading-none text-white tabular-nums"
                  >
                    {unreadWatchlistCount}
                  </span>
                )}
              </button>
            </div>

            {sidebarTab === 'recent' ? (
              <RecentInvestigationsSidebar
                embedded
                entries={recentHistory}
                indicatorTags={indicatorTags}
                activeEntryId={activeHistoryId}
                selectedRegion={recentRegionFilter}
                onClearRegionFilter={onClearRecentRegionFilter}
                isRunning={loading}
                onViewDetails={handleViewRecentDetails}
                onRerun={handleRerunRecent}
                onTogglePinEntry={handleTogglePinRecent}
                onRenameEntry={handleRenameRecent}
                onRemoveEntry={handleRemoveRecent}
                onClearAll={handleClearRecent}
              />
            ) : (
              <WatchlistSidebarTab
                items={watchlistItems}
                isChecking={checkingWatchlist}
                lastCheckedUtc={watchlistLastCheckedUtc}
                onAddIndicator={handleAddToWatchlistFromSidebar}
                onRemoveIndicator={handleRemoveFromWatchlist}
                onCheckUpdatesNow={handleCheckWatchlistUpdates}
                onInspectIndicator={handleInspectFromWatchlist}
                onAcknowledgeItem={handleAcknowledgeWatchlistItem}
                onAcknowledgeAll={handleAcknowledgeAllWatchlist}
              />
            )}
          </div>

          <QuickNotesSidebarPanel
            variant="embedded"
            notesState={quickNotesState}
            onChangeText={onChangeQuickNotesText}
            onClearText={onClearQuickNotes}
            onToggleCollapse={onToggleQuickNotesCollapsed}
          />
        </div>
      </div>

      {snapshotModalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-[1px] print:hidden"
          role="dialog"
          aria-modal="true"
          aria-labelledby="session-snapshot-modal-title"
          data-testid="session-snapshot-modal"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setSnapshotModalOpen(false);
            }
          }}
        >
          <div className="w-full max-w-lg rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between gap-3 border-b border-slate-100 dark:border-slate-800 px-5 py-4">
              <div className="flex items-center gap-2 min-w-0">
                <Link2 className="h-4 w-4 shrink-0 text-red-600 dark:text-red-400" aria-hidden="true" />
                <h2
                  id="session-snapshot-modal-title"
                  className="text-base font-semibold text-slate-950 dark:text-slate-50"
                >
                  Shareable Session Snapshot
                </h2>
              </div>
              <button
                type="button"
                aria-label="Close session snapshot modal"
                onClick={() => setSnapshotModalOpen(false)}
                className="rounded-lg p-1 text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>

            <div className="space-y-4 px-5 py-4 text-xs">
              <p className="leading-relaxed text-slate-600 dark:text-slate-300">
                Your current investigation results, indicator tags, active Risk Threshold / verdict filters, table sort state, and Researcher Notes are serialized directly into this browser-only URL. Anyone opening it picks up right where you left off.
              </p>

              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-slate-600 dark:text-slate-300 tabular-nums">
                <span>{resultIndicatorsList.length} IOCs</span>
                <span>·</span>
                <span>{state.results.length} findings</span>
                <span>·</span>
                <span>Filter: {verdictFilter}</span>
                {riskThreshold > 0 && (
                  <>
                    <span>·</span>
                    <span>Min Risk: {riskThreshold}+</span>
                  </>
                )}
                <span>·</span>
                <span>Payload: {snapshotSizeLabel}</span>
              </div>

              {snapshotTruncated && (
                <div className="rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 px-3 py-2 text-[11px] text-amber-900 dark:text-amber-200">
                  Large batch detected — secondary metadata fields were trimmed to keep the browser URL compact while retaining all IOC verdicts, scores, tags, and notes.
                </div>
              )}

              <div className="space-y-1.5">
                <label
                  htmlFor="session-snapshot-url-input"
                  className="block font-medium text-slate-700 dark:text-slate-300"
                >
                  Shareable Browser Link
                </label>
                <div className="flex items-center gap-2">
                  <input
                    id="session-snapshot-url-input"
                    data-testid="session-snapshot-url-input"
                    type="text"
                    readOnly
                    value={snapshotUrl}
                    onFocus={(e) => e.currentTarget.select()}
                    className="flex-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 px-3 py-2 font-mono text-[11px] text-slate-800 dark:text-slate-200 focus:border-red-600 focus:outline-none"
                  />
                  <button
                    type="button"
                    data-testid="copy-session-snapshot-btn"
                    onClick={async () => {
                      const ok = await copyToClipboard(snapshotUrl);
                      if (ok) {
                        setSnapshotCopied(true);
                        window.setTimeout(() => setSnapshotCopied(false), 2000);
                      }
                    }}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-red-700 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    {snapshotCopied ? (
                      <>
                        <Check className="h-3.5 w-3.5" aria-hidden="true" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                        <span>Copy Link</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 px-5 py-3 text-xs">
              <button
                type="button"
                data-testid="apply-session-snapshot-url-btn"
                onClick={() => {
                  if (typeof window !== 'undefined' && snapshotUrl) {
                    window.history.replaceState({}, '', snapshotUrl);
                    setSnapshotCopied(true);
                    window.setTimeout(() => setSnapshotCopied(false), 1800);
                  }
                }}
                className="font-medium text-slate-700 dark:text-slate-300 hover:text-red-700 dark:hover:text-red-400 hover:underline cursor-pointer"
              >
                Update Address Bar URL
              </button>
              <button
                type="button"
                onClick={() => setSnapshotModalOpen(false)}
                className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
