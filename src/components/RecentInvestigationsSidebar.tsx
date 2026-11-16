import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronUp,
  Clock,
  Download,
  Eye,
  FileText,
  Filter,
  Globe,
  MoreVertical,
  Pencil,
  Pin,
  PinOff,
  RotateCw,
  Tag,
  Trash2,
  X,
} from 'lucide-react';
import {
  buildRecentHistoryExportFilename,
  formatInvestigationTitle,
  formatRelativeTime,
  getInvestigationDisplayTitle,
  getPrimaryVerdictBadge,
  serializeRecentHistoryExportJson,
  sortRecentInvestigations,
  type RecentInvestigationEntry,
} from '../utils/investigationHistory';
import {
  filterRecentInvestigationsByTag,
  getAllUniqueTags,
  getResolvedEntryTags,
  type IndicatorTagMap,
} from '../utils/iocTags';
import { filterRecentInvestigationsByRegion } from '../utils/heatmapAnalytics';

interface RecentInvestigationsSidebarProps {
  entries: RecentInvestigationEntry[];
  indicatorTags?: IndicatorTagMap;
  activeEntryId: string | null;
  selectedRegion?: string | null;
  onClearRegionFilter?: () => void;
  isRunning: boolean;
  onViewDetails: (entry: RecentInvestigationEntry) => void;
  onRerun: (entry: RecentInvestigationEntry) => void;
  onTogglePinEntry: (id: string) => void;
  onRenameEntry: (id: string, nextTitle: string) => void;
  onRemoveEntry: (id: string) => void;
  onClearAll: () => void;
  embedded?: boolean;
}

interface ContextMenuState {
  entryId: string;
  x: number;
  y: number;
}

function clampContextMenuPosition(x: number, y: number): { left: number; top: number } {
  const menuWidth = 192;
  const menuHeight = 144;
  if (typeof window === 'undefined') {
    return { left: x, top: y };
  }
  return {
    left: Math.max(8, Math.min(x, window.innerWidth - menuWidth - 8)),
    top: Math.max(8, Math.min(y, window.innerHeight - menuHeight - 8)),
  };
}

export function RecentInvestigationsSidebar({
  entries,
  indicatorTags = {},
  activeEntryId,
  selectedRegion = null,
  onClearRegionFilter,
  isRunning,
  onViewDetails,
  onRerun,
  onTogglePinEntry,
  onRenameEntry,
  onRemoveEntry,
  onClearAll,
  embedded = false,
}: RecentInvestigationsSidebarProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [selectedTag, setSelectedTag] = useState<string>('All');
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameDraft, setRenameDraft] = useState('');
  const [confirmClearOpen, setConfirmClearOpen] = useState(false);
  const [historyExported, setHistoryExported] = useState(false);

  const menuRef = useRef<HTMLDivElement | null>(null);
  const renameInputRef = useRef<HTMLInputElement | null>(null);
  const exportTimerRef = useRef<number | null>(null);

  const availableTags = useMemo(
    () => getAllUniqueTags(entries, indicatorTags),
    [entries, indicatorTags],
  );

  useEffect(() => {
    if (
      selectedTag !== 'All' &&
      !availableTags.some((t) => t.toLowerCase() === selectedTag.toLowerCase())
    ) {
      setSelectedTag('All');
    }
  }, [availableTags, selectedTag]);

  const orderedEntries = useMemo(() => sortRecentInvestigations(entries), [entries]);

  const hasRegionFilter = Boolean(selectedRegion && selectedRegion.trim() && selectedRegion.toLowerCase() !== 'all');

  const filteredEntries = useMemo(() => {
    const byTag = filterRecentInvestigationsByTag(orderedEntries, selectedTag, indicatorTags);
    return filterRecentInvestigationsByRegion(byTag, selectedRegion);
  }, [orderedEntries, selectedTag, indicatorTags, selectedRegion]);

  const contextMenuEntry = useMemo(
    () => (contextMenu ? entries.find((item) => item.id === contextMenu.entryId) ?? null : null),
    [contextMenu, entries],
  );

  useEffect(() => {
    if (contextMenu && !contextMenuEntry) {
      setContextMenu(null);
    }
  }, [contextMenu, contextMenuEntry]);

  useEffect(() => {
    if (renamingId && !entries.some((item) => item.id === renamingId)) {
      setRenamingId(null);
      setRenameDraft('');
    }
  }, [entries, renamingId]);

  useEffect(() => {
    if (!contextMenu) return;

    function handlePointerDown(event: PointerEvent) {
      if (menuRef.current && menuRef.current.contains(event.target as Node)) {
        return;
      }
      setContextMenu(null);
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setContextMenu(null);
      }
    }

    function handleCloseOnLayoutShift() {
      setContextMenu(null);
    }

    window.addEventListener('pointerdown', handlePointerDown);
    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('resize', handleCloseOnLayoutShift);
    window.addEventListener('scroll', handleCloseOnLayoutShift, true);

    return () => {
      window.removeEventListener('pointerdown', handlePointerDown);
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('resize', handleCloseOnLayoutShift);
      window.removeEventListener('scroll', handleCloseOnLayoutShift, true);
    };
  }, [contextMenu]);

  useEffect(() => {
    if (!renamingId) return;
    const id = window.requestAnimationFrame(() => {
      renameInputRef.current?.focus();
      renameInputRef.current?.select();
    });
    return () => window.cancelAnimationFrame(id);
  }, [renamingId]);

  useEffect(() => {
    if (!confirmClearOpen) return;
    function handleEsc(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setConfirmClearOpen(false);
      }
    }
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [confirmClearOpen]);

  useEffect(() => {
    return () => {
      if (exportTimerRef.current !== null) {
        window.clearTimeout(exportTimerRef.current);
      }
    };
  }, []);

  function handleExportHistory() {
    if (entries.length === 0) return;
    const now = new Date();
    const json = serializeRecentHistoryExportJson(orderedEntries, now);
    const filename = buildRecentHistoryExportFilename(now);
    const blob = new Blob([json], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    setHistoryExported(true);
    if (exportTimerRef.current !== null) {
      window.clearTimeout(exportTimerRef.current);
    }
    exportTimerRef.current = window.setTimeout(() => {
      setHistoryExported(false);
    }, 2000);
  }

  function handleConfirmClearHistory() {
    setExpandedId(null);
    setSelectedTag('All');
    onClearRegionFilter?.();
    setContextMenu(null);
    setRenamingId(null);
    setConfirmClearOpen(false);
    onClearAll();
  }

  function handleDetailsClick(entry: RecentInvestigationEntry) {
    setExpandedId((prev) => (prev === entry.id ? null : entry.id));
    onViewDetails(entry);
  }

  function handleToggleTagFilter(tag: string) {
    setSelectedTag((prev) => (prev.toLowerCase() === tag.toLowerCase() ? 'All' : tag));
  }

  function openMenuAt(entryId: string, clientX: number, clientY: number) {
    setContextMenu({ entryId, x: clientX, y: clientY });
  }

  function startRename(entry: RecentInvestigationEntry) {
    setContextMenu(null);
    setRenamingId(entry.id);
    setRenameDraft(getInvestigationDisplayTitle(entry));
  }

  function commitRename(entryId: string) {
    onRenameEntry(entryId, renameDraft);
    setRenamingId(null);
    setRenameDraft('');
  }

  function cancelRename() {
    setRenamingId(null);
    setRenameDraft('');
  }

  const clampedMenuPos = contextMenu
    ? clampContextMenuPosition(contextMenu.x, contextMenu.y)
    : null;

  return (
    <aside
      aria-label="Recent Investigations"
      data-testid="recent-investigations-sidebar"
      className={
        embedded
          ? 'overflow-hidden'
          : 'rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden'
      }
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 px-4 py-3.5">
        <div className="flex items-center gap-2 min-w-0">
          <Clock className="h-4 w-4 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-slate-950 dark:text-slate-50 truncate">
            Recent
          </h2>
          <span className="font-mono text-xs text-slate-500 dark:text-slate-400 tabular-nums shrink-0">
            ({selectedTag === 'All' && !hasRegionFilter ? entries.length : `${filteredEntries.length}/${entries.length}`})
          </span>
        </div>

        {entries.length > 0 && (
          <div className="flex items-center gap-1.5 shrink-0">
            <button
              type="button"
              data-testid="export-recent-history-btn"
              aria-label="Export recent investigation history as JSON"
              title="Download investigation IDs and timestamps as JSON"
              onClick={handleExportHistory}
              className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer"
            >
              {historyExported ? (
                <>
                  <Check className="h-3 w-3 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
                  <span>Exported</span>
                </>
              ) : (
                <>
                  <Download className="h-3 w-3" aria-hidden="true" />
                  <span>Export</span>
                </>
              )}
            </button>
            <button
              type="button"
              data-testid="clear-recent-investigations"
              aria-label="Clear recent investigation history"
              onClick={() => setConfirmClearOpen(true)}
              className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-1 text-[11px] font-medium text-slate-600 dark:text-slate-300 hover:border-red-300 dark:hover:border-red-800 hover:text-red-700 dark:hover:text-red-400 whitespace-nowrap shrink-0 cursor-pointer"
            >
              Clear History
            </button>
          </div>
        )}
      </div>

      {hasRegionFilter && selectedRegion && (
        <div
          data-testid="recent-region-filter-banner"
          className="flex items-center justify-between gap-2 border-b border-red-200 dark:border-red-900/60 bg-red-50/70 dark:bg-red-950/35 px-4 py-2 text-xs text-red-900 dark:text-red-200"
        >
          <span className="inline-flex items-center gap-1.5 min-w-0 font-medium">
            <Globe className="h-3.5 w-3.5 shrink-0 text-red-600 dark:text-red-400" aria-hidden="true" />
            <span className="truncate">Region: {selectedRegion}</span>
          </span>
          {onClearRegionFilter && (
            <button
              type="button"
              data-testid="clear-recent-region-filter"
              onClick={onClearRegionFilter}
              className="inline-flex items-center gap-0.5 text-[11px] font-semibold text-red-700 dark:text-red-300 hover:underline whitespace-nowrap shrink-0 cursor-pointer"
            >
              <X className="h-3 w-3" aria-hidden="true" />
              Reset
            </button>
          )}
        </div>
      )}

      {entries.length > 0 && availableTags.length > 0 && (
        <div
          data-testid="recent-tag-filter"
          className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-800/40 px-4 py-2.5 space-y-1.5"
        >
          <div className="flex items-center justify-between gap-2 text-[11px] font-medium text-slate-500 dark:text-slate-400">
            <span className="inline-flex items-center gap-1.5">
              <Filter className="h-3 w-3 shrink-0" aria-hidden="true" />
              <span>Filter by tag</span>
            </span>
            {selectedTag !== 'All' && (
              <button
                type="button"
                onClick={() => setSelectedTag('All')}
                className="inline-flex items-center gap-0.5 text-[11px] text-slate-600 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white hover:underline cursor-pointer"
              >
                <X className="h-3 w-3" aria-hidden="true" />
                Reset
              </button>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter recent investigations by tag">
            <button
              type="button"
              data-testid="tag-filter-option-all"
              onClick={() => setSelectedTag('All')}
              aria-pressed={selectedTag === 'All'}
              className={`rounded-md border px-2 py-0.5 text-[11px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                selectedTag === 'All'
                  ? 'border-slate-900 dark:border-slate-100 bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-950'
                  : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              All
            </button>
            {availableTags.map((tag) => {
              const isSelected = selectedTag.toLowerCase() === tag.toLowerCase();
              return (
                <button
                  key={tag}
                  type="button"
                  data-testid={`tag-filter-option-${tag.toLowerCase().replace(/\s+/g, '-')}`}
                  onClick={() => handleToggleTagFilter(tag)}
                  aria-pressed={isSelected}
                  className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    isSelected
                      ? 'border-red-700 dark:border-red-500 bg-red-600 text-white'
                      : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:border-slate-400 dark:hover:border-slate-500 hover:bg-slate-50 dark:hover:bg-slate-800'
                  }`}
                >
                  <Tag className="h-2.5 w-2.5 shrink-0" aria-hidden="true" />
                  <span>{tag}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {entries.length === 0 ? (
        <div
          data-testid="recent-investigations-empty"
          className="px-4 py-8 text-center"
        >
          <p className="text-xs font-medium text-slate-700 dark:text-slate-300">
            No recent queries saved yet
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Completed enrichments are stored locally in your browser so you can inspect results or re-run batches in one click.
          </p>
        </div>
      ) : filteredEntries.length === 0 ? (
        <div
          data-testid="recent-investigations-filtered-empty"
          className="px-4 py-8 text-center"
        >
          <p className="text-xs font-medium text-slate-700 dark:text-slate-300">
            No investigations match{' '}
            {hasRegionFilter && selectedTag !== 'All'
              ? `region "${selectedRegion}" and tag "${selectedTag}"`
              : hasRegionFilter
                ? `region "${selectedRegion}"`
                : `tag "${selectedTag}"`}
          </p>
          <button
            type="button"
            onClick={() => {
              setSelectedTag('All');
              onClearRegionFilter?.();
            }}
            className="mt-2 inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 cursor-pointer"
          >
            Show all ({entries.length})
          </button>
        </div>
      ) : (
        <ul className="max-h-[540px] overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800">
          {filteredEntries.map((entry) => {
            const fallbackTitle = formatInvestigationTitle(entry.indicators, entry.normalizedInput);
            const title = getInvestigationDisplayTitle(entry);
            const hasCustomTitle = Boolean(entry.customTitle && entry.customTitle.trim());
            const verdictBadge = getPrimaryVerdictBadge(entry.verdictSummary);
            const entryTags = getResolvedEntryTags(entry, indicatorTags);
            const isExpanded = expandedId === entry.id;
            const isActive = activeEntryId === entry.id;
            const isPinned = Boolean(entry.pinned);
            const isRenaming = renamingId === entry.id;
            const isContextTarget = contextMenu?.entryId === entry.id;

            const verdictToneClass =
              verdictBadge.tone === 'malicious'
                ? 'text-red-700 dark:text-red-400 font-semibold'
                : verdictBadge.tone === 'suspicious'
                  ? 'text-amber-700 dark:text-amber-400 font-semibold'
                  : verdictBadge.tone === 'clean'
                    ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                    : 'text-slate-600 dark:text-slate-400 font-medium';

            return (
              <li
                key={entry.id}
                data-testid="recent-investigation-item"
                data-pinned={isPinned ? 'true' : 'false'}
                onContextMenu={(e) => {
                  const target = e.target as HTMLElement | null;
                  if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA')) {
                    return;
                  }
                  e.preventDefault();
                  e.stopPropagation();
                  openMenuAt(entry.id, e.clientX, e.clientY);
                }}
                className={`px-4 py-3.5 transition-colors ${
                  isPinned ? 'border-l-2 border-l-amber-500 dark:border-l-amber-400' : ''
                } ${
                  isContextTarget
                    ? 'bg-slate-100/80 dark:bg-slate-800/90'
                    : isActive
                      ? 'bg-slate-50 dark:bg-slate-800/70'
                      : 'hover:bg-slate-50/70 dark:hover:bg-slate-800/40'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    {isRenaming ? (
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          commitRename(entry.id);
                        }}
                        className="flex flex-wrap items-center gap-1.5"
                      >
                        <input
                          ref={renameInputRef}
                          type="text"
                          data-testid="recent-rename-input"
                          aria-label="Rename investigation"
                          value={renameDraft}
                          onChange={(e) => setRenameDraft(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Escape') {
                              e.preventDefault();
                              cancelRename();
                            }
                          }}
                          maxLength={120}
                          placeholder={fallbackTitle}
                          className="min-w-0 flex-1 rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1 text-xs font-medium text-slate-900 dark:text-slate-100 focus:border-slate-900 dark:focus:border-slate-300 focus:outline-none"
                        />
                        <button
                          type="submit"
                          data-testid="recent-rename-save-btn"
                          className="rounded-md bg-slate-900 dark:bg-slate-100 px-2 py-1 text-[11px] font-semibold text-white dark:text-slate-950 hover:bg-slate-800 dark:hover:bg-slate-200 cursor-pointer"
                        >
                          Save
                        </button>
                        <button
                          type="button"
                          data-testid="recent-rename-cancel-btn"
                          onClick={cancelRename}
                          className="rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-1 text-[11px] font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 cursor-pointer"
                        >
                          Cancel
                        </button>
                      </form>
                    ) : (
                      <div className="flex items-center gap-1.5 min-w-0">
                        {isPinned && (
                          <Pin
                            data-testid="recent-pinned-indicator"
                            aria-label="Pinned investigation"
                            className="h-3 w-3 shrink-0 text-amber-600 dark:text-amber-400"
                          />
                        )}
                        <div
                          data-testid="recent-entry-title"
                          className={`${
                            hasCustomTitle ? 'font-sans' : 'font-mono'
                          } text-xs font-semibold text-slate-900 dark:text-slate-100 truncate`}
                          title={hasCustomTitle ? `${title} (${entry.normalizedInput})` : entry.normalizedInput}
                        >
                          {title}
                        </div>
                      </div>
                    )}

                    <div className="mt-1 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                      {hasCustomTitle && (
                        <>
                          <span className="font-mono text-slate-600 dark:text-slate-300 truncate max-w-[140px]">
                            {fallbackTitle}
                          </span>
                          <span aria-hidden="true">·</span>
                        </>
                      )}
                      <span>{formatRelativeTime(entry.createdAt)}</span>
                      <span aria-hidden="true">·</span>
                      <span>{entry.mode === 'live' ? 'Live' : 'Sample'}</span>
                      <span aria-hidden="true">·</span>
                      <span className={verdictToneClass}>{verdictBadge.label}</span>
                    </div>

                    {entry.notes && entry.notes.trim().length > 0 && (
                      <p
                        data-testid="recent-entry-note-preview"
                        className="mt-1.5 flex items-center gap-1 text-[11px] text-slate-600 dark:text-slate-300 truncate"
                        title={entry.notes}
                      >
                        <FileText className="h-3 w-3 shrink-0 text-slate-400 dark:text-slate-500" aria-hidden="true" />
                        <span className="truncate">{entry.notes.replace(/\s+/g, ' ')}</span>
                      </p>
                    )}

                    {entryTags.length > 0 && (
                      <div
                        data-testid="recent-entry-tags"
                        className="mt-1.5 flex flex-wrap items-center gap-1"
                      >
                        {entryTags.map((tag) => {
                          const isFilteredByThis = selectedTag.toLowerCase() === tag.toLowerCase();
                          return (
                            <button
                              key={tag}
                              type="button"
                              onClick={() => handleToggleTagFilter(tag)}
                              title={isFilteredByThis ? `Clear "${tag}" filter` : `Filter by tag "${tag}"`}
                              className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium transition-colors cursor-pointer ${
                                isFilteredByThis
                                  ? 'border-red-600 bg-red-50 dark:bg-red-950/50 text-red-700 dark:text-red-300'
                                  : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/70 text-slate-700 dark:text-slate-300 hover:border-slate-400 dark:hover:border-slate-500'
                              }`}
                            >
                              <Tag className="h-2.5 w-2.5 shrink-0" aria-hidden="true" />
                              <span>{tag}</span>
                            </button>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-0.5 shrink-0">
                    <button
                      type="button"
                      data-testid="recent-item-menu-btn"
                      onClick={(e) => {
                        const rect = e.currentTarget.getBoundingClientRect();
                        openMenuAt(entry.id, rect.right - 192, rect.bottom + 4);
                      }}
                      aria-label={`More options for ${title}`}
                      aria-haspopup="menu"
                      title="Quick actions (or right-click item)"
                      className="rounded-md p-1 text-slate-400 dark:text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer"
                    >
                      <MoreVertical className="h-3.5 w-3.5" aria-hidden="true" />
                    </button>

                    <button
                      type="button"
                      onClick={() => onRemoveEntry(entry.id)}
                      aria-label={`Remove ${title} from recent investigations`}
                      title="Remove from history"
                      className="rounded-md p-1 text-slate-400 dark:text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-red-600 dark:hover:text-red-400 cursor-pointer"
                    >
                      <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                    </button>
                  </div>
                </div>

                <div className="mt-2.5 flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    data-testid="recent-view-details-btn"
                    aria-expanded={isExpanded}
                    aria-label={`View details for ${title}`}
                    onClick={() => handleDetailsClick(entry)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1.5 text-[11px] font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Eye className="h-3 w-3" aria-hidden="true" />
                    <span>Details</span>
                    {isExpanded ? (
                      <ChevronUp className="h-3 w-3 text-slate-400" aria-hidden="true" />
                    ) : (
                      <ChevronDown className="h-3 w-3 text-slate-400" aria-hidden="true" />
                    )}
                  </button>

                  <button
                    type="button"
                    data-testid="recent-rerun-btn"
                    disabled={isRunning}
                    aria-label={`Re-run ${title}`}
                    onClick={() => onRerun(entry)}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 dark:bg-slate-100 px-2.5 py-1.5 text-[11px] font-semibold text-white dark:text-slate-950 hover:bg-slate-800 dark:hover:bg-slate-200 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <RotateCw className="h-3 w-3" aria-hidden="true" />
                    <span>Re-run</span>
                  </button>
                </div>

                {isExpanded && (
                  <div
                    data-testid="recent-investigation-details"
                    className="mt-3 space-y-2 border-t border-slate-200 dark:border-slate-700 pt-2.5 text-[11px] text-slate-600 dark:text-slate-300"
                  >
                    <div>
                      <span className="font-semibold text-slate-700 dark:text-slate-200">Timestamp: </span>
                      <span className="font-mono tabular-nums">
                        {entry.createdAt.slice(0, 19).replace('T', ' ')} UTC
                      </span>
                    </div>
                    <div>
                      <span className="font-semibold text-slate-700 dark:text-slate-200">
                        Indicators ({entry.indicatorCount}):{' '}
                      </span>
                      <span className="font-mono break-all text-slate-800 dark:text-slate-100">
                        {entry.indicators.join(', ')}
                      </span>
                    </div>
                    <div>
                      <span className="font-semibold text-slate-700 dark:text-slate-200">Sources: </span>
                      <span>
                        {entry.sourceLabels.length > 0 ? entry.sourceLabels.join(' · ') : 'Configured APIs'}
                      </span>
                    </div>
                    {entryTags.length > 0 && (
                      <div>
                        <span className="font-semibold text-slate-700 dark:text-slate-200">Tags: </span>
                        <span>{entryTags.join(', ')}</span>
                      </div>
                    )}
                    <div className="flex flex-wrap items-center gap-x-2.5 gap-y-0.5 font-mono tabular-nums">
                      <span className="text-red-700 dark:text-red-400">
                        Mal: {entry.verdictSummary.malicious}
                      </span>
                      <span className="text-amber-700 dark:text-amber-400">
                        Susp: {entry.verdictSummary.suspicious}
                      </span>
                      <span className="text-emerald-700 dark:text-emerald-400">
                        Clean: {entry.verdictSummary.clean}
                      </span>
                      <span className="text-slate-500 dark:text-slate-400">
                        Unk: {entry.verdictSummary.unknown}
                      </span>
                    </div>
                    {entry.reportFile && (
                      <div className="truncate font-mono text-slate-500 dark:text-slate-400">
                        Report: {entry.reportFile}
                      </div>
                    )}
                    {entry.notes && entry.notes.trim().length > 0 && (
                      <div
                        data-testid="recent-entry-details-notes"
                        className="rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-2.5 space-y-1"
                      >
                        <div className="flex items-center justify-between gap-2 text-[10px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                          <span>Researcher Notes</span>
                          {entry.notesUpdatedAt && (
                            <span className="font-mono font-normal tabular-nums">
                              {entry.notesUpdatedAt.slice(11, 16)} UTC
                            </span>
                          )}
                        </div>
                        <p className="whitespace-pre-wrap break-words text-[11px] leading-relaxed text-slate-800 dark:text-slate-200">
                          {entry.notes}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}

      {contextMenuEntry && clampedMenuPos && (
        <div
          ref={menuRef}
          role="menu"
          data-testid="recent-context-menu"
          aria-label={`Actions for ${getInvestigationDisplayTitle(contextMenuEntry)}`}
          style={{ left: `${clampedMenuPos.left}px`, top: `${clampedMenuPos.top}px` }}
          className="fixed z-50 w-48 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 py-1 shadow-lg"
        >
          <button
            type="button"
            role="menuitem"
            data-testid="context-menu-pin"
            onClick={() => {
              onTogglePinEntry(contextMenuEntry.id);
              setContextMenu(null);
            }}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
          >
            {contextMenuEntry.pinned ? (
              <>
                <PinOff className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400 shrink-0" aria-hidden="true" />
                <span>Unpin</span>
              </>
            ) : (
              <>
                <Pin className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400 shrink-0" aria-hidden="true" />
                <span>Pin</span>
              </>
            )}
          </button>

          <button
            type="button"
            role="menuitem"
            data-testid="context-menu-rename"
            onClick={() => startRename(contextMenuEntry)}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
          >
            <Pencil className="h-3.5 w-3.5 text-slate-500 dark:text-slate-400 shrink-0" aria-hidden="true" />
            <span>Rename</span>
          </button>

          <div className="my-1 border-t border-slate-100 dark:border-slate-800" role="separator" />

          <button
            type="button"
            role="menuitem"
            data-testid="context-menu-delete"
            onClick={() => {
              const targetId = contextMenuEntry.id;
              setContextMenu(null);
              if (expandedId === targetId) setExpandedId(null);
              if (renamingId === targetId) cancelRename();
              onRemoveEntry(targetId);
            }}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs font-medium text-red-700 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/50 cursor-pointer"
          >
            <Trash2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span>Delete</span>
          </button>
        </div>
      )}

      {confirmClearOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-[1px]"
          role="dialog"
          aria-modal="true"
          aria-labelledby="clear-history-dialog-title"
          data-testid="clear-history-confirm-dialog"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setConfirmClearOpen(false);
            }
          }}
        >
          <div className="w-full max-w-md rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 shadow-2xl overflow-hidden">
            <div className="flex items-start gap-3 border-b border-slate-100 dark:border-slate-800 px-5 py-4">
              <div className="rounded-lg bg-red-50 dark:bg-red-950/50 p-2 text-red-600 dark:text-red-400 shrink-0">
                <AlertTriangle className="h-4 w-4" aria-hidden="true" />
              </div>
              <div className="min-w-0 flex-1">
                <h3
                  id="clear-history-dialog-title"
                  className="text-sm font-semibold text-slate-950 dark:text-slate-50"
                >
                  Clear Investigation History?
                </h3>
                <p className="mt-1 text-xs leading-relaxed text-slate-600 dark:text-slate-300">
                  This will permanently remove all{' '}
                  <span className="font-mono font-semibold text-slate-900 dark:text-slate-100 tabular-nums">
                    {entries.length}
                  </span>{' '}
                  saved investigation{entries.length === 1 ? '' : 's'}
                  {entries.some((e) => e.pinned)
                    ? ` (including ${entries.filter((e) => e.pinned).length} pinned)`
                    : ''}{' '}
                  from your browser storage. Consider exporting your history first if you need an audit trail.
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 bg-slate-50/70 dark:bg-slate-950/60 px-5 py-3">
              <button
                type="button"
                onClick={handleExportHistory}
                className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 hover:text-slate-950 dark:hover:text-white hover:underline cursor-pointer"
              >
                <Download className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Export JSON First</span>
              </button>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  data-testid="clear-history-cancel-btn"
                  onClick={() => setConfirmClearOpen(false)}
                  className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  data-testid="clear-history-confirm-btn"
                  onClick={handleConfirmClearHistory}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-red-700 cursor-pointer"
                >
                  <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Clear History</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
}
