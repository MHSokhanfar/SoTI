import { useEffect, useRef, useState } from 'react';
import {
  Check,
  ChevronDown,
  Copy,
  RotateCcw,
  StickyNote,
  Trash2,
  X,
} from 'lucide-react';
import { copyToClipboard } from '../utils/clipboard';
import {
  formatQuickNotesUtc,
  summarizeQuickNotesStats,
  type QuickNotesState,
} from '../utils/quickNotes';

interface QuickNotesSidebarPanelProps {
  notesState: QuickNotesState;
  onChangeText: (nextText: string) => void;
  onClearText: () => void;
  onToggleCollapse?: () => void;
  variant?: 'embedded' | 'drawer';
  onCloseDrawer?: () => void;
}

export function QuickNotesSidebarPanel({
  notesState,
  onChangeText,
  onClearText,
  onToggleCollapse,
  variant = 'embedded',
  onCloseDrawer,
}: QuickNotesSidebarPanelProps) {
  const [copied, setCopied] = useState(false);
  const [undoText, setUndoText] = useState<string | null>(null);
  const undoTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (undoTimerRef.current !== null) {
        window.clearTimeout(undoTimerRef.current);
      }
    };
  }, []);

  const stats = summarizeQuickNotesStats(notesState.text);
  const savedUtc = formatQuickNotesUtc(notesState.updatedAt);
  const isCollapsed = variant === 'embedded' && notesState.collapsed;

  async function handleCopy() {
    if (!notesState.text.trim()) return;
    const ok = await copyToClipboard(notesState.text);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    }
  }

  function handleClear() {
    if (!notesState.text) return;
    const snapshot = notesState.text;
    onClearText();
    setUndoText(snapshot);
    if (undoTimerRef.current !== null) {
      window.clearTimeout(undoTimerRef.current);
    }
    undoTimerRef.current = window.setTimeout(() => {
      setUndoText(null);
      undoTimerRef.current = null;
    }, 6000);
  }

  function handleUndoClear() {
    if (undoText === null) return;
    onChangeText(undoText);
    setUndoText(null);
    if (undoTimerRef.current !== null) {
      window.clearTimeout(undoTimerRef.current);
      undoTimerRef.current = null;
    }
  }

  const testPrefix = variant === 'drawer' ? 'quick-notes-drawer' : 'quick-notes';

  return (
    <section
      aria-label="Quick Notes scratchpad"
      data-testid={`${testPrefix}-panel`}
      className={
        variant === 'drawer'
          ? 'flex h-full flex-col bg-white dark:bg-slate-900'
          : 'rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden'
      }
    >
      <div className="flex items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 px-4 py-3">
        <div className="flex items-center gap-2 min-w-0">
          <StickyNote
            className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400"
            aria-hidden="true"
          />
          <h2 className="text-sm font-semibold text-slate-950 dark:text-slate-50 truncate">
            Quick Notes
          </h2>
          {stats.characters > 0 && (
            <span
              data-testid={`${testPrefix}-char-count`}
              className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums shrink-0"
            >
              ({stats.characters})
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {variant === 'embedded' && onToggleCollapse && (
            <button
              type="button"
              data-testid="quick-notes-collapse-toggle"
              aria-expanded={!isCollapsed}
              aria-label={isCollapsed ? 'Expand Quick Notes panel' : 'Collapse Quick Notes panel'}
              onClick={onToggleCollapse}
              className="inline-flex items-center justify-center rounded-md p-1 text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
            >
              <ChevronDown
                className={`h-4 w-4 transition-transform duration-150 ${
                  isCollapsed ? '-rotate-90' : ''
                }`}
                aria-hidden="true"
              />
            </button>
          )}
          {variant === 'drawer' && onCloseDrawer && (
            <button
              type="button"
              data-testid="quick-notes-drawer-close"
              aria-label="Close Quick Notes sidebar"
              onClick={onCloseDrawer}
              className="inline-flex items-center justify-center rounded-md p-1 text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>

      {!isCollapsed && (
        <div
          className={
            variant === 'drawer'
              ? 'flex flex-1 flex-col justify-between p-4 gap-3'
              : 'p-3.5 space-y-2.5'
          }
        >
          <div className={variant === 'drawer' ? 'flex-1 flex flex-col gap-2' : 'space-y-1.5'}>
            <p className="text-[11px] leading-relaxed text-slate-500 dark:text-slate-400">
              Persistent scratchpad for transient triage thoughts while pivoting across VirusTotal, AbuseIPDB, OTX, and reports.
            </p>
            <textarea
              data-testid={`${testPrefix}-textarea`}
              aria-label="Quick Notes persistent scratchpad"
              value={notesState.text}
              onChange={(e) => {
                if (undoText !== null) setUndoText(null);
                onChangeText(e.target.value);
              }}
              rows={variant === 'drawer' ? 14 : 5}
              placeholder="Jot transient IOC leads, WHOIS handles, ticket IDs, or cross-platform observations..."
              className={`w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-950 p-2.5 text-xs leading-relaxed text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:bg-white dark:focus:bg-slate-950 focus:outline-none ${
                variant === 'drawer' ? 'flex-1 resize-none' : 'resize-y min-h-[108px]'
              }`}
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5 text-[11px]">
            <span
              data-testid={`${testPrefix}-status`}
              className="font-mono text-slate-500 dark:text-slate-400 tabular-nums"
            >
              {savedUtc ? `Saved · ${savedUtc}` : 'Persists in localStorage'}
            </span>

            <div className="flex items-center gap-2 shrink-0">
              {undoText !== null && !notesState.text && (
                <button
                  type="button"
                  data-testid={`${testPrefix}-undo-btn`}
                  onClick={handleUndoClear}
                  className="inline-flex items-center gap-1 font-medium text-amber-700 dark:text-amber-400 hover:underline cursor-pointer whitespace-nowrap"
                >
                  <RotateCcw className="h-3 w-3" aria-hidden="true" />
                  <span>Undo</span>
                </button>
              )}

              <button
                type="button"
                data-testid={`${testPrefix}-copy-btn`}
                disabled={!notesState.text.trim()}
                onClick={handleCopy}
                className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-1 font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-45 whitespace-nowrap cursor-pointer"
              >
                {copied ? (
                  <>
                    <Check className="h-3 w-3 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
                    <span>Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3" aria-hidden="true" />
                    <span>Copy</span>
                  </>
                )}
              </button>

              <button
                type="button"
                data-testid={`${testPrefix}-clear-btn`}
                disabled={!notesState.text}
                onClick={handleClear}
                className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2 py-1 font-medium text-slate-600 dark:text-slate-300 hover:border-red-300 dark:hover:border-red-800 hover:text-red-700 dark:hover:text-red-400 disabled:opacity-45 whitespace-nowrap cursor-pointer"
              >
                <Trash2 className="h-3 w-3" aria-hidden="true" />
                <span>Clear</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
