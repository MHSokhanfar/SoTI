import { Keyboard, X } from 'lucide-react';
import {
  GLOBAL_SHORTCUTS,
  type KeyboardShortcutSpec,
} from '../utils/keyboardShortcuts';

interface KeyboardShortcutsModalProps {
  open: boolean;
  onClose: () => void;
}

const CATEGORIES: KeyboardShortcutSpec['category'][] = [
  'Search & Triage',
  'Navigation',
  'Workspace',
];

export function KeyboardShortcutsModal({ open, onClose }: KeyboardShortcutsModalProps) {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-labelledby="shortcuts-modal-title"
      data-testid="keyboard-shortcuts-modal"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-2xl rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 px-6 py-4">
          <div className="flex items-center gap-2.5">
            <Keyboard className="h-5 w-5 text-red-600 dark:text-red-400 shrink-0" aria-hidden="true" />
            <div>
              <h2
                id="shortcuts-modal-title"
                className="text-base font-bold text-slate-950 dark:text-slate-50"
              >
                Keyboard Shortcuts
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Power-user shortcuts for rapid SOC triage across workbench views.
              </p>
            </div>
          </div>

          <button
            type="button"
            data-testid="close-shortcuts-modal"
            onClick={onClose}
            aria-label="Close keyboard shortcuts reference"
            className="rounded-lg p-1.5 text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="max-h-[70vh] overflow-y-auto px-6 py-5 space-y-6">
          {CATEGORIES.map((category) => {
            const items = GLOBAL_SHORTCUTS.filter((s) => s.category === category);
            return (
              <div key={category} className="space-y-2.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  {category}
                </h3>
                <div className="divide-y divide-slate-100 dark:divide-slate-800 rounded-xl border border-slate-200 dark:border-slate-800">
                  {items.map((spec) => (
                    <div
                      key={spec.id}
                      data-testid={`shortcut-row-${spec.id}`}
                      className="flex items-center justify-between gap-4 px-4 py-3"
                    >
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                          {spec.label}
                        </div>
                        <div className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
                          {spec.description}
                        </div>
                      </div>

                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="inline-flex items-center gap-1">
                          {spec.keys.map((keyLabel) => (
                            <kbd
                              key={keyLabel}
                              className="inline-flex min-w-[24px] items-center justify-center rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[11px] font-semibold text-slate-800 dark:text-slate-200"
                            >
                              {keyLabel}
                            </kbd>
                          ))}
                        </span>
                        {spec.altKeys && spec.altKeys.length > 0 && (
                          <>
                            <span className="text-[11px] text-slate-400 dark:text-slate-500">or</span>
                            <span className="inline-flex items-center gap-1">
                              {spec.altKeys.map((keyLabel) => (
                                <kbd
                                  key={keyLabel}
                                  className="inline-flex min-w-[24px] items-center justify-center rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[11px] font-semibold text-slate-800 dark:text-slate-200"
                                >
                                  {keyLabel}
                                </kbd>
                              ))}
                            </span>
                          </>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        <div className="flex items-center justify-between border-t border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 px-6 py-3 text-xs text-slate-500 dark:text-slate-400">
          <span>
            Note: Single-key shortcuts (<code className="font-mono">/</code>, <code className="font-mono">?</code>) pause while typing inside text fields.
          </span>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
