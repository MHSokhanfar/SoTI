export type ShortcutActionId =
  | 'focus_search'
  | 'goto_investigate'
  | 'goto_reports'
  | 'goto_scheduled'
  | 'goto_logs'
  | 'goto_cli'
  | 'toggle_theme'
  | 'toggle_shortcuts_help'
  | 'escape';

export interface KeyboardShortcutSpec {
  id: ShortcutActionId;
  category: 'Navigation' | 'Search & Triage' | 'Workspace';
  label: string;
  description: string;
  keys: string[];
  altKeys?: string[];
  allowInInputs: boolean;
}

export const GLOBAL_SHORTCUTS: readonly KeyboardShortcutSpec[] = [
  {
    id: 'focus_search',
    category: 'Search & Triage',
    label: 'Global Search',
    description: 'Focus search across IOCs, reports, schedules, and logs',
    keys: ['Ctrl', 'K'],
    altKeys: ['/'],
    allowInInputs: true,
  },
  {
    id: 'goto_investigate',
    category: 'Navigation',
    label: 'Investigate Workbench',
    description: 'Switch to Investigate tab and focus IOC input',
    keys: ['Ctrl', 'I'],
    altKeys: ['Alt', '1'],
    allowInInputs: true,
  },
  {
    id: 'goto_reports',
    category: 'Navigation',
    label: 'Reports & Analytics',
    description: 'Open CSV Reports Archive, D3 heatmaps, and AI summaries',
    keys: ['Alt', '2'],
    allowInInputs: true,
  },
  {
    id: 'goto_scheduled',
    category: 'Navigation',
    label: 'Scheduled Checks',
    description: 'View and manage recurring IOC monitoring jobs',
    keys: ['Alt', '3'],
    allowInInputs: true,
  },
  {
    id: 'goto_logs',
    category: 'Navigation',
    label: 'Audit Logs',
    description: 'Inspect live provider lookups and quota failover logs',
    keys: ['Alt', '4'],
    allowInInputs: true,
  },
  {
    id: 'goto_cli',
    category: 'Navigation',
    label: 'CLI & APIs',
    description: 'Configure threat intel API keys, quotas, and alerts',
    keys: ['Alt', '5'],
    allowInInputs: true,
  },
  {
    id: 'toggle_theme',
    category: 'Workspace',
    label: 'Toggle Theme',
    description: 'Switch between Light and Dark appearance',
    keys: ['Alt', 'T'],
    allowInInputs: false,
  },
  {
    id: 'toggle_shortcuts_help',
    category: 'Workspace',
    label: 'Keyboard Shortcuts',
    description: 'Open or close this keyboard shortcut reference',
    keys: ['Shift', '?'],
    allowInInputs: false,
  },
  {
    id: 'escape',
    category: 'Workspace',
    label: 'Dismiss / Close',
    description: 'Close open shortcut guide, help modal, or drawers',
    keys: ['Esc'],
    allowInInputs: true,
  },
];

export interface KeyboardEventLike {
  key: string;
  ctrlKey?: boolean;
  metaKey?: boolean;
  altKey?: boolean;
  shiftKey?: boolean;
  target?:
    | EventTarget
    | {
        tagName?: string;
        isContentEditable?: boolean;
      }
    | null;
}

export function isEditableTarget(target: KeyboardEventLike['target']): boolean {
  if (!target || typeof target !== 'object') return false;
  const candidate = target as { tagName?: string; isContentEditable?: boolean };
  const tag = (candidate.tagName || '').toUpperCase();
  return (
    tag === 'INPUT' ||
    tag === 'TEXTAREA' ||
    tag === 'SELECT' ||
    Boolean(candidate.isContentEditable)
  );
}

export function matchGlobalKeyboardShortcut(
  event: KeyboardEventLike,
): ShortcutActionId | null {
  const key = (event.key || '').toLowerCase();
  const hasPrimaryMod = Boolean(event.ctrlKey || event.metaKey);
  const hasAlt = Boolean(event.altKey);
  const hasShift = Boolean(event.shiftKey);
  const editing = isEditableTarget(event.target);

  if (key === 'escape') {
    return 'escape';
  }

  // Ctrl+K / Cmd+K always opens Global Search
  if (hasPrimaryMod && !hasAlt && !hasShift && key === 'k') {
    return 'focus_search';
  }

  // Ctrl+I / Cmd+I always jumps to Investigate
  if (hasPrimaryMod && !hasAlt && !hasShift && key === 'i') {
    return 'goto_investigate';
  }

  // Alt + 1..5 tab navigation
  if (hasAlt && !hasPrimaryMod && !hasShift) {
    if (key === '1') return 'goto_investigate';
    if (key === '2') return 'goto_reports';
    if (key === '3') return 'goto_scheduled';
    if (key === '4') return 'goto_logs';
    if (key === '5') return 'goto_cli';
  }

  if (editing) {
    return null;
  }

  if (!hasPrimaryMod && !hasAlt && key === '/') {
    return 'focus_search';
  }

  if (!hasPrimaryMod && !hasAlt && event.key === '?') {
    return 'toggle_shortcuts_help';
  }

  if (hasAlt && !hasPrimaryMod && !hasShift && key === 't') {
    return 'toggle_theme';
  }

  return null;
}
