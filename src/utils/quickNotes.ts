export const QUICK_NOTES_STORAGE_KEY = 'soti_quick_notes_v1';

export interface QuickNotesState {
  text: string;
  updatedAt: string | null;
  collapsed: boolean;
}

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export const DEFAULT_QUICK_NOTES_STATE: QuickNotesState = {
  text: '',
  updatedAt: null,
  collapsed: false,
};

export function loadQuickNotes(storage: StorageLike | null | undefined): QuickNotesState {
  if (!storage) return { ...DEFAULT_QUICK_NOTES_STATE };
  try {
    const raw = storage.getItem(QUICK_NOTES_STORAGE_KEY);
    if (!raw) return { ...DEFAULT_QUICK_NOTES_STATE };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') {
      return { ...DEFAULT_QUICK_NOTES_STATE };
    }
    return {
      text: typeof parsed.text === 'string' ? parsed.text : '',
      updatedAt:
        typeof parsed.updatedAt === 'string' && parsed.updatedAt.trim().length > 0
          ? parsed.updatedAt
          : null,
      collapsed: typeof parsed.collapsed === 'boolean' ? parsed.collapsed : false,
    };
  } catch {
    return { ...DEFAULT_QUICK_NOTES_STATE };
  }
}

export function saveQuickNotes(
  storage: StorageLike | null | undefined,
  state: QuickNotesState,
): boolean {
  if (!storage) return false;
  try {
    storage.setItem(
      QUICK_NOTES_STORAGE_KEY,
      JSON.stringify({
        text: state.text,
        updatedAt: state.updatedAt,
        collapsed: state.collapsed,
      }),
    );
    return true;
  } catch {
    return false;
  }
}

export function updateQuickNotesText(
  prev: QuickNotesState,
  nextText: string,
  now: Date = new Date(),
): QuickNotesState {
  return {
    ...prev,
    text: nextText,
    updatedAt: now.toISOString(),
  };
}

export function clearQuickNotesState(
  prev: QuickNotesState,
  now: Date = new Date(),
): QuickNotesState {
  return {
    ...prev,
    text: '',
    updatedAt: now.toISOString(),
  };
}

export function toggleQuickNotesCollapsed(prev: QuickNotesState): QuickNotesState {
  return {
    ...prev,
    collapsed: !prev.collapsed,
  };
}

export function formatQuickNotesUtc(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  return `${new Date(ms).toISOString().slice(11, 19)} UTC`;
}

export function summarizeQuickNotesStats(text: string): {
  characters: number;
  lines: number;
} {
  if (!text) {
    return { characters: 0, lines: 0 };
  }
  return {
    characters: text.length,
    lines: text.split(/\r?\n/).length,
  };
}
