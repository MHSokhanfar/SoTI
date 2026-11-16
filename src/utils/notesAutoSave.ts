import {
  MAX_INVESTIGATION_NOTES_LENGTH,
  normalizeInvestigationNotes,
  type StorageLike,
} from './investigationHistory';

export const NOTES_AUTOSAVE_STORAGE_KEY = 'soti_researcher_notes_autosave_v1';
export const NOTES_AUTOSAVE_INTERVAL_MS = 3000;
export const NOTES_AUTOSAVE_DEBOUNCE_MS = 700;
export const MAX_AUTOSAVED_ENTRY_DRAFTS = 25;

export interface NotesEntryDraft {
  notes: string;
  updatedAt: string;
}

export interface NotesAutoSaveState {
  draftNotes: string;
  draftUpdatedAt: string | null;
  activeEntryId: string | null;
  entryDrafts: Record<string, NotesEntryDraft>;
}

export function createEmptyNotesAutoSaveState(): NotesAutoSaveState {
  return {
    draftNotes: '',
    draftUpdatedAt: null,
    activeEntryId: null,
    entryDrafts: {},
  };
}

function normalizeRawTextForDraft(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  return raw.replace(/\r\n?/g, '\n').slice(0, MAX_INVESTIGATION_NOTES_LENGTH);
}

export function loadNotesAutoSaveState(storage?: StorageLike | null): NotesAutoSaveState {
  if (!storage) return createEmptyNotesAutoSaveState();
  try {
    const raw = storage.getItem(NOTES_AUTOSAVE_STORAGE_KEY);
    if (!raw) return createEmptyNotesAutoSaveState();
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (!parsed || typeof parsed !== 'object') return createEmptyNotesAutoSaveState();

    const draftNotes = normalizeRawTextForDraft(parsed.draftNotes);
    const draftUpdatedAt =
      typeof parsed.draftUpdatedAt === 'string' && parsed.draftUpdatedAt.trim()
        ? parsed.draftUpdatedAt
        : null;
    const activeEntryId =
      typeof parsed.activeEntryId === 'string' && parsed.activeEntryId.trim()
        ? parsed.activeEntryId
        : null;

    const entryDrafts: Record<string, NotesEntryDraft> = {};
    if (parsed.entryDrafts && typeof parsed.entryDrafts === 'object' && !Array.isArray(parsed.entryDrafts)) {
      const entries = Object.entries(parsed.entryDrafts as Record<string, unknown>);
      for (const [entryId, val] of entries.slice(0, MAX_AUTOSAVED_ENTRY_DRAFTS)) {
        if (!entryId.trim() || !val || typeof val !== 'object') continue;
        const obj = val as Record<string, unknown>;
        const notes = normalizeRawTextForDraft(obj.notes);
        if (!notes.trim()) continue;
        entryDrafts[entryId] = {
          notes,
          updatedAt:
            typeof obj.updatedAt === 'string' && obj.updatedAt.trim()
              ? obj.updatedAt
              : new Date().toISOString(),
        };
      }
    }

    return {
      draftNotes,
      draftUpdatedAt,
      activeEntryId,
      entryDrafts,
    };
  } catch {
    return createEmptyNotesAutoSaveState();
  }
}

export function saveNotesAutoSaveState(
  storage: StorageLike | null | undefined,
  state: NotesAutoSaveState,
): boolean {
  if (!storage) return false;
  try {
    const hasDraft = state.draftNotes.length > 0;
    const entryKeys = Object.keys(state.entryDrafts);
    if (!hasDraft && entryKeys.length === 0 && typeof storage.removeItem === 'function') {
      storage.removeItem(NOTES_AUTOSAVE_STORAGE_KEY);
      return true;
    }

    const boundedDrafts: Record<string, NotesEntryDraft> = {};
    const sortedEntries = Object.entries(state.entryDrafts).sort((a, b) => {
      const tsA = Date.parse(a[1].updatedAt) || 0;
      const tsB = Date.parse(b[1].updatedAt) || 0;
      return tsB - tsA;
    });
    for (const [k, v] of sortedEntries.slice(0, MAX_AUTOSAVED_ENTRY_DRAFTS)) {
      boundedDrafts[k] = v;
    }

    const payload: NotesAutoSaveState = {
      draftNotes: normalizeRawTextForDraft(state.draftNotes),
      draftUpdatedAt: hasDraft ? state.draftUpdatedAt : null,
      activeEntryId: state.activeEntryId,
      entryDrafts: boundedDrafts,
    };

    storage.setItem(NOTES_AUTOSAVE_STORAGE_KEY, JSON.stringify(payload));
    return true;
  } catch {
    return false;
  }
}

export function upsertNotesAutoSaveDraft(
  current: NotesAutoSaveState,
  params: {
    entryId: string | null;
    notes: string;
    now?: Date;
  },
): NotesAutoSaveState {
  const updatedAt = (params.now ?? new Date()).toISOString();
  const nextRaw = normalizeRawTextForDraft(params.notes);
  const nextTrimmed = normalizeInvestigationNotes(nextRaw);
  const nextEntryDrafts = { ...current.entryDrafts };

  if (params.entryId) {
    if (nextTrimmed.length > 0) {
      nextEntryDrafts[params.entryId] = {
        notes: nextRaw,
        updatedAt,
      };
    } else {
      delete nextEntryDrafts[params.entryId];
    }
  }

  return {
    draftNotes: nextRaw,
    draftUpdatedAt: nextRaw.length > 0 ? updatedAt : null,
    activeEntryId: params.entryId,
    entryDrafts: nextEntryDrafts,
  };
}

export function removeEntryFromAutoSaveDrafts(
  current: NotesAutoSaveState,
  entryId: string,
): NotesAutoSaveState {
  const nextEntryDrafts = { ...current.entryDrafts };
  delete nextEntryDrafts[entryId];
  const clearActive = current.activeEntryId === entryId;
  return {
    draftNotes: clearActive ? '' : current.draftNotes,
    draftUpdatedAt: clearActive ? null : current.draftUpdatedAt,
    activeEntryId: clearActive ? null : current.activeEntryId,
    entryDrafts: nextEntryDrafts,
  };
}

export function resolveRestoredNotesForEntry(
  autoSaveState: NotesAutoSaveState,
  entryId: string,
  historyNotes?: string,
): { notes: string; updatedAt: string | null } {
  const autoSaved = autoSaveState.entryDrafts[entryId];
  const cleanHistory = normalizeInvestigationNotes(historyNotes);
  if (autoSaved && normalizeInvestigationNotes(autoSaved.notes).length > 0) {
    return {
      notes: autoSaved.notes,
      updatedAt: autoSaved.updatedAt,
    };
  }
  return {
    notes: cleanHistory,
    updatedAt: null,
  };
}

export function formatAutoSaveUtcTimestamp(iso: string | null | undefined): string {
  if (!iso || typeof iso !== 'string') return '';
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return '';
  return `${new Date(ts).toISOString().slice(11, 19)} UTC`;
}
