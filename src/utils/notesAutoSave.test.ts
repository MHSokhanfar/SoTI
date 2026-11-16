import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createEmptyNotesAutoSaveState,
  formatAutoSaveUtcTimestamp,
  loadNotesAutoSaveState,
  NOTES_AUTOSAVE_STORAGE_KEY,
  removeEntryFromAutoSaveDrafts,
  resolveRestoredNotesForEntry,
  saveNotesAutoSaveState,
  upsertNotesAutoSaveDraft,
} from './notesAutoSave';
import type { StorageLike } from './investigationHistory';

function createMemoryStorage(): StorageLike & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k) => (map.has(k) ? map.get(k)! : null),
    setItem: (k, v) => {
      map.set(k, v);
    },
    removeItem: (k) => {
      map.delete(k);
    },
  };
}

test('upsertNotesAutoSaveDraft and save/load persist analyst findings across reloads', () => {
  const storage = createMemoryStorage();
  const now = new Date('2026-11-16T04:15:30.000Z');

  let state = loadNotesAutoSaveState(storage);
  assert.equal(state.draftNotes, '');

  state = upsertNotesAutoSaveDraft(state, {
    entryId: 'inv_100',
    notes: 'Observed CobaltStrike beacon callback to 1.2.3.4 over HTTPS',
    now,
  });

  assert.equal(saveNotesAutoSaveState(storage, state), true);
  assert.ok(storage.map.has(NOTES_AUTOSAVE_STORAGE_KEY));

  const reloaded = loadNotesAutoSaveState(storage);
  assert.equal(
    reloaded.draftNotes,
    'Observed CobaltStrike beacon callback to 1.2.3.4 over HTTPS',
  );
  assert.equal(reloaded.activeEntryId, 'inv_100');
  assert.equal(reloaded.draftUpdatedAt, '2026-11-16T04:15:30.000Z');
  assert.equal(
    reloaded.entryDrafts['inv_100']?.notes,
    'Observed CobaltStrike beacon callback to 1.2.3.4 over HTTPS',
  );
});

test('upsertNotesAutoSaveDraft works for standalone unlinked drafts and clears cleanly when empty', () => {
  const storage = createMemoryStorage();
  const state = upsertNotesAutoSaveDraft(createEmptyNotesAutoSaveState(), {
    entryId: null,
    notes: 'Standalone triage scratchpad note',
    now: new Date('2026-11-16T05:00:00.000Z'),
  });
  saveNotesAutoSaveState(storage, state);

  const loaded = loadNotesAutoSaveState(storage);
  assert.equal(loaded.draftNotes, 'Standalone triage scratchpad note');
  assert.equal(loaded.activeEntryId, null);

  const cleared = upsertNotesAutoSaveDraft(loaded, {
    entryId: null,
    notes: '',
    now: new Date('2026-11-16T05:01:00.000Z'),
  });
  saveNotesAutoSaveState(storage, cleared);
  assert.equal(storage.map.has(NOTES_AUTOSAVE_STORAGE_KEY), false);
});

test('resolveRestoredNotesForEntry prefers non-empty auto-saved draft over stale history', () => {
  let state = createEmptyNotesAutoSaveState();
  state = upsertNotesAutoSaveDraft(state, {
    entryId: 'inv_2',
    notes: 'Updated periodic finding',
    now: new Date('2026-11-16T06:10:00.000Z'),
  });

  const resolved = resolveRestoredNotesForEntry(state, 'inv_2', 'Older manual note');
  assert.equal(resolved.notes, 'Updated periodic finding');
  assert.equal(resolved.updatedAt, '2026-11-16T06:10:00.000Z');

  const fallback = resolveRestoredNotesForEntry(state, 'inv_other', 'Saved history note');
  assert.equal(fallback.notes, 'Saved history note');
  assert.equal(fallback.updatedAt, null);
});

test('removeEntryFromAutoSaveDrafts deletes removed history entry draft', () => {
  let state = createEmptyNotesAutoSaveState();
  state = upsertNotesAutoSaveDraft(state, {
    entryId: 'inv_del',
    notes: 'Temporary finding',
  });
  const pruned = removeEntryFromAutoSaveDrafts(state, 'inv_del');
  assert.equal(pruned.entryDrafts['inv_del'], undefined);
  assert.equal(pruned.draftNotes, '');
  assert.equal(pruned.activeEntryId, null);
});

test('formatAutoSaveUtcTimestamp formats valid ISO timestamps and ignores invalid ones', () => {
  assert.equal(formatAutoSaveUtcTimestamp('2026-11-16T04:15:30.000Z'), '04:15:30 UTC');
  assert.equal(formatAutoSaveUtcTimestamp(null), '');
  assert.equal(formatAutoSaveUtcTimestamp('not-a-date'), '');
});
