import assert from 'node:assert/strict';
import test from 'node:test';
import {
  clearQuickNotesState,
  DEFAULT_QUICK_NOTES_STATE,
  formatQuickNotesUtc,
  loadQuickNotes,
  QUICK_NOTES_STORAGE_KEY,
  saveQuickNotes,
  summarizeQuickNotesStats,
  toggleQuickNotesCollapsed,
  updateQuickNotesText,
  type StorageLike,
} from './quickNotes';

function createMemoryStorage(initial: Record<string, string> = {}): StorageLike & { data: Record<string, string> } {
  const data: Record<string, string> = { ...initial };
  return {
    data,
    getItem(key: string) {
      return Object.prototype.hasOwnProperty.call(data, key) ? data[key] : null;
    },
    setItem(key: string, value: string) {
      data[key] = value;
    },
  };
}

test('loadQuickNotes handles empty, corrupt, and valid persisted state safely', () => {
  const emptyStorage = createMemoryStorage();
  assert.deepEqual(loadQuickNotes(emptyStorage), DEFAULT_QUICK_NOTES_STATE);

  const corruptStorage = createMemoryStorage({
    [QUICK_NOTES_STORAGE_KEY]: '{not-valid-json',
  });
  assert.deepEqual(loadQuickNotes(corruptStorage), DEFAULT_QUICK_NOTES_STATE);

  const validStorage = createMemoryStorage({
    [QUICK_NOTES_STORAGE_KEY]: JSON.stringify({
      text: 'Check 1.2.3.4 in AbuseIPDB + Shodan',
      updatedAt: '2026-11-16T09:15:30.000Z',
      collapsed: true,
    }),
  });
  const loaded = loadQuickNotes(validStorage);
  assert.equal(loaded.text, 'Check 1.2.3.4 in AbuseIPDB + Shodan');
  assert.equal(loaded.updatedAt, '2026-11-16T09:15:30.000Z');
  assert.equal(loaded.collapsed, true);
});

test('saveQuickNotes and update/clear/collapse helpers persist text across simulated sessions', () => {
  const storage = createMemoryStorage();
  const t1 = new Date('2026-11-16T10:20:30.000Z');
  const updated = updateQuickNotesText(
    DEFAULT_QUICK_NOTES_STATE,
    'Pivot evil.com -> ASN 13335\nTicket INC-4912',
    t1,
  );
  assert.equal(saveQuickNotes(storage, updated), true);

  // Simulate brand new browser session reading localStorage
  const reloaded = loadQuickNotes(storage);
  assert.equal(reloaded.text, 'Pivot evil.com -> ASN 13335\nTicket INC-4912');
  assert.equal(formatQuickNotesUtc(reloaded.updatedAt), '10:20:30 UTC');
  assert.deepEqual(summarizeQuickNotesStats(reloaded.text), {
    characters: 43,
    lines: 2,
  });

  const collapsed = toggleQuickNotesCollapsed(reloaded);
  assert.equal(collapsed.collapsed, true);
  saveQuickNotes(storage, collapsed);
  assert.equal(loadQuickNotes(storage).collapsed, true);

  const cleared = clearQuickNotesState(collapsed, new Date('2026-11-16T10:25:00.000Z'));
  assert.equal(cleared.text, '');
  assert.equal(formatQuickNotesUtc(cleared.updatedAt), '10:25:00 UTC');
  assert.deepEqual(summarizeQuickNotesStats(cleared.text), { characters: 0, lines: 0 });
});
