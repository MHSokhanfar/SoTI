import assert from 'node:assert/strict';
import test from 'node:test';
import type { LookupResult } from './indicators';
import type { StorageLike } from './investigationHistory';
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
  WATCHLIST_STORAGE_KEY,
} from './watchlist';

function createMemoryStorage(): StorageLike {
  const store = new Map<string, string>();
  return {
    getItem: (k) => store.get(k) ?? null,
    setItem: (k, v) => {
      store.set(k, v);
    },
    removeItem: (k) => {
      store.delete(k);
    },
  };
}

function makeLookup(indicator: string, verdict: LookupResult['verdict'], detections: number): LookupResult {
  return {
    indicator,
    originalToken: indicator,
    type: 'ip',
    source: 'VirusTotal',
    sourceId: 'virustotal',
    verdict,
    score: `${detections}/91`,
    summary: `${detections} engines flagged`,
    status: 'ok',
    link: '',
    details: {},
  };
}

test('addIocToWatchlist normalizes defanged IOCs, deduplicates, and removes cleanly', () => {
  const res1 = addIocToWatchlist([], {
    indicator: '1[.]2[.]3[.]4',
    verdict: 'Clean',
    confidenceScore: 0,
  });
  assert.ok(res1.added);
  assert.equal(res1.added.indicator, '1.2.3.4');
  assert.equal(isWatchlistIndicator(res1.next, '1.2.3.4'), true);

  // Duplicate check
  const resDup = addIocToWatchlist(res1.next, { indicator: '1.2.3.4' });
  assert.equal(resDup.added, null);
  assert.equal(resDup.next.length, 1);

  const afterRemove = removeIocFromWatchlist(res1.next, '1.2.3.4');
  assert.equal(afterRemove.length, 0);
});

test('evaluateWatchlistUpdates detects verdict/score escalations and tracks unread notification badges', () => {
  let list = addIocToWatchlist([], {
    indicator: '8.8.8.8',
    verdict: 'Clean',
    confidenceScore: 0,
    now: new Date('2026-11-15T10:00:00Z'),
  }).next;
  list = addIocToWatchlist(list, {
    indicator: 'evil.com',
  }).next;

  // Unchanged 8.8.8.8 + initial baseline capture for evil.com should not trigger unread notifications
  const pass1 = evaluateWatchlistUpdates(
    list,
    [makeLookup('8.8.8.8', 'Clean', 0), makeLookup('evil.com', 'Malicious', 20)],
    '2026-11-15T10:05:00Z',
  );
  assert.deepEqual(pass1.changedIndicators, []);
  assert.equal(countUnreadWatchlistUpdates(pass1.next), 0);

  // Escalation on 8.8.8.8 triggers an unread status update!
  const pass2 = evaluateWatchlistUpdates(
    pass1.next,
    [makeLookup('8.8.8.8', 'Malicious', 15)],
    '2026-11-15T10:15:00Z',
  );
  assert.deepEqual(pass2.changedIndicators, ['8.8.8.8']);
  assert.equal(countUnreadWatchlistUpdates(pass2.next), 1);
  const item8888 = pass2.next.find((i) => i.indicator === '8.8.8.8')!;
  assert.equal(item8888.lastVerdict, 'Malicious');
  assert.ok(item8888.lastChange?.summary.includes('Clean -> Malicious'));

  const ackOne = markWatchlistItemSeen(pass2.next, '8.8.8.8');
  assert.equal(countUnreadWatchlistUpdates(ackOne), 0);

  const ackAll = markAllWatchlistUpdatesSeen(pass2.next);
  assert.equal(countUnreadWatchlistUpdates(ackAll), 0);
});

test('loadWatchlist, saveWatchlist, loadSidebarTab, and saveSidebarTab persist cleanly', () => {
  const storage = createMemoryStorage();
  const list = addIocToWatchlist([], {
    indicator: '44d88612fea8a8f36de82e1278abb02f',
    verdict: 'Malicious',
    confidenceScore: 90,
  }).next;

  assert.equal(saveWatchlist(storage, list), true);
  assert.equal(loadWatchlist(storage).length, 1);

  storage.setItem(WATCHLIST_STORAGE_KEY, '{corrupt');
  assert.deepEqual(loadWatchlist(storage), []);

  assert.equal(loadSidebarTab(storage), 'recent');
  saveSidebarTab(storage, 'watchlist');
  assert.equal(loadSidebarTab(storage), 'watchlist');
});
