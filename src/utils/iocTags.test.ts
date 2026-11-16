import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildRecentInvestigationEntry,
  type StorageLike,
} from './investigationHistory';
import {
  addTagToIndicator,
  collectTagsForIndicators,
  filterItemsByIndicatorTag,
  filterRecentInvestigationsByTag,
  getAllUniqueTags,
  getTagsForIndicator,
  getUniqueTagsForIndicators,
  indicatorMatchesTagFilter,
  IOC_TAGS_STORAGE_KEY,
  loadIndicatorTags,
  normalizeTagLabel,
  removeTagFromIndicator,
  saveIndicatorTags,
  syncRecentInvestigationsTags,
} from './iocTags';

function createMemoryStorage(): StorageLike {
  const map = new Map<string, string>();
  return {
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => {
      map.set(k, v);
    },
    removeItem: (k) => {
      map.delete(k);
    },
  };
}

test('normalizeTagLabel, addTagToIndicator, and removeTagFromIndicator manage case-insensitive tags cleanly', () => {
  assert.equal(normalizeTagLabel('  Phishing  '), 'Phishing');
  assert.equal(normalizeTagLabel('   '), null);
  assert.equal(normalizeTagLabel('Malware,\nC2'), 'Malware C2');

  let map = addTagToIndicator({}, 'EVIL.COM', 'Phishing');
  map = addTagToIndicator(map, 'evil.com', 'phishing'); // duplicate differing only in case
  map = addTagToIndicator(map, 'evil.com', 'Critical');

  assert.deepEqual(getTagsForIndicator(map, 'evil.com'), ['Phishing', 'Critical']);
  assert.deepEqual(getTagsForIndicator(map, 'EVIL.COM'), ['Phishing', 'Critical']);

  map = removeTagFromIndicator(map, 'evil.com', 'phishing');
  assert.deepEqual(getTagsForIndicator(map, 'evil.com'), ['Critical']);

  map = removeTagFromIndicator(map, 'evil.com', 'Critical');
  assert.deepEqual(getTagsForIndicator(map, 'evil.com'), []);
  assert.equal('evil.com' in map, false);
});

test('syncRecentInvestigationsTags, getAllUniqueTags, and filterRecentInvestigationsByTag work across entries', () => {
  const entryA = buildRecentInvestigationEntry({
    id: 'a',
    rawInput: 'evil.com',
    normalizedInput: 'evil.com',
    indicators: ['evil.com'],
    source: 'all',
    customSources: [],
    useCustomSources: false,
    sourceLabels: ['VirusTotal'],
    mode: 'sample',
    results: [],
    invalidTokens: [],
    quotaSkipped: [],
    reportFile: null,
  });

  const entryB = buildRecentInvestigationEntry({
    id: 'b',
    rawInput: '1.2.3.4, 8.8.8.8',
    normalizedInput: '1.2.3.4, 8.8.8.8',
    indicators: ['1.2.3.4', '8.8.8.8'],
    source: 'all',
    customSources: [],
    useCustomSources: false,
    sourceLabels: ['AbuseIPDB'],
    mode: 'sample',
    results: [],
    invalidTokens: [],
    quotaSkipped: [],
    reportFile: null,
  });

  let tagMap = addTagToIndicator({}, 'evil.com', 'Phishing');
  tagMap = addTagToIndicator(tagMap, '1.2.3.4', 'Critical');
  tagMap = addTagToIndicator(tagMap, '1.2.3.4', 'Malware');

  const synced = syncRecentInvestigationsTags([entryA, entryB], tagMap);
  assert.deepEqual(synced[0].tags, ['Phishing']);
  assert.deepEqual(synced[1].tags, ['Critical', 'Malware']);

  assert.deepEqual(collectTagsForIndicators(tagMap, ['1.2.3.4', 'evil.com']), [
    'Critical',
    'Malware',
    'Phishing',
  ]);

  assert.deepEqual(getAllUniqueTags(synced, tagMap), ['Critical', 'Malware', 'Phishing']);

  assert.equal(filterRecentInvestigationsByTag(synced, 'All', tagMap).length, 2);
  assert.deepEqual(
    filterRecentInvestigationsByTag(synced, 'phishing', tagMap).map((e) => e.id),
    ['a'],
  );
  assert.deepEqual(
    filterRecentInvestigationsByTag(synced, 'Critical', tagMap).map((e) => e.id),
    ['b'],
  );
  assert.deepEqual(filterRecentInvestigationsByTag(synced, 'UnknownTag', tagMap), []);
});

test('loadIndicatorTags and saveIndicatorTags handle storage persistence and corrupt payloads', () => {
  const storage = createMemoryStorage();
  let map = addTagToIndicator({}, '1.2.3.4', 'Malware');
  map = addTagToIndicator(map, 'evil.com', 'Phishing');

  assert.equal(saveIndicatorTags(storage, map), true);
  assert.deepEqual(loadIndicatorTags(storage), {
    '1.2.3.4': ['Malware'],
    'evil.com': ['Phishing'],
  });

  storage.setItem(IOC_TAGS_STORAGE_KEY, '{not-json');
  assert.deepEqual(loadIndicatorTags(storage), {});

  assert.equal(saveIndicatorTags(storage, {}), true);
  assert.equal(storage.getItem(IOC_TAGS_STORAGE_KEY), null);
});

test('getUniqueTagsForIndicators and filterItemsByIndicatorTag support in-table triage filtering', () => {
  let map = addTagToIndicator({}, '1.2.3.4', 'Malware');
  map = addTagToIndicator(map, '1.2.3.4', 'Critical');
  map = addTagToIndicator(map, '8.8.8.8', 'False Positive');
  map = addTagToIndicator(map, 'evil.com', 'Phishing');

  const unique = getUniqueTagsForIndicators(map, ['1.2.3.4', '8.8.8.8', '9.9.9.9']);
  assert.deepEqual(unique, ['Critical', 'False Positive', 'Malware']);

  assert.equal(indicatorMatchesTagFilter(map, '8.8.8.8', 'false positive'), true);
  assert.equal(indicatorMatchesTagFilter(map, '1.2.3.4', 'False Positive'), false);

  const rows = [
    { indicator: '1.2.3.4', source: 'VirusTotal' },
    { indicator: '8.8.8.8', source: 'VirusTotal' },
    { indicator: 'evil.com', source: 'AlienVault OTX' },
  ];
  assert.deepEqual(
    filterItemsByIndicatorTag(rows, 'All', map).map((r) => r.indicator),
    ['1.2.3.4', '8.8.8.8', 'evil.com'],
  );
  assert.deepEqual(
    filterItemsByIndicatorTag(rows, 'False Positive', map).map((r) => r.indicator),
    ['8.8.8.8'],
  );
  assert.deepEqual(
    filterItemsByIndicatorTag(rows, 'Phishing', map).map((r) => r.indicator),
    ['evil.com'],
  );
});

