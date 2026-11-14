import test from 'node:test';
import assert from 'node:assert/strict';
import {
  extractIndicatorsFromCsv,
  extractIndicatorsFromFile,
  extractIndicatorsFromTxt,
  isSupportedIndicatorFile,
  parseCsvMatrix,
} from './bulkCsv';

test('parseCsvMatrix handles quoted commas, BOM, and CRLF line endings', () => {
  const csv = '\ufeffindicator,notes,verdict\r\n"1[.]2[.]3[.]4","Seen in, logs",Malicious\r\nevil[.]com,Phishing,Suspicious\r\n';
  const matrix = parseCsvMatrix(csv);
  assert.equal(matrix.length, 3);
  assert.deepEqual(matrix[1], ['1[.]2[.]3[.]4', 'Seen in, logs', 'Malicious']);
});

test('extractIndicatorsFromCsv prioritizes IOC header columns, deduplicates, and counts skipped rows', () => {
  const csv = [
    'timestamp,indicator,verdict,notes',
    '2026-11-14,1[.]2[.]3[.]4,Malicious,c2',
    '2026-11-14,hxxps://evil[.]com/login,Malicious,phishing',
    '2026-11-14,8.8.8.8,Clean,dns',
    '2026-11-14,1.2.3.4,Malicious,duplicate',
    '2026-11-14,not-an-indicator,Unknown,noise',
    '2026-11-14,44d88612fea8a8f36de82e1278abb02f,Malicious,eicar',
  ].join('\n');

  const res = extractIndicatorsFromCsv(csv);
  assert.deepEqual(res.detectedColumns, ['indicator']);
  assert.deepEqual(res.indicators, [
    '1.2.3.4',
    'evil.com',
    '8.8.8.8',
    '44d88612fea8a8f36de82e1278abb02f',
  ]);
  assert.equal(res.validCount, 4);
  assert.equal(res.skippedCount, 1);
  assert.deepEqual(res.breakdown, { ip: 2, domain: 1, hash: 1 });
  assert.equal(res.sourceFormat, 'csv');
});

test('extractIndicatorsFromCsv extracts IOCs cleanly from headerless CSV files', () => {
  const csv = '8.8.8.8,clean\nexample.org,clean\n';
  const res = extractIndicatorsFromCsv(csv);
  assert.deepEqual(res.indicators, ['8.8.8.8', 'example.org']);
  assert.equal(res.totalRows, 2);
});

test('extractIndicatorsFromTxt extracts refanged IOCs, ignores comments, and counts skipped lines', () => {
  const txt = [
    '# Daily Watchlist Feed',
    '- 1[.]2[.]3[.]4 # Known C2 server',
    'hxxps://evil[.]com/login, 8.8.8.8; 1.2.3.4',
    '// Ignore this line completely',
    '44d88612fea8a8f36de82e1278abb02f',
    'random prose with no valid observable',
  ].join('\n');

  const res = extractIndicatorsFromTxt(txt);
  assert.equal(res.sourceFormat, 'txt');
  assert.deepEqual(res.indicators, [
    '1.2.3.4',
    'evil.com',
    '8.8.8.8',
    '44d88612fea8a8f36de82e1278abb02f',
  ]);
  assert.equal(res.validCount, 4);
  assert.equal(res.skippedCount, 1);
  assert.deepEqual(res.breakdown, { ip: 2, domain: 1, hash: 1 });
});

test('isSupportedIndicatorFile and extractIndicatorsFromFile dispatch CSV and TXT accurately', () => {
  assert.equal(isSupportedIndicatorFile('feed.csv'), true);
  assert.equal(isSupportedIndicatorFile('feed.TXT'), true);
  assert.equal(isSupportedIndicatorFile('malware.exe'), false);

  const fromTxt = extractIndicatorsFromFile('9.9.9.9\nhxxp://phish[.]org/a', 'watchlist.txt', 'text/plain');
  assert.equal(fromTxt.sourceFormat, 'txt');
  assert.equal(fromTxt.rawText, '9.9.9.9, phish.org');

  const fromCsv = extractIndicatorsFromFile('ioc,notes\n8.8.8.8,google', 'feed.csv', 'text/csv');
  assert.equal(fromCsv.sourceFormat, 'csv');
  assert.equal(fromCsv.rawText, '8.8.8.8');
});
