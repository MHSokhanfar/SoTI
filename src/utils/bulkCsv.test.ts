import test from 'node:test';
import assert from 'node:assert/strict';
import {
  extractIndicatorsFromCsv,
  extractIndicatorsFromFile,
  extractIndicatorsFromTxt,
  formatBulkIndicatorsText,
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
  assert.equal(
    formatBulkIndicatorsText(res),
    '1.2.3.4\nevil.com\n8.8.8.8\n44d88612fea8a8f36de82e1278abb02f',
  );
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

test('extractIndicatorsFromCsv discovers all columns and extracts strictly from a designated column', () => {
  const csv = [
    'timestamp,src_ip,target_domain,payload_sha256,analyst_note',
    '2026-11-16,1[.]2[.]3[.]4,evil[.]com,44d88612fea8a8f36de82e1278abb02f,c2 beacon',
    '2026-11-16,8.8.8.8,sub.example.org,d41d8cd98f00b204e9800998ecf8427e,clean dns check',
  ].join('\n');

  const autoRes = extractIndicatorsFromCsv(csv);
  assert.equal(autoRes.hasHeaderRow, true);
  assert.equal(autoRes.availableColumns?.length, 5);
  assert.equal(autoRes.availableColumns?.[1].name, 'src_ip');
  assert.equal(autoRes.availableColumns?.[1].validCount, 2);
  assert.equal(autoRes.availableColumns?.[2].name, 'target_domain');
  assert.equal(autoRes.availableColumns?.[2].validCount, 2);
  assert.equal(autoRes.availableColumns?.[4].validCount, 0);

  const domainOnly = extractIndicatorsFromFile(csv, 'multi_col.csv', 'text/csv', {
    designatedColumn: 'target_domain',
  });
  assert.equal(domainOnly.designatedColumn, 'target_domain');
  assert.deepEqual(domainOnly.indicators, ['evil.com', 'sub.example.org']);
  assert.deepEqual(domainOnly.breakdown, { ip: 0, domain: 2, hash: 0 });

  const hashOnly = extractIndicatorsFromCsv(csv, { designatedColumn: 'payload_sha256' });
  assert.equal(hashOnly.designatedColumn, 'payload_sha256');
  assert.deepEqual(hashOnly.indicators, [
    '44d88612fea8a8f36de82e1278abb02f',
    'd41d8cd98f00b204e9800998ecf8427e',
  ]);
  assert.deepEqual(hashOnly.breakdown, { ip: 0, domain: 0, hash: 2 });
});
