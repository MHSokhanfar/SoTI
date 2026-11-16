import test from 'node:test';
import assert from 'node:assert/strict';
import {
  loadPrivacyMode,
  maskIndicatorValue,
  maskSensitiveText,
  PRIVACY_MODE_STORAGE_KEY,
  REDACTED_DOMAIN,
  REDACTED_HASH,
  REDACTED_IOC,
  REDACTED_IP,
  REDACTED_URL,
  savePrivacyMode,
} from './privacyMode';

test('maskIndicatorValue leaves original intact when disabled', () => {
  assert.equal(maskIndicatorValue('1.2.3.4', 'ip', false), '1.2.3.4');
  assert.equal(maskIndicatorValue('evil.com', 'domain', false), 'evil.com');
});

test('maskIndicatorValue masks IPv4, defanged IPv4, and IPv6 addresses', () => {
  assert.equal(maskIndicatorValue('1.2.3.4', 'ip', true), REDACTED_IP);
  assert.equal(maskIndicatorValue('1[.]2[.]3[.]4', null, true), REDACTED_IP);
  assert.equal(maskIndicatorValue('2001:db8::1', 'ip', true), REDACTED_IP);
  assert.equal(maskIndicatorValue('::1', null, true), REDACTED_IP);
});

test('maskIndicatorValue masks domains, URLs, and hashes accurately', () => {
  assert.equal(maskIndicatorValue('evil.com', 'domain', true), REDACTED_DOMAIN);
  assert.equal(maskIndicatorValue('sub.evil[.]com', null, true), REDACTED_DOMAIN);
  assert.equal(
    maskIndicatorValue('44d88612fea8a8f36de82e1278abb02f', 'hash', true),
    REDACTED_HASH,
  );
  assert.equal(
    maskIndicatorValue(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      null,
      true,
    ),
    REDACTED_HASH,
  );
  assert.equal(
    maskIndicatorValue('hxxps://evil[.]com/login', 'domain', true),
    REDACTED_URL,
  );
  assert.equal(
    maskIndicatorValue('https://bad.example.org/payload.exe', null, true),
    REDACTED_URL,
  );
  assert.equal(maskIndicatorValue(REDACTED_IP, 'ip', true), REDACTED_IP);
  assert.equal(maskIndicatorValue('unknown-token', null, true), REDACTED_IOC);
});

test('maskSensitiveText masks mixed IOCs while preserving logs, timestamps, filenames, and UI labels', () => {
  const sample =
    '[12:34:56 UTC] Lookup 1[.]2[.]3[.]4, hxxp://evil[.]com/login, bad.c2.net, 44d88612fea8a8f36de82e1278abb02f -> saved reports/soti_report_20260401.csv via URLScan.io (To: soc@example.com)';
  const masked = maskSensitiveText(sample, true);

  assert.ok(masked.includes('[12:34:56 UTC]'));
  assert.ok(masked.includes(REDACTED_IP));
  assert.ok(masked.includes(REDACTED_URL));
  assert.ok(masked.includes(REDACTED_DOMAIN));
  assert.ok(masked.includes(REDACTED_HASH));
  assert.ok(masked.includes('reports/soti_report_20260401.csv'));
  assert.ok(masked.includes('URLScan.io'));
  assert.ok(masked.includes('soc@example.com'));
  assert.ok(!masked.includes('1[.]2[.]3[.]4'));
  assert.ok(!masked.includes('evil[.]com'));
  assert.ok(!masked.includes('bad.c2.net'));
  assert.ok(!masked.includes('44d88612fea8a8f36de82e1278abb02f'));
});

test('maskSensitiveText preserves IPv6 replacement without touching timestamps', () => {
  const input = '2026-04-01 09:15:30 Peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334 flagged';
  const masked = maskSensitiveText(input, true);
  assert.ok(masked.includes('09:15:30'));
  assert.ok(masked.includes(REDACTED_IP));
  assert.ok(!masked.includes('2001:0db8'));
});

test('loadPrivacyMode and savePrivacyMode persist state in storage', () => {
  const mem = new Map<string, string>();
  const mockStorage = {
    getItem: (k: string) => mem.get(k) ?? null,
    setItem: (k: string, v: string) => {
      mem.set(k, v);
    },
  };

  assert.equal(loadPrivacyMode(mockStorage), false);
  savePrivacyMode(mockStorage, true);
  assert.equal(mem.get(PRIVACY_MODE_STORAGE_KEY), '1');
  assert.equal(loadPrivacyMode(mockStorage), true);
  savePrivacyMode(mockStorage, false);
  assert.equal(loadPrivacyMode(mockStorage), false);
});
