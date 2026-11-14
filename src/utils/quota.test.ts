import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildQuotaSnapshots,
  getQuotaWarningProviders,
  normalizeQuotaLedger,
  partitionSourcesByQuota,
  recordQuotaConsumption,
} from './quota';

test('normalizeQuotaLedger rolls over usage cleanly on a new UTC date', () => {
  const yesterday = {
    date: '2026-11-12',
    usage: {
      virustotal: { used: 500, limit: 500, exhausted: true, lastUpdatedAt: '2026-11-12T23:55:00Z' },
    },
  };
  const today = new Date('2026-11-13T00:05:00Z');
  const fresh = normalizeQuotaLedger(yesterday, { virustotal: 500, abuseipdb: 1000 }, today);

  assert.equal(fresh.date, '2026-11-13');
  assert.equal(fresh.usage.virustotal.used, 0);
  assert.equal(fresh.usage.virustotal.exhausted, false);
});

test('recordQuotaConsumption and partitionSourcesByQuota allow other APIs to run when one hits daily quota', () => {
  const now = new Date('2026-11-14T10:00:00Z');
  let ledger = normalizeQuotaLedger(null, { virustotal: 2, abuseipdb: 100, alienvault: 500 }, now);

  ledger = recordQuotaConsumption(ledger, 'virustotal', 2, { httpStatus: 200, now });
  ledger = recordQuotaConsumption(ledger, 'virustotal', 2, { httpStatus: 200, now });
  ledger = recordQuotaConsumption(ledger, 'abuseipdb', 100, { httpStatus: 200, now });

  const { availableSources, exhaustedSources } = partitionSourcesByQuota(
    ['virustotal', 'abuseipdb', 'alienvault'],
    ledger,
    { virustotal: 2, abuseipdb: 100, alienvault: 500 },
  );

  assert.deepEqual(availableSources, ['abuseipdb', 'alienvault']);
  assert.equal(exhaustedSources.length, 1);
  assert.equal(exhaustedSources[0].providerId, 'virustotal');
  assert.equal(exhaustedSources[0].used, 2);

  const snapshots = buildQuotaSnapshots(ledger, [
    { id: 'virustotal', name: 'VirusTotal', limit: 2 },
    { id: 'abuseipdb', name: 'AbuseIPDB', limit: 100 },
  ]);
  assert.equal(snapshots[0].exhausted, true);
  assert.equal(snapshots[0].percentUsed, 100);
  assert.equal(snapshots[1].exhausted, false);
  assert.equal(snapshots[1].remaining, 99);
});

test('HTTP 429 immediately marks provider exhausted while preserving other providers', () => {
  const now = new Date('2026-11-14T10:00:00Z');
  let ledger = normalizeQuotaLedger(null, { virustotal: 500, shodan: 100 }, now);
  ledger = recordQuotaConsumption(ledger, 'virustotal', 500, { httpStatus: 429, now });

  const part = partitionSourcesByQuota(['virustotal', 'shodan'], ledger, { virustotal: 500, shodan: 100 });
  assert.deepEqual(part.availableSources, ['shodan']);
  assert.equal(part.exhaustedSources[0].providerId, 'virustotal');
});

test('getQuotaWarningProviders triggers strictly above 80% before limit is reached', () => {
  const now = new Date('2026-11-14T10:00:00Z');
  let ledger = normalizeQuotaLedger(
    null,
    { virustotal: 10, abuseipdb: 10, alienvault: 10 },
    now,
  );

  // VirusTotal: 8/10 (80% -> should NOT warn)
  for (let i = 0; i < 8; i++) {
    ledger = recordQuotaConsumption(ledger, 'virustotal', 10, { httpStatus: 200, now });
  }
  // AbuseIPDB: 9/10 (90% -> SHOULD warn)
  for (let i = 0; i < 9; i++) {
    ledger = recordQuotaConsumption(ledger, 'abuseipdb', 10, { httpStatus: 200, now });
  }
  // AlienVault: 10/10 (100% exhausted -> already handled by failover, not pre-limit warning)
  for (let i = 0; i < 10; i++) {
    ledger = recordQuotaConsumption(ledger, 'alienvault', 10, { httpStatus: 200, now });
  }

  const snapshots = buildQuotaSnapshots(ledger, [
    { id: 'virustotal', name: 'VirusTotal', limit: 10 },
    { id: 'abuseipdb', name: 'AbuseIPDB', limit: 10 },
    { id: 'alienvault', name: 'AlienVault OTX', limit: 10 },
  ]);

  const warnings = getQuotaWarningProviders(snapshots);
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0].providerId, 'abuseipdb');
  assert.equal(warnings[0].percentUsed, 90);
});
