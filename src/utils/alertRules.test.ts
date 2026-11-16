import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAlertRuleHistoryEntries,
  buildDesktopNotificationsFromHits,
  DEFAULT_CUSTOM_ALERT_RULES,
  evaluateCustomAlertRules,
  formatDesktopBrowserNotificationContent,
  loadCustomAlertRules,
  saveCustomAlertRules,
  validateAndNormalizeAlertRuleDraft,
  type CustomAlertRule,
} from './alertRules';
import type { LookupResult } from './indicators';

const SAMPLE_RESULTS: LookupResult[] = [
  {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: 'evil.com',
    originalToken: 'evil[.]com',
    type: 'domain',
    status: 'ok',
    verdict: 'Malicious',
    score: '18/92',
    summary: '18 malicious detections',
    details: { Malicious: 18, 'Total Engines': 92 },
    link: 'https://www.virustotal.com',
  },
  {
    source: 'AlienVault OTX',
    sourceId: 'alienvault',
    indicator: 'evil.com',
    originalToken: 'evil[.]com',
    type: 'domain',
    status: 'ok',
    verdict: 'Malicious',
    score: '9 pulses',
    summary: '9 threat pulses',
    details: { Pulses: 9 },
    link: 'https://otx.alienvault.com',
  },
  {
    source: 'VirusTotal',
    sourceId: 'virustotal',
    indicator: '8.8.8.8',
    originalToken: '8.8.8.8',
    type: 'ip',
    status: 'ok',
    verdict: 'Clean',
    score: '0/92',
    summary: 'Clean resolver',
    details: { Malicious: 0, 'Total Engines': 92 },
    link: 'https://www.virustotal.com',
  },
  {
    source: 'AbuseIPDB',
    sourceId: 'abuseipdb',
    indicator: '1.2.3.4',
    originalToken: '1.2.3.4',
    type: 'ip',
    status: 'ok',
    verdict: 'Malicious',
    score: '90%',
    summary: 'Abuse confidence 90%',
    details: { 'Abuse Confidence Score': 90 },
    link: 'https://www.abuseipdb.com',
  },
];

test('validateAndNormalizeAlertRuleDraft enforces rule constraints and email syntax', () => {
  const missingName = validateAndNormalizeAlertRuleDraft({
    name: '   ',
    indicatorType: 'domain',
    minRiskScore: 60,
    channel: 'desktop',
  });
  assert.equal(missingName.ok, false);

  const badScore = validateAndNormalizeAlertRuleDraft({
    name: 'Bad Threshold',
    indicatorType: 'domain',
    minRiskScore: 150,
    channel: 'desktop',
  });
  assert.equal(badScore.ok, false);

  const badEmail = validateAndNormalizeAlertRuleDraft({
    name: 'Bad Email Rule',
    indicatorType: 'domain',
    minRiskScore: 55,
    channel: 'email',
    emailRecipientsInput: 'soc@example.com, not-an-email',
  });
  assert.equal(badEmail.ok, false);

  const valid = validateAndNormalizeAlertRuleDraft({
    name: '  Domain C2 Rule  ',
    indicatorType: 'domain',
    minRiskScore: 55,
    verdictScope: 'malicious_only',
    patternFilter: 'evil',
    channel: 'both',
    emailRecipientsInput: 'soc@example.com; lead@example.com',
    triggerOnSampleRuns: true,
  });
  assert.equal(valid.ok, true);
  if (valid.ok) {
    assert.equal(valid.rule.name, 'Domain C2 Rule');
    assert.equal(valid.rule.minRiskScore, 55);
    assert.deepEqual(valid.rule.emailRecipients, ['soc@example.com', 'lead@example.com']);
  }
});

test('evaluateCustomAlertRules filters by indicatorType, score threshold, verdict, pattern, and sample flag', () => {
  const domainRule: CustomAlertRule = {
    id: 'r-domain',
    name: 'Domain >= 50',
    enabled: true,
    indicatorType: 'domain',
    minRiskScore: 50,
    verdictScope: 'malicious_only',
    patternFilter: '',
    channel: 'both',
    emailRecipients: ['soc@example.com'],
    triggerOnSampleRuns: true,
    createdAt: '2026-04-01T00:00:00Z',
    lastTriggeredAt: null,
    triggerCount: 0,
  };

  const disabledRule: CustomAlertRule = {
    ...domainRule,
    id: 'r-disabled',
    name: 'Disabled IP',
    enabled: false,
    indicatorType: 'ip',
    minRiskScore: 10,
  };

  const liveOnlyRule: CustomAlertRule = {
    ...domainRule,
    id: 'r-live-only',
    name: 'Live Only IP',
    indicatorType: 'ip',
    triggerOnSampleRuns: false,
  };

  const sampleEval = evaluateCustomAlertRules({
    rules: [domainRule, disabledRule, liveOnlyRule],
    results: SAMPLE_RESULTS,
    mode: 'sample',
    nowIso: '2026-04-01T12:00:00Z',
  });

  assert.equal(sampleEval.hits.length, 1);
  assert.equal(sampleEval.hits[0].rule.id, 'r-domain');
  assert.equal(sampleEval.hits[0].matches.length, 1);
  assert.equal(sampleEval.hits[0].matches[0].indicator, 'evil.com');
  assert.equal(sampleEval.updatedRules[0].triggerCount, 1);
  assert.equal(sampleEval.updatedRules[0].lastTriggeredAt, '2026-04-01T12:00:00Z');
  assert.equal(sampleEval.updatedRules[2].triggerCount, 0);

  const liveEval = evaluateCustomAlertRules({
    rules: [liveOnlyRule],
    results: SAMPLE_RESULTS,
    mode: 'live',
  });
  assert.equal(liveEval.hits.length, 1);
  assert.equal(liveEval.hits[0].matches[0].indicator, '1.2.3.4');
});

test('desktop notification and trigger history builders support privacy masking', () => {
  const rule = DEFAULT_CUSTOM_ALERT_RULES[0];
  const evaluation = evaluateCustomAlertRules({
    rules: [rule],
    results: SAMPLE_RESULTS,
    mode: 'sample',
    nowIso: '2026-04-01T12:00:00Z',
  });

  const desktopAlerts = buildDesktopNotificationsFromHits(
    evaluation.hits,
    '2026-04-01T12:00:00Z',
  );
  assert.equal(desktopAlerts.length, 1);
  const formattedUnmasked = formatDesktopBrowserNotificationContent(desktopAlerts[0]);
  assert.ok(formattedUnmasked.body.includes('evil.com'));

  const formattedMasked = formatDesktopBrowserNotificationContent(
    desktopAlerts[0],
    () => '[REDACTED-DOMAIN]',
  );
  assert.ok(formattedMasked.body.includes('[REDACTED-DOMAIN]'));
  assert.ok(!formattedMasked.body.includes('evil.com'));

  const history = buildAlertRuleHistoryEntries(evaluation.hits, 'sample', '2026-04-01T12:00:00Z');
  assert.equal(history.length, 1);
  assert.equal(history[0].matchCount, 1);
  assert.equal(history[0].topIndicators[0].indicator, 'evil.com');
});

test('loadCustomAlertRules and saveCustomAlertRules persist across storage', () => {
  const mem = new Map<string, string>();
  const mockStorage = {
    getItem: (k: string) => mem.get(k) ?? null,
    setItem: (k: string, v: string) => {
      mem.set(k, v);
    },
  };
  const defaults = loadCustomAlertRules(mockStorage);
  assert.ok(defaults.length >= 2);
  saveCustomAlertRules(mockStorage, [defaults[0]]);
  const reloaded = loadCustomAlertRules(mockStorage);
  assert.equal(reloaded.length, 1);
  assert.equal(reloaded[0].id, defaults[0].id);
});
