import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildThresholdAlertEmailContent,
  DEFAULT_EMAIL_ALERT_CONFIG,
  evaluateEmailAlertTriggers,
  parseRecipientList,
  validateAndNormalizeEmailAlertConfig,
} from './emailAlerts';
import type { IocConfidenceSummary } from './riskScoring';

function makeConfidence(overrides: Partial<IocConfidenceSummary>): IocConfidenceSummary {
  return {
    indicator: '1.2.3.4',
    confidenceScore: 84,
    riskLevel: 'Critical',
    activeProviderCount: 5,
    totalResultCount: 5,
    breakdown: [],
    summaryText: '84/100 Critical',
    explanation: 'VirusTotal: 75/100 (31% wt) · ThreatFox: 95/100 (18% wt)',
    ...overrides,
  };
}

test('parseRecipientList and validateAndNormalizeEmailAlertConfig validate recipients and thresholds', () => {
  const parsed = parseRecipientList('alice@soc.example, bob@soc.example; ALICE@soc.example, not-an-email');
  assert.deepEqual(parsed.valid, ['alice@soc.example', 'bob@soc.example']);
  assert.deepEqual(parsed.invalid, ['not-an-email']);

  const invalidEnabled = validateAndNormalizeEmailAlertConfig({
    enabled: true,
    recipientsInput: '',
    riskTierPreset: 'Critical',
  });
  assert.equal(invalidEnabled.ok, false);

  const validCritical = validateAndNormalizeEmailAlertConfig({
    enabled: true,
    recipientsInput: 'soc@company.com, lead@company.com',
    riskTierPreset: 'Critical',
    cooldownMinutes: 15,
    subjectPrefix: '[SOC-CRIT]\r\nInjected',
  });
  assert.equal(validCritical.ok, true);
  if (validCritical.ok) {
    assert.equal(validCritical.config.minConfidenceScore, 75);
    assert.equal(validCritical.config.recipients.length, 2);
    assert.equal(validCritical.config.subjectPrefix, '[SOC-CRIT] Injected');
  }

  const validCustom = validateAndNormalizeEmailAlertConfig({
    enabled: true,
    recipientsInput: 'analyst@company.com',
    riskTierPreset: 'Custom',
    minConfidenceScore: 62,
  });
  assert.equal(validCustom.ok, true);
  if (validCustom.ok) {
    assert.equal(validCustom.config.minConfidenceScore, 62);
  }
});

test('evaluateEmailAlertTriggers checks thresholds, sample run policy, and cooldown windows', () => {
  const config = {
    ...DEFAULT_EMAIL_ALERT_CONFIG,
    enabled: true,
    recipients: ['soc@company.com'],
    riskTierPreset: 'Critical' as const,
    minConfidenceScore: 75,
    triggerOnSampleRuns: true,
    cooldownMinutes: 30,
  };

  const summaries = [
    makeConfidence({ indicator: '1.2.3.4', confidenceScore: 84, riskLevel: 'Critical' }),
    makeConfidence({ indicator: 'suspicious.net', confidenceScore: 60, riskLevel: 'High' }),
    makeConfidence({ indicator: '8.8.8.8', confidenceScore: 0, riskLevel: 'Low' }),
  ];

  const t0 = 1_700_000_000_000;
  const firstRun = evaluateEmailAlertTriggers({
    config,
    summaries,
    mode: 'sample',
    lastAlertedAtByIndicator: {},
    nowMs: t0,
  });
  assert.equal(firstRun.shouldTrigger, true);
  assert.deepEqual(
    firstRun.triggered.map((t) => t.indicator),
    ['1.2.3.4'],
  );

  // Within cooldown window (5 min later): skipped
  const secondRun = evaluateEmailAlertTriggers({
    config,
    summaries,
    mode: 'sample',
    lastAlertedAtByIndicator: firstRun.nextLastAlertedAtByIndicator,
    nowMs: t0 + 5 * 60_000,
  });
  assert.equal(secondRun.shouldTrigger, false);
  assert.deepEqual(secondRun.skippedCooldown, ['1.2.3.4']);

  // After cooldown expires (35 min later): triggers again
  const thirdRun = evaluateEmailAlertTriggers({
    config,
    summaries,
    mode: 'live',
    lastAlertedAtByIndicator: firstRun.nextLastAlertedAtByIndicator,
    nowMs: t0 + 35 * 60_000,
  });
  assert.equal(thirdRun.shouldTrigger, true);
});

test('buildThresholdAlertEmailContent formats subject, body, and RFC-5322 EML safely', () => {
  const email = buildThresholdAlertEmailContent({
    config: {
      ...DEFAULT_EMAIL_ALERT_CONFIG,
      enabled: true,
      recipients: ['analyst@soc.org'],
      riskTierPreset: 'Critical',
      minConfidenceScore: 75,
    },
    triggered: [
      {
        indicator: '1.2.3.4',
        confidenceScore: 88,
        riskLevel: 'Critical',
        activeProviderCount: 5,
        explanation: 'VirusTotal: 80/100 (33% wt)',
      },
    ],
    mode: 'live',
    fromAddress: 'alerts@soti.local',
    reportFile: 'soti_20261115_040000.csv',
    now: new Date('2026-11-15T04:00:00.000Z'),
  });

  assert.ok(email.subject.includes('[SoTI Alert] Critical IOC Detected: 1.2.3.4 (88/100)'));
  assert.ok(email.textBody.includes('1.2.3.4 — 88/100 (Critical)'));
  assert.ok(email.emlContent.includes('To: analyst@soc.org'));
  assert.ok(email.emlContent.includes('MIME-Version: 1.0'));
});
