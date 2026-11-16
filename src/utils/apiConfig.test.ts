import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCustomEndpointUrl,
  buildHeartbeatEndpoint,
  buildTopBarApiStatuses,
  classifyLatencyTier,
  cloneDefaultApiSettings,
  DEFAULT_API_SETTINGS,
  evaluateHeartbeatResponse,
  formatLatencyMs,
  getAllEnabledProviderIds,
  getEnabledSourceIds,
  isEditableThreatIntelEnvVar,
  maskSecretHint,
  mergeConfigAndConnectionStatus,
  normalizeLatencyMs,
  resolveSelectedSources,
  summarizeTopBarApiGroup,
  validateAndNormalizeApiSettings,
  validateCustomThreatProvider,
  validateSingleProviderUrl,
} from './apiConfig';

test('validateAndNormalizeApiSettings strips trailing slashes and preserves valid settings', () => {
  const input = cloneDefaultApiSettings();
  input.providers.virustotal.baseUrl = 'https://proxy.corp.local/vt/v3///';
  input.providers.abuseipdb.enabled = false;
  input.timeoutSeconds = 30;
  input.abuseMaxAgeDays = 180;

  const res = validateAndNormalizeApiSettings(input);
  assert.equal(res.ok, true);
  if (res.ok) {
    assert.equal(res.settings.providers.virustotal.baseUrl, 'https://proxy.corp.local/vt/v3');
    assert.equal(res.settings.providers.abuseipdb.enabled, false);
    assert.equal(res.settings.timeoutSeconds, 30);
    assert.equal(res.settings.abuseMaxAgeDays, 180);
  }
});

test('validateAndNormalizeApiSettings rejects all-disabled APIs, bad URLs, and out-of-range limits', () => {
  const noneEnabled = cloneDefaultApiSettings();
  noneEnabled.providers.virustotal.enabled = false;
  noneEnabled.providers.abuseipdb.enabled = false;
  noneEnabled.providers.alienvault.enabled = false;
  assert.equal(validateAndNormalizeApiSettings(noneEnabled).ok, false);

  const badUrl = cloneDefaultApiSettings();
  badUrl.providers.alienvault.baseUrl = 'ftp://invalid-scheme.local';
  assert.equal(validateAndNormalizeApiSettings(badUrl).ok, false);

  const badTimeout = cloneDefaultApiSettings();
  badTimeout.timeoutSeconds = 2;
  assert.equal(validateAndNormalizeApiSettings(badTimeout).ok, false);

  const badMaxAge = cloneDefaultApiSettings();
  badMaxAge.abuseMaxAgeDays = 400;
  assert.equal(validateAndNormalizeApiSettings(badMaxAge).ok, false);
});

test('resolveSelectedSources respects disabled providers for all-source runs and explicit custom arrays', () => {
  const settings = cloneDefaultApiSettings();
  settings.providers.abuseipdb.enabled = false;

  assert.deepEqual(getEnabledSourceIds(settings), ['virustotal', 'alienvault']);
  assert.deepEqual(resolveSelectedSources('all', settings), ['virustotal', 'alienvault']);
  assert.deepEqual(resolveSelectedSources('all', DEFAULT_API_SETTINGS, ['abuseipdb', 'alienvault', 'abuseipdb']), [
    'abuseipdb',
    'alienvault',
  ]);
  assert.deepEqual(resolveSelectedSources('virustotal', settings), ['virustotal']);
});

test('validateSingleProviderUrl, buildHeartbeatEndpoint, and evaluateHeartbeatResponse cover all providers and statuses', () => {
  assert.deepEqual(validateSingleProviderUrl('https://www.virustotal.com/api/v3/', 'virustotal'), {
    ok: true,
    url: 'https://www.virustotal.com/api/v3',
  });
  assert.equal(validateSingleProviderUrl('not-a-url', 'abuseipdb').ok, false);

  assert.equal(
    buildHeartbeatEndpoint('virustotal', 'https://www.virustotal.com/api/v3/'),
    'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8',
  );
  assert.equal(
    buildHeartbeatEndpoint('abuseipdb', 'https://api.abuseipdb.com/api/v2'),
    'https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=30',
  );
  assert.equal(
    buildHeartbeatEndpoint('alienvault', 'https://otx.alienvault.com/api/v1'),
    'https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general',
  );

  assert.equal(evaluateHeartbeatResponse(200, 'virustotal').ok, true);
  assert.equal(evaluateHeartbeatResponse(401, 'virustotal').ok, false);
  assert.equal(evaluateHeartbeatResponse(403, 'abuseipdb').ok, false);
  assert.equal(evaluateHeartbeatResponse(404, 'alienvault').ok, false);
  assert.equal(evaluateHeartbeatResponse(429, 'virustotal').ok, false);
  assert.equal(evaluateHeartbeatResponse(0, 'virustotal').ok, false);
});

test('mergeConfigAndConnectionStatus preserves configStatus keys and applies live overrides', () => {
  const base = { virustotal: true, abuseipdb: false, alienvault: true };
  assert.deepEqual(mergeConfigAndConnectionStatus(base), base);
  assert.deepEqual(
    mergeConfigAndConnectionStatus(base, { virustotal: false, abuseipdb: true }),
    { virustotal: false, abuseipdb: true, alienvault: true },
  );
});

test('custom threat intelligence providers validate env var names and integrate with enabled sources', () => {
  const bad = validateCustomThreatProvider({
    name: 'GreyNoise',
    endpointTemplate: 'https://api.greynoise.io/v3/community/{indicator}',
    envVarName: 'bad-env-name',
  });
  assert.equal(bad.ok, false);

  const valid = validateCustomThreatProvider({
    name: 'GreyNoise',
    endpointTemplate: 'https://api.greynoise.io/v3/community/{indicator}',
    authHeader: 'key',
    envVarName: 'GREYNOISE_API_KEY',
    supportedTypes: ['ip'],
    dailyQuotaLimit: 50,
  });
  assert.equal(valid.ok, true);
  if (valid.ok) {
    assert.equal(
      buildCustomEndpointUrl(valid.provider.endpointTemplate, '8.8.8.8', 'ip'),
      'https://api.greynoise.io/v3/community/8.8.8.8',
    );
    const settings = cloneDefaultApiSettings();
    settings.extraProviders.shodan.enabled = true;
    settings.customProviders = [valid.provider];
    const allEnabled = getAllEnabledProviderIds(settings);
    assert.ok(allEnabled.includes('shodan'));
    assert.ok(allEnabled.includes(valid.provider.id));
  }
});

test('isEditableThreatIntelEnvVar allows provider keys, blocks system/Gemini vars, and masks secrets', () => {
  assert.equal(isEditableThreatIntelEnvVar('VT_API_KEY'), true);
  assert.equal(isEditableThreatIntelEnvVar('URLSCAN_API_KEY'), true);
  assert.equal(isEditableThreatIntelEnvVar('GEMINI_API_KEY'), false);
  assert.equal(isEditableThreatIntelEnvVar('SMTP_PASS'), false);
  assert.equal(isEditableThreatIntelEnvVar('PORT'), false);

  const settings = cloneDefaultApiSettings();
  settings.customProviders = [
    {
      id: 'custom-greynoise',
      name: 'GreyNoise',
      enabled: true,
      endpointTemplate: 'https://api.greynoise.io/v3/community/{indicator}',
      authHeader: 'key',
      authPrefix: '',
      envVarName: 'GREYNOISE_API_KEY',
      supportedTypes: ['ip'],
      dailyQuotaLimit: 50,
    },
  ];
  assert.equal(isEditableThreatIntelEnvVar('GREYNOISE_API_KEY', settings), true);
  assert.equal(isEditableThreatIntelEnvVar('UNREGISTERED_VAR', settings), false);

  assert.equal(maskSecretHint('abcdef1234567890'), '••••7890');
  assert.equal(maskSecretHint('short'), '••••••');
  assert.equal(maskSecretHint(''), '');
});

test('buildTopBarApiStatuses and summarizeTopBarApiGroup track core, extra (other), and custom providers', () => {
  const settings = cloneDefaultApiSettings();
  settings.extraProviders.shodan.enabled = true;
  settings.extraProviders.threatfox.enabled = true;
  settings.customProviders = [
    {
      id: 'custom-misp',
      name: 'MISP ThreatFeed',
      enabled: true,
      endpointTemplate: 'https://misp.local/lookup/{indicator}',
      authHeader: 'Authorization',
      authPrefix: 'Bearer',
      envVarName: 'MISP_API_KEY',
      supportedTypes: ['ip', 'domain'],
      dailyQuotaLimit: 500,
    },
  ];

  const items = buildTopBarApiStatuses({
    apiSettings: settings,
    keyStatus: { virustotal: true, abuseipdb: false, alienvault: true },
    extraKeyStatus: { shodan: true, threatfox: false, urlscan: false },
    customKeyStatus: { 'custom-misp': true },
    connectionOverrides: { threatfox: false, 'custom-misp': true },
  });

  const shodan = items.find((i) => i.id === 'shodan')!;
  assert.equal(shodan.kind, 'extra');
  assert.equal(shodan.status, 'connected');

  const threatfox = items.find((i) => i.id === 'threatfox')!;
  assert.equal(threatfox.status, 'failed');

  const urlscan = items.find((i) => i.id === 'urlscan')!;
  assert.equal(urlscan.status, 'disabled');

  const misp = items.find((i) => i.id === 'custom-misp')!;
  assert.equal(misp.kind, 'custom');
  assert.equal(misp.status, 'connected');
  assert.equal(misp.statusLabel, 'Verified');

  const extraSummary = summarizeTopBarApiGroup(items, 'extra');
  assert.deepEqual(extraSummary, {
    total: 3,
    enabledCount: 2,
    connectedCount: 1,
    issueCount: 1,
    disabledCount: 1,
  });

  const customSummary = summarizeTopBarApiGroup(items, 'custom');
  assert.deepEqual(customSummary, {
    total: 1,
    enabledCount: 1,
    connectedCount: 1,
    issueCount: 0,
    disabledCount: 0,
  });
});

test('normalizeLatencyMs, classifyLatencyTier, and formatLatencyMs classify API latency tiers accurately', () => {
  assert.equal(normalizeLatencyMs(142.6), 143);
  assert.equal(normalizeLatencyMs(-5), 0);
  assert.equal(normalizeLatencyMs(Number.NaN), 0);

  assert.equal(classifyLatencyTier(45), 'fast');
  assert.equal(classifyLatencyTier(399), 'fast');
  assert.equal(classifyLatencyTier(400), 'moderate');
  assert.equal(classifyLatencyTier(1199), 'moderate');
  assert.equal(classifyLatencyTier(1200), 'slow');
  assert.equal(classifyLatencyTier(2450), 'slow');

  assert.equal(formatLatencyMs(88.4), '88ms');
  assert.equal(formatLatencyMs(1520), '1520ms');
});
