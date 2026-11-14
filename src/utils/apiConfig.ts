import type { IndicatorType, SourceId, SourceSelection } from './indicators';

export type BuiltinExtraSourceId = 'shodan' | 'threatfox' | 'urlscan';

export interface ApiProviderConfig {
  enabled: boolean;
  baseUrl: string;
  dailyQuotaLimit: number;
}

export interface ExtraApiProviderConfig extends ApiProviderConfig {
  envVarName: string;
}

export interface CustomThreatProvider {
  id: string;
  name: string;
  enabled: boolean;
  endpointTemplate: string;
  authHeader: string;
  authPrefix: string;
  envVarName: string;
  supportedTypes: IndicatorType[];
  dailyQuotaLimit: number;
}

export interface ApiSettings {
  providers: {
    virustotal: ApiProviderConfig;
    abuseipdb: ApiProviderConfig;
    alienvault: ApiProviderConfig;
  };
  extraProviders: {
    shodan: ExtraApiProviderConfig;
    threatfox: ExtraApiProviderConfig;
    urlscan: ExtraApiProviderConfig;
  };
  customProviders: CustomThreatProvider[];
  timeoutSeconds: number;
  abuseMaxAgeDays: number;
}

export const BUILTIN_EXTRA_IDS: BuiltinExtraSourceId[] = ['shodan', 'threatfox', 'urlscan'];

export const EXTRA_PROVIDER_META: Record<
  BuiltinExtraSourceId,
  { name: string; envVar: string; support: string; defaultUrl: string; defaultQuota: number }
> = {
  shodan: {
    name: 'Shodan',
    envVar: 'SHODAN_API_KEY',
    support: 'IP only',
    defaultUrl: 'https://api.shodan.io',
    defaultQuota: 100,
  },
  threatfox: {
    name: 'ThreatFox (abuse.ch)',
    envVar: 'THREATFOX_AUTH_KEY',
    support: 'IP, Domain, Hash',
    defaultUrl: 'https://threatfox-api.abuse.ch/api/v1',
    defaultQuota: 2000,
  },
  urlscan: {
    name: 'urlscan.io',
    envVar: 'URLSCAN_API_KEY',
    support: 'IP, Domain, Hash',
    defaultUrl: 'https://urlscan.io/api/v1',
    defaultQuota: 1000,
  },
};

export const DEFAULT_API_SETTINGS: ApiSettings = {
  providers: {
    virustotal: {
      enabled: true,
      baseUrl: 'https://www.virustotal.com/api/v3',
      dailyQuotaLimit: 500,
    },
    abuseipdb: {
      enabled: true,
      baseUrl: 'https://api.abuseipdb.com/api/v2',
      dailyQuotaLimit: 1000,
    },
    alienvault: {
      enabled: true,
      baseUrl: 'https://otx.alienvault.com/api/v1',
      dailyQuotaLimit: 10000,
    },
  },
  extraProviders: {
    shodan: {
      enabled: false,
      baseUrl: 'https://api.shodan.io',
      envVarName: 'SHODAN_API_KEY',
      dailyQuotaLimit: 100,
    },
    threatfox: {
      enabled: false,
      baseUrl: 'https://threatfox-api.abuse.ch/api/v1',
      envVarName: 'THREATFOX_AUTH_KEY',
      dailyQuotaLimit: 2000,
    },
    urlscan: {
      enabled: false,
      baseUrl: 'https://urlscan.io/api/v1',
      envVarName: 'URLSCAN_API_KEY',
      dailyQuotaLimit: 1000,
    },
  },
  customProviders: [],
  timeoutSeconds: 20,
  abuseMaxAgeDays: 90,
};

export const ALL_SOURCE_IDS: SourceId[] = ['virustotal', 'abuseipdb', 'alienvault'];

export function cloneDefaultApiSettings(): ApiSettings {
  return {
    providers: {
      virustotal: { ...DEFAULT_API_SETTINGS.providers.virustotal },
      abuseipdb: { ...DEFAULT_API_SETTINGS.providers.abuseipdb },
      alienvault: { ...DEFAULT_API_SETTINGS.providers.alienvault },
    },
    extraProviders: {
      shodan: { ...DEFAULT_API_SETTINGS.extraProviders.shodan },
      threatfox: { ...DEFAULT_API_SETTINGS.extraProviders.threatfox },
      urlscan: { ...DEFAULT_API_SETTINGS.extraProviders.urlscan },
    },
    customProviders: [],
    timeoutSeconds: DEFAULT_API_SETTINGS.timeoutSeconds,
    abuseMaxAgeDays: DEFAULT_API_SETTINGS.abuseMaxAgeDays,
  };
}

function normalizeHttpUrl(raw: unknown, fallbackLabel: string): { ok: true; url: string } | { ok: false; error: string } {
  if (typeof raw !== 'string' || !raw.trim()) {
    return { ok: false, error: `${fallbackLabel} base URL cannot be empty.` };
  }
  const trimmed = raw.trim().replace(/\/+$/, '');
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { ok: false, error: `${fallbackLabel} base URL must start with http:// or https://.` };
    }
    return { ok: true, url: trimmed };
  } catch {
    return { ok: false, error: `${fallbackLabel} base URL is not a valid URL.` };
  }
}

const ENV_VAR_NAME_RE = /^[A-Z][A-Z0-9_]{1,63}$/;
const HEADER_NAME_RE = /^[A-Za-z0-9-]{2,64}$/;

export function validateCustomThreatProvider(
  input: unknown,
): { ok: true; provider: CustomThreatProvider } | { ok: false; error: string } {
  if (!input || typeof input !== 'object') {
    return { ok: false, error: 'Invalid custom provider configuration.' };
  }
  const raw = input as Partial<CustomThreatProvider>;
  const name = typeof raw.name === 'string' ? raw.name.trim() : '';
  if (!name || name.length > 50) {
    return { ok: false, error: 'Custom provider name must be 1–50 characters.' };
  }

  const endpointTemplate = typeof raw.endpointTemplate === 'string' ? raw.endpointTemplate.trim() : '';
  const urlCheck = normalizeHttpUrl(endpointTemplate.replace(/\{indicator\}|\{type\}/g, 'sample'), name);
  if (!urlCheck.ok) {
    return { ok: false, error: `${name} endpoint URL template must be a valid http(s) URL.` };
  }

  const envVarName = typeof raw.envVarName === 'string' ? raw.envVarName.trim().toUpperCase() : '';
  if (!ENV_VAR_NAME_RE.test(envVarName)) {
    return {
      ok: false,
      error: `${name} environment variable name must be UPPER_SNAKE_CASE (e.g. CUSTOM_TI_API_KEY).`,
    };
  }

  const authHeader = typeof raw.authHeader === 'string' && raw.authHeader.trim() ? raw.authHeader.trim() : 'X-API-Key';
  if (!HEADER_NAME_RE.test(authHeader)) {
    return { ok: false, error: `${name} auth header name contains invalid characters.` };
  }

  const authPrefix = typeof raw.authPrefix === 'string' ? raw.authPrefix.trim() : '';
  const rawTypes = Array.isArray(raw.supportedTypes) ? raw.supportedTypes : ['ip', 'domain', 'hash'];
  const supportedTypes = rawTypes.filter(
    (t): t is IndicatorType => t === 'ip' || t === 'domain' || t === 'hash',
  );
  if (supportedTypes.length === 0) {
    return { ok: false, error: `${name} must support at least one IOC type.` };
  }

  const dailyQuotaLimit = Number(raw.dailyQuotaLimit ?? 1000);
  if (!Number.isFinite(dailyQuotaLimit) || !Number.isInteger(dailyQuotaLimit) || dailyQuotaLimit < 1 || dailyQuotaLimit > 1_000_000) {
    return { ok: false, error: `${name} daily quota limit must be a whole number between 1 and 1,000,000.` };
  }

  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 24);
  const id =
    typeof raw.id === 'string' && raw.id.trim()
      ? raw.id.trim()
      : `custom-${slug || 'intel'}-${Math.random().toString(16).slice(2, 6)}`;

  return {
    ok: true,
    provider: {
      id,
      name,
      enabled: raw.enabled === undefined ? true : Boolean(raw.enabled),
      endpointTemplate,
      authHeader,
      authPrefix,
      envVarName,
      supportedTypes: Array.from(new Set(supportedTypes)),
      dailyQuotaLimit,
    },
  };
}

function normalizeQuota(raw: unknown, fallback: number, label: string): { ok: true; value: number } | { ok: false; error: string } {
  const num = Number(raw ?? fallback);
  if (!Number.isFinite(num) || !Number.isInteger(num) || num < 1 || num > 1_000_000) {
    return { ok: false, error: `${label} daily quota must be a whole number between 1 and 1,000,000.` };
  }
  return { ok: true, value: num };
}

export function validateAndNormalizeApiSettings(
  input: unknown,
): { ok: true; settings: ApiSettings } | { ok: false; error: string } {
  if (!input || typeof input !== 'object') {
    return { ok: false, error: 'Invalid API settings payload.' };
  }

  const candidate = input as Partial<ApiSettings>;
  const providersInput = (candidate.providers || {}) as Partial<ApiSettings['providers']>;
  const extraInput = (candidate.extraProviders || {}) as Partial<ApiSettings['extraProviders']>;
  const defaults = DEFAULT_API_SETTINGS.providers;
  const extraDefaults = DEFAULT_API_SETTINGS.extraProviders;

  const vtEnabled = Boolean(providersInput.virustotal?.enabled ?? defaults.virustotal.enabled);
  const abuseEnabled = Boolean(providersInput.abuseipdb?.enabled ?? defaults.abuseipdb.enabled);
  const otxEnabled = Boolean(providersInput.alienvault?.enabled ?? defaults.alienvault.enabled);

  const shodanEnabled = Boolean(extraInput.shodan?.enabled ?? extraDefaults.shodan.enabled);
  const threatfoxEnabled = Boolean(extraInput.threatfox?.enabled ?? extraDefaults.threatfox.enabled);
  const urlscanEnabled = Boolean(extraInput.urlscan?.enabled ?? extraDefaults.urlscan.enabled);

  const customProviders: CustomThreatProvider[] = [];
  if (Array.isArray(candidate.customProviders)) {
    const seenIds = new Set<string>();
    for (const item of candidate.customProviders) {
      const check = validateCustomThreatProvider(item);
      if (!check.ok) return check;
      if (!seenIds.has(check.provider.id)) {
        seenIds.add(check.provider.id);
        customProviders.push(check.provider);
      }
    }
  }

  const anyCustomEnabled = customProviders.some((c) => c.enabled);
  if (!vtEnabled && !abuseEnabled && !otxEnabled && !shodanEnabled && !threatfoxEnabled && !urlscanEnabled && !anyCustomEnabled) {
    return { ok: false, error: 'At least one intelligence API must remain enabled.' };
  }

  const vtUrl = normalizeHttpUrl(
    providersInput.virustotal?.baseUrl ?? defaults.virustotal.baseUrl,
    'VirusTotal',
  );
  if (!vtUrl.ok) return vtUrl;
  const vtQuota = normalizeQuota(providersInput.virustotal?.dailyQuotaLimit, defaults.virustotal.dailyQuotaLimit, 'VirusTotal');
  if (!vtQuota.ok) return vtQuota;

  const abuseUrl = normalizeHttpUrl(
    providersInput.abuseipdb?.baseUrl ?? defaults.abuseipdb.baseUrl,
    'AbuseIPDB',
  );
  if (!abuseUrl.ok) return abuseUrl;
  const abuseQuota = normalizeQuota(providersInput.abuseipdb?.dailyQuotaLimit, defaults.abuseipdb.dailyQuotaLimit, 'AbuseIPDB');
  if (!abuseQuota.ok) return abuseQuota;

  const otxUrl = normalizeHttpUrl(
    providersInput.alienvault?.baseUrl ?? defaults.alienvault.baseUrl,
    'AlienVault OTX',
  );
  if (!otxUrl.ok) return otxUrl;
  const otxQuota = normalizeQuota(providersInput.alienvault?.dailyQuotaLimit, defaults.alienvault.dailyQuotaLimit, 'AlienVault OTX');
  if (!otxQuota.ok) return otxQuota;

  const shodanUrl = normalizeHttpUrl(extraInput.shodan?.baseUrl ?? extraDefaults.shodan.baseUrl, 'Shodan');
  if (!shodanUrl.ok) return shodanUrl;
  const shodanQuota = normalizeQuota(extraInput.shodan?.dailyQuotaLimit, extraDefaults.shodan.dailyQuotaLimit, 'Shodan');
  if (!shodanQuota.ok) return shodanQuota;

  const threatfoxUrl = normalizeHttpUrl(extraInput.threatfox?.baseUrl ?? extraDefaults.threatfox.baseUrl, 'ThreatFox');
  if (!threatfoxUrl.ok) return threatfoxUrl;
  const threatfoxQuota = normalizeQuota(extraInput.threatfox?.dailyQuotaLimit, extraDefaults.threatfox.dailyQuotaLimit, 'ThreatFox');
  if (!threatfoxQuota.ok) return threatfoxQuota;

  const urlscanUrl = normalizeHttpUrl(extraInput.urlscan?.baseUrl ?? extraDefaults.urlscan.baseUrl, 'urlscan.io');
  if (!urlscanUrl.ok) return urlscanUrl;
  const urlscanQuota = normalizeQuota(extraInput.urlscan?.dailyQuotaLimit, extraDefaults.urlscan.dailyQuotaLimit, 'urlscan.io');
  if (!urlscanQuota.ok) return urlscanQuota;

  const timeoutRaw = Number(candidate.timeoutSeconds ?? DEFAULT_API_SETTINGS.timeoutSeconds);
  if (!Number.isFinite(timeoutRaw) || !Number.isInteger(timeoutRaw) || timeoutRaw < 5 || timeoutRaw > 60) {
    return { ok: false, error: 'Request timeout must be a whole number between 5 and 60 seconds.' };
  }

  const ageRaw = Number(candidate.abuseMaxAgeDays ?? DEFAULT_API_SETTINGS.abuseMaxAgeDays);
  if (!Number.isFinite(ageRaw) || !Number.isInteger(ageRaw) || ageRaw < 1 || ageRaw > 365) {
    return { ok: false, error: 'AbuseIPDB max age must be a whole number between 1 and 365 days.' };
  }

  return {
    ok: true,
    settings: {
      providers: {
        virustotal: { enabled: vtEnabled, baseUrl: vtUrl.url, dailyQuotaLimit: vtQuota.value },
        abuseipdb: { enabled: abuseEnabled, baseUrl: abuseUrl.url, dailyQuotaLimit: abuseQuota.value },
        alienvault: { enabled: otxEnabled, baseUrl: otxUrl.url, dailyQuotaLimit: otxQuota.value },
      },
      extraProviders: {
        shodan: {
          enabled: shodanEnabled,
          baseUrl: shodanUrl.url,
          envVarName: 'SHODAN_API_KEY',
          dailyQuotaLimit: shodanQuota.value,
        },
        threatfox: {
          enabled: threatfoxEnabled,
          baseUrl: threatfoxUrl.url,
          envVarName: 'THREATFOX_AUTH_KEY',
          dailyQuotaLimit: threatfoxQuota.value,
        },
        urlscan: {
          enabled: urlscanEnabled,
          baseUrl: urlscanUrl.url,
          envVarName: 'URLSCAN_API_KEY',
          dailyQuotaLimit: urlscanQuota.value,
        },
      },
      customProviders,
      timeoutSeconds: timeoutRaw,
      abuseMaxAgeDays: ageRaw,
    },
  };
}

export function getEnabledSourceIds(settings: ApiSettings): SourceId[] {
  return ALL_SOURCE_IDS.filter((id) => settings.providers[id].enabled);
}

export function getAllEnabledProviderIds(settings: ApiSettings): string[] {
  const core = ALL_SOURCE_IDS.filter((id) => settings.providers[id].enabled);
  const extra = BUILTIN_EXTRA_IDS.filter((id) => settings.extraProviders?.[id]?.enabled);
  const custom = (settings.customProviders || []).filter((c) => c.enabled).map((c) => c.id);
  return [...core, ...extra, ...custom];
}

export function getAllKnownProviderIds(settings: ApiSettings): string[] {
  return [
    ...ALL_SOURCE_IDS,
    ...BUILTIN_EXTRA_IDS,
    ...(settings.customProviders || []).map((c) => c.id),
  ];
}

export function getAllConfiguredQuotaLimits(settings: ApiSettings): Record<string, number> {
  const limits: Record<string, number> = {
    virustotal: settings.providers.virustotal.dailyQuotaLimit,
    abuseipdb: settings.providers.abuseipdb.dailyQuotaLimit,
    alienvault: settings.providers.alienvault.dailyQuotaLimit,
    shodan: settings.extraProviders?.shodan?.dailyQuotaLimit ?? 100,
    threatfox: settings.extraProviders?.threatfox?.dailyQuotaLimit ?? 2000,
    urlscan: settings.extraProviders?.urlscan?.dailyQuotaLimit ?? 1000,
  };
  for (const cp of settings.customProviders || []) {
    limits[cp.id] = cp.dailyQuotaLimit;
  }
  return limits;
}

export function resolveSelectedSources(
  selection: SourceSelection,
  settings: ApiSettings,
  customSources?: unknown,
): string[] {
  const validKnown = new Set(getAllKnownProviderIds(settings));

  if (Array.isArray(customSources) && customSources.length > 0) {
    const valid: string[] = [];
    for (const item of customSources) {
      if (typeof item === 'string' && validKnown.has(item) && !valid.includes(item)) {
        valid.push(item);
      }
    }
    if (valid.length > 0) {
      return valid;
    }
  }

  if (selection === 'all') {
    return getAllEnabledProviderIds(settings);
  }
  return [selection];
}

export function buildCustomEndpointUrl(template: string, indicator: string, itype: IndicatorType): string {
  const encoded = encodeURIComponent(indicator);
  if (template.includes('{indicator}')) {
    return template.replace(/\{indicator\}/g, encoded).replace(/\{type\}/g, encodeURIComponent(itype));
  }
  return `${template.replace(/\/+$/, '')}/${encoded}`;
}

const PROVIDER_DISPLAY_NAMES: Record<SourceId | BuiltinExtraSourceId, string> = {
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
  alienvault: 'AlienVault OTX',
  shodan: 'Shodan',
  threatfox: 'ThreatFox',
  urlscan: 'urlscan.io',
};

export function validateSingleProviderUrl(
  rawUrl: unknown,
  provider: SourceId | BuiltinExtraSourceId,
): { ok: true; url: string } | { ok: false; error: string } {
  return normalizeHttpUrl(rawUrl, PROVIDER_DISPLAY_NAMES[provider]);
}

export function buildHeartbeatEndpoint(provider: SourceId | BuiltinExtraSourceId, baseUrl: string): string {
  const cleanBase = baseUrl.trim().replace(/\/+$/, '');
  if (provider === 'virustotal') {
    return `${cleanBase}/ip_addresses/8.8.8.8`;
  }
  if (provider === 'abuseipdb') {
    return `${cleanBase}/check?ipAddress=8.8.8.8&maxAgeInDays=30`;
  }
  if (provider === 'alienvault') {
    return `${cleanBase}/indicators/IPv4/8.8.8.8/general`;
  }
  if (provider === 'shodan') {
    return `${cleanBase}/shodan/host/8.8.8.8`;
  }
  if (provider === 'threatfox') {
    return cleanBase;
  }
  return `${cleanBase}/search/?q=ip:8.8.8.8&size=1`;
}

export function evaluateHeartbeatResponse(
  httpStatus: number,
  providerNameOrId: SourceId | BuiltinExtraSourceId | string,
): { ok: boolean; message: string } {
  const name =
    (PROVIDER_DISPLAY_NAMES as Record<string, string>)[providerNameOrId] || providerNameOrId;
  if (httpStatus >= 200 && httpStatus < 300) {
    return { ok: true, message: `${name} API key is valid and reachable` };
  }
  if (httpStatus === 401 || httpStatus === 403) {
    return { ok: false, message: `Unauthorized (HTTP ${httpStatus}) — verify ${name} API key` };
  }
  if (httpStatus === 429) {
    return { ok: false, message: `Rate limited (HTTP 429) — ${name} key recognized, retry shortly` };
  }
  if (httpStatus === 404) {
    return { ok: false, message: `Endpoint not found (HTTP 404) — check ${name} base URL` };
  }
  if (httpStatus <= 0) {
    return { ok: false, message: `Unable to reach ${name} endpoint` };
  }
  return { ok: false, message: `${name} returned HTTP ${httpStatus}` };
}

export interface ApiKeyStatus {
  virustotal: boolean;
  abuseipdb: boolean;
  alienvault: boolean;
}

export function mergeConfigAndConnectionStatus(
  configKeys: ApiKeyStatus,
  overrides: Partial<Record<SourceId, boolean>> = {},
): ApiKeyStatus {
  return {
    virustotal: overrides.virustotal ?? configKeys.virustotal,
    abuseipdb: overrides.abuseipdb ?? configKeys.abuseipdb,
    alienvault: overrides.alienvault ?? configKeys.alienvault,
  };
}


