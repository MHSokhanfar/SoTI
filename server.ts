import 'dotenv/config';
import fs from 'node:fs/promises';
import path from 'node:path';
import express from 'express';
import { createServer as createViteServer } from 'vite';
import {
  computeAbuseIpdbVerdict,
  computeOtxVerdict,
  computeVirusTotalVerdict,
  parseIndicators,
  serializeResultsToCsv,
  type IndicatorType,
  type LookupResult,
  type SourceId,
  type SourceSelection,
} from './src/utils/indicators';
import {
  buildAggregatedCsvFilename,
  mergeHistoricalCsvRows,
  sanitizeSelectedReportNames,
  summarizeReportVerdicts,
} from './src/utils/reportsAnalytics';
import {
  buildCustomEndpointUrl,
  buildHeartbeatEndpoint,
  BUILTIN_EXTRA_IDS,
  cloneDefaultApiSettings,
  DEFAULT_API_SETTINGS,
  evaluateHeartbeatResponse,
  EXTRA_PROVIDER_META,
  getAllConfiguredQuotaLimits,
  resolveSelectedSources,
  validateAndNormalizeApiSettings,
  validateSingleProviderUrl,
  type ApiSettings,
  type BuiltinExtraSourceId,
  type CustomThreatProvider,
} from './src/utils/apiConfig';
import {
  buildQuotaSnapshots,
  normalizeQuotaLedger,
  partitionSourcesByQuota,
  recordQuotaConsumption,
  type DailyQuotaLedger,
} from './src/utils/quota';
import {
  computeNextRunIso,
  isScheduleDue,
  summarizeSchedules,
  validateAndNormalizeScheduleInput,
  type ScheduledJob,
} from './src/utils/scheduler';

const PORT = 3000;
const ROOT_DIR = process.cwd();
const REPORTS_DIR = path.join(ROOT_DIR, 'reports');
const LOGS_DIR = path.join(ROOT_DIR, 'logs');
const CONFIG_DIR = path.join(ROOT_DIR, 'config');
const API_SETTINGS_FILE = path.join(CONFIG_DIR, 'api_settings.json');
const SCHEDULES_FILE = path.join(CONFIG_DIR, 'schedules.json');
const QUOTA_USAGE_FILE = path.join(CONFIG_DIR, 'quota_usage.json');
const LOG_FILE = path.join(LOGS_DIR, 'soti.log');
const REQUEST_TIMEOUT_MS = 20_000;
const ABUSEIPDB_MAX_AGE_DAYS = 90;

const SOURCE_LABELS: Record<string, string> = {
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
  alienvault: 'AlienVault OTX',
  shodan: 'Shodan',
  threatfox: 'ThreatFox (abuse.ch)',
  urlscan: 'urlscan.io',
};

const VT_ENDPOINTS: Record<IndicatorType, string> = {
  ip: 'ip_addresses',
  domain: 'domains',
  hash: 'files',
};

const VT_GUI: Record<IndicatorType, string> = {
  ip: 'ip-address',
  domain: 'domain',
  hash: 'file',
};

async function ensureDirs() {
  await fs.mkdir(REPORTS_DIR, { recursive: true });
  await fs.mkdir(LOGS_DIR, { recursive: true });
  await fs.mkdir(CONFIG_DIR, { recursive: true });
}

async function loadApiSettings(): Promise<ApiSettings> {
  try {
    const raw = await fs.readFile(API_SETTINGS_FILE, 'utf-8');
    const parsed = JSON.parse(raw);
    const validated = validateAndNormalizeApiSettings(parsed);
    if (validated.ok) {
      return validated.settings;
    }
  } catch {
    // Missing or unreadable config falls back to defaults
  }
  return cloneDefaultApiSettings();
}

async function saveApiSettings(settings: ApiSettings): Promise<void> {
  await ensureDirs();
  await fs.writeFile(API_SETTINGS_FILE, JSON.stringify(settings, null, 2) + '\n', 'utf-8');
}

async function loadSchedules(): Promise<ScheduledJob[]> {
  try {
    const raw = await fs.readFile(SCHEDULES_FILE, 'utf-8');
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item) => item && typeof item.id === 'string' && typeof item.name === 'string');
  } catch {
    return [];
  }
}

async function saveSchedules(jobs: ScheduledJob[]): Promise<void> {
  await ensureDirs();
  await fs.writeFile(SCHEDULES_FILE, JSON.stringify(jobs, null, 2) + '\n', 'utf-8');
}

async function loadQuotaLedger(settings: ApiSettings): Promise<DailyQuotaLedger> {
  const limits = getAllConfiguredQuotaLimits(settings);
  try {
    const raw = await fs.readFile(QUOTA_USAGE_FILE, 'utf-8');
    const parsed = JSON.parse(raw);
    return normalizeQuotaLedger(parsed, limits);
  } catch {
    return normalizeQuotaLedger(null, limits);
  }
}

async function saveQuotaLedger(ledger: DailyQuotaLedger): Promise<void> {
  await ensureDirs();
  await fs.writeFile(QUOTA_USAGE_FILE, JSON.stringify(ledger, null, 2) + '\n', 'utf-8');
}

function getProviderDisplayInfos(settings: ApiSettings): { id: string; name: string; limit: number }[] {
  const list: { id: string; name: string; limit: number }[] = [
    { id: 'virustotal', name: 'VirusTotal', limit: settings.providers.virustotal.dailyQuotaLimit },
    { id: 'abuseipdb', name: 'AbuseIPDB', limit: settings.providers.abuseipdb.dailyQuotaLimit },
    { id: 'alienvault', name: 'AlienVault OTX', limit: settings.providers.alienvault.dailyQuotaLimit },
    { id: 'shodan', name: 'Shodan', limit: settings.extraProviders.shodan.dailyQuotaLimit },
    { id: 'threatfox', name: 'ThreatFox (abuse.ch)', limit: settings.extraProviders.threatfox.dailyQuotaLimit },
    { id: 'urlscan', name: 'urlscan.io', limit: settings.extraProviders.urlscan.dailyQuotaLimit },
  ];
  for (const cp of settings.customProviders || []) {
    list.push({ id: cp.id, name: cp.name, limit: cp.dailyQuotaLimit });
  }
  return list;
}

function resolveProviderName(providerId: string, settings: ApiSettings): string {
  if (SOURCE_LABELS[providerId]) return SOURCE_LABELS[providerId];
  const custom = (settings.customProviders || []).find((c) => c.id === providerId);
  return custom?.name || providerId;
}

function formatLogTimestamp(d = new Date()): string {
  const pad = (n: number, len = 2) => String(n).padStart(len, '0');
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())},${pad(d.getMilliseconds(), 3)}`
  );
}

async function appendLog(level: 'INFO' | 'WARNING' | 'ERROR', message: string) {
  await ensureDirs();
  const line = `${formatLogTimestamp()} | ${level} | ${message}\n`;
  await fs.appendFile(LOG_FILE, line, 'utf-8');
}

const PLACEHOLDER_KEYS = new Set([
  'your_virustotal_api_key',
  'your_abuseipdb_api_key',
  'your_alienvault_otx_api_key',
  'your_shodan_api_key',
  'your_threatfox_auth_key',
  'your_urlscan_api_key',
  'your_custom_provider_api_key',
]);

function cleanEnvKey(name: string): string {
  const val = (process.env[name] || '').trim();
  return PLACEHOLDER_KEYS.has(val) ? '' : val;
}

function getEnvKeys() {
  return {
    virustotal: cleanEnvKey('VT_API_KEY'),
    abuseipdb: cleanEnvKey('ABUSEIPDB_API_KEY'),
    alienvault: cleanEnvKey('OTX_API_KEY'),
    shodan: cleanEnvKey('SHODAN_API_KEY'),
    threatfox: cleanEnvKey('THREATFOX_AUTH_KEY'),
    urlscan: cleanEnvKey('URLSCAN_API_KEY'),
  };
}

function parseHeaderInt(headers: Headers, names: string[]): number | null {
  for (const name of names) {
    const val = headers.get(name);
    if (val !== null) {
      const parsed = Number.parseInt(val, 10);
      if (Number.isFinite(parsed) && parsed >= 0) {
        return parsed;
      }
    }
  }
  return null;
}

async function trackProviderRequest(
  providerId: string,
  settings: ApiSettings,
  httpStatus: number,
  headers?: Headers,
): Promise<DailyQuotaLedger> {
  const ledger = await loadQuotaLedger(settings);
  const limits = getAllConfiguredQuotaLimits(settings);
  const limit = limits[providerId] ?? 500;
  const upstreamRemainingHeader = headers
    ? parseHeaderInt(headers, ['x-ratelimit-remaining', 'ratelimit-remaining'])
    : null;
  const upstreamLimitHeader = headers
    ? parseHeaderInt(headers, ['x-ratelimit-limit', 'ratelimit-limit'])
    : null;

  const updated = recordQuotaConsumption(ledger, providerId, limit, {
    httpStatus,
    upstreamRemainingHeader,
    upstreamLimitHeader,
  });
  await saveQuotaLedger(updated);
  return updated;
}

async function fetchJson(
  source: string,
  providerId: string,
  indicator: string,
  url: string,
  headers: Record<string, string>,
  settings: ApiSettings,
  options: { method?: 'GET' | 'POST'; body?: string } = {},
): Promise<{ data?: any; status: number; errorSummary?: string; errorStatus?: 'not_found' | 'error' }> {
  const controller = new AbortController();
  const timeoutMs = (settings.timeoutSeconds || 20) * 1000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      method: options.method || 'GET',
      headers,
      body: options.body,
      signal: controller.signal,
    });
    await appendLog('INFO', `${source} | ${indicator} | HTTP ${resp.status}`);
    await trackProviderRequest(providerId, settings, resp.status, resp.headers);

    if (resp.status === 404) {
      return { status: 404, errorStatus: 'not_found', errorSummary: 'Not found in database' };
    }
    if (resp.status === 401 || resp.status === 403) {
      return { status: resp.status, errorStatus: 'error', errorSummary: 'Invalid or unauthorized API key' };
    }
    if (resp.status === 429) {
      return { status: 429, errorStatus: 'error', errorSummary: 'Daily/rate limit reached (HTTP 429) — skipped for remaining indicators' };
    }
    if (!resp.ok) {
      return { status: resp.status, errorStatus: 'error', errorSummary: `HTTP ${resp.status}` };
    }
    const data = await resp.json();
    return { status: resp.status, data };
  } catch (err: any) {
    const errName = err?.name || 'FetchError';
    await appendLog('ERROR', `${source} | ${indicator} | network error: ${err?.message || errName}`);
    return { status: 0, errorStatus: 'error', errorSummary: `Network error (${errName})` };
  } finally {
    clearTimeout(timer);
  }
}

async function lookupLiveVirusTotal(
  indicator: string,
  originalToken: string,
  itype: IndicatorType,
  settings: ApiSettings,
): Promise<LookupResult> {
  const source = SOURCE_LABELS.virustotal;
  const apiKey = getEnvKeys().virustotal;
  if (!apiKey) {
    await appendLog('WARNING', `${source} | ${indicator} | missing API key (VT_API_KEY)`);
    return {
      source,
      sourceId: 'virustotal',
      indicator,
      originalToken,
      type: itype,
      status: 'error',
      verdict: 'Unknown',
      score: 'N/A',
      summary: 'API key missing - set VT_API_KEY in .env',
      details: {},
      link: '',
    };
  }

  const res = await fetchJson(
    source,
    'virustotal',
    indicator,
    `${settings.providers.virustotal.baseUrl}/${VT_ENDPOINTS[itype]}/${encodeURIComponent(indicator)}`,
    { 'x-apikey': apiKey },
    settings,
  );
  if (res.errorStatus) {
    return {
      source,
      sourceId: 'virustotal',
      indicator,
      originalToken,
      type: itype,
      status: res.errorStatus,
      verdict: 'Unknown',
      score: 'N/A',
      summary: res.errorSummary || 'Lookup failed',
      details: {},
      link: '',
    };
  }

  const attrs = res.data?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const mal = Number(stats.malicious || 0);
  const sus = Number(stats.suspicious || 0);
  const total = Object.values(stats).reduce((acc: number, v: any) => acc + Number(v || 0), 0);
  const verdict = computeVirusTotalVerdict(mal, sus, total);

  const details: Record<string, string | number | boolean | null> = {
    Malicious: mal,
    Suspicious: sus,
    Harmless: Number(stats.harmless || 0),
    Undetected: Number(stats.undetected || 0),
    Reputation: attrs.reputation ?? 'N/A',
  };
  if (itype === 'ip') {
    details.Country = attrs.country ?? 'N/A';
    details['AS Owner'] = attrs.as_owner ?? 'N/A';
    details.ASN = attrs.asn ?? 'N/A';
  } else if (itype === 'domain') {
    details.Registrar = attrs.registrar ?? 'N/A';
    const cats = attrs.categories ? Object.values(attrs.categories) : [];
    if (cats.length) details.Categories = Array.from(new Set(cats.map(String))).sort().join(', ');
  } else {
    details.Name = attrs.meaningful_name ?? 'N/A';
    details.Type = attrs.type_description ?? 'N/A';
    details.Size = attrs.size ?? 'N/A';
    details.SHA256 = attrs.sha256 ?? 'N/A';
    const label = attrs.popular_threat_classification?.suggested_threat_label;
    if (label) details['Threat Label'] = label;
  }

  if (attrs.last_analysis_date) {
    details['Last Analysis'] = new Date(attrs.last_analysis_date * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  }
  if (Array.isArray(attrs.tags) && attrs.tags.length) {
    details.Tags = attrs.tags.slice(0, 8).join(', ');
  }

  return {
    source,
    sourceId: 'virustotal',
    indicator,
    originalToken,
    type: itype,
    status: 'ok',
    verdict,
    score: total ? `${mal}/${total}` : 'N/A',
    summary: `${mal} malicious, ${sus} suspicious out of ${total} engines`,
    details,
    link: `https://www.virustotal.com/gui/${VT_GUI[itype]}/${indicator}`,
  };
}

async function lookupLiveAbuseIpdb(
  indicator: string,
  originalToken: string,
  itype: IndicatorType,
  settings: ApiSettings,
): Promise<LookupResult> {
  const source = SOURCE_LABELS.abuseipdb;
  if (itype !== 'ip') {
    await appendLog('INFO', `${source} | ${indicator} | unsupported type: ${itype}`);
    return {
      source,
      sourceId: 'abuseipdb',
      indicator,
      originalToken,
      type: itype,
      status: 'unsupported',
      verdict: 'Unknown',
      score: 'N/A',
      summary: `${source} does not support ${itype} lookups`,
      details: {},
      link: '',
    };
  }

  const apiKey = getEnvKeys().abuseipdb;
  if (!apiKey) {
    await appendLog('WARNING', `${source} | ${indicator} | missing API key (ABUSEIPDB_API_KEY)`);
    return {
      source,
      sourceId: 'abuseipdb',
      indicator,
      originalToken,
      type: itype,
      status: 'error',
      verdict: 'Unknown',
      score: 'N/A',
      summary: 'API key missing - set ABUSEIPDB_API_KEY in .env',
      details: {},
      link: '',
    };
  }

  const maxAgeDays = settings.abuseMaxAgeDays || ABUSEIPDB_MAX_AGE_DAYS;
  const params = new URLSearchParams({
    ipAddress: indicator,
    maxAgeInDays: String(maxAgeDays),
  });
  const res = await fetchJson(
    source,
    'abuseipdb',
    indicator,
    `${settings.providers.abuseipdb.baseUrl}/check?${params.toString()}`,
    { Key: apiKey, Accept: 'application/json' },
    settings,
  );
  if (res.errorStatus) {
    return {
      source,
      sourceId: 'abuseipdb',
      indicator,
      originalToken,
      type: itype,
      status: res.errorStatus,
      verdict: 'Unknown',
      score: 'N/A',
      summary: res.errorSummary || 'Lookup failed',
      details: {},
      link: '',
    };
  }

  const d = res.data?.data || {};
  const score = Number(d.abuseConfidenceScore || 0);
  const reports = Number(d.totalReports || 0);
  const verdict = computeAbuseIpdbVerdict(score);

  return {
    source,
    sourceId: 'abuseipdb',
    indicator,
    originalToken,
    type: itype,
    status: 'ok',
    verdict,
    score: `${score}%`,
    summary: `${reports} reports in last ${maxAgeDays} days`,
    details: {
      'Abuse Confidence': `${score}%`,
      'Total Reports': reports,
      'Distinct Reporters': d.numDistinctUsers ?? 0,
      'Last Reported': d.lastReportedAt || 'Never',
      Country: d.countryCode ?? 'N/A',
      ISP: d.isp ?? 'N/A',
      'Usage Type': d.usageType ?? 'N/A',
      Domain: d.domain ?? 'N/A',
      Whitelisted: d.isWhitelisted ?? false,
      Tor: d.isTor ?? false,
    },
    link: `https://www.abuseipdb.com/check/${indicator}`,
  };
}

async function lookupLiveOtx(
  indicator: string,
  originalToken: string,
  itype: IndicatorType,
  settings: ApiSettings,
): Promise<LookupResult> {
  const source = SOURCE_LABELS.alienvault;
  const apiKey = getEnvKeys().alienvault;
  if (!apiKey) {
    await appendLog('WARNING', `${source} | ${indicator} | missing API key (OTX_API_KEY)`);
    return {
      source,
      sourceId: 'alienvault',
      indicator,
      originalToken,
      type: itype,
      status: 'error',
      verdict: 'Unknown',
      score: 'N/A',
      summary: 'API key missing - set OTX_API_KEY in .env',
      details: {},
      link: '',
    };
  }

  const sectionPath =
    itype === 'ip'
      ? `${indicator.includes(':') ? 'IPv6' : 'IPv4'}/${encodeURIComponent(indicator)}`
      : `${itype === 'domain' ? 'domain' : 'file'}/${encodeURIComponent(indicator)}`;

  const res = await fetchJson(
    source,
    'alienvault',
    indicator,
    `${settings.providers.alienvault.baseUrl}/indicators/${sectionPath}/general`,
    { 'X-OTX-API-KEY': apiKey },
    settings,
  );
  if (res.errorStatus) {
    return {
      source,
      sourceId: 'alienvault',
      indicator,
      originalToken,
      type: itype,
      status: res.errorStatus,
      verdict: 'Unknown',
      score: 'N/A',
      summary: res.errorSummary || 'Lookup failed',
      details: {},
      link: '',
    };
  }

  const data = res.data || {};
  const pulseInfo = data.pulse_info || {};
  const pulses = Number(pulseInfo.count || 0);
  const verdict = computeOtxVerdict(pulses);
  const details: Record<string, string | number | boolean | null> = { Pulses: pulses };

  const names = (pulseInfo.pulses || [])
    .slice(0, 3)
    .map((p: any) => p?.name)
    .filter(Boolean);
  if (names.length) details['Top Pulses'] = names.join(' | ');

  const families = Array.from(
    new Set(
      (pulseInfo.pulses || [])
        .flatMap((p: any) => p?.malware_families || [])
        .filter((f: any) => f && typeof f === 'object')
        .map((f: any) => f.display_name || f.id)
        .filter(Boolean),
    ),
  ).sort() as string[];
  if (families.length) details['Malware Families'] = families.slice(0, 6).join(', ');

  if (itype === 'ip') {
    details.Country = data.country_name ?? 'N/A';
    details.ASN = data.asn ?? 'N/A';
    details.Reputation = data.reputation ?? 'N/A';
  } else if (itype === 'domain') {
    details.Alexa = data.alexa ?? 'N/A';
    details.Whois = data.whois ?? 'N/A';
  } else {
    details.Type = data.type_title ?? 'N/A';
  }

  const guiType = itype === 'hash' ? 'file' : itype;
  return {
    source,
    sourceId: 'alienvault',
    indicator,
    originalToken,
    type: itype,
    status: 'ok',
    verdict,
    score: `${pulses} pulses`,
    summary: `Found in ${pulses} OTX pulse(s)`,
    details,
    link: `https://otx.alienvault.com/indicator/${guiType}/${indicator}`,
  };
}

async function lookupLiveShodan(
  indicator: string,
  originalToken: string,
  itype: IndicatorType,
  settings: ApiSettings,
): Promise<LookupResult> {
  const source = SOURCE_LABELS.shodan;
  if (itype !== 'ip') {
    return {
      source,
      sourceId: 'shodan',
      indicator,
      originalToken,
      type: itype,
      status: 'unsupported',
      verdict: 'Unknown',
      score: 'N/A',
      summary: `${source} supports IP addresses only`,
      details: {},
      link: '',
    };
  }
  const apiKey = getEnvKeys().shodan;
  if (!apiKey) {
    return {
      source,
      sourceId: 'shodan',
      indicator,
      originalToken,
      type: itype,
      status: 'error',
      verdict: 'Unknown',
      score: 'N/A',
      summary: 'API key missing - set SHODAN_API_KEY in .env',
      details: {},
      link: '',
    };
  }

  const res = await fetchJson(
    source,
    'shodan',
    indicator,
    `${settings.extraProviders.shodan.baseUrl}/shodan/host/${encodeURIComponent(indicator)}?key=${encodeURIComponent(apiKey)}`,
    {},
    settings,
  );
  if (res.errorStatus) {
    return {
      source,
      sourceId: 'shodan',
      indicator,
      originalToken,
      type: itype,
      status: res.errorStatus,
      verdict: 'Unknown',
      score: 'N/A',
      summary: res.errorSummary || 'Lookup failed',
      details: {},
      link: '',
    };
  }
  const data = res.data || {};
  const ports = Array.isArray(data.ports) ? data.ports : [];
  const vulns = Array.isArray(data.vulns) ? data.vulns : [];
  const verdict = vulns.length >= 3 ? 'Malicious' : vulns.length > 0 ? 'Suspicious' : 'Clean';
  return {
    source,
    sourceId: 'shodan',
    indicator,
    originalToken,
    type: itype,
    status: 'ok',
    verdict,
    score: `${ports.length} ports / ${vulns.length} CVEs`,
    summary: `${ports.length} open port(s), ${vulns.length} known CVE(s)`,
    details: {
      Organization: data.org ?? 'N/A',
      ISP: data.isp ?? 'N/A',
      ASN: data.asn ?? 'N/A',
      Country: data.country_name ?? 'N/A',
      Ports: ports.slice(0, 10).join(', ') || 'None',
    },
    link: `https://www.shodan.io/host/${indicator}`,
  };
}

async function lookupLiveThreatFox(
  indicator: string,
  originalToken: string,
  itype: IndicatorType,
  settings: ApiSettings,
): Promise<LookupResult> {
  const source = SOURCE_LABELS.threatfox;
  const apiKey = getEnvKeys().threatfox;
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (apiKey) headers['Auth-Key'] = apiKey;

  const res = await fetchJson(
    source,
    'threatfox',
    indicator,
    settings.extraProviders.threatfox.baseUrl,
    headers,
    settings,
    { method: 'POST', body: JSON.stringify({ query: 'search_ioc', search_term: indicator }) },
  );
  if (res.errorStatus) {
    return {
      source,
      sourceId: 'threatfox',
      indicator,
      originalToken,
      type: itype,
      status: res.errorStatus,
      verdict: 'Unknown',
      score: 'N/A',
      summary: res.errorSummary || 'Lookup failed',
      details: {},
      link: '',
    };
  }
  const matches = Array.isArray(res.data?.data) ? res.data.data : [];
  const maxConf = matches.reduce((m: number, item: any) => Math.max(m, Number(item?.confidence_level || 0)), 0);
  const verdict = matches.length === 0 ? 'Unknown' : maxConf >= 75 ? 'Malicious' : 'Suspicious';
  return {
    source,
    sourceId: 'threatfox',
    indicator,
    originalToken,
    type: itype,
    status: 'ok',
    verdict,
    score: `${matches.length} IOC match(es)`,
    summary: matches.length > 0 ? `${matches.length} ThreatFox IOC record(s) (max confidence ${maxConf}%)` : 'Not found in ThreatFox IOC database',
    details: {
      Matches: matches.length,
      Malware: matches[0]?.malware_printable ?? 'N/A',
      'Threat Type': matches[0]?.threat_type ?? 'N/A',
    },
    link: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(indicator)}`,
  };
}

async function lookupLiveUrlscan(
  indicator: string,
  originalToken: string,
  itype: IndicatorType,
  settings: ApiSettings,
): Promise<LookupResult> {
  const source = SOURCE_LABELS.urlscan;
  const apiKey = getEnvKeys().urlscan;
  const query = itype === 'ip' ? `ip:${indicator}` : itype === 'domain' ? `domain:${indicator}` : `hash:${indicator}`;
  const headers: Record<string, string> = {};
  if (apiKey) headers['API-Key'] = apiKey;

  const res = await fetchJson(
    source,
    'urlscan',
    indicator,
    `${settings.extraProviders.urlscan.baseUrl}/search/?q=${encodeURIComponent(query)}&size=5`,
    headers,
    settings,
  );
  if (res.errorStatus) {
    return {
      source,
      sourceId: 'urlscan',
      indicator,
      originalToken,
      type: itype,
      status: res.errorStatus,
      verdict: 'Unknown',
      score: 'N/A',
      summary: res.errorSummary || 'Lookup failed',
      details: {},
      link: '',
    };
  }
  const results = Array.isArray(res.data?.results) ? res.data.results : [];
  const total = Number(res.data?.total ?? results.length);
  const maliciousCount = results.filter((r: any) => Boolean(r?.verdicts?.overall?.malicious)).length;
  const verdict = maliciousCount > 0 ? 'Malicious' : total > 0 ? 'Clean' : 'Unknown';
  return {
    source,
    sourceId: 'urlscan',
    indicator,
    originalToken,
    type: itype,
    status: 'ok',
    verdict,
    score: `${total} scan(s)`,
    summary: `${total} urlscan.io historical scan(s)${maliciousCount > 0 ? `, ${maliciousCount} flagged malicious` : ''}`,
    details: {
      'Total Scans': total,
      'Flagged Malicious': maliciousCount,
      'Latest Page': results[0]?.page?.domain ?? 'N/A',
    },
    link: `https://urlscan.io/search/#${encodeURIComponent(query)}`,
  };
}

async function lookupLiveCustomProvider(
  provider: CustomThreatProvider,
  indicator: string,
  originalToken: string,
  itype: IndicatorType,
  settings: ApiSettings,
): Promise<LookupResult> {
  if (!provider.supportedTypes.includes(itype)) {
    return {
      source: provider.name,
      sourceId: provider.id,
      indicator,
      originalToken,
      type: itype,
      status: 'unsupported',
      verdict: 'Unknown',
      score: 'N/A',
      summary: `${provider.name} does not support ${itype} lookups`,
      details: {},
      link: '',
    };
  }

  const apiKey = cleanEnvKey(provider.envVarName);
  if (!apiKey) {
    await appendLog('WARNING', `${provider.name} | ${indicator} | missing env key (${provider.envVarName})`);
    return {
      source: provider.name,
      sourceId: provider.id,
      indicator,
      originalToken,
      type: itype,
      status: 'error',
      verdict: 'Unknown',
      score: 'N/A',
      summary: `API key missing - set ${provider.envVarName} in .env`,
      details: {},
      link: '',
    };
  }

  const targetUrl = buildCustomEndpointUrl(provider.endpointTemplate, indicator, itype);
  const authVal = provider.authPrefix ? `${provider.authPrefix} ${apiKey}` : apiKey;
  const res = await fetchJson(
    provider.name,
    provider.id,
    indicator,
    targetUrl,
    { [provider.authHeader]: authVal, Accept: 'application/json' },
    settings,
  );
  if (res.errorStatus) {
    return {
      source: provider.name,
      sourceId: provider.id,
      indicator,
      originalToken,
      type: itype,
      status: res.errorStatus,
      verdict: 'Unknown',
      score: 'N/A',
      summary: res.errorSummary || 'Lookup failed',
      details: {},
      link: '',
    };
  }

  const d = res.data || {};
  const rawMalicious = Boolean(d.malicious) || String(d.classification || d.verdict || '').toLowerCase() === 'malicious';
  const rawSuspicious = String(d.classification || d.verdict || '').toLowerCase() === 'suspicious';
  const verdict = rawMalicious ? 'Malicious' : rawSuspicious ? 'Suspicious' : d.noise === false && d.riot === false ? 'Unknown' : 'Clean';
  return {
    source: provider.name,
    sourceId: provider.id,
    indicator,
    originalToken,
    type: itype,
    status: 'ok',
    verdict,
    score: String(d.score ?? d.confidence ?? d.classification ?? verdict),
    summary: String(d.summary ?? d.message ?? d.description ?? `${provider.name} response received`),
    details: {
      Classification: d.classification ?? d.verdict ?? verdict,
      Provider: provider.name,
    },
    link: targetUrl,
  };
}

function deterministicHash(str: string): number {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return Math.abs(h);
}

async function lookupSample(
  sourceId: string,
  indicator: string,
  originalToken: string,
  itype: IndicatorType,
  settings?: ApiSettings,
): Promise<LookupResult> {
  const customProvider = settings?.customProviders?.find((c) => c.id === sourceId);
  const source = customProvider?.name || SOURCE_LABELS[sourceId] || sourceId;
  if ((sourceId === 'abuseipdb' || sourceId === 'shodan') && itype !== 'ip') {
    await appendLog('INFO', `${source} | ${indicator} | unsupported type: ${itype} (sample mode)`);
    return {
      source,
      sourceId,
      indicator,
      originalToken,
      type: itype,
      status: 'unsupported',
      verdict: 'Unknown',
      score: 'N/A',
      summary: `${source} does not support ${itype} lookups`,
      details: {},
      link: '',
    };
  }
  if (customProvider && !customProvider.supportedTypes.includes(itype)) {
    return {
      source,
      sourceId,
      indicator,
      originalToken,
      type: itype,
      status: 'unsupported',
      verdict: 'Unknown',
      score: 'N/A',
      summary: `${source} does not support ${itype} lookups`,
      details: {},
      link: '',
    };
  }

  await appendLog('INFO', `${source} | ${indicator} | HTTP 200 (sample mode)`);

  const cleanList = new Set(['8.8.8.8', '1.1.1.1', '9.9.9.9', 'google.com', 'example.com', 'cloudflare.com']);
  const suspiciousList = new Set(['185.220.101.4', 'login-verify.net', '356a192b7913b04c54574d18c28d46e6395428ab']);
  const eicarHash = '44d88612fea8a8f36de82e1278abb02f';

  const isClean = cleanList.has(indicator);
  const isSuspicious = suspiciousList.has(indicator);
  const seed = deterministicHash(indicator);

  if (sourceId === 'virustotal') {
    let mal = 12 + (seed % 28);
    let sus = 1 + (seed % 3);
    const total = 91;
    if (isClean) {
      mal = 0;
      sus = 0;
    } else if (isSuspicious) {
      mal = 2;
      sus = 2;
    } else if (indicator === eicarHash) {
      mal = 62;
      sus = 0;
    }

    const verdict = computeVirusTotalVerdict(mal, sus, total);
    const details: Record<string, string | number | boolean | null> = {
      Malicious: mal,
      Suspicious: sus,
      Harmless: Math.max(0, total - mal - sus - 14),
      Undetected: 14,
      Reputation: isClean ? 412 : isSuspicious ? -8 : -46,
    };
    if (itype === 'ip') {
      details.Country = isClean ? 'US' : ['NL', 'RU', 'DE', 'SG'][seed % 4];
      details['AS Owner'] = isClean ? 'Google LLC' : 'Example Autonomous Hosting';
      details.ASN = isClean ? 15169 : 49505 + (seed % 200);
    } else if (itype === 'domain') {
      details.Registrar = isClean ? 'MarkMonitor Inc.' : 'NameCheap, Inc.';
      details.Categories = isClean ? 'Search Engine, Technology' : 'Phishing, Newly Registered Domain';
    } else {
      details.Name = indicator === eicarHash ? 'eicar.com' : 'payload_sample.bin';
      details.Type = indicator === eicarHash ? 'ASCII text' : 'Win32 EXE';
      details.Size = indicator === eicarHash ? 68 : 284672;
      if (!isClean) details['Threat Label'] = indicator === eicarHash ? 'eicar.test.file' : 'trojan.cobaltstrike/beacon';
    }

    return {
      source,
      sourceId,
      indicator,
      originalToken,
      type: itype,
      status: 'ok',
      verdict,
      score: `${mal}/${total}`,
      summary: `${mal} malicious, ${sus} suspicious out of ${total} engines`,
      details,
      link: `https://www.virustotal.com/gui/${VT_GUI[itype]}/${indicator}`,
    };
  }

  if (sourceId === 'abuseipdb') {
    const score = isClean ? 0 : isSuspicious ? 48 : 82 + (seed % 18);
    const reports = isClean ? 0 : isSuspicious ? 9 : 34 + (seed % 90);
    const verdict = computeAbuseIpdbVerdict(score);

    return {
      source,
      sourceId,
      indicator,
      originalToken,
      type: itype,
      status: 'ok',
      verdict,
      score: `${score}%`,
      summary: `${reports} reports in last ${ABUSEIPDB_MAX_AGE_DAYS} days`,
      details: {
        'Abuse Confidence': `${score}%`,
        'Total Reports': reports,
        'Distinct Reporters': isClean ? 0 : Math.max(1, Math.floor(reports / 2)),
        'Last Reported': isClean ? 'Never' : '2026-11-13T21:14:00+00:00',
        Country: isClean ? 'US' : ['NL', 'DE', 'FR', 'SG'][seed % 4],
        ISP: isClean ? 'Google LLC' : 'Stark Industries Solutions Ltd',
        'Usage Type': isClean ? 'Content Delivery Network' : 'Data Center/Web Hosting/Transit',
        Domain: isClean ? 'dns.google' : 'hosting-node.example',
        Whitelisted: isClean,
        Tor: isSuspicious,
      },
      link: `https://www.abuseipdb.com/check/${indicator}`,
    };
  }

  if (sourceId === 'shodan') {
    const ports = isClean ? [53, 443] : [22, 80, 443, 8443];
    const cves = isClean ? 0 : isSuspicious ? 1 : 4;
    const verdict = cves >= 3 ? 'Malicious' : cves > 0 ? 'Suspicious' : 'Clean';
    return {
      source,
      sourceId,
      indicator,
      originalToken,
      type: itype,
      status: 'ok',
      verdict,
      score: `${ports.length} ports / ${cves} CVEs`,
      summary: `${ports.length} open port(s), ${cves} known CVE(s)`,
      details: {
        Organization: isClean ? 'Google LLC' : 'External Cloud Host',
        Ports: ports.join(', '),
      },
      link: `https://www.shodan.io/host/${indicator}`,
    };
  }

  if (sourceId === 'threatfox' || sourceId === 'urlscan' || customProvider) {
    const verdict = isClean ? 'Clean' : isSuspicious ? 'Suspicious' : 'Malicious';
    return {
      source,
      sourceId,
      indicator,
      originalToken,
      type: itype,
      status: 'ok',
      verdict,
      score: isClean ? '0 matches' : '85% confidence',
      summary: isClean ? `No threat feed matches in ${source}` : `${source} flagged indicator (${verdict})`,
      details: {
        Provider: source,
        Classification: verdict,
      },
      link: '',
    };
  }

  const pulses = isClean ? 0 : isSuspicious ? 3 : 6 + (seed % 11);
  const verdict = computeOtxVerdict(pulses);
  const details: Record<string, string | number | boolean | null> = { Pulses: pulses };
  if (pulses > 0) {
    details['Top Pulses'] = 'SOC Triage IOC Feed | External C2 Infrastructure | Credential Harvesting Campaign';
    details['Malware Families'] = itype === 'hash' ? 'CobaltStrike, AgentTesla' : 'LummaStealer';
  }
  if (itype === 'ip') {
    details.Country = isClean ? 'United States' : 'Netherlands';
    details.ASN = isClean ? 'AS15169 Google LLC' : 'AS49505 Selectel';
    details.Reputation = isClean ? 0 : -12;
  } else if (itype === 'domain') {
    details.Alexa = isClean ? 'Top 100' : 'N/A';
    details.Whois = `https://whois.domaintools.com/${indicator}`;
  } else {
    details.Type = indicator === eicarHash ? 'ASCII text' : 'PE32 executable';
  }

  const guiType = itype === 'hash' ? 'file' : itype;
  return {
    source,
    sourceId,
    indicator,
    originalToken,
    type: itype,
    status: 'ok',
    verdict,
    score: `${pulses} pulses`,
    summary: `Found in ${pulses} OTX pulse(s)`,
    details,
    link: `https://otx.alienvault.com/indicator/${guiType}/${indicator}`,
  };
}

function parseCsvLine(line: string): string[] {
  const cells: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') {
        current += '"';
        i++;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        current += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      cells.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  cells.push(current);
  return cells;
}

function parseCsvFile(content: string): Record<string, string>[] {
  const clean = content.replace(/^\ufeff/, '');
  const lines = clean.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return [];
  const headers = parseCsvLine(lines[0]);
  return lines.slice(1).map((line) => {
    const vals = parseCsvLine(line);
    const obj: Record<string, string> = {};
    headers.forEach((h, idx) => {
      obj[h] = vals[idx] ?? '';
    });
    return obj;
  });
}

async function createApp() {
  await ensureDirs();
  const app = express();
  app.use(express.json());

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });

  app.get('/api/config/status', async (_req, res) => {
    const keys = getEnvKeys();
    const settings = await loadApiSettings();
    const customKeys: Record<string, boolean> = {};
    for (const cp of settings.customProviders || []) {
      customKeys[cp.id] = Boolean(cleanEnvKey(cp.envVarName));
    }

    res.json({
      keys: {
        virustotal: Boolean(keys.virustotal),
        abuseipdb: Boolean(keys.abuseipdb),
        alienvault: Boolean(keys.alienvault),
      },
      extraKeys: {
        shodan: Boolean(keys.shodan),
        threatfox: Boolean(keys.threatfox),
        urlscan: Boolean(keys.urlscan),
      },
      customKeys,
      anyKeyConfigured: Boolean(
        keys.virustotal ||
          keys.abuseipdb ||
          keys.alienvault ||
          keys.shodan ||
          keys.threatfox ||
          keys.urlscan ||
          Object.values(customKeys).some(Boolean),
      ),
      allKeysConfigured: Boolean(keys.virustotal && keys.abuseipdb && keys.alienvault),
    });
  });

  app.get('/api/quota', async (_req, res) => {
    const settings = await loadApiSettings();
    const ledger = await loadQuotaLedger(settings);
    const providers = buildQuotaSnapshots(ledger, getProviderDisplayInfos(settings));
    res.json({ date: ledger.date, providers });
  });

  app.post('/api/quota/reset', async (req, res) => {
    const settings = await loadApiSettings();
    const ledger = await loadQuotaLedger(settings);
    const limits = getAllConfiguredQuotaLimits(settings);
    const providerId = typeof req.body?.providerId === 'string' ? req.body.providerId : null;

    if (providerId) {
      ledger.usage[providerId] = {
        used: 0,
        limit: limits[providerId] ?? 500,
        exhausted: false,
        exhaustedReason: null,
        upstreamRemaining: null,
        lastUpdatedAt: null,
      };
      await saveQuotaLedger(ledger);
      await appendLog('INFO', `Reset daily quota usage counter for ${resolveProviderName(providerId, settings)}`);
    } else {
      const fresh = normalizeQuotaLedger(null, limits);
      await saveQuotaLedger(fresh);
      await appendLog('INFO', 'Reset daily quota usage counters for all providers');
    }

    const latest = await loadQuotaLedger(settings);
    res.json({
      date: latest.date,
      providers: buildQuotaSnapshots(latest, getProviderDisplayInfos(settings)),
    });
  });

  app.get('/api/config/apis', async (_req, res) => {
    const settings = await loadApiSettings();
    res.json({ settings, defaults: DEFAULT_API_SETTINGS });
  });

  app.put('/api/config/apis', async (req, res) => {
    const validated = validateAndNormalizeApiSettings(req.body);
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }
    await saveApiSettings(validated.settings);
    const ledger = await loadQuotaLedger(validated.settings);
    await saveQuotaLedger(ledger);
    const enabledList = (['virustotal', 'abuseipdb', 'alienvault'] as const)
      .filter((id) => validated.settings.providers[id].enabled)
      .join(', ');
    await appendLog(
      'INFO',
      `Updated API settings from GUI (enabled: ${enabledList}; extra/custom: ${validated.settings.customProviders.length}; timeout: ${validated.settings.timeoutSeconds}s)`,
    );
    res.json({
      settings: validated.settings,
      quota: {
        date: ledger.date,
        providers: buildQuotaSnapshots(ledger, getProviderDisplayInfos(validated.settings)),
      },
    });
  });

  app.post('/api/config/apis/reset', async (_req, res) => {
    const defaults = cloneDefaultApiSettings();
    await saveApiSettings(defaults);
    const ledger = await loadQuotaLedger(defaults);
    await appendLog('INFO', 'Reset API settings to defaults from GUI');
    res.json({
      settings: defaults,
      quota: {
        date: ledger.date,
        providers: buildQuotaSnapshots(ledger, getProviderDisplayInfos(defaults)),
      },
    });
  });

  app.post('/api/config/apis/test', async (req, res) => {
    const rawProvider = String(req.body?.provider || '');
    const currentSettings = await loadApiSettings();
    const isCore =
      rawProvider === 'virustotal' || rawProvider === 'abuseipdb' || rawProvider === 'alienvault';
    const isExtra =
      rawProvider === 'shodan' || rawProvider === 'threatfox' || rawProvider === 'urlscan';
    const customProvider = (currentSettings.customProviders || []).find((c) => c.id === rawProvider);

    if (!isCore && !isExtra && !customProvider) {
      res.status(400).json({ ok: false, error: 'Unsupported API provider.' });
      return;
    }

    const displayName = resolveProviderName(rawProvider, currentSettings);
    let endpointUrl = '';
    const headers: Record<string, string> = {};
    let method: 'GET' | 'POST' = 'GET';
    let body: string | undefined;

    if (customProvider) {
      const apiKey = cleanEnvKey(customProvider.envVarName);
      if (!apiKey) {
        await appendLog('WARNING', `${customProvider.name} | heartbeat | missing API key (${customProvider.envVarName})`);
        res.json({
          ok: false,
          provider: rawProvider,
          httpStatus: 0,
          latencyMs: 0,
          message: `Set ${customProvider.envVarName} in .env or environment secrets to enable live checks.`,
        });
        return;
      }
      endpointUrl = buildCustomEndpointUrl(customProvider.endpointTemplate, '8.8.8.8', 'ip');
      headers[customProvider.authHeader] = customProvider.authPrefix
        ? `${customProvider.authPrefix} ${apiKey}`
        : apiKey;
    } else if (isCore) {
      const provider = rawProvider as SourceId;
      const rawUrl =
        typeof req.body?.baseUrl === 'string' && req.body.baseUrl.trim()
          ? req.body.baseUrl
          : currentSettings.providers[provider].baseUrl;
      const urlCheck = validateSingleProviderUrl(rawUrl, provider);
      if (!urlCheck.ok) {
        res.json({ ok: false, provider, httpStatus: 0, latencyMs: 0, message: urlCheck.error });
        return;
      }
      const apiKey = getEnvKeys()[provider];
      if (!apiKey) {
        await appendLog('WARNING', `${displayName} | heartbeat | missing API key`);
        res.json({
          ok: false,
          provider,
          httpStatus: 0,
          latencyMs: 0,
          message: `API key for ${displayName} is not configured in .env or environment secrets.`,
        });
        return;
      }
      endpointUrl = buildHeartbeatEndpoint(provider, urlCheck.url);
      if (provider === 'virustotal') headers['x-apikey'] = apiKey;
      else if (provider === 'abuseipdb') {
        headers.Key = apiKey;
        headers.Accept = 'application/json';
      } else headers['X-OTX-API-KEY'] = apiKey;
    } else {
      const provider = rawProvider as BuiltinExtraSourceId;
      const rawUrl =
        typeof req.body?.baseUrl === 'string' && req.body.baseUrl.trim()
          ? req.body.baseUrl
          : currentSettings.extraProviders[provider].baseUrl;
      const urlCheck = validateSingleProviderUrl(rawUrl, provider);
      if (!urlCheck.ok) {
        res.json({ ok: false, provider, httpStatus: 0, latencyMs: 0, message: urlCheck.error });
        return;
      }
      const apiKey = getEnvKeys()[provider];
      if (!apiKey) {
        const envName = EXTRA_PROVIDER_META[provider].envVar;
        await appendLog('WARNING', `${displayName} | heartbeat | missing API key (${envName})`);
        res.json({
          ok: false,
          provider,
          httpStatus: 0,
          latencyMs: 0,
          message: `API key missing — add ${envName} to .env on the server.`,
        });
        return;
      }
      if (provider === 'shodan') {
        endpointUrl = `${buildHeartbeatEndpoint(provider, urlCheck.url)}?key=${encodeURIComponent(apiKey)}`;
      } else if (provider === 'threatfox') {
        endpointUrl = buildHeartbeatEndpoint(provider, urlCheck.url);
        method = 'POST';
        headers['Content-Type'] = 'application/json';
        headers['Auth-Key'] = apiKey;
        body = JSON.stringify({ query: 'search_ioc', search_term: '8.8.8.8' });
      } else {
        endpointUrl = buildHeartbeatEndpoint(provider, urlCheck.url);
        headers['API-Key'] = apiKey;
      }
    }

    const timeoutRaw = Number(req.body?.timeoutSeconds ?? currentSettings.timeoutSeconds);
    const timeoutSec =
      Number.isFinite(timeoutRaw) && timeoutRaw >= 5 && timeoutRaw <= 60
        ? Math.round(timeoutRaw)
        : currentSettings.timeoutSeconds;

    const startedAt = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutSec * 1000);

    try {
      const resp = await fetch(endpointUrl, { method, headers, body, signal: controller.signal });
      const latencyMs = Math.max(1, Date.now() - startedAt);
      const latestLedger = await trackProviderRequest(rawProvider, currentSettings, resp.status, resp.headers);
      const evalResult = evaluateHeartbeatResponse(resp.status, displayName);
      await appendLog(
        evalResult.ok ? 'INFO' : 'WARNING',
        `${displayName} | heartbeat | HTTP ${resp.status} (${latencyMs}ms)`,
      );
      res.json({
        ok: evalResult.ok,
        provider: rawProvider,
        httpStatus: resp.status,
        latencyMs,
        message: evalResult.message,
        quota: {
          date: latestLedger.date,
          providers: buildQuotaSnapshots(latestLedger, getProviderDisplayInfos(currentSettings)),
        },
      });
    } catch (err: any) {
      const latencyMs = Math.max(1, Date.now() - startedAt);
      const errName = err?.name || 'NetworkError';
      await appendLog(
        'ERROR',
        `${displayName} | heartbeat | connection failed: ${err?.message || errName}`,
      );
      res.json({
        ok: false,
        provider: rawProvider,
        httpStatus: 0,
        latencyMs,
        message: `Connection failed (${errName}) — verify endpoint URL`,
      });
    } finally {
      clearTimeout(timer);
    }
  });

  async function executeEnrichmentBatch(opts: {
    raw: string;
    source: SourceSelection;
    sources?: unknown;
    requestedMode?: unknown;
  }): Promise<
    | { ok: false; errorStatus: number; error: string; invalid: string[] }
    | {
        ok: true;
        mode: 'live' | 'sample';
        reportFile: string;
        invalid: string[];
        results: LookupResult[];
        quotaSkipped: { providerId: string; name: string; used: number; limit: number; reason: string }[];
        quota: { date: string; providers: ReturnType<typeof buildQuotaSnapshots> };
      }
  > {
    const settings = await loadApiSettings();
    const keys = getEnvKeys();
    const anyCustomKey = (settings.customProviders || []).some((c) => Boolean(cleanEnvKey(c.envVarName)));
    const defaultMode =
      keys.virustotal || keys.abuseipdb || keys.alienvault || keys.shodan || keys.threatfox || keys.urlscan || anyCustomKey
        ? 'live'
        : 'sample';
    const mode: 'live' | 'sample' =
      opts.requestedMode === 'live' || opts.requestedMode === 'sample' ? opts.requestedMode : defaultMode;

    const parsed = parseIndicators(opts.raw);
    const valid = parsed.filter(
      (p): p is { original: string; cleaned: string; type: IndicatorType } => p.type !== null,
    );
    const invalid = parsed.filter((p) => p.type === null).map((p) => p.original);

    if (invalid.length > 0) {
      await appendLog('WARNING', `Invalid indicators skipped: ${invalid.join(', ')}`);
    }
    if (valid.length === 0) {
      return {
        ok: false,
        errorStatus: 400,
        error: 'No valid IP, domain, or MD5/SHA1/SHA256 indicators detected.',
        invalid,
      };
    }

    const selectedSources = resolveSelectedSources(opts.source, settings, opts.sources);
    if (selectedSources.length === 0) {
      return {
        ok: false,
        errorStatus: 400,
        error: 'No intelligence APIs are enabled. Enable at least one API in CLI & APIs settings.',
        invalid,
      };
    }

    let ledger = await loadQuotaLedger(settings);
    const limits = getAllConfiguredQuotaLimits(settings);
    const { availableSources, exhaustedSources } =
      mode === 'live'
        ? partitionSourcesByQuota(selectedSources, ledger, limits)
        : { availableSources: selectedSources, exhaustedSources: [] };

    if (mode === 'live' && availableSources.length === 0) {
      return {
        ok: false,
        errorStatus: 429,
        error: 'All selected threat intelligence APIs have reached their daily quota limit. Try another provider or reset quota in CLI & APIs.',
        invalid,
      };
    }

    const quotaSkippedMap = new Map<
      string,
      { providerId: string; name: string; used: number; limit: number; reason: string }
    >();

    for (const ex of exhaustedSources) {
      const name = resolveProviderName(ex.providerId, settings);
      quotaSkippedMap.set(ex.providerId, {
        providerId: ex.providerId,
        name,
        used: ex.used,
        limit: ex.limit,
        reason: ex.reason,
      });
      await appendLog(
        'WARNING',
        `QUOTA FAILOVER | ${name} daily quota reached (${ex.used}/${ex.limit}) — continuing with available APIs`,
      );
    }

    const results: LookupResult[] = [];
    for (const item of valid) {
      for (const src of availableSources) {
        if (mode === 'live' && quotaSkippedMap.has(src)) {
          continue;
        }
        let lookupRes: LookupResult;
        if (mode === 'sample') {
          lookupRes = await lookupSample(src, item.cleaned, item.original, item.type, settings);
        } else if (src === 'virustotal') {
          lookupRes = await lookupLiveVirusTotal(item.cleaned, item.original, item.type, settings);
        } else if (src === 'abuseipdb') {
          lookupRes = await lookupLiveAbuseIpdb(item.cleaned, item.original, item.type, settings);
        } else if (src === 'alienvault') {
          lookupRes = await lookupLiveOtx(item.cleaned, item.original, item.type, settings);
        } else if (src === 'shodan') {
          lookupRes = await lookupLiveShodan(item.cleaned, item.original, item.type, settings);
        } else if (src === 'threatfox') {
          lookupRes = await lookupLiveThreatFox(item.cleaned, item.original, item.type, settings);
        } else if (src === 'urlscan') {
          lookupRes = await lookupLiveUrlscan(item.cleaned, item.original, item.type, settings);
        } else {
          const custom = (settings.customProviders || []).find((c) => c.id === src);
          lookupRes = custom
            ? await lookupLiveCustomProvider(custom, item.cleaned, item.original, item.type, settings)
            : {
                source: src,
                sourceId: src,
                indicator: item.cleaned,
                originalToken: item.original,
                type: item.type,
                status: 'error',
                verdict: 'Unknown',
                score: 'N/A',
                summary: `Unknown provider "${src}"`,
                details: {},
                link: '',
              };
        }
        results.push(lookupRes);

        if (mode === 'live') {
          ledger = await loadQuotaLedger(settings);
          const entry = ledger.usage[src];
          if (entry && (entry.exhausted || entry.used >= entry.limit)) {
            const name = resolveProviderName(src, settings);
            quotaSkippedMap.set(src, {
              providerId: src,
              name,
              used: entry.used,
              limit: entry.limit,
              reason: entry.exhaustedReason || `Daily quota reached (${entry.used}/${entry.limit})`,
            });
          }
        }
      }
    }

    const now = new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    const filename = `soti_${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}.csv`;
    const csvPath = path.join(REPORTS_DIR, filename);
    const csvContent = serializeResultsToCsv(results, now.toISOString().slice(0, 19));
    await fs.writeFile(csvPath, csvContent, 'utf-8');
    await appendLog('INFO', `Saved CSV report with ${results.length} rows to ${filename}`);

    const latestLedger = await loadQuotaLedger(settings);
    return {
      ok: true,
      mode,
      reportFile: filename,
      invalid,
      results,
      quotaSkipped: Array.from(quotaSkippedMap.values()),
      quota: {
        date: latestLedger.date,
        providers: buildQuotaSnapshots(latestLedger, getProviderDisplayInfos(settings)),
      },
    };
  }

  const runningScheduleIds = new Set<string>();

  async function runScheduledJob(jobId: string, trigger: 'auto' | 'manual'): Promise<{
    job: ScheduledJob;
    reportFile: string | null;
    results: LookupResult[];
    quota?: { date: string; providers: ReturnType<typeof buildQuotaSnapshots> };
  } | null> {
    if (runningScheduleIds.has(jobId)) {
      return null;
    }
    runningScheduleIds.add(jobId);
    try {
      const jobs = await loadSchedules();
      const idx = jobs.findIndex((j) => j.id === jobId);
      if (idx === -1) return null;
      const target = jobs[idx];

      await appendLog('INFO', `SCHEDULED (${trigger}) | Running "${target.name}" (${target.indicators.join(', ')})`);
      const outcome = await executeEnrichmentBatch({
        raw: target.indicators.join(', '),
        source: target.source,
        sources: target.sources,
        requestedMode: target.mode,
      });

      const now = new Date();
      const nowIso = now.toISOString().replace(/\.\d{3}Z$/, 'Z');
      let updatedJob: ScheduledJob;
      let reportFile: string | null = null;
      let results: LookupResult[] = [];

      if (outcome.ok === false) {
        updatedJob = {
          ...target,
          lastRunAt: nowIso,
          nextRunAt: computeNextRunIso(now, target.intervalMinutes),
          updatedAt: nowIso,
          lastStatus: 'error',
          lastSummary: outcome.error,
          runCount: target.runCount + 1,
        };
      } else {
        results = outcome.results;
        reportFile = outcome.reportFile;
        const errors = results.filter((r) => r.status === 'error').length;
        const mal = results.filter((r) => r.verdict === 'Malicious').length;
        const sus = results.filter((r) => r.verdict === 'Suspicious').length;
        const lastStatus =
          results.length > 0 && errors === results.length
            ? 'error'
            : errors > 0
              ? 'partial'
              : 'success';

        updatedJob = {
          ...target,
          lastRunAt: nowIso,
          nextRunAt: computeNextRunIso(now, target.intervalMinutes),
          updatedAt: nowIso,
          lastStatus,
          lastReportFile: reportFile,
          lastSummary: `${results.length} checks completed (${mal} malicious, ${sus} suspicious)`,
          runCount: target.runCount + 1,
        };
      }

      const latestJobs = await loadSchedules();
      const latestIdx = latestJobs.findIndex((j) => j.id === jobId);
      if (latestIdx !== -1) {
        latestJobs[latestIdx] = updatedJob;
        await saveSchedules(latestJobs);
      }
      return {
        job: updatedJob,
        reportFile,
        results,
        quota: outcome.ok ? outcome.quota : undefined,
      };
    } finally {
      runningScheduleIds.delete(jobId);
    }
  }

  app.get('/api/schedules', async (_req, res) => {
    const jobs = await loadSchedules();
    res.json({ jobs, summary: summarizeSchedules(jobs) });
  });

  app.post('/api/schedules', async (req, res) => {
    const check = validateAndNormalizeScheduleInput(req.body);
    if (!check.ok) {
      res.status(400).json({ error: check.error });
      return;
    }

    const now = new Date();
    const nowIso = now.toISOString().replace(/\.\d{3}Z$/, 'Z');
    const id = `sched-${Math.random().toString(16).slice(2, 10)}`;
    const newJob: ScheduledJob = {
      id,
      name: check.data.name,
      indicators: check.data.indicators,
      source: check.data.source,
      sources: check.data.sources,
      intervalMinutes: check.data.intervalMinutes,
      enabled: check.data.enabled,
      mode: check.data.mode,
      createdAt: nowIso,
      updatedAt: nowIso,
      lastRunAt: null,
      nextRunAt: computeNextRunIso(now, check.data.intervalMinutes),
      lastStatus: 'idle',
      lastReportFile: null,
      lastSummary: 'Scheduled check awaiting first execution',
      runCount: 0,
    };

    const jobs = await loadSchedules();
    jobs.unshift(newJob);
    await saveSchedules(jobs);
    await appendLog(
      'INFO',
      `Created scheduled check "${newJob.name}" (${newJob.indicators.join(', ')}) every ${newJob.intervalMinutes}m`,
    );
    res.status(201).json({ job: newJob, summary: summarizeSchedules(jobs) });
  });

  app.patch('/api/schedules/:id', async (req, res) => {
    const jobs = await loadSchedules();
    const idx = jobs.findIndex((j) => j.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({ error: 'Scheduled check not found.' });
      return;
    }

    const current = jobs[idx];
    const mergedCandidate = {
      name: req.body?.name ?? current.name,
      indicators: req.body?.indicators ?? current.indicators,
      source: req.body?.source ?? current.source,
      sources: req.body?.sources ?? current.sources,
      intervalMinutes: req.body?.intervalMinutes ?? current.intervalMinutes,
      enabled: req.body?.enabled ?? current.enabled,
      mode: req.body?.mode ?? current.mode,
    };

    const check = validateAndNormalizeScheduleInput(mergedCandidate);
    if (!check.ok) {
      res.status(400).json({ error: check.error });
      return;
    }

    const now = new Date();
    const nowIso = now.toISOString().replace(/\.\d{3}Z$/, 'Z');
    const intervalChanged = check.data.intervalMinutes !== current.intervalMinutes;
    const reEnabled = !current.enabled && check.data.enabled;

    const updated: ScheduledJob = {
      ...current,
      name: check.data.name,
      indicators: check.data.indicators,
      source: check.data.source,
      sources: check.data.sources,
      intervalMinutes: check.data.intervalMinutes,
      enabled: check.data.enabled,
      mode: check.data.mode,
      updatedAt: nowIso,
      nextRunAt: intervalChanged || reEnabled ? computeNextRunIso(now, check.data.intervalMinutes) : current.nextRunAt,
    };

    jobs[idx] = updated;
    await saveSchedules(jobs);
    await appendLog('INFO', `Updated scheduled check "${updated.name}" (${updated.enabled ? 'active' : 'paused'})`);
    res.json({ job: updated, summary: summarizeSchedules(jobs) });
  });

  app.delete('/api/schedules/:id', async (req, res) => {
    const jobs = await loadSchedules();
    const target = jobs.find((j) => j.id === req.params.id);
    if (!target) {
      res.status(404).json({ error: 'Scheduled check not found.' });
      return;
    }
    const next = jobs.filter((j) => j.id !== req.params.id);
    await saveSchedules(next);
    await appendLog('INFO', `Deleted scheduled check "${target.name}"`);
    res.json({ ok: true, summary: summarizeSchedules(next) });
  });

  app.post('/api/schedules/:id/run', async (req, res) => {
    const outcome = await runScheduledJob(req.params.id, 'manual');
    if (!outcome) {
      res.status(404).json({ error: 'Scheduled check not found or already running.' });
      return;
    }
    const jobs = await loadSchedules();
    res.json({
      job: outcome.job,
      reportFile: outcome.reportFile,
      results: outcome.results,
      summary: summarizeSchedules(jobs),
      quota: outcome.quota,
    });
  });

  app.post('/api/lookup', async (req, res) => {
    const raw = typeof req.body?.raw === 'string' ? req.body.raw : '';
    const source: SourceSelection = ['virustotal', 'abuseipdb', 'alienvault', 'all'].includes(req.body?.source)
      ? req.body.source
      : 'all';

    const outcome = await executeEnrichmentBatch({
      raw,
      source,
      sources: req.body?.sources,
      requestedMode: req.body?.mode,
    });
    if (outcome.ok === false) {
      res.status(outcome.errorStatus).json({
        error: outcome.error,
        invalid: outcome.invalid,
      });
      return;
    }

    res.json({
      mode: outcome.mode,
      source,
      reportFile: outcome.reportFile,
      invalid: outcome.invalid,
      results: outcome.results,
      quotaSkipped: outcome.quotaSkipped,
      quota: outcome.quota,
    });
  });

  app.get('/api/reports', async (_req, res) => {
    await ensureDirs();
    const entries = await fs.readdir(REPORTS_DIR);
    const csvNames = entries.filter((f) => f.endsWith('.csv')).sort().reverse();
    const reports = await Promise.all(
      csvNames.map(async (name) => {
        const full = path.join(REPORTS_DIR, name);
        const stat = await fs.stat(full);
        const text = await fs.readFile(full, 'utf-8');
        const rows = parseCsvFile(text);
        return {
          name,
          sizeBytes: stat.size,
          modifiedAt: stat.mtime.toISOString(),
          rowCount: rows.length,
          verdicts: summarizeReportVerdicts(rows),
          indicators: Array.from(new Set(rows.map((r) => r.indicator).filter(Boolean))),
        };
      }),
    );
    res.json({ reports });
  });

  async function handleHistoricalCsvExport(requestedNames: string[], res: express.Response) {
    await ensureDirs();
    const entries = await fs.readdir(REPORTS_DIR);
    const availableCsvNames = entries.filter((f) => f.endsWith('.csv')).sort();

    let targetNames = availableCsvNames;
    let filename = 'soti_historical_analysis.csv';

    if (requestedNames.length > 0) {
      const sanitized = sanitizeSelectedReportNames(requestedNames, availableCsvNames);
      if (sanitized.length === 0) {
        res.status(400).json({ error: 'None of the selected report files exist.' });
        return;
      }
      targetNames = sanitized.sort();
      filename = buildAggregatedCsvFilename(targetNames.length);
    }

    const reportEntries = await Promise.all(
      targetNames.map(async (name) => {
        const text = await fs.readFile(path.join(REPORTS_DIR, name), 'utf-8');
        return { name, rows: parseCsvFile(text) };
      }),
    );
    const mergedCsv = mergeHistoricalCsvRows(reportEntries);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(mergedCsv);
  }

  app.get('/api/reports/export/historical', async (req, res) => {
    const rawNames = req.query.names;
    const requestedNames: string[] = Array.isArray(rawNames)
      ? rawNames.flatMap((v) => String(v).split(','))
      : typeof rawNames === 'string'
        ? rawNames.split(',')
        : [];
    await handleHistoricalCsvExport(
      requestedNames.map((n) => n.trim()).filter(Boolean),
      res,
    );
  });

  app.post('/api/reports/export/historical', async (req, res) => {
    const bodyNames = Array.isArray(req.body?.names)
      ? req.body.names.map((v: unknown) => String(v).trim()).filter(Boolean)
      : [];
    await handleHistoricalCsvExport(bodyNames, res);
  });

  app.get('/api/reports/:name', async (req, res) => {
    const safeName = path.basename(req.params.name);
    if (!safeName.endsWith('.csv')) {
      res.status(400).json({ error: 'Invalid report filename.' });
      return;
    }
    const full = path.join(REPORTS_DIR, safeName);
    try {
      const text = await fs.readFile(full, 'utf-8');
      if (req.query.download === '1') {
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
        res.send(text);
        return;
      }
      res.json({ name: safeName, rows: parseCsvFile(text) });
    } catch {
      res.status(404).json({ error: 'Report not found.' });
    }
  });

  app.get('/api/logs', async (_req, res) => {
    await ensureDirs();
    try {
      const content = await fs.readFile(LOG_FILE, 'utf-8');
      const lines = content
        .split(/\r?\n/)
        .filter((l) => l.trim().length > 0)
        .reverse()
        .slice(0, 200);
      res.json({ lines });
    } catch {
      res.json({ lines: [] });
    }
  });

  if (process.env.NODE_ENV === 'production') {
    const distDir = path.join(ROOT_DIR, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  setInterval(async () => {
    try {
      const jobs = await loadSchedules();
      const now = new Date();
      for (const job of jobs) {
        if (isScheduleDue(job, now)) {
          await runScheduledJob(job.id, 'auto');
        }
      }
    } catch {
      // Scheduler tick errors are non-fatal
    }
  }, 30_000);

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SoTI server listening on http://localhost:${PORT}`);
  });
}

createApp();

