import { parseRecipientList } from './emailAlerts';
import type { IndicatorType, LookupResult, Verdict } from './indicators';
import {
  computeAllIocConfidenceScores,
  type ConfidenceRiskLevel,
  type IocConfidenceSummary,
} from './riskScoring';

export type AlertRuleIndicatorScope = 'all' | 'ip' | 'domain' | 'hash' | 'url';
export type AlertRuleVerdictScope = 'any' | 'malicious_only' | 'malicious_or_suspicious';
export type AlertRuleChannel = 'desktop' | 'email' | 'both';

export interface CustomAlertRule {
  id: string;
  name: string;
  enabled: boolean;
  indicatorType: AlertRuleIndicatorScope;
  minRiskScore: number;
  verdictScope: AlertRuleVerdictScope;
  patternFilter: string;
  channel: AlertRuleChannel;
  emailRecipients: string[];
  triggerOnSampleRuns: boolean;
  createdAt: string;
  lastTriggeredAt: string | null;
  triggerCount: number;
}

export interface AlertRuleDraftInput {
  id?: string;
  name: string;
  enabled?: boolean;
  indicatorType: AlertRuleIndicatorScope;
  minRiskScore: number;
  verdictScope?: AlertRuleVerdictScope;
  patternFilter?: string;
  channel: AlertRuleChannel;
  emailRecipientsInput?: string;
  emailRecipients?: string[];
  triggerOnSampleRuns?: boolean;
}

export interface AlertRuleMatchedIndicator {
  indicator: string;
  type: IndicatorType | 'url';
  confidenceScore: number;
  riskLevel: ConfidenceRiskLevel;
  overallVerdict: Verdict;
  activeProviderCount: number;
  explanation: string;
}

export interface AlertRuleEvaluationHit {
  rule: CustomAlertRule;
  matches: AlertRuleMatchedIndicator[];
}

export interface DesktopRuleNotification {
  id: string;
  ruleId: string;
  ruleName: string;
  createdAt: string;
  indicatorType: AlertRuleIndicatorScope;
  minRiskScore: number;
  read: boolean;
  matches: AlertRuleMatchedIndicator[];
}

export interface AlertRuleTriggerHistoryEntry {
  id: string;
  ruleId: string;
  ruleName: string;
  channel: AlertRuleChannel;
  createdAt: string;
  mode: 'sample' | 'live' | 'test';
  matchCount: number;
  deliverySummary: string;
  topIndicators: Array<{
    indicator: string;
    type: IndicatorType | 'url';
    confidenceScore: number;
  }>;
}

export const ALERT_RULES_STORAGE_KEY = 'soti_custom_alert_rules_v1';
export const ALERT_RULE_HISTORY_STORAGE_KEY = 'soti_alert_rule_history_v1';
export const DESKTOP_RULE_ALERTS_STORAGE_KEY = 'soti_desktop_rule_alerts_v1';

export const DEFAULT_CUSTOM_ALERT_RULES: CustomAlertRule[] = [
  {
    id: 'rule-high-risk-domain',
    name: 'High-Risk Domain Alert',
    enabled: true,
    indicatorType: 'domain',
    minRiskScore: 50,
    verdictScope: 'any',
    patternFilter: '',
    channel: 'desktop',
    emailRecipients: [],
    triggerOnSampleRuns: true,
    createdAt: '2026-04-01T00:00:00.000Z',
    lastTriggeredAt: null,
    triggerCount: 0,
  },
  {
    id: 'rule-critical-ip-escalation',
    name: 'Critical IP Infrastructure Escalation',
    enabled: false,
    indicatorType: 'ip',
    minRiskScore: 75,
    verdictScope: 'malicious_or_suspicious',
    patternFilter: '',
    channel: 'both',
    emailRecipients: [],
    triggerOnSampleRuns: true,
    createdAt: '2026-04-01T00:00:00.000Z',
    lastTriggeredAt: null,
    triggerCount: 0,
  },
];

const URL_INDICATOR_RE = /^(?:https?|hxxps?|fxps?|ftp):\/\//i;

export function inferAlertIndicatorKind(result: Pick<LookupResult, 'indicator' | 'originalToken' | 'type'>): IndicatorType | 'url' {
  const token = (result.originalToken || result.indicator || '').trim();
  if (URL_INDICATOR_RE.test(token) || URL_INDICATOR_RE.test(result.indicator || '')) {
    return 'url';
  }
  return result.type;
}

export function summarizeOverallVerdict(results: readonly LookupResult[]): Verdict {
  if (results.some((r) => r.verdict === 'Malicious')) return 'Malicious';
  if (results.some((r) => r.verdict === 'Suspicious')) return 'Suspicious';
  if (results.some((r) => r.verdict === 'Clean')) return 'Clean';
  return 'Unknown';
}

export function doesRuleMatchVerdict(
  scope: AlertRuleVerdictScope,
  overallVerdict: Verdict,
): boolean {
  switch (scope) {
    case 'malicious_only':
      return overallVerdict === 'Malicious';
    case 'malicious_or_suspicious':
      return overallVerdict === 'Malicious' || overallVerdict === 'Suspicious';
    default:
      return true;
  }
}

export function doesRuleMatchIndicatorScope(
  ruleScope: AlertRuleIndicatorScope,
  kind: IndicatorType | 'url',
): boolean {
  if (ruleScope === 'all') return true;
  if (ruleScope === 'domain' && kind === 'domain') return true;
  if (ruleScope === 'url' && kind === 'url') return true;
  return ruleScope === kind;
}

export function validateAndNormalizeAlertRuleDraft(
  draft: AlertRuleDraftInput,
  nowIso = new Date().toISOString(),
): { ok: true; rule: CustomAlertRule } | { ok: false; error: string } {
  const name = String(draft.name ?? '').trim();
  if (!name) {
    return { ok: false, error: 'Rule name is required.' };
  }
  if (name.length > 80) {
    return { ok: false, error: 'Rule name must be 80 characters or fewer.' };
  }

  const parsedScore = Math.round(Number(draft.minRiskScore));
  if (!Number.isFinite(parsedScore) || parsedScore < 1 || parsedScore > 100) {
    return {
      ok: false,
      error: 'Risk score threshold must be an integer between 1 and 100.',
    };
  }

  const rawType = draft.indicatorType;
  const indicatorType: AlertRuleIndicatorScope =
    rawType === 'ip' ||
    rawType === 'domain' ||
    rawType === 'hash' ||
    rawType === 'url' ||
    rawType === 'all'
      ? rawType
      : 'all';

  const rawVerdict = draft.verdictScope;
  const verdictScope: AlertRuleVerdictScope =
    rawVerdict === 'malicious_only' ||
    rawVerdict === 'malicious_or_suspicious' ||
    rawVerdict === 'any'
      ? rawVerdict
      : 'any';

  const rawChannel = draft.channel;
  const channel: AlertRuleChannel =
    rawChannel === 'desktop' || rawChannel === 'email' || rawChannel === 'both'
      ? rawChannel
      : 'desktop';

  const { valid: emailRecipients, invalid } =
    typeof draft.emailRecipientsInput === 'string'
      ? parseRecipientList(draft.emailRecipientsInput)
      : parseRecipientList(draft.emailRecipients ?? []);

  if (invalid.length > 0) {
    return {
      ok: false,
      error: `Invalid email address(es): ${invalid.join(', ')}`,
    };
  }

  const patternFilter = String(draft.patternFilter ?? '').trim().slice(0, 120);
  const id =
    draft.id && draft.id.trim()
      ? draft.id.trim()
      : `rule-${Date.now()}-${Math.random().toString(16).slice(2, 7)}`;

  return {
    ok: true,
    rule: {
      id,
      name,
      enabled: draft.enabled !== undefined ? Boolean(draft.enabled) : true,
      indicatorType,
      minRiskScore: parsedScore,
      verdictScope,
      patternFilter,
      channel,
      emailRecipients,
      triggerOnSampleRuns:
        draft.triggerOnSampleRuns !== undefined ? Boolean(draft.triggerOnSampleRuns) : true,
      createdAt: nowIso,
      lastTriggeredAt: null,
      triggerCount: 0,
    },
  };
}

export function evaluateCustomAlertRules(params: {
  rules: readonly CustomAlertRule[];
  results: readonly LookupResult[];
  confidenceMap?: Map<string, IocConfidenceSummary>;
  mode: 'sample' | 'live';
  nowIso?: string;
}): {
  hits: AlertRuleEvaluationHit[];
  updatedRules: CustomAlertRule[];
} {
  const nowIso = params.nowIso ?? new Date().toISOString();
  const confidenceMap =
    params.confidenceMap ?? computeAllIocConfidenceScores([...params.results]);

  // Group lookup results by normalized indicator key
  const grouped = new Map<
    string,
    {
      indicator: string;
      kind: IndicatorType | 'url';
      overallVerdict: Verdict;
      summary: IocConfidenceSummary;
    }
  >();

  const rowsByKey = new Map<string, LookupResult[]>();
  for (const row of params.results) {
    const key = row.indicator.trim().toLowerCase();
    if (!key) continue;
    const list = rowsByKey.get(key) ?? [];
    list.push(row);
    rowsByKey.set(key, list);
  }

  for (const [key, rows] of rowsByKey.entries()) {
    const summary = confidenceMap.get(key);
    if (!summary || summary.confidenceScore === null) continue;
    const first = rows[0];
    grouped.set(key, {
      indicator: summary.indicator,
      kind: inferAlertIndicatorKind(first),
      overallVerdict: summarizeOverallVerdict(rows),
      summary,
    });
  }

  const hits: AlertRuleEvaluationHit[] = [];
  const updatedRules: CustomAlertRule[] = [];

  for (const rule of params.rules) {
    if (!rule.enabled) {
      updatedRules.push(rule);
      continue;
    }
    if (params.mode === 'sample' && !rule.triggerOnSampleRuns) {
      updatedRules.push(rule);
      continue;
    }

    const pattern = rule.patternFilter.trim().toLowerCase();
    const matches: AlertRuleMatchedIndicator[] = [];

    for (const item of grouped.values()) {
      const score = item.summary.confidenceScore ?? 0;
      if (score < rule.minRiskScore) continue;
      if (!doesRuleMatchIndicatorScope(rule.indicatorType, item.kind)) continue;
      if (!doesRuleMatchVerdict(rule.verdictScope, item.overallVerdict)) continue;
      if (pattern && !item.indicator.toLowerCase().includes(pattern)) continue;

      matches.push({
        indicator: item.indicator,
        type: item.kind,
        confidenceScore: score,
        riskLevel: item.summary.riskLevel,
        overallVerdict: item.overallVerdict,
        activeProviderCount: item.summary.activeProviderCount,
        explanation: item.summary.explanation,
      });
    }

    matches.sort((a, b) => b.confidenceScore - a.confidenceScore);

    if (matches.length > 0) {
      const updatedRule: CustomAlertRule = {
        ...rule,
        lastTriggeredAt: nowIso,
        triggerCount: (rule.triggerCount || 0) + 1,
      };
      hits.push({ rule: updatedRule, matches });
      updatedRules.push(updatedRule);
    } else {
      updatedRules.push(rule);
    }
  }

  return { hits, updatedRules };
}

export function buildDesktopNotificationsFromHits(
  hits: readonly AlertRuleEvaluationHit[],
  nowIso = new Date().toISOString(),
): DesktopRuleNotification[] {
  const notifications: DesktopRuleNotification[] = [];
  for (const hit of hits) {
    if (hit.rule.channel !== 'desktop' && hit.rule.channel !== 'both') continue;
    notifications.push({
      id: `drule-${Date.now()}-${Math.random().toString(16).slice(2, 7)}-${hit.rule.id}`,
      ruleId: hit.rule.id,
      ruleName: hit.rule.name,
      createdAt: nowIso,
      indicatorType: hit.rule.indicatorType,
      minRiskScore: hit.rule.minRiskScore,
      read: false,
      matches: hit.matches,
    });
  }
  return notifications;
}

export function formatDesktopBrowserNotificationContent(
  notification: DesktopRuleNotification,
  maskIndicator?: (value: string, type: IndicatorType | 'url') => string,
): { title: string; body: string } {
  const top = notification.matches[0];
  const topLabel = top
    ? maskIndicator
      ? maskIndicator(top.indicator, top.type)
      : top.indicator
    : 'Indicator';

  const title = `SoTI Alert Rule: ${notification.ruleName}`;
  const body =
    notification.matches.length === 1 && top
      ? `${topLabel} scored ${top.confidenceScore}/100 (${top.riskLevel}, threshold >= ${notification.minRiskScore})`
      : `${notification.matches.length} indicators exceeded threshold >= ${notification.minRiskScore} (top: ${topLabel} at ${top?.confidenceScore ?? 0}/100)`;

  return { title, body };
}

export function buildAlertRuleHistoryEntries(
  hits: readonly AlertRuleEvaluationHit[],
  mode: 'sample' | 'live' | 'test',
  nowIso = new Date().toISOString(),
  deliverySummaryByRuleId?: Record<string, string>,
): AlertRuleTriggerHistoryEntry[] {
  return hits.map((hit) => {
    const fallbackDelivery =
      hit.rule.channel === 'desktop'
        ? 'Desktop alert dispatched'
        : hit.rule.channel === 'email'
          ? 'Email dispatch queued'
          : 'Desktop + Email dispatch triggered';

    return {
      id: `rh-${Date.now()}-${Math.random().toString(16).slice(2, 7)}-${hit.rule.id}`,
      ruleId: hit.rule.id,
      ruleName: hit.rule.name,
      channel: hit.rule.channel,
      createdAt: nowIso,
      mode,
      matchCount: hit.matches.length,
      deliverySummary: deliverySummaryByRuleId?.[hit.rule.id] || fallbackDelivery,
      topIndicators: hit.matches.slice(0, 4).map((m) => ({
        indicator: m.indicator,
        type: m.type,
        confidenceScore: m.confidenceScore,
      })),
    };
  });
}

export function describeAlertRuleSummary(rule: CustomAlertRule): string {
  const typeLabel =
    rule.indicatorType === 'all'
      ? 'Any IOC'
      : rule.indicatorType === 'ip'
        ? 'IP'
        : rule.indicatorType === 'domain'
          ? 'Domain'
          : rule.indicatorType === 'hash'
            ? 'Hash'
            : 'URL';
  const verdictLabel =
    rule.verdictScope === 'malicious_only'
      ? 'Malicious only'
      : rule.verdictScope === 'malicious_or_suspicious'
        ? 'Malicious / Suspicious'
        : 'Any verdict';
  const channelLabel =
    rule.channel === 'both'
      ? 'Desktop + Email'
      : rule.channel === 'email'
        ? 'Email'
        : 'Desktop';

  return `${typeLabel} · Score >= ${rule.minRiskScore} · ${verdictLabel} · ${channelLabel}`;
}

export function loadCustomAlertRules(
  storage?: Pick<Storage, 'getItem'> | null,
): CustomAlertRule[] {
  if (!storage) return DEFAULT_CUSTOM_ALERT_RULES.map((r) => ({ ...r }));
  try {
    const raw = storage.getItem(ALERT_RULES_STORAGE_KEY);
    if (!raw) return DEFAULT_CUSTOM_ALERT_RULES.map((r) => ({ ...r }));
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return DEFAULT_CUSTOM_ALERT_RULES.map((r) => ({ ...r }));
    return parsed
      .filter((item) => item && typeof item.id === 'string' && typeof item.name === 'string')
      .map((item) => ({
        id: item.id,
        name: item.name,
        enabled: Boolean(item.enabled),
        indicatorType: item.indicatorType || 'all',
        minRiskScore: Math.max(1, Math.min(100, Math.round(Number(item.minRiskScore) || 50))),
        verdictScope: item.verdictScope || 'any',
        patternFilter: typeof item.patternFilter === 'string' ? item.patternFilter : '',
        channel: item.channel || 'desktop',
        emailRecipients: Array.isArray(item.emailRecipients) ? item.emailRecipients : [],
        triggerOnSampleRuns:
          item.triggerOnSampleRuns !== undefined ? Boolean(item.triggerOnSampleRuns) : true,
        createdAt: typeof item.createdAt === 'string' ? item.createdAt : new Date().toISOString(),
        lastTriggeredAt: typeof item.lastTriggeredAt === 'string' ? item.lastTriggeredAt : null,
        triggerCount: Number.isFinite(Number(item.triggerCount)) ? Number(item.triggerCount) : 0,
      }));
  } catch {
    return DEFAULT_CUSTOM_ALERT_RULES.map((r) => ({ ...r }));
  }
}

export function saveCustomAlertRules(
  storage: Pick<Storage, 'setItem'> | null | undefined,
  rules: readonly CustomAlertRule[],
): void {
  if (!storage) return;
  try {
    storage.setItem(ALERT_RULES_STORAGE_KEY, JSON.stringify(rules));
  } catch {
    // ignore storage errors
  }
}

export function loadAlertRuleHistory(
  storage?: Pick<Storage, 'getItem'> | null,
): AlertRuleTriggerHistoryEntry[] {
  if (!storage) return [];
  try {
    const raw = storage.getItem(ALERT_RULE_HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.slice(0, 40) : [];
  } catch {
    return [];
  }
}

export function saveAlertRuleHistory(
  storage: Pick<Storage, 'setItem'> | null | undefined,
  entries: readonly AlertRuleTriggerHistoryEntry[],
): void {
  if (!storage) return;
  try {
    storage.setItem(ALERT_RULE_HISTORY_STORAGE_KEY, JSON.stringify(entries.slice(0, 40)));
  } catch {
    // ignore storage errors
  }
}

export function loadDesktopRuleNotifications(
  storage?: Pick<Storage, 'getItem'> | null,
): DesktopRuleNotification[] {
  if (!storage) return [];
  try {
    const raw = storage.getItem(DESKTOP_RULE_ALERTS_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.slice(0, 30) : [];
  } catch {
    return [];
  }
}

export function saveDesktopRuleNotifications(
  storage: Pick<Storage, 'setItem'> | null | undefined,
  items: readonly DesktopRuleNotification[],
): void {
  if (!storage) return;
  try {
    storage.setItem(DESKTOP_RULE_ALERTS_STORAGE_KEY, JSON.stringify(items.slice(0, 30)));
  } catch {
    // ignore storage errors
  }
}
