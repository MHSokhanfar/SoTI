import type { EmailAlertRecord } from './emailAlerts';
import type { RecentInvestigationEntry } from './investigationHistory';
import type { ReportMeta } from './reportsAnalytics';

export type LiveActivityCategory = 'threat_alert' | 'investigation' | 'system_event';
export type LiveActivitySeverity = 'critical' | 'warning' | 'info' | 'success';

export interface LiveActivityEvent {
  id: string;
  category: LiveActivityCategory;
  severity: LiveActivitySeverity;
  title: string;
  detail: string;
  timestamp: string;
  indicator?: string;
  reportName?: string;
  source?: string;
  confidenceScore?: number;
}

export interface LiveActivitySummary {
  total: number;
  threatAlerts: number;
  investigations: number;
  systemEvents: number;
  criticalCount: number;
}

const LOG_LINE_PATTERN =
  /^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})(?:,(\d{1,3}))?\s+\|\s+(INFO|WARNING|ERROR)\s+\|\s+(.+)$/;

function parseLogTimestampToIso(datePart: string, timePart: string, msPart?: string): string {
  const ms = msPart ? msPart.padEnd(3, '0').slice(0, 3) : '000';
  return `${datePart}T${timePart}.${ms}Z`;
}

export function formatActivityUtcTime(isoTimestamp: string): string {
  const parsed = Date.parse(isoTimestamp);
  if (!Number.isFinite(parsed)) {
    return isoTimestamp.slice(0, 19);
  }
  const d = new Date(parsed);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}

export function formatActivityDateBadge(isoTimestamp: string): string {
  const parsed = Date.parse(isoTimestamp);
  if (!Number.isFinite(parsed)) return '';
  const d = new Date(parsed);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

export function parseLogLineToActivity(line: string): LiveActivityEvent | null {
  const trimmed = line.trim();
  if (!trimmed) return null;

  const match = trimmed.match(LOG_LINE_PATTERN);
  if (!match) {
    return {
      id: `log-raw-${trimmed.slice(0, 48)}`,
      category: 'system_event',
      severity: 'info',
      title: 'System Audit Entry',
      detail: trimmed,
      timestamp: new Date(0).toISOString(),
    };
  }

  const [, datePart, timePart, msPart, level, message] = match;
  const timestamp = parseLogTimestampToIso(datePart, timePart, msPart);
  const msgLower = message.toLowerCase();

  let category: LiveActivityCategory = 'system_event';
  let severity: LiveActivitySeverity =
    level === 'ERROR' ? 'critical' : level === 'WARNING' ? 'warning' : 'info';
  let title = 'System Event';
  let reportName: string | undefined;
  let indicator: string | undefined;
  let source: string | undefined;

  const csvMatch = message.match(/\b(soti_\d{8}_\d{6}\.csv)\b/);
  if (csvMatch) {
    reportName = csvMatch[1];
  }

  // Detect provider | indicator | outcome structured messages
  const pipeParts = message.split('|').map((p) => p.trim());
  if (pipeParts.length >= 3 && !pipeParts[0].startsWith('EMAIL ALERT') && !pipeParts[0].startsWith('QUOTA') && !pipeParts[0].startsWith('SCHEDULED')) {
    source = pipeParts[0];
    if (pipeParts[1] && pipeParts[1] !== 'heartbeat') {
      indicator = pipeParts[1];
    }
  }

  if (msgLower.startsWith('email alert')) {
    category = 'threat_alert';
    severity = level === 'ERROR' ? 'critical' : 'critical';
    title = 'Threshold Threat Alert Dispatched';
  } else if (msgLower.startsWith('quota failover') || msgLower.includes('rate limit')) {
    category = 'system_event';
    severity = 'warning';
    title = 'Provider Quota Failover';
  } else if (msgLower.includes('saved csv report') || msgLower.startsWith('live poll')) {
    category = 'investigation';
    severity = 'success';
    title = msgLower.startsWith('live poll')
      ? 'Live Mode Background Poll'
      : 'Investigation Report Saved';
  } else if (msgLower.startsWith('scheduled')) {
    category = 'investigation';
    severity = level === 'ERROR' ? 'warning' : 'info';
    title = 'Scheduled Enrichment Executed';
  } else if (msgLower.includes('heartbeat')) {
    category = 'system_event';
    severity = level === 'INFO' ? 'success' : severity;
    title = `${pipeParts[0] || 'Provider'} Health Check`;
  } else if (level === 'ERROR') {
    category = 'system_event';
    severity = 'critical';
    title = source ? `${source} Lookup Error` : 'System Error';
  } else if (level === 'WARNING') {
    category = 'system_event';
    severity = 'warning';
    title = source ? `${source} Warning` : 'System Warning';
  } else if (source && indicator) {
    title = `${source} Lookup (${indicator})`;
  } else if (msgLower.includes('key') || msgLower.includes('api settings')) {
    title = 'API Configuration Updated';
  } else if (msgLower.includes('executive summary')) {
    title = 'AI Executive Summary Generated';
  } else if (msgLower.includes('shared report')) {
    title = 'Report Share Link Created';
  }

  return {
    id: `log-${timestamp}-${message.slice(0, 48)}`,
    category,
    severity,
    title,
    detail: message,
    timestamp,
    ...(indicator ? { indicator } : {}),
    ...(reportName ? { reportName } : {}),
    ...(source ? { source } : {}),
  };
}

export function buildActivityFromEmailAlert(record: EmailAlertRecord): LiveActivityEvent {
  const top = record.triggeredIndicators[0];
  const indicatorList = record.triggeredIndicators
    .map((item) => `${item.indicator} (${item.confidenceScore}/100)`)
    .slice(0, 3)
    .join(', ');

  return {
    id: `alert-${record.id}`,
    category: 'threat_alert',
    severity:
      top && top.confidenceScore >= 75
        ? 'critical'
        : record.deliveryStatus === 'failed'
          ? 'warning'
          : 'warning',
    title:
      record.mode === 'test'
        ? 'Threshold Alert Test Dispatched'
        : `High-Risk Threat Alert (${record.triggeredIndicators.length} IOC${record.triggeredIndicators.length === 1 ? '' : 's'})`,
    detail: `${indicatorList || record.subject} · Threshold ≥ ${record.thresholdScore}/100 · ${record.deliveryStatus.toUpperCase()}`,
    timestamp: record.createdAt,
    ...(top ? { indicator: top.indicator, confidenceScore: top.confidenceScore } : {}),
  };
}

export function buildActivityFromReportMeta(report: ReportMeta): LiveActivityEvent {
  const mal = report.verdicts?.malicious ?? 0;
  const sus = report.verdicts?.suspicious ?? 0;
  const clean = report.verdicts?.clean ?? 0;
  const preview = (report.indicators || []).slice(0, 3).join(', ');

  const isThreatElevated = mal > 0;
  return {
    id: `report-${report.name}`,
    category: isThreatElevated ? 'threat_alert' : 'investigation',
    severity: mal >= 3 ? 'critical' : mal > 0 || sus > 0 ? 'warning' : 'success',
    title: isThreatElevated
      ? `Malicious IOCs Detected in ${report.name}`
      : `Completed Investigation ${report.name}`,
    detail: `${report.rowCount} lookup${report.rowCount === 1 ? '' : 's'} · ${mal} malicious, ${sus} suspicious, ${clean} clean${preview ? ` · ${preview}` : ''}`,
    timestamp: report.modifiedAt,
    reportName: report.name,
    ...(report.indicators?.[0] ? { indicator: report.indicators[0] } : {}),
  };
}

export function buildActivityFromRecentInvestigation(
  entry: RecentInvestigationEntry,
): LiveActivityEvent {
  const mal = entry.verdictSummary?.malicious ?? 0;
  const sus = entry.verdictSummary?.suspicious ?? 0;
  const clean = entry.verdictSummary?.clean ?? 0;
  const preview = entry.indicators.slice(0, 3).join(', ');

  return {
    id: `recent-${entry.id}-${entry.createdAt}`,
    category: 'investigation',
    severity: mal > 0 ? 'warning' : 'success',
    title: `Investigation Completed (${entry.indicators.length} IOC${entry.indicators.length === 1 ? '' : 's'})`,
    detail: `${entry.mode === 'live' ? 'Live API' : 'Sample Data'} · ${mal} malicious, ${sus} suspicious, ${clean} clean${preview ? ` · ${preview}` : ''}`,
    timestamp: entry.createdAt,
    ...(entry.reportFile ? { reportName: entry.reportFile } : {}),
    ...(entry.indicators[0] ? { indicator: entry.indicators[0] } : {}),
  };
}

export function mergeLiveActivityEvents(
  existing: LiveActivityEvent[],
  incoming: LiveActivityEvent[],
  maxItems = 80,
): LiveActivityEvent[] {
  const byId = new Map<string, LiveActivityEvent>();
  for (const ev of [...existing, ...incoming]) {
    if (!ev || !ev.id) continue;
    const prev = byId.get(ev.id);
    if (!prev || Date.parse(ev.timestamp) >= Date.parse(prev.timestamp)) {
      byId.set(ev.id, ev);
    }
  }

  return Array.from(byId.values())
    .sort((a, b) => {
      const tb = Date.parse(b.timestamp) || 0;
      const ta = Date.parse(a.timestamp) || 0;
      if (tb !== ta) return tb - ta;
      return b.id.localeCompare(a.id);
    })
    .slice(0, Math.max(1, maxItems));
}

export function filterLiveActivityEvents(
  events: LiveActivityEvent[],
  options: {
    category?: 'all' | LiveActivityCategory;
    searchQuery?: string;
  } = {},
): LiveActivityEvent[] {
  const category = options.category ?? 'all';
  const q = (options.searchQuery ?? '').trim().toLowerCase();

  return events.filter((ev) => {
    if (category !== 'all' && ev.category !== category) {
      return false;
    }
    if (!q) return true;
    return (
      ev.title.toLowerCase().includes(q) ||
      ev.detail.toLowerCase().includes(q) ||
      (ev.indicator?.toLowerCase().includes(q) ?? false) ||
      (ev.reportName?.toLowerCase().includes(q) ?? false) ||
      (ev.source?.toLowerCase().includes(q) ?? false)
    );
  });
}

export function summarizeLiveActivity(events: LiveActivityEvent[]): LiveActivitySummary {
  let threatAlerts = 0;
  let investigations = 0;
  let systemEvents = 0;
  let criticalCount = 0;

  for (const ev of events) {
    if (ev.category === 'threat_alert') threatAlerts += 1;
    else if (ev.category === 'investigation') investigations += 1;
    else systemEvents += 1;
    if (ev.severity === 'critical') criticalCount += 1;
  }

  return {
    total: events.length,
    threatAlerts,
    investigations,
    systemEvents,
    criticalCount,
  };
}
