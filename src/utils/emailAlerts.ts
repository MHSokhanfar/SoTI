import type { ConfidenceRiskLevel, IocConfidenceSummary } from './riskScoring';

export type EmailAlertTierPreset = 'Critical' | 'High' | 'Medium' | 'Custom';

export interface EmailAlertConfig {
  enabled: boolean;
  recipients: string[];
  riskTierPreset: EmailAlertTierPreset;
  minConfidenceScore: number;
  triggerOnSampleRuns: boolean;
  cooldownMinutes: number;
  subjectPrefix: string;
}

export interface EmailAlertTriggeredIndicator {
  indicator: string;
  confidenceScore: number;
  riskLevel: ConfidenceRiskLevel;
  activeProviderCount: number;
  explanation: string;
}

export interface EmailAlertRecord {
  id: string;
  createdAt: string;
  mode: 'sample' | 'live' | 'test';
  deliveryMethod: 'smtp' | 'local_outbox';
  deliveryStatus: 'sent' | 'queued' | 'failed';
  statusDetail: string;
  recipients: string[];
  thresholdScore: number;
  subject: string;
  textBody: string;
  emlContent: string;
  triggeredIndicators: EmailAlertTriggeredIndicator[];
}

export const DEFAULT_EMAIL_ALERT_CONFIG: EmailAlertConfig = {
  enabled: false,
  recipients: [],
  riskTierPreset: 'Critical',
  minConfidenceScore: 75,
  triggerOnSampleRuns: true,
  cooldownMinutes: 0,
  subjectPrefix: '[SoTI Alert]',
};

const SIMPLE_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isValidEmailAddress(value: string): boolean {
  const trimmed = String(value ?? '').trim();
  if (!trimmed || trimmed.length > 254 || /[\r\n]/.test(trimmed)) return false;
  return SIMPLE_EMAIL_RE.test(trimmed);
}

export function parseRecipientList(input: string | readonly string[]): {
  valid: string[];
  invalid: string[];
} {
  const rawTokens = Array.isArray(input)
    ? input.flatMap((s) => String(s ?? '').split(/[,;\n\r]+/))
    : String(input ?? '').split(/[,;\n\r]+/);

  const valid: string[] = [];
  const invalid: string[] = [];
  const seen = new Set<string>();

  for (const raw of rawTokens) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    if (!isValidEmailAddress(trimmed)) {
      invalid.push(trimmed);
      continue;
    }
    const lower = trimmed.toLowerCase();
    if (!seen.has(lower)) {
      seen.add(lower);
      valid.push(trimmed);
    }
  }
  return { valid, invalid };
}

export function thresholdFromTierPreset(preset: EmailAlertTierPreset): number {
  switch (preset) {
    case 'Critical':
      return 75;
    case 'High':
      return 50;
    case 'Medium':
      return 25;
    default:
      return 75;
  }
}

export function inferTierPresetFromScore(score: number): EmailAlertTierPreset {
  if (score === 75) return 'Critical';
  if (score === 50) return 'High';
  if (score === 25) return 'Medium';
  return 'Custom';
}

export function sanitizeHeaderText(value: string, fallback = '[SoTI Alert]'): string {
  const cleaned = String(value ?? '')
    .replace(/[\r\n]+/g, ' ')
    .trim();
  return cleaned ? cleaned.slice(0, 64) : fallback;
}

export function validateAndNormalizeEmailAlertConfig(
  candidate: Partial<EmailAlertConfig> & { recipientsInput?: string },
): { ok: true; config: EmailAlertConfig } | { ok: false; error: string } {
  const enabled = Boolean(candidate.enabled);
  const { valid: recipients, invalid } =
    typeof candidate.recipientsInput === 'string'
      ? parseRecipientList(candidate.recipientsInput)
      : parseRecipientList(candidate.recipients ?? []);

  if (invalid.length > 0) {
    return {
      ok: false,
      error: `Invalid email address(es): ${invalid.join(', ')}`,
    };
  }

  if (enabled && recipients.length === 0) {
    return {
      ok: false,
      error: 'Enter at least one valid recipient email address when email alerts are enabled.',
    };
  }

  const rawPreset = candidate.riskTierPreset;
  const preset: EmailAlertTierPreset =
    rawPreset === 'Critical' ||
    rawPreset === 'High' ||
    rawPreset === 'Medium' ||
    rawPreset === 'Custom'
      ? rawPreset
      : inferTierPresetFromScore(Number(candidate.minConfidenceScore ?? 75));

  const parsedScore =
    preset === 'Custom'
      ? Math.round(Number(candidate.minConfidenceScore))
      : thresholdFromTierPreset(preset);

  if (!Number.isFinite(parsedScore) || parsedScore < 1 || parsedScore > 100) {
    return {
      ok: false,
      error: 'Confidence threshold must be an integer between 1 and 100.',
    };
  }

  const rawCooldown = Number(candidate.cooldownMinutes ?? 0);
  const cooldownMinutes = Number.isFinite(rawCooldown)
    ? Math.max(0, Math.min(1440, Math.round(rawCooldown)))
    : 0;

  return {
    ok: true,
    config: {
      enabled,
      recipients,
      riskTierPreset: preset,
      minConfidenceScore: parsedScore,
      triggerOnSampleRuns:
        candidate.triggerOnSampleRuns !== undefined ? Boolean(candidate.triggerOnSampleRuns) : true,
      cooldownMinutes,
      subjectPrefix: sanitizeHeaderText(candidate.subjectPrefix ?? '[SoTI Alert]', '[SoTI Alert]'),
    },
  };
}

export function evaluateEmailAlertTriggers(params: {
  config: EmailAlertConfig;
  summaries: Iterable<IocConfidenceSummary>;
  mode: 'sample' | 'live';
  lastAlertedAtByIndicator?: Record<string, number>;
  nowMs?: number;
}): {
  shouldTrigger: boolean;
  triggered: EmailAlertTriggeredIndicator[];
  skippedCooldown: string[];
  nextLastAlertedAtByIndicator: Record<string, number>;
} {
  const nowMs = params.nowMs ?? Date.now();
  const prevMap = params.lastAlertedAtByIndicator ?? {};
  const nextMap: Record<string, number> = { ...prevMap };

  if (!params.config.enabled || params.config.recipients.length === 0) {
    return {
      shouldTrigger: false,
      triggered: [],
      skippedCooldown: [],
      nextLastAlertedAtByIndicator: nextMap,
    };
  }

  if (params.mode === 'sample' && !params.config.triggerOnSampleRuns) {
    return {
      shouldTrigger: false,
      triggered: [],
      skippedCooldown: [],
      nextLastAlertedAtByIndicator: nextMap,
    };
  }

  const seenIndicators = new Set<string>();
  const triggered: EmailAlertTriggeredIndicator[] = [];
  const skippedCooldown: string[] = [];
  const cooldownMs = Math.max(0, params.config.cooldownMinutes) * 60_000;

  for (const summary of params.summaries) {
    if (summary.confidenceScore === null) continue;
    const key = summary.indicator.trim().toLowerCase();
    if (!key || seenIndicators.has(key)) continue;
    seenIndicators.add(key);

    if (summary.confidenceScore < params.config.minConfidenceScore) continue;

    const lastSentMs = prevMap[key];
    if (cooldownMs > 0 && typeof lastSentMs === 'number' && nowMs - lastSentMs < cooldownMs) {
      skippedCooldown.push(summary.indicator);
      continue;
    }

    triggered.push({
      indicator: summary.indicator,
      confidenceScore: summary.confidenceScore,
      riskLevel: summary.riskLevel,
      activeProviderCount: summary.activeProviderCount,
      explanation: summary.explanation,
    });
    nextMap[key] = nowMs;
  }

  triggered.sort((a, b) => b.confidenceScore - a.confidenceScore);

  return {
    shouldTrigger: triggered.length > 0,
    triggered,
    skippedCooldown,
    nextLastAlertedAtByIndicator: nextMap,
  };
}

export function buildThresholdAlertEmailContent(params: {
  config: EmailAlertConfig;
  triggered: EmailAlertTriggeredIndicator[];
  mode: 'sample' | 'live' | 'test';
  fromAddress: string;
  reportFile?: string | null;
  now?: Date;
}): {
  subject: string;
  textBody: string;
  htmlBody: string;
  emlContent: string;
} {
  const now = params.now ?? new Date();
  const timestamp = now.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const sorted = [...params.triggered].sort((a, b) => b.confidenceScore - a.confidenceScore);
  const highest = sorted[0];
  const prefix = sanitizeHeaderText(params.config.subjectPrefix, '[SoTI Alert]');

  const tierLabel =
    params.config.minConfidenceScore >= 75
      ? 'Critical'
      : params.config.minConfidenceScore >= 50
        ? 'High'
        : `${params.config.minConfidenceScore}+`;

  const subject =
    sorted.length === 1 && highest
      ? `${prefix} ${highest.riskLevel} IOC Detected: ${highest.indicator} (${highest.confidenceScore}/100)`
      : `${prefix} ${sorted.length} IOC(s) Reached ${tierLabel} Threshold (>= ${params.config.minConfidenceScore}/100)`;

  const lines = [
    'SoTI Threat Intelligence — Threshold Alert Notification',
    '======================================================',
    `Timestamp:       ${timestamp}`,
    `Mode:            ${params.mode.toUpperCase()}`,
    `Threshold Rule:  Confidence Score >= ${params.config.minConfidenceScore}/100 (${params.config.riskTierPreset})`,
    `Matched IOCs:    ${sorted.length}`,
    ...(params.reportFile ? [`CSV Report:      reports/${params.reportFile}`] : []),
    '',
    'Triggered Indicators:',
    ...sorted.map(
      (item, idx) =>
        `  ${idx + 1}. ${item.indicator} — ${item.confidenceScore}/100 (${item.riskLevel}) [${item.activeProviderCount} active providers]\n     Breakdown: ${item.explanation}`,
    ),
    '',
    'Review this alert in the SoTI workbench Reports or Investigate tab.',
  ];
  const textBody = lines.join('\r\n');

  const escapeHtml = (s: string) =>
    s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');

  const rowsHtml = sorted
    .map(
      (item) => `
      <tr>
        <td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-family:monospace;font-size:13px;">${escapeHtml(item.indicator)}</td>
        <td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-weight:700;color:#b91c1c;">${item.confidenceScore}/100 (${escapeHtml(item.riskLevel)})</td>
        <td style="padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:12px;color:#475569;">${escapeHtml(item.explanation)}</td>
      </tr>`,
    )
    .join('');

  const htmlBody = `
  <div style="font-family:system-ui,-apple-system,sans-serif;max-width:680px;margin:0 auto;color:#0f172a;">
    <h2 style="margin:0 0 8px;color:#991b1b;">SoTI Threshold Alert</h2>
    <p style="margin:0 0 16px;font-size:13px;color:#475569;">
      <strong>${sorted.length}</strong> indicator(s) exceeded your configured confidence threshold
      (<strong>&ge; ${params.config.minConfidenceScore}/100 · ${escapeHtml(params.config.riskTierPreset)}</strong>) at ${escapeHtml(timestamp)}.
    </p>
    <table style="width:100%;border-collapse:collapse;border:1px solid #e2e8f0;">
      <thead>
        <tr style="background:#f8fafc;text-align:left;font-size:12px;color:#334155;">
          <th style="padding:8px 10px;border-bottom:1px solid #e2e8f0;">Indicator</th>
          <th style="padding:8px 10px;border-bottom:1px solid #e2e8f0;">Confidence</th>
          <th style="padding:8px 10px;border-bottom:1px solid #e2e8f0;">Weighted Providers</th>
        </tr>
      </thead>
      <tbody>${rowsHtml}</tbody>
    </table>
    ${params.reportFile ? `<p style="margin-top:14px;font-size:12px;color:#475569;">Saved report: <code>reports/${escapeHtml(params.reportFile)}</code></p>` : ''}
  </div>`.trim();

  const fromSafe = sanitizeHeaderText(params.fromAddress, 'alerts@soti.local');
  const toSafe = params.config.recipients.map((r) => sanitizeHeaderText(r, '')).filter(Boolean).join(', ');
  const emlContent = [
    `From: ${fromSafe}`,
    `To: ${toSafe}`,
    `Subject: ${sanitizeHeaderText(subject, '[SoTI Alert]')}`,
    `Date: ${now.toUTCString()}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    '',
    textBody,
  ].join('\r\n');

  return {
    subject,
    textBody,
    htmlBody,
    emlContent,
  };
}
