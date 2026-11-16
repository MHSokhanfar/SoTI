import type { IndicatorType } from './indicators';

export const PRIVACY_MODE_STORAGE_KEY = 'soti_privacy_mode_v1';

export const REDACTED_IP = '[REDACTED-IP]';
export const REDACTED_DOMAIN = '[REDACTED-DOMAIN]';
export const REDACTED_HASH = '[REDACTED-HASH]';
export const REDACTED_URL = '[REDACTED-URL]';
export const REDACTED_IOC = '[REDACTED-IOC]';

export type RedactableIndicatorKind = IndicatorType | 'url';

const ALREADY_REDACTED_RE = /^\[REDACTED-(?:IP|DOMAIN|HASH|URL|IOC)\]$/i;
const URL_EXACT_RE = /^(?:hxxps?|https?|fxps?|ftp)(?:\[:\/\/\]|\(:\/\/\)|\{\:\/\/\}|:\/\/)/i;
const HASH_EXACT_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;

const IPV4_DEFANGED_EXACT_RE =
  /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\s*(?:\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\.)\s*(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?::\d{1,5})?$/;

const IPV6_EXACT_RE =
  /^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$|^((?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4})?::((?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4})?$/i;

const DOMAIN_EXACT_RE =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\.))+(?:[a-z]{2,63})$/i;

const SAFE_FILE_EXTENSIONS = new Set([
  'csv',
  'json',
  'txt',
  'log',
  'eml',
  'md',
  'py',
  'ts',
  'tsx',
  'js',
  'jsx',
  'css',
  'html',
  'png',
  'jpg',
  'jpeg',
  'svg',
  'webp',
  'pdf',
  'env',
  'yml',
  'yaml',
  'example',
  'lock',
  'toml',
  'ini',
  'cfg',
  'sh',
  'bat',
  'ps1',
  'local',
]);

const SAFE_UI_DOMAINS = new Set(['urlscan.io', 'localhost']);

export function loadPrivacyMode(
  storage?: Pick<Storage, 'getItem'> | null,
): boolean {
  if (!storage) return false;
  try {
    const raw = storage.getItem(PRIVACY_MODE_STORAGE_KEY);
    return raw === '1' || raw === 'true';
  } catch {
    return false;
  }
}

export function savePrivacyMode(
  storage: Pick<Storage, 'setItem'> | null | undefined,
  enabled: boolean,
): void {
  if (!storage) return;
  try {
    storage.setItem(PRIVACY_MODE_STORAGE_KEY, enabled ? '1' : '0');
  } catch {
    // ignore storage quota errors
  }
}

export function getRedactedPlaceholder(kind?: RedactableIndicatorKind | null): string {
  switch (kind) {
    case 'ip':
      return REDACTED_IP;
    case 'domain':
      return REDACTED_DOMAIN;
    case 'hash':
      return REDACTED_HASH;
    case 'url':
      return REDACTED_URL;
    default:
      return REDACTED_IOC;
  }
}

export function detectSensitiveIndicatorKind(
  value: string,
  typeHint?: RedactableIndicatorKind | string | null,
): RedactableIndicatorKind | null {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) return null;

  if (URL_EXACT_RE.test(trimmed)) {
    return 'url';
  }
  if (HASH_EXACT_RE.test(trimmed)) {
    return 'hash';
  }
  if (
    IPV4_DEFANGED_EXACT_RE.test(trimmed) ||
    (trimmed.includes(':') && IPV6_EXACT_RE.test(trimmed.replace(/^\[|\]$/g, '')))
  ) {
    return 'ip';
  }
  const normalizedHint = typeof typeHint === 'string' ? typeHint.trim().toLowerCase() : null;
  if (
    normalizedHint === 'url' ||
    normalizedHint === 'ip' ||
    normalizedHint === 'hash' ||
    normalizedHint === 'domain'
  ) {
    return normalizedHint;
  }
  if (DOMAIN_EXACT_RE.test(trimmed)) {
    return 'domain';
  }
  return null;
}

export function maskIndicatorValue(
  value: string,
  typeHint?: RedactableIndicatorKind | string | null,
  enabled = true,
): string {
  if (!enabled) return value;
  const trimmed = String(value ?? '').trim();
  if (!trimmed) return value;
  if (ALREADY_REDACTED_RE.test(trimmed)) return trimmed;

  const detected = detectSensitiveIndicatorKind(trimmed, typeHint);
  return getRedactedPlaceholder(detected);
}

const URL_IN_TEXT_RE =
  /\b(?:hxxps?|https?|fxps?|ftp)(?:\[:\/\/\]|\(:\/\/\)|\{\:\/\/\}|:\/\/)[^\s,;'"<>]+/gi;

const HASH_IN_TEXT_RE = /\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi;

const IPV4_IN_TEXT_RE =
  /(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\s*(?:\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\.)\s*(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?::\d{1,5})?(?![\w.])/g;

const IPV6_DOUBLE_COLON_RE =
  /(?<![\w:])(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?(?![\w:])|(?<![\w:])::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?(?![\w:])/gi;

const IPV6_FULL_RE = /(?<![\w:])(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}(?![\w:])/gi;

const DOMAIN_IN_TEXT_RE =
  /(?<![\w@.\-\[\]\/])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\.))+(?:[a-z]{2,24})(?![\w.\-\[\]])/gi;

function stripTrailingSentencePunctuation(token: string): { core: string; suffix: string } {
  const m = token.match(/^(.+?)([),.;!?]+)$/);
  if (!m) return { core: token, suffix: '' };
  return { core: m[1], suffix: m[2] };
}

export function maskSensitiveText(text: string, enabled = true): string {
  if (!enabled || !text) return text;

  let out = String(text);

  // 1. Mask URLs (preserving trailing punctuation)
  out = out.replace(URL_IN_TEXT_RE, (match) => {
    const { suffix } = stripTrailingSentencePunctuation(match);
    return `${REDACTED_URL}${suffix}`;
  });

  // 2. Mask MD5 / SHA1 / SHA256 hashes
  out = out.replace(HASH_IN_TEXT_RE, REDACTED_HASH);

  // 3. Mask IPv4 addresses (normal + defanged)
  out = out.replace(IPV4_IN_TEXT_RE, REDACTED_IP);

  // 4. Mask IPv6 addresses (avoiding HH:MM:SS timestamps)
  out = out.replace(IPV6_DOUBLE_COLON_RE, (match) =>
    match.length >= 3 ? REDACTED_IP : match,
  );
  out = out.replace(IPV6_FULL_RE, REDACTED_IP);

  // 5. Mask domain names (preserving known file extensions & brand labels)
  out = out.replace(DOMAIN_IN_TEXT_RE, (match) => {
    const refanged = match
      .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]/gi, '.')
      .toLowerCase();
    if (SAFE_UI_DOMAINS.has(refanged)) {
      return match;
    }
    const parts = refanged.split('.');
    const tld = parts[parts.length - 1] || '';
    if (SAFE_FILE_EXTENSIONS.has(tld)) {
      return match;
    }
    return REDACTED_DOMAIN;
  });

  return out;
}
