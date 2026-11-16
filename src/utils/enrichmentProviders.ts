import {
  extractRefangedUrl,
  type IndicatorType,
  type LookupResult,
  type Verdict,
} from './indicators';

export type SampleThreatTier = 'clean' | 'suspicious' | 'malicious';

export function buildUrlscanSearchQuery(
  indicator: string,
  itype: IndicatorType,
  refangedUrl: string | null,
): {
  query: string;
  fallbackQuery: string | null;
  targetLabel: string;
  isUrlAnalysis: boolean;
} {
  if (refangedUrl) {
    const escapedUrl = refangedUrl.replace(/"/g, '\\"');
    return {
      query: `page.url:"${escapedUrl}" OR task.url:"${escapedUrl}"`,
      fallbackQuery: itype === 'domain' ? `domain:${indicator}` : itype === 'ip' ? `ip:${indicator}` : null,
      targetLabel: refangedUrl,
      isUrlAnalysis: true,
    };
  }
  if (itype === 'domain') {
    return {
      query: `domain:${indicator}`,
      fallbackQuery: null,
      targetLabel: indicator,
      isUrlAnalysis: true,
    };
  }
  if (itype === 'ip') {
    return {
      query: `ip:${indicator}`,
      fallbackQuery: null,
      targetLabel: indicator,
      isUrlAnalysis: false,
    };
  }
  return {
    query: `hash:${indicator}`,
    fallbackQuery: null,
    targetLabel: indicator,
    isUrlAnalysis: false,
  };
}

export function parseThreatFoxApiResponse(params: {
  indicator: string;
  originalToken: string;
  itype: IndicatorType;
  payload: any;
  sourceLabel?: string;
}): LookupResult {
  const source = params.sourceLabel || 'ThreatFox (abuse.ch)';
  const statusStr = typeof params.payload?.query_status === 'string' ? params.payload.query_status : '';

  if (statusStr === 'no_result') {
    return {
      source,
      sourceId: 'threatfox',
      indicator: params.indicator,
      originalToken: params.originalToken,
      type: params.itype,
      status: 'not_found',
      verdict: 'Unknown',
      score: '0 matches',
      summary: 'Not found in ThreatFox IOC database',
      details: {
        Matches: 0,
      },
      link: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(params.indicator)}`,
    };
  }

  if (statusStr && statusStr !== 'ok') {
    const errorMsg =
      typeof params.payload?.data === 'string' && params.payload.data.trim()
        ? params.payload.data.trim()
        : `ThreatFox query_status: ${statusStr}`;
    return {
      source,
      sourceId: 'threatfox',
      indicator: params.indicator,
      originalToken: params.originalToken,
      type: params.itype,
      status: 'error',
      verdict: 'Unknown',
      score: 'N/A',
      summary: errorMsg,
      details: {},
      link: '',
    };
  }

  const matches: any[] = Array.isArray(params.payload?.data) ? params.payload.data : [];
  if (matches.length === 0) {
    return {
      source,
      sourceId: 'threatfox',
      indicator: params.indicator,
      originalToken: params.originalToken,
      type: params.itype,
      status: 'not_found',
      verdict: 'Unknown',
      score: '0 matches',
      summary: 'Not found in ThreatFox IOC database',
      details: { Matches: 0 },
      link: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(params.indicator)}`,
    };
  }

  const maxConf = matches.reduce(
    (m: number, item: any) => Math.max(m, Number(item?.confidence_level || 0)),
    0,
  );
  const verdict: Verdict = maxConf >= 75 ? 'Malicious' : 'Suspicious';
  const primary = matches[0] || {};
  const malwareList = Array.from(
    new Set(matches.map((m) => m?.malware_printable).filter((v): v is string => typeof v === 'string' && v.trim().length > 0)),
  );
  const tagsList = Array.from(
    new Set(
      matches
        .flatMap((m) => (Array.isArray(m?.tags) ? m.tags : []))
        .filter((v): v is string => typeof v === 'string' && v.trim().length > 0),
    ),
  ).slice(0, 6);

  const details: Record<string, string | number | boolean | null> = {
    Matches: matches.length,
    Malware: malwareList.join(', ') || 'Unknown',
    'Threat Type': primary.threat_type_desc || primary.threat_type || 'N/A',
    'IOC Type': primary.ioc_type || params.itype,
    Confidence: `${maxConf}%`,
  };
  if (primary.ioc) {
    details['Matched IOC'] = String(primary.ioc);
  }
  if (primary.first_seen) {
    details['First Seen'] = String(primary.first_seen);
  }
  if (tagsList.length > 0) {
    details.Tags = tagsList.join(', ');
  }
  if (primary.reporter) {
    details.Reporter = String(primary.reporter);
  }
  if (primary.reference) {
    details.Reference = String(primary.reference);
  }

  return {
    source,
    sourceId: 'threatfox',
    indicator: params.indicator,
    originalToken: params.originalToken,
    type: params.itype,
    status: 'ok',
    verdict,
    score: `${matches.length} IOC match(es) · ${maxConf}%`,
    summary: `${matches.length} ThreatFox IOC record(s) (max confidence ${maxConf}%${malwareList[0] ? ` · ${malwareList[0]}` : ''})`,
    details,
    link: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(params.indicator)}`,
  };
}

export function parseUrlscanApiResponse(params: {
  indicator: string;
  originalToken: string;
  itype: IndicatorType;
  refangedUrl: string | null;
  searchPayload: any;
  detailPayload?: any;
  queuedScanUuid?: string | null;
  sourceLabel?: string;
}): LookupResult {
  const source = params.sourceLabel || 'urlscan.io';
  const results: any[] = Array.isArray(params.searchPayload?.results) ? params.searchPayload.results : [];
  const total = Number(params.searchPayload?.total ?? results.length);
  const top = results[0] || {};
  const detail = params.detailPayload || {};

  const maliciousCount = results.filter((r) => Boolean(r?.verdicts?.overall?.malicious)).length;
  const suspiciousScoreRaw = Number(
    detail?.verdicts?.overall?.score ?? top?.verdicts?.overall?.score ?? 0,
  );
  const detailMalicious = Boolean(detail?.verdicts?.overall?.malicious);
  const verdict: Verdict =
    maliciousCount > 0 || detailMalicious || suspiciousScoreRaw >= 50
      ? 'Malicious'
      : suspiciousScoreRaw > 0
        ? 'Suspicious'
        : total > 0
          ? 'Clean'
          : 'Unknown';

  const scanUuid: string | undefined =
    (typeof detail?.task?.uuid === 'string' && detail.task.uuid) ||
    (typeof top?._id === 'string' && top._id) ||
    params.queuedScanUuid ||
    undefined;

  const pageUrl =
    detail?.page?.url ||
    detail?.task?.url ||
    top?.page?.url ||
    top?.task?.url ||
    params.refangedUrl ||
    null;

  const pageDomain = detail?.page?.domain || top?.page?.domain || (params.itype === 'domain' ? params.indicator : null);
  const pageIp = detail?.page?.ip || top?.page?.ip || (params.itype === 'ip' ? params.indicator : null);
  const categories = Array.isArray(detail?.verdicts?.overall?.categories)
    ? detail.verdicts.overall.categories.filter(Boolean)
    : Array.isArray(top?.verdicts?.overall?.categories)
      ? top.verdicts.overall.categories.filter(Boolean)
      : [];

  const contactedIps = Array.isArray(detail?.lists?.ips)
    ? detail.lists.ips.filter((ip: unknown) => typeof ip === 'string' && ip !== pageIp && ip !== params.indicator).slice(0, 2)
    : [];
  const contactedDomains = Array.isArray(detail?.lists?.domains)
    ? detail.lists.domains.filter((dom: unknown) => typeof dom === 'string' && dom !== pageDomain && dom !== params.indicator).slice(0, 2)
    : [];

  const scopeLabel = params.refangedUrl
    ? 'URL & Domain Analysis'
    : params.itype === 'domain'
      ? 'Domain Analysis'
      : params.itype === 'ip'
        ? 'IP Scan History'
        : 'File Hash History';

  const details: Record<string, string | number | boolean | null> = {
    'Analysis Scope': scopeLabel,
    'Total Scans': total,
    'Flagged Malicious': maliciousCount,
  };

  if (pageUrl) details['Scanned URL'] = String(pageUrl);
  if (pageDomain) details['Latest Page'] = String(pageDomain);
  if (pageIp) details['Page IP'] = String(pageIp);
  if (detail?.page?.asn || top?.page?.asn) {
    details.ASN = String(detail?.page?.asnname ? `${detail.page.asn} ${detail.page.asnname}` : (detail?.page?.asn || top?.page?.asn));
  }
  if (detail?.page?.country || top?.page?.country) {
    details.Country = String(detail?.page?.country || top?.page?.country);
  }
  if (detail?.page?.server || top?.page?.server) {
    details.Server = String(detail?.page?.server || top?.page?.server);
  }
  if (detail?.page?.title || top?.page?.title) {
    details['Page Title'] = String(detail?.page?.title || top?.page?.title).slice(0, 80);
  }
  if (Number.isFinite(suspiciousScoreRaw) && (total > 0 || suspiciousScoreRaw !== 0)) {
    details['Verdict Score'] = `${suspiciousScoreRaw}/100`;
  }
  if (categories.length > 0) {
    details.Categories = categories.slice(0, 4).join(', ');
  }
  if (contactedIps.length > 0) {
    details['Related IP'] = contactedIps.join(', ');
  }
  if (contactedDomains.length > 0) {
    details['Contacted Domain'] = contactedDomains.join(', ');
  }
  const scanTimeRaw = detail?.task?.time || top?.task?.time;
  if (scanTimeRaw) {
    details['Scan Time'] = String(scanTimeRaw);
  }
  if (scanUuid) {
    details['Scan UUID'] = scanUuid;
  }

  const fallbackQuery = buildUrlscanSearchQuery(params.indicator, params.itype, params.refangedUrl).query;
  const reportLink = scanUuid
    ? `https://urlscan.io/result/${encodeURIComponent(scanUuid)}/`
    : `https://urlscan.io/search/#${encodeURIComponent(fallbackQuery)}`;

  let summary = `${total} urlscan.io historical scan(s)`;
  if (maliciousCount > 0) {
    summary += `, ${maliciousCount} flagged malicious`;
  } else if (total === 0 && params.queuedScanUuid) {
    summary = `No prior scans; submitted live URL scan (${params.queuedScanUuid.slice(0, 8)})`;
  } else if (total === 0) {
    summary = `No historical scans found for ${params.refangedUrl || params.indicator}`;
  }

  return {
    source,
    sourceId: 'urlscan',
    indicator: params.indicator,
    originalToken: params.originalToken,
    type: params.itype,
    status: total === 0 && !params.queuedScanUuid ? 'not_found' : 'ok',
    verdict,
    score: total > 0 ? `${maliciousCount}/${total} scans` : params.queuedScanUuid ? 'Queued' : '0 scans',
    summary,
    details,
    link: reportLink,
  };
}

export function buildThreatFoxSampleResult(
  indicator: string,
  originalToken: string,
  itype: IndicatorType,
  tier: SampleThreatTier,
  seed: number,
): LookupResult {
  const source = 'ThreatFox (abuse.ch)';
  if (tier === 'clean') {
    return {
      source,
      sourceId: 'threatfox',
      indicator,
      originalToken,
      type: itype,
      status: 'not_found',
      verdict: 'Unknown',
      score: '0 matches',
      summary: 'Not found in ThreatFox IOC database',
      details: {
        Matches: 0,
        'Auth Mode': 'THREATFOX_AUTH_KEY',
      },
      link: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(indicator)}`,
    };
  }

  const isSuspicious = tier === 'suspicious';
  const confidence = isSuspicious ? 65 : 95;
  const matches = isSuspicious ? 1 : 2 + (seed % 3);
  const malware = itype === 'hash' ? 'CobaltStrike' : isSuspicious ? 'RedLine Stealer' : 'LummaStealer';
  const threatType = itype === 'hash' ? 'payload' : 'botnet_cc';
  const iocType = itype === 'ip' ? 'ip:port' : itype === 'domain' ? 'domain' : 'md5_hash';
  const refangedUrl = extractRefangedUrl(originalToken);

  const details: Record<string, string | number | boolean | null> = {
    Matches: matches,
    Malware: malware,
    'Threat Type': threatType,
    'IOC Type': refangedUrl ? 'url' : iocType,
    Confidence: `${confidence}%`,
    'Matched IOC': refangedUrl || (itype === 'ip' ? `${indicator}:443` : indicator),
    'First Seen': '2026-11-12 08:42:10 UTC',
    Tags: isSuspicious ? 'c2, proxy' : 'c2, stealer, payload-delivery',
  };

  return {
    source,
    sourceId: 'threatfox',
    indicator,
    originalToken,
    type: itype,
    status: 'ok',
    verdict: isSuspicious ? 'Suspicious' : 'Malicious',
    score: `${matches} IOC match(es) · ${confidence}%`,
    summary: `${matches} ThreatFox IOC record(s) (max confidence ${confidence}% · ${malware})`,
    details,
    link: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(indicator)}`,
  };
}

export function buildUrlscanSampleResult(
  indicator: string,
  originalToken: string,
  itype: IndicatorType,
  tier: SampleThreatTier,
  seed: number,
): LookupResult {
  const source = 'urlscan.io';
  const refangedUrl = extractRefangedUrl(originalToken);
  const isClean = tier === 'clean';
  const isSuspicious = tier === 'suspicious';

  const totalScans = isClean ? 14 : isSuspicious ? 4 : 9 + (seed % 8);
  const maliciousScans = isClean ? 0 : isSuspicious ? 0 : 3 + (seed % 4);
  const verdictScore = isClean ? 0 : isSuspicious ? 35 : 85;
  const verdict: Verdict = maliciousScans > 0 ? 'Malicious' : isSuspicious ? 'Suspicious' : 'Clean';

  const resolvedDomain =
    itype === 'domain'
      ? indicator
      : isClean
        ? 'dns.google'
        : isSuspicious
          ? 'login-verify.net'
          : 'evil.com';
  const resolvedIp =
    itype === 'ip'
      ? indicator
      : indicator === 'google.com'
        ? '8.8.8.8'
        : isClean
          ? '1.1.1.1'
          : indicator === 'evil.com'
            ? '1.2.3.4'
            : `185.220.${100 + (seed % 20)}.${10 + (seed % 190)}`;

  const scannedUrl = refangedUrl || `https://${resolvedDomain}/`;
  const scopeLabel = refangedUrl
    ? 'URL & Domain Analysis'
    : itype === 'domain'
      ? 'Domain Analysis'
      : itype === 'ip'
        ? 'IP Scan History'
        : 'File Hash History';

  const details: Record<string, string | number | boolean | null> = {
    'Analysis Scope': scopeLabel,
    'Total Scans': totalScans,
    'Flagged Malicious': maliciousScans,
    'Verdict Score': `${verdictScore}/100`,
    'Scanned URL': scannedUrl,
    'Latest Page': resolvedDomain,
    'Page IP': resolvedIp,
    ASN: isClean ? 'AS15169 Google LLC' : 'AS49505 Selectel',
    Country: isClean ? 'US' : ['NL', 'RU', 'DE'][seed % 3],
    Server: isClean ? 'gws' : 'nginx/1.24.0',
    Categories: isClean ? 'Search Engine' : isSuspicious ? 'Suspicious Redirect' : 'Phishing, Credential Harvesting',
    'Scan Time': '2026-11-15 09:30 UTC',
  };

  if (itype === 'domain' || refangedUrl) {
    details['Domain Registered'] = isClean ? '1997-09-15 04:00 UTC' : '2026-11-01 14:15 UTC';
  }
  if (itype === 'hash') {
    details['Contacted Domain'] = 'evil.com';
  }

  const queryInfo = buildUrlscanSearchQuery(indicator, itype, refangedUrl);

  return {
    source,
    sourceId: 'urlscan',
    indicator,
    originalToken,
    type: itype,
    status: 'ok',
    verdict,
    score: `${maliciousScans}/${totalScans} scans`,
    summary:
      maliciousScans > 0
        ? `${totalScans} urlscan.io historical scan(s), ${maliciousScans} flagged malicious`
        : isSuspicious
          ? `${totalScans} urlscan.io scan(s) · heuristic risk score ${verdictScore}/100`
          : `${totalScans} urlscan.io historical scan(s), 0 malicious`,
    details,
    link: `https://urlscan.io/search/#${encodeURIComponent(queryInfo.query)}`,
  };
}
