import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildThreatFoxSampleResult,
  buildUrlscanSampleResult,
  buildUrlscanSearchQuery,
  parseThreatFoxApiResponse,
  parseUrlscanApiResponse,
} from './enrichmentProviders';

test('buildUrlscanSearchQuery builds URL and domain queries cleanly', () => {
  const urlQuery = buildUrlscanSearchQuery('evil.com', 'domain', 'http://evil.com/login');
  assert.equal(urlQuery.isUrlAnalysis, true);
  assert.equal(urlQuery.targetLabel, 'http://evil.com/login');
  assert.ok(urlQuery.query.includes('page.url:"http://evil.com/login"'));
  assert.equal(urlQuery.fallbackQuery, 'domain:evil.com');

  const domainQuery = buildUrlscanSearchQuery('evil.com', 'domain', null);
  assert.equal(domainQuery.query, 'domain:evil.com');
  assert.equal(domainQuery.fallbackQuery, null);
  assert.equal(domainQuery.isUrlAnalysis, true);

  const ipQuery = buildUrlscanSearchQuery('8.8.8.8', 'ip', null);
  assert.equal(ipQuery.query, 'ip:8.8.8.8');
  assert.equal(ipQuery.isUrlAnalysis, false);
});

test('parseThreatFoxApiResponse handles ok, no_result, and auth error payloads', () => {
  const notFound = parseThreatFoxApiResponse({
    indicator: '8.8.8.8',
    originalToken: '8.8.8.8',
    itype: 'ip',
    payload: { query_status: 'no_result', data: 'Your query did not yield any results' },
  });
  assert.equal(notFound.status, 'not_found');
  assert.equal(notFound.verdict, 'Unknown');

  const authError = parseThreatFoxApiResponse({
    indicator: 'evil.com',
    originalToken: 'evil.com',
    itype: 'domain',
    payload: { query_status: 'wrong_auth_key', data: 'Invalid Auth-Key' },
  });
  assert.equal(authError.status, 'error');
  assert.equal(authError.summary, 'Invalid Auth-Key');

  const okRes = parseThreatFoxApiResponse({
    indicator: 'evil.com',
    originalToken: 'hxxp://evil[.]com/login',
    itype: 'domain',
    payload: {
      query_status: 'ok',
      data: [
        {
          ioc: 'http://evil.com/login',
          threat_type: 'payload_delivery',
          threat_type_desc: 'Delivering malware payload',
          ioc_type: 'url',
          malware_printable: 'LummaStealer',
          confidence_level: 90,
          first_seen: '2026-11-10 12:00:00 UTC',
          tags: ['stealer', 'phish'],
          reporter: 'abuse_hunter',
        },
      ],
    },
  });
  assert.equal(okRes.status, 'ok');
  assert.equal(okRes.verdict, 'Malicious');
  assert.equal(okRes.details.Malware, 'LummaStealer');
  assert.equal(okRes.details.Confidence, '90%');
  assert.equal(okRes.details['Matched IOC'], 'http://evil.com/login');
});

test('parseUrlscanApiResponse extracts rich domain and URL analysis from search and detail payloads', () => {
  const parsed = parseUrlscanApiResponse({
    indicator: 'evil.com',
    originalToken: 'hxxp://evil[.]com/login',
    itype: 'domain',
    refangedUrl: 'http://evil.com/login',
    searchPayload: {
      total: 4,
      results: [
        {
          _id: 'scan-uuid-123',
          page: {
            url: 'http://evil.com/login',
            domain: 'evil.com',
            ip: '1.2.3.4',
            country: 'RU',
            asn: 'AS49505',
            server: 'nginx',
          },
          verdicts: { overall: { malicious: true, score: 90, categories: ['phishing'] } },
        },
      ],
    },
    detailPayload: {
      task: { uuid: 'scan-uuid-123', url: 'http://evil.com/login' },
      page: {
        url: 'http://evil.com/login',
        domain: 'evil.com',
        ip: '1.2.3.4',
        asn: 'AS49505',
        asnname: 'Selectel',
        country: 'RU',
        server: 'nginx/1.24.0',
        title: 'Sign in',
      },
      verdicts: { overall: { malicious: true, score: 90, categories: ['phishing'] } },
      lists: {
        ips: ['1.2.3.4', '185.220.101.4'],
        domains: ['evil.com', 'cdn-evil.net'],
      },
    },
  });

  assert.equal(parsed.status, 'ok');
  assert.equal(parsed.verdict, 'Malicious');
  assert.equal(parsed.details['Analysis Scope'], 'URL & Domain Analysis');
  assert.equal(parsed.details['Scanned URL'], 'http://evil.com/login');
  assert.equal(parsed.details['Page IP'], '1.2.3.4');
  assert.equal(parsed.details.ASN, 'AS49505 Selectel');
  assert.equal(parsed.details['Verdict Score'], '90/100');
  assert.equal(parsed.details['Related IP'], '185.220.101.4');
  assert.equal(parsed.details['Contacted Domain'], 'cdn-evil.net');
  assert.equal(parsed.link, 'https://urlscan.io/result/scan-uuid-123/');
});

test('sample builders produce domain/URL urlscan and ThreatFox enrichment', () => {
  const tf = buildThreatFoxSampleResult('evil.com', 'hxxp://evil[.]com/login', 'domain', 'malicious', 12);
  assert.equal(tf.sourceId, 'threatfox');
  assert.equal(tf.verdict, 'Malicious');
  assert.equal(tf.details['IOC Type'], 'url');

  const us = buildUrlscanSampleResult('evil.com', 'hxxp://evil[.]com/login', 'domain', 'malicious', 12);
  assert.equal(us.sourceId, 'urlscan');
  assert.equal(us.verdict, 'Malicious');
  assert.equal(us.details['Analysis Scope'], 'URL & Domain Analysis');
  assert.equal(us.details['Scanned URL'], 'http://evil.com/login');
  assert.equal(us.details['Page IP'], '1.2.3.4');
});
