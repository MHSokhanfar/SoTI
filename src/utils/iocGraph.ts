import { detectIndicatorType, type LookupResult, type LookupStatus, type Verdict } from './indicators';

export type IocNodeType = 'ip' | 'domain' | 'file' | 'infra' | 'malware';

export type IocRelationType =
  | 'resolves_to'
  | 'communicates_with'
  | 'drops_file'
  | 'hosted_on'
  | 'attributed_to';

export interface IocGraphNode {
  id: string;
  label: string;
  subLabel?: string;
  type: IocNodeType;
  verdict: Verdict;
  queried: boolean;
  isSharedHub?: boolean;
  sources: string[];
  connectionCount: number;
  details: Record<string, string>;
}

export interface IocGraphLink {
  id: string;
  sourceId: string;
  targetId: string;
  relation: IocRelationType;
  label: string;
  evidenceSource: string;
}

export interface SharedInfrastructureBridge {
  hubId: string;
  hubLabel: string;
  hubType: IocNodeType;
  linkedIndicators: string[];
}

export interface IocGraphData {
  nodes: IocGraphNode[];
  links: IocGraphLink[];
  queriedIndicators: string[];
  sharedHubIds: string[];
  sharedBridges: SharedInfrastructureBridge[];
  sharedHubCount: number;
  countsByType: Record<IocNodeType, number>;
}

const VERDICT_RANK: Record<Verdict, number> = {
  Malicious: 4,
  Suspicious: 3,
  Clean: 2,
  Unknown: 1,
};

const RELATION_LABELS: Record<IocRelationType, string> = {
  resolves_to: 'Resolves to',
  communicates_with: 'Communicates with',
  drops_file: 'Drops / Links file',
  hosted_on: 'Hosted on',
  attributed_to: 'Attributed to',
};

const IGNORED_VALUES = new Set([
  '',
  'n/a',
  'na',
  'none',
  'unknown',
  'null',
  'undefined',
  'never',
  '-',
  'asnone',
  'as0',
]);

function isMeaningful(val: unknown): val is string | number {
  if (val === null || val === undefined || typeof val === 'boolean') return false;
  const s = String(val).trim();
  if (!s) return false;
  return !IGNORED_VALUES.has(s.toLowerCase());
}

function splitList(raw: unknown): string[] {
  if (!isMeaningful(raw)) return [];
  return String(raw)
    .split(/[,|]+/)
    .map((part) => part.trim())
    .filter((part) => !IGNORED_VALUES.has(part.toLowerCase()));
}

function pickHigherVerdict(a: Verdict, b: Verdict): Verdict {
  return VERDICT_RANK[b] > VERDICT_RANK[a] ? b : a;
}

function mapIndicatorToNodeType(itype: LookupResult['type']): IocNodeType {
  return itype === 'hash' ? 'file' : itype;
}

function makeNodeId(type: IocNodeType, rawLabel: string): string {
  return `${type}:${rawLabel.trim().toLowerCase()}`;
}

function normalizeInfraNode(raw: string, key: string): { idKey: string; displayLabel: string } | null {
  const trimmed = raw.trim();
  if (!trimmed || IGNORED_VALUES.has(trimmed.toLowerCase())) return null;
  if (key === 'ASN') {
    if (/^\d+$/.test(trimmed)) {
      return { idKey: `as${trimmed}`, displayLabel: `AS${trimmed}` };
    }
    const asnMatch = trimmed.match(/^AS(\d+)\b(.*)$/i);
    if (asnMatch) {
      const code = `AS${asnMatch[1]}`;
      return { idKey: `as${asnMatch[1]}`, displayLabel: trimmed.length > code.length ? `${code}${asnMatch[2]}` : code };
    }
  }
  return { idKey: trimmed.toLowerCase(), displayLabel: trimmed };
}

export function csvRowsToLookupResults(rows: Record<string, string>[]): LookupResult[] {
  const out: LookupResult[] = [];
  const seen = new Set<string>();

  for (const row of rows) {
    const indicator = String(row.indicator ?? '').trim();
    const source = String(row.source ?? '').trim();
    if (!indicator || !source) continue;

    const dedupeKey = `${indicator.toLowerCase()}::${source.toLowerCase()}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    const rawType = String(row.type ?? '').trim().toLowerCase();
    const type: LookupResult['type'] =
      rawType === 'ip' || rawType === 'domain' || rawType === 'hash'
        ? rawType
        : detectIndicatorType(indicator) ?? 'domain';

    const rawStatus = String(row.status ?? 'ok').trim().toLowerCase();
    const status: LookupStatus =
      rawStatus === 'ok' ||
      rawStatus === 'not_found' ||
      rawStatus === 'unsupported' ||
      rawStatus === 'error'
        ? rawStatus
        : 'ok';

    const rawVerdict = String(row.verdict ?? 'Unknown').trim();
    const verdict: Verdict =
      rawVerdict === 'Malicious' ||
      rawVerdict === 'Suspicious' ||
      rawVerdict === 'Clean' ||
      rawVerdict === 'Unknown'
        ? rawVerdict
        : 'Unknown';

    let parsedDetails: Record<string, string | number | boolean | null> = {};
    const rawDetails = row.details;
    if (typeof rawDetails === 'string' && rawDetails.trim().startsWith('{')) {
      try {
        const obj = JSON.parse(rawDetails);
        if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
          parsedDetails = obj;
        }
      } catch {
        parsedDetails = {};
      }
    }

    out.push({
      source,
      sourceId: source.toLowerCase().replace(/[^a-z0-9]+/g, '_'),
      indicator,
      originalToken: indicator,
      type,
      status,
      verdict,
      score: String(row.score ?? 'N/A'),
      summary: String(row.summary ?? ''),
      details: parsedDetails,
      link: String(row.link ?? ''),
    });
  }

  return out;
}

export function mergeGraphLookupResults(
  currentResults: LookupResult[],
  historicalRows: Record<string, string>[],
): LookupResult[] {
  const merged: LookupResult[] = [...currentResults];
  const seen = new Set(
    currentResults.map((r) => `${r.indicator.trim().toLowerCase()}::${r.source.trim().toLowerCase()}`),
  );

  for (const item of csvRowsToLookupResults(historicalRows)) {
    const key = `${item.indicator.trim().toLowerCase()}::${item.source.trim().toLowerCase()}`;
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(item);
    }
  }
  return merged;
}

export function buildIocGraphData(
  results: LookupResult[],
  options?: { focusIndicator?: string | null; sharedOnly?: boolean },
): IocGraphData {
  const nodeMap = new Map<string, IocGraphNode>();
  const linkMap = new Map<string, IocGraphLink>();
  const queriedIndicators: string[] = [];
  const queriedSet = new Set<string>();

  const ensureNode = (params: {
    id: string;
    label: string;
    subLabel?: string;
    type: IocNodeType;
    verdict?: Verdict;
    queried?: boolean;
    source?: string;
    detailEntries?: Record<string, string>;
  }): IocGraphNode => {
    const existing = nodeMap.get(params.id);
    if (existing) {
      if (params.verdict) {
        existing.verdict = pickHigherVerdict(existing.verdict, params.verdict);
      }
      if (params.queried) {
        existing.queried = true;
      }
      if (params.subLabel && !existing.subLabel) {
        existing.subLabel = params.subLabel;
      }
      if (params.source && !existing.sources.includes(params.source)) {
        existing.sources.push(params.source);
      }
      if (params.detailEntries) {
        for (const [k, v] of Object.entries(params.detailEntries)) {
          if (!(k in existing.details)) {
            existing.details[k] = v;
          }
        }
      }
      return existing;
    }

    const created: IocGraphNode = {
      id: params.id,
      label: params.label,
      ...(params.subLabel ? { subLabel: params.subLabel } : {}),
      type: params.type,
      verdict: params.verdict ?? 'Unknown',
      queried: Boolean(params.queried),
      sources: params.source ? [params.source] : [],
      connectionCount: 0,
      details: params.detailEntries ? { ...params.detailEntries } : {},
    };
    nodeMap.set(params.id, created);
    return created;
  };

  const addLink = (
    sourceId: string,
    targetId: string,
    relation: IocRelationType,
    evidenceSource: string,
  ) => {
    if (sourceId === targetId) return;
    const key = `${sourceId}->${targetId}:${relation}`;
    if (linkMap.has(key)) return;
    linkMap.set(key, {
      id: key,
      sourceId,
      targetId,
      relation,
      label: RELATION_LABELS[relation],
      evidenceSource,
    });
  };

  // Pass 1: register all queried IOC nodes
  for (const r of results) {
    const nodeType = mapIndicatorToNodeType(r.type);
    const id = makeNodeId(nodeType, r.indicator);
    const cleanDetails: Record<string, string> = {};
    for (const [k, v] of Object.entries(r.details || {})) {
      if (isMeaningful(v)) {
        cleanDetails[k] = String(v);
      }
    }
    const fileSubLabel =
      nodeType === 'file' && isMeaningful(r.details?.Name) ? String(r.details.Name) : undefined;

    ensureNode({
      id,
      label: r.indicator,
      subLabel: fileSubLabel,
      type: nodeType,
      verdict: r.status === 'ok' ? r.verdict : 'Unknown',
      queried: true,
      source: r.source,
      detailEntries: cleanDetails,
    });

    if (!queriedSet.has(r.indicator)) {
      queriedSet.add(r.indicator);
      queriedIndicators.push(r.indicator);
    }
  }

  // Pass 2: extract relationships across IPs, Domains, Files, Infra, and Malware
  for (const r of results) {
    const sourceType = mapIndicatorToNodeType(r.type);
    const sourceNodeId = makeNodeId(sourceType, r.indicator);
    const d = r.details || {};
    const inheritedVerdict: Verdict = r.status === 'ok' ? r.verdict : 'Unknown';

    // Domain links (Domain, Hostnames, Latest Page, Page Domain, Contacted Domain, Related Domain)
    const domainKeys: { key: string; relation: IocRelationType }[] = [
      { key: 'Domain', relation: sourceType === 'file' ? 'communicates_with' : 'resolves_to' },
      { key: 'Hostnames', relation: 'resolves_to' },
      { key: 'Latest Page', relation: 'resolves_to' },
      { key: 'Page Domain', relation: 'resolves_to' },
      { key: 'Hosted Domain', relation: 'resolves_to' },
      { key: 'Shared Domain', relation: 'resolves_to' },
      { key: 'Related Domain', relation: 'communicates_with' },
      { key: 'Contacted Domain', relation: 'communicates_with' },
    ];
    for (const { key, relation } of domainKeys) {
      for (const token of splitList(d[key])) {
        const cleaned = token.toLowerCase();
        if (detectIndicatorType(cleaned) === 'domain') {
          const targetId = makeNodeId('domain', cleaned);
          ensureNode({
            id: targetId,
            label: cleaned,
            type: 'domain',
            verdict: key === 'Contacted Domain' ? inheritedVerdict : undefined,
            source: r.source,
          });
          addLink(sourceNodeId, targetId, relation, r.source);
        }
      }
    }

    // IP links (Resolved IP, Page IP, Contacted IP, Related IP)
    const ipKeys: { key: string; relation: IocRelationType }[] = [
      { key: 'Resolved IP', relation: 'resolves_to' },
      { key: 'Page IP', relation: 'resolves_to' },
      { key: 'Related IP', relation: 'communicates_with' },
      { key: 'Contacted IP', relation: 'communicates_with' },
    ];
    for (const { key, relation } of ipKeys) {
      for (const token of splitList(d[key])) {
        if (detectIndicatorType(token) === 'ip') {
          const targetId = makeNodeId('ip', token);
          ensureNode({
            id: targetId,
            label: token,
            type: 'ip',
            source: r.source,
          });
          addLink(sourceNodeId, targetId, relation, r.source);
        }
      }
    }

    // File links (Communicating File, Dropped File, Related File)
    const fileKeys: { key: string; relation: IocRelationType }[] = [
      { key: 'Communicating File', relation: 'communicates_with' },
      { key: 'Dropped File', relation: 'drops_file' },
      { key: 'Related File', relation: 'drops_file' },
    ];
    for (const { key, relation } of fileKeys) {
      for (const token of splitList(d[key])) {
        const lower = token.toLowerCase();
        const targetId = makeNodeId('file', lower);
        ensureNode({
          id: targetId,
          label: lower,
          type: 'file',
          source: r.source,
        });
        addLink(sourceNodeId, targetId, relation, r.source);
      }
    }

    // Infrastructure links (ASN, AS Owner, ISP, Organization) - canonicalize ASN codes so multi-source ASNs merge cleanly
    const infraCandidates: { idKey: string; displayLabel: string }[] = [];
    if (isMeaningful(d.ASN)) {
      const norm = normalizeInfraNode(String(d.ASN), 'ASN');
      if (norm) infraCandidates.push(norm);
    } else if (isMeaningful(d['AS Owner'])) {
      const norm = normalizeInfraNode(String(d['AS Owner']), 'AS Owner');
      if (norm) infraCandidates.push(norm);
    } else if (isMeaningful(d.Organization)) {
      const norm = normalizeInfraNode(String(d.Organization), 'Organization');
      if (norm) infraCandidates.push(norm);
    } else if (isMeaningful(d.ISP)) {
      const norm = normalizeInfraNode(String(d.ISP), 'ISP');
      if (norm) infraCandidates.push(norm);
    }

    const seenInfraIds = new Set<string>();
    for (const infra of infraCandidates) {
      if (seenInfraIds.has(infra.idKey)) continue;
      seenInfraIds.add(infra.idKey);
      const targetId = makeNodeId('infra', infra.idKey);
      const existingInfra = nodeMap.get(targetId);
      if (existingInfra && infra.displayLabel.length > existingInfra.label.length) {
        existingInfra.label = infra.displayLabel;
      }
      ensureNode({
        id: targetId,
        label: infra.displayLabel,
        type: 'infra',
        source: r.source,
      });
      addLink(sourceNodeId, targetId, 'hosted_on', r.source);
    }

    // Malware / Threat attribution
    const malwareKeys = ['Malware Families', 'Malware Family', 'Malware', 'Threat Label'];
    for (const key of malwareKeys) {
      for (const family of splitList(d[key])) {
        const targetId = makeNodeId('malware', family);
        ensureNode({
          id: targetId,
          label: family,
          type: 'malware',
          verdict: inheritedVerdict === 'Clean' ? 'Unknown' : inheritedVerdict,
          source: r.source,
        });
        addLink(sourceNodeId, targetId, 'attributed_to', r.source);
      }
    }
  }

  let activeNodes = Array.from(nodeMap.values());
  let activeLinks = Array.from(linkMap.values());

  // Identify shared infrastructure hubs: entities connecting >= 2 distinct neighbor nodes
  const computeSharedHubs = (nodesList: IocGraphNode[], linksList: IocGraphLink[]) => {
    const nodeById = new Map(nodesList.map((n) => [n.id, n]));
    const neighborsMap = new Map<string, Set<string>>();
    for (const l of linksList) {
      if (!neighborsMap.has(l.sourceId)) neighborsMap.set(l.sourceId, new Set());
      if (!neighborsMap.has(l.targetId)) neighborsMap.set(l.targetId, new Set());
      neighborsMap.get(l.sourceId)!.add(l.targetId);
      neighborsMap.get(l.targetId)!.add(l.sourceId);
    }

    const bridges: SharedInfrastructureBridge[] = [];
    const hubIds = new Set<string>();
    for (const node of nodesList) {
      const neighbors = Array.from(neighborsMap.get(node.id) || [])
        .map((nid) => nodeById.get(nid))
        .filter((n): n is IocGraphNode => Boolean(n));
      // Consider shared if >= 2 distinct connected nodes (especially >= 2 queried or multi-IOC links)
      const uniqueIndicatorCount = neighbors.length;
      const queriedNeighborCount = neighbors.filter((n) => n.queried).length;
      if (uniqueIndicatorCount >= 2 && (queriedNeighborCount >= 2 || node.type === 'domain' || node.type === 'malware' || node.type === 'infra' || node.type === 'ip')) {
        hubIds.add(node.id);
        bridges.push({
          hubId: node.id,
          hubLabel: node.subLabel || node.label,
          hubType: node.type,
          linkedIndicators: neighbors.map((n) => n.label).sort(),
        });
      }
    }

    bridges.sort((a, b) => b.linkedIndicators.length - a.linkedIndicators.length || a.hubLabel.localeCompare(b.hubLabel));
    return { hubIds, bridges };
  };

  if (options?.sharedOnly) {
    const { hubIds } = computeSharedHubs(activeNodes, activeLinks);
    if (hubIds.size > 0) {
      const keepIds = new Set<string>(hubIds);
      for (const l of activeLinks) {
        if (hubIds.has(l.sourceId)) keepIds.add(l.targetId);
        if (hubIds.has(l.targetId)) keepIds.add(l.sourceId);
      }
      activeNodes = activeNodes.filter((n) => keepIds.has(n.id));
      activeLinks = activeLinks.filter((l) => keepIds.has(l.sourceId) && keepIds.has(l.targetId));
    } else {
      activeNodes = [];
      activeLinks = [];
    }
  }

  // Filter to focused IOC neighborhood (2-hop BFS) if requested
  if (options?.focusIndicator) {
    const focusMatch = activeNodes.find(
      (n) => n.label.toLowerCase() === options.focusIndicator?.trim().toLowerCase(),
    );
    if (focusMatch) {
      const allowed = new Set<string>([focusMatch.id]);
      const adj = new Map<string, string[]>();
      for (const l of activeLinks) {
        if (!adj.has(l.sourceId)) adj.set(l.sourceId, []);
        if (!adj.has(l.targetId)) adj.set(l.targetId, []);
        adj.get(l.sourceId)!.push(l.targetId);
        adj.get(l.targetId)!.push(l.sourceId);
      }

      const queue: { id: string; depth: number }[] = [{ id: focusMatch.id, depth: 0 }];
      while (queue.length > 0) {
        const current = queue.shift()!;
        if (current.depth >= 2) continue;
        for (const neighborId of adj.get(current.id) || []) {
          if (!allowed.has(neighborId)) {
            allowed.add(neighborId);
            queue.push({ id: neighborId, depth: current.depth + 1 });
          }
        }
      }

      activeNodes = activeNodes.filter((n) => allowed.has(n.id));
      activeLinks = activeLinks.filter((l) => allowed.has(l.sourceId) && allowed.has(l.targetId));
    }
  }

  // Compute connection counts & shared hubs for active graph
  const degreeMap = new Map<string, number>();
  for (const l of activeLinks) {
    degreeMap.set(l.sourceId, (degreeMap.get(l.sourceId) ?? 0) + 1);
    degreeMap.set(l.targetId, (degreeMap.get(l.targetId) ?? 0) + 1);
  }

  const { hubIds: finalHubIds, bridges: sharedBridges } = computeSharedHubs(activeNodes, activeLinks);

  const countsByType: Record<IocNodeType, number> = {
    ip: 0,
    domain: 0,
    file: 0,
    infra: 0,
    malware: 0,
  };

  const finalNodes = activeNodes.map((n) => {
    countsByType[n.type] += 1;
    return {
      ...n,
      isSharedHub: finalHubIds.has(n.id),
      connectionCount: degreeMap.get(n.id) ?? 0,
    };
  });

  return {
    nodes: finalNodes,
    links: activeLinks,
    queriedIndicators,
    sharedHubIds: Array.from(finalHubIds),
    sharedBridges,
    sharedHubCount: sharedBridges.length,
    countsByType,
  };
}

export function formatIocClipboardText(result: LookupResult): string {
  const statusTag = result.status === 'ok' ? result.verdict : result.status.replace('_', ' ').toUpperCase();
  const parts = [
    `${result.indicator} [${result.type.toUpperCase()}]`,
    `${result.source}: ${statusTag} (${result.score})`,
    result.summary,
  ];
  if (result.link) {
    parts.push(result.link);
  }
  return parts.join(' | ');
}

export function formatIocGroupClipboardText(
  indicator: string,
  type: string,
  items: LookupResult[],
): string {
  const header = `${indicator} [${type.toUpperCase()}]`;
  const lines = items.map((item) => {
    const statusTag = item.status === 'ok' ? item.verdict : item.status.replace('_', ' ').toUpperCase();
    return `- ${item.source}: ${statusTag} (${item.score}) — ${item.summary}`;
  });
  return [header, ...lines].join('\n');
}
