import { useEffect, useMemo, useRef, useState } from 'react';
import * as d3 from 'd3';
import {
  Check,
  Copy,
  Focus,
  Maximize2,
  Network,
  RotateCcw,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import {
  buildIocGraphData,
  type IocGraphLink,
  type IocGraphNode,
  type IocNodeType,
} from '../utils/iocGraph';
import type { LookupResult } from '../utils/indicators';
import { copyToClipboard } from '../utils/clipboard';
import type { ThemeMode } from '../utils/theme';

interface IocNetworkGraphProps {
  results: LookupResult[];
  theme: ThemeMode;
  focusedIndicator?: string | null;
  onFocusIndicatorChange?: (indicator: string | null) => void;
}

interface SimNode extends d3.SimulationNodeDatum {
  data: IocGraphNode;
}

interface SimLink extends d3.SimulationLinkDatum<SimNode> {
  data: IocGraphLink;
}

const NODE_TYPE_META: Record<
  IocNodeType,
  {
    label: string;
    short: string;
    lightFill: string;
    darkFill: string;
    legendDot: string;
  }
> = {
  ip: {
    label: 'IP Address',
    short: 'IP',
    lightFill: '#0284c7',
    darkFill: '#0ea5e9',
    legendDot: 'bg-sky-600',
  },
  domain: {
    label: 'Domain',
    short: 'DOM',
    lightFill: '#4f46e5',
    darkFill: '#6366f1',
    legendDot: 'bg-indigo-600',
  },
  file: {
    label: 'File / Hash',
    short: 'FILE',
    lightFill: '#d97706',
    darkFill: '#f59e0b',
    legendDot: 'bg-amber-600',
  },
  infra: {
    label: 'ASN / Infra',
    short: 'ASN',
    lightFill: '#0f766e',
    darkFill: '#14b8a6',
    legendDot: 'bg-teal-600',
  },
  malware: {
    label: 'Malware / Threat',
    short: 'THRT',
    lightFill: '#dc2626',
    darkFill: '#ef4444',
    legendDot: 'bg-red-600',
  },
};

function shortenLabel(node: IocGraphNode): string {
  if (node.subLabel) {
    return node.subLabel.length > 22 ? `${node.subLabel.slice(0, 19)}...` : node.subLabel;
  }
  const raw = node.label;
  if (node.type === 'file' && raw.length > 18) {
    return `${raw.slice(0, 8)}...${raw.slice(-6)}`;
  }
  return raw.length > 24 ? `${raw.slice(0, 21)}...` : raw;
}

export function IocNetworkGraph({
  results,
  theme,
  focusedIndicator,
  onFocusIndicatorChange,
}: IocNetworkGraphProps) {
  const [internalFocus, setInternalFocus] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const svgRef = useRef<SVGSVGElement | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const defaultTransformRef = useRef<d3.ZoomTransform>(d3.zoomIdentity);
  const copyTimerRef = useRef<number | null>(null);

  const activeFocus = focusedIndicator !== undefined ? focusedIndicator : internalFocus;

  const setFocus = (next: string | null) => {
    if (onFocusIndicatorChange) {
      onFocusIndicatorChange(next);
    } else {
      setInternalFocus(next);
    }
  };

  const fullGraph = useMemo(() => buildIocGraphData(results), [results]);
  const graph = useMemo(
    () => buildIocGraphData(results, { focusIndicator: activeFocus }),
    [results, activeFocus],
  );

  // Reset selected node if it disappears after filter change; otherwise auto-pick first queried node
  useEffect(() => {
    if (graph.nodes.length === 0) {
      setSelectedNodeId(null);
      return;
    }
    setSelectedNodeId((prev) => {
      if (prev && graph.nodes.some((n) => n.id === prev)) return prev;
      const firstQueried = graph.nodes.find((n) => n.queried);
      return firstQueried?.id ?? graph.nodes[0].id;
    });
  }, [graph.nodes]);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  const selectedNode = useMemo(
    () => graph.nodes.find((n) => n.id === selectedNodeId) ?? null,
    [graph.nodes, selectedNodeId],
  );

  const selectedNodeLinks = useMemo(() => {
    if (!selectedNode) return [];
    const byId = new Map(graph.nodes.map((n) => [n.id, n]));
    return graph.links
      .filter((l) => l.sourceId === selectedNode.id || l.targetId === selectedNode.id)
      .map((l) => {
        const isOutgoing = l.sourceId === selectedNode.id;
        const peer = byId.get(isOutgoing ? l.targetId : l.sourceId);
        return {
          link: l,
          isOutgoing,
          peer,
        };
      })
      .filter((item) => Boolean(item.peer));
  }, [graph.nodes, graph.links, selectedNode]);

  useEffect(() => {
    const svgElement = svgRef.current;
    if (!svgElement || graph.nodes.length === 0) return;

    const width = 760;
    const height = 430;
    const isDark = theme === 'dark';

    const colors = {
      linkStroke: isDark ? '#475569' : '#cbd5e1',
      linkLabel: isDark ? '#94a3b8' : '#64748b',
      nodeText: isDark ? '#e2e8f0' : '#0f172a',
      nodeSubText: isDark ? '#94a3b8' : '#64748b',
      haloBg: isDark ? '#0f172a' : '#ffffff',
      selectedStroke: '#ef4444',
      maliciousRing: '#dc2626',
      suspiciousRing: '#d97706',
      cleanRing: '#16a34a',
      unknownRing: isDark ? '#475569' : '#94a3b8',
    };

    const svg = d3.select(svgElement);
    svg.selectAll('*').remove();

    const defs = svg.append('defs');
    defs
      .append('marker')
      .attr('id', 'ioc-arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 26)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-4L8,0L0,4Z')
      .attr('fill', colors.linkStroke);

    const rootGroup = svg.append('g').attr('class', 'ioc-graph-viewport');

    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.45, 2.5])
      .on('zoom', (event) => {
        rootGroup.attr('transform', event.transform.toString());
      });

    zoomBehaviorRef.current = zoom;
    svg.call(zoom).on('dblclick.zoom', null);

    const simNodes: SimNode[] = graph.nodes.map((node, index) => {
      const angle = (index / Math.max(1, graph.nodes.length)) * Math.PI * 2;
      const radius = node.queried ? 90 : 160;
      return {
        data: node,
        x: width / 2 + Math.cos(angle) * radius,
        y: height / 2 + Math.sin(angle) * radius,
      };
    });

    const nodeById = new Map(simNodes.map((n) => [n.data.id, n]));
    const simLinks: SimLink[] = graph.links
      .map((l) => {
        const s = nodeById.get(l.sourceId);
        const t = nodeById.get(l.targetId);
        if (!s || !t) return null;
        return {
          data: l,
          source: s,
          target: t,
        } as SimLink;
      })
      .filter((x): x is SimLink => x !== null);

    const simulation = d3
      .forceSimulation<SimNode>(simNodes)
      .force(
        'link',
        d3
          .forceLink<SimNode, SimLink>(simLinks)
          .id((d) => d.data.id)
          .distance((l) => (l.data.relation === 'resolves_to' || l.data.relation === 'communicates_with' ? 128 : 108)),
      )
      .force('charge', d3.forceManyBody<SimNode>().strength(-360))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide<SimNode>().radius((d) => (d.data.queried ? 44 : 36)))
      .force('x', d3.forceX<SimNode>(width / 2).strength(0.06))
      .force('y', d3.forceY<SimNode>(height / 2).strength(0.08));

    // Pre-stabilize positions synchronously so first frame renders balanced without overlap
    simulation.stop();
    for (let i = 0; i < 95; i++) {
      simulation.tick();
    }

    // Compute auto-fit transform so dense multi-IOC graphs stay comfortably within SVG margins
    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;
    for (const n of simNodes) {
      const nx = n.x ?? width / 2;
      const ny = n.y ?? height / 2;
      if (nx < minX) minX = nx;
      if (nx > maxX) maxX = nx;
      if (ny < minY) minY = ny;
      if (ny > maxY) maxY = ny;
    }
    const padX = 76;
    const padY = 58;
    const contentW = Math.max(120, maxX - minX + padX * 2);
    const contentH = Math.max(120, maxY - minY + padY * 2);
    const fitScale = Math.min(1.05, Math.max(0.5, Math.min(width / contentW, height / contentH)));
    const midX = (minX + maxX) / 2;
    const midY = (minY + maxY) / 2;
    const initialTransform = d3.zoomIdentity
      .translate(width / 2 - fitScale * midX, height / 2 - fitScale * midY)
      .scale(fitScale);
    defaultTransformRef.current = initialTransform;
    svg.call(zoom.transform, initialTransform);

    const linkGroup = rootGroup.append('g').attr('class', 'ioc-links');
    const linkLines = linkGroup
      .selectAll('line')
      .data(simLinks)
      .join('line')
      .attr('stroke', colors.linkStroke)
      .attr('stroke-width', 1.6)
      .attr('stroke-dasharray', (d) =>
        d.data.relation === 'hosted_on' || d.data.relation === 'attributed_to' ? '4,3' : null,
      )
      .attr('marker-end', 'url(#ioc-arrow)');

    const linkLabelGroup = rootGroup.append('g').attr('class', 'ioc-link-labels');
    const linkLabels = linkLabelGroup
      .selectAll('text')
      .data(simLinks)
      .join('text')
      .attr('text-anchor', 'middle')
      .attr('font-size', '9px')
      .attr('font-family', 'ui-sans-serif, system-ui, sans-serif')
      .attr('fill', colors.linkLabel)
      .attr('pointer-events', 'none')
      .text((d) => d.data.label);

    const nodeGroup = rootGroup.append('g').attr('class', 'ioc-nodes');
    const nodeElements = nodeGroup
      .selectAll<SVGGElement, SimNode>('g')
      .data(simNodes, (d) => d.data.id)
      .join('g')
      .attr('class', 'ioc-node')
      .attr('cursor', 'grab')
      .on('click', (event, d) => {
        event.stopPropagation();
        setSelectedNodeId(d.data.id);
      });

    // Outer verdict halo ring
    nodeElements
      .append('circle')
      .attr('class', 'ioc-node-halo')
      .attr('r', (d) => (d.data.queried ? 23 : 17))
      .attr('fill', colors.haloBg)
      .attr('stroke', (d) => {
        switch (d.data.verdict) {
          case 'Malicious':
            return colors.maliciousRing;
          case 'Suspicious':
            return colors.suspiciousRing;
          case 'Clean':
            return colors.cleanRing;
          default:
            return colors.unknownRing;
        }
      })
      .attr('stroke-width', 2);

    // Inner entity circle
    nodeElements
      .append('circle')
      .attr('class', 'ioc-node-core')
      .attr('r', (d) => (d.data.queried ? 18 : 13))
      .attr('fill', (d) => {
        const meta = NODE_TYPE_META[d.data.type];
        return isDark ? meta.darkFill : meta.lightFill;
      });

    // Entity type tag inside circle
    nodeElements
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'central')
      .attr('font-size', (d) => (d.data.queried ? '8.5px' : '7.5px'))
      .attr('font-weight', '700')
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
      .attr('fill', '#ffffff')
      .attr('pointer-events', 'none')
      .text((d) => NODE_TYPE_META[d.data.type].short);

    // Readable indicator label below node
    nodeElements
      .append('text')
      .attr('y', (d) => (d.data.queried ? 35 : 29))
      .attr('text-anchor', 'middle')
      .attr('font-size', (d) => (d.data.queried ? '11px' : '10px'))
      .attr('font-weight', (d) => (d.data.queried ? '600' : '500'))
      .attr('font-family', 'ui-monospace, SFMono-Regular, Menlo, monospace')
      .attr('fill', colors.nodeText)
      .attr('pointer-events', 'none')
      .text((d) => shortenLabel(d.data));

    nodeElements.append('title').text((d) => `${d.data.label} (${NODE_TYPE_META[d.data.type].label} · ${d.data.verdict})`);

    const renderPositions = () => {
      linkLines
        .attr('x1', (d) => (d.source as SimNode).x ?? 0)
        .attr('y1', (d) => (d.source as SimNode).y ?? 0)
        .attr('x2', (d) => (d.target as SimNode).x ?? 0)
        .attr('y2', (d) => (d.target as SimNode).y ?? 0);

      linkLabels
        .attr('x', (d) => (((d.source as SimNode).x ?? 0) + ((d.target as SimNode).x ?? 0)) / 2)
        .attr('y', (d) => (((d.source as SimNode).y ?? 0) + ((d.target as SimNode).y ?? 0)) / 2 - 4);

      nodeElements.attr('transform', (d) => `translate(${d.x ?? 0}, ${d.y ?? 0})`);
    };

    renderPositions();

    const dragBehavior = d3
      .drag<SVGGElement, SimNode>()
      .on('start', (event, d) => {
        if (!event.active) simulation.alphaTarget(0.25).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on('drag', (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on('end', (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });

    nodeElements.call(dragBehavior);
    simulation.on('tick', renderPositions);
    simulation.alpha(0.08).restart();

    return () => {
      simulation.stop();
    };
  }, [graph, theme]);

  // Highlight selected node ring without restarting force physics
  useEffect(() => {
    const svgElement = svgRef.current;
    if (!svgElement) return;
    const isDark = theme === 'dark';
    const svg = d3.select(svgElement);
    svg
      .selectAll<SVGGElement, SimNode>('g.ioc-node')
      .select<SVGCircleElement>('circle.ioc-node-halo')
      .attr('stroke', (d) => {
        if (d.data.id === selectedNodeId) return '#ef4444';
        switch (d.data.verdict) {
          case 'Malicious':
            return '#dc2626';
          case 'Suspicious':
            return '#d97706';
          case 'Clean':
            return '#16a34a';
          default:
            return isDark ? '#475569' : '#94a3b8';
        }
      })
      .attr('stroke-width', (d) => (d.data.id === selectedNodeId ? 3.5 : 2));
  }, [selectedNodeId, graph, theme]);

  function handleZoomStep(scaleFactor: number) {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(180)
      .call(zoomBehaviorRef.current.scaleBy, scaleFactor);
  }

  function handleZoomReset() {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(200)
      .call(zoomBehaviorRef.current.transform, defaultTransformRef.current);
  }

  async function handleCopyNodeValue(node: IocGraphNode) {
    const ok = await copyToClipboard(node.label);
    if (ok) {
      setCopiedId(node.id);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => setCopiedId(null), 2000);
    }
  }

  if (results.length === 0) return null;

  return (
    <div
      data-testid="ioc-network-graph"
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900"
    >
      <div className="flex flex-col gap-3 border-b border-slate-200 dark:border-slate-800 px-5 py-4 sm:flex-row sm:items-center sm:justify-between md:px-6">
        <div>
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-red-600 dark:text-red-400" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">
              IOC Relationship Network
            </h2>
          </div>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400 tabular-nums">
            {graph.nodes.length} entities · {graph.links.length} relationships · {graph.countsByType.ip} IP · {graph.countsByType.domain} Domain · {graph.countsByType.file} File
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 shrink-0">
          <button
            type="button"
            onClick={() => handleZoomStep(1.25)}
            aria-label="Zoom in relationship graph"
            className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <ZoomIn className="h-3.5 w-3.5" aria-hidden="true" />
            Zoom In
          </button>
          <button
            type="button"
            onClick={() => handleZoomStep(0.8)}
            aria-label="Zoom out relationship graph"
            className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <ZoomOut className="h-3.5 w-3.5" aria-hidden="true" />
            Zoom Out
          </button>
          <button
            type="button"
            onClick={handleZoomReset}
            aria-label="Reset relationship graph zoom"
            className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
            Reset
          </button>
        </div>
      </div>

      {fullGraph.queriedIndicators.length > 1 && (
        <div
          className="flex flex-wrap items-center gap-1.5 border-b border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-800/30 px-5 py-2.5 md:px-6"
          role="group"
          aria-label="Focus relationship graph by IOC"
        >
          <span className="mr-1 text-xs font-medium text-slate-500 dark:text-slate-400">Scope:</span>
          <button
            type="button"
            onClick={() => setFocus(null)}
            className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              !activeFocus
                ? 'bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-950'
                : 'text-slate-600 dark:text-slate-300 hover:bg-slate-200/70 dark:hover:bg-slate-700/60'
            }`}
          >
            All IOCs ({fullGraph.queriedIndicators.length})
          </button>
          {fullGraph.queriedIndicators.map((ind) => {
            const isSelected = activeFocus?.toLowerCase() === ind.toLowerCase();
            const shortInd = ind.length > 20 ? `${ind.slice(0, 10)}...${ind.slice(-6)}` : ind;
            return (
              <button
                key={ind}
                type="button"
                onClick={() => setFocus(isSelected ? null : ind)}
                className={`rounded-md px-2.5 py-1 font-mono text-xs transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  isSelected
                    ? 'bg-red-600 text-white'
                    : 'text-slate-700 dark:text-slate-300 hover:bg-slate-200/70 dark:hover:bg-slate-700/60'
                }`}
                title={ind}
              >
                {shortInd}
              </button>
            );
          })}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_280px]">
        <div className="relative bg-slate-50/70 dark:bg-slate-950/60 p-3 md:p-4">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-600 dark:text-slate-400">
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
              {(Object.keys(NODE_TYPE_META) as IocNodeType[]).map((typeKey) => {
                const meta = NODE_TYPE_META[typeKey];
                return (
                  <span key={typeKey} className="inline-flex items-center gap-1.5">
                    <span className={`inline-block h-2.5 w-2.5 rounded-sm ${meta.legendDot}`} aria-hidden="true" />
                    <span>{meta.label}</span>
                  </span>
                );
              })}
            </div>
            <span className="text-slate-500 dark:text-slate-400">Drag nodes · Scroll to zoom · Click to inspect</span>
          </div>

          {graph.nodes.length > 0 ? (
            <svg
              ref={svgRef}
              viewBox="0 0 760 430"
              role="img"
              aria-label={`IOC relationship network graph with ${graph.nodes.length} nodes and ${graph.links.length} links`}
              className="h-[340px] w-full rounded-lg border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-950 select-none sm:h-[420px]"
            />
          ) : (
            <div className="flex h-[320px] items-center justify-center rounded-lg border border-dashed border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
              No entity relationships extracted for the active filter.
            </div>
          )}
        </div>

        <aside
          aria-label="Selected entity inspector"
          className="border-t border-slate-200 dark:border-slate-800 lg:border-t-0 lg:border-l p-4 md:p-5 space-y-4"
        >
          {selectedNode ? (
            <>
              <div className="space-y-1.5">
                <div className="flex items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
                  <span className="font-medium">{NODE_TYPE_META[selectedNode.type].label}</span>
                  <span>
                    {selectedNode.verdict} · {selectedNode.connectionCount} link{selectedNode.connectionCount === 1 ? '' : 's'}
                  </span>
                </div>
                <p className="font-mono text-xs font-semibold text-slate-950 dark:text-slate-50 break-all">
                  {selectedNode.label}
                </p>
                {selectedNode.subLabel && (
                  <p className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                    Filename: {selectedNode.subLabel}
                  </p>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => handleCopyNodeValue(selectedNode)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {copiedId === selectedNode.id ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
                      Copied
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                      Copy Value
                    </>
                  )}
                </button>

                {selectedNode.queried && fullGraph.queriedIndicators.length > 1 && (
                  <button
                    type="button"
                    onClick={() =>
                      setFocus(
                        activeFocus?.toLowerCase() === selectedNode.label.toLowerCase()
                          ? null
                          : selectedNode.label,
                      )
                    }
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    {activeFocus?.toLowerCase() === selectedNode.label.toLowerCase() ? (
                      <>
                        <Maximize2 className="h-3.5 w-3.5" aria-hidden="true" />
                        Show All
                      </>
                    ) : (
                      <>
                        <Focus className="h-3.5 w-3.5" aria-hidden="true" />
                        Focus IOC
                      </>
                    )}
                  </button>
                )}
              </div>

              {selectedNode.sources.length > 0 && (
                <div className="border-t border-slate-100 dark:border-slate-800 pt-3">
                  <p className="text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                    Observed by
                  </p>
                  <p className="mt-1 text-xs text-slate-700 dark:text-slate-300">
                    {selectedNode.sources.join(' · ')}
                  </p>
                </div>
              )}

              <div className="border-t border-slate-100 dark:border-slate-800 pt-3">
                <p className="text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                  Connected Entities ({selectedNodeLinks.length})
                </p>
                {selectedNodeLinks.length > 0 ? (
                  <ul className="mt-2 max-h-48 space-y-2 overflow-y-auto pr-1 text-xs">
                    {selectedNodeLinks.map(({ link, isOutgoing, peer }) => (
                      <li key={link.id}>
                        <button
                          type="button"
                          onClick={() => peer && setSelectedNodeId(peer.id)}
                          className="w-full rounded-lg border border-slate-200/80 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/50 px-2.5 py-1.5 text-left hover:border-slate-300 dark:hover:border-slate-700 cursor-pointer"
                        >
                          <span className="block text-[10px] text-slate-500 dark:text-slate-400">
                            {isOutgoing ? link.label : `← ${link.label}`} · {peer ? NODE_TYPE_META[peer.type].short : ''}
                          </span>
                          <span className="mt-0.5 block font-mono text-[11px] font-medium text-slate-800 dark:text-slate-200 break-all">
                            {peer?.subLabel ? `${peer.subLabel} (${peer.label.slice(0, 10)}...)` : peer?.label}
                          </span>
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
                    Isolated indicator — no external entities linked.
                  </p>
                )}
              </div>
            </>
          ) : (
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Select any node in the graph to inspect connected IPs, domains, files, and threat infrastructure.
            </p>
          )}
        </aside>
      </div>
    </div>
  );
}
