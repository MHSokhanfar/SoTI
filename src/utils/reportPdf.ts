import type { LookupResult } from './indicators';
import { csvRowsToLookupResults } from './heatmapAnalytics';
import { maskIndicatorValue, maskSensitiveText } from './privacyMode';
import type {
  HistoricalTotals,
  IndicatorConfidence,
  ReportMeta,
  ReportsQuickStats,
  ThreatAlertTrendPoint,
  ThreatAlertTrendSummary,
  VerdictFilterOption,
} from './reportsAnalytics';
import { formatRunLabel } from './reportsAnalytics';
import { buildRiskScoreHeatmap, type RiskScoreHeatmapModel } from './riskScoreHeatmap';
import { computeAllIocConfidenceScores } from './riskScoring';

export interface PdfRunRow {
  name: string;
  runLabel: string;
  rowCount: number;
  malicious: number;
  clean: number;
  suspicious: number;
  unknown: number;
  other: number;
  selected: boolean;
}

export interface PdfIndicatorRow {
  indicator: string;
  type: string;
  source: string;
  verdictLabel: string;
  score: string;
  confidenceLabel: string;
  summary: string;
}

export interface PdfDocumentData {
  title: string;
  subtitle: string;
  generatedIso: string;
  generatedDisplay: string;
  filterSummary: string;
  selectedReportName: string | null;
  selectedReportRowSummary: string;
  quickStats: ReportsQuickStats;
  totals: HistoricalTotals;
  trendSummary: ThreatAlertTrendSummary;
  runRows: PdfRunRow[];
  indicatorRows: PdfIndicatorRow[];
}

export interface BuildPdfDataParams {
  reports: ReportMeta[];
  filteredReports: ReportMeta[];
  selectedName: string | null;
  allRowsCount: number;
  filteredRows: Record<string, string>[];
  confidenceMap: Map<string, IndicatorConfidence>;
  searchQuery: string;
  verdictFilter: VerdictFilterOption;
  quickStats: ReportsQuickStats;
  totals: HistoricalTotals;
  trendSummary: ThreatAlertTrendSummary;
  generatedAt?: Date;
}

export function sanitizePdfCell(value: unknown, maxLen = 220): string {
  const normalized = String(value ?? '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim();
  if (!normalized) return '—';
  if (normalized.length <= maxLen) return normalized;
  return `${normalized.slice(0, Math.max(1, maxLen - 1)).trimEnd()}…`;
}

export function buildPdfReportFilename(
  selectedName?: string | null,
  date: Date = new Date(),
): string {
  const stamp = date.toISOString().slice(0, 10);
  const rawStem = (selectedName || '')
    .trim()
    .replace(/\.csv$/i, '')
    .replace(/[^a-zA-Z0-9_-]+/g, '_')
    .replace(/^_+|_+$/g, '');

  if (rawStem) {
    return `${rawStem}_report_${stamp}.pdf`;
  }
  return `soti_threat_report_${stamp}.pdf`;
}

export function buildPdfDocumentData({
  reports,
  filteredReports,
  selectedName,
  allRowsCount,
  filteredRows,
  confidenceMap,
  searchQuery,
  verdictFilter,
  quickStats,
  totals,
  trendSummary,
  generatedAt = new Date(),
}: BuildPdfDataParams): PdfDocumentData {
  const generatedIso = generatedAt.toISOString();
  const generatedDisplay = `${generatedIso.slice(0, 10)} ${generatedIso.slice(11, 16)} UTC`;

  const activeFilters: string[] = [];
  if (verdictFilter !== 'All') {
    activeFilters.push(`Verdict: ${verdictFilter}`);
  }
  if (searchQuery.trim()) {
    activeFilters.push(`Query: "${searchQuery.trim()}"`);
  }

  const filterSummary =
    activeFilters.length > 0
      ? `Filtered (${activeFilters.join(' · ')}) — ${filteredReports.length} of ${reports.length} runs`
      : `All Historical Data (${reports.length} run${reports.length === 1 ? '' : 's'})`;

  const runRows: PdfRunRow[] = (filteredReports.length > 0 ? filteredReports : reports).map((rep) => {
    const v = rep.verdicts || { malicious: 0, clean: 0, suspicious: 0, unknown: 0, other: 0 };
    return {
      name: rep.name,
      runLabel: formatRunLabel(rep.name, rep.modifiedAt),
      rowCount: rep.rowCount || 0,
      malicious: v.malicious || 0,
      clean: v.clean || 0,
      suspicious: v.suspicious || 0,
      unknown: v.unknown || 0,
      other: v.other || 0,
      selected: rep.name === selectedName,
    };
  });

  const indicatorRows: PdfIndicatorRow[] = filteredRows.map((row) => {
    const indicatorKey = (row.indicator || '').trim().toLowerCase();
    const confidence = confidenceMap.get(indicatorKey);
    const verdictLabel =
      (row.status || '').trim().toLowerCase() === 'ok'
        ? sanitizePdfCell(row.verdict || 'Unknown', 32)
        : sanitizePdfCell(row.status || 'Error', 32);

    const confidenceLabel =
      confidence && confidence.score !== null
        ? `${confidence.score}% (${confidence.sourceCount} src)`
        : '—';

    return {
      indicator: sanitizePdfCell(row.indicator, 80),
      type: sanitizePdfCell((row.type || '').toUpperCase(), 16),
      source: sanitizePdfCell(row.source, 36),
      verdictLabel,
      score: sanitizePdfCell(row.score, 28),
      confidenceLabel,
      summary: sanitizePdfCell(row.summary, 200),
    };
  });

  const selectedReportRowSummary = selectedName
    ? `${selectedName} (${filteredRows.length} of ${allRowsCount} rows shown)`
    : 'No active report selected';

  return {
    title: 'SoTI Threat Intelligence Report',
    subtitle: 'Dashboard Analytics & Historical Indicator Archive',
    generatedIso,
    generatedDisplay,
    filterSummary,
    selectedReportName: selectedName,
    selectedReportRowSummary,
    quickStats,
    totals,
    trendSummary,
    runRows,
    indicatorRows,
  };
}

export interface CapturedChartImage {
  dataUrl: string;
  width: number;
  height: number;
}

const DARK_COLOR_MAP: Record<string, string> = {
  '#1e293b': '#e2e8f0',
  'rgb(30, 41, 59)': '#e2e8f0',
  '#334155': '#cbd5e1',
  'rgb(51, 65, 85)': '#cbd5e1',
  '#94a3b8': '#475569',
  'rgb(148, 163, 184)': '#475569',
  '#cbd5e1': '#475569',
  'rgb(203, 213, 225)': '#475569',
  '#f1f5f9': '#0f172a',
  'rgb(241, 245, 249)': '#0f172a',
  '#0f172a': '#ffffff',
  'rgb(15, 23, 42)': '#ffffff',
};

export function mapDarkSvgColorToPdfLight(color: string | null | undefined): string | null {
  if (!color) return null;
  const normalized = color.trim().toLowerCase();
  return DARK_COLOR_MAP[normalized] ?? null;
}

function normalizeSvgColorsForLightPdf(root: SVGSVGElement): void {
  const nodes = [root, ...Array.from(root.querySelectorAll<SVGElement>('*'))];
  for (const el of nodes) {
    const stroke = el.getAttribute('stroke');
    const mappedStroke = mapDarkSvgColorToPdfLight(stroke);
    if (mappedStroke) {
      el.setAttribute('stroke', mappedStroke);
    }

    const fill = el.getAttribute('fill');
    const mappedFill = mapDarkSvgColorToPdfLight(fill);
    if (mappedFill) {
      el.setAttribute('fill', mappedFill);
    }

    if (el.style) {
      const styleStroke = mapDarkSvgColorToPdfLight(el.style.stroke);
      if (styleStroke) el.style.stroke = styleStroke;
      const styleFill = mapDarkSvgColorToPdfLight(el.style.fill);
      if (styleFill) el.style.fill = styleFill;
      const styleColor = mapDarkSvgColorToPdfLight(el.style.color);
      if (styleColor) el.style.color = styleColor;
    }
  }
}

async function captureSvgChartPng(containerSelector: string): Promise<CapturedChartImage | null> {
  if (typeof document === 'undefined') return null;
  const container = document.querySelector(containerSelector);
  const svg = container?.tagName?.toLowerCase() === 'svg'
    ? (container as SVGSVGElement)
    : container?.querySelector('svg');
  if (!svg) return null;

  const rect = svg.getBoundingClientRect();
  const width = Math.max(Math.round(rect.width), Number(svg.getAttribute('width')) || 520);
  const height = Math.max(Math.round(rect.height), Number(svg.getAttribute('height')) || 220);
  if (width <= 0 || height <= 0) return null;

  const cloned = svg.cloneNode(true) as SVGSVGElement;
  cloned.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  cloned.setAttribute('width', String(width));
  cloned.setAttribute('height', String(height));
  cloned.style.fontFamily = 'sans-serif';
  cloned.style.backgroundColor = '#ffffff';
  normalizeSvgColorsForLightPdf(cloned);

  const serialized = new XMLSerializer().serializeToString(cloned);
  const dataUri = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(serialized)}`;

  return await new Promise<CapturedChartImage | null>((resolve) => {
    const img = new Image();
    const timer = window.setTimeout(() => resolve(null), 1500);

    img.onload = () => {
      window.clearTimeout(timer);
      try {
        const scale = 2;
        const canvas = document.createElement('canvas');
        canvas.width = width * scale;
        canvas.height = height * scale;
        const ctx = canvas.getContext('2d');
        if (!ctx) {
          resolve(null);
          return;
        }
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.scale(scale, scale);
        ctx.drawImage(img, 0, 0, width, height);
        resolve({ dataUrl: canvas.toDataURL('image/png'), width, height });
      } catch {
        resolve(null);
      }
    };

    img.onerror = () => {
      window.clearTimeout(timer);
      resolve(null);
    };

    img.src = dataUri;
  });
}

function getVerdictRgb(verdict: string): [number, number, number] {
  const v = verdict.trim().toLowerCase();
  if (v === 'malicious') return [185, 28, 28]; // #B91C1C
  if (v === 'clean') return [21, 128, 61]; // #15803D
  if (v === 'suspicious') return [180, 83, 9]; // #B45309
  return [71, 85, 105]; // #475569
}

export async function exportReportsDashboardPdf(
  params: BuildPdfDataParams,
  options: {
    verdictChartSelector?: string;
    trendChartSelector?: string;
  } = {},
): Promise<{ filename: string; pageCount: number }> {
  const data = buildPdfDocumentData(params);
  const filename = buildPdfReportFilename(params.selectedName, params.generatedAt);

  const [verdictImg, trendImg, jspdfModule] = await Promise.all([
    captureSvgChartPng(options.verdictChartSelector || '[data-testid="verdict-history-chart"]'),
    captureSvgChartPng(options.trendChartSelector || '[data-testid="threat-alert-trend-chart"]'),
    import('jspdf'),
  ]);

  const { jsPDF } = jspdfModule;
  const doc = new jsPDF({
    orientation: 'landscape',
    unit: 'mm',
    format: 'a4',
    compress: true,
  });

  const pageWidth = doc.internal.pageSize.getWidth(); // 297mm
  const pageHeight = doc.internal.pageSize.getHeight(); // 210mm
  const marginX = 14;
  const contentWidth = pageWidth - marginX * 2; // 269mm
  const bottomLimit = pageHeight - 14;

  function drawHeaderBar(yStart = 10): number {
    // Crimson top rule
    doc.setFillColor(220, 38, 38);
    doc.rect(0, 0, pageWidth, 2.5, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(15);
    doc.setTextColor(15, 23, 42);
    doc.text(data.title, marginX, yStart + 3);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(100, 116, 139);
    doc.text(data.subtitle, marginX, yStart + 8);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    doc.text(`Generated: ${data.generatedDisplay}`, pageWidth - marginX, yStart + 2.5, { align: 'right' });
    doc.text(data.filterSummary, pageWidth - marginX, yStart + 7.5, { align: 'right' });

    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.3);
    doc.line(marginX, yStart + 11.5, pageWidth - marginX, yStart + 11.5);
    return yStart + 16;
  }

  let y = drawHeaderBar(10);

  // Section 1: Quick Stats Strip (3 columns)
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(15, 23, 42);
  doc.text('Quick Stats Overview', marginX, y);
  y += 3;

  const statsBoxHeight = 20;
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(marginX, y, contentWidth, statsBoxHeight, 2, 2, 'FD');

  const colW = contentWidth / 3;
  doc.line(marginX + colW, y + 3, marginX + colW, y + statsBoxHeight - 3);
  doc.line(marginX + colW * 2, y + 3, marginX + colW * 2, y + statsBoxHeight - 3);

  const statCols = [
    {
      label: 'Total Threats Analyzed',
      value: String(data.quickStats.totalThreatsAnalyzed),
      detail: `${data.quickStats.uniqueIndicatorsCount} unique IOCs · ${data.quickStats.totalRuns} report${data.quickStats.totalRuns === 1 ? '' : 's'}`,
      valueColor: [15, 23, 42] as [number, number, number],
    },
    {
      label: 'Malicious Findings',
      value: `${data.quickStats.maliciousPercentage}%`,
      detail: `${data.quickStats.maliciousCount} malicious of ${data.quickStats.evaluatedVerdictsCount} verdicts`,
      valueColor: [185, 28, 28] as [number, number, number],
    },
    {
      label: 'Top Queried Indicator Type',
      value: data.quickStats.topIndicatorType
        ? `${data.quickStats.topIndicatorLabel} (${data.quickStats.topIndicatorShare}%)`
        : data.quickStats.topIndicatorLabel,
      detail: `${data.quickStats.typeCounts.ip} IP · ${data.quickStats.typeCounts.domain} Domain · ${data.quickStats.typeCounts.hash} Hash`,
      valueColor: [15, 23, 42] as [number, number, number],
    },
  ];

  statCols.forEach((col, i) => {
    const x = marginX + i * colW + 4;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text(col.label, x, y + 5.5);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(...col.valueColor);
    doc.text(col.value, x, y + 12.2);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text(col.detail, x, y + 17);
  });

  y += statsBoxHeight + 7;

  // Section 2: Dashboard Analytics Widgets (2 columns)
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(15, 23, 42);
  doc.text('Dashboard Analytics Widgets', marginX, y);
  y += 3;

  const widgetGap = 6;
  const widgetW = (contentWidth - widgetGap) / 2; // ~131.5mm
  const widgetH = 66;

  // Left Widget: Verdict Distribution Across Runs
  doc.setFillColor(255, 255, 255);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(marginX, y, widgetW, widgetH, 2, 2, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(15, 23, 42);
  doc.text('Verdict Distribution Across Runs', marginX + 4, y + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(71, 85, 105);
  doc.text(
    `Runs: ${data.totals.runs}  |  Malicious: ${data.totals.malicious}  |  Clean: ${data.totals.clean}  |  Other/Susp: ${data.totals.suspicious + data.totals.unknown}`,
    marginX + 4,
    y + 11,
  );

  if (verdictImg) {
    const maxImgW = widgetW - 8;
    const maxImgH = widgetH - 16;
    const ratio = Math.min(maxImgW / verdictImg.width, maxImgH / verdictImg.height);
    const drawW = verdictImg.width * ratio;
    const drawH = verdictImg.height * ratio;
    doc.addImage(verdictImg.dataUrl, 'PNG', marginX + 4, y + 13.5, drawW, drawH);
  } else {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text(
      `Malicious: ${data.totals.malicious} · Clean: ${data.totals.clean} · Suspicious: ${data.totals.suspicious} · Unknown: ${data.totals.unknown}`,
      marginX + 4,
      y + 24,
    );
  }

  // Right Widget: Threat Alerts (Last 30 Days)
  const rightX = marginX + widgetW + widgetGap;
  doc.setFillColor(255, 255, 255);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(rightX, y, widgetW, widgetH, 2, 2, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(15, 23, 42);
  doc.text('Threat Alerts (Last 30 Days)', rightX + 4, y + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(71, 85, 105);
  const peakText =
    data.trendSummary.peakAlerts > 0
      ? `${data.trendSummary.peakAlerts} (${data.trendSummary.peakDateLabel})`
      : String(data.trendSummary.peakAlerts);
  doc.text(
    `30-Day Alerts: ${data.trendSummary.totalAlerts}  |  Peak Day: ${peakText}  |  Alert Days: ${data.trendSummary.activeAlertDays}/30`,
    rightX + 4,
    y + 11,
  );

  if (trendImg) {
    const maxImgW = widgetW - 8;
    const maxImgH = widgetH - 16;
    const ratio = Math.min(maxImgW / trendImg.width, maxImgH / trendImg.height);
    const drawW = trendImg.width * ratio;
    const drawH = trendImg.height * ratio;
    doc.addImage(trendImg.dataUrl, 'PNG', rightX + 4, y + 13.5, drawW, drawH);
  } else {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text(
      `Total Alerts: ${data.trendSummary.totalAlerts} · Active Days: ${data.trendSummary.activeAlertDays}/30`,
      rightX + 4,
      y + 24,
    );
  }

  y += widgetH + 8;

  // Section 3: Historical Runs Archive Summary
  function ensureSpace(neededHeight: number, repeatHeaderFn?: () => void) {
    if (y + neededHeight > bottomLimit) {
      doc.addPage();
      y = 14;
      repeatHeaderFn?.();
    }
  }

  function drawRunsTableHeader() {
    doc.setFillColor(241, 245, 249);
    doc.rect(marginX, y, contentWidth, 6.5, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(51, 65, 85);
    doc.text('Report File', marginX + 3, y + 4.4);
    doc.text('Run Time', marginX + 92, y + 4.4);
    doc.text('Rows', marginX + 146, y + 4.4, { align: 'right' });
    doc.text('Malicious', marginX + 174, y + 4.4, { align: 'right' });
    doc.text('Clean', marginX + 200, y + 4.4, { align: 'right' });
    doc.text('Suspicious', marginX + 230, y + 4.4, { align: 'right' });
    doc.text('Unknown', marginX + 263, y + 4.4, { align: 'right' });
    y += 6.5;
  }

  if (data.runRows.length > 0) {
    ensureSpace(18);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(15, 23, 42);
    doc.text(`Historical Runs Summary (${data.runRows.length})`, marginX, y);
    y += 3;
    drawRunsTableHeader();

    data.runRows.forEach((run, idx) => {
      ensureSpace(6.5, drawRunsTableHeader);
      if (run.selected) {
        doc.setFillColor(254, 242, 242);
        doc.rect(marginX, y, contentWidth, 6, 'F');
      } else if (idx % 2 === 1) {
        doc.setFillColor(248, 250, 252);
        doc.rect(marginX, y, contentWidth, 6, 'F');
      }

      doc.setFont('courier', run.selected ? 'bold' : 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(15, 23, 42);
      doc.text(sanitizePdfCell(run.name, 48), marginX + 3, y + 4.2);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text(run.runLabel, marginX + 92, y + 4.2);

      doc.setFont('courier', 'normal');
      doc.setTextColor(15, 23, 42);
      doc.text(String(run.rowCount), marginX + 146, y + 4.2, { align: 'right' });

      doc.setTextColor(185, 28, 28);
      doc.text(String(run.malicious), marginX + 174, y + 4.2, { align: 'right' });

      doc.setTextColor(21, 128, 61);
      doc.text(String(run.clean), marginX + 200, y + 4.2, { align: 'right' });

      doc.setTextColor(180, 83, 9);
      doc.text(String(run.suspicious), marginX + 230, y + 4.2, { align: 'right' });

      doc.setTextColor(71, 85, 105);
      doc.text(String(run.unknown), marginX + 263, y + 4.2, { align: 'right' });

      doc.setDrawColor(241, 245, 249);
      doc.line(marginX, y + 6, pageWidth - marginX, y + 6);
      y += 6;
    });

    y += 7;
  }

  // Section 4: Active Historical Data Table
  function drawIndicatorTableHeader() {
    doc.setFillColor(15, 23, 42);
    doc.rect(marginX, y, contentWidth, 7, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(255, 255, 255);
    doc.text('Indicator', marginX + 3, y + 4.7);
    doc.text('Type', marginX + 60, y + 4.7);
    doc.text('Source', marginX + 76, y + 4.7);
    doc.text('Verdict', marginX + 112, y + 4.7);
    doc.text('Score', marginX + 150, y + 4.7, { align: 'right' });
    doc.text('Confidence', marginX + 178, y + 4.7, { align: 'right' });
    doc.text('Summary', marginX + 183, y + 4.7);
    y += 7;
  }

  ensureSpace(22);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(15, 23, 42);
  doc.text(`Historical Indicator Data — ${data.selectedReportRowSummary}`, marginX, y);
  y += 3;

  if (data.indicatorRows.length === 0) {
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(marginX, y, contentWidth, 12, 1.5, 1.5, 'FD');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text('No matching indicator rows in the current filter scope.', marginX + 4, y + 7.5);
    y += 14;
  } else {
    drawIndicatorTableHeader();

    data.indicatorRows.forEach((row, idx) => {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      const summaryLines = doc.splitTextToSize(row.summary, 83) as string[];
      const indicatorLines = doc.splitTextToSize(row.indicator, 54) as string[];
      const lineCount = Math.max(1, summaryLines.length, indicatorLines.length);
      const rowHeight = Math.max(6.2, lineCount * 3.6 + 2.6);

      ensureSpace(rowHeight, drawIndicatorTableHeader);

      if (idx % 2 === 1) {
        doc.setFillColor(248, 250, 252);
        doc.rect(marginX, y, contentWidth, rowHeight, 'F');
      }

      doc.setFont('courier', 'bold');
      doc.setFontSize(7.3);
      doc.setTextColor(15, 23, 42);
      doc.text(indicatorLines, marginX + 3, y + 4.1);

      doc.setFont('courier', 'normal');
      doc.setTextColor(100, 116, 139);
      doc.text(row.type, marginX + 60, y + 4.1);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(30, 41, 59);
      doc.text(sanitizePdfCell(row.source, 24), marginX + 76, y + 4.1);

      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...getVerdictRgb(row.verdictLabel));
      doc.text(row.verdictLabel, marginX + 112, y + 4.1);

      doc.setFont('courier', 'normal');
      doc.setTextColor(15, 23, 42);
      doc.text(row.score, marginX + 150, y + 4.1, { align: 'right' });

      doc.text(row.confidenceLabel, marginX + 178, y + 4.1, { align: 'right' });

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text(summaryLines, marginX + 183, y + 4.1);

      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.2);
      doc.line(marginX, y + rowHeight, pageWidth - marginX, y + rowHeight);
      y += rowHeight;
    });
  }

  // Stamp consistent print footers across all pages
  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p += 1) {
    doc.setPage(p);
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.25);
    doc.line(marginX, pageHeight - 10, pageWidth - marginX, pageHeight - 10);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text(
      'SoTI Threat Intelligence Platform · Automated Threat Enrichment Archive',
      marginX,
      pageHeight - 5.5,
    );
    doc.text(`Page ${p} of ${totalPages}`, pageWidth - marginX, pageHeight - 5.5, { align: 'right' });
  }

  doc.save(filename);
  return { filename, pageCount: totalPages };
}

export interface TopMaliciousIndicatorEntry {
  rank: number;
  indicator: string;
  type: string;
  confidenceScore: number;
  riskLevel: string;
  verdictLabel: string;
  sources: string[];
  hitCount: number;
  summary: string;
}

export interface DashboardSummaryPdfData {
  title: string;
  subtitle: string;
  generatedIso: string;
  generatedDisplay: string;
  scopeSummary: string;
  quickStats: ReportsQuickStats;
  totals: HistoricalTotals;
  trendSummary: ThreatAlertTrendSummary;
  recentTrendPoints: ThreatAlertTrendPoint[];
  heatmapModel: RiskScoreHeatmapModel;
  typeHeatmapModel: RiskScoreHeatmapModel;
  topMaliciousIndicators: TopMaliciousIndicatorEntry[];
  aiSummaryExcerpt: string | null;
}

export interface BuildDashboardSummaryPdfParams {
  reports: ReportMeta[];
  allRunRows: Record<string, string>[];
  selectedRows?: Record<string, string>[];
  currentResults?: LookupResult[];
  quickStats: ReportsQuickStats;
  totals: HistoricalTotals;
  trendSeries: ThreatAlertTrendPoint[];
  trendSummary: ThreatAlertTrendSummary;
  aiSummary?: string | null;
  privacyMode?: boolean;
  generatedAt?: Date;
}

export function buildSummaryPdfFilename(date: Date = new Date()): string {
  const stamp = date.toISOString().slice(0, 10);
  return `soti_risk_summary_${stamp}.pdf`;
}

export function extractTopMaliciousIndicators(params: {
  allRunRows: Record<string, string>[];
  selectedRows?: Record<string, string>[];
  currentResults?: LookupResult[];
  maxItems?: number;
  privacyMode?: boolean;
}): TopMaliciousIndicatorEntry[] {
  const maxItems = Math.max(1, params.maxItems ?? 12);
  const privacyMode = Boolean(params.privacyMode);

  const mergedResults: LookupResult[] = [];
  const seenKeys = new Set<string>();

  const pushUnique = (item: LookupResult) => {
    const key = `${(item.source || '').toLowerCase()}|${item.indicator.trim().toLowerCase()}|${item.verdict}|${item.score}`;
    if (!item.indicator.trim() || seenKeys.has(key)) return;
    seenKeys.add(key);
    mergedResults.push(item);
  };

  for (const r of csvRowsToLookupResults(params.allRunRows || [])) {
    pushUnique(r);
  }
  for (const r of csvRowsToLookupResults(params.selectedRows || [])) {
    pushUnique(r);
  }
  for (const r of params.currentResults || []) {
    pushUnique(r);
  }

  if (mergedResults.length === 0) return [];

  const confidenceByIndicator = computeAllIocConfidenceScores(mergedResults);
  const byIndicator = new Map<string, LookupResult[]>();

  for (const r of mergedResults) {
    const key = r.indicator.trim().toLowerCase();
    if (!key) continue;
    const list = byIndicator.get(key);
    if (list) list.push(r);
    else byIndicator.set(key, [r]);
  }

  const candidates: Array<TopMaliciousIndicatorEntry & { isMalicious: number; isSuspicious: number }> = [];

  for (const [key, group] of byIndicator.entries()) {
    const conf = confidenceByIndicator.get(key);
    const maliciousHits = group.filter(
      (g) => g.status === 'ok' && g.verdict.trim().toLowerCase() === 'malicious',
    ).length;
    const suspiciousHits = group.filter(
      (g) => g.status === 'ok' && g.verdict.trim().toLowerCase() === 'suspicious',
    ).length;
    const score = conf?.confidenceScore ?? 0;

    if (maliciousHits === 0 && suspiciousHits === 0 && score < 25) {
      continue;
    }

    const first = group[0];
    const verdictLabel =
      maliciousHits > 0
        ? 'Malicious'
        : suspiciousHits > 0
          ? 'Suspicious'
          : conf?.riskLevel || 'Elevated';

    const rankedGroup = [...group].sort((a, b) => {
      const aMal = a.verdict === 'Malicious' ? 2 : a.verdict === 'Suspicious' ? 1 : 0;
      const bMal = b.verdict === 'Malicious' ? 2 : b.verdict === 'Suspicious' ? 1 : 0;
      return bMal - aMal;
    });

    const rawSummary = rankedGroup.find((g) => g.summary && g.summary.trim())?.summary || 'Threat finding recorded';
    const sources = Array.from(new Set(group.map((g) => g.source).filter(Boolean)));

    candidates.push({
      rank: 0,
      indicator: maskIndicatorValue(first.indicator, first.type, privacyMode),
      type: (first.type || 'ioc').toUpperCase(),
      confidenceScore: score,
      riskLevel: conf?.riskLevel || 'Unknown',
      verdictLabel,
      sources,
      hitCount: maliciousHits > 0 ? maliciousHits : suspiciousHits || group.length,
      summary: sanitizePdfCell(maskSensitiveText(rawSummary, privacyMode), 160),
      isMalicious: maliciousHits > 0 ? 1 : 0,
      isSuspicious: suspiciousHits > 0 ? 1 : 0,
    });
  }

  candidates.sort(
    (a, b) =>
      b.isMalicious - a.isMalicious ||
      b.confidenceScore - a.confidenceScore ||
      b.isSuspicious - a.isSuspicious ||
      b.hitCount - a.hitCount ||
      a.indicator.localeCompare(b.indicator),
  );

  return candidates.slice(0, maxItems).map((item, idx) => ({
    rank: idx + 1,
    indicator: item.indicator,
    type: item.type,
    confidenceScore: item.confidenceScore,
    riskLevel: item.riskLevel,
    verdictLabel: item.verdictLabel,
    sources: item.sources,
    hitCount: item.hitCount,
    summary: item.summary,
  }));
}

export function buildDashboardSummaryPdfData({
  reports,
  allRunRows,
  selectedRows = [],
  currentResults = [],
  quickStats,
  totals,
  trendSeries,
  trendSummary,
  aiSummary = null,
  privacyMode = false,
  generatedAt = new Date(),
}: BuildDashboardSummaryPdfParams): DashboardSummaryPdfData {
  const generatedIso = generatedAt.toISOString();
  const generatedDisplay = `${generatedIso.slice(0, 10)} ${generatedIso.slice(11, 16)} UTC`;

  const heatmapModel = buildRiskScoreHeatmap({
    reports,
    allRunRows,
    currentResults,
    mode: 'investigations',
    maxRuns: 10,
  });

  const typeHeatmapModel = buildRiskScoreHeatmap({
    reports,
    allRunRows,
    currentResults,
    mode: 'indicator_type',
  });

  const topMaliciousIndicators = extractTopMaliciousIndicators({
    allRunRows,
    selectedRows,
    currentResults,
    maxItems: 12,
    privacyMode,
  });

  const activeDays = trendSeries.filter((p) => p.threatAlerts > 0);
  const recentTrendPoints = (activeDays.length > 0 ? activeDays.slice(-8) : trendSeries.slice(-6)).reverse();

  const scopeSummary =
    reports.length > 0
      ? `Consolidated across ${reports.length} archived run${reports.length === 1 ? '' : 's'} · ${heatmapModel.uniqueEvaluatedIndicators} scored IOCs${privacyMode ? ' · Privacy Mode Redacted' : ''}`
      : `Active Session Summary · ${heatmapModel.uniqueEvaluatedIndicators} scored IOCs${privacyMode ? ' · Privacy Mode Redacted' : ''}`;

  const aiSummaryExcerpt =
    aiSummary && aiSummary.trim()
      ? sanitizePdfCell(maskSensitiveText(aiSummary.replace(/[#*`]/g, ''), privacyMode), 520)
      : null;

  return {
    title: 'SoTI Consolidated Risk & Threat Summary',
    subtitle: 'Executive Posture Brief · Risk Trendline, Heatmap Distribution & Top Malicious Indicators',
    generatedIso,
    generatedDisplay,
    scopeSummary,
    quickStats,
    totals,
    trendSummary,
    recentTrendPoints,
    heatmapModel,
    typeHeatmapModel,
    topMaliciousIndicators,
    aiSummaryExcerpt,
  };
}

export async function exportDashboardSummaryPdf(
  params: BuildDashboardSummaryPdfParams,
  options: {
    trendChartSelector?: string;
    heatmapSelector?: string;
  } = {},
): Promise<{ filename: string; pageCount: number }> {
  const data = buildDashboardSummaryPdfData(params);
  const filename = buildSummaryPdfFilename(params.generatedAt);

  const [trendImg, heatmapImg, jspdfModule] = await Promise.all([
    captureSvgChartPng(options.trendChartSelector || '[data-testid="threat-alert-trend-chart"]'),
    captureSvgChartPng(options.heatmapSelector || '[data-testid="risk-score-heatmap-svg"]'),
    import('jspdf'),
  ]);

  const { jsPDF } = jspdfModule;
  const doc = new jsPDF({
    orientation: 'landscape',
    unit: 'mm',
    format: 'a4',
    compress: true,
  });

  const pageWidth = doc.internal.pageSize.getWidth(); // 297mm
  const pageHeight = doc.internal.pageSize.getHeight(); // 210mm
  const marginX = 14;
  const contentWidth = pageWidth - marginX * 2; // 269mm
  const bottomLimit = pageHeight - 14;

  // Header band
  doc.setFillColor(220, 38, 38);
  doc.rect(0, 0, pageWidth, 2.5, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15);
  doc.setTextColor(15, 23, 42);
  doc.text(data.title, marginX, 13);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(100, 116, 139);
  doc.text(data.subtitle, marginX, 18);

  doc.setFontSize(8);
  doc.setTextColor(71, 85, 105);
  doc.text(`Generated: ${data.generatedDisplay}`, pageWidth - marginX, 12.5, { align: 'right' });
  doc.text(data.scopeSummary, pageWidth - marginX, 17.5, { align: 'right' });

  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.3);
  doc.line(marginX, 21.5, pageWidth - marginX, 21.5);

  let y = 26;

  // Section 1: Security Posture & KPIs (4 columns)
  const kpiHeight = 19;
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(marginX, y, contentWidth, kpiHeight, 2, 2, 'FD');

  const kpiW = contentWidth / 4;
  for (let i = 1; i < 4; i += 1) {
    doc.line(marginX + kpiW * i, y + 3, marginX + kpiW * i, y + kpiHeight - 3);
  }

  const postureColor: [number, number, number] =
    data.heatmapModel.postureRating === 'Critical'
      ? [185, 28, 28]
      : data.heatmapModel.postureRating === 'Elevated'
        ? [180, 83, 9]
        : data.heatmapModel.postureRating === 'Moderate'
          ? [15, 23, 42]
          : [21, 128, 61];

  const kpiCards = [
    {
      label: 'Overall Security Posture',
      value: data.heatmapModel.postureRating,
      detail: `${data.heatmapModel.bandSummary.High.criticalCount} critical (>=75) IOCs`,
      color: postureColor,
    },
    {
      label: 'Total Threats Analyzed',
      value: String(data.quickStats.totalThreatsAnalyzed),
      detail: `${data.quickStats.uniqueIndicatorsCount} unique · ${data.quickStats.totalRuns} runs`,
      color: [15, 23, 42] as [number, number, number],
    },
    {
      label: 'Malicious Findings Rate',
      value: `${data.quickStats.maliciousPercentage}%`,
      detail: `${data.quickStats.maliciousCount} malicious · ${data.totals.suspicious} susp.`,
      color: [185, 28, 28] as [number, number, number],
    },
    {
      label: '30-Day Threat Alerts',
      value: String(data.trendSummary.totalAlerts),
      detail:
        data.trendSummary.peakAlerts > 0
          ? `Peak: ${data.trendSummary.peakAlerts} on ${data.trendSummary.peakDateLabel}`
          : `${data.trendSummary.activeAlertDays}/30 alert days`,
      color: [15, 23, 42] as [number, number, number],
    },
  ];

  kpiCards.forEach((col, i) => {
    const x = marginX + i * kpiW + 3.5;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.2);
    doc.setTextColor(100, 116, 139);
    doc.text(col.label, x, y + 5.2);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(...col.color);
    doc.text(col.value, x, y + 11.6);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(100, 116, 139);
    doc.text(col.detail, x, y + 16.2);
  });

  y += kpiHeight + 6;

  // Section 2: Side-by-Side Risk Trendline & Heatmap Distribution
  const panelGap = 6;
  const panelW = (contentWidth - panelGap) / 2;
  const panelH = 74;

  // Left: 30-Day Risk Trendline
  doc.setFillColor(255, 255, 255);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(marginX, y, panelW, panelH, 2, 2, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(15, 23, 42);
  doc.text('Risk Trendline (30-Day Threat Alerts)', marginX + 4, y + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(71, 85, 105);
  doc.text(
    `Total: ${data.trendSummary.totalAlerts}  |  Malicious: ${data.trendSummary.maliciousAlerts}  |  Suspicious: ${data.trendSummary.suspiciousAlerts}  |  Active Days: ${data.trendSummary.activeAlertDays}/30`,
    marginX + 4,
    y + 11,
  );

  if (trendImg) {
    const maxW = panelW - 8;
    const maxH = panelH - 16;
    const ratio = Math.min(maxW / trendImg.width, maxH / trendImg.height);
    doc.addImage(trendImg.dataUrl, 'PNG', marginX + 4, y + 14, trendImg.width * ratio, trendImg.height * ratio);
  } else {
    let ty = y + 19;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);
    data.recentTrendPoints.slice(0, 7).forEach((pt) => {
      doc.text(
        `${pt.label} (${pt.dateKey}): ${pt.threatAlerts} alerts (${pt.malicious} mal, ${pt.suspicious} susp)`,
        marginX + 4,
        ty,
      );
      ty += 5.5;
    });
  }

  // Right: Risk Score Heatmap Distribution
  const rightX = marginX + panelW + panelGap;
  doc.setFillColor(255, 255, 255);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(rightX, y, panelW, panelH, 2, 2, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(15, 23, 42);
  doc.text('Risk Score Heatmap Distribution', rightX + 4, y + 6);

  const highBand = data.heatmapModel.bandSummary.High;
  const medBand = data.heatmapModel.bandSummary.Medium;
  const lowBand = data.heatmapModel.bandSummary.Low;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(71, 85, 105);
  doc.text(
    `High (50+): ${highBand.count} (${highBand.percentage}%)  |  Medium (25-49): ${medBand.count} (${medBand.percentage}%)  |  Low (0-24): ${lowBand.count} (${lowBand.percentage}%)`,
    rightX + 4,
    y + 11,
  );

  if (heatmapImg) {
    const maxW = panelW - 8;
    const maxH = panelH - 16;
    const ratio = Math.min(maxW / heatmapImg.width, maxH / heatmapImg.height);
    doc.addImage(heatmapImg.dataUrl, 'PNG', rightX + 4, y + 14, heatmapImg.width * ratio, heatmapImg.height * ratio);
  } else {
    let hy = y + 19;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    data.typeHeatmapModel.columns.forEach((col) => {
      doc.setTextColor(15, 23, 42);
      doc.text(
        `${col.label}: ${col.highCount} High · ${col.mediumCount} Med · ${col.lowCount} Low (Avg ${col.avgScore ?? 'N/A'})`,
        rightX + 4,
        hy,
      );
      hy += 6;
    });
  }

  y += panelH + 6;

  // Heatmap Distribution by Indicator Type Strip
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(15, 23, 42);
  doc.text('Heatmap Distribution by Indicator Type', marginX, y);
  y += 3;

  doc.setFillColor(241, 245, 249);
  doc.rect(marginX, y, contentWidth, 6.2, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.3);
  doc.setTextColor(51, 65, 85);
  doc.text('Indicator Category', marginX + 3, y + 4.3);
  doc.text('Total Scored', marginX + 95, y + 4.3, { align: 'right' });
  doc.text('High (50-100)', marginX + 135, y + 4.3, { align: 'right' });
  doc.text('Medium (25-49)', marginX + 178, y + 4.3, { align: 'right' });
  doc.text('Low (0-24)', marginX + 216, y + 4.3, { align: 'right' });
  doc.text('Avg Confidence', marginX + 263, y + 4.3, { align: 'right' });
  y += 6.2;

  data.typeHeatmapModel.columns.forEach((col, idx) => {
    if (idx % 2 === 1) {
      doc.setFillColor(248, 250, 252);
      doc.rect(marginX, y, contentWidth, 5.8, 'F');
    }
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(15, 23, 42);
    doc.text(col.label, marginX + 3, y + 4);

    doc.setFont('courier', 'normal');
    doc.text(String(col.totalEvaluated), marginX + 95, y + 4, { align: 'right' });
    doc.setTextColor(185, 28, 28);
    doc.text(String(col.highCount), marginX + 135, y + 4, { align: 'right' });
    doc.setTextColor(180, 83, 9);
    doc.text(String(col.mediumCount), marginX + 178, y + 4, { align: 'right' });
    doc.setTextColor(21, 128, 61);
    doc.text(String(col.lowCount), marginX + 216, y + 4, { align: 'right' });
    doc.setTextColor(15, 23, 42);
    doc.text(col.avgScore !== null ? `${col.avgScore}/100` : '—', marginX + 263, y + 4, { align: 'right' });

    doc.setDrawColor(241, 245, 249);
    doc.line(marginX, y + 5.8, pageWidth - marginX, y + 5.8);
    y += 5.8;
  });

  y += 7;

  function ensureSpace(neededHeight: number, repeatHeaderFn?: () => void) {
    if (y + neededHeight > bottomLimit) {
      doc.addPage();
      y = 14;
      repeatHeaderFn?.();
    }
  }

  // Optional AI Executive Summary Excerpt
  if (data.aiSummaryExcerpt) {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.8);
    const lines = doc.splitTextToSize(data.aiSummaryExcerpt, contentWidth - 8) as string[];
    const boxHeight = Math.max(14, lines.length * 3.8 + 10);
    ensureSpace(boxHeight + 6);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(marginX, y, contentWidth, boxHeight, 2, 2, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text('Executive Summary Brief', marginX + 4, y + 5.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.8);
    doc.setTextColor(51, 65, 85);
    doc.text(lines, marginX + 4, y + 10.5);
    y += boxHeight + 7;
  }

  // Section 3: Top Identified Malicious Indicators
  function drawTopMaliciousHeader() {
    doc.setFillColor(15, 23, 42);
    doc.rect(marginX, y, contentWidth, 6.8, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.4);
    doc.setTextColor(255, 255, 255);
    doc.text('#', marginX + 3, y + 4.5);
    doc.text('Indicator', marginX + 11, y + 4.5);
    doc.text('Type', marginX + 70, y + 4.5);
    doc.text('Risk Score', marginX + 102, y + 4.5, { align: 'right' });
    doc.text('Verdict', marginX + 108, y + 4.5);
    doc.text('Sources & Hits', marginX + 134, y + 4.5);
    doc.text('Primary Threat Finding', marginX + 186, y + 4.5);
    y += 6.8;
  }

  ensureSpace(22);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(15, 23, 42);
  doc.text(`Top Identified Malicious Indicators (${data.topMaliciousIndicators.length})`, marginX, y);
  y += 3;

  if (data.topMaliciousIndicators.length === 0) {
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(marginX, y, contentWidth, 12, 1.5, 1.5, 'FD');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text('No elevated or malicious indicators identified in the current historical scope.', marginX + 4, y + 7.5);
    y += 14;
  } else {
    drawTopMaliciousHeader();
    data.topMaliciousIndicators.forEach((item, idx) => {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.3);
      const summaryLines = doc.splitTextToSize(item.summary, 80) as string[];
      const indicatorLines = doc.splitTextToSize(item.indicator, 56) as string[];
      const sourcesLabel = sanitizePdfCell(`${item.sources.slice(0, 3).join(', ')} (${item.hitCount})`, 46);
      const sourcesLines = doc.splitTextToSize(sourcesLabel, 48) as string[];
      const lineCount = Math.max(1, summaryLines.length, indicatorLines.length, sourcesLines.length);
      const rowHeight = Math.max(6.2, lineCount * 3.6 + 2.6);

      ensureSpace(rowHeight, drawTopMaliciousHeader);
      if (idx % 2 === 1) {
        doc.setFillColor(248, 250, 252);
        doc.rect(marginX, y, contentWidth, rowHeight, 'F');
      }

      doc.setFont('courier', 'bold');
      doc.setFontSize(7.3);
      doc.setTextColor(100, 116, 139);
      doc.text(String(item.rank), marginX + 3, y + 4.1);

      doc.setTextColor(15, 23, 42);
      doc.text(indicatorLines, marginX + 11, y + 4.1);

      doc.setFont('courier', 'normal');
      doc.setTextColor(100, 116, 139);
      doc.text(item.type, marginX + 70, y + 4.1);

      doc.setFont('courier', 'bold');
      doc.setTextColor(...getVerdictRgb(item.verdictLabel));
      doc.text(`${item.confidenceScore}/100`, marginX + 102, y + 4.1, { align: 'right' });

      doc.setFont('helvetica', 'bold');
      doc.text(item.verdictLabel, marginX + 108, y + 4.1);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      doc.text(sourcesLines, marginX + 134, y + 4.1);

      doc.setTextColor(71, 85, 105);
      doc.text(summaryLines, marginX + 186, y + 4.1);

      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.2);
      doc.line(marginX, y + rowHeight, pageWidth - marginX, y + rowHeight);
      y += rowHeight;
    });
  }

  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p += 1) {
    doc.setPage(p);
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.25);
    doc.line(marginX, pageHeight - 10, pageWidth - marginX, pageHeight - 10);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text(
      'SoTI Threat Intelligence Platform · Consolidated Executive Risk Summary',
      marginX,
      pageHeight - 5.5,
    );
    doc.text(`Page ${p} of ${totalPages}`, pageWidth - marginX, pageHeight - 5.5, { align: 'right' });
  }

  doc.save(filename);
  return { filename, pageCount: totalPages };
}
