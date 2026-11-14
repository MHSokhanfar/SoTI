import type {
  HistoricalTotals,
  IndicatorConfidence,
  ReportMeta,
  ReportsQuickStats,
  ThreatAlertTrendSummary,
  VerdictFilterOption,
} from './reportsAnalytics';
import { formatRunLabel } from './reportsAnalytics';

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
