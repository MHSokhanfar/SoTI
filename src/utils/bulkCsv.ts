import { cleanIndicator, detectIndicatorType, type IndicatorType } from './indicators';

export type IndicatorFileFormat = 'csv' | 'txt';

export interface CsvColumnCandidate {
  index: number;
  name: string;
  validCount: number;
  sampleValues: string[];
  isPriorityHeader: boolean;
}

export interface BulkCsvImportResult {
  indicators: string[];
  rawText: string;
  totalRows: number;
  validCount: number;
  skippedCount: number;
  detectedColumns: string[];
  hasHeaderRow?: boolean;
  availableColumns?: CsvColumnCandidate[];
  designatedColumn?: string | null;
  breakdown: Record<IndicatorType, number>;
  sourceFormat?: IndicatorFileFormat;
}

const PRIORITY_HEADER_RE =
  /^(?:indicator|indicators|ioc|iocs|observable|observables|ip|ip_address|ipv4|ipv6|src_ip|dst_ip|dest_ip|domain|host|hostname|hash|sha256|sha1|md5|artifact|value|target)$/i;

export function parseCsvMatrix(csvText: string): string[][] {
  const clean = csvText.replace(/^\ufeff/, '');
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let inQuotes = false;

  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i];
    if (inQuotes) {
      if (ch === '"' && clean[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        cell += ch;
      }
      continue;
    }

    if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(cell);
      cell = '';
    } else if (ch === '\r') {
      if (clean[i + 1] === '\n') i++;
      row.push(cell);
      if (row.some((c) => c.trim().length > 0)) {
        rows.push(row);
      }
      row = [];
      cell = '';
    } else if (ch === '\n') {
      row.push(cell);
      if (row.some((c) => c.trim().length > 0)) {
        rows.push(row);
      }
      row = [];
      cell = '';
    } else {
      cell += ch;
    }
  }

  row.push(cell);
  if (row.some((c) => c.trim().length > 0)) {
    rows.push(row);
  }

  return rows;
}

function extractValidTokensFromCell(rawCell: string): Array<{ cleaned: string; type: IndicatorType }> {
  const trimmed = rawCell.trim();
  if (!trimmed) return [];
  const subTokens = trimmed.split(/[\s;]+/).filter(Boolean);
  const found: Array<{ cleaned: string; type: IndicatorType }> = [];
  for (const tok of subTokens) {
    const cleaned = cleanIndicator(tok);
    const type = detectIndicatorType(cleaned);
    if (type) {
      found.push({ cleaned, type });
    }
  }
  return found;
}

export function extractIndicatorsFromCsv(
  csvText: string,
  options?: { designatedColumn?: string | null },
): BulkCsvImportResult {
  const matrix = parseCsvMatrix(csvText);
  if (matrix.length === 0) {
    return {
      indicators: [],
      rawText: '',
      totalRows: 0,
      validCount: 0,
      skippedCount: 0,
      detectedColumns: [],
      hasHeaderRow: false,
      availableColumns: [],
      designatedColumn: null,
      breakdown: { ip: 0, domain: 0, hash: 0 },
      sourceFormat: 'csv',
    };
  }

  const maxColCount = matrix.reduce((max, r) => Math.max(max, r.length), 0);
  const firstRow = matrix[0].map((c) => c.trim());
  const priorityColIndices: number[] = [];
  const priorityHeaders: string[] = [];

  firstRow.forEach((header, idx) => {
    if (PRIORITY_HEADER_RE.test(header)) {
      priorityColIndices.push(idx);
      priorityHeaders.push(header);
    }
  });

  // Check if first row looks like a header (non-IOC header names)
  const firstRowHasIoc = firstRow.some((cell) => detectIndicatorType(cleanIndicator(cell)) !== null);
  const hasHeaderRow = priorityColIndices.length > 0 || !firstRowHasIoc;
  const startRow = hasHeaderRow ? 1 : 0;
  const dataRows = matrix.slice(startRow);

  const availableColumns: CsvColumnCandidate[] = Array.from({ length: maxColCount }, (_, idx) => {
    const rawHeader = hasHeaderRow ? (firstRow[idx] || '').trim() : '';
    const name = rawHeader || `Column ${idx + 1}`;
    const colSeen = new Set<string>();
    const sampleValues: string[] = [];
    for (const row of dataRows) {
      const cell = row[idx] ?? '';
      for (const hit of extractValidTokensFromCell(cell)) {
        const key = `${hit.type}:${hit.cleaned}`;
        if (!colSeen.has(key)) {
          colSeen.add(key);
          if (sampleValues.length < 3) sampleValues.push(hit.cleaned);
        }
      }
    }
    return {
      index: idx,
      name,
      validCount: colSeen.size,
      sampleValues,
      isPriorityHeader: Boolean(rawHeader && PRIORITY_HEADER_RE.test(rawHeader)),
    };
  });

  const requestedCol = options?.designatedColumn?.trim() || null;
  let targetColIndices: number[];
  let detectedColumns: string[];
  let resolvedDesignatedColumn: string | null = '__auto__';

  if (requestedCol && requestedCol !== '__auto__' && requestedCol !== '__all__') {
    const matchedCol =
      availableColumns.find((c) => c.name === requestedCol) ??
      availableColumns.find((c) => c.name.toLowerCase() === requestedCol.toLowerCase());
    if (matchedCol) {
      targetColIndices = [matchedCol.index];
      detectedColumns = [matchedCol.name];
      resolvedDesignatedColumn = matchedCol.name;
    } else {
      targetColIndices = [];
      detectedColumns = [requestedCol];
      resolvedDesignatedColumn = requestedCol;
    }
  } else if (requestedCol === '__all__') {
    targetColIndices = availableColumns.map((c) => c.index);
    detectedColumns = availableColumns.map((c) => c.name);
    resolvedDesignatedColumn = '__all__';
  } else if (priorityColIndices.length > 0) {
    targetColIndices = priorityColIndices;
    detectedColumns = priorityHeaders;
    resolvedDesignatedColumn =
      priorityHeaders.length === 1 ? priorityHeaders[0] : '__auto__';
  } else {
    targetColIndices = availableColumns.map((c) => c.index);
    detectedColumns = [];
    resolvedDesignatedColumn = '__auto__';
  }

  const seen = new Set<string>();
  const indicators: string[] = [];
  const breakdown: Record<IndicatorType, number> = { ip: 0, domain: 0, hash: 0 };
  let skippedCount = 0;

  for (const cells of dataRows) {
    const targetCells = targetColIndices.map((colIdx) => cells[colIdx] ?? '');

    let rowHadCandidate = false;
    let rowHadValid = false;

    for (const rawCell of targetCells) {
      const trimmed = rawCell.trim();
      if (!trimmed) continue;
      rowHadCandidate = true;

      for (const hit of extractValidTokensFromCell(trimmed)) {
        rowHadValid = true;
        const key = `${hit.type}:${hit.cleaned}`;
        if (!seen.has(key)) {
          seen.add(key);
          indicators.push(hit.cleaned);
          breakdown[hit.type]++;
        }
      }
    }

    if (rowHadCandidate && !rowHadValid) {
      skippedCount++;
    }
  }

  return {
    indicators,
    rawText: indicators.join(', '),
    totalRows: dataRows.length,
    validCount: indicators.length,
    skippedCount,
    detectedColumns,
    hasHeaderRow,
    availableColumns,
    designatedColumn: resolvedDesignatedColumn,
    breakdown,
    sourceFormat: 'csv',
  };
}

function stripTxtComment(line: string): string {
  const withoutHash = line.replace(/(^|\s)#.*$/, '');
  // Preserve http://, https://, hxxp://, hxxps:// while stripping standalone or spaced // comments
  return withoutHash.replace(/(^|\s)\/\/.*$/, '').trim();
}

export function extractIndicatorsFromTxt(txtContent: string): BulkCsvImportResult {
  const clean = txtContent.replace(/^\ufeff/, '');
  const lines = clean.split(/\r?\n/);

  const seen = new Set<string>();
  const indicators: string[] = [];
  const breakdown: Record<IndicatorType, number> = { ip: 0, domain: 0, hash: 0 };
  let totalRows = 0;
  let skippedCount = 0;

  for (const rawLine of lines) {
    const lineWithoutComments = stripTxtComment(rawLine).replace(/^[-*•]+\s+/, '').trim();
    if (!lineWithoutComments) continue;
    totalRows += 1;

    const tokens = lineWithoutComments
      .split(/[\s,;|]+/)
      .map((t) => t.replace(/^["'<(]+|["'>),.;:]+$/g, '').trim())
      .filter(Boolean);

    let lineHadValid = false;
    for (const tok of tokens) {
      const cleaned = cleanIndicator(tok);
      const type = detectIndicatorType(cleaned);
      if (!type) continue;
      lineHadValid = true;
      const key = `${type}:${cleaned}`;
      if (!seen.has(key)) {
        seen.add(key);
        indicators.push(cleaned);
        breakdown[type] += 1;
      }
    }

    if (!lineHadValid) {
      skippedCount += 1;
    }
  }

  return {
    indicators,
    rawText: indicators.join(', '),
    totalRows,
    validCount: indicators.length,
    skippedCount,
    detectedColumns: [],
    breakdown,
    sourceFormat: 'txt',
  };
}

export function isSupportedIndicatorFile(fileName: string, mimeType = ''): boolean {
  const lowerName = fileName.trim().toLowerCase();
  const lowerMime = mimeType.trim().toLowerCase();
  if (lowerName.endsWith('.csv') || lowerName.endsWith('.txt')) {
    return true;
  }
  return lowerMime === 'text/csv' || lowerMime === 'text/plain' || lowerMime === 'application/vnd.ms-excel';
}

export function extractIndicatorsFromFile(
  fileContent: string,
  fileName: string,
  mimeType = '',
  options?: { designatedColumn?: string | null },
): BulkCsvImportResult {
  const lowerName = fileName.trim().toLowerCase();
  const lowerMime = mimeType.trim().toLowerCase();
  if (lowerName.endsWith('.txt') || (lowerMime === 'text/plain' && !lowerName.endsWith('.csv'))) {
    return extractIndicatorsFromTxt(fileContent);
  }
  return extractIndicatorsFromCsv(fileContent, options);
}

export function formatBulkIndicatorsText(
  parsed: Pick<BulkCsvImportResult, 'indicators'>,
): string {
  return (parsed.indicators || []).join('\n');
}

