import { cleanIndicator, detectIndicatorType, type IndicatorType } from './indicators';

export type IndicatorFileFormat = 'csv' | 'txt';

export interface BulkCsvImportResult {
  indicators: string[];
  rawText: string;
  totalRows: number;
  validCount: number;
  skippedCount: number;
  detectedColumns: string[];
  breakdown: Record<IndicatorType, number>;
  sourceFormat?: IndicatorFileFormat;
}

const PRIORITY_HEADER_RE =
  /^(?:indicator|indicators|ioc|iocs|observable|observables|ip|ip_address|ipv4|ipv6|domain|host|hostname|hash|sha256|sha1|md5|artifact|value|target)$/i;

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

export function extractIndicatorsFromCsv(csvText: string): BulkCsvImportResult {
  const matrix = parseCsvMatrix(csvText);
  if (matrix.length === 0) {
    return {
      indicators: [],
      rawText: '',
      totalRows: 0,
      validCount: 0,
      skippedCount: 0,
      detectedColumns: [],
      breakdown: { ip: 0, domain: 0, hash: 0 },
      sourceFormat: 'csv',
    };
  }

  const firstRow = matrix[0].map((c) => c.trim());
  const priorityColIndices: number[] = [];
  const detectedColumns: string[] = [];

  firstRow.forEach((header, idx) => {
    if (PRIORITY_HEADER_RE.test(header)) {
      priorityColIndices.push(idx);
      detectedColumns.push(header);
    }
  });

  // Check if first row looks like a header (non-IOC header names)
  const firstRowHasIoc = firstRow.some((cell) => detectIndicatorType(cleanIndicator(cell)) !== null);
  const startRow = priorityColIndices.length > 0 || !firstRowHasIoc ? 1 : 0;
  const dataRows = matrix.slice(startRow);

  const seen = new Set<string>();
  const indicators: string[] = [];
  const breakdown: Record<IndicatorType, number> = { ip: 0, domain: 0, hash: 0 };
  let skippedCount = 0;

  for (const cells of dataRows) {
    const targetCells =
      priorityColIndices.length > 0
        ? priorityColIndices.map((colIdx) => cells[colIdx] ?? '')
        : cells;

    let rowHadCandidate = false;
    let rowHadValid = false;

    for (const rawCell of targetCells) {
      const trimmed = rawCell.trim();
      if (!trimmed) continue;
      rowHadCandidate = true;

      // Also support cells containing multiple space/semicolon separated IOCs
      const subTokens = trimmed.split(/[\s;]+/).filter(Boolean);
      for (const tok of subTokens) {
        const cleaned = cleanIndicator(tok);
        const type = detectIndicatorType(cleaned);
        if (!type) continue;
        rowHadValid = true;
        const key = `${type}:${cleaned}`;
        if (!seen.has(key)) {
          seen.add(key);
          indicators.push(cleaned);
          breakdown[type]++;
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
): BulkCsvImportResult {
  const lowerName = fileName.trim().toLowerCase();
  const lowerMime = mimeType.trim().toLowerCase();
  if (lowerName.endsWith('.txt') || (lowerMime === 'text/plain' && !lowerName.endsWith('.csv'))) {
    return extractIndicatorsFromTxt(fileContent);
  }
  return extractIndicatorsFromCsv(fileContent);
}

