import { useRef, useState } from 'react';
import { CheckCircle2, Columns3, FileText, Upload, X } from 'lucide-react';
import {
  extractIndicatorsFromFile,
  isSupportedIndicatorFile,
  type BulkCsvImportResult,
} from '../utils/bulkCsv';

export interface IndicatorFileSummary {
  fileName: string;
  mimeType: string;
  rawContent: string;
  designatedColumn: string;
  parsed: BulkCsvImportResult;
}

interface IndicatorFileUploadProps {
  summary: IndicatorFileSummary | null;
  fileInputRef?: React.RefObject<HTMLInputElement | null>;
  onIndicatorsExtracted: (summary: IndicatorFileSummary) => void;
  onChangeDesignatedColumn?: (column: string) => void;
  onError: (message: string) => void;
  onDismissSummary: () => void;
}

export function IndicatorFileUpload({
  summary,
  fileInputRef,
  onIndicatorsExtracted,
  onChangeDesignatedColumn,
  onError,
  onDismissSummary,
}: IndicatorFileUploadProps) {
  const internalInputRef = useRef<HTMLInputElement | null>(null);
  const inputRef = fileInputRef ?? internalInputRef;
  const [dragging, setDragging] = useState(false);

  async function processFile(file: File | undefined | null) {
    if (!file) return;

    if (!isSupportedIndicatorFile(file.name, file.type)) {
      onError(`Unsupported file "${file.name}". Please upload a .csv or .txt file of indicators.`);
      return;
    }

    try {
      const content = await file.text();
      const parsed = extractIndicatorsFromFile(content, file.name, file.type);
      if (parsed.validCount === 0 && !(parsed.availableColumns && parsed.availableColumns.some((c) => c.validCount > 0))) {
        onError(`No valid IP, domain, or hash indicators found in "${file.name}".`);
        return;
      }

      onIndicatorsExtracted({
        fileName: file.name,
        mimeType: file.type,
        rawContent: content,
        designatedColumn: parsed.designatedColumn || '__auto__',
        parsed,
      });
    } catch {
      onError(`Failed to read file "${file.name}".`);
    }
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = '';
    void processFile(file);
  }

  function handleDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    void processFile(file);
  }

  const availableColumns =
    summary?.parsed.sourceFormat === 'csv' ? summary.parsed.availableColumns ?? [] : [];

  return (
    <div className="space-y-2.5">
      <div
        data-testid="indicator-file-dropzone"
        onDragOver={(e) => {
          e.preventDefault();
          if (!dragging) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        className={`flex flex-col gap-2 rounded-lg border border-dashed px-3.5 py-2.5 transition-colors sm:flex-row sm:items-center sm:justify-between ${
          dragging
            ? 'border-red-500 bg-red-50/50 dark:bg-red-950/30'
            : 'border-slate-300 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-800/50 hover:border-slate-400 dark:hover:border-slate-600'
        }`}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <FileText className="h-4 w-4 shrink-0 text-slate-500 dark:text-slate-400" aria-hidden="true" />
          <div className="min-w-0 text-xs">
            <span className="font-medium text-slate-800 dark:text-slate-200">
              Upload local CSV / TXT feed
            </span>
            <span className="hidden sm:inline text-slate-500 dark:text-slate-400">
              {' '}
              — drag &amp; drop here or onto the Bulk input to extract IOCs from a designated column
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <input
            ref={inputRef}
            id="ioc-file-upload"
            data-testid="indicator-file-input"
            type="file"
            accept=".csv,.txt,text/csv,text/plain"
            onChange={handleFileChange}
            className="sr-only"
            aria-label="Upload CSV or TXT indicator file"
          />
          <button
            type="button"
            onClick={() => inputRef.current?.click()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 dark:focus-visible:outline-slate-200"
          >
            <Upload className="h-3.5 w-3.5" aria-hidden="true" />
            Choose CSV / TXT File
          </button>
        </div>
      </div>

      {summary && (
        <div
          data-testid="csv-import-banner"
          className="flex flex-col gap-2.5 rounded-lg border border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 px-4 py-2.5 text-xs text-emerald-900 dark:text-emerald-200"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 min-w-0">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-700 dark:text-emerald-400" aria-hidden="true" />
              <span className="font-semibold">
                Extracted {summary.parsed.validCount} unique IOC
                {summary.parsed.validCount === 1 ? '' : 's'}
              </span>
              <span>
                from {summary.fileName} ({(summary.parsed.sourceFormat || 'csv').toUpperCase()}) → Bulk Investigation input
              </span>
              <span aria-hidden="true">·</span>
              <span className="font-mono tabular-nums">
                {summary.parsed.breakdown.ip} IP · {summary.parsed.breakdown.domain} Domain ·{' '}
                {summary.parsed.breakdown.hash} Hash
              </span>
              {summary.parsed.skippedCount > 0 && (
                <>
                  <span aria-hidden="true">·</span>
                  <span>{summary.parsed.skippedCount} non-IOC row(s) skipped</span>
                </>
              )}
            </div>
            <button
              type="button"
              onClick={onDismissSummary}
              aria-label="Dismiss imported file summary"
              className="rounded p-1 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-100 dark:hover:bg-emerald-900/50 cursor-pointer shrink-0"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>

          {availableColumns.length > 0 && onChangeDesignatedColumn && (
            <div
              data-testid="csv-column-designation-bar"
              className="flex flex-wrap items-center gap-2.5 border-t border-emerald-200/80 dark:border-emerald-800/70 pt-2"
            >
              <label
                htmlFor="csv-designated-column-select"
                className="inline-flex items-center gap-1.5 font-medium text-emerald-950 dark:text-emerald-100 whitespace-nowrap shrink-0"
              >
                <Columns3 className="h-3.5 w-3.5 text-emerald-700 dark:text-emerald-400" aria-hidden="true" />
                <span>Designated CSV Column</span>
              </label>
              <select
                id="csv-designated-column-select"
                data-testid="csv-designated-column-select"
                value={summary.designatedColumn}
                onChange={(e) => onChangeDesignatedColumn(e.target.value)}
                className="w-full max-w-full min-w-0 sm:w-auto rounded-md border border-emerald-300 dark:border-emerald-700 bg-white dark:bg-slate-900 px-2.5 py-1 font-mono text-xs text-slate-900 dark:text-slate-100 focus:border-red-600 focus:outline-none cursor-pointer"
              >
                <option value="__auto__">
                  Auto-detected IOC columns ({summary.parsed.detectedColumns.join(', ') || 'all'})
                </option>
                <option value="__all__">All Columns Combined</option>
                {availableColumns.map((col) => (
                  <option key={`${col.index}-${col.name}`} value={col.name}>
                    {col.name} ({col.validCount} IOC{col.validCount === 1 ? '' : 's'})
                    {col.sampleValues.length > 0 ? ` — e.g. ${col.sampleValues[0]}` : ''}
                  </option>
                ))}
              </select>
              <span className="text-[11px] text-emerald-800/90 dark:text-emerald-300/90">
                Switch column to re-extract IOCs directly into the Bulk Investigation field.
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
