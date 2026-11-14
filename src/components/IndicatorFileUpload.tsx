import { useRef, useState } from 'react';
import { CheckCircle2, FileText, Upload, X } from 'lucide-react';
import {
  extractIndicatorsFromFile,
  isSupportedIndicatorFile,
  type BulkCsvImportResult,
} from '../utils/bulkCsv';

export interface IndicatorFileSummary {
  fileName: string;
  parsed: BulkCsvImportResult;
}

interface IndicatorFileUploadProps {
  summary: IndicatorFileSummary | null;
  onIndicatorsExtracted: (summary: IndicatorFileSummary) => void;
  onError: (message: string) => void;
  onDismissSummary: () => void;
}

export function IndicatorFileUpload({
  summary,
  onIndicatorsExtracted,
  onError,
  onDismissSummary,
}: IndicatorFileUploadProps) {
  const inputRef = useRef<HTMLInputElement | null>(null);
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
      if (parsed.validCount === 0) {
        onError(`No valid IP, domain, or hash indicators found in "${file.name}".`);
        return;
      }

      onIndicatorsExtracted({ fileName: file.name, parsed });
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
              Upload indicator file (.csv or .txt)
            </span>
            <span className="hidden sm:inline text-slate-500 dark:text-slate-400">
              {' '}
              — parsed locally in your browser to populate the input field above
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
          className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 px-4 py-2.5 text-xs text-emerald-900 dark:text-emerald-200"
        >
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-700 dark:text-emerald-400" aria-hidden="true" />
            <span className="font-semibold">
              Imported {summary.parsed.validCount} unique IOC
              {summary.parsed.validCount === 1 ? '' : 's'}
            </span>
            <span>
              from {summary.fileName} ({(summary.parsed.sourceFormat || 'csv').toUpperCase()})
            </span>
            <span aria-hidden="true">·</span>
            <span className="font-mono tabular-nums">
              {summary.parsed.breakdown.ip} IP · {summary.parsed.breakdown.domain} Domain ·{' '}
              {summary.parsed.breakdown.hash} Hash
            </span>
            {summary.parsed.skippedCount > 0 && (
              <>
                <span aria-hidden="true">·</span>
                <span>{summary.parsed.skippedCount} non-IOC line(s) skipped</span>
              </>
            )}
          </div>
          <button
            type="button"
            onClick={onDismissSummary}
            aria-label="Dismiss imported file summary"
            className="rounded p-1 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-100 dark:hover:bg-emerald-900/50 cursor-pointer"
          >
            <X className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </div>
      )}
    </div>
  );
}
