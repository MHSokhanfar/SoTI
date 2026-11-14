import { useEffect, useState } from 'react';
import { RefreshCw, ScrollText } from 'lucide-react';

export function LogsView() {
  const [lines, setLines] = useState<string[]>([]);
  const [filter, setFilter] = useState('');
  const [loading, setLoading] = useState(true);

  async function loadLogs() {
    setLoading(true);
    try {
      const resp = await fetch('/api/logs');
      const data = await resp.json();
      setLines(data.lines || []);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadLogs();
  }, []);

  const visibleLines = filter.trim()
    ? lines.filter((l) => l.toLowerCase().includes(filter.trim().toLowerCase()))
    : lines;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-950 dark:text-slate-50">
            Execution Audit Logs
          </h1>
          <p className="mt-0.5 text-sm text-slate-600 dark:text-slate-400">
            Recent entries from <code className="font-mono text-xs">logs/soti.log</code> (newest first).
          </p>
        </div>

        <div className="flex items-center gap-3">
          <input
            type="search"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter log lines..."
            aria-label="Filter log lines"
            className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-xs text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-red-600 focus:outline-none"
          />
          <button
            type="button"
            onClick={loadLogs}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3.5 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
            Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-8 text-sm text-slate-500 dark:text-slate-400">
          Loading logs...
        </div>
      ) : visibleLines.length === 0 ? (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-6 py-12 text-center">
          <ScrollText className="mx-auto h-8 w-8 text-slate-400 dark:text-slate-500" aria-hidden="true" />
          <h2 className="mt-3 text-base font-semibold text-slate-900 dark:text-slate-100">
            No log entries found
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            Run an enrichment query in the web workbench or Python CLI to record HTTP and report logs.
          </p>
        </div>
      ) : (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-950 p-4 font-mono text-xs text-slate-200 overflow-x-auto">
          <ul className="space-y-1.5">
            {visibleLines.map((line, idx) => (
              <li key={idx} className="whitespace-pre leading-relaxed">
                {line}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
