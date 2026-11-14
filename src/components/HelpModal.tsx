import { useEffect } from 'react';
import { CheckCircle2, ExternalLink, KeyRound, Settings2, X, XCircle } from 'lucide-react';
import type { ApiKeyStatus, BuiltinExtraSourceId } from '../utils/apiConfig';

interface HelpModalProps {
  open: boolean;
  onClose: () => void;
  onOpenApiSettings: () => void;
  keyStatus: ApiKeyStatus;
  extraKeyStatus: Record<BuiltinExtraSourceId, boolean>;
}

interface ProviderDocGuide {
  id: string;
  name: string;
  envVar: string;
  tier: string;
  support: string;
  docsUrl: string;
  portalUrl: string;
  portalLabel: string;
  steps: string[];
  configured: boolean;
}

export function HelpModal({
  open,
  onClose,
  onOpenApiSettings,
  keyStatus,
  extraKeyStatus,
}: HelpModalProps) {
  useEffect(() => {
    if (!open) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        onClose();
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const guides: ProviderDocGuide[] = [
    {
      id: 'virustotal',
      name: 'VirusTotal',
      envVar: 'VT_API_KEY',
      tier: 'Core · 500/day free',
      support: 'IP, Domain, Hash',
      docsUrl: 'https://docs.virustotal.com/reference/overview',
      portalUrl: 'https://www.virustotal.com/gui/my-apikey',
      portalLabel: 'Get VT API Key',
      configured: keyStatus.virustotal,
      steps: [
        'Sign in or register for a free VirusTotal Community account.',
        'Open your user profile menu and select API Key to copy your 64-character personal key.',
        'Add VT_API_KEY=<your_key> to .env on the server and run Test Connection in CLI & APIs.',
      ],
    },
    {
      id: 'abuseipdb',
      name: 'AbuseIPDB',
      envVar: 'ABUSEIPDB_API_KEY',
      tier: 'Core · 1,000/day free',
      support: 'IP addresses',
      docsUrl: 'https://docs.abuseipdb.com/',
      portalUrl: 'https://www.abuseipdb.com/account/api',
      portalLabel: 'AbuseIPDB API Portal',
      configured: keyStatus.abuseipdb,
      steps: [
        'Create or sign into your AbuseIPDB account and open Account → API.',
        'Click Create Key (v2 API), assign a label (e.g. SoTI), and copy the generated key.',
        'Add ABUSEIPDB_API_KEY=<your_key> to .env and verify connectivity in CLI & APIs.',
      ],
    },
    {
      id: 'alienvault',
      name: 'AlienVault OTX',
      envVar: 'OTX_API_KEY',
      tier: 'Core · 10,000/day free',
      support: 'IP, Domain, Hash',
      docsUrl: 'https://otx.alienvault.com/api',
      portalUrl: 'https://otx.alienvault.com/settings',
      portalLabel: 'OTX Key Settings',
      configured: keyStatus.alienvault,
      steps: [
        'Register for a free Open Threat Exchange (OTX) account.',
        'Navigate to Settings and copy your OTX Key shown at the top of the profile settings.',
        'Add OTX_API_KEY=<your_key> to .env and test the heartbeat in CLI & APIs.',
      ],
    },
    {
      id: 'shodan',
      name: 'Shodan',
      envVar: 'SHODAN_API_KEY',
      tier: 'Optional · 100/day default',
      support: 'IP addresses',
      docsUrl: 'https://developer.shodan.io/api',
      portalUrl: 'https://account.shodan.io/',
      portalLabel: 'Shodan Account',
      configured: extraKeyStatus.shodan,
      steps: [
        'Sign into Shodan and open your Account overview page.',
        'Click Show API Key next to your account details to copy it.',
        'Set SHODAN_API_KEY=<your_key> in .env, then enable Shodan under CLI & APIs.',
      ],
    },
    {
      id: 'threatfox',
      name: 'ThreatFox (abuse.ch)',
      envVar: 'THREATFOX_AUTH_KEY',
      tier: 'Optional · 2,000/day default',
      support: 'IP, Domain, Hash',
      docsUrl: 'https://threatfox.abuse.ch/api/',
      portalUrl: 'https://auth.abuse.ch/',
      portalLabel: 'abuse.ch Auth Portal',
      configured: extraKeyStatus.threatfox,
      steps: [
        'Sign in at the abuse.ch authentication portal (auth.abuse.ch).',
        'Generate a new Auth-Key for ThreatFox API requests.',
        'Set THREATFOX_AUTH_KEY=<your_key> in .env and enable ThreatFox in CLI & APIs.',
      ],
    },
    {
      id: 'urlscan',
      name: 'urlscan.io',
      envVar: 'URLSCAN_API_KEY',
      tier: 'Optional · 1,000/day default',
      support: 'IP, Domain, Hash',
      docsUrl: 'https://urlscan.io/docs/api/',
      portalUrl: 'https://urlscan.io/user/profile/',
      portalLabel: 'urlscan.io Profile',
      configured: extraKeyStatus.urlscan,
      steps: [
        'Log into urlscan.io and go to Settings & API.',
        'Click Create New API Key and copy the generated token.',
        'Set URLSCAN_API_KEY=<your_key> in .env and enable urlscan.io in CLI & APIs.',
      ],
    },
  ];

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/55 dark:bg-black/70 p-4 backdrop-blur-[1px]"
      onClick={onClose}
      role="presentation"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="help-modal-title"
        data-testid="api-help-modal"
        onClick={(e) => e.stopPropagation()}
        className="flex max-h-[88vh] w-full max-w-4xl flex-col overflow-hidden rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-xl"
      >
        <div className="flex items-start justify-between gap-4 border-b border-slate-200 dark:border-slate-800 px-6 py-4">
          <div className="flex items-start gap-3">
            <KeyRound className="mt-0.5 h-5 w-5 shrink-0 text-red-600 dark:text-red-500" aria-hidden="true" />
            <div>
              <h2 id="help-modal-title" className="text-base font-bold text-slate-950 dark:text-slate-50">
                Threat Intelligence API Keys &amp; Documentation
              </h2>
              <p className="mt-0.5 text-xs text-slate-600 dark:text-slate-400">
                Obtain API keys from each provider&apos;s official portal and store them securely in your server <code className="font-mono">.env</code> file (never exposed in browser storage).
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close help modal"
            className="rounded-lg p-1.5 text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer shrink-0"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="min-w-0 flex-1 overflow-y-auto px-5 sm:px-6 py-5 space-y-6">
          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            {guides.map((g) => (
              <section key={g.id} className="py-4 first:pt-0 last:pb-0">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                      <h3 className="text-sm font-semibold text-slate-950 dark:text-slate-100">{g.name}</h3>
                      <span className="font-mono text-xs text-slate-600 dark:text-slate-300">{g.envVar}</span>
                      <span className="text-slate-300 dark:text-slate-700" aria-hidden="true">·</span>
                      <span className="text-xs text-slate-500 dark:text-slate-400">{g.tier}</span>
                      <span className="text-slate-300 dark:text-slate-700" aria-hidden="true">·</span>
                      <span className="text-xs text-slate-500 dark:text-slate-400">{g.support}</span>
                      <span className="text-slate-300 dark:text-slate-700" aria-hidden="true">·</span>
                      {g.configured ? (
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                          Key ready
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-500 dark:text-slate-400">
                          <XCircle className="h-3.5 w-3.5" aria-hidden="true" />
                          Not configured
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <a
                      href={g.portalUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 whitespace-nowrap"
                    >
                      {g.portalLabel}
                      <ExternalLink className="h-3 w-3" aria-hidden="true" />
                    </a>
                    <a
                      href={g.docsUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 whitespace-nowrap"
                    >
                      API Docs
                      <ExternalLink className="h-3 w-3" aria-hidden="true" />
                    </a>
                  </div>
                </div>

                <ol className="mt-2.5 list-decimal space-y-1 pl-5 text-xs text-slate-600 dark:text-slate-300">
                  {g.steps.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              </section>
            ))}
          </div>

          <section className="min-w-0 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/60 p-4 space-y-2">
            <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
              Custom Providers &amp; Server Environment Setup
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-300">
              For additional providers (e.g. GreyNoise, Pulsedive, IPQualityScore), register the endpoint template and environment variable name in{' '}
              <span className="font-semibold text-slate-800 dark:text-slate-100">CLI &amp; APIs</span>, add the key to <code className="font-mono">.env</code>, restart the server or run <code className="font-mono">Test Connection</code>, and SoTI will automatically apply quota tracking and failover across all enabled providers.
            </p>
            <pre className="overflow-x-auto rounded-md bg-slate-950 p-3 font-mono text-[11px] leading-relaxed text-slate-200 border border-slate-800">
{`# .env example
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
OTX_API_KEY=your_alienvault_otx_key
SHODAN_API_KEY=your_shodan_key
THREATFOX_AUTH_KEY=your_threatfox_key
URLSCAN_API_KEY=your_urlscan_key`}
            </pre>
          </section>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 px-6 py-3.5">
          <p className="text-xs text-slate-500 dark:text-slate-400">
            No keys configured? Switch Investigate to <span className="font-medium text-slate-700 dark:text-slate-200">Sample Data</span> mode for offline demonstrations.
          </p>
          <div className="flex items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => {
                onClose();
                onOpenApiSettings();
              }}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3.5 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 whitespace-nowrap cursor-pointer"
            >
              <Settings2 className="h-3.5 w-3.5" aria-hidden="true" />
              Open CLI &amp; APIs
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg bg-slate-900 dark:bg-slate-100 px-4 py-2 text-xs font-semibold text-white dark:text-slate-950 hover:bg-slate-800 dark:hover:bg-white whitespace-nowrap cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
