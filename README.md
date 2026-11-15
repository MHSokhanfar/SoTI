# SoTI — Threat Intelligence Enrichment CLI & SOC Workbench

**SoTI (Threat Intelligence Enrichment & IOC Assessment Workbench)** is a threat intelligence enrichment and indicator-of-compromise (IOC) triage platform available as both a **Python CLI** and an interactive **React + Express SOC Web Workbench**. It supports normal and defanged **IPv4/IPv6 addresses, domains, URLs, and file hashes** (`MD5`, `SHA1`, `SHA256`) across **VirusTotal**, **AbuseIPDB**, **AlienVault OTX**, and configurable backup/custom threat intelligence providers.

**Created and developed by Mohammad Hossein Sokhanfar**  
Repository: [https://github.com/MHSokhanfar/SoTI](https://github.com/MHSokhanfar/SoTI)

---

## 1. Prerequisites

Ensure the following tools are installed on your machine before setting up the project:

| Prerequisite | Recommended Version | Purpose |
| :--- | :--- | :--- |
| **Git** | `2.30+` | Clone the repository from GitHub |
| **Python** | `3.10+` with `pip` | Run the Python CLI (`main.py`) and Python unit tests |
| **Node.js & npm** | `Node.js 18+` (`20 LTS` preferred) | Run the React/Vite frontend, Express backend (`server.ts`), and TypeScript tests |
| **API Keys** | Free or standard tier | Live lookups against VirusTotal, AbuseIPDB, and AlienVault OTX *(optional for offline `--demo` / `Sample Data` mode)* |

---

## 2. Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/MHSokhanfar/SoTI.git
cd SoTI
```

### Step 2: Create and Activate a Python Virtual Environment
- **Linux / macOS:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

- **Windows — Command Prompt (CMD):**
  ```cmd
  python -m venv venv
  venv\Scripts\activate.bat
  ```

- **Windows — PowerShell:**
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```
  > **Windows Note:** If PowerShell blocks script execution, allow local scripts once for your user and re-run activation:
  > `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### Step 3: Install Python Dependencies (`requirements.txt`)
With the virtual environment `(venv)` active, install the CLI dependencies (`requests`, `python-dotenv`, `rich`):

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Install Web Workbench Dependencies (Optional — for Web UI)
If you plan to run the SOC Web Dashboard, install the Node.js dependencies:

```bash
npm install
```

---

## 3. API Configuration

### Step 1: Copy `.env.example` to `.env`
- **Linux / macOS:**
  ```bash
  cp .env.example .env
  ```
- **Windows (CMD / PowerShell):**
  ```cmd
  copy .env.example .env
  ```

### Step 2: Add Your API Keys
Open `.env` in your editor and configure your threat intelligence API keys:

```env
# Primary Threat Intelligence API Keys (Python CLI & Web Workbench)
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
OTX_API_KEY=your_alienvault_otx_api_key

# Optional Additional Threat Intelligence Providers
SHODAN_API_KEY=your_shodan_api_key
THREATFOX_AUTH_KEY=your_threatfox_auth_key
URLSCAN_API_KEY=your_urlscan_api_key
```

> **Security & Quota Notes:**
> - `.env` is listed in `.gitignore` and must never be committed to version control.
> - Inside the Web Workbench, you can inspect API health, enable backup/custom providers, and view setup instructions via the **CLI & APIs** tab and the **Help** modal.
> - Automatic daily quota failover tracks provider usage and seamlessly falls back to healthy active providers if an API reaches its daily limit or returns `HTTP 429`.

---

## 4. Usage & Execution

### A. Python CLI (`main.py`)

#### 1. Interactive Menu Mode
```bash
# Live API lookups
python main.py

# Offline deterministic demo mode (no API quota consumed)
python main.py --demo
```

#### 2. Non-Interactive CLI Commands
SoTI automatically refangs defanged indicators (such as `1[.]2[.]3[.]4` and `hxxp://evil[.]com`):

```bash
# Query multiple indicators across all configured sources
python main.py --source all --indicators "1[.]2[.]3[.]4, hxxp://evil[.]com, 44d88612fea8a8f36de82e1278abb02f"

# Query a single IP address using VirusTotal only
python main.py --source vt --indicators 8.8.8.8

# Load indicators from a text or CSV file
python main.py --source all --file indicators.txt

# Offline simulation with machine-readable JSON output
python main.py --source all --indicators "8.8.8.8, evil[.]com" --demo --json
```

#### 3. Scheduled Checks via CLI
```bash
# Add a recurring check running every 60 minutes
python main.py --add-schedule --schedule-name "Critical IOC Watch" --source all --indicators "1[.]2[.]3[.]4, evil[.]com" --interval 60

# List all configured schedules
python main.py --list-schedules

# Execute all currently due schedules
python main.py --run-due

# Remove a scheduled job by ID
python main.py --remove-schedule <SCHEDULE_ID>
```

---

### B. SOC Web Workbench (`server.ts`)

The Web Workbench combines an Express API server (`server.ts`) with a React + TypeScript + Tailwind CSS interface featuring:
- **Investigate**: Interactive IOC input, local browser-side `.csv`/`.txt` bulk upload, `Sample Data` / `Live API` mode switch, >80% quota warnings, and automatic quota failover.
- **Reports**: Quick Stats KPIs, verdict distribution & 30-day alert charts, multi-source confidence scores, multi-report aggregated CSV export, print-ready **Download PDF**, configurable **Auto-refresh** (`60s` default), and table **Density** selector (`Compact`, `Normal`, `Spacious`).
- **Scheduled**, **Logs**, **CLI & APIs**, Light/Dark theme toggle, **Help** modal, and an app-wide **Notification Center** (alerting at ≥90% daily quota usage).

#### Development Mode
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

#### Production Build & Start
```bash
npm run build
npm start
```

---

## 5. Source Support & Default Verdict Thresholds

| Source | IP | Domain | Hash | Malicious | Suspicious | Clean |
| :--- | :---: | :---: | :---: | :--- | :--- | :--- |
| **VirusTotal** | Yes | Yes | Yes | ≥ 5 engines | 1–4 malicious or any suspicious | 0 detections |
| **AbuseIPDB** | Yes | No | No | Confidence ≥ 75% | 25–74% | < 25% |
| **AlienVault OTX** | Yes | Yes | Yes | ≥ 5 pulses | 1–4 pulses | 0 pulses = `Unknown` |

---

## 6. Directory Structure

```text
SoTI/
├── .github/
│   └── workflows/
│       └── main.yml              # GitHub Actions CI for Python CLI & React frontend
├── api/                          # Python threat intelligence provider clients
│   ├── __init__.py               # IOC refanging & type classification (ip/domain/hash)
│   ├── virustotal.py             # VirusTotal API v3 integration
│   ├── abuseipdb.py              # AbuseIPDB API v2 integration
│   └── alienvault.py             # AlienVault OTX integration
├── config/                       # Configuration, scheduling, and runtime state
│   ├── settings.py               # Central paths, version, and defaults
│   ├── scheduler.py              # Recurring schedule engine
│   ├── quota_usage.json          # Daily API quota ledger for automatic failover
│   └── schedules.json            # Persisted scheduled IOC checks
├── logs/                         # Runtime and audit logs (created automatically)
│   └── soti.log                  # Enrichment & system audit log file
├── reports/                      # Auto-saved CSV reports (created automatically)
│   └── soti_YYYYMMDD_HHMMSS.csv  # UTF-8-SIG Excel-compatible enrichment exports
├── src/                          # React + TypeScript + Tailwind CSS frontend
│   ├── App.tsx                   # App shell, theme switcher, and Notification Center
│   ├── components/               # Investigate, Reports, Scheduled, Logs, Help, CLI & APIs
│   └── utils/                    # Pure analytics, parsers, quota helpers, & unit tests
├── tests/                        # Python CLI unit tests
│   └── test_soti.py
├── main.py                       # Python CLI entry point
├── server.ts                     # Express backend & Vite server (port 3000)
├── index.html                    # Web application entry document
├── requirements.txt              # Python package requirements
├── package.json                  # Node.js scripts and dependencies
├── .env.example                  # Environment variable & API key template
└── README.md                     # Project documentation
```

---

## 7. Testing & CI Verification

Automated checks run on every push via `.github/workflows/main.yml`:

```bash
# Python CLI unit tests & syntax check
python -m py_compile main.py api/*.py config/*.py tests/*.py
python -m unittest discover -s tests -v

# TypeScript unit tests, type check, and production build
npx --yes tsx --test src/utils/*.test.ts
npm run lint
npm run build
```

---

## Disclaimer

For defensive security and SOC triage use only.
