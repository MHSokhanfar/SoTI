# SoTI — Threat Intelligence Enrichment CLI & SOC Workbench

**SoTI (Threat Intelligence Enrichment & IOC Assessment Workbench)** is a full-stack threat intelligence enrichment and indicator-of-compromise (IOC) triage platform combining a **Python CLI** and an interactive **React + Express SOC Web Workbench**. It enables security analysts to inspect normal and defanged **IPv4/IPv6 addresses, domains, URLs, and file hashes** (`MD5`, `SHA1`, `SHA256`) across **VirusTotal**, **AbuseIPDB**, **AlienVault OTX**, **Shodan**, **ThreatFox**, **URLScan.io**, and configurable custom threat intelligence APIs.

**Created and developed by Mohammad Hossein Sokhanfar**  
Repository: [https://github.com/MHSokhanfar/SoTI](https://github.com/MHSokhanfar/SoTI)

---

## 1. Project Overview

SoTI bridges lightweight command-line threat lookups with an interactive SOC browser workbench:
- **Automatic IOC Parsing & Defanging Recovery**: Recognizes and refangs indicators such as `1[.]2[.]3[.]4`, `hxxps://evil[.]example/login`, and hashes across single-input, CSV upload, and multi-line bulk triage.
- **Multi-Provider Enrichment & Failover**: Aggregates telemetry across VirusTotal, AbuseIPDB, AlienVault OTX, Shodan, ThreatFox, URLScan.io, and custom HTTP endpoints with daily quota tracking and automatic failover when a provider nears exhaustion or returns `HTTP 429`.
- **Weighted Confidence Risk Scoring**: Computes normalized `0–100` threat confidence scores and verdicts (`Critical`, `High`, `Medium`, `Low`, `Clean`, `Unknown`) per indicator and provider finding.
- **Dual Execution Modes**: Run completely offline in deterministic **Sample / Demo mode** (zero external quota used) or connect real API keys for **Live API** intelligence lookups.

---

## 2. Prerequisites

Install the following before setting up SoTI locally:

| Prerequisite | Recommended Version | Purpose |
| :--- | :--- | :--- |
| **Git** | `2.30+` | Clone the repository |
| **Python** | `3.10+` with `pip` | Run the Python CLI (`main.py`) and Python unit tests |
| **Node.js & npm** | `Node.js 22+` (`22 LTS` recommended) | Run the Express backend (`server.ts`), React/Vite Web Workbench, TypeScript unit tests, and production builds |
| **Threat Intel API Keys** | Free or standard tier | Live lookups against VirusTotal, AbuseIPDB, AlienVault OTX, Shodan, ThreatFox, URLScan *(optional for offline Demo / Sample mode)* |
| **Gemini API Key** *(Optional)* | Standard AI Studio / Gemini key | Server-side AI executive summary generation in the Web Workbench Reports view (`GEMINI_API_KEY`) |

---

## 3. Installation Guide

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
With `(venv)` active, install the CLI packages (`requests`, `python-dotenv`, `rich`):
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Install Web Workbench Dependencies (`package.json`)
Install the Node.js, React, D3, Express, and TypeScript packages required by the Web Workbench:
```bash
npm install
```

---

## 4. API Configuration

You can configure threat intelligence API keys **either via `.env` on disk** or **directly inside the Web Workbench GUI**.

### Option A: Configure via `.env` (CLI & Web Workbench)
Copy `.env.example` to `.env`:
- **Linux / macOS:** `cp .env.example .env`
- **Windows (CMD / PowerShell):** `copy .env.example .env`

Edit `.env` with your keys:
```env
# Primary Threat Intelligence API Keys (Python CLI & Web Workbench)
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
OTX_API_KEY=your_alienvault_otx_api_key

# Extended Threat Intelligence Providers
SHODAN_API_KEY=your_shodan_api_key
THREATFOX_AUTH_KEY=your_threatfox_auth_key
URLSCAN_API_KEY=your_urlscan_api_key

# Optional AI Executive Summary & Email Alerting (Server-Side Only)
GEMINI_API_KEY=your_gemini_api_key
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=alerts@example.com
SMTP_PASS=your_smtp_password
SMTP_FROM=soti-alerts@example.com
```

### Option B: Configure Threat Intel API Keys Directly from the Web Workbench GUI
1. Launch and open the **Web Workbench** (`http://localhost:3000`).
2. Switch to the **CLI & APIs** tab (or press `Alt+5`).
3. Locate any Core (**VirusTotal**, **AbuseIPDB**, **AlienVault OTX**), Built-in Extended (**Shodan**, **ThreatFox**, **URLScan**), or **Custom Integration** card.
4. Paste your provider API key into the masked **API Key** input and click **Save Key** (use the eye icon to toggle visibility or **Clear Key** to remove a stored key).
5. Keys saved from the GUI are persisted server-side in `config/provider_keys.json` (gitignored), immediately update `process.env` and the live TopBar status indicator (`Configured ••••xxxx`), and are never exposed back to browser storage.

> **Security Note:** `.env` and `config/provider_keys.json` are excluded via `.gitignore` and never expose raw secret values to client browsers.

---

## 5. How to Run & Use the Web Workbench

The **Web Workbench** pairs an Express backend (`server.ts` serving API endpoints, CSV archive streaming, scheduled checks, email alerting, Gemini AI summaries, and temporary shared reports) with a React + Vite + Tailwind CSS + D3.js frontend on **port `3000`**.

### Starting the Web Workbench

> Make sure **Node.js 22+** is installed and you have run `npm install` in the project root (`SoTI/`).

#### 1. Development Mode (Interactive Local Workbench)
From the project root:
```bash
npm run dev
```
This starts `tsx server.ts` on port `3000` with Vite middleware attached. Open:
**[http://localhost:3000](http://localhost:3000)**

> **Offline Evaluation Without Keys:** You can launch `npm run dev` immediately—even before configuring API keys—and switch **Sample Data** on inside the Investigate bar to test single lookups, Bulk Input triage, Live Mode polling, D3 visualizations, and exports without consuming external API quota.

#### 2. Production Mode (Compiled Static Bundle + Express API)
Build the frontend assets into `dist/` and start the Express server:
```bash
npm run build
npm start
```
Then open **[http://localhost:3000](http://localhost:3000)**.

### Web Workbench Walkthrough by Workspace Tab

1. **Investigate (`Ctrl+I` or `Alt+1`)**
   - **Data Source (`Sample Data` vs `Live API`)**: Toggle **Sample Data** for offline deterministic triage (zero external quota consumed) or **Live API** to query configured threat intelligence providers.
   - **Standard vs Bulk Input Mode**:
     - **Standard Mode**: Enter single or comma/space/newline-separated IPs, domains, URLs, or hashes (supports defanged syntax like `1[.]2[.]3[.]4` and `hxxps://evil[.]com`), or click **Import CSV** to load from `.csv`/`.txt`.
     - **Bulk Input Mode**: Paste multiple indicators separated by **newlines** into the multi-line editor, inspect the real-time **lines / valid / invalid** indicator counts, click **Split to Lines** or **Clean & Deduplicate** to normalize mixed input, and run simultaneous concurrent provider enrichment across the entire batch into a consolidated **Unified Batch** table.
   - **Live Mode (Periodic Background Polling)**:
     - Toggle the **Live Mode** switch ON whenever you have active indicators to continuously monitor for score or verdict changes in the background.
     - Choose a polling cadence (`15s`, `30s`, `60s`, or `5m`), watch the real-time **`Next refresh in Xs (HH:MM:SS UTC)`** countdown and last-refresh timestamp in the status strip, or click **Refresh Now** for an immediate poll without creating duplicate history cards or redundant CSV reports.
   - **Providers, Risk Threshold & Inspection**: Select active providers (**VirusTotal**, **AbuseIPDB**, **AlienVault OTX**, **ThreatFox**, **URLScan**, plus enabled custom sources), dial the **Risk Threshold** slider (`0–100` with `All`, `25+`, `50+`, `75+` presets) to hide low-impact IOCs from both the **Summary Matrix** and **Unified Batch** tables, inspect the **Confidence Score Legend**, per-row **Historical Confidence Trend Mini-Sparklines** (highlighting rising `Emerging` threat signals across past CSV reports, history, and Live Mode polls), D3 **Attack Infrastructure Network Graph**, and **Chronological IOC Activity Timeline** (`Creation Date`, `Domain Registered`, `First Seen`, `Last Seen`, `Last Reported`, `Last Analysis`).
   - **Interactive Column Sorting, Last Seen, Quick Copy, Tagging, Auto-Saved Notes & Export Dropdown**: Click any sortable column header (**`Indicator`**, **`Type`**, **`Source`**, **`Verdict`**, **`Risk Score`**, **`Last Seen`**, **`Score`**, or **`Hits`**) in either the **Summary Matrix** or **Unified Batch** table to toggle ascending/descending order (`aria-sort` + directional indicators) for rapid threat prioritization. Click the inline **Copy to Clipboard** icon next to any indicator value in every row to copy the raw IOC (`1.2.3.4`, `evil.com`, hash) for external security tools (or use **Copy** for the formatted provider summary). Click **`+ Tag`** on any row or IOC card to assign presets (`Phishing`, `Malware`, `Critical`, `C2`, `Ransomware`, `False Positive`) or custom labels, filter results by tag and verdict, and record **Researcher Notes**—which **auto-save periodically to `localStorage`** (with debounced writes, a 3-second periodic timer, and `beforeunload` flush, showing `"Auto-saved to local storage · HH:MM:SS UTC"`). Open the **`Export Data`** dropdown menu to export the currently sorted & filtered table view to **`Export CSV (.csv)`**, **`Export JSON (.json)`**, or **`Export TXT Report (.txt)`**, click **`Print / PDF`** for a clean print-formatted PDF layout via `@media print` rules in `index.css`, or export the complete workbench bundle via **Export Full Session**.
   - **Tabbed Sidebar (`Recent` & Persistent `Watchlist`)**:
     - **Recent**: Browse local investigation history with right-click **Pin / Rename / Delete**, tag filtering, and D3 heatmap geographic region filtering.
     - **Watchlist**: Monitor specific IOCs persistently across browser reloads—add indicators manually or toggle **`Watch`** / **`Watching`** on any results row or IOC card, run **Check Updates** on demand (or let Live Mode / enrichment polls re-evaluate monitored IOCs), view status/score transition deltas (`Verdict Clean -> Malicious · Score 0 -> 79`), and clear unread counters from the red **notification badge** on the Watchlist tab.

2. **Reports (`Alt+2`)**
   - Review SOC **Quick Stats** KPIs, the real-time **Live Activity** scrollable feed, verdict distribution charts, **30-day alert trendline**, D3 **Relationship Graph**, D3 **Real-Time Threat Landscape World Map**, and interactive D3 **Geographic Region IOC Heatmap**.
   - **Live Activity Scrollable Feed (`LiveActivityFeed`)**: Streams real-time **Threat Alerts** (high-confidence detections and threshold emails), **Investigations** (completed enrichments and saved CSV runs), and **System Events** (`logs/soti.log` telemetry and rate-limit events) over Server-Sent Events (`/api/activity/stream`) into a bounded scrollable feed (`max-h-[300px] overflow-y-auto`). Filter by category tabs (`All Activity`, `Threat Alerts`, `Investigations`, `System Events`), search inline, pause/resume the live stream, or click **Filter IOC** / **Open Run** to pivot immediately.
   - **Dashboard Relationship Graph (`RelationshipGraphWidget`)**: Interactive D3 force-directed network map connecting IPs, shared domains, file hashes, malware families, and ASN infrastructure across **`All Runs & Active`**, **`Selected Run`**, or **`Active Session`**. Toggle **`Shared Links Only`** or click any **`Shared Infrastructure Hubs`** spotlight button (`1.2.3.4`, `evil.com`, `eicar.com`, etc.) to highlight cross-indicator hubs with dashed amber rings and inspect connected entities with **Copy Value** and **Filter Reports** actions.
   - **Real-Time D3 World Map (`ThreatLandscapeWidget`)**: Displays geolocated active IOC origin points overlaid on a Natural Earth projection with optional 30-second **Real-Time Sync** polling; hover any **continental landmass region** or **origin marker** to inspect live threat counts, peak confidence score, and top source countries, or switch scopes (`Active IOCs (Real-Time)`, `All Runs`, `Selected Run`, `Current Investigation`) and confidence thresholds.
   - Click any geographic region label or cell on the heatmap and choose **Filter Recent Investigations** to pivot directly to matching IOCs in the Investigate sidebar.
   - Click **Generate Summary** to draft a natural-language executive summary via Gemini AI (`GEMINI_API_KEY` server-side).
   - Click **Share Report** to create a temporary expiring share link (`/?share=<token>`, TTL options from 1 hour to 7 days) alongside a copy-ready team summary message.
   - Click **Download PDF** or **Export Aggregated CSV**, tune **Auto-refresh** (`60s` default), and adjust table **Density** (`Compact`, `Normal`, `Spacious`).

3. **Scheduled (`Alt+3`)**
   - Create recurring interval monitoring jobs across IOCs and sources, inspect next-run timers, or execute due schedules immediately.

4. **Logs (`Alt+4`)**
   - Inspect real-time audit logs (`logs/soti.log`), API lookup outcomes, rate-limit warnings, and quota failover events.

5. **CLI & APIs (`Alt+5`)**
   - Add, update, or clear Threat Intel API keys directly in the GUI, configure email threshold alerts (`EmailAlertSettingsPanel`), monitor daily API quota headroom, inspect CLI command presets, and register custom provider endpoints.

### Global Keyboard Shortcuts

Press `Shift+?` anywhere outside text inputs (or click the keyboard icon in the top bar) to view all shortcuts:

| Shortcut | Action |
| :--- | :--- |
| `Ctrl+K` / `Cmd+K` or `/` | Focus **Global Search** across IOCs, reports, schedules, and logs |
| `Ctrl+I` / `Cmd+I` | Switch to **Investigate** and focus the IOC input box |
| `Alt+1` – `Alt+5` | Switch between **Investigate**, **Reports**, **Scheduled**, **Logs**, and **CLI & APIs** |
| `Alt+T` | Toggle **Light / Dark** theme |
| `Shift+?` | Open or close the **Keyboard Shortcuts** reference modal |
| `Esc` | Dismiss active modals or drawers |

---

## 6. Python CLI Usage (`main.py`)

With `(venv)` activated:

### Interactive Menu Mode
```bash
# Live API lookups
python main.py

# Offline deterministic demo mode (no API quota consumed)
python main.py --demo
```

### Non-Interactive CLI Commands
```bash
# Query multiple defanged/standard indicators across all configured sources
python main.py --source all --indicators "1[.]2[.]3[.]4, hxxp://evil[.]com, 44d88612fea8a8f36de82e1278abb02f"

# Query a single IP address using VirusTotal only
python main.py --source vt --indicators 8.8.8.8

# Load indicators from a text or CSV file
python main.py --source all --file indicators.txt

# Offline simulation with machine-readable JSON output
python main.py --source all --indicators "8.8.8.8, evil[.]com" --demo --json
```

### Scheduled Checks via CLI
```bash
python main.py --add-schedule --schedule-name "Critical IOC Watch" --source all --indicators "1[.]2[.]3[.]4, evil[.]com" --interval 60
python main.py --list-schedules
python main.py --run-due
python main.py --remove-schedule <SCHEDULE_ID>
```

---

## 7. Recently Added Features

- **Interactive Sortable Results Columns & `Last Seen` Telemetry (`InvestigateView` & `resultsTable`)**: Clickable ascending/descending column sorting (`Indicator`, `Risk Score`, `Last Seen`, `Type`, `Source`, `Verdict`, `Score`, and `Hits`) across both the **Summary Matrix** and **Unified Batch** tables with accessible `aria-sort` state, active sort arrow indicators, deterministic N/A-last ranking, and a dedicated **`Last Seen`** UTC observation timestamp column extracted from provider telemetry (`Last Seen`, `Last Reported`, `Last Analysis`, `Updated`).
- **`Export Data` Multi-Format Dropdown (`CSV`, `JSON`, `TXT Report`)**: Replaced separate export triggers with a unified **`Export Data`** dropdown menu in **InvestigateView** allowing analysts to export the **currently sorted & filtered view** as **`Export CSV (.csv)`**, **`Export JSON (.json)`**, or a human-readable **`Export TXT Report (.txt)`** (`soti_report_*.txt`) complete with active filter metadata, sort order, verdict breakdown, confidence scores, `Last Seen` timestamps, tags, and **Researcher Notes**.
- **Researcher Notes Periodic Auto-Save (`InvestigateView` & `notesAutoSave`)**: Analyst findings typed into the **Researcher Notes** panel are automatically persisted to `localStorage` (`soti_researcher_notes_autosave_v1` + recent run history sync) via fast debounced writes, a **3-second periodic interval**, and `pagehide` / `beforeunload` flushes—requiring zero manual Save clicks while keeping live `"Auto-saving..."` / `"Auto-saved to local storage · HH:MM:SS UTC"` feedback and cross-reload restoration.
- **Dedicated Print-Friendly Investigation View (`Print / PDF` & `index.css` `@media print`)**: Added a dedicated **`Print / PDF`** button in the **Summary Matrix** toolbar that triggers the browser print dialog (`window.print()`) with curated A4 landscape `@media print` rules in `src/index.css`—hiding navigation/input chrome, adding a print report header, expanding full multi-line **Researcher Notes**, preserving confidence legends/sparklines, chronological timelines, and D3 relationship graphs, and normalizing Dark Mode surfaces to high-contrast light paper ink.
- **Real-Time `Live Activity` Scrollable Feed (`LiveActivityFeed` & `/api/activity/stream`)**: Scrollable dashboard event stream backed by Server-Sent Events (SSE) and `/api/activity` snapshot aggregation that updates in real time whenever threat alerts trigger, enrichments complete, CSV reports are saved, or provider logs record telemetry—complete with stream pause/resume, category tabs (`Threat Alerts`, `Investigations`, `System Events`), search filtering, and quick **Filter IOC / Open Run** pivots.
- **Dashboard D3 `Relationship Graph` (`RelationshipGraphWidget` & `iocGraph`)**: Force-directed D3 network visualization uniting IPs, shared domains, file hashes, malware families (`LummaStealer`, `CobaltStrike`, `AgentTesla`, etc.), and ASN hosts across runs and the active session, featuring **`Shared Links Only`** hub filtering, clickable **`Shared Infrastructure Hubs`** spotlight chips, dashed amber hub rings, zoom/drag physics, and a **Selected Entity Inspector**.
- **Risk Threshold Confidence Slider (`InvestigateView` & `riskScoring`)**: Persistent `0–100` minimum confidence slider with quick-jump presets (`All`, `25+`, `50+`, `75+`), active filter banner (`Hidden X low-risk`), and one-click reset that hides low-impact IOCs from both the **Summary Matrix** and **Unified Batch** tables across Standard and Bulk Input modes.
- **Per-Row Copy to Clipboard Quick Action (`InvestigateView`)**: Dedicated inline clipboard icon button (`Copy indicator value`) placed beside every indicator in both the **Summary Matrix** and **Unified Batch** results tables, enabling instant one-click copying of raw IOCs into SIEMs, firewalls, or EDR tools with visual confirmation.
- **Real-Time D3 World Map Visualization (`ThreatLandscapeWidget`)**: Interactive Natural Earth world map plotting active IOC origin points with **Real-Time Sync** auto-polling, hover tooltips across **continental landmass regions** and **origin markers** displaying live threat counts and top countries, plus risk threshold and scope filters.
- **Persistent `Watchlist` Sidebar Tab (`WatchlistSidebarTab`)**: Dedicated monitored-IOC tab persisted in `localStorage` with one-click **`Watch`** row/card toggles, manual IOC addition, on-demand **Check Updates**, verdict/confidence transition history, and an unread **notification badge** whenever new threat telemetry changes a watched indicator's status.
- **Per-Indicator Tagging & In-Results Triage Filtering (`InvestigateView`)**: Assign preset (`Phishing`, `Malware`, `False Positive`, `Critical`, `C2`, `Ransomware`) or custom labels directly from table rows (`+ Tag`) and IOC detail cards, then filter both active results tables and **Recent Investigations** by tag.
- **Historical Confidence Trend Mini-Sparklines (`ConfidenceSparkline`)**: Inline SVG mini-sparkline in the **Trend** column of the Unified Batch and Summary Matrix tables plotting an IOC's weighted confidence history across archived CSV runs, local history, and Live Mode polls with net delta and `Emerging` threat indicators.
- **Bulk Input Mode (Newline-Separated Multi-IOC Processing)**: Dedicated multi-line Bulk Input editor supporting newline-separated normal and defanged indicators, live line/valid counts, one-click **Split to Lines** / **Clean & Deduplicate**, and simultaneous concurrent provider enrichment into a unified batch results table.
- **Live Mode Periodic Background Polling & Next-Refresh Countdown**: Dedicated **Live Mode** toggle switch with configurable polling intervals (`15s`, `30s`, `60s`, `5m`), a real-time **Next refresh (`Xs` / `HH:MM:SS UTC`)** countdown bar, manual **Refresh Now**, and in-place history updates without generating duplicate CSV report files.
- **GUI Threat-Intel API Key Manager**: Add, update, mask (`••••xxxx`), or clear provider API keys directly from the **CLI & APIs** tab with server-side persistence (`config/provider_keys.json`).
- **Gemini AI Executive Summary (`Generate Summary`)**: Drafts concise SOC executive briefings in **ReportsView** from visible KPIs, charts, and enriched IOC records via server-side `@google/genai`.
- **Interactive D3 Geographic Heatmap Filtering**: Click regions or cells in the **IocRegionHeatmap** to filter **Recent Investigations** to indicators originating from that geography.
- **Temporary Report Sharing (`Share Report`)**: Generates expiring server-backed share URLs (`/?share=<token>`) with pre-populated team clipboard messages and a shared snapshot banner.
- **Chronological IOC Activity Timeline (`IocEventTimeline`)**: Plots first-seen, last-seen, domain registration, and last-analysis UTC timestamps per IOC with indicator filters and chronological sort order toggle.
- **Confidence Score Legend & Structured CSV/JSON Export**: Visual threat-tier legend (`Low`, `Medium`, `High`, `Critical`, `Unknown`) plus **Export to CSV**, **Download JSON** (with confidence scores), and **Export Full Session** bundles.
- **ThreatFox & URLScan.io Providers + Weighted Risk Scoring**: Dedicated ThreatFox & URLScan enrichment toggles, unified 0–100 confidence calculation, and **D3 Network Graph** + **Threat Landscape** visualizations.
- **Investigation Organization & Alerting**: Custom IOC **Tags**, **Researcher Notes**, **Recent Investigations** right-click context menu (`Pin`, `Rename`, `Delete`), **Download PDF** report capture (`jsPDF` + `html2canvas`), SMTP threshold **Email Alerts**, and the **Global Keyboard Shortcut Manager** with persistent footer hints.

---

## 8. Project Screenshots & Visual Walkthrough

All screenshots below were captured directly from the running SoTI Web Workbench (`http://localhost:3000`) at desktop viewport resolution (`1440×900`):

### Investigation Workbench & Input Controls
![SoTI Investigation Workbench](docs/screenshots/investigate-workbench.png)

*Main **Investigate** workspace displaying the **Standard / Bulk Input** mode switcher, **Sample Data / Live API** execution controls, **Live Mode** background polling selector, live daily provider quota bars, automatic defanged IOC recovery (`1[.]2[.]3[.]4`, `hxxps://evil[.]com/login`), provider selector strip, **Risk Threshold** slider, and **Recent Investigations** history sidebar.*

### Results Matrix, Risk Threshold Slider, Sparklines & Quick Copy
![SoTI Results Matrix with Risk Threshold and Copy Actions](docs/screenshots/investigate-results-matrix.png)

*Enriched **Summary Matrix** with clickable ascending/descending column sorting (**`Indicator`**, **`Type`**, **`Source`**, **`Verdict`**, **`Risk Score`**, **`Last Seen`**, **`Score`**), the **Risk Threshold** confidence filter bar (`0–100` slider and `All`, `25+`, `50+`, `75+` presets), color-coded **Confidence Score Legend**, per-row inline **Copy to Clipboard** buttons beside every indicator value, **Trend** confidence sparklines, **`+ Tag`** / **`Watch`** triage controls, and **`Export Data` (`CSV` / `JSON` / `TXT Report`)**, **`Print / PDF`**, and **`Export Full Session`** controls.*

### Real-Time `Live Activity` Scrollable Feed (`Reports` Dashboard)
![SoTI Live Activity Feed](docs/screenshots/dashboard-live-activity.png)

*Real-time **Live Activity** feed mounted beneath the SOC **Quick Stats** KPI cards on the **Reports** dashboard, showing **Live Stream Active** SSE status, alert/run/system-event counters, category filter tabs (`All Activity`, `Threat Alerts`, `Investigations`, `System Events`), inline search, and direct **Filter IOC** / **Open Run** pivots.*

### Dashboard D3 `Relationship Graph` & Shared Infrastructure Hubs
![SoTI D3 Relationship Graph](docs/screenshots/dashboard-relationship-graph.png)

*Force-directed D3 **Relationship Graph** linking IPs, shared domains (`evil.com`), malicious file hashes (`44d88612fea8a8f36de82e1278abb02f` / `eicar.com`), ASNs, and malware families (`LummaStealer`, `CobaltStrike`, `AgentTesla`) with **Shared Infrastructure Hubs** spotlight buttons, **Shared Links Only** filtering, and the **Selected Entity Inspector**.*

### Real-Time D3 Threat Landscape World Map (`Reports` Tab)
![SoTI Real-Time D3 Threat Landscape World Map](docs/screenshots/reports-world-map.png)

*Interactive Natural Earth **Threat Landscape** D3 widget on the **Reports** dashboard with **Real-Time Sync**, severity-colored origin clusters, hover highlighting on continental landmasses (showing live threat counts, peak risk score, and country breakdown), and **Regional Threat Clusters** drill-down cards.*

### Persistent IOC Watchlist & Status-Change Alerts
![SoTI Persistent Watchlist Sidebar](docs/screenshots/watchlist-sidebar.png)

*Tabbed **Watchlist** sidebar showing an active unread **notification badge (`1`)**, tracked indicator verdict and confidence score (`1.2.3.4 · Malicious · 69/100`), status-transition delta banner (`Verdict Clean -> Malicious · Score 0 -> 69 (+69)`), and on-demand **Check Updates / Mark Read** controls.*

### GUI Threat-Intel API Key Manager & Quota Ledger (`CLI & APIs` Tab)
![SoTI CLI & APIs Key Manager](docs/screenshots/cli-api-settings.png)

*Centralized **CLI & APIs** configuration view for saving, testing, masking (`••••238b`), or clearing provider API keys directly in the GUI alongside live daily quota meters and automatic failover rules.*

---

## 9. Source Support & Default Verdict Thresholds

| Source | IP | Domain | Hash | Malicious | Suspicious | Clean |
| :--- | :---: | :---: | :---: | :--- | :--- | :--- |
| **VirusTotal** | Yes | Yes | Yes | ≥ 5 engines | 1–4 malicious or any suspicious | 0 detections |
| **AbuseIPDB** | Yes | No | No | Confidence ≥ 75% | 25–74% | < 25% |
| **AlienVault OTX** | Yes | Yes | Yes | ≥ 5 pulses | 1–4 pulses | 0 pulses = `Unknown` |
| **ThreatFox / URLScan** | Yes | Yes | Yes | Active malware / verdict hit | Suspicious tag / score | Benign / no hit |

---

## 10. Directory Structure

```text
SoTI/
├── .github/
│   └── workflows/
│       └── main.yml                        # CI workflow for Python CLI & Node/React build
├── api/                                    # Python threat intelligence API clients
│   ├── __init__.py                         # IOC refanging & classification (ip/domain/hash/url)
│   ├── virustotal.py                       # VirusTotal v3 client
│   ├── abuseipdb.py                        # AbuseIPDB v2 client
│   └── alienvault.py                       # AlienVault OTX client
├── config/                                 # Runtime settings, schedules, quotas & alert state
│   ├── __init__.py
│   ├── settings.py                         # Paths, version, and Python CLI defaults
│   ├── scheduler.py                        # Recurring schedule evaluation engine
│   ├── email_alerts_config.json            # Threshold email alert rules
│   ├── email_alerts_log.json               # Dispatched alert history
│   ├── quota_usage.json                    # Daily provider quota ledger for failover
│   └── schedules.json                      # Persisted scheduled IOC checks
├── docs/
│   └── screenshots/                        # Curated Web Workbench UI screenshots for README.md
├── logs/                                   # Runtime audit logs (created at runtime)
│   └── soti.log
├── reports/                                # Saved enrichment CSV exports (created at runtime)
├── src/                                    # React + TypeScript + Tailwind CSS Web Workbench
│   ├── App.tsx                             # Root shell, theme, shortcuts, share loader, search
│   ├── index.css                           # Tailwind CSS configuration, design tokens & @media print rules
│   ├── main.tsx                            # React DOM mount entry point
│   ├── components/
│   │   ├── CliSetupView.tsx                # CLI setup, GUI API key manager & custom sources
│   │   ├── ConfidenceSparkline.tsx         # Inline SVG historical confidence trend mini-sparkline
│   │   ├── EmailAlertSettingsPanel.tsx     # Threshold-based SMTP alert rules UI
│   │   ├── HelpModal.tsx                   # Workbench onboarding & provider setup guide
│   │   ├── IndicatorFileUpload.tsx         # Local .csv/.txt IOC upload & parser
│   │   ├── InvestigateView.tsx             # Standard/Bulk Input, Live Mode, auto-saved notes, Print/PDF, exports
│   │   ├── IocEventTimeline.tsx            # Chronological UTC activity timeline component
│   │   ├── IocNetworkGraph.tsx             # D3 force-directed IOC relationship graph
│   │   ├── IocRegionHeatmap.tsx            # D3 interactive geographic IOC heatmap & filter
│   │   ├── KeyboardShortcutsModal.tsx      # Categorized global shortcuts reference modal
│   │   ├── LiveActivityFeed.tsx            # Real-time SSE scrollable alerts & telemetry feed
│   │   ├── LogsView.tsx                    # Real-time audit & failover log viewer
│   │   ├── NotificationCenter.tsx          # Quota warning & workspace alert drawer
│   │   ├── RecentInvestigationsSidebar.tsx # Context-menu history, pin/rename/tag/region filter
│   │   ├── RelationshipGraphWidget.tsx     # Dashboard D3 force-directed IOC relationship graph
│   │   ├── ReportsView.tsx                 # KPIs, charts, Live Activity, Relationship Graph, AI summary & Share modal
│   │   ├── ScheduledView.tsx               # Recurring schedule manager UI
│   │   ├── ThreatLandscapeWidget.tsx       # Real-time D3 world map, region hover & threat clusters
│   │   ├── TopBar.tsx                      # Navigation tabs, global search, provider status, theme
│   │   └── WatchlistSidebarTab.tsx         # Persistent IOC watchlist monitor & update badge UI
│   └── utils/                              # Pure TypeScript business logic & node:test suites
│       ├── apiConfig.ts / .test.ts         # Threat-intel key validation, masking & provider rules
│       ├── bulkAnalysis.ts / .test.ts      # Multi-IOC batch runner state & progress
│       ├── bulkCsv.ts / .test.ts           # CSV/TXT IOC extraction & refanging
│       ├── clipboard.ts                    # Safe clipboard helper
│       ├── confidenceTrend.ts / .test.ts   # Historical confidence series & emerging threat analyzer
│       ├── emailAlerts.ts / .test.ts       # Confidence threshold alert evaluation
│       ├── enrichmentProviders.ts/.test.ts # Shodan, ThreatFox & URLScan parsers/samplers
│       ├── globalSearch.ts / .test.ts      # Cross-workbench search index & filtering
│       ├── heatmapAnalytics.ts / .test.ts  # Geographic region aggregation & history filter
│       ├── indicators.ts / .test.ts        # Frontend IOC parser & validator
│       ├── investigationHistory.ts/.test.ts# Local history store, pin/rename/delete helpers
│       ├── iocGraph.ts / .test.ts          # Network graph node/edge transformation
│       ├── iocTags.ts / .test.ts           # Custom IOC tag CRUD & filter logic
│       ├── iocTimeline.ts / .test.ts       # Chronological timestamp extractor & sorter
│       ├── keyboardShortcuts.ts / .test.ts # Shortcut key matching & spec registry
│       ├── liveActivity.ts / .test.ts      # Real-time activity event parsers, mergers & filters
│       ├── livePolling.ts / .test.ts       # Live Mode polling intervals, countdown & delta tracking
│       ├── notesAutoSave.ts / .test.ts     # Researcher Notes periodic localStorage auto-save helpers
│       ├── notifications.ts / .test.ts     # Quota threshold & alert notifications
│       ├── quota.ts / .test.ts             # Daily quota & failover calculation
│       ├── reportPdf.ts / .test.ts         # jsPDF + html2canvas export preparation
│       ├── reportSharing.ts / .test.ts     # Expiring report snapshot & clipboard formatter
│       ├── reportsAnalytics.ts / .test.ts  # Verdict, confidence, and 30-day trend aggregation
│       ├── resultsExport.ts / .test.ts     # Visible table CSV, JSON & formatted TXT report builders
│       ├── resultsTable.ts / .test.ts      # Results table column sorting & Last Seen UTC extraction
│       ├── riskScoring.ts / .test.ts       # Weighted multi-provider confidence scoring
│       ├── scheduler.ts / .test.ts         # Frontend schedule interval formatting
│       ├── sessionExport.ts / .test.ts     # Portable full-session JSON serializer
│       ├── theme.ts / .test.ts             # Light/Dark theme persistence
│       ├── threatLandscape.ts / .test.ts   # D3 world map region summaries & cluster aggregation
│       └── watchlist.ts / .test.ts         # Persistent watchlist state & status-change evaluator
├── tests/
│   └── test_soti.py                        # Python CLI unit tests
├── .env.example                            # API key & optional SMTP/Gemini template
├── .gitattributes                          # Line-ending & binary PNG attributes for GitHub rendering
├── index.html                              # HTML entry document
├── main.py                                 # Python CLI entry point
├── package.json                            # Node dependencies & scripts (`dev`, `build`, `start`, `lint`)
├── requirements.txt                        # Python dependencies
├── server.ts                               # Express API server & Vite host (port 3000)
├── tsconfig.json                           # TypeScript compiler configuration
├── vite.config.ts                          # Vite configuration
└── README.md                               # Project documentation
```

---

## 11. Testing & Verification

```bash
# TypeScript unit tests, ESLint/type check, and production bundle
npx --yes tsx --test src/utils/*.test.ts
npm run lint
npm run build

# Python CLI syntax check & unit tests
python -m py_compile main.py api/*.py config/*.py tests/*.py
python -m unittest discover -s tests -v
```

---

## Disclaimer

For defensive security operations and authorized SOC triage use only.
