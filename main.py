#!/usr/bin/env python3
"""SoTI - Threat Intelligence Tool.

Created and developed by Mohammad Hossein Sokhanfar.
Repository: https://github.com/MHSokhanfar/SoTI
"""
import argparse
import csv
import json
import logging
import re
import sys
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path

try:
    from rich import box  # type: ignore
    from rich.console import Console  # type: ignore
    from rich.panel import Panel  # type: ignore
    from rich.table import Table  # type: ignore

    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from api import (
    abuseipdb,
    alienvault,
    clean_indicator,
    detect_indicator_type,
    make_result,
    unsupported,
    virustotal,
)
from config import scheduler, settings

console = Console() if HAS_RICH else None
log = logging.getLogger("soti")

BANNER = r"""
 ____        _____ ___
/ ___|  ___ |_   _|_ _|
\___ \ / _ \  | |  | |
 ___) | (_) | | |  | |
|____/ \___/  |_| |___|
"""

SOURCES = {
    "1": ("VirusTotal", [virustotal]),
    "2": ("AbuseIPDB", [abuseipdb]),
    "3": ("AlienVault OTX", [alienvault]),
    "4": ("All Sources", [virustotal, abuseipdb, alienvault]),
}

SOURCE_ALIASES = {
    "1": "1",
    "vt": "1",
    "virustotal": "1",
    "2": "2",
    "abuse": "2",
    "abuseipdb": "2",
    "3": "3",
    "otx": "3",
    "alienvault": "3",
    "4": "4",
    "all": "4",
}

VERDICT_STYLE = {
    "Malicious": "bold red",
    "Suspicious": "bold yellow",
    "Clean": "bold green",
    "Unknown": "dim white",
}
STATUS_STYLE = {"not_found": "cyan", "unsupported": "dim", "error": "red"}

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "bold_red": "\033[1;31m",
    "bold_yellow": "\033[1;33m",
    "bold_green": "\033[1;32m",
    "cyan": "\033[36m",
    "bold_cyan": "\033[1;36m",
    "magenta": "\033[35m",
    "white": "\033[37m",
}

VERDICT_ANSI = {
    "Malicious": ANSI["bold_red"],
    "Suspicious": ANSI["bold_yellow"],
    "Clean": ANSI["bold_green"],
    "Unknown": ANSI["dim"],
}
STATUS_ANSI = {
    "not_found": ANSI["cyan"],
    "unsupported": ANSI["dim"],
    "error": ANSI["red"],
}

CSV_FIELDS = [
    "timestamp",
    "source",
    "indicator",
    "type",
    "status",
    "verdict",
    "score",
    "summary",
    "details",
    "link",
]


def setup_logging():
    settings.LOGS_DIR.mkdir(exist_ok=True)
    logging.basicConfig(
        filename=settings.LOGS_DIR / "soti.log",
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


def show_menu():
    if HAS_RICH and console is not None:
        console.print(BANNER, style="bold red", markup=False, highlight=False)
        console.print("     THREAT INTELLIGENCE TOOL", style="bold white", highlight=False)
        console.print(f"          Version {settings.VERSION}\n", style="white")
        line = "=" * 37
        console.print(line, style="red")
        console.print()
        for key, (name, _) in SOURCES.items():
            console.print(f"[bold cyan][{key}][/] {name}", highlight=False)
        console.print()
        console.print(line, style="red")
        console.print("\nSelect Threat Intelligence Source:\n")
        return

    print(f"{ANSI['bold_red']}{BANNER}{ANSI['reset']}")
    print(f"{ANSI['bold']}     THREAT INTELLIGENCE TOOL{ANSI['reset']}")
    print(f"          Version {settings.VERSION}\n")
    print(f"{ANSI['red']}{'=' * 37}{ANSI['reset']}\n")
    for key, (name, _) in SOURCES.items():
        print(f"{ANSI['bold_cyan']}[{key}]{ANSI['reset']} {name}")
    print(f"\n{ANSI['red']}{'=' * 37}{ANSI['reset']}")
    print("\nSelect Threat Intelligence Source:\n")


def render_result(res):
    if HAS_RICH and console is not None:
        if res["status"] == "ok":
            style = VERDICT_STYLE[res["verdict"]]
            title = f"[bold]{res['source']}[/] - [{style}]{res['verdict']}[/] ({res['score']})"
        else:
            style = STATUS_STYLE.get(res["status"], "white")
            title = f"[bold]{res['source']}[/] - [{style}]{res['status'].replace('_', ' ').upper()}[/]"

        table = Table(show_header=False, box=box.SIMPLE, pad_edge=False)
        table.add_column(style="cyan", no_wrap=True)
        table.add_column(overflow="fold")
        table.add_row("Summary", res["summary"])
        for k, v in res["details"].items():
            table.add_row(str(k), str(v))
        if res["link"]:
            table.add_row("Link", res["link"])
        console.print(Panel(table, title=title, title_align="left", border_style=style))
        return

    if res["status"] == "ok":
        color = VERDICT_ANSI.get(res["verdict"], ANSI["white"])
        status_txt = f"{color}{res['verdict']}{ANSI['reset']} ({res['score']})"
    else:
        color = STATUS_ANSI.get(res["status"], ANSI["white"])
        status_txt = f"{color}{res['status'].replace('_', ' ').upper()}{ANSI['reset']}"
    print(f"{color}+-- {res['source']} - {status_txt}{ANSI['reset']}")
    print(f"  {ANSI['cyan']}Summary{ANSI['reset']}: {res['summary']}")
    for k, v in res["details"].items():
        print(f"  {ANSI['cyan']}{k}{ANSI['reset']}: {v}")
    if res["link"]:
        print(f"  {ANSI['cyan']}Link{ANSI['reset']}: {res['link']}")
    print()


def render_summary(results):
    if HAS_RICH and console is not None:
        table = Table(title="Summary", box=box.ROUNDED, header_style="bold magenta")
        for col in ("Indicator", "Type", "Source", "Verdict", "Score"):
            table.add_column(col, overflow="fold")
        for r in results:
            if r["status"] == "ok":
                verdict = f"[{VERDICT_STYLE[r['verdict']]}]{r['verdict']}[/]"
            else:
                verdict = f"[{STATUS_STYLE.get(r['status'], 'white')}]{r['status']}[/]"
            table.add_row(r["indicator"], r["type"], r["source"], verdict, r["score"])
        console.print(table)
        return

    print(f"{ANSI['magenta']}=== Summary ==={ANSI['reset']}")
    header = f"{'Indicator':<36} {'Type':<8} {'Source':<16} {'Verdict':<13} {'Score'}"
    print(header)
    print("-" * len(header))
    for r in results:
        if r["status"] == "ok":
            verdict_val = r["verdict"]
            color = VERDICT_ANSI.get(verdict_val, "")
        else:
            verdict_val = r["status"]
            color = STATUS_ANSI.get(verdict_val, "")
        ind_disp = (r["indicator"][:33] + "...") if len(r["indicator"]) > 36 else r["indicator"]
        print(
            f"{ind_disp:<36} {r['type']:<8} {r['source']:<16} "
            f"{color}{verdict_val:<13}{ANSI['reset']} {r['score']}"
        )


def save_csv(results, reports_dir: Path = settings.REPORTS_DIR):
    reports_dir.mkdir(exist_ok=True)
    path = reports_dir / f"soti_{datetime.now():%Y%m%d_%H%M%S}.csv"
    now = datetime.now().isoformat(timespec="seconds")
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "timestamp": now,
                "source": r["source"],
                "indicator": r["indicator"],
                "type": r["type"],
                "status": r["status"],
                "verdict": r["verdict"],
                "score": r["score"],
                "summary": r["summary"],
                "details": json.dumps(r["details"], ensure_ascii=False),
                "link": r["link"],
            })
    log.info("Saved CSV report with %d rows to %s", len(results), path.name)
    return path


def _demo_lookup(module, indicator: str, itype: str) -> dict:
    """Offline sample enrichment payload for --demo mode."""
    source = module.NAME
    if source == "AbuseIPDB" and itype != "ip":
        return unsupported(source, indicator, itype, itype)

    is_known_clean = indicator in ("8.8.8.8", "1.1.1.1", "google.com", "example.com")
    is_eicar = indicator == "44d88612fea8a8f36de82e1278abb02f"

    if source == "VirusTotal":
        if is_known_clean:
            return make_result(
                source, indicator, itype, "ok", "Clean", "0/93",
                "0 malicious, 0 suspicious out of 93 engines",
                {"Malicious": 0, "Suspicious": 0, "Harmless": 74, "Undetected": 19, "Reputation": 420},
                f"https://www.virustotal.com/gui/{virustotal.GUI[itype]}/{indicator}",
            )
        if is_eicar or itype == "hash":
            return make_result(
                source, indicator, itype, "ok", "Malicious", "62/68",
                "62 malicious, 0 suspicious out of 68 engines",
                {"Malicious": 62, "Suspicious": 0, "Harmless": 0, "Undetected": 6, "Threat Label": "eicar.test.file"},
                f"https://www.virustotal.com/gui/file/{indicator}",
            )
        return make_result(
            source, indicator, itype, "ok", "Malicious", "14/91",
            "14 malicious, 2 suspicious out of 91 engines",
            {"Malicious": 14, "Suspicious": 2, "Harmless": 60, "Undetected": 15, "Reputation": -38},
            f"https://www.virustotal.com/gui/{virustotal.GUI[itype]}/{indicator}",
        )

    if source == "AbuseIPDB":
        if is_known_clean:
            return make_result(
                source, indicator, itype, "ok", "Clean", "0%",
                "0 reports in last 90 days",
                {"Abuse Confidence": "0%", "Total Reports": 0, "Country": "US", "ISP": "Google LLC", "Whitelisted": True},
                f"https://www.abuseipdb.com/check/{indicator}",
            )
        return make_result(
            source, indicator, itype, "ok", "Malicious", "89%",
            "47 reports in last 90 days",
            {"Abuse Confidence": "89%", "Total Reports": 47, "Distinct Reporters": 19, "Country": "NL", "Tor": False},
            f"https://www.abuseipdb.com/check/{indicator}",
        )

    # AlienVault OTX
    if is_known_clean:
        return make_result(
            source, indicator, itype, "ok", "Unknown", "0 pulses",
            "Found in 0 OTX pulse(s)",
            {"Pulses": 0},
            f"https://otx.alienvault.com/indicator/{'file' if itype == 'hash' else itype}/{indicator}",
        )
    return make_result(
        source, indicator, itype, "ok", "Suspicious", "3 pulses",
        "Found in 3 OTX pulse(s)",
        {"Pulses": 3, "Top Pulses": "SOC Triage IOC Feed | Phishing Infrastructure"},
        f"https://otx.alienvault.com/indicator/{'file' if itype == 'hash' else itype}/{indicator}",
    )


def investigate(raw: str, modules, demo: bool = False, quiet: bool = False):
    results = []
    tokens = list(filter(None, re.split(r"[,\s;]+", raw)))
    for token in tokens:
        indicator = clean_indicator(token)
        itype = detect_indicator_type(indicator)
        if not itype:
            log.warning("Invalid indicator skipped: %s", token)
            if not quiet:
                if HAS_RICH and console is not None:
                    console.print(f"[red]Invalid indicator, skipped:[/] {token}")
                else:
                    print(f"{ANSI['red']}Invalid indicator, skipped:{ANSI['reset']} {token}")
            continue

        if not quiet:
            if HAS_RICH and console is not None:
                console.print(f"\n[bold]>> {indicator}[/] [dim]({itype})[/]")
            else:
                print(f"\n{ANSI['bold']}>> {indicator}{ANSI['reset']} {ANSI['dim']}({itype}){ANSI['reset']}")

        for module in modules:
            spinner = (
                console.status(f"Querying {module.NAME}...", spinner="dots")
                if (HAS_RICH and console is not None and not quiet)
                else nullcontext()
            )
            with spinner:
                res = _demo_lookup(module, indicator, itype) if demo else module.lookup(indicator, itype)
            if not quiet:
                render_result(res)
            results.append(res)

    csv_path = None
    if results:
        csv_path = save_csv(results)
        if not quiet:
            if HAS_RICH and console is not None:
                console.print()
                render_summary(results)
                console.print(f"\n[green]CSV report saved:[/] {csv_path}\n")
            else:
                print()
                render_summary(results)
                print(f"\n{ANSI['bold_green']}CSV report saved:{ANSI['reset']} {csv_path}\n")
    return results, csv_path


def prompt_input(prompt_text: str) -> str:
    if HAS_RICH and console is not None:
        return console.input(prompt_text).strip()
    plain = re.sub(r"\[/?[^\]]+\]", "", prompt_text)
    return input(plain).strip()


def interactive_loop(demo: bool = False):
    while True:
        show_menu()
        choice = prompt_input("[bold red]SoTI[/] > ").lower()
        if choice in ("q", "quit", "exit", "0"):
            print("Goodbye.")
            return
        if choice not in SOURCES:
            if HAS_RICH and console is not None:
                console.print("[red]Invalid choice, please select 1-4.[/]\n")
            else:
                print(f"{ANSI['red']}Invalid choice, please select 1-4.{ANSI['reset']}\n")
            continue

        name, modules = SOURCES[choice]
        if HAS_RICH and console is not None:
            console.print(f"\n[bold]Source:[/] {name}")
            console.print("Enter IP / Domain / Hash (comma or space separated). "
                          "Type [bold]back[/] to return, [bold]exit[/] to quit.\n")
        else:
            print(f"\n{ANSI['bold']}Source:{ANSI['reset']} {name}")
            print("Enter IP / Domain / Hash (comma or space separated). Type 'back' to return, 'exit' to quit.\n")

        while True:
            raw = prompt_input(f"[bold red]SoTI[/][cyan]({name})[/] > ")
            if not raw:
                continue
            if raw.lower() == "back":
                break
            if raw.lower() in ("exit", "quit", "q"):
                print("Goodbye.")
                return
            investigate(raw, modules, demo=demo)


def _modules_for_job(job: dict):
    src_key = SOURCE_ALIASES.get(str(job.get("source", "all")).lower(), "4")
    if src_key == "4" and isinstance(job.get("sources"), list):
        mapping = {"virustotal": virustotal, "abuseipdb": abuseipdb, "alienvault": alienvault}
        selected = [mapping[s] for s in job["sources"] if s in mapping]
        if selected:
            return selected
    return SOURCES[src_key][1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SoTI - Threat Intelligence Enrichment CLI"
    )
    parser.add_argument(
        "-s", "--source",
        default=None,
        help="Source: 1/vt/virustotal, 2/abuseipdb, 3/otx/alienvault, 4/all",
    )
    parser.add_argument(
        "-i", "--indicators",
        default=None,
        help="Comma or space separated indicators (supports defanged IOCs)",
    )
    parser.add_argument(
        "-f", "--file",
        default=None,
        help="Path to a text file containing indicators",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with offline sample threat intelligence responses",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON instead of terminal tables",
    )
    parser.add_argument(
        "--list-schedules",
        action="store_true",
        help="Display all configured recurring threat intelligence checks",
    )
    parser.add_argument(
        "--add-schedule",
        action="store_true",
        help="Add a recurring check for --indicators using --schedule-name and --interval",
    )
    parser.add_argument(
        "--schedule-name",
        default="Recurring Threat Check",
        help="Name for the new scheduled check",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=settings.DEFAULT_SCHEDULE_INTERVAL_MINUTES,
        help="Interval in minutes for recurring checks (5-43200, default: 60)",
    )
    parser.add_argument(
        "--remove-schedule",
        default=None,
        help="Remove a scheduled check by job ID",
    )
    parser.add_argument(
        "--run-due",
        action="store_true",
        help="Execute all currently due enabled recurring checks",
    )
    return parser


def main(argv=None):
    setup_logging()
    args = build_parser().parse_args(argv)

    if args.list_schedules:
        jobs = scheduler.load_schedules()
        if args.json:
            print(json.dumps({"schedules": jobs}, indent=2))
            return 0
        if not jobs:
            print("No scheduled checks configured.")
            return 0
        for j in jobs:
            state = "ACTIVE" if j["enabled"] else "PAUSED"
            print(
                f"[{j['id']}] {j['name']} | {state} | every {j['intervalMinutes']}m | "
                f"next: {j.get('nextRunAt') or 'now'} | IOCs: {', '.join(j['indicators'])}"
            )
        return 0

    if args.remove_schedule:
        removed = scheduler.remove_schedule(args.remove_schedule)
        if not removed:
            print(f"Schedule not found: {args.remove_schedule}", file=sys.stderr)
            return 1
        print(f"Removed schedule: {args.remove_schedule}")
        return 0

    if args.add_schedule:
        raw_ind = args.indicators or ""
        if args.file:
            file_path = Path(args.file)
            if not file_path.is_file():
                print(f"File not found: {args.file}", file=sys.stderr)
                return 1
            raw_ind = f"{raw_ind} {file_path.read_text(encoding='utf-8')}".strip()
        src_key = SOURCE_ALIASES.get((args.source or "all").strip().lower())
        if not src_key:
            print("Invalid --source. Choose virustotal, abuseipdb, alienvault, or all.", file=sys.stderr)
            return 1
        src_name_map = {"1": "virustotal", "2": "abuseipdb", "3": "alienvault", "4": "all"}
        try:
            job = scheduler.add_schedule(
                name=args.schedule_name,
                indicators=raw_ind,
                source=src_name_map[src_key],
                interval_minutes=args.interval,
                mode="sample" if args.demo else "live",
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps({"schedule": job}, indent=2))
        else:
            print(f"Added schedule [{job['id']}]: {job['name']} (every {job['intervalMinutes']}m)")
        return 0

    if args.run_due:
        executed = scheduler.run_due_schedules(
            lambda job: investigate(
                ", ".join(job["indicators"]),
                _modules_for_job(job),
                demo=args.demo or (job.get("mode") == "sample"),
                quiet=args.json,
            )
        )
        if args.json:
            print(json.dumps({"executed": executed}, indent=2))
        elif not executed:
            print("No due schedules to run.")
        return 0

    raw_indicators = args.indicators or ""
    if args.file:
        file_path = Path(args.file)
        if not file_path.is_file():
            print(f"File not found: {args.file}", file=sys.stderr)
            return 1
        raw_indicators = f"{raw_indicators} {file_path.read_text(encoding='utf-8')}".strip()

    if raw_indicators:
        src_key = SOURCE_ALIASES.get((args.source or "all").strip().lower())
        if not src_key:
            print("Invalid --source. Choose virustotal, abuseipdb, alienvault, or all.", file=sys.stderr)
            return 1
        _, modules = SOURCES[src_key]
        results, csv_path = investigate(raw_indicators, modules, demo=args.demo, quiet=args.json)
        if args.json:
            print(json.dumps({
                "results": results,
                "csv_report": str(csv_path) if csv_path else None,
            }, indent=2))
        return 0

    interactive_loop(demo=args.demo)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye.")
        sys.exit(0)

