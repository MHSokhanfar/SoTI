"""Recurring check scheduling module for SoTI CLI config.

Created and developed by Mohammad Hossein Sokhanfar.
Repository: https://github.com/MHSokhanfar/SoTI
"""
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
SCHEDULES_FILE = BASE_DIR / "config" / "schedules.json"

MIN_INTERVAL_MINUTES = 5
MAX_INTERVAL_MINUTES = 43200  # 30 days
VALID_SOURCES = ("all", "virustotal", "abuseipdb", "alienvault")
VALID_PROVIDER_IDS = ("virustotal", "abuseipdb", "alienvault")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        cleaned = value.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        parsed = datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def compute_next_run(from_dt: datetime, interval_minutes: int) -> str:
    return format_iso(from_dt + timedelta(minutes=interval_minutes))


def normalize_indicators_list(raw_indicators: object) -> List[str]:
    if isinstance(raw_indicators, str):
        tokens = [t.strip() for t in re.split(r"[,\s;]+", raw_indicators) if t.strip()]
    elif isinstance(raw_indicators, Iterable):
        tokens = [str(t).strip() for t in raw_indicators if str(t).strip()]
    else:
        tokens = []

    seen = set()
    unique: List[str] = []
    for tok in tokens:
        if tok not in seen:
            seen.add(tok)
            unique.append(tok)
    return unique


def normalize_schedule_entry(entry: dict) -> Optional[dict]:
    if not isinstance(entry, dict):
        return None

    name = str(entry.get("name", "")).strip()
    indicators = normalize_indicators_list(entry.get("indicators", []))
    if not name or not indicators:
        return None

    raw_interval = entry.get("intervalMinutes", 60)
    try:
        interval_minutes = int(raw_interval)
    except (TypeError, ValueError):
        interval_minutes = 60
    interval_minutes = max(MIN_INTERVAL_MINUTES, min(MAX_INTERVAL_MINUTES, interval_minutes))

    source = str(entry.get("source", "all")).strip().lower()
    if source not in VALID_SOURCES:
        source = "all"

    raw_sources = entry.get("sources")
    if isinstance(raw_sources, list):
        sources = [s for s in raw_sources if s in VALID_PROVIDER_IDS]
    else:
        sources = list(VALID_PROVIDER_IDS) if source == "all" else [source]
    if not sources:
        sources = list(VALID_PROVIDER_IDS) if source == "all" else [source]

    mode = str(entry.get("mode", "live")).strip().lower()
    if mode not in ("live", "sample"):
        mode = "live"

    now_iso = format_iso(_utc_now())
    created_at = str(entry.get("createdAt") or now_iso)
    updated_at = str(entry.get("updatedAt") or created_at)
    last_run_at = entry.get("lastRunAt") if isinstance(entry.get("lastRunAt"), str) else None
    next_run_at = entry.get("nextRunAt") if isinstance(entry.get("nextRunAt"), str) else None

    if not next_run_at:
        base_dt = parse_iso(last_run_at) or _utc_now()
        next_run_at = compute_next_run(base_dt, interval_minutes)

    last_status = str(entry.get("lastStatus") or "idle")
    if last_status not in ("idle", "success", "partial", "error"):
        last_status = "idle"

    try:
        run_count = max(0, int(entry.get("runCount", 0)))
    except (TypeError, ValueError):
        run_count = 0

    return {
        "id": str(entry.get("id") or f"sched-{uuid.uuid4().hex[:8]}"),
        "name": name[:80],
        "indicators": indicators,
        "source": source,
        "sources": sources,
        "intervalMinutes": interval_minutes,
        "enabled": bool(entry.get("enabled", True)),
        "mode": mode,
        "createdAt": created_at,
        "updatedAt": updated_at,
        "lastRunAt": last_run_at,
        "nextRunAt": next_run_at,
        "lastStatus": last_status,
        "lastReportFile": entry.get("lastReportFile") if isinstance(entry.get("lastReportFile"), str) else None,
        "lastSummary": entry.get("lastSummary") if isinstance(entry.get("lastSummary"), str) else None,
        "runCount": run_count,
    }


def load_schedules(schedules_file: Path = SCHEDULES_FILE) -> List[dict]:
    if not schedules_file.is_file():
        return []
    try:
        raw = json.loads(schedules_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(raw, list):
        return []

    jobs: List[dict] = []
    for item in raw:
        norm = normalize_schedule_entry(item)
        if norm is not None:
            jobs.append(norm)
    return jobs


def save_schedules(jobs: List[dict], schedules_file: Path = SCHEDULES_FILE) -> None:
    schedules_file.parent.mkdir(parents=True, exist_ok=True)
    normalized = [n for j in jobs if (n := normalize_schedule_entry(j)) is not None]
    schedules_file.write_text(json.dumps(normalized, indent=2) + "\n", encoding="utf-8")


def add_schedule(
    name: str,
    indicators: object,
    source: str = "all",
    interval_minutes: int = 60,
    enabled: bool = True,
    mode: str = "live",
    sources: Optional[List[str]] = None,
    schedules_file: Path = SCHEDULES_FILE,
) -> dict:
    clean_name = name.strip()
    if not clean_name:
        raise ValueError("Schedule name cannot be empty.")

    ind_list = normalize_indicators_list(indicators)
    if not ind_list:
        raise ValueError("At least one indicator is required for a scheduled check.")

    if interval_minutes < MIN_INTERVAL_MINUTES or interval_minutes > MAX_INTERVAL_MINUTES:
        raise ValueError(
            f"Interval must be between {MIN_INTERVAL_MINUTES} and {MAX_INTERVAL_MINUTES} minutes."
        )

    src_norm = source.strip().lower()
    if src_norm not in VALID_SOURCES:
        raise ValueError(f"Unsupported source '{source}'. Choose one of: {', '.join(VALID_SOURCES)}.")

    now = _utc_now()
    entry = normalize_schedule_entry({
        "id": f"sched-{uuid.uuid4().hex[:8]}",
        "name": clean_name,
        "indicators": ind_list,
        "source": src_norm,
        "sources": sources if sources is not None else (list(VALID_PROVIDER_IDS) if src_norm == "all" else [src_norm]),
        "intervalMinutes": interval_minutes,
        "enabled": enabled,
        "mode": mode,
        "createdAt": format_iso(now),
        "updatedAt": format_iso(now),
        "lastRunAt": None,
        "nextRunAt": compute_next_run(now, interval_minutes),
        "lastStatus": "idle",
        "lastReportFile": None,
        "lastSummary": "Scheduled check awaiting first execution",
        "runCount": 0,
    })
    assert entry is not None

    jobs = load_schedules(schedules_file)
    jobs.insert(0, entry)
    save_schedules(jobs, schedules_file)
    return entry


def remove_schedule(job_id: str, schedules_file: Path = SCHEDULES_FILE) -> bool:
    jobs = load_schedules(schedules_file)
    filtered = [j for j in jobs if j["id"] != job_id]
    if len(filtered) == len(jobs):
        return False
    save_schedules(filtered, schedules_file)
    return True


def toggle_schedule(
    job_id: str,
    enabled: Optional[bool] = None,
    schedules_file: Path = SCHEDULES_FILE,
) -> Optional[dict]:
    jobs = load_schedules(schedules_file)
    updated: Optional[dict] = None
    now = _utc_now()

    for job in jobs:
        if job["id"] == job_id:
            next_enabled = (not job["enabled"]) if enabled is None else bool(enabled)
            job["enabled"] = next_enabled
            job["updatedAt"] = format_iso(now)
            if next_enabled:
                job["nextRunAt"] = compute_next_run(now, job["intervalMinutes"])
            updated = job
            break

    if updated is not None:
        save_schedules(jobs, schedules_file)
    return updated


def is_schedule_due(job: dict, now: Optional[datetime] = None) -> bool:
    if not job.get("enabled"):
        return False
    check_now = now or _utc_now()
    next_dt = parse_iso(job.get("nextRunAt"))
    if next_dt is None:
        return True
    return next_dt <= check_now


def get_due_schedules(
    now: Optional[datetime] = None,
    schedules_file: Path = SCHEDULES_FILE,
) -> List[dict]:
    check_now = now or _utc_now()
    return [job for job in load_schedules(schedules_file) if is_schedule_due(job, check_now)]


def run_due_schedules(
    executor: Callable[[dict], tuple],
    now: Optional[datetime] = None,
    schedules_file: Path = SCHEDULES_FILE,
) -> List[dict]:
    """Run all enabled schedules due as of `now`.

    `executor(job)` returns `(results, report_file_name)`.
    """
    check_now = now or _utc_now()
    jobs = load_schedules(schedules_file)
    executed: List[dict] = []

    for job in jobs:
        if not is_schedule_due(job, check_now):
            continue
        try:
            results, report_file = executor(job)
            errors = sum(1 for r in results if r.get("status") == "error")
            if results and errors == len(results):
                status = "error"
            elif errors > 0:
                status = "partial"
            else:
                status = "success"

            malicious_count = sum(1 for r in results if r.get("verdict") == "Malicious")
            suspicious_count = sum(1 for r in results if r.get("verdict") == "Suspicious")
            job["lastStatus"] = status
            job["lastReportFile"] = str(report_file) if report_file else None
            job["lastSummary"] = (
                f"{len(results)} checks completed "
                f"({malicious_count} malicious, {suspicious_count} suspicious)"
            )
        except Exception as exc:
            job["lastStatus"] = "error"
            job["lastSummary"] = f"Scheduled check failed: {exc}"

        job["lastRunAt"] = format_iso(check_now)
        job["nextRunAt"] = compute_next_run(check_now, job["intervalMinutes"])
        job["updatedAt"] = format_iso(check_now)
        job["runCount"] = int(job.get("runCount", 0)) + 1
        executed.append(job)

    if executed:
        save_schedules(jobs, schedules_file)
    return executed
