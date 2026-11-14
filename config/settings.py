"""Central configuration for SoTI.

Created and developed by Mohammad Hossein Sokhanfar.
Repository: https://github.com/MHSokhanfar/SoTI
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_env_file(env_path: Path) -> None:
    """Load key=value pairs from .env using python-dotenv or stdlib fallback."""
    try:
        from dotenv import load_dotenv  # type: ignore

        load_dotenv(env_path)
        return
    except ImportError:
        pass

    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


_load_env_file(BASE_DIR / ".env")

VERSION = "1.0.0"

_PLACEHOLDERS = {
    "your_virustotal_api_key",
    "your_abuseipdb_api_key",
    "your_alienvault_otx_api_key",
    "your_shodan_api_key",
    "your_threatfox_auth_key",
    "your_urlscan_api_key",
    "your_custom_provider_api_key",
}


def _clean_key(name: str) -> str:
    val = os.getenv(name, "").strip()
    return "" if val in _PLACEHOLDERS else val


# API keys (loaded from .env or environment)
VT_API_KEY = _clean_key("VT_API_KEY")
ABUSEIPDB_API_KEY = _clean_key("ABUSEIPDB_API_KEY")
OTX_API_KEY = _clean_key("OTX_API_KEY")
SHODAN_API_KEY = _clean_key("SHODAN_API_KEY")
THREATFOX_AUTH_KEY = _clean_key("THREATFOX_AUTH_KEY")
URLSCAN_API_KEY = _clean_key("URLSCAN_API_KEY")

# HTTP
REQUEST_TIMEOUT = 20  # seconds
ABUSEIPDB_MAX_AGE_DAYS = 90

# Paths
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"
SCHEDULES_FILE = BASE_DIR / "config" / "schedules.json"
DEFAULT_SCHEDULE_INTERVAL_MINUTES = 60
REPORTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

