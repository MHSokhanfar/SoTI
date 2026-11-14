"""Shared helpers for all threat-intelligence API modules.

Created and developed by Mohammad Hossein Sokhanfar.
Repository: https://github.com/MHSokhanfar/SoTI
"""
import ipaddress
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

try:
    import requests  # type: ignore
except ImportError:
    requests = None

from config import settings

log = logging.getLogger("soti")

HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def clean_indicator(value: str) -> str:
    """Refang common defanged IOCs (1[.]2[.]3[.]4, hxxp://evil[.]com) and extract host."""
    v = value.strip().strip("'\"<>")
    v = re.sub(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)", ".", v, flags=re.IGNORECASE)
    v = v.replace("[:]", ":").replace("(:", ":").replace(":)", ":")
    v = v.replace("[://]", "://")
    v = re.sub(r"^hxxps?", lambda m: "https" if m.group(0).lower().endswith("s") else "http", v, flags=re.IGNORECASE)

    if "://" in v:
        parsed = urlparse(v)
        if parsed.hostname:
            v = parsed.hostname
    elif v.count(":") == 1 and not v.startswith("["):
        host_part, port_part = v.split(":", 1)
        if port_part.split("/", 1)[0].isdigit():
            v = host_part
    elif "/" in v:
        parsed = urlparse(f"http://{v}")
        if parsed.hostname:
            v = parsed.hostname

    v = v.strip("[]")
    if HASH_RE.match(v) or DOMAIN_RE.match(v):
        v = v.lower()
    return v


def detect_indicator_type(value: str):
    """Return 'ip', 'domain', 'hash' or None."""
    if not value:
        return None
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if HASH_RE.match(value):
        return "hash"
    if DOMAIN_RE.match(value):
        return "domain"
    return None


def make_result(source, indicator, itype, status="ok", verdict="Unknown",
                score="N/A", summary="", details=None, link=""):
    """Normalized result structure used by the CLI and the CSV exporter.

    status : ok | not_found | unsupported | error
    verdict: Malicious | Suspicious | Clean | Unknown
    """
    return {
        "source": source,
        "indicator": indicator,
        "type": itype,
        "status": status,
        "verdict": verdict,
        "score": score,
        "summary": summary,
        "details": details or {},
        "link": link,
    }


def _status_error(source, indicator, itype, status_code: int):
    if status_code == 404:
        return None, make_result(source, indicator, itype, "not_found",
                                 summary="Not found in database")
    if status_code in (401, 403):
        return None, make_result(source, indicator, itype, "error",
                                 summary="Invalid or unauthorized API key")
    if status_code == 429:
        return None, make_result(source, indicator, itype, "error",
                                 summary="Rate limit exceeded - wait and retry")
    return None, make_result(source, indicator, itype, "error",
                             summary=f"HTTP {status_code}")


def fetch(source, indicator, itype, url, headers=None, params=None):
    """GET a JSON endpoint. Returns (data, None) on success or (None, error_result)."""
    if requests is not None:
        try:
            r = requests.get(url, headers=headers, params=params,
                             timeout=settings.REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            log.error("%s | %s | network error: %s", source, indicator, exc)
            return None, make_result(source, indicator, itype, "error",
                                     summary=f"Network error ({exc.__class__.__name__})")

        log.info("%s | %s | HTTP %s", source, indicator, r.status_code)
        if not r.ok:
            return _status_error(source, indicator, itype, r.status_code)
        try:
            return r.json(), None
        except ValueError:
            return None, make_result(source, indicator, itype, "error",
                                     summary="Invalid JSON response")

    # Standard-library urllib fallback when requests is not installed
    full_url = url
    if params:
        full_url = f"{url}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(full_url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=settings.REQUEST_TIMEOUT) as resp:
            status_code = resp.getcode()
            body = resp.read().decode("utf-8", errors="replace")
            log.info("%s | %s | HTTP %s", source, indicator, status_code)
            try:
                return json.loads(body), None
            except ValueError:
                return None, make_result(source, indicator, itype, "error",
                                         summary="Invalid JSON response")
    except urllib.error.HTTPError as exc:
        log.info("%s | %s | HTTP %s", source, indicator, exc.code)
        return _status_error(source, indicator, itype, exc.code)
    except urllib.error.URLError as exc:
        log.error("%s | %s | network error: %s", source, indicator, exc.reason)
        return None, make_result(source, indicator, itype, "error",
                                 summary=f"Network error ({exc.__class__.__name__})")
    except Exception as exc:
        log.error("%s | %s | unexpected error: %s", source, indicator, exc)
        return None, make_result(source, indicator, itype, "error",
                                 summary=f"Network error ({exc.__class__.__name__})")


def missing_key(source, indicator, itype, env_name):
    log.warning("%s | %s | missing API key (%s)", source, indicator, env_name)
    return make_result(source, indicator, itype, "error",
                       summary=f"API key missing - set {env_name} in .env")


def unsupported(source, indicator, itype, what):
    log.info("%s | %s | unsupported type: %s", source, indicator, what)
    return make_result(source, indicator, itype, "unsupported",
                       summary=f"{source} does not support {what} lookups")
