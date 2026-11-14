"""VirusTotal API v3 - supports IP, domain and file hash.

Created and developed by Mohammad Hossein Sokhanfar.
Repository: https://github.com/MHSokhanfar/SoTI
"""
from datetime import datetime, timezone

from api import fetch, make_result, missing_key
from config import settings

NAME = "VirusTotal"
BASE = "https://www.virustotal.com/api/v3"
ENDPOINTS = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}
GUI = {"ip": "ip-address", "domain": "domain", "hash": "file"}


def parse_response(indicator: str, itype: str, data: dict) -> dict:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total = sum(stats.values())

    if mal >= 5:
        verdict = "Malicious"
    elif mal > 0 or sus > 0:
        verdict = "Suspicious"
    elif total > 0:
        verdict = "Clean"
    else:
        verdict = "Unknown"

    details = {
        "Malicious": mal,
        "Suspicious": sus,
        "Harmless": stats.get("harmless", 0),
        "Undetected": stats.get("undetected", 0),
        "Reputation": attrs.get("reputation", "N/A"),
    }
    if itype == "ip":
        details.update({
            "Country": attrs.get("country", "N/A"),
            "AS Owner": attrs.get("as_owner", "N/A"),
            "ASN": attrs.get("asn", "N/A"),
        })
    elif itype == "domain":
        details["Registrar"] = attrs.get("registrar", "N/A")
        cats = attrs.get("categories", {})
        if cats:
            details["Categories"] = ", ".join(sorted(set(cats.values())))
    else:
        details.update({
            "Name": attrs.get("meaningful_name", "N/A"),
            "Type": attrs.get("type_description", "N/A"),
            "Size": attrs.get("size", "N/A"),
            "SHA256": attrs.get("sha256", "N/A"),
        })
        label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
        if label:
            details["Threat Label"] = label

    ts = attrs.get("last_analysis_date")
    if ts:
        details["Last Analysis"] = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if attrs.get("tags"):
        details["Tags"] = ", ".join(attrs["tags"][:8])

    return make_result(
        NAME, indicator, itype, "ok", verdict,
        score=f"{mal}/{total}" if total else "N/A",
        summary=f"{mal} malicious, {sus} suspicious out of {total} engines",
        details=details,
        link=f"https://www.virustotal.com/gui/{GUI[itype]}/{indicator}",
    )


def lookup(indicator: str, itype: str) -> dict:
    if not settings.VT_API_KEY:
        return missing_key(NAME, indicator, itype, "VT_API_KEY")

    data, err = fetch(
        NAME, indicator, itype,
        f"{BASE}/{ENDPOINTS[itype]}/{indicator}",
        headers={"x-apikey": settings.VT_API_KEY},
    )
    if err:
        return err

    return parse_response(indicator, itype, data)
